# -*- coding: utf-8 -*-
"""
Runner AUTONOMO do solver GSMG. "Incansavel": roda ate resolver ou ser parado.

Divisao de trabalho (a chave da corretude):
  - LLAMA (local, via Ollama) PROPOE hipoteses e novos blocos (alfabetos/chaves).
  - O GERADOR ENUMERATIVO varre sistematicamente o espaco tematico (throughput).
  - Os ORACULOS DUROS de oracles.py JULGAM. So eles declaram solve.
Nada que o modelo "diga" conta como solucao — apenas endereco batido / checksum /
padding AES valido. Isso torna impossivel um falso-solve por alucinacao.

Saidas (todas em solver/out/, ignoradas pelo git):
  journal.jsonl      — toda tentativa {hyp, res, ts}
  candidates.jsonl   — plaintexts com score de legibilidade alto (revisao humana)
  discovered.jsonl   — alfabetos/chaves novos propostos pelo modelo
  SOLVED.json        — escrito UMA vez se um oraculo duro passar; o loop para
  status.json        — heartbeat (contadores) para monitoramento
"""
import os, sys, json, time, hashlib, urllib.request, random, itertools, argparse
import dsl, oracles as O
from scorer import Scorer

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)
MODEL = os.environ.get("GSMG_MODEL", "llama3:latest")
READABLE_FLAG = -4.4          # score de legibilidade que vira candidato humano
random.seed()

# ---------------- fatos + becos (contexto p/ o modelo) ----------------
FACTS = """FATOS VERIFICADOS (nao repetir becos):
- faed = 570 chars sobre a-i (payload); dbbi = 91 chars sobre a-i (chave/keyword).
- Bifid do faed com alfabeto 25-letras "DBIFHCEGAKLMNOPQRSTUVWXYZ" (periodo=570)
  produz header "BTCSEED" + 563 chars ilegiveis. Isso e SINAL REAL (teste nulo 0/3000).
- Os 563 chars pos-BTCSEED NAO sao ingles por substituicao monoalfabetica (verificado).
- So o periodo 570 da BTCSEED; periodos 101/91/13/38 e outros falham.
- matrixsumlist (somas linha [6,10,8,7,6,6,5,4,9,9,7,8,7,9] / coluna
  [8,10,8,10,8,7,3,6,7,5,9,6,6,8], total 101) como keystream mod-9 sobre faed
  DESTROI o BTCSEED -> nao e over-encryption pre-Bifid.
- Senha AES direta (faed/dbbi cru, temas) NAO abre os blobs SMALL/COSMIC.
- Metodo a-i->1-9->base16->ascii (que decodifica lastwords/thispassword) no faed = lixo.
OBJETIVO: achar o transform que torna os 563 chars pos-BTCSEED = seed/priv-key,
ou a senha real que abre SMALL (=faed decodificado) e depois COSMIC."""

DSL_SPEC = """Voce propoe HIPOTESES como JSON. Formato de UMA hipotese:
{"source": <S>, "ops": [<op>...], "check": {"oracle": <ORACLE>, ...}}
S (fonte): "faed" | "faed_no_prefix" | "dbbi" | "bif" (=saida Bifid) | "bif_rest" (563 pos-BTCSEED)
ORACLE: "aes_open"(usa valor como senha p/ SMALL/COSMIC) | "as_privkey"(valor->chave BTC->endereco)
        | "as_bip39"(nums->palavras) | "readable"(legibilidade EN)
ops disponiveis (encadeaveis):
  {"op":"bifid","alphabet":<25 letras unicas,I=J>,"period":<int>,"mode":"decrypt|encrypt"}
  {"op":"to_digits","o_is_zero":false}                      # texto a-i -> nums 1..9
  {"op":"letters_to_nums","base":0}                          # A-Z -> nums
  {"op":"nums_to_letters","alphabet":"ABC..."}               # nums -> texto
  {"op":"digits_to_faed"}                                    # nums 1..9 -> a..i
  {"op":"keystream","key":<str a-i ou lista int>,"mod":9,"dir":"add|sub","offset":0}
  {"op":"vigenere","key":<str>,"mod":26,"dir":"sub"}         # sobre nums
  {"op":"beaufort","key":<str>,"mod":26}
  {"op":"columnar","key":<lista int>,"mode":"dec|enc"}
  {"op":"substitute","from":"ABC...","to":"XYZ..."}
  {"op":"base_convert","from_base":9,"to_base":16}           # nums(digitos)->numero->hex->ascii
  {"op":"reverse"} | {"op":"slice","start":0,"end":100}
Responda SOMENTE JSON: {"hypotheses":[...ate 6...], "new_alphabets":["25 letras"...], "new_keys":["..."]}
Seja CRIATIVO e TEMATICO (Matrix, xadrez, HSM, primos, dbbi, cosmic duality),
mas cada hipotese deve ser executavel com as ops acima. Evite os becos dos FATOS."""

# ---------------- utils ----------------
def now(): return time.strftime("%Y-%m-%d %H:%M:%S")

def sig(hyp):
    return hashlib.sha1(json.dumps(hyp, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

def jl_append(fname, obj):
    with open(os.path.join(OUT, fname), "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

# ---------------- construcao de alfabetos tematicos ----------------
def keyword_square(keyword, filler_rev=False):
    kw = keyword.upper().replace("J", "I")
    seen = []
    for c in kw:
        if c.isalpha() and c not in seen:
            seen.append(c)
    rest = [c for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ" if c not in seen]  # sem J
    if filler_rev: rest = rest[::-1]
    sq = "".join(seen + rest)
    return sq if len(sq) == 25 else None

THEME_WORDS = ["THEMATRIXHASYOU", "SALPHASEION", "COSMICDUALITY", "THESEEDISPLANTED",
               "BTCSEED", "GSMGIO", "LASTWORDSBEFOREARCHICHOICE", "THISPASSWORD",
               "MATRIXSUMLIST", "CAUSALITY", "COSMIC", "DUALITY", "SATOSHI",
               "BITCOIN", "PRIVATEKEY", "HALFANDBETTERHALF", "ENTER", "NEO"]

def base_alphabets():
    al = ["DBIFHCEGAKLMNOPQRSTUVWXYZ"]  # CANON (verificado)
    for w in THEME_WORDS:
        for rev in (False, True):
            s = keyword_square(w, rev)
            if s and s not in al:
                al.append(s)
    # dbbi-derivado: 1as ocorrencias de dbbi + filler
    dbbi = O.sources()["dbbi"].upper()
    seen = []
    for c in dbbi:
        if c not in seen: seen.append(c)
    rest = [c for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ" if c not in seen]
    s = "".join(seen + rest)
    if len(s) == 25 and s not in al: al.append(s)
    return al

# ---------------- keystreams tematicos ----------------
def base_keys():
    row = [6,10,8,7,6,6,5,4,9,9,7,8,7,9]
    col = [8,10,8,10,8,7,3,6,7,5,9,6,6,8]
    keys = [row, col, [1,1,4,1], [1,4], [1,4,2,1],
            [int(x) for x in "101"], [int(x) for x in "570"],
            [int(x) for x in "91"], [int(x) for x in "1141"]]
    keys.append([O.sources()["dbbi"].upper()])  # dbbi como string-chave (marcador)
    return keys

# ---------------- gerador enumerativo ----------------
def enum_gen(alphabets, deterministic_first=True):
    """Yield hipoteses executaveis, cobertura sistematica + amostragem."""
    periods_themed = [570, 566, 285, 190, 114, 101, 91, 45, 38, 30, 19, 15, 13, 9, 7, 5, 3, 2]
    # familia A: Bifid decode/encode variando alfabeto x periodo x fonte
    fam_a = []
    for src in ("faed", "faed_no_prefix"):
        for alpha in alphabets:
            for per in periods_themed:
                for mode in ("decrypt", "encrypt"):
                    fam_a.append({"source": src,
                                  "ops": [{"op": "bifid", "alphabet": alpha, "period": per, "mode": mode}],
                                  "check": {"oracle": "readable"}})
    # familia B: remover keystream mod9 do faed-digits, depois Bifid CANON
    fam_b = []
    for key in base_keys():
        if isinstance(key[0], str):  # dbbi-string
            kk = key[0]
        else:
            kk = key
        for d in ("add", "sub"):
            for off in range(0, 14, 2):
                fam_b.append({"source": "faed",
                              "ops": [{"op": "to_digits"},
                                      {"op": "keystream", "key": kk, "mod": 9, "dir": d, "offset": off},
                                      {"op": "digits_to_faed"},
                                      {"op": "bifid", "alphabet": "DBIFHCEGAKLMNOPQRSTUVWXYZ", "period": 570}],
                              "check": {"oracle": "readable"}})
    # familia C: bif/bif_rest -> aes_open e as_privkey (senha/chave direta)
    fam_c = []
    for src in ("bif", "bif_rest", "faed", "dbbi"):
        for orc in ("aes_open", "as_privkey"):
            fam_c.append({"source": src, "ops": [], "check": {"oracle": orc}})
    # familia D: bif_rest -> nums -> bip39
    fam_d = [{"source": "bif_rest", "ops": [{"op": "letters_to_nums", "base": 0}],
              "check": {"oracle": "as_bip39"}},
             {"source": "bif", "ops": [{"op": "letters_to_nums", "base": 1}],
              "check": {"oracle": "as_bip39"}}]
    # familia E: metodo ensinado em slices do faed
    fam_e = []
    for start in range(4, 400, 60):
        fam_e.append({"source": "faed",
                      "ops": [{"op": "slice", "start": start, "end": start + 60},
                              {"op": "to_digits", "o_is_zero": True},
                              {"op": "base_convert", "from_base": 10, "to_base": 16}],
                      "check": {"oracle": "readable"}})

    families = fam_a + fam_b + fam_c + fam_d + fam_e
    if deterministic_first:
        for h in families:
            yield h
    # depois: amostragem aleatoria continua do mesmo espaco (variando oraculo do fam_a)
    while True:
        h = dict(random.choice(fam_a))
        h = json.loads(json.dumps(h))
        h["check"] = {"oracle": random.choice(["readable", "aes_open", "as_privkey"])}
        yield h

# ---------------- cliente Ollama ----------------
def llm_batch(recent_fail, discovered, timeout=120):
    prompt = (FACTS + "\n\n" + DSL_SPEC +
              "\n\nFALHAS RECENTES (evite):\n" + "\n".join(recent_fail[-12:]) +
              ("\n\nBLOCOS JA DESCOBERTOS: " + json.dumps(discovered[-10:]) if discovered else ""))
    body = json.dumps({"model": MODEL, "prompt": prompt, "format": "json", "stream": False,
                       "options": {"temperature": 0.9, "num_predict": 700}}).encode()
    req = urllib.request.Request("http://localhost:11434/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
        data = json.loads(resp["response"])
    except Exception as e:
        return [], [], []
    hyps = data.get("hypotheses", []) if isinstance(data, dict) else []
    alphas = [a for a in data.get("new_alphabets", []) if isinstance(a, str)
              and len(set(a.upper().replace("J", "I"))) == 25]
    keys = [k for k in data.get("new_keys", []) if isinstance(k, (str, list))]
    good = [h for h in hyps if isinstance(h, dict) and "source" in h]
    return good, alphas, keys

# ---------------- loop principal ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm-every", type=int, default=400,
                    help="chamar o Llama a cada N tentativas enumerativas")
    ap.add_argument("--max", type=int, default=0, help="parar apos N tentativas (0=infinito)")
    ap.add_argument("--max-hours", type=float, default=0, help="parar apos N horas (0=infinito)")
    args = ap.parse_args()
    deadline = time.time() + args.max_hours * 3600 if args.max_hours else None

    print(f"[{now()}] solver GSMG iniciado | modelo={MODEL} | out={OUT}")
    scorer = Scorer()
    alphabets = base_alphabets()
    discovered = []
    seen = set()
    recent_fail = []
    stats = {"tried": 0, "invalid": 0, "llm_hyps": 0, "best_readable": -99, "candidates": 0, "start": time.time()}
    gen = enum_gen(alphabets)
    llm_alpha_pool = list(alphabets)

    def handle(hyp, origin):
        s = sig(hyp)
        if s in seen:
            return False
        seen.add(s)
        res = dsl.execute(hyp, scorer)
        stats["tried"] += 1
        if "invalid" in res:
            stats["invalid"] += 1
            return False
        rec = {"ts": now(), "origin": origin, "hyp": hyp, "res": res}
        # SOLVE?
        if res.get("solve"):
            jl_append("journal.jsonl", rec)
            with open(os.path.join(OUT, "SOLVED.json"), "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False, indent=2)
            print(f"\n{'='*60}\n[{now()}] !!!!! SOLVE VERIFICADO POR ORACULO !!!!!")
            print(json.dumps(res, ensure_ascii=False, indent=2))
            print(f"{'='*60}\nescrito em out/SOLVED.json")
            return True
        # legibilidade promissora?
        sc = res.get("score")
        if sc is not None and sc > stats["best_readable"]:
            stats["best_readable"] = sc
        if sc is not None and sc >= READABLE_FLAG:
            stats["candidates"] += 1
            jl_append("candidates.jsonl", rec)
        # journal amostrado (nao inflar disco): tudo que nao e readable-negativo trivial
        if origin == "llm" or res.get("oracle") != "readable" or (sc and sc > -5.2):
            jl_append("journal.jsonl", rec)
        # feedback compacto
        if len(recent_fail) < 200:
            recent_fail.append(f"{hyp.get('source')}:{[o.get('op') for o in hyp.get('ops',[])]}->{res.get('oracle')}")
        return False

    heartbeat = time.time()
    try:
        while True:
            # parada por deadline ou por SOLVE de outro motor (GPU)
            if deadline and time.time() >= deadline:
                print(f"[{now()}] limite de {args.max_hours}h atingido"); return
            if os.path.exists(os.path.join(OUT, "SOLVED.json")) or \
               os.path.exists(os.path.join(OUT, "BREAKTHROUGH.json")):
                print(f"[{now()}] outro motor fechou (SOLVED/BREAKTHROUGH) — encerrando"); return
            # rajada enumerativa
            for _ in range(args.llm_every):
                if handle(next(gen), "enum"):
                    return
                if args.max and stats["tried"] >= args.max:
                    print(f"[{now()}] limite --max atingido"); return
            # rajada do Llama
            hyps, alphas, keys = llm_batch(recent_fail, discovered)
            stats["llm_hyps"] += len(hyps)
            for a in alphas:
                sq = a.upper().replace("J", "I")
                if sq not in llm_alpha_pool and len(set(sq)) == 25:
                    llm_alpha_pool.append(sq); discovered.append({"alphabet": sq})
                    jl_append("discovered.jsonl", {"ts": now(), "alphabet": sq})
            for h in hyps:
                # injeta tambem checagens duras alem da que o modelo pediu
                if handle(h, "llm"):
                    return
                for orc in ("aes_open", "as_privkey"):
                    h2 = json.loads(json.dumps(h)); h2["check"] = {"oracle": orc}
                    if handle(h2, "llm"):
                        return
            # se o modelo deu alfabetos novos, varre-os via Bifid (determina)
            for sq in [d["alphabet"] for d in discovered[-len(alphas):]] if alphas else []:
                for src in ("faed", "faed_no_prefix"):
                    for orc in ("readable", "aes_open", "as_privkey"):
                        if handle({"source": src, "ops": [{"op": "bifid", "alphabet": sq, "period": 570}],
                                   "check": {"oracle": orc}}, "llm"):
                            return
            # heartbeat
            if time.time() - heartbeat > 20:
                heartbeat = time.time()
                el = int(time.time() - stats["start"])
                rate = stats["tried"] / max(1, el)
                st = {**stats, "elapsed_s": el, "rate_per_s": round(rate, 1),
                      "seen": len(seen), "alphabets": len(llm_alpha_pool), "ts": now()}
                with open(os.path.join(OUT, "status.json"), "w", encoding="utf-8") as f:
                    json.dump(st, f, ensure_ascii=False, indent=2)
                print(f"[{now()}] tried={stats['tried']} invalid={stats['invalid']} "
                      f"llm={stats['llm_hyps']} best_read={stats['best_readable']:.2f} "
                      f"cand={stats['candidates']} alpha={len(llm_alpha_pool)} {rate:.0f}/s")
    except KeyboardInterrupt:
        print(f"\n[{now()}] interrompido. tried={stats['tried']}")

if __name__ == "__main__":
    main()
