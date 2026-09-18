# -*- coding: utf-8 -*-
"""
CRITICO ADVERSARIAL da familia "matrixsumlist_rab" (solver/operador_ensinado_2026_09_17/rab_a1z26.py).

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O agente reportou negativo limpo para o operador RAB (a1z26 -> soma | lista) sobre 184 objetos
nomeados do puzzle: 9.722 senhas unicas x 3 blobs x 2 KDF, 10.994 privkeys, 230 paddings validos,
0 hits duros, nulo casado de 100 replicas dentro da banda. Este script tenta DERRUBAR esse negativo
por tres vias, cada uma julgada so pelo oraculo duro (G.semantic / nested_blob / ebcdic_sig /
privkey -> pubkey do premio ou h160-alvo):

1. RE-VARREDURA: os 230 plaintexts com padding valido (campo `hex` do soft_padding.jsonl dele)
   passam pelo oraculo completo — semantic, nested_blob, ebcdic_sig, fast_priv_scan (pubkey) e
   O.check_privkey (h160 dos dois enderecos) em TODA janela de 32 B, nas DUAS ordens de byte.
   Se algum passar, o negativo cai.
2. COMPLEMENTO das lacunas declaradas mais baratas, no MESMO pipeline:
   (a) ordinais 0-based (A=0..Z=25) sobre todas as entradas;
   (b) janelas contiguas de 6 a 22 palavras da frase de 23 palavras da 3.2 (170 janelas), 1- e 0-based;
   (c) serializacoes aritmeticas extras: produto, soma de quadrados, soma alternada, diferencas
       sucessivas (crua e com zero-padding);
   (d) formas extras: sha256 hex MAIUSCULO e sha256 DUPLO de cada forma-base;
   (e) as duas URLs com '.'->27 e '/'->28 em vez de descartados.
   Tudo deduplicado contra as 9.722 senhas do agente; nulo casado de forma (>= 100 replicas,
   mesma quantidade de palavras e mesmos comprimentos; listas numericas de mesmo tamanho e faixa),
   z por sub-familia blob x KDF.
3. LOOK-ELSEWHERE do maior z dele (TAIL32/SHA256, z = +1,85 entre 6 sub-familias).

FALSIFICACAO: qualquer hit duro derruba o negativo. Sem hits e com padding dentro do nulo, o
negativo do agente fica CONFIRMADO com a cobertura ampliada declarada em resumo.json.
FORA DE ESCOPO (declarado): encadeamento RAB(RAB(x)) (ambiguo: digitos nao sao letras), o numero
como parametro de outra operacao (indice/transposicao), agrupamentos NAO contiguos das 23 palavras,
residuo de dbbi/faed como entrada (colide com ENDGAME secao 4B/6).

Saida: _work/operador_ensinado_2026-09-17/critico_rab/{rescan.json, ext_hits.jsonl, ext_soft.jsonl, resumo.json}
"""
import sys, os, json, time, random, hashlib, statistics, importlib.util
from multiprocessing import Pool
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver")
import gsmg_common as G
import oracles as O
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

BASE = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
OUT = os.path.join(BASE, r"_work\operador_ensinado_2026-09-17\critico_rab")
AGENTE_LOG = os.path.join(BASE, r"_work\operador_ensinado_2026-09-17\rab_a1z26\soft_padding.jsonl")
os.makedirs(OUT, exist_ok=True)

# reutiliza as ENTRADAS e o gerador do agente (sem executar o main dele)
_spec = importlib.util.spec_from_file_location(
    "rab", os.path.join(BASE, r"solver\operador_ensinado_2026_09_17\rab_a1z26.py"))
rab = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(rab)

_BLOBS = [(b, G.BLOBS[b][0], G.BLOBS[b][1]) for b in ("SMALL", "TAIL32", "COSMIC")]
_KDFS = [("MD5", MD5), ("SHA256", SHA256)]
SUBS = [f"{b}/{k}" for b, _, _ in _BLOBS for k, _ in _KDFS]


# ------------------------------------------------------------ 1. re-varredura dos 230 plaintexts
def rescan(path):
    recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    tot_win = 0; hits = []; mx = {"printable": 0.0, "ebcdic": 0.0}
    n_sem = n_nested = n_wif = 0
    for r in recs:
        p = bytes.fromhex(r["hex"])
        for tag, buf in (("fwd", p), ("rev", p[::-1])):
            n = max(0, len(buf) - 31); tot_win += n
            hits += G.fast_priv_scan(buf, f"{r['blob']}/{tag}")
            for j in range(n):                                   # h160 dos DOIS enderecos
                if O.check_privkey(buf[j:j + 32]):
                    hits.append((f"{r['blob']}/{tag}", f"h160@{j}", buf[j:j + 32].hex()))
            if G.semantic(buf): n_sem += 1
            if G.nested_blob(buf): n_nested += 1
            t = buf.decode("latin-1")
            if G.wif_candidates(t) or G.hex64_candidates(t): n_wif += 1
        mx["printable"] = max(mx["printable"], G.printable(p))
        mx["ebcdic"] = max(mx["ebcdic"], G.ebcdic_sig(p))
    return {"plaintexts": len(recs), "janelas_32B_duas_ordens": tot_win, "priv_hits": hits,
            "semantic": n_sem, "nested": n_nested, "wif_hex64": n_wif,
            "max_printable": round(mx["printable"], 3), "max_ebcdic_sig": round(mx["ebcdic"], 3)}


# ------------------------------------------------------------ 2. complemento
def ordinais_ext(texto, base0=False, url_map=False):
    out = []
    for c in texto.lower():
        if "a" <= c <= "z": out.append(ord(c) - 96 - (1 if base0 else 0))
        elif url_map and c == ".": out.append(27 - (1 if base0 else 0))
        elif url_map and c == "/": out.append(28 - (1 if base0 else 0))
    return out


def serializacoes_ext(L, palavras=None):
    s = rab.serializacoes(L, palavras)            # as 11 do agente
    if not L: return s
    prod = 1
    for x in L: prod *= x
    s["produto"] = str(prod)
    s["soma_quadrados"] = str(sum(x * x for x in L))
    s["soma_alternada"] = str(abs(sum(x if i % 2 == 0 else -x for i, x in enumerate(L))))
    if len(L) > 1:
        d = [abs(L[i + 1] - L[i]) for i in range(len(L) - 1)]
        s["difs"] = "".join(str(x) for x in d)
        s["difs02"] = "".join(f"{x:02d}" for x in d)
    return s


def formas_ext(digitos):
    base = rab.formas(digitos)                     # 5 formas-base + 5 sha256
    out = list(base)
    for nome, v in base[:5]:
        b = v.encode() if isinstance(v, str) else v
        h = hashlib.sha256(b).hexdigest()
        out.append(("SHA256:" + nome, h.upper()))
        out.append(("sha256x2:" + nome, hashlib.sha256(h.encode()).hexdigest()))
    return out


def entradas_ext():
    """(texto: nome -> (texto, base0, url_map)), (num: nome -> lista)."""
    t = {}
    et = rab.entradas_texto()
    for tam in range(6, 23):                       # janelas 6..22 da frase da 3.2
        for i in range(0, 23 - tam + 1):
            et[f"f32:{tam}@{i+1}"] = " ".join(rab.FRASE32[i:i + tam])
    for nome, texto in et.items():
        t[nome + "|b1"] = (texto, False, False)
        t[nome + "|b0"] = (texto, True, False)
    for u in ("gsmg.io/theseedisplanted", "gsmg.io/theseedisplante"):
        t[f"pag:{u}|url27|b1"] = (u, False, True)
        t[f"pag:{u}|url27|b0"] = (u, True, True)
    return t, rab.entradas_numericas()


def gerar_ext(ent_t, ent_n):
    senhas, privs = {}, {}

    def addpw(pw, prov):
        b = pw.encode() if isinstance(pw, str) else pw
        if b and len(b) <= 4096: senhas.setdefault(b, prov)

    def addpk(b, prov):
        if len(b) > 32: b = b[-32:]
        privs.setdefault(bytes(32 - len(b)) + b, prov)

    fontes = []
    for nome, (texto, b0, um) in ent_t.items():
        fontes.append((nome, serializacoes_ext(ordinais_ext(texto, b0, um),
                                               [ordinais_ext(w, b0, um) for w in texto.split()])))
    for nome, L in ent_n.items():
        fontes.append((nome, serializacoes_ext(L)))
    for nome, ser in fontes:
        for sn, dig in ser.items():
            if not dig.isdigit(): continue
            n = int(dig)
            addpk(n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big"), f"{nome}|{sn}|int32be")
            for fn, pw in formas_ext(dig):
                addpw(pw, f"{nome}|{sn}|{fn}")
                b = pw.encode() if isinstance(pw, str) else pw
                addpk(hashlib.sha256(b).digest(), f"{nome}|{sn}|sha256({fn})")
    return senhas, privs


def _scan_chunk(items):
    hard, soft, cont = [], [], {k: 0 for k in SUBS}
    for pw, prov in items:
        h, s = G.try_password_all(pw)
        for rec in h + s:
            rec["senha"] = pw.decode("latin-1"); rec["proveniencia"] = prov
            cont[f"{rec['blob']}/{rec['kdf'].rsplit('.', 1)[-1]}"] += 1
        hard += h; soft += s
    return hard, soft, cont


def _padding_only(senhas):
    cont = {k: 0 for k in SUBS}
    for pw in senhas:
        for bname, salt, ct in _BLOBS:
            for kname, hm in _KDFS:
                key, iv = G.evp(pw, salt, hm)
                if G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct)) is not None:
                    cont[f"{bname}/{kname}"] += 1
    return cont


def _nulo_replica(i):
    """Uma replica do nulo: mesma FORMA de cada entrada, letras/valores sorteados, mesmo pipeline."""
    rnd = random.Random(20260917 * 1000 + i)
    ent_t, ent_n = entradas_ext()
    nt = {}
    for nome, (texto, b0, um) in ent_t.items():
        # preserva letras E os nao-letras (a URL mantem '.' e '/'; so as letras sao sorteadas)
        nt[nome] = ("".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") if c.isalpha() else c
                            for c in texto), b0, um)
    nn = {n: [rnd.randint(min(L), max(L)) for _ in L] for n, L in ent_n.items()}
    s, _ = gerar_ext(nt, nn)
    c = _padding_only(s)
    return {k: v / len(s) for k, v in c.items()}, len(s)


def main():
    t0 = time.time()
    ok, amostra = rab.controle_positivo()
    print(f"[controle positivo] fase2 EVP-SHA256 sha256hex('causality') -> {ok}: {amostra!r}")
    assert ok

    # 1. re-varredura
    rs = rescan(AGENTE_LOG)
    json.dump(rs, open(os.path.join(OUT, "rescan.json"), "w", encoding="utf-8"), indent=2)
    print("[rescan]", json.dumps(rs))

    # 2. complemento
    ent_t, ent_n = entradas_ext()
    senhas, privs = gerar_ext(ent_t, ent_n)
    dele = rab.gerar_senhas(rab.entradas_texto(), rab.entradas_numericas())
    pk_dele = rab.privkeys_candidatas(rab.entradas_texto(), rab.entradas_numericas())
    novas = {k: v for k, v in senhas.items() if k not in dele}
    novas_pk = {k: v for k, v in privs.items() if k not in pk_dele}
    print(f"[ext] {len(ent_t)} entradas texto + {len(ent_n)} numericas -> {len(senhas)} senhas "
          f"({len(novas)} novas vs agente), {len(privs)} privkeys ({len(novas_pk)} novas)")
    pk_hits = [(k.hex(), v) for k, v in novas_pk.items() if G.priv_hit(k)]
    print(f"[ext privkey] {len(novas_pk)} testadas -> {len(pk_hits)} hits ({time.time()-t0:.0f}s)")

    items = list(novas.items()); NP = max(1, os.cpu_count() - 2)
    chunks = [items[i::NP] for i in range(NP)]
    with Pool(NP) as pool:
        parts = pool.map(_scan_chunk, chunks)
    hits, soft, cont = [], [], {k: 0 for k in SUBS}
    for h, s, c in parts:
        hits += h; soft += s
        for k in SUBS: cont[k] += c[k]
    with open(os.path.join(OUT, "ext_hits.jsonl"), "w", encoding="utf-8") as f:
        for r in hits: f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(OUT, "ext_soft.jsonl"), "w", encoding="utf-8") as f:
        for r in soft: f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[ext AES] {len(novas)*6} decifracoes, {len(hits)} hits duros, {len(soft)} paddings "
          f"({time.time()-t0:.0f}s)")

    # nulo casado (o nulo mede o pipeline ext inteiro; a taxa observada tambem, sobre `senhas`)
    N = int(os.environ.get("N_NULO", "100"))
    cont_all = _padding_only(senhas)
    with Pool(NP) as pool:
        reps = pool.map(_nulo_replica, range(N))
    print(f"[nulo] {N} replicas, ~{statistics.fmean(n for _, n in reps):.0f} senhas cada "
          f"({time.time()-t0:.0f}s)")

    resumo = {"rescan": rs, "entradas_texto": len(ent_t), "entradas_numericas": len(ent_n),
              "senhas_ext": len(senhas), "senhas_novas": len(novas),
              "decifracoes_novas": len(novas) * 6, "privkeys_novas": len(novas_pk),
              "privkey_hits": len(pk_hits), "hits_duros": len(hits), "paddings_novos": len(soft),
              "max_printable_ext": max([r["printable"] for r in soft], default=0),
              "n_nulo": N, "subfamilias": {}}
    for k in SUBS:
        obs = cont_all[k] / len(senhas)
        xs = [r[k] for r, _ in reps]
        mu, sd = statistics.fmean(xs), (statistics.pstdev(xs) or 1e-12)
        resumo["subfamilias"][k] = {"padding_ok": cont_all[k], "taxa_obs": round(obs, 5),
                                    "nulo_media": round(mu, 5), "nulo_sd": round(sd, 5),
                                    "z": round((obs - mu) / sd, 2)}
    resumo["segundos"] = round(time.time() - t0)
    json.dump(resumo, open(os.path.join(OUT, "resumo.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print(json.dumps(resumo, ensure_ascii=False, indent=2))


def demo():
    assert ordinais_ext("RAB") == [18, 1, 2] and ordinais_ext("RAB", base0=True) == [17, 0, 1]
    assert ordinais_ext("a.b/", url_map=True) == [1, 27, 2, 28]
    s = serializacoes_ext([18, 1, 2])
    assert s["produto"] == "36" and s["soma_quadrados"] == "329" and s["soma_alternada"] == "19" \
        and s["difs"] == "171", s
    assert len(formas_ext("21")) == 20
    assert G.semantic(b"Salted__" + bytes(40)) and G.fast_priv_scan(bytes(40)) == []
    print("demo OK")


if __name__ == "__main__":
    demo() if "--demo" in sys.argv else main()
