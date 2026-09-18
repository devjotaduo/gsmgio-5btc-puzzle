# -*- coding: utf-8 -*-
"""Frente orfaos_temp (campanha enxame_2026-09-18; hipótese auditoria-01, camadas A+B).

Os plaintexts com padding válido de 17/09 que ficaram no scratchpad da sessão bd1a3ae7, em %TEMP%,
nunca passaram por uma varredura de dois alvos nem pelas visões cp273/UTF-16, porque as coletas da
§3.11, §3.12 e §3.13 só leem _work/ e solver/. Esta frente:
  1. reproduz a lacuna: o fast_priv_scan histórico (9062dc7) dá falso negativo para 17ucy e para LE;
  2. congela o manifesto sha256 das fontes;
  3. extrai plain_hex/hex/soft.hex (exclui pw_hex, head_hex, D_hex) da camada A (aes-256-cbc em
     SMALL/COSMIC de premissa_cifra) e da B (rerun_ext, infrared, unicode_yinyang, kfile_first_line,
     marcadores, forense_bytes), deduplica por conteúdo e mede a sobreposição com a recoleta da §3.11
     (scan.recoletar()) e com os corpora da §3.12/§3.13;
  4. varre TODO conteúdo único, inclusive os sobrepostos (superconjunto): raw32 em todo offset, BE e
     LE, h160 comprimido e não comprimido contra os dois alvos; scan.processar() (visão original e
     cp273 inversa, cp273, UTF-16 LE/BE @0/@1: hex64 em todo nibble, WIF com checksum, G.semantic,
     ebcdic_sig, nested_blob, ASCII ≥ 48 B, Salted__/U2FsdGVk em qualquer offset);
  5. refaz o braço de privkey (brainwallet) do marcadores.py contra os dois alvos, sem AES.
Camadas C (outras 11 cifras) e D (montagens) ficam de fora, como o gate recomendou.
Nenhuma decifração AES nova. Qualquer achado é CANDIDATO (AGENTS.md, regra 1), nunca solução.

Rodar em primeiro plano, em etapas (cada uma < 10 min):
  python orfaos.py --etapa preparar
  python orfaos.py --etapa varrer --parte k --partes n   (as classes k::n precisam particionar os itens)
  python orfaos.py --etapa juntar --partes 4
Saída: _work/enxame_2026-09-18/orfaos_temp/{controls.json, prep.json, parte<k>.json, summary.json, candidates.jsonl}.
"""
import argparse, glob, hashlib, itertools, json, os, random, re, sqlite3, subprocess, sys, time
from collections import Counter
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[2]
sys.path.insert(0, str(AQUI.parent / "lacuna_cp273_utf16"))
import scan  # noqa: E402  (recoletar, processar, triar e controles da frente lacuna; importa o kit da worktree)
from coincurve import PublicKey  # noqa: E402

G = scan.G
ORFAO = Path(r"C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle"
             r"\bd1a3ae7-baeb-4498-9cf8-1a8d8944473a\scratchpad")
OUT = REPO / "_work" / "enxame_2026-09-18" / "orfaos_temp"
FAMILIAS = ("A:premissa_cifra", "rerun_ext", "infrared", "unicode_yinyang", "kfile_first_line",
            "marcadores", "forense_bytes")
EXCLUI = {"pw_hex", "head_hex", "D_hex"}
HEXRE = re.compile(r"[0-9a-fA-F]+")
DBS = {  # corpora da §3.12 e da §3.13 (só para declarar a sobreposição)
    "3.12_v3": "_work/oraculo_duplo_2026-09-17/corpus_v3/corpus.sqlite",
    "3.12_supplement": "_work/oraculo_duplo_2026-09-17/corpus_supplement/corpus.sqlite",
    "3.12_partial": "_work/oraculo_duplo_2026-09-17/corpus_partial/corpus.sqlite",
    "3.13_recovered": "_work/multiagente_2026-09-18/recovered/corpus.sqlite",
}
MARCADORES_NPRIV = 1153925  # marcadores/summary.json: n_priv (real + nulo), para a reconciliação
COMMIT_ANTIGO = "9062dc7"   # kit em uso quando as campanhas órfãs rodaram (fix em 0ce4185, 17/09 23:21)


def _utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# ------------------------------------------------------------------ oráculo de privkey
def _casa(sec):
    """True se o escalar é válido e o h160 (comprimido ou não) está em G.TARGET_H160S (lido na hora,
    para o alvo plantado dos controles valer)."""
    try:
        pk = PublicKey.from_valid_secret(sec)
    except Exception:
        return None
    return any(G._h160_hex(pk.format(c)) in G.TARGET_H160S for c in (False, True))


def raw32(data):
    """Toda janela de 32 B, BE (como está) e LE (bytes invertidos). Devolve (válidos, hits)."""
    validos, hits = 0, []
    for ordem, buf in (("be", data), ("le", data[::-1])):
        for j in range(len(buf) - 31):
            r = _casa(buf[j:j + 32])
            if r is None:
                continue
            validos += 1
            if r:
                off = j if ordem == "be" else len(data) - 32 - j  # onde os 32 B estão no conteúdo
                hits.append({"visao": "original", "formato": f"raw32-{ordem}", "offset": off,
                             "privkey": buf[j:j + 32].hex(), "confirmado_G.priv_hit": G.priv_hit(buf[j:j + 32])})
    return validos, hits


# ------------------------------------------------------------------ fontes, manifesto, extração
def arquivos_fonte():
    arqs = []
    for i, fam in enumerate(FAMILIAS):
        d = ORFAO / fam.split(":")[-1]
        arqs += [(i, Path(p)) for p in sorted(glob.glob(str(d / "**" / "*.json*"), recursive=True))]
    return arqs


def manifesto(arqs):
    return {str(p.relative_to(ORFAO)): {"sha256": _sha(p), "bytes": p.stat().st_size,
                                         "mtime_utc": _utc(p.stat().st_mtime)} for _, p in arqs}


def _hexes(o, out):
    """(dict que contém o campo, chave, valor) de todo campo *hex* com ≥ 32 B, menos EXCLUI."""
    if isinstance(o, dict):
        for k, v in o.items():
            if (isinstance(v, str) and "hex" in k.lower() and k not in EXCLUI and len(v) >= 64
                    and len(v) % 2 == 0 and HEXRE.fullmatch(v)):
                out.append((o, k, v))
            else:
                _hexes(v, out)
    elif isinstance(o, list):
        for v in o:
            _hexes(v, out)


def _registros(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        if p.suffix == ".json":
            yield 0, f.read()
        else:
            yield from enumerate(f)


def extrair(arqs):
    """corpus: bytes -> máscara de famílias; origem: bytes -> primeira origem (para a triagem)."""
    corpus, origem, tail32, fora = {}, {}, set(), Counter()
    est = {f: Counter() for f in FAMILIAS}
    sub_a = Counter()
    for i, p in arqs:
        fam, rel = FAMILIAS[i], str(p.relative_to(ORFAO))
        for n, linha in _registros(p):
            linha = linha.strip()
            if not linha:
                continue
            try:
                o = json.loads(linha)
            except json.JSONDecodeError:
                est[fam]["linhas_invalidas"] += 1
                continue
            got = []
            _hexes(o, got)
            for d, k, v in got:
                b = bytes.fromhex(v)
                if i == 0:  # camada A: só aes-256-cbc em SMALL/COSMIC
                    if d.get("cipher") != "aes-256-cbc":
                        fora["C:outras_cifras"] += 1
                        continue
                    if d.get("blob") == "TAIL32":
                        fora["A:TAIL32_aes-256-cbc"] += 1
                        tail32.add(b)
                        continue
                    if d.get("blob") not in ("SMALL", "COSMIC"):
                        fora["A:blob_desconhecido"] += 1
                        continue
                    sub_a[f'{d["blob"]}/{d.get("kdf")}'] += 1
                est[fam]["campos"] += 1
                est[fam][f"chave:{k}"] += 1
                m = corpus.get(b, 0)
                if not m & (1 << i):
                    est[fam]["conteudos"] += 1
                    est[fam]["janelas_raw32"] += max(0, len(b) - 31)
                    est[fam]["bytes"] += len(b)
                corpus[b] = m | (1 << i)
                origem.setdefault(b, {"familia": fam, "arquivo": rel, "linha": n,
                                      **{c: d[c] for c in ("ext_mode", "kind", "blob", "kdf", "cipher", "tag", "file")
                                         if c in d and isinstance(d[c], str)}})
    return corpus, origem, tail32, {"por_familia": {f: dict(c) for f, c in est.items()},
                                    "camada_A_por_blob_kdf_campos": dict(sub_a), "fora_do_escopo_campos": dict(fora)}


def sobreposicao(corpus, tail32):
    """Recoleta da §3.11 (scan.recoletar) e sha256 dos corpora da §3.12/§3.13."""
    t0 = time.monotonic()
    r311, _mt, _arq = scan.recoletar()
    s311 = set(r311)
    del r311, _mt, _arq
    dbs = set()
    tamanhos = {}
    for nome, rel in DBS.items():
        con = sqlite3.connect(f"file:{REPO / rel}?mode=ro&immutable=1", uri=True)
        hs = {r[0] for r in con.execute("select sha256 from payloads")}
        con.close()
        tamanhos[nome] = len(hs)
        dbs |= hs
    fam = {f: Counter() for f in FAMILIAS}
    novos = set()
    for b, m in corpus.items():
        em311, emdb = b in s311, hashlib.sha256(b).hexdigest() in dbs
        if not (em311 or emdb):
            novos.add(b)
        for i, f in enumerate(FAMILIAS):
            if m & (1 << i):
                c = fam[f]
                c["em_3.11"] += em311
                c["em_3.12_3.13"] += emdb
                c["fora_de_todos"] += not (em311 or emdb)
                c["janelas_fora_de_todos"] += max(0, len(b) - 31) if not (em311 or emdb) else 0
    t32 = {"conteudos": len(tail32), "em_3.11": sum(b in s311 for b in tail32),
           "em_3.12_3.13": sum(hashlib.sha256(b).hexdigest() in dbs for b in tail32),
           "fora_de_todos": sum(b not in s311 and hashlib.sha256(b).hexdigest() not in dbs for b in tail32)}
    return novos, {"recoleta_3.11_conteudos": len(s311), "corpora_sha256": tamanhos,
                   "uniao_A+B": {"conteudos": len(corpus), "em_3.11": sum(b in s311 for b in corpus),
                                 "fora_de_todos": len(novos),
                                 "janelas_fora_de_todos": sum(max(0, len(b) - 31) for b in novos)},
                   "por_familia": {f: dict(c) for f, c in fam.items()},
                   "TAIL32_aes-256-cbc_excluido": t32, "segundos": round(time.monotonic() - t0, 1)}


# ------------------------------------------------------------------ varredura (processos filhos)
def trabalhar(lote):
    agg = {"n": 0, "bytes": 0, "raw32_janelas": 0, "raw32_validos": 0, "tent": Counter(), "validos_hexwif": 0,
           "motivos": Counter(), "novos": Counter(), "orig": Counter(), "hits": [], "candidatos": [],
           "digest": 0, "artefatos": 0}
    for data, mask in lote:
        dg = hashlib.sha256(data).digest()
        agg["digest"] = (agg["digest"] + int.from_bytes(dg, "big")) % (1 << 256)
        v, hits = raw32(data)
        r = scan.processar(data)
        agg["n"] += 1
        agg["bytes"] += len(data)
        agg["raw32_janelas"] += 2 * max(0, len(data) - 31)
        agg["raw32_validos"] += v
        agg["tent"].update(r["tent"])
        agg["validos_hexwif"] += r["validos"]
        hits += r["hits"]
        fams = [f for i, f in enumerate(FAMILIAS) if mask & (1 << i)]
        agg["orig"].update(f"{f}:{x}" for f in fams for x in r["orig"])
        for nome, vi in r["visoes"].items():
            agg["motivos"].update(f"{nome}:{x}" for x in vi["reasons"])
            agg["novos"].update(f"{nome}:{x}" for x in vi["novos"])
        novos_v = any(vi["novos"] for vi in r["visoes"].values())
        if hits or novos_v or r["orig"]:
            if hits:
                tri = "HIT: exige proof-certificate"
            elif novos_v:
                tri = scan.triar(r["visoes"], r["orig"])
            else:
                tri = "a examinar: motivo na visão original"
            rec = {"sha256": dg.hex(), "len": len(data), "familias": fams, "classe": "CANDIDATO (triagem, não solução)",
                   "triagem": tri, "hits": hits, "orig_reasons": r["orig"],
                   "visoes": {k: vi for k, vi in r["visoes"].items() if vi["novos"]}, "hex": data.hex()}
            agg["candidatos"].append(rec)
            agg["hits"] += [{**h, "sha256": dg.hex()} for h in hits]
        elif r["visoes"]:
            agg["artefatos"] += 1
    return agg


def _lotes(itens, tam):
    for i in range(0, len(itens), tam):
        yield itens[i:i + tam]


SOMA = ("n", "bytes", "raw32_janelas", "raw32_validos", "validos_hexwif", "artefatos", "candidatos")
CONTA = ("tent", "motivos", "novos", "orig", "triagem")


def varrer(itens, origem, workers, tam, arq_cand):
    tot = {**{k: 0 for k in SOMA}, **{k: Counter() for k in CONTA}, "hits": [], "digest": 0}
    t0 = time.monotonic()
    with open(arq_cand, "w", encoding="utf-8") as cand, Pool(workers) as pool:
        for i, agg in enumerate(pool.imap_unordered(trabalhar, _lotes(itens, tam)), 1):
            for k in SOMA[:-1]:
                tot[k] += agg[k]
            for k in CONTA[:-1]:
                tot[k].update(agg[k])
            tot["digest"] = (tot["digest"] + agg["digest"]) % (1 << 256)
            tot["hits"] += agg["hits"]
            for c in agg["candidatos"]:
                c["origem"] = origem[bytes.fromhex(c["hex"])]
                tot["candidatos"] += 1
                tot["triagem"][c["triagem"]] += 1
                cand.write(json.dumps(c, ensure_ascii=False) + "\n")
            if i % 100 == 0:
                print(f"  {tot['n']:,}/{len(itens):,} conteúdos  janelas={tot['raw32_janelas']:,}  "
                      f"candidatos={tot['candidatos']}  hits={len(tot['hits'])}  {time.monotonic() - t0:.0f}s", flush=True)
    tot["segundos"] = round(time.monotonic() - t0, 1)
    return tot


# ------------------------------------------------------------------ braço brainwallet do marcadores.py
def brainwallet():
    """Refaz só o braço priv() de marcadores.py (sha256, sha256d, sha256(upper), raw32, janelas, int,
    bin, hex64), agora contra os dois alvos e as duas formas de pubkey, com os mesmos materiais (reais
    e os 100 nulos da semente 20260917). O arquivo original não é importado: ele apaga o próprio log."""
    src = (ORFAO / "marcadores" / "marcadores.py").read_text(encoding="utf-8")
    sep = "# ------------------------------------------------------------------ "
    seg = src[src.index(sep + "segmentacao"):src.index(sep + "oraculo")]
    ger = src[src.index(sep + "geradores"):src.index(sep + "execucao")]
    cont = {"n_priv": 0, "validos": 0, "hits": []}

    def priv(sec, where):
        if len(sec) != 32:
            return
        cont["n_priv"] += 1
        r = _casa(sec)
        cont["validos"] += r is not None
        if r:
            cont["hits"].append({"where": where, "privkey": sec.hex(), "confirmado_G.priv_hit": G.priv_hit(sec)})

    def test(name, m, fam):  # cópia do braço de privkey de marcadores.test(), sem AES
        mb = ns["as_bytes"](m)
        if not mb:
            return
        priv(G.sha(mb), f"{fam}/{name}/sha256"); priv(G.sha(G.sha(mb)), f"{fam}/{name}/sha256d")
        priv(G.sha(mb.upper()), f"{fam}/{name}/sha256(upper)")
        if len(mb) == 32:
            priv(mb, f"{fam}/{name}/raw32")
        if len(mb) > 32:
            for j in range(len(mb) - 31):
                priv(mb[j:j + 32], f"{fam}/{name}/win{j}")
        t = mb.decode("latin-1")
        if t.isdigit() and int(t) > 0:
            priv(int(t).to_bytes(32, "big")[-32:] if int(t) < 2 ** 256 else b"", f"{fam}/{name}/int")
        if set(t) <= {"0", "1"} and len(t) >= 8:
            priv(int(t, 2).to_bytes(32, "big"), f"{fam}/{name}/bin")
        if len(t) == 64 and all(c in "0123456789abcdefABCDEF" for c in t):
            priv(bytes.fromhex(t), f"{fam}/{name}/hex64")

    ns = {"G": G, "os": os, "itertools": itertools, "random": random, "OUT": str(ORFAO / "marcadores"),
          "as_bytes": lambda m: m if isinstance(m, bytes) else m.encode("latin-1")}
    exec(seg, ns)  # asserts do próprio script: bits 16 b + 7 be, cores, URL, Arquiteto 1.539, 3.2.2
    exec(ger, ns)
    for fam, mats in (("H1", ns["gen_H1"]()),
                      ("H2/H4", {**ns["gen_bits"](ns["B84"], "L84"), **ns["gen_bits"](ns["B83"], "L83")}),
                      ("H3", {**ns["gen_H3"](ns["S84"], "L84"), **ns["gen_H3"](ns["S83"], "L83")}),
                      ("H3iter", ns["gen_iter"]())):
        for name, m in mats.items():
            test(name, m, fam)
    _keep, drop = ns["splits"](ns["S84"], "be")
    after7 = drop[1:]
    for perm in itertools.permutations(range(7)):
        pz = [after7[i] for i in perm]
        for m in ("".join(pz), ns["interleave"](pz)):
            test(f"perm7:{perm}", m, "H3perm")
    n_real = cont["n_priv"]
    rng = random.Random(20260917)
    for it in range(100):
        b = list(ns["B84"])
        rng.shuffle(b)
        for name, m in ns["gen_bits"]("".join(b), "N").items():
            test(f"null{it}:{name}", m, "NULL")
    cont.update(n_real=n_real, n_nulo=cont["n_priv"] - n_real, esperado=MARCADORES_NPRIV,
                reconcilia=cont["n_priv"] == MARCADORES_NPRIV, sha256_marcadores_py=_sha(ORFAO / "marcadores" / "marcadores.py"))
    return cont


# ------------------------------------------------------------------ reprodução da lacuna e controles
def _sintetica(rotulo):
    seg = hashlib.sha256(f"enxame 2026-09-18 orfaos_temp: {rotulo}".encode()).digest()
    pk = PublicKey.from_valid_secret(seg)
    return seg, {c: G._h160_hex(pk.format(c)) for c in (False, True)}, pk.format(False).hex()


def reproduzir_lacuna():
    """Falso negativo concreto do fast_priv_scan histórico (em uso quando as campanhas órfãs rodaram)."""
    src = subprocess.run(["git", "-C", str(REPO), "show",
                          f"{COMMIT_ANTIGO}:solver/experiments/claude_endgame_2026_09_02/gsmg_common.py"],
                         capture_output=True, check=True).stdout.decode("utf-8")
    i = src.index("def fast_priv_scan")
    fonte = src[i:src.index("\ndef ", i + 1)]
    ns = {"TARGET_PUBKEY_HEX": G.TARGET_PUBKEY_HEX}
    exec(fonte, ns)
    hist = ns["fast_priv_scan"]
    seg, h160, pub_unc = _sintetica("reproducao da lacuna")
    filler = hashlib.shake_256(b"orfaos_temp filler").digest(79)
    be = filler[:23] + seg + filler[23 + 32:]
    le = filler[:23] + seg[::-1] + filler[23 + 32:]
    res = {}
    scan._plantar((h160[True],))  # alvo sintético "estilo 17ucy": só o h160 (comprimido) é conhecido
    try:
        res["17ucy_sintetico_BE"] = {"historico": len(hist(be)), "atual": len(G.fast_priv_scan(be)), "frente": len(raw32(be)[1])}
        res["17ucy_sintetico_LE"] = {"historico": len(hist(le)), "atual": len(G.fast_priv_scan(le)), "frente": len(raw32(le)[1])}
    finally:
        scan._desplantar((h160[True],))
    ns["TARGET_PUBKEY_HEX"] = pub_unc  # dá ao histórico a vantagem máxima: a pubkey sintética como alvo
    exec(fonte, ns)
    res["1GSMG_sintetico_pubkey_nao_comprimida"] = {"historico_BE": len(ns["fast_priv_scan"](be)),
                                                    "historico_LE": len(ns["fast_priv_scan"](le))}
    assert res["17ucy_sintetico_BE"] == {"historico": 0, "atual": 1, "frente": 1}, res
    assert res["17ucy_sintetico_LE"] == {"historico": 0, "atual": 0, "frente": 1}, res
    assert res["1GSMG_sintetico_pubkey_nao_comprimida"] == {"historico_BE": 1, "historico_LE": 0}, res
    return {"commit_historico": COMMIT_ANTIGO, "sha256_fonte_fast_priv_scan": hashlib.sha256(fonte.encode()).hexdigest(),
            "casos": res, "conclusao": "o histórico é cego a 17ucy (compara só a pubkey não comprimida de 1GSMG) e a LE; "
                                       "o kit atual cobre 17ucy só em BE; esta frente cobre BE e LE"}


def controle_raw32():
    """Chave sintética plantada em BE e LE, em 79 e 1.327 B, nos offsets 0, ímpar e final; alvo sintético
    só com o h160 comprimido e, à parte, só com o não comprimido. Passa pelo caminho inteiro (trabalhar)."""
    seg, h160, _ = _sintetica("controle raw32")
    casos = []
    for forma in (True, False):
        for tam in (79, 1327):
            filler = hashlib.shake_256(f"filler {tam}".encode()).digest(tam)
            for ordem in ("be", "le"):
                for off in (0, 13, tam - 32):
                    data = filler[:off] + (seg if ordem == "be" else seg[::-1]) + filler[off + 32:]
                    assert not trabalhar([(data, 1)])["hits"], "hit sem alvo plantado"
                    scan._plantar((h160[forma],))
                    try:
                        hits = trabalhar([(data, 1)])["hits"]
                    finally:
                        scan._desplantar((h160[forma],))
                    # em LE a janela invertida é a própria chave: privkey registrada = seg nas duas ordens
                    alvo = [h for h in hits if (h["formato"], h["offset"], h["privkey"]) == (f"raw32-{ordem}", off, seg.hex())]
                    assert alvo and all(h["confirmado_G.priv_hit"] for h in hits), (forma, tam, ordem, off, hits)
                    casos.append({"pubkey": "comprimida" if forma else "nao_comprimida", "len": tam,
                                  "ordem": ordem, "offset": off, "hits": len(hits)})
    assert G.TARGET_H160S == G.O.TARGET_H160S and len(G.TARGET_H160S) == 2
    return {"n": len(casos), "casos": casos}


def controle_alvos():
    """Os dois h160 do kit são os dos endereços do prêmio (base58check)."""
    import base58
    esperado = tuple(base58.b58decode_check(a)[1:].hex() for a in
                     ("1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"))
    assert G.TARGET_H160S == esperado, G.TARGET_H160S
    return {"TARGET_H160S": list(G.TARGET_H160S)}


def controle_brainwallet():
    """sha256 de um material real do marcadores (lit:nd) plantado como alvo é achado pelo braço."""
    sec = G.sha(b"nd")
    h = G._h160_hex(PublicKey.from_valid_secret(sec).format(True))
    scan._plantar((h,))
    try:
        assert _casa(sec) is True
    finally:
        scan._desplantar((h,))
    assert _casa(sec) is False
    return {"material": "lit:nd", "forma": "sha256", "achado_com_alvo_plantado": True}


def rodar_controles():
    c = scan.rodar_controles()  # kit self-test (fase 2 + 3.2.2), chaves nas visões, texto/aninhado, fase 3.2...
    c.update(alvos=controle_alvos(), reproducao_lacuna=reproduzir_lacuna(), raw32_17ucy_sintetico=controle_raw32(),
             brainwallet_plantado=controle_brainwallet())
    return c


# ------------------------------------------------------------------ execução em etapas
# ponytail: a varredura inteira leva ~13 min de parede com 5 processos e cada execução em primeiro plano
# tem teto de 10 min; por isso roda em partes determinísticas (itens ordenados por sha256, fatia k::N),
# cada uma com checkpoint próprio, e a etapa `juntar` reconcilia contagens e impressão multiconjunto.
def _grava(nome, valor):
    with open(OUT / nome, "w", encoding="utf-8") as f:
        json.dump(valor, f, ensure_ascii=False, indent=1)
        f.write("\n")


def _le(nome):
    return json.load(open(OUT / nome, encoding="utf-8"))


def _congelado():
    """Manifesto + extração; confere que as fontes não mudaram desde a etapa preparar."""
    arqs = arquivos_fonte()
    man = manifesto(arqs)
    sha_man = hashlib.sha256(json.dumps(man, sort_keys=True).encode()).hexdigest()
    corpus, origem, tail32, ext = extrair(arqs)
    return man, sha_man, corpus, origem, tail32, ext


def _digest(conteudos):
    return f"{sum(int.from_bytes(hashlib.sha256(b).digest(), 'big') for b in conteudos) % (1 << 256):064x}"


def preparar(head, hashes):
    t0 = time.monotonic()
    controles = rodar_controles()
    controles["hashes"] = hashes
    _grava("controls.json", controles)
    print("controles OK:", controles["reproducao_lacuna"]["casos"], "| raw32:", controles["raw32_17ucy_sintetico"]["n"],
          "casos", flush=True)
    man, sha_man, corpus, _origem, tail32, ext = _congelado()
    print("extração:", json.dumps(ext, ensure_ascii=False), flush=True)
    _novos, sob = sobreposicao(corpus, tail32)
    print("sobreposição:", json.dumps(sob["uniao_A+B"], ensure_ascii=False), flush=True)
    bw = brainwallet()
    print("brainwallet:", {k: bw[k] for k in ("n_priv", "n_real", "n_nulo", "validos", "reconcilia")},
          "hits:", len(bw["hits"]), flush=True)
    _grava("prep.json", {"commit": head, "hashes": hashes, "sha256_do_manifesto": sha_man, "manifesto": man,
                         "extracao": ext, "sobreposicao": sob, "brainwallet_marcadores": bw,
                         "total": {"conteudos": len(corpus), "bytes": sum(map(len, corpus)),
                                   "raw32_janelas_BE+LE": 2 * sum(max(0, len(b) - 31) for b in corpus),
                                   "impressao_multiconjunto": _digest(corpus)},
                         "segundos": round(time.monotonic() - t0, 1)})


def varrer_parte(k, n, workers, lote, limite):
    prep = _le("prep.json")
    controle_raw32()  # o caminho dos filhos (trabalhar) ainda acha a chave plantada nesta execução
    _man, sha_man, corpus, origem, _t, _e = _congelado()
    assert sha_man == prep["sha256_do_manifesto"], "fontes mudaram desde a etapa preparar"
    itens = sorted(corpus.items(), key=lambda kv: hashlib.sha256(kv[0]).digest())[k::n][: limite or None]
    del corpus
    tot = varrer(itens, origem, workers, lote, OUT / f"candidates_parte{k}de{n}.jsonl")
    tot.update(parte=k, partes=n, esperado=len(itens), limite=limite, sha256_do_manifesto=sha_man,
               digest=f"{tot['digest']:064x}", **{c: dict(tot[c]) for c in CONTA})
    _grava(f"parte{k}de{n}.json", tot)
    print(f"parte {k}/{n}: {tot['n']:,} conteúdos, {tot['raw32_janelas']:,} janelas, candidatos={tot['candidatos']}, "
          f"hits={len(tot['hits'])}, {tot['segundos']} s", flush=True)


def _partes_presentes():
    """Partes k::n gravadas; as classes residuais precisam cobrir cada resto módulo o mmc exatamente uma vez
    (ex.: 0/4, 1/4, 2/8, 6/8, 3/8, 7/8 — a 2/4 e a 3/4 rodaram em metades para caber em 10 min cada)."""
    partes = [_le(Path(p).name) for p in sorted(glob.glob(str(OUT / "parte*de*.json")))]
    mmc = 1
    for p in partes:
        mmc = mmc * p["partes"] // __import__("math").gcd(mmc, p["partes"])
    cobre = Counter(r for p in partes for r in range(mmc) if r % p["partes"] == p["parte"])
    assert partes and all(cobre[r] == 1 for r in range(mmc)), ("partição incompleta ou sobreposta", dict(cobre))
    return partes


REGRAS_TRIAGEM = (  # só reclassificam "a examinar: motivo na visão original", pela origem gravada
    (lambda o: o["arquivo"].endswith("f5_retro_ebcdic.json"),
     "não-AES: prefixo de 80 B de material de senha de _work gravado pela forense f5 (texto por construção)"),
    (lambda o: o.get("blob") == "CONTROL", "controle positivo sintético da campanha original (select256)"),
)


def _triagem_final(c):
    if c["triagem"].startswith("a examinar: motivo na visão original"):
        for regra, rotulo in REGRAS_TRIAGEM:
            if regra(c["origem"]):
                return rotulo
    return c["triagem"]


def juntar(_n):
    prep = _le("prep.json")
    partes = _partes_presentes()
    assert all(not p["limite"] and p["n"] == p["esperado"] and
               p["sha256_do_manifesto"] == prep["sha256_do_manifesto"] for p in partes), "parte incompleta ou de outra rodada"
    tot = {k: sum(p[k] for p in partes) for k in SOMA}
    for c in CONTA:
        tot[c] = Counter()
        for p in partes:
            tot[c].update(p[c])
    digest = f"{sum(int(p['digest'], 16) for p in partes) % (1 << 256):064x}"
    rec = {"conteudos": tot["n"] == prep["total"]["conteudos"], "bytes": tot["bytes"] == prep["total"]["bytes"],
           "janelas": tot["raw32_janelas"] == prep["total"]["raw32_janelas_BE+LE"],
           "impressao_multiconjunto": digest == prep["total"]["impressao_multiconjunto"]}
    assert all(rec.values()), rec
    hits = [h for p in partes for h in p["hits"]]
    final = Counter()
    with open(OUT / "candidates.jsonl", "w", encoding="utf-8") as f:
        for p in partes:
            arq = OUT / f"candidates_parte{p['parte']}de{p['partes']}.jsonl"
            for linha in arq.read_text(encoding="utf-8").splitlines():
                c = json.loads(linha)
                c["triagem_final"] = _triagem_final(c)
                final[c["triagem_final"]] += 1
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
            arq.unlink()
    assert sum(final.values()) == tot["candidatos"], (final, tot["candidatos"])
    for h in hits:
        h["classe"] = "CANDIDATO: exige proof-certificate (AGENTS.md, regra 1)"
    summary = {
        "frente": "orfaos_temp", "status": "completo", "hipotese": "auditoria-01, camadas A+B",
        "commit": prep["commit"], "hashes": prep["hashes"],
        "manifesto_fontes": {"raiz": str(ORFAO), "arquivos": len(prep["manifesto"]),
                             "bytes": sum(v["bytes"] for v in prep["manifesto"].values()),
                             "sha256_do_manifesto": prep["sha256_do_manifesto"], "itens": prep["manifesto"]},
        "extracao": prep["extracao"], "sobreposicao": prep["sobreposicao"],
        "cobertura": {"conteudos_varridos": tot["n"], "bytes": tot["bytes"], "raw32_janelas_BE+LE": tot["raw32_janelas"],
                      "raw32_escalares_validos": tot["raw32_validos"], "impressao_multiconjunto": digest,
                      "definicao_impressao": "Σ sha256(conteúdo) mod 2^256", "reconciliacao_com_a_extracao": rec,
                      "partes": [f"{p['parte']}/{p['partes']}" for p in partes], "visoes": ["original", "cp273-inverse", "cp273", "utf-16-le@0", "utf-16-le@1",
                                              "utf-16-be@0", "utf-16-be@1"],
                      "tentativas_hex64_wif": dict(sorted(tot["tent"].items())),
                      "escalares_validos_hex64_wif": tot["validos_hexwif"]},
        "hits": hits, "motivos_visao_original_por_familia": dict(sorted(tot["orig"].items())),
        "motivos_por_visao": dict(sorted(tot["motivos"].items())),
        "motivos_novos_por_visao": dict(sorted(tot["novos"].items())),
        "conteudos_candidatos": tot["candidatos"], "triagem_dos_candidatos": dict(tot["triagem"]),
        "triagem_final": dict(final),
        "candidatos_a_examinar": sum(v for k, v in final.items() if k.startswith(("a examinar", "HIT"))),
        "conteudos_so_com_motivos_explicados_pela_original": tot["artefatos"],
        "brainwallet_marcadores": prep["brainwallet_marcadores"], "aes_novos": 0,
        "script_no_juntar_sha256": _sha(Path(__file__)),
        "nota_script": "prep.json e as partes 0/4 e 1/4 rodaram com o sha256 em hashes; depois só mudaram o nome dos "
                       "arquivos de parte (parte<k>de<n>) e o juntar (partição mista e triagem_final). trabalhar/raw32 "
                       "e processar não mudaram.",
        "fora_de_escopo": {"camada_C": "outras 11 cifras (premissa refutada em §4-D)",
                           "camada_D": "12.754.752 montagens e 660.828 'best' (premissa refutada em §4-D)",
                           "TAIL32_aes-256-cbc": "medido em sobreposicao; 100 % nos corpora já varridos"},
        "segundos": {"preparar": prep["segundos"], "partes": [p["segundos"] for p in partes]},
        "fim_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "solucao_declarada": False,
    }
    _grava("summary.json", summary)
    print(json.dumps({k: summary[k] for k in ("status", "cobertura", "conteudos_candidatos", "triagem_dos_candidatos",
                                              "motivos_novos_por_visao")}, ensure_ascii=False), flush=True)
    print("HITS:", len(hits), "| brainwallet hits:", len(prep["brainwallet_marcadores"]["hits"]), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--etapa", choices=("preparar", "varrer", "juntar"), required=True)
    ap.add_argument("--parte", type=int, default=0)
    ap.add_argument("--partes", type=int, default=4)
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--lote", type=int, default=100)
    ap.add_argument("--limite", type=int, default=0, help="só os N primeiros itens da parte (ensaio)")
    a = ap.parse_args()
    if not 1 <= a.workers <= 5:
        ap.error("no máximo 5 processos: outras frentes rodam em paralelo")
    if not 0 <= a.parte < a.partes:
        ap.error("--parte fora de [0, --partes)")
    OUT.mkdir(parents=True, exist_ok=True)
    if a.etapa == "preparar":
        fontes = [Path(__file__), AQUI.parent / "lacuna_cp273_utf16" / "scan.py", scan.KIT_DIR / "gsmg_common.py",
                  REPO / "solver" / "oracles.py", scan.ORACULO_DUPLO / "oracle.py"]
        hashes = {str(p.relative_to(REPO)): _sha(p) for p in fontes}
        head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        preparar(head, hashes)
    elif a.etapa == "varrer":
        varrer_parte(a.parte, a.partes, a.workers, a.lote, a.limite)
    else:
        juntar(a.partes)


if __name__ == "__main__":
    main()
