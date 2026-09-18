# -*- coding: utf-8 -*-
"""Pipeline ordenado do roadmap (fora da caixa, 2026-09-18).

O roadmap do criador (binário invertido, 2023-02-23) é:
  yellowblueprimes  matrixsumlist  lastwordsbeforearchichoice  yinyang
  wewontgiveawaythepassword  itsinfrontofyoureyesbutyourenotseeingit  verylaststepisatruegiveaway

Os 4 primeiros são operacionais; os 3 últimos são meta-comentário ("não damos a senha", "está na
frente dos seus olhos", "último passo é uma doação"). Tudo foi testado TOKEN A TOKEN (ENDGAME §4-B,
§6). O que nunca se fez: encadear, a saída de um passo virando a entrada do próximo, terminando em
`yinyang` que funde o lado dbbi com faed e emite o PAR de chaves (1GSMG + 17ucy).

Passos:
 1. yellowblueprimes  — dado inicial = resíduo de dbbi (L84/L83, comprovado em §6) ou dbbi inteiro.
 2. matrixsumlist     — operador: as 28 somas da matriz sobre a lista (add mod, concatenar, selecionar).
 3. lastwords…        — keystream: "lastwordsbeforearchichoice"/"thispassword"/"matrixsumlist" (a1z26)
                        somado à lista.
 4. yinyang           — funde o lado dbbi (lista final) com faed e reduz a 32 B cada; critério do PAR.

Critério do par (par_half_betterhalf): a MESMA composição dá {addr(k_dbbi), addr(k_faed)} ⊇
{1GSMG, 17ucy} (inclui cruzado). Falso positivo ~2^-320, então a cascata pode ser varrida sem ruído.
Uso: python pipeline_roadmap.py
"""
import hashlib, json, sys
from itertools import product
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI))
import par_half_betterhalf as P  # noqa: E402  (N, SOMAS, RESID_*, GSMG, UCY, TGT, h160, addr_de)

N, SOMAS = P.N, P.SOMAS
OUT = P.REPO / "_work" / "half_betterhalf_2026-09-18"
A1Z26 = {chr(97 + i): i + 1 for i in range(26)}
SOMA_DIGS = [int(d) for d in "".join(str(x) for x in SOMAS)]        # 6,1,0,8,7,...
KEYS = {"lastwords": "lastwordsbeforearchichoice", "thispassword": "thispassword",
        "matrixsumlist": "matrixsumlist"}


def dig(s):
    """símbolos a-i,o -> dígitos 0-9 (a=1..i=9, o=0)."""
    m = {**{c: i + 1 for i, c in enumerate("abcdefghi")}, "o": 0}
    return [m[c] for c in s if c in m]


# ------------------------------------------------------------------ passo 1: yellowblueprimes
def passo1():
    return {"resid_L84": dig(P.RESID_L84), "resid_L83": dig(P.RESID_L83), "dbbi": dig(P.G.DBBI)}


# ------------------------------------------------------------------ passo 2: matrixsumlist
def passo2(L):
    yield "none", L
    yield "add10", [(x + SOMAS[i % len(SOMAS)]) % 10 for i, x in enumerate(L)]
    yield "sub10", [(x - SOMAS[i % len(SOMAS)]) % 10 for i, x in enumerate(L)]
    yield "concat_pre", SOMA_DIGS + L
    yield "concat_post", L + SOMA_DIGS
    if L:
        yield "select", [L[SOMAS[i % len(SOMAS)] % len(L)] for i in range(len(SOMAS))]


# ------------------------------------------------------------------ passo 3: lastwords keystream
def passo3(L):
    yield "none", L
    for kn, kw in KEYS.items():
        kd = [A1Z26[c] for c in kw]
        yield f"add:{kn}", [(x + kd[i % len(kd)]) % 10 for i, x in enumerate(L)]


# ------------------------------------------------------------------ passo 4: yinyang -> par
def escalares_faed():
    """O lado faed, reduzido a 32 B por leituras 'yinyang' (metades) e diretas."""
    fd = dig(P.G.FAED)
    h = len(fd) // 2
    metades = {"faed": fd, "faed_rev": fd[::-1],
               "faed_xor_meias": [(a ^ b) for a, b in zip(fd[:h], fd[h:2 * h])],
               "faed_h1": fd[:h], "faed_h2": fd[h:2 * h]}
    out = {}
    for nome, L in metades.items():
        s = "".join(str(x) for x in L)
        out[f"{nome}/int10"] = int(s, 10) % N
        out[f"{nome}/sha"] = int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % N
    return {k: v.to_bytes(32, "big") for k, v in out.items()}


def reduzir(L):
    """lista de dígitos -> {como: escalar 32 B} (o lado dbbi depois dos 3 passos)."""
    s = "".join(str(x) for x in L)
    out = {"int10": int(s, 10) % N if s else 0,
           "sha": int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % N}
    return {k: v.to_bytes(32, "big") for k, v in out.items() if 0 < v < N}


FAED = None


def par(sec_d):
    """addr do lado dbbi e de cada leitura faed; True se juntos cobrem os dois alvos."""
    ad = P.addr_de(sec_d)
    for fn, sf in FAED.items():
        juntos = ad | P.addr_de(sf)
        if P.GSMG in juntos and P.UCY in juntos:
            return {"faed_leitura": fn, "dbbi_da": sorted(ad), "faed_da": sorted(P.addr_de(sf))}
    return None


def controle():
    """Planta os h160 de dois secrets como alvos e confirma que a fusão do par dispara."""
    global FAED
    sd = hashlib.sha256(b"pipe-d").digest()
    sf = hashlib.sha256(b"pipe-f").digest()
    P.TGT[P.h160(P.PublicKey.from_valid_secret(sd).format(True))] = P.GSMG
    hf = P.h160(P.PublicKey.from_valid_secret(sf).format(False))
    P.TGT[hf] = P.UCY
    FAED = {"plantado": sf}
    try:
        ok = par(sd)
    finally:
        for h in [h for h, a in list(P.TGT.items()) if a in (P.GSMG, P.UCY) and h not in
                  {bytes.fromhex(x) for x in P.G.O.TARGET_H160S}]:
            del P.TGT[h]
    assert ok, "controle do pipeline falhou"
    return {"fusao_do_par_ok": True}


def main():
    global FAED
    OUT.mkdir(parents=True, exist_ok=True)
    ctl = controle()
    FAED = escalares_faed()
    hits, n_pipelines = [], 0
    for p1n, L1 in passo1().items():
        for p2n, L2 in passo2(L1):
            for p3n, L3 in passo3(L2):
                for rn, sec in reduzir(L3).items():
                    n_pipelines += 1
                    got = par(sec)
                    if got:
                        hits.append({"pipeline": f"{p1n}|{p2n}|{p3n}|{rn}", **got})
    res = {"roadmap": "yellowblueprimes -> matrixsumlist -> lastwords -> yinyang (encadeado)",
           "controle": ctl, "pipelines_testados": n_pipelines,
           "leituras_faed": list(FAED), "criterio": "par: {addr(dbbi), addr(faed)} superset {1GSMG, 17ucy}",
           "hits": hits, "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(res, open(OUT / "pipeline_summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
