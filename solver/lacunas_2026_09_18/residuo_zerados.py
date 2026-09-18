# -*- coding: utf-8 -*-
"""O último buraco enumerável do fluxo de §6: "some characters need to be zeroed out" (2026-09-18).

O criador disse (2021-12-26) que "prime numbers … definitely required" e que "some characters need to
be 'zeroed out'". Os primos já são o `yellowblueprimes` (fato provado). Falta a zeragem. O histórico
varreu zerar UM e DOIS tipos de símbolo; três ou mais nunca foi coberto no alfabeto literal.

O espaço inteiro é pequeno: 2^9 = 512 subconjuntos de {a..i}, e aqui TODOS rodam (os de 0, 1 e 2 tipos
inclusive, para reconciliar com o histórico), em L84 e L83, na ordem publicada e invertida.

Por zeragem, três leituras, todas com oráculo duro:
  1. método literal da página: dígitos -> decimal -> To_Base(16) -> From_Hex -> bytes (texto?);
  2. chave privada: o decimal mod n, sha256 da string de dígitos e sha256 dos bytes, contra os DOIS
     alvos, pubkey comprimida e não comprimida;
  3. par (par_half_betterhalf): a leitura do resíduo com cada leitura de faed cobrindo {1GSMG, 17ucy}.
Controles: um texto ASCII plantado é detectado pelo leitor da página; um h160 plantado é achado pelo
oráculo de chave.
Uso: python residuo_zerados.py
"""
import hashlib, json, sys
from itertools import combinations
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI))
sys.path.insert(0, str(AQUI.parents[1] / "solver" / "primos_2026_09_17"))
import par_half_betterhalf as P  # noqa: E402
import pipeline_roadmap as PIPE  # noqa: E402
import clean_scorer  # noqa: E402

N = P.N
OUT = P.REPO / "_work" / "half_betterhalf_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
NUM = {c: i + 1 for i, c in enumerate("abcdefghi")}
ALFA = "abcdefghi"


def digitos(R, zerados):
    return "".join("0" if c in zerados else str(NUM[c]) for c in R)


def bytes_da_pagina(s):
    """decimal -> hex -> bytes (o método que decodificou lastwords/thispassword)."""
    n = int(s)
    if n == 0:
        return b""
    h = format(n, "x")
    return bytes.fromhex(("0" + h) if len(h) % 2 else h)


def chaves(s, b):
    """Escalares que a zeragem rende."""
    out = {}
    n = int(s) % N if s.strip("0") else 0
    if 0 < n < N:
        out["decimal_mod_n"] = n.to_bytes(32, "big")
    out["sha256_digitos"] = hashlib.sha256(s.encode()).digest()
    if b:
        out["sha256_bytes"] = hashlib.sha256(b).digest()
    return out


def controles():
    # (a) leitor da página detecta texto ASCII plantado
    alvo = b"THEPRIVATEKEY"
    s = str(int.from_bytes(alvo, "big"))
    assert bytes_da_pagina(s) == alvo, "leitor da página falhou"
    # (b) oráculo de chave acha um h160 plantado
    sec = hashlib.sha256(b"zerados-controle").digest()
    h = P.h160(P.PublicKey.from_valid_secret(sec).format(True))
    P.TGT[h] = "PLANTADO"
    try:
        achou = "PLANTADO" in P.addr_de(sec)
    finally:
        del P.TGT[h]
    assert achou and len(P.TGT) == 2, "oráculo de chave falhou"
    return {"leitor_da_pagina_ok": True, "oraculo_de_chave_ok": True}


def main():
    sc = clean_scorer.Scorer()
    ctl = controles()
    PIPE.FAED = PIPE.escalares_faed()
    hits, textos = [], []
    n_zer = n_chaves = 0
    melhor_pr = {"printable": 0.0}
    por_tamanho = {k: 0 for k in range(10)}
    for k in range(10):
        for zer in combinations(ALFA, k):
            zer = set(zer)
            por_tamanho[k] += 1
            for nome, R in (("L84", R84), ("L83", R83)):
                for ordem, S in (("dir", R), ("rev", R[::-1])):
                    s = digitos(S, zer)
                    if not s.strip("0"):
                        continue
                    n_zer += 1
                    b = bytes_da_pagina(s)
                    if b:
                        pr = sum(32 <= x < 127 for x in b) / len(b)
                        if pr > melhor_pr["printable"]:
                            melhor_pr = {"printable": round(pr, 3), "zerados": "".join(sorted(zer)),
                                         "variante": f"{nome}/{ordem}", "latin1": b.decode("latin-1")}
                        if pr >= 0.85:
                            t = "".join(chr(x) for x in b if 32 <= x < 127)
                            textos.append({"zerados": "".join(sorted(zer)), "variante": f"{nome}/{ordem}",
                                           "printable": round(pr, 3), "texto": b.decode("latin-1"),
                                           "escore_limpo": round(sc(t.upper()), 3) if t else None})
                    for como, sec in chaves(s, b).items():
                        n_chaves += 1
                        ad = P.addr_de(sec)
                        if ad:
                            hits.append({"zerados": "".join(sorted(zer)), "variante": f"{nome}/{ordem}",
                                         "como": como, "alvos": sorted(ad), "sec": sec.hex()})
                        for fn, sf in PIPE.FAED.items():   # critério do par
                            juntos = ad | P.addr_de(sf)
                            if P.GSMG in juntos and P.UCY in juntos:
                                hits.append({"par": True, "zerados": "".join(sorted(zer)),
                                             "variante": f"{nome}/{ordem}", "como": como, "faed": fn})
    res = {"hipotese": "'some characters need to be zeroed out' sobre o resíduo de §6",
           "espaco": {"subconjuntos_de_simbolos": sum(por_tamanho.values()), "por_tamanho": por_tamanho,
                      "leituras_de_zeragem": n_zer, "escalares_testados": n_chaves,
                      "cobre_o_historico": "tamanhos 0, 1 e 2 inclusos para reconciliar"},
           "controles": ctl, "hits_de_chave_ou_par": hits,
           "textos_printable_ge_085": textos, "melhor_printable": melhor_pr,
           "referencia_escore_ingles": round(sc("INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALF"), 3),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(res, open(OUT / "residuo_zerados.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "textos_printable_ge_085"}, ensure_ascii=False, indent=1))
    print("textos com printable >= 0.85:", len(textos))
    for t in sorted(textos, key=lambda x: -(x["escore_limpo"] or -99))[:5]:
        print(" ", t)


if __name__ == "__main__":
    main()
