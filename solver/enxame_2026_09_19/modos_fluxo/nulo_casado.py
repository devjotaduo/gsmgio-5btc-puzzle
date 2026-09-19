#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nulo casado da frente F1 (modos_fluxo), enxame 2026-09-19.

Não há scorer de quadgramas neste clone (`result.json` ausente => solver/scorer.py e
clean_scorer.py quebram). O único critério estrutural de triagem usado pela frente é
`G.semantic` (printable >= 0,85, blob aninhado, assinatura EBCDIC cp273, WIF/hex64).
Este nulo mede a distribuição desse critério sob senhas ALEATÓRIAS, com exatamente o
mesmo número de senhas e de decifrações da varredura real (3 blobs x 5 modos x 2 KDF),
para que o máximo observado seja comparável sem viés de tamanho de amostra.

Uso: python3 nulo_casado.py --n 1750 --out <dir>
"""
import argparse
import json
import os
import random
import sys

from Crypto.Hash import MD5, SHA256

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.abspath(os.path.join(HERE, "..", "..", "experiments", "claude_endgame_2026_09_02"))
sys.path.insert(0, KIT)
sys.path.insert(0, HERE)
import gsmg_common as G  # noqa: E402
from stream_scan import MODOS, BLOBS, stream_decrypt  # noqa: E402

KDFS = (("sha256", SHA256), ("md5", MD5))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1750)
    ap.add_argument("--seed", type=int, default=20260919)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    vals = []
    por_blob = {b: [] for b in BLOBS}
    semanticos = nested = ebcdic = 0
    for _ in range(a.n):
        pw = bytes(rnd.randrange(256) for _ in range(rnd.randrange(8, 40)))
        for b in BLOBS:
            salt, ct = G.BLOBS[b]
            for _nome, hm in KDFS:
                k, iv = G.evp(pw, salt, hm)
                for modo in MODOS:
                    p = stream_decrypt(modo, k, iv, ct)
                    pr = G.printable(p)
                    vals.append(pr)
                    por_blob[b].append(pr)
                    if G.semantic(p):
                        semanticos += 1
                    if G.nested_blob(p):
                        nested += 1
                    if G.ebcdic_sig(p) >= 0.75:
                        ebcdic += 1
    vals.sort()
    res = {"senhas": a.n, "decifracoes": len(vals), "seed": a.seed,
           "printable_media": round(sum(vals) / len(vals), 4),
           "printable_max": round(vals[-1], 4),
           "printable_p99": round(vals[int(0.99 * len(vals))], 4),
           "printable_p999": round(vals[int(0.999 * len(vals))], 4),
           "max_por_blob": {b: round(max(v), 4) for b, v in por_blob.items()},
           "semanticos_thr085": semanticos, "blob_aninhado": nested, "ebcdic_sig_075": ebcdic}
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "final_qa.json"), "w") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
