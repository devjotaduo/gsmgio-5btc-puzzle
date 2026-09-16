# -*- coding: utf-8 -*-
"""
brainwallet parte 2 — "in front of your eyes" LITERAL: a frase NAO e hasheada.
1) bytes ASCII da frase (>=32) usados diretamente como privkey (primeiros 32 B,
   ultimos 32 B, e frase curta padded com \\x00 a esquerda/direita);
2) frase que seja hex64 -> bytes;
3) frase base58/WIF -> bytes.
Mesmo oraculo duro de brainwallet.py.
"""
import sys, os, re, json, hashlib, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gsmg_common as G
import brainwallet as B

LOG = os.path.join(HERE, "brainwallet.jsonl")

def main():
    corpus = B.build_corpus()
    n = 0; hard = []
    t0 = time.time()
    for p in corpus:
        for f in B.forms(p):
            bs = f.encode("utf-8", "replace")
            cands = []
            if len(bs) >= 32:
                cands += [bs[:32], bs[-32:]]
            else:
                cands += [bs.rjust(32, b"\x00"), bs.ljust(32, b"\x00"),
                          bs.rjust(32, b" "), bs.ljust(32, b" ")]
            s = f.strip()
            if re.fullmatch(r"[0-9a-fA-F]{64}", s):
                cands.append(bytes.fromhex(s))
            if len(bs) >= 32:
                cands.append(hashlib.sha256(bs).digest()[::-1])  # espelho byte-reverse
            for k in cands:
                n += 1
                r = B.key_hits(k)
                if r:
                    r.update({"phrase": p, "form": f, "mode": "rawbytes"})
                    hard.append(r); G.jsonl(LOG, {"HARD2": r}); print("HARD", r)
    out = {"family": "brainwallet/part2-rawbytes", "n_tests": n, "n_hard": len(hard),
           "elapsed_s": round(time.time() - t0, 1)}
    G.jsonl(LOG, {"SUMMARY2": out}); print(json.dumps(out))

if __name__ == "__main__":
    main()
