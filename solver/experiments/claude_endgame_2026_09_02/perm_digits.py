# -*- coding: utf-8 -*-
"""Hipótese: a-i são 9 dígitos com atribuição DESCONHECIDA (permutação); dbbi/faed são números em base 9
(ou base 10 sem um dígito). dbbi em base 9 = 288 bits = 36 B = chave32 + checksum4 (Base58Check sem versão)?
Espaço: 9! × {base9, base10} × {direto, reverso} × {dbbi, faed, faed_np}. Oráculos: checksum sha256d,
printable ≥0.85, privkey (coincurve) em janelas de dbbi."""
import sys, itertools, hashlib, time, json
sys.path.insert(0, ".")
import gsmg_common as G
from coincurve import PublicKey
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
def is_target(sec):
    try: return PublicKey.from_valid_secret(sec).format(False) == TGT
    except Exception: return False
srcs = {"dbbi": G.DBBI, "faed": G.FAED, "faed_np": G.FAED[4:]}
idx = {k: [ord(c) - 97 for c in v] for k, v in srcs.items()}
t0 = time.time(); n = 0; hits = []; best_print = {}
pow9 = {}
for name, ix in idx.items():
    L = len(ix)
    # precompute positional weights for base 9 and 10 (direct and reversed)
    W = {("b9", "fwd"): [9 ** (L - 1 - i) for i in range(L)], ("b9", "rev"): [9 ** i for i in range(L)],
         ("b10", "fwd"): [10 ** (L - 1 - i) for i in range(L)], ("b10", "rev"): [10 ** i for i in range(L)]}
    # per-symbol weight sums: value = sum_over_symbols digit(sym) * S[sym]
    S = {}
    for key, w in W.items():
        s = [0] * 9
        for i, sym in enumerate(ix): s[sym] += w[i]
        S[key] = s
    for perm in itertools.permutations(range(9)):
        for key, s in S.items():
            val = sum(perm[sym] * s[sym] for sym in range(9))
            b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big"); n += 1
            pr = G.printable(b)
            if pr > best_print.get((name, key), (0,))[0]: best_print[(name, key)] = (round(pr, 3), perm, b[:40])
            if pr >= 0.85: hits.append(("printable", name, key, perm, b[:80].decode("latin-1")))
            if name == "dbbi":
                if len(b) >= 36:
                    for off in range(0, len(b) - 35):
                        k32, chk = b[off:off + 32], b[off + 32:off + 36]
                        if hashlib.sha256(hashlib.sha256(k32).digest()).digest()[:4] == chk:
                            hits.append(("checksum", name, key, perm, b.hex()))
                for off in range(0, len(b) - 31):
                    if is_target(b[off:off + 32]): hits.append(("PRIVKEY", name, key, perm, b.hex()))
print("n", n, "time", round(time.time() - t0), "hits", hits[:20])
for k, v in sorted(best_print.items()): print(k, v[0], v[1], v[2])
G.jsonl("perm_digits.jsonl", {"family": "perm_digits", "n_tests": n, "hits": [list(map(str, h)) for h in hits], "best_printable": {str(k): [v[0], list(v[1])] for k, v in best_print.items()}})
