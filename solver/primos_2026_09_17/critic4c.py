# -*- coding: utf-8 -*-
"""Critico, parte 3.
(F) familia ESTENDIDA do casamento bits<->cores: ordens {espiral, espiral reversa, linha, coluna, por byte da URL}
    x subconjuntos {25 omitir 2 (W=B|Y), 24 sem W omitir 1, 25 omitir 1 + W removido} x polaridade x L83/L84 -> p familiar;
(G) lacuna: somas dos 24 pedacos do residuo entre marcadores (a=1..9 e a=0..8), 23 pedacos por b, 8 por be, em L83/L84,
    comparadas com as somas da matriz (igualdade/sub-sequencia) e como senha (5 serializacoes, crua+sha256, 3 blobs x 2 KDF)
    e z-method -> privkey."""
import sys, os, json, random, math, itertools
from collections import Counter
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from critic4 import segment, SCHEMES, PR
LOG = os.path.join(HERE, "critic4c.jsonl"); out = {}
tot, paths = segment(G.DBBI, "b", "e", SCHEMES["prime1"], want_paths=True)
SEGS = {len(p): p for p in paths}
bits = {L: "".join("1" if t == "be" else "0" for k, t in enumerate(p, 1) if k in PR) for L, p in SEGS.items()}

# ---------------- (F)
ev = sorted(G.COLORED.items())  # (idx, (cor, r, c))
orders = {"espiral": ev, "espiral_rev": ev[::-1], "linha": sorted(ev, key=lambda e: (e[1][1], e[1][2])),
          "coluna": sorted(ev, key=lambda e: (e[1][2], e[1][1]))}
reach = {}
for on, o in orders.items():
    cols = [v[0] for _, v in o]
    for W in "BY":
        cs = [W if c == "W*" else c for c in cols]
        for om in itertools.combinations(range(25), 2):
            s = "".join("1" if cs[i] == "Y" else "0" for i in range(25) if i not in om); reach.setdefault(s, []).append((on, W, om))
    cs = [c for c in cols if c != "W*"]  # 24 sem W, omitir 1
    for om in range(24):
        s = "".join("1" if cs[i] == "Y" else "0" for i in range(24) if i != om); reach.setdefault(s, []).append((on, "noW", (om,)))
n_conf = len(orders) * (2 * 300 + 24)
matches = {}
for L, b in bits.items():
    for pol, tgt in (("be=1", b), ("be=0", "".join("1" if c == "0" else "0" for c in b))):
        if tgt in reach: matches[f"L{L}/{pol}"] = [(a, w, tuple(x+1 for x in om)) for a, w, om in reach[tgt]]
def cnt(k): return sum(1 for s in reach if s.count("1") == k)
p = (cnt(7) + cnt(16)) / math.comb(23, 7) + (cnt(8) + cnt(15)) / math.comb(23, 8)
out["F_bits_cores_estendido"] = {"n_configs": n_conf, "distintas": len(reach), "matches": matches, "p_familia": p}
print("(F)", json.dumps(out["F_bits_cores_estendido"]))

# ---------------- (G)
rs = G.row_sums(G.MATRIX_README); cs_ = G.col_sums(G.MATRIX_README); MS = {"rows": rs, "cols": cs_, "rowcol": rs + cs_, "colrow": cs_ + rs}
def chunks(p, kind):
    """pedacos do residuo entre marcadores: kind='all' (23 marcadores -> 24 pedacos), 'b' (so b), 'be' (so be)."""
    res = [[]]
    for k, t in enumerate(p, 1):
        if k in PR:
            if kind == "all" or (kind == "b" and t == "b") or (kind == "be" and t == "be"): res.append([])
            elif kind == "be": res[-1].append(t[0])  # 'b' vira simbolo comum? nao: markers nao entram no residuo
            continue
        res[-1].append(t)
    return ["".join(c) for c in res]
n_aes = 0; n_priv = 0; hard = []; eq = []; ser = 0
def serial(v): return {"sp": " ".join(map(str, v)), "cm": ",".join(map(str, v)), "cat": "".join(map(str, v)),
                       "hex": "".join(f"{x:02x}" for x in v), "z": G.z_method([int(c) for c in "".join(map(str, v))]) if any(v) else b""}
for L, p in SEGS.items():
    for kind in ("all", "b", "be"):
        ch = chunks(p, kind)
        for base in (1, 0):
            sums = [sum(ord(c) - 97 + base for c in x) for x in ch]
            for name, v in (("sums", sums), ("sums_rev", sums[::-1]), ("lens", [len(x) for x in ch])):
                for mn, ms in MS.items():
                    if v == ms or (len(v) >= 5 and "".join(map(chr, [x+48 for x in v])) in "".join(map(chr, [x+48 for x in ms]))):
                        eq.append((L, kind, base, name, mn))
                for sn, s in serial(v).items():
                    ser += 1
                    for pw in (s, G.shahex(s)):
                        h, soft = G.try_password_all(pw); n_aes += 6
                        if h: hard.append((L, kind, base, name, sn, [x["head"] for x in h]))
                    b = s if isinstance(s, bytes) else s.encode()
                    for k in (G.sha(b), G.sha(G.sha(b))):
                        n_priv += 1
                        if G.priv_hit(k): hard.append((L, kind, base, name, sn, "PRIV"))
                    if isinstance(s, bytes) and len(s) >= 32:
                        n_priv += len(s) - 31
                        if G.fast_priv_scan(s): hard.append((L, kind, base, name, sn, "PRIVWIN"))
ex = chunks(SEGS[84], "all")
out["G_somas_pedacos"] = {"exemplo_L84_all": ex, "somas_L84_all_a1": [sum(ord(c)-96 for c in x) for x in ex],
                         "igualdades_com_somas_matriz": eq, "n_serializacoes": ser, "n_aes": n_aes, "n_priv": n_priv, "hard": hard}
print("(G)", json.dumps(out["G_somas_pedacos"]))
json.dump(out, open(os.path.join(HERE, "summary_c.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
G.jsonl(LOG, {"hipotese": "critico parte 3: familia estendida bits/cores; somas dos pedacos do residuo como lista/senha", "resultado": out})
