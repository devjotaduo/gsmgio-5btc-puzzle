import sys
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
srcs = {"dbbi": G.DBBI, "faed": G.FAED, "dbbi+faed": G.DBBI + G.FAED, "faed+dbbi": G.FAED + G.DBBI,
        "faedA": G.FAED[:285], "faedB": G.FAED[285:]}
n = 0; best = []
for name, s in srcs.items():
    for rev in (False, True):
        t = s[::-1] if rev else s
        for base, off in ((9, 0), (10, 1), (10, 0), (16, 0), (16, 1), (26, 0), (26, 1)):
            digs = [ord(c) - 97 + off for c in t]
            if max(digs) >= base: continue
            v = 0
            for d in digs: v = v * base + d
            h = format(v, "x"); h = "0" * (len(h) % 2) + h
            by = bytes.fromhex(h)
            for bb in (by, by[::-1]):
                n += 1
                pr = G.printable(bb)
                hits = G.fast_priv_scan(bb, f"{name} rev{rev} b{base} o{off}")
                hard, soft = G.try_password_all(bb)
                hard2, _ = G.try_password_all(bb.hex())
                best.append((pr, name, rev, base, off, bb[:24]))
                if hits or hard or hard2 or pr > 0.8: print("!!!", name, rev, base, off, hits, hard, hard2, pr, bb[:60])
best.sort(reverse=True); print("n", n, "best printable", [(round(b[0],2), b[1:5]) for b in best[:4]])
