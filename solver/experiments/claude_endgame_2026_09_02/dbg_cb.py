import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gsmg_common as G
readme = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
i0 = readme.index("NOW TO RETURN TO THE SOURCE CODES")
ARCH = re.sub("[^A-Z]", "", readme[i0 - 3000:i0 + 1200].upper().replace("J", "I"))
def cb_encode(pt, alphabet, escapes):
    top = [d for d in "123456789" if int(d) not in escapes]
    need = len(top) + 18; alphabet = (alphabet + "." * need)[:need]
    m = {}; k = 0
    for d in top: m[alphabet[k]] = [int(d)]; k += 1
    for e in escapes:
        for d in "123456789": m[alphabet[k]] = [e, int(d)]; k += 1
    out = []
    for c in pt:
        if c in m: out += m[c]
    return out
digs = cb_encode(ARCH, G.CANON, (1, 4))
S = "".join(chr(96 + d) for d in digs)[:570]
back = G.checkerboard_decode(G.digits(S), G.CANON, (1, 4))
print("ARCH[:40]:", ARCH[:40])
print("back[:40]:", back[:40])
print("startswith:", back.startswith(ARCH[:30]))
print("semantic_text:", G.semantic_text(back), "score", round(G.english_score(back), 3))
print("len digs", len(digs), "uniq", sorted(set(digs)))
