import sys, hashlib, itertools
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
H = "5ac407837447fba24ba2802e4d1e9aecb4580aa29fef1088cc387c180b746f75"
# what is H? try phase-1 candidates
for c in ["theseedisplanted", "gsmg.io/theseedisplanted", "https://gsmg.io/theseedisplanted", "causality", "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
          "theflowerblossomsthroughwhatseemstobeaconcretesurface", "thematrixhasyou", "followthewhiterabbit"]:
    if G.shahex(c) == H: print("H = sha256(", c, ")")
n = 0; hard = []
forms = [H, H.upper(), G.shahex(H), G.shahex(H).upper(), bytes.fromhex(H), G.shahex(H.upper()),
         H + "\n", G.shahex(H + "\n"), G.shahex(bytes.fromhex(H))]
for f in forms:
    for blob in ("SMALL", "COSMIC", "TAIL32"):
        for kdf, p in G.aes_try(f, blob):
            n += 1
            print("PAD OK", blob, kdf, repr(f)[:20], "printable", round(G.printable(p), 3), p[:40])
            if G.semantic(p): hard.append((blob, kdf, f, p))
    if isinstance(f, str) and len(f) == 64:
        r = G.priv_hit(bytes.fromhex(f))
        if r: hard.append(("priv", f, r))
print("tested forms", len(forms) * 3, "paddings", n, "HARD", hard)
