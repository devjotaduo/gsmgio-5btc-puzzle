import sys, random, re
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
D = G.DBBI
M = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE"
print("len M91 =", len(M), "len dbbi =", len(D))
A = lambda c: ord(c) - 65
L = lambda n: chr(n % 26 + 65)
def combo(key, off, sign_key, sign_m):
    return "".join(L(sign_m * A(M[i]) + sign_key * (key[i] + off)) for i in range(91))
dig = [ord(c) - 97 for c in D]   # a=0..i=8
variants = {}
for off in (0, 1):
    for sk, sm, name in ((-1, 1, "M-key"), (1, 1, "M+key"), (1, -1, "key-M"), (-1, -1, "-M-key")):
        variants[f"{name} off{off}"] = combo(dig, off, sk, sm)
for k, v in variants.items():
    print(f"{k:14s} {v}  | score {G.english_score(v):.2f} words {G.word_hits(v,5)}")
# Vasilis: A = dbbi - M91 (a=0)
v = variants["key-M off0"]; print("YOUWON idx:", v.find("YOUWON"))
# null: shuffled dbbi -> how often does a 6+ letter BIP39 word appear in any of the 8 variants?
random.seed(1)
words6 = [w.upper() for w in G.O.WORDLIST if len(w) >= 6]
def hits(s): return [w for w in words6 if w in s]
real = {k: hits(v) for k, v in variants.items()}
print("real hits:", {k: v for k, v in real.items() if v})
n = 3000; cnt = 0; cnt_any = 0
for _ in range(n):
    d2 = dig[:]; random.shuffle(d2)
    got = 0
    for off in (0, 1):
        for sk, sm in ((-1, 1), (1, 1), (1, -1), (-1, -1)):
            if hits(combo(d2, off, sk, sm)): got += 1
    cnt += got; cnt_any += (got > 0)
print(f"null: mean variants-with-6+word per shuffle {cnt/n:.3f}; P(any of 8 variants has a 6+ letter word) = {cnt_any/n:.3f}")
