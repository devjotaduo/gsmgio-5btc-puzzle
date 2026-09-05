import sys, random
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
D = G.DBBI
M = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE"
A = lambda c: ord(c) - 65
L = lambda n: chr(n % 26 + 65)
def combo(key, off, sk, sm): return "".join(L(sm * A(M[i]) + sk * (key[i] + off)) for i in range(91))
dig = [ord(c) - 97 for c in D]
def best(d):
    return max(G.english_score(combo(d, off, sk, sm)) for off in (0, 1) for sk, sm in ((-1,1),(1,1),(1,-1),(-1,-1)))
real = best(dig); print("real best score", round(real, 3))
random.seed(7); n = 3000; ge = 0; scores = []
for _ in range(n):
    d2 = dig[:]; random.shuffle(d2); s = best(d2); scores.append(s); ge += (s >= real)
scores.sort()
print(f"null (shuffle dbbi): p = {ge/n:.4f}; null max {scores[-1]:.2f}, 99th pct {scores[int(0.99*n)]:.2f}, median {scores[n//2]:.2f}")
# also shuffle M instead (keeps dbbi structure)
random.seed(8); ge2 = 0; Ml = list(M)
for _ in range(n):
    random.shuffle(Ml); M2 = "".join(Ml)
    s = max(G.english_score("".join(L(sm * A(M2[i]) + sk * (dig[i] + off)) for i in range(91))) for off in (0,1) for sk, sm in ((-1,1),(1,1),(1,-1),(-1,-1)))
    ge2 += (s >= real)
print(f"null (shuffle M91): p = {ge2/n:.4f}")
