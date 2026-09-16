import sys, time
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import numpy as np
import permutation_search as P
tot = 0
for fam, d in P.all_families(570).items():
    for nm, p in d.items(): assert sorted(p) == list(range(570)), (fam, nm, len(p))
    print(fam, len(d)); tot += len(d)
print("total perms 570:", tot)
print(P.columnar_encrypt_perm(10, "bca"))
t = time.time(); nl = P.Null(np.random.randint(0, 9, 570), 9, 300); print("null300", round(time.time() - t, 2), nl.mi_m, nl.mi_s)
t = time.time(); [P.mi1(np.random.randint(0, 9, 570)) for _ in range(2000)]; print("mi1 x2000", round(time.time() - t, 2))
# controle: z do checkerboard 3.2.2
D = np.array([int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"])
n = P.Null(D, 10, 1000); print("z322", n.z(D), n.zio(D))
FA = np.array([ord(c) - 97 for c in P.G.FAED]); nF = P.Null(FA, 9, 1000); print("z faed id", nF.z(FA), nF.zio(FA))
t = time.time(); P.hill(FA, nF, steps=2000, restarts=1); print("hill 2000 steps", round(time.time() - t, 2))
t = time.time(); P.decode_seq(P.G.FAED[:570], "test"); print("decode_seq", round(time.time() - t, 1), P.N, P.best)
