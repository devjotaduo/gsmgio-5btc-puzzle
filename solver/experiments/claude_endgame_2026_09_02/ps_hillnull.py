# nulo justo do hill-climb: faed real vs 4 embaralhamentos, 5 restarts x 30k cada, mesmas seeds
import sys; sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import numpy as np, json, permutation_search as P
FA = np.array([ord(c) - 97 for c in P.G.FAED]); nl = P.Null(FA, 9)
out = {"real": [round(z, 2) for z, _ in P.hill(FA, nl, 30000, 5, "hillnull_real", seed=11)]}
rng = np.random.RandomState(5)
for s in range(4):
    b = FA.copy(); rng.shuffle(b)
    out[f"shuf{s}"] = [round(z, 2) for z, _ in P.hill(b, nl, 30000, 5, f"hillnull_shuf{s}", seed=11)]
print(json.dumps(out)); P.G.jsonl(P.LOG, {"hill_fair_null": out, "perm_eval_extra": P.N["perm_eval"]})
