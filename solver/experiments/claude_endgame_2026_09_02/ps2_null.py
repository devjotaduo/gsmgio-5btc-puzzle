# -*- coding: utf-8 -*-
"""Nulo empirico da permutation_search2: MESMAS familias (rota dupla / colunar dupla / metades mistas)
aplicadas a faed EMBARALHADO. Se o max |z| do faed real nao superar o do embaralhado, a hipotese cai."""
import sys, json, numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G, permutation_search as PS, permutation_search2 as P2
P2.LOG = SP + r"\permutation_search2.jsonl"; PS.LOG = P2.LOG
faed = np.array(G.digits(G.FAED)) - 1
fams = {"route2": P2.fam_route2(570), "dblcol": P2.fam_dblcol(570), "halves_mixed": P2.fam_halves_mixed(570)}
res = {}
for trial in range(3):
    rng = np.random.default_rng(100 + trial); b = faed.copy(); rng.shuffle(b)
    null = PS.Null(b, 9)
    top, st, nse = P2.scan(b, null, fams, f"nullshuf{trial}", keep=3)
    res[f"shuf{trial}"] = {"max_abs_z": round(float(abs(top[0][0])), 2), "n_perm": nse,
                           "por_familia": {k: v["z_max"] for k, v in st.items()}}
    print(trial, res[f"shuf{trial}"], flush=True)
G.jsonl(P2.LOG, {"empirical_null_faed": res})
json.dump(res, open(SP + r"\ps2_null.json", "w"), indent=1)
