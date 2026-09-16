# -*- coding: utf-8 -*-
"""Calibracao nula EXTRA (3 reps de faed, semente nova) para julgar o residuo z_Hcond=-8.21."""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np, gsmg_common as G
SP = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(SP, "bifid3x3_exhaustive.py"), encoding="utf-8").read()
head = src.split("# ------------------------------------------------------------------ CONTROLE positivo")[0]
head = head.replace('open(LOG, "w").close()', "pass").replace('log({"kind": "hypothesis", "text": __doc__.strip()})', "")
g = {"__name__": "b3x3head", "__file__": os.path.join(SP, "bifid3x3_exhaustive.py")}
exec(compile(head, "b3x3head", "exec"), g)
screen = g["screen"]; rng = np.random.default_rng(424242); g["rng"] = rng
LOG = os.path.join(SP, "bifid3x3_exhaustive.jsonl"); out = []
for rep in range(3):
    sh = "".join(np.array(list(G.FAED))[rng.permutation(570)])
    tri, gst, allg = screen(sh, f"null2_faed_{rep}", g["PERIODS"]["faed"], top_T=4000)
    rec = {"kind": "null_calib2", "text": "faed", "rep": rep,
           "zH_min": min(r["zH"] for r in tri), "absz_max": max(r["absz"] for r in tri),
           "n_zH_le_m6": sum(r["zH"] <= -6 for r in tri), "n_zH_le_m7": sum(r["zH"] <= -7 for r in tri),
           "n_zH_le_m8": sum(r["zH"] <= -8 for r in tri), "G_max": max(v["max"] for v in gst.values())}
    G.jsonl(LOG, rec); out.append(rec); print(json.dumps(rec), flush=True)
json.dump(out, open(os.path.join(SP, "bifid3x3_nullcalib2.json"), "w"), indent=1)
