# -*- coding: utf-8 -*-
"""
CALIBRACAO NULA da familia bifid3x3_exhaustive.

O z por candidato ja e' calibrado contra 200 embaralhamentos da propria saida, mas o EXTREMO do
funil (min z_Hcond entre 4000 candidatos escolhidos por G entre 1,81 M) tem vies de selecao. Aqui
rodo o pipeline INTEIRO sobre textos NULOS (faed e dbbi embaralhados, mesmo unigrama) para saber
qual z_Hcond minimo o pipeline produz quando nao ha nada. Se o real nao superar o nulo, a familia
esta refutada.
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np, gsmg_common as G

SP = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(SP, "bifid3x3_exhaustive.py"), encoding="utf-8").read()
head = src.split("# ------------------------------------------------------------------ CONTROLE positivo")[0]
head = head.replace('open(LOG, "w").close()', "pass").replace(
    'log({"kind": "hypothesis", "text": __doc__.strip()})', "")
g = {"__name__": "b3x3head", "__file__": os.path.join(SP, "bifid3x3_exhaustive.py")}
exec(compile(head, "b3x3head", "exec"), g)
screen, rng = g["screen"], g["rng"]
LOG = os.path.join(SP, "bifid3x3_exhaustive.jsonl")
T0 = time.time()
out = []
for label, txt, per in (("faed", G.FAED, g["PERIODS"]["faed"]), ("dbbi", G.DBBI, g["PERIODS"]["dbbi"])):
    for rep in range(2):
        sh = "".join(np.array(list(txt))[rng.permutation(len(txt))])
        tri, gst, allg = screen(sh, f"null_{label}_{rep}", per, top_T=4000)
        rec = {"kind": "null_calib", "text": label, "rep": rep,
               "zH_min": min(r["zH"] for r in tri), "absz_max": max(r["absz"] for r in tri),
               "n_zH_le_m6": sum(r["zH"] <= -6 for r in tri), "n_zH_le_m7": sum(r["zH"] <= -7 for r in tri),
               "G_max": max(v["max"] for v in gst.values()),
               "top3": [{k: r[k] for k in ("period", "mode", "square", "G", "zH", "absz")} for r in tri[:3]]}
        G.jsonl(LOG, rec); out.append(rec)
        print(json.dumps({k: rec[k] for k in ("text", "rep", "zH_min", "absz_max", "n_zH_le_m6", "n_zH_le_m7", "G_max")}), flush=True)
json.dump(out, open(os.path.join(SP, "bifid3x3_nullcalib.json"), "w"), indent=1)
print("elapsed", round(time.time() - T0))
