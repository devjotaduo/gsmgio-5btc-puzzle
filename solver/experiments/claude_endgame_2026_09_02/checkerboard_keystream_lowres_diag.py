# -*- coding: utf-8 -*-
"""Diagnostico de POTENCIA: quanto da estrutura serial de um checkerboard sobrevive a uma camada
aditiva de poucos residuos? Distribuicao de H_cond-z do TEXTO CIFRADO sobre milhares de mascaras
binarias/ternarias aleatorias (periodos e densidades variados) — comparada ao faed real (z ~ -0.7).
Se quase nenhuma camada de 2-3 residuos consegue empurrar z ate a faixa do faed, a hipotese
'faed = checkerboard + camada aditiva de poucos residuos' esta refutada por medida."""
import sys, json, collections
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\checkerboard_keystream_lowres_diag.jsonl"
open(LOG, "w").close()
rng = np.random.default_rng(4242)

def hcond_np(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).reshape(n, n).astype(float)
    rows = bg.sum(1, keepdims=True); N = bg.sum()
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(bg > 0, bg * np.log2(bg / rows), 0.0)
    return -t.sum() / N
def hcond_z(seq, n, nshuf=25):
    a = np.asarray(seq, dtype=np.int64); obs = hcond_np(a, n)
    null = np.array([hcond_np(rng.permutation(a), n) for _ in range(nshuf)])
    return float((obs - null.mean()) / (null.std() or 1e-9))
def cb_encode(text, alpha, esc, uni):
    top = [d for d in uni if int(d) not in esc]; table = {}; k = 0
    for d in top: table[alpha[k]] = [int(d)]; k += 1
    for e in esc:
        for d in uni: table[alpha[k]] = [e, int(d)]; k += 1
    return [v for ch in text.upper() if ch in table for v in table[ch]]

AL322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
TXT = ("THE ARCHITECT SAID THAT THE DOOR TO YOUR RIGHT LEADS TO THE SOURCE AND THE SALVATION OF ZION "
       "WHILE THE DOOR TO YOUR LEFT LEADS BACK TO THE MATRIX TO HER AND TO THE END OF YOUR SPECIES "
       "YOU ARE HERE BECAUSE ZION IS ABOUT TO BE DESTROYED ITS EVERY LIVING INHABITANT TERMINATED "
       "ITS ENTIRE EXISTENCE ERADICATED THE FUNCTION OF THE ONE IS NOW TO RETURN TO THE SOURCE "
       "THE PROBLEM IS CHOICE THE FIRST MATRIX WAS DESIGNED TO BE A PERFECT HUMAN WORLD")
P = cb_encode(TXT, AL322, (1, 4), "0123456789")[:570]
res = {"bin": [], "ter": [], "full": []}
N = 0
for kind in ("bin", "ter", "full"):
    for _ in range(700):
        L = int(rng.integers(2, 60))
        if kind == "bin":
            m = rng.integers(0, 2, L)
            d = int(rng.integers(1, 10)); k = [int(x) * d % 10 for x in m]
        elif kind == "ter":
            m = rng.integers(0, 3, L)
            d = int(rng.integers(1, 10)); k = [int(x) * d % 10 for x in m]
        else:
            k = [int(x) for x in rng.integers(0, 10, L)]     # chave "cheia" (>=3 residuos variados)
        if len(set(k)) < 2: continue
        c = [(P[i] + k[i % L]) % 10 for i in range(len(P))]
        res[kind].append(round(hcond_z(c, 10), 2)); N += 1
out = {"event": "power_diag", "n_masks": N, "z_plain": round(hcond_z(P, 10), 2),
       "faed_z_m10a": round(hcond_z(G.digits(G.FAED), 10), 2)}
for kind, v in res.items():
    a = np.array(v)
    out[kind] = {"n": len(v), "z_mean": round(float(a.mean()), 2), "z_median": round(float(np.median(a)), 2),
                 "z_max(menos negativo)": round(float(a.max()), 2),
                 "frac_|z|<1.5 (faixa do faed)": round(float((np.abs(a) < 1.5).mean()), 4),
                 "frac_|z|<2.5": round(float((np.abs(a) < 2.5).mean()), 4)}
G.jsonl(LOG, out)
print(json.dumps(out, ensure_ascii=False, indent=1))
