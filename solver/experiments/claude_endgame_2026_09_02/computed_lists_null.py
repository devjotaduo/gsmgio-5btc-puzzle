# -*- coding: utf-8 -*-
"""Calibração do NULO da família computed_lists.

O estatístico usado é max-sobre-alinhamentos de z binomial (p=1/9), que é enviesado para cima.
Aqui medimos, por comprimento (len_lista, len_alvo), a distribuição do máximo sob H0 (lista i.i.d.
uniforme 1..9) e comparamos com o máximo REAL observado nas 9.968 comparações. Se o real ≤ o
esperado do nulo para ~10^4 comparações, a família está refutada sem ambiguidade.
"""
import sys, json, math
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import numpy as np, gsmg_common as G

LOG = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02\computed_lists.jsonl"
rng = np.random.default_rng(12345)
D1 = np.array(G.digits(G.DBBI)); F1 = np.array(G.digits(G.FAED))

def max_z(L, T):
    """max sobre alinhamentos (n>=20) do z binomial p=1/9 — mesma definição do script principal."""
    best = -9.0
    for off in range(-len(L) + 20, len(T) - 19):
        a0 = max(0, -off); b0 = max(0, off)
        n = min(len(L) - a0, len(T) - b0)
        if n < 20: continue
        m = int(np.count_nonzero(L[a0:a0 + n] == T[b0:b0 + n]))
        z = (m - n / 9) / math.sqrt(n * (1 / 9) * (8 / 9))
        if z > best: best = z
    return best

CASES = [(91, "dbbi"), (182, "dbbi"), (196, "dbbi"), (5000, "dbbi"),
         (188, "faed"), (196, "faed"), (5000, "faed"), (570, "faed")]
NDRAW = 400
out = {}
for LL, tname in CASES:
    T = D1 if tname == "dbbi" else F1
    zs = np.array([max_z(rng.integers(1, 10, LL), T) for _ in range(NDRAW)])
    out[f"{LL}vs{tname}"] = {"mean": round(float(zs.mean()), 2), "sd": round(float(zs.std()), 2),
                             "max": round(float(zs.max()), 2),
                             "p99": round(float(np.quantile(zs, 0.99)), 2),
                             # máximo esperado de ~10^4 comparações independentes deste tipo
                             "expected_max_1e4": round(float(zs.mean() + zs.std() * math.sqrt(2 * math.log(10000))), 2)}
    print(LL, tname, out[f"{LL}vs{tname}"], flush=True)

# controle positivo: lista plantada (dbbi com 15% de ruído) tem de sair MUITO acima do nulo
noisy = D1.copy(); idx = rng.choice(91, 13, replace=False); noisy[idx] = rng.integers(1, 10, 13)
z_planted = max_z(noisy, D1)
assert z_planted > 12, z_planted
G.jsonl(LOG, {"null_calibration": out, "z_planted_control": round(z_planted, 2), "n_draws_per_case": NDRAW})
print(json.dumps({"null_calibration": out, "z_planted_control": round(z_planted, 2)}, indent=1))
