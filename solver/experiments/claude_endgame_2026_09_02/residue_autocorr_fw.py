# -*- coding: utf-8 -*-
"""
COMPLEMENTO da familia residue_autocorr — teste FAMILY-WISE do bloco A.

Motivo: a autocorrelacao de n-gramas com n=3..4 conta eventos RAROS (esperado <1 match por lag),
logo o z gaussiano superestima grosseiramente a significancia. O teste correto e' a estatistica
MAXIMA: para cada um dos 500 embaralhados, recalcular TODAS as 1250 estatisticas, padronizar pelo
nulo leave-one-out e tomar max|z|. A distribuicao desses 500 max|z| e' o nulo family-wise. Se o
max|z| observado do faed real cair dentro dessa distribuicao, os "lags 4/35/42" sao artefato de
multiplas comparacoes e o bloco A esta REFUTADO.
"""
import sys, json, time
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\residue_autocorr.jsonl"
rng = np.random.default_rng(4242)
T0 = time.time()

def as_arr(s): return np.array([ord(c) - 97 for c in s], dtype=np.int8)
def ngram_rate(a, n, lag):
    m = len(a) - lag - n + 1
    if m <= 5: return np.nan
    eq = (a[:len(a) - lag] == a[lag:])
    if n == 1: return eq[:m].mean()
    acc = eq[:m].copy()
    for k in range(1, n): acc &= eq[k:k + m]
    return acc.mean()
def blockrep(a, m):
    if len(a) < m + 2: return np.nan
    win = np.lib.stride_tricks.sliding_window_view(a.astype(np.int64), m)
    keys = win @ (9 ** np.arange(m)).astype(np.int64)
    _, c = np.unique(keys, return_counts=True)
    return float((c * (c - 1) // 2).sum())

SEQS = {"faed": G.FAED, "dbbi": G.DBBI, "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:],
        "faed+dbbi": G.FAED + G.DBBI}
STATS = [("autocorr", n, lag) for n in (1, 2, 3, 4) for lag in range(1, 61)] + \
        [("blockrep", m, None) for m in range(3, 13)]
NS = 500
n_tests = 0
res = {}
for sname, s in SEQS.items():
    a = as_arr(s)
    shuf = np.stack([rng.permutation(a) for _ in range(NS)])
    obs = np.empty(len(STATS)); null = np.empty((NS, len(STATS)))
    for si, (kind, p, lag) in enumerate(STATS):
        f = (lambda x: ngram_rate(x, p, lag)) if kind == "autocorr" else (lambda x: blockrep(x, p))
        obs[si] = f(a)
        for j in range(NS): null[j, si] = f(shuf[j])
        n_tests += 1
    ok = ~np.isnan(obs)
    mu = null[:, ok].mean(0); sd = null[:, ok].std(0); sd[sd == 0] = 1e-12
    z_obs = (obs[ok] - mu) / sd
    # nulo family-wise: leave-one-out para cada embaralhado
    S = null[:, ok].sum(0); S2 = (null[:, ok] ** 2).sum(0)
    mu_loo = (S - null[:, ok]) / (NS - 1)
    var_loo = (S2 - null[:, ok] ** 2) / (NS - 1) - mu_loo ** 2
    sd_loo = np.sqrt(np.maximum(var_loo, 1e-24))
    z_null = (null[:, ok] - mu_loo) / sd_loo
    maxz_null = np.abs(z_null).max(1)
    maxz_obs = float(np.abs(z_obs).max())
    p_fw = float((maxz_null >= maxz_obs).mean())
    idx = int(np.abs(z_obs).argmax()); which = [st for st, k in zip(STATS, ok) if k][idx]
    res[sname] = {"max_abs_z": round(maxz_obs, 2), "arg": list(which),
                  "fw_null_max|z|_p50": round(float(np.percentile(maxz_null, 50)), 2),
                  "fw_null_max|z|_p95": round(float(np.percentile(maxz_null, 95)), 2),
                  "fw_null_max|z|_max": round(float(maxz_null.max()), 2),
                  "p_familywise": p_fw, "significant": bool(p_fw < 0.05)}
    print(sname, res[sname], round(time.time() - T0), "s", flush=True)

# nulo family-wise conjunto (todas as 5 sequencias juntas), como o bloco A foi realmente inspecionado
G.jsonl(LOG, {"event": "partA_familywise", "n_shuffles": NS, "n_stats_per_seq": len(STATS),
              "n_tests": n_tests, "per_seq": res,
              "verdict": "REFUTADO" if all(not v["significant"] for v in res.values())
                         else "residuo sobrevive ao family-wise"})
print(json.dumps({"partA_familywise": res}, indent=1))
