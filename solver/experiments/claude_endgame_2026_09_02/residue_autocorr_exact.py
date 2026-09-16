# -*- coding: utf-8 -*-
"""
COMPLEMENTO 2 do bloco A — p-valor EXATO de permutacao (sem z gaussiano).

As contagens de n-gramas repetidos sao raras e discretas: o z padronizado por 500 embaralhados e'
instavel (mudar a semente do nulo levou o "max|z|=11,18" para 7,51). O teste correto: p empirico
bicaudal por estatistica, e como estatistica FAMILY-WISE o MIN dos p (com nulo do min-p obtido por
leave-one-out sobre os mesmos 2000 embaralhados). Falsifica ou confirma o bloco A de vez.
"""
import sys, json, time
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\residue_autocorr.jsonl"
rng = np.random.default_rng(9001)
T0 = time.time(); NS = 2000

def as_arr(s): return np.array([ord(c) - 97 for c in s], dtype=np.int8)
def ngram_cnt(a, n, lag):
    m = len(a) - lag - n + 1
    if m <= 5: return np.nan
    eq = (a[:len(a) - lag] == a[lag:])
    if n == 1: return float(eq[:m].sum())
    acc = eq[:m].copy()
    for k in range(1, n): acc &= eq[k:k + m]
    return float(acc.sum())
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
out = {}; n_tests = 0
for sname, s in SEQS.items():
    a = as_arr(s); shuf = np.stack([rng.permutation(a) for _ in range(NS)])
    obs = np.empty(len(STATS)); null = np.empty((NS, len(STATS)))
    for si, (kind, p, lag) in enumerate(STATS):
        f = (lambda x: ngram_cnt(x, p, lag)) if kind == "autocorr" else (lambda x: blockrep(x, p))
        obs[si] = f(a)
        for j in range(NS): null[j, si] = f(shuf[j])
        n_tests += 1
    ok = ~np.isnan(obs); O = obs[ok]; Nl = null[:, ok]
    # p bicaudal empirico (min das caudas, x2), com correcao +1
    up = ((Nl >= O).sum(0) + 1) / (NS + 1); dn = ((Nl <= O).sum(0) + 1) / (NS + 1)
    p_two = np.minimum(1.0, 2 * np.minimum(up, dn))
    # nulo do MIN-p: leave-one-out
    up_n = (np.cumsum(np.zeros(1)) if False else None)
    ranks_up = ((Nl[:, None, :] if False else None))
    up_l = np.empty_like(Nl); dn_l = np.empty_like(Nl)
    for si in range(Nl.shape[1]):
        col = Nl[:, si]; order = np.argsort(col, kind="stable")
        srt = col[order]
        ge = NS - np.searchsorted(srt, col, side="left")      # #{x >= col}
        le = np.searchsorted(srt, col, side="right")          # #{x <= col}
        up_l[:, si] = ge / NS; dn_l[:, si] = le / NS          # inclui a si mesmo (conservador)
    p_null = np.minimum(1.0, 2 * np.minimum(up_l, dn_l)).min(1)
    minp = float(p_two.min()); idx = int(p_two.argmin())
    which = [st for st, k in zip(STATS, ok) if k][idx]
    p_fw = float(((p_null <= minp).sum() + 1) / (NS + 1))
    out[sname] = {"min_p_uncorrected": round(minp, 5), "arg": list(which),
                  "obs": O[idx], "null_mean": round(float(Nl[:, idx].mean()), 3),
                  "familywise_p": round(p_fw, 4), "significant_fw": bool(p_fw < 0.05),
                  "n_stats": int(ok.sum())}
    print(sname, out[sname], round(time.time() - T0), "s", flush=True)
G.jsonl(LOG, {"event": "partA_exact_permutation", "n_shuffles": NS, "n_tests": n_tests,
              "per_seq": out,
              "verdict": "REFUTADO (nenhum lag/bloco sobrevive ao family-wise)"
                         if all(not v["significant_fw"] for v in out.values()) else "SOBREVIVE"})
print(json.dumps(out, indent=1))
