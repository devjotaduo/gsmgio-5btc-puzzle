# -*- coding: utf-8 -*-
"""Controle nulo CASADO: hill-climb com restarts=10 (mesmo esforco do run real) sobre
faed EMBARALHADO (preserva unigrama) em 8 escapes distintos -> distribuicao do maximo."""
import sys, os, random, json, pickle, math, re, unicodedata
import numpy as np
SP = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, SP)
import gsmg_common as G
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; IDX = {c: i for i, c in enumerate(A)}
NPW = np.array([17576, 676, 26, 1], dtype=np.int64)
M = {}
for lang in ("nl", "de"):
    tab, floor, held = pickle.load(open(os.path.join(SP, f"quad_{lang}.pkl"), "rb"))
    M[lang] = (np.asarray(tab, dtype=np.float32), floor)
def hc(seq, nsym, lang, restarts=10, iters=6000, patience=600, seed=0):
    T, floor = M[lang]; n = len(seq)
    S = np.asarray(seq, dtype=np.int64)
    Q = np.stack([S[0:n-3], S[1:n-2], S[2:n-1], S[3:n]], axis=1); inv = 1.0/(n-3)
    rng = random.Random(seed); best = -1e9
    for r in range(restarts):
        key = list(range(26)); rng.shuffle(key); ka = np.asarray(key, dtype=np.int64)
        cur = float(T[(ka[Q]*NPW).sum(1)].sum())*inv; since = 0
        for it in range(iters):
            a = rng.randrange(nsym); b = rng.randrange(26)
            if a == b: continue
            ka[a], ka[b] = ka[b], ka[a]
            s = float(T[(ka[Q]*NPW).sum(1)].sum())*inv
            if s > cur: cur = s; since = 0
            else:
                ka[a], ka[b] = ka[b], ka[a]; since += 1
                if since >= patience: break
        best = max(best, cur)
    return best
def cb_cells(digs, escapes, universe="123456789"):
    top = [int(d) for d in universe if int(d) not in escapes]
    cell = {}; k = 0
    for d in top: cell[(d,)] = k; k += 1
    for e in escapes:
        for d in universe: cell[(e, int(d))] = k; k += 1
    out = []; i = 0
    while i < len(digs):
        d = digs[i]
        if d in escapes:
            if i+1 < len(digs): out.append(cell[(d, digs[i+1])]); i += 2
            else: break
        else: out.append(cell[(d,)]); i += 1
    return out
rng = random.Random(2024)
ESC = [(2,8),(1,2),(8,9),(4,8),(3,7),(5,6),(1,9),(6,7)]
res = {"faed_shuffled": {"nl": [], "de": []}, "dbbi_shuffled": {"nl": [], "de": []}}
for name, base in (("faed_shuffled", G.digits(G.FAED)), ("dbbi_shuffled", G.digits(G.DBBI))):
    for k, e in enumerate(ESC):
        d = base[:]; rng.shuffle(d)
        seq = cb_cells(d, e)
        for lang in ("nl", "de"):
            res[name][lang].append(round(hc(seq, 25, lang, seed=1000+k), 3))
# nulo casado para o mono-sub: REST563/ODD285 EMBARALHADOS (preservam unigrama do Bifid)
BIF = G.bif_full(); REST = BIF[7:]; ODD = BIF[1::2]
for name, t in (("mono_REST563_shuffled", REST), ("mono_ODD285_shuffled", ODD)):
    res[name] = {"nl": [], "de": []}
    syms = sorted(set(t))
    for k in range(6):
        c = list(t); rng.shuffle(c)
        seq = [syms.index(x) for x in c]
        for lang in ("nl", "de"):
            res[name][lang].append(round(hc(seq, len(syms), lang, seed=2000+k), 3))
summ = {n: {l: {"max": max(v), "mean": round(sum(v)/len(v), 3), "vals": v} for l, v in d.items()} for n, d in res.items()}
print(json.dumps(summ, indent=1))
G.jsonl(os.path.join(SP, "dutch_german_scorer.jsonl"), {"null_matched_restarts10": summ})
