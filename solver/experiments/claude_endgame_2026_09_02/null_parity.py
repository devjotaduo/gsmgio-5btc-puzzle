# -*- coding: utf-8 -*-
"""Nulo casado 2: preserva o ARTEFATO ESTRUTURAL do Bifid (posicoes pares do BIF vivem em {B,C,D,E}).
Embaralha REST563 DENTRO de cada classe de paridade e ODD_REST (4 simbolos) -> teto real do hill-climb mono."""
import sys, os, random, json, pickle
import numpy as np
SP = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, SP)
import gsmg_common as G
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NPW = np.array([17576, 676, 26, 1], dtype=np.int64)
M = {}
for lang in ("nl", "de"):
    tab, floor, _ = pickle.load(open(os.path.join(SP, f"quad_{lang}.pkl"), "rb"))
    M[lang] = (np.asarray(tab, dtype=np.float32), floor)
def hc(seq, nsym, lang, restarts=10, iters=6000, patience=600, seed=0):
    T, _ = M[lang]; n = len(seq)
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
rng = random.Random(7)
BIF = G.bif_full(); REST = BIF[7:]; ODD_REST = REST[1::2]
out = {}
# (a) REST563: embaralhar dentro das classes de paridade (preserva o artefato "pares in {B,C,D,E}")
syms = sorted(set(REST))
vals = {"nl": [], "de": []}
for k in range(6):
    ev = [REST[i] for i in range(0, len(REST), 2)]; od = [REST[i] for i in range(1, len(REST), 2)]
    rng.shuffle(ev); rng.shuffle(od)
    c = []
    for i in range(len(REST)): c.append(ev.pop() if i % 2 == 0 else od.pop())
    seq = [syms.index(x) for x in c]
    for lang in ("nl", "de"): vals[lang].append(round(hc(seq, len(syms), lang, seed=3000+k), 3))
out["REST563_parity_shuffled"] = {l: {"max": max(v), "mean": round(sum(v)/len(v), 3), "vals": v} for l, v in vals.items()}
# (b) ODD_REST (4 simbolos) embaralhado
syms2 = sorted(set(ODD_REST)); vals2 = {"nl": [], "de": []}
for k in range(6):
    c = list(ODD_REST); rng.shuffle(c)
    seq = [syms2.index(x) for x in c]
    for lang in ("nl", "de"): vals2[lang].append(round(hc(seq, len(syms2), lang, seed=4000+k), 3))
out["ODD_REST_shuffled"] = {"nsym": len(syms2), **{l: {"max": max(v), "mean": round(sum(v)/len(v), 3), "vals": v} for l, v in vals2.items()}}
print(json.dumps(out, indent=1))
G.jsonl(os.path.join(SP, "dutch_german_scorer.jsonl"), {"null_parity_matched": out})
