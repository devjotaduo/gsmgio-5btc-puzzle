# -*- coding: utf-8 -*-
"""
COMPLEMENTO 3 (modelo NULO do bloco B) — a MESMA varredura de chaves de poucos residuos aplicada a
um faed EMBARALHADO (i.i.d. por construcao, sem camada aditiva). O max|z| que essa varredura produz
no nulo e' a barra que o faed real precisa ultrapassar. Sem isso, "z=6,9 entre 130k streams" nao
significa nada (os z sao estimados com 30 embaralhados -> cauda pesada tipo t_29).
"""
import sys, json, time, itertools
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\residue_autocorr.jsonl"
rng = np.random.default_rng(777)
T0 = time.time(); NSHUF_B = 30

def a1z26(s): return [ord(c) - 96 for c in s.lower() if 'a' <= c <= 'z']
def ascii_bits(s): return [int(b) for ch in s for b in format(ord(ch), "08b")]
KEYS = {}
KEYS["bin(enter)"] = ascii_bits("enter")
KEYS["bin(matrixsumlist)"] = ascii_bits("matrixsumlist")
for w in ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword",
          "yellowblueprimes", "hashthetext", "enter"]:
    v = a1z26(w); KEYS[f"{w}:a1z26m2"] = [x % 2 for x in v]; KEYS[f"{w}:a1z26m3"] = [x % 3 for x in v]
MR = G.MATRIX_README
KEYS["matrixREADME:spiral"] = [MR[r][c] for r, c in G.SPIRAL]
KEYS["matrixREADME:rowmajor"] = [MR[r][c] for r in range(14) for c in range(14)]
KEYS["url_bits192"] = KEYS["matrixREADME:spiral"][:192]
KEYS["dbbi:m2"] = [d % 2 for d in G.digits(G.DBBI)]; KEYS["dbbi:m3"] = [d % 3 for d in G.digits(G.DBBI)]
KEYS["primeind570"] = [1 if G.is_prime(i) else 0 for i in range(570)]
KEYS["primeind570_b1"] = [1 if G.is_prime(i + 1) else 0 for i in range(570)]
KEYS["thuemorse"] = [bin(i).count("1") % 2 for i in range(570)]
fib = [0, 1]
while len(fib) < 570: fib.append(fib[-1] + fib[-2])
KEYS["fib:m2"] = [x % 2 for x in fib[:570]]; KEYS["fib:m3"] = [x % 3 for x in fib[:570]]
fw = "0"
while len(fw) < 570: fw = "".join("01" if c == "0" else "0" for c in fw)
KEYS["fibword"] = [int(c) for c in fw[:570]]
def primitive(t):
    L = len(t)
    for p in range(1, L):
        if L % p == 0 and all(t[i] == t[i % p] for i in range(L)): return False
    return True
PERIODIC = [list(b) for p in range(1, 13) for b in itertools.product((0, 1), repeat=p)
            if len(set(b)) > 1 and primitive(b)]
ALLKEYS = list(KEYS.items()) + [(f"per{len(b)}", b) for b in PERIODIC]

def hcond(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).reshape(n, n).astype(float)
    rows = bg.sum(1, keepdims=True); N = bg.sum()
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(bg > 0, bg * np.log2(bg / rows), 0.0)
    return -t.sum() / N
def digioc(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).astype(float); N = bg.sum()
    return (bg * (bg - 1)).sum() / (N * (N - 1))
_NULL = {}
def filt(a, n):
    key = (n, tuple(np.bincount(a, minlength=n).tolist()))
    if key not in _NULL:
        h = np.empty(NSHUF_B); d = np.empty(NSHUF_B)
        for i in range(NSHUF_B):
            x = rng.permutation(a); h[i] = hcond(x, n); d[i] = digioc(x, n)
        _NULL[key] = (h.mean(), h.std() or 1e-12, d.mean(), d.std() or 1e-12)
    hm, hs, dm, ds = _NULL[key]
    return (hcond(a, n) - hm) / hs, (digioc(a, n) - dm) / ds

FD = G.digits(G.FAED)
def mkcfg(digs):
    return {"m9": dict(n=9, c=np.array([d - 1 for d in digs])),
            "m10a1": dict(n=10, c=np.array(digs)),
            "m10a0": dict(n=10, c=np.array([d - 1 for d in digs])),
            "m10i0": dict(n=10, c=np.array([0 if d == 9 else d for d in digs]))}
out = {}
for rep in range(2):
    sh = list(np.random.default_rng(1000 + rep).permutation(FD))
    cfgs = mkcfg(sh); zmax = 0.0; arg = ""; npass = 0; nst = 0
    for cn, cfg in cfgs.items():
        n, c = cfg["n"], cfg["c"]; seen = set()
        for kname, kraw in ALLKEYS:
            L = len(kraw); rots = range(L) if kname in KEYS else (0,)
            for rot in rots:
                k = [x % n for x in (list(kraw[rot:]) + list(kraw[:rot]))]
                if len(set(k)) == 1: continue
                tk = (n, tuple(k[:min(L, len(c))]))
                if tk in seen: continue
                seen.add(tk)
                K = np.resize(np.array(k), len(c))
                for mode, a in (("add", (c - K) % n), ("sub", (c + K) % n)):
                    z1, z2 = filt(a, n); nst += 1
                    m = max(abs(z1), abs(z2))
                    if m > 3.0: npass += 1
                    if m > zmax: zmax, arg = m, f"{cn}|{kname}|rot{rot}|{mode}"
    out[f"shuffled_faed_rep{rep}"] = {"n_streams": nst, "n_pass_z3": npass,
                                      "zmax": round(float(zmax), 2), "arg": arg}
    print(out, round(time.time() - T0), "s", flush=True)
G.jsonl(LOG, {"event": "partB_null_model", "note": "mesma varredura em faed EMBARALHADO", **out})
print(json.dumps(out, indent=1))
