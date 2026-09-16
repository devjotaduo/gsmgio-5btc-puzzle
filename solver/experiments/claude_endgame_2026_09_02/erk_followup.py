# -*- coding: utf-8 -*-
"""Verificação do único passer do scan external_running_key: a0z25 / m10i0 / beau / offset 252770."""
import sys, os, io, re, json
import numpy as np
SCR = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, SCR)
import gsmg_common as G
rng = np.random.default_rng(7)
txt = io.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\cosmic_duality.txt", encoding="utf-8", errors="ignore").read()
pos = [i for i, c in enumerate(txt.lower()) if "a" <= c <= "z"]
LET = np.array([ord(txt[i].lower()) - 96 for i in pos], dtype=np.int64)
FD = np.array(G.digits(G.FAED), dtype=np.int64); N = 570
CONFIGS = {"m9": (9, FD - 1), "m10a": (10, FD.copy()), "m10i0": (10, np.where(FD == 9, 0, FD)), "m10a0": (10, FD - 1)}
def rekey(c, k, mode, n):
    return (c - k) % n if mode == "add" else (c + k) % n if mode == "sub" else (k - c) % n
def bigram_stats(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).astype(float)
    Mn = bg.sum(); ioc = (bg * (bg - 1)).sum() / (Mn * (Mn - 1))
    b2 = bg.reshape(n, n); rows = b2.sum(1, keepdims=True)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(b2 > 0, b2 * np.log2(b2 / rows), 0.0)
    return -t.sum() / Mn, ioc
def gate(a, n, nshuf):
    H, I = bigram_stats(a, n)
    nul = np.array([bigram_stats(rng.permutation(a), n) for _ in range(nshuf)])
    zH = (H - nul[:, 0].mean()) / nul[:, 0].std(); zI = (I - nul[:, 1].mean()) / nul[:, 1].std()
    pH = (nul[:, 0] <= H).mean(); return zH, zI, H, pH

OFF = 252770
key = (LET - 1)          # a0z25
n, c = CONFIGS["m10i0"]
a = rekey(c, key[OFF:OFF + N] % n, "beau", n)
zH, zI, H, pH = gate(a, n, 3000)
print(f"passer: zH={zH:+.2f} zI={zI:+.2f} H={H:.4f} p_exato(3000 emb)={pH:.4f}")
# (a) controle: chave certa em stream sintético → magnitude esperada
README = io.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
arch = re.sub(r"[^A-Z]", "", re.search(r"NOW TO RETURN TO THE SOURCE[^\n]*", README).group())
AL322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"; table = {}
row0 = AL322.replace(".", "")[:8]; rest = AL322.replace(".", "")[8:]
for ch, col in zip(row0, [i for i in range(10) if i not in (1, 4)]): table[ch] = str(col)
for j, ch in enumerate(rest): table[ch] = ("1" if j < 10 else "4") + str(j % 10)
digs = np.resize(np.array([int(d) for ch in arch if ch in table for d in table[ch]], dtype=np.int64), N)
ctrl_ct = (digs + key[12345:12345 + N] % 10) % 10
zc = gate(rekey(ctrl_ct, key[12345:12345 + N] % 10, "add", 10), 10, 300)
print(f"controle chave certa: zH={zc[0]:+.2f} zI={zc[1]:+.2f} | chave deslocada +1: zH={gate(rekey(ctrl_ct, key[12346:12346+N]%10,'add',10),10,300)[0]:+.2f}")
# (b) localização: offsets vizinhos e outras configs/modos no mesmo offset
print("vizinhos (a0z25/m10i0/beau):", [f"{o - OFF:+d}:{gate(rekey(c, key[o:o + N] % n, 'beau', n), n, 100)[0]:+.1f}" for o in range(OFF - 6, OFF + 7)])
for kn, kk in (("a0z25", LET - 1), ("a1z26", LET)):
    for cn, (nn, cc) in CONFIGS.items():
        print(f"  @{OFF} {kn} {cn}: " + " ".join(f"{m}={gate(rekey(cc, kk[OFF:OFF + N] % nn, m, nn), nn, 100)[0]:+.1f}" for m in ("add", "sub", "beau")))
# (c) trecho do livro
i0, i1 = pos[OFF], pos[min(OFF + N, len(pos) - 1)]
print("trecho do livro @offset (letras 252770..):\n", txt[i0:i0 + 400].replace("\n", " "))
print("... fim do trecho:\n", txt[max(i1 - 200, i0):i1 + 100].replace("\n", " "))
# (d) decode do stream: checkerboard (alfabetos 3.2.2/CANON/keyed) × escapes; Bifid CANON; z-method
s = "".join(str(int(x)) for x in a)
best = []
alphs = {"al322": AL322, "CANON+J..": G.CANON + "J..", "AZ": "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
for p in ("matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "cosmicduality", "yinyang", "salphaseion", "lifeanddeath", "unityofopposites"):
    try: alphs["kw:" + p] = G.keyed_alphabet(p)
    except Exception as e: print("keyed_alphabet falhou para", p, ":", e)
import itertools
dec_err = []
for an, al in alphs.items():
    for e1, e2 in itertools.permutations(range(10), 2):
        try:
            t = G.checkerboard_decode([int(x) for x in s], al, (e1, e2), "0123456789")
        except Exception as e:
            dec_err.append(f"{an}/{e1}{e2}: {e}"); continue
        if not t or len(t) < 20: continue
        sc = G.english_score(t); best.append((sc, an, (e1, e2), t[:80]))
best.sort(reverse=True)
print("checkerboard top-5 (decodes com erro: %d, ex.: %s):" % (len(dec_err), dec_err[:2])); [print(f"  {sc:.2f} {an} esc={e} {t}") for sc, an, e, t in best[:5]]
try:
    ai = "".join("abcdefghi"[(int(x) - 1) % 9] for x in s)
    b = G.bifid(ai, G.CANON, 570); print("bifid CANON 570:", b[:80], round(G.english_score(b), 2))
except Exception as e: print("bifid:", e)
try:
    z = G.z_method([int(x) for x in s]); print("z-method printable:", round(G.printable(z), 2), z[:60])
except Exception as e: print("z-method:", e)
