# -*- coding: utf-8 -*-
"""Critico, parte 4 (lacuna flagada pelo agente 1, nunca testada): residuo como CHAVE periodica sobre faed
(Vigenere: F+K, F-K, K-F mod 9; a=0..8; ambas direcoes de faed e da chave; 61/60 fases) -> 570 simbolos ->
oraculo = a propria regra do lead (x / x+sufixo em primos logicos 1- e 0-based) — faed nunca segmenta no nulo (ag.2),
logo qualquer segmentacao completa seria decisiva. Controle positivo: planta um faed sintetico com marcadores."""
import sys, os, json, random
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from critic4 import segment, SCHEMES, L9, PR
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"; R83 = R84[:-1]
RULES = [(x, suf, scn) for x in L9 for suf in [""] + [L9] + list(L9) for scn in ("prime1", "prime0")]
def hits(s): return [(x, suf, scn) for x, suf, scn in RULES if segment(s, x, suf, SCHEMES[scn])[0]]
# controle positivo
rng = random.Random(1); toks = [("b" + ("e" if rng.random() < .3 else "")) if k in PR else rng.choice(L9) for k in range(1, 540)]
assert hits("".join(toks)), "controle positivo falhou"
n = 0; found = []
F = [ord(c) - 97 for c in G.FAED]
for kname, key in (("R84", R84), ("R83", R83)):
    K = [ord(c) - 97 for c in key]
    for kdir in (1, -1):
        KK = K[::kdir]
        for fdir in (1, -1):
            FF = F[::fdir]
            for ph in range(len(KK)):
                ks = [KK[(i + ph) % len(KK)] for i in range(len(FF))]
                for op, fn in (("F+K", lambda f, k: (f + k) % 9), ("F-K", lambda f, k: (f - k) % 9), ("K-F", lambda f, k: (k - f) % 9)):
                    s = "".join(chr(97 + fn(f, k)) for f, k in zip(FF, ks)); n += 1
                    h = hits(s)
                    if h: found.append((kname, kdir, fdir, ph, op, h))
out = {"n_transformadas": n, "n_regras_por_transformada": len(RULES), "n_dp": n * len(RULES), "hits": found}
print(json.dumps(out)); G.jsonl(os.path.join(HERE, "critic4d.jsonl"), {"hipotese": "residuo como chave Vigenere mod 9 sobre faed; oraculo = regra dos primos", "resultado": out})
