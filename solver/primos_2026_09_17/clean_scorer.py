# -*- coding: utf-8 -*-
"""Scorer de quadgramas DESCONTAMINADO: mesmo corpus (result.json) mas sem mensagens dbbi-like
(letras >= 70% em a-i, ou run de >= 12 letras a-i). O scorer original aprende os quadgramas do
proprio dbbi (DIFH = -5,1 em vez do piso), o que infla qualquer leitura identidade do residuo."""
import os, re, math, pickle, sys
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver")
import scorer as S0
from collections import Counter
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quadgram_clean.pkl")
RUN = re.compile(r"[a-iA-I]{10,}")
LONG = re.compile(r"[A-Za-z]{20,}")   # token alfabetico >= 20 letras = sopa de letras/hash/url, nao ingles
def build():
    if os.path.exists(CACHE): return pickle.load(open(CACHE, "rb"))
    counts = Counter(); kept = dropped = 0
    for t in S0._corpus():
        letters = re.sub(r"[^A-Za-z]", "", t)
        if RUN.search(t) or LONG.search(t) or sum(c in "abcdefghiABCDEFGHI" for c in letters) / len(letters) >= 0.6:
            dropped += 1; continue
        kept += 1; u = re.sub(r"[^A-Z]", "", t.upper())
        for i in range(len(u) - 3): counts[u[i:i + 4]] += 1
    total = sum(counts.values()) or 1; floor = math.log10(0.01 / total)
    tab = [floor] * (26 ** 4)
    for q, c in counts.items():
        tab[((S0.IDX[q[0]] * 26 + S0.IDX[q[1]]) * 26 + S0.IDX[q[2]]) * 26 + S0.IDX[q[3]]] = math.log10(c / total)
    pickle.dump((tab, floor, kept, dropped), open(CACHE, "wb"))
    return tab, floor, kept, dropped
class Scorer(S0.Scorer):
    def __init__(self):
        self.tab, self.floor, self.kept, self.dropped = build()
if __name__ == "__main__":
    sc = Scorer(); s0 = S0.Scorer()
    print("kept/dropped:", sc.kept, sc.dropped)
    for t in ("DIFHCCGIHAEEIHGGEGEBGEHHEHHFAFDHFFCDBFCCCGFEGGECDCIFFFGIGEEAE", "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG", "DIFH", "GEHH",
              "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALF"):
        print(t[:20], "orig", round(s0(t), 3), "limpo", round(sc(t), 3))
