# -*- coding: utf-8 -*-
"""Modelo de quadgramas de ingles (corpus = result.json do Telegram).
Usado pelo oraculo 'readable' como SINAL (nao decide solve): plaintext
com score alto vira candidato para revisao humana.
Cache em disco para nao reconstruir toda vez.
"""
import os, re, math, json, pickle
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CACHE = os.path.join(HERE, "quadgram.pkl")
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(A)}

def _corpus():
    data = json.load(open(os.path.join(ROOT, "result.json"), encoding="utf-8"))
    for m in data.get("messages", []):
        t = m.get("text", "")
        if isinstance(t, list):
            t = " ".join(x if isinstance(x, str) else x.get("text", "") for x in t)
        letters = re.sub(r"[^A-Za-z]", "", t)
        if len(letters) > 20:
            v = sum(letters.upper().count(c) for c in "AEIOU") / len(letters)
            if 0.25 < v < 0.6:  # descarta blobs base64
                yield t

def build(force=False):
    if not force and os.path.exists(CACHE):
        with open(CACHE, "rb") as f:
            return pickle.load(f)
    counts = Counter()
    for t in _corpus():
        t = re.sub(r"[^A-Z]", "", t.upper())
        for i in range(len(t) - 3):
            counts[t[i:i+4]] += 1
    total = sum(counts.values()) or 1
    floor = math.log10(0.01 / total)
    tab = [floor] * (26 ** 4)
    for q, c in counts.items():
        k = ((IDX[q[0]] * 26 + IDX[q[1]]) * 26 + IDX[q[2]]) * 26 + IDX[q[3]]
        tab[k] = math.log10(c / total)
    with open(CACHE, "wb") as f:
        pickle.dump((tab, floor), f)
    return tab, floor

class Scorer:
    def __init__(self):
        self.tab, self.floor = build()
    def __call__(self, text):
        t = [IDX[c] for c in text if c in IDX]
        if len(t) < 4:
            return self.floor
        s = 0.0
        for i in range(len(t) - 3):
            s += self.tab[((t[i] * 26 + t[i+1]) * 26 + t[i+2]) * 26 + t[i+3]]
        return s / (len(t) - 3)

if __name__ == "__main__":
    sc = Scorer()
    print("EN sample:", round(sc("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"), 3))
    print("random   :", round(sc("QXZJKVWPBFMGHLCDNRTSYAEIOU" * 2), 3))
    print("(ingles legivel ~ -2.5..-3.5 ; ruido < -6)")
