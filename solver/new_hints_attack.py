# -*- coding: utf-8 -*-
"""
new_hints_attack.py — bateria de senhas derivadas dos hints novos do criador
(ENDGAME.md secao 2026-09-01 (b)) + vocabulario extraido do result.json
(pista barrystyle "Cosmic Duality Book Page - Life and Death", dez/2022).

Oraculos: aes_open / check_privkey de solver/oracles.py.
Log: _work/new_hints_attack.jsonl
"""
import os, sys, json, hashlib, itertools, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracles import aes_open, check_privkey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "_work", "new_hints_attack.jsonl")

def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).digest()

def variants(w):
    """gera variacoes de caixa/formato de uma palavra/frase."""
    out = {w, w.lower(), w.upper(), w.title().replace(" ", ""),
           w.replace(" ", ""), w.replace(" ", "").lower(),
           w.title(), w.capitalize()}
    return out

CANDS = set()
FAM = {}  # familia -> count

def add(fam, c):
    if c and c not in CANDS:
        CANDS.add(c)
        FAM[fam] = FAM.get(fam, 0) + 1

# ---------------- (a) PURPLE ----------------
purple_base = ["purple", "purplepill", "thepurplepill", "purplecarrots",
               "carrots", "purple pill", "the purple pill", "purple carrots",
               "takethepurplepill", "purplepillmatrix"]
for w in purple_base:
    for v in variants(w):
        add("purple", v)

# cores hex
hexes = {"yellow": "FFF200", "blue": "3F48CC", "red": "FF0000",
         "purple": "800080", "purple2": "A020F0", "purple3": "9400D3",
         "orange": "FFA500"}
def hx(h): return bytes.fromhex(h)
def avg(a, b): return bytes((x + y) // 2 for x, y in zip(a, b))
def xorb(a, b): return bytes(x ^ y for x, y in zip(a, b))
def orb(a, b): return bytes(x | y for x, y in zip(a, b))

mixes = {
    "avg_yb": avg(hx("FFF200"), hx("3F48CC")).hex(),
    "xor_yb": xorb(hx("FFF200"), hx("3F48CC")).hex(),
    "or_yb": orb(hx("FFF200"), hx("3F48CC")).hex(),
    "avg_rb": avg(hx("FF0000"), hx("3F48CC")).hex(),
    "xor_rb": xorb(hx("FF0000"), hx("3F48CC")).hex(),
    "or_rb": orb(hx("FF0000"), hx("3F48CC")).hex(),
}
for v in mixes.values():
    add("purple", v); add("purple", v.upper()); add("purple", v.lower())

color_seqs = [("FFF200", "3F48CC"), ("3F48CC", "FFF200"),
              ("FFF200", "3F48CC", "FF0000"), ("FF0000", "3F48CC"),
              ("FFF200", "3F48CC", "800080"), ("800080", "FFF200", "3F48CC")]
for s in color_seqs:
    add("purple", "".join(s)); add("purple", "".join(s).lower())

# somas de digitos hex e numeros
for n in ["47", "54", "101", "7", "30", "16", "4754", "5447", "47101",
          "547", "47+54", "1017", "73016"]:
    add("purple", n)
for name, h in hexes.items():
    ds = sum(int(c, 16) for c in h)
    add("purple", str(ds)); add("purple", name + str(ds))
    add("purple", name); add("purple", h); add("purple", h.lower())

poems = ["rosesarewhitebutoftenred", "yellowhasanumberandsodoesblue",
         "roses are white but often red", "yellow has a number and so does blue",
         "RosesAreWhiteButOftenRed", "YellowHasANumberAndSoDoesBlue",
         "rosesarewhite", "butoftenred"]
for w in poems:
    for v in variants(w): add("purple", v)

# ---------------- (b) PASSAPORTE NEO ----------------
dates = ["11SEP2001", "11092001", "09112001", "2001-09-11", "11/09/2001",
         "SEP112001", "11sep2001", "11Sep2001", "11 SEP 2001", "11/sep/2001",
         "20010911", "9112001", "11901", "11.09.2001", "09/11/2001",
         "September112001", "september112001", "11september2001",
         "11SEP01", "Sep112001"]
tails = ["", "neo", "Neo", "NEO", "passport", "Passport", "expiry", "expires",
         "thematrixhasyou", "thematrix", "matrix", "thomasanderson",
         "neopassport", "passportneo", "mrAnderson"]
for d in dates:
    for t in tails:
        add("neo", d + t)
        if t: add("neo", t + d)
        if t: add("neo", d + " " + t)

# ---------------- (c) GSMG ----------------
gsmg = ["globallysupportingmygeneration", "GloballySupportingMyGeneration",
        "globally supporting my generation", "GLOBALLYSUPPORTINGMYGENERATION",
        "gsmg", "GSMG", "gsmgio", "GSMG.io", "gsmg.io", "GSMGIO",
        "gsmgiogloballysupportingmygeneration",
        "globallysupportingmygenerationgsmg", "gsmgloballysupportingmygeneration"]
for w in gsmg:
    for v in variants(w): add("gsmg", v)

# ---------------- (d) R18/A1/B2, 21, 1812 ----------------
r18 = ["r18a1b2", "R18A1B2", "r=18a=1b=2", "1812", "1812bit", "1812bits",
       "21", "twentyone", "twenty-one", "21bit", "21bits", "1821", "2118",
       "1218", "a1z26", "r18", "a1b2"]
for w in r18: add("r18", w)

def a1z26(word):
    return [ord(c) - 96 for c in word.lower() if 'a' <= c <= 'z']
for word in ["dbbi", "faed", "cosmicduality", "salphaseion", "cosmic", "duality"]:
    nums = a1z26(word)
    add("r18", str(sum(nums)))
    add("r18", "".join(map(str, nums)))
    add("r18", "".join(f"{n:02d}" for n in nums))
    add("r18", word + str(sum(nums)))
    add("r18", str(sum(nums)) + word)
    p = 1
    for n in nums: p *= n
    add("r18", str(p))

# ---------------- (e) VIDA E MORTE / LIVRO (FASE 0) ----------------
life = ["lifeanddeath", "life and death", "LifeAndDeath", "Life and Death",
        "lifeanddeathpage", "lifeanddeathbookpage", "cosmicdualitylifeanddeath",
        "cosmicduality", "CosmicDuality", "cosmic duality",
        "cosmicdualitybook", "cosmicdualitybookpage", "cosmicdualitypage",
        "cosmicdualitymys0000time", "cosmicdualitymysteriesoftheunknown",
        "mysteriesoftheunknown", "mysteries of the unknown",
        "MysteriesOfTheUnknown", "timelife", "TimeLife", "timelifebooks",
        "godandsatan", "lightanddarkness", "maleandfemale", "goodandevil",
        "innocenceandexperience", "godandsatanlightanddarkness",
        "goodandevillifeanddeath", "lifeanddeathgoodandevil",
        "lightanddarknesslifeanddeath", "yinandyang", "yingyang", "yinyang",
        "opposingforces", "theopposingforces", "dualities",
        "cosmicdualitymysteries", "cosmicduality1991", "lifeanddeath1991",
        "salphaseioncosmicduality", "cosmicdualitysalphaseion"]
for w in life:
    for v in variants(w): add("life", v)

# ---------------- (f) CRUZADAS ----------------
classic = ["shabef", "ans too", "anstoo", "ourfirsthintisyourlastcommand",
           "hashthetext", "matrixsumlist", "yinyang",
           "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"]
newbits = ["purple", "purplepill", "carrots", "11SEP2001", "11092001",
           "lifeanddeath", "cosmicduality", "1812", "21", "gsmg",
           "globallysupportingmygeneration", "mysteriesoftheunknown"]
for c in classic:
    for v in variants(c): add("classic", v)
for c in classic:
    for n in newbits:
        add("cross", c.replace(" ", "") + n)
        add("cross", n + c.replace(" ", ""))
for a, b in itertools.permutations(newbits, 2):
    add("cross", a + b)
# triplas selecionadas + sufixos numericos comuns
for a, b in itertools.permutations(newbits, 2):
    for tail in ["21", "1812", "47", "54", "101", "2001", "1", "0", "0000"]:
        add("cross2", a + b + tail)
for c in classic:
    for n in newbits:
        for tail in ["21", "1812", "2001"]:
            add("cross2", c.replace(" ", "") + n + tail)
for w in ["cosmicduality", "lifeanddeath", "purplepill", "salphaseion",
          "mysteriesoftheunknown", "globallysupportingmygeneration"]:
    for tail in ["11SEP2001", "11092001", "21", "1812", "47", "54", "101",
                 "1", "2", "3", "0000", "1991", "2022", "01", "001"]:
        add("cross2", w + tail); add("cross2", tail + w)

# ---------------- exec ----------------
def main():
    t0 = time.time()
    cands = sorted(CANDS)
    n = len(cands)
    counts = {"aes_md5_sha256_tries": 0, "privkey_tries": 0}
    best = []
    solved = []
    with open(LOG, "w", encoding="utf-8") as log:
        log.write(json.dumps({"event": "start", "candidates": n,
                              "families": FAM}) + "\n")
        for i, cand in enumerate(cands):
            h1 = sha(cand)
            h2 = sha(h1)
            for pw in (cand, h1.hex(), h2.hex()):
                counts["aes_md5_sha256_tries"] += 1
                hits = aes_open(pw)
                if hits:
                    ev = {"event": "AES_HIT", "cand": cand, "via": pw, "hits": hits}
                    log.write(json.dumps(ev) + "\n"); log.flush()
                    print("AES HIT!", ev)
                    solved.append(ev)
            for dig in (h1, h2):
                counts["privkey_tries"] += 1
                r = check_privkey(dig)
                if r:
                    ev = {"event": "PRIVKEY_HIT", "cand": cand, "result": r}
                    log.write(json.dumps(ev) + "\n"); log.flush()
                    print("PRIVKEY HIT!", ev)
                    solved.append(ev)
            if i % 2000 == 0:
                log.write(json.dumps({"event": "progress", "i": i}) + "\n")
        log.write(json.dumps({"event": "done", "elapsed_s": round(time.time() - t0, 1),
                              "counts": counts, "solved": solved}) + "\n")
    print(json.dumps({"candidates": n, "families": FAM, "counts": counts,
                      "solved": len(solved)}, indent=2))
    if solved:
        out = os.path.join(ROOT, "solver", "out", "SOLVED.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        json.dump(solved, open(out, "w"), indent=2)

if __name__ == "__main__":
    main()
