# -*- coding: utf-8 -*-
"""
5 lacunas determinísticas específicas (nunca cobertas pelos scripts existentes).
Padrao do puzzle = concatenacao ORDENADA de keywords -> SHA256 -> senha AES.
Todas canonicas (verbatim dos hints), sem variantes arbitrarias. Segundos.
"""
import hashlib, json, os
import oracles as O
from prime_attack import bifid_decrypt, hard_oracles, CANON, ALPHA25
from scorer import Scorer

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_work", "five_gaps.jsonl")
log = open(OUT, "w", encoding="utf-8")
hits = []

def test(label, pw):
    h = O.aes_open(pw)
    log.write(json.dumps({"label": label, "pw": pw[:50], "hits": h}, ensure_ascii=False) + "\n")
    if h:
        hits.append((label, h)); print(f"!!! HIT {label} -> {h}")
    return h

# tokens verbatim da pagina SalPhaseIon decodificada (ordem de aparicao)
TOK = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
       "shabef", "ourfirsthintisyourlastcommand"]

MATRIX_ROWS = [
    "0 0 1 1 0 1 0 0 1 0 1 1 0 0","1 1 1 1 0 0 1 1 1 0 1 0 1 1",
    "1 1 0 1 1 1 0 1 0 0 1 0 0 1","0 1 1 0 1 0 0 0 0 1 1 1 0 1",
    "0 1 1 0 0 0 1 1 0 0 0 1 1 0","1 0 0 1 1 0 0 0 1 0 0 0 1 1",
    "1 0 0 1 1 1 0 0 0 1 0 0 0 0","1 1 1 0 0 0 0 0 0 0 1 0 0 0",
    "0 0 0 1 1 1 0 1 1 1 1 1 0 1","1 1 1 1 1 1 0 0 1 1 0 0 0 1",
    "1 1 0 1 0 0 0 0 0 1 1 0 1 1","1 1 1 1 0 0 1 0 1 0 1 1 0 0",
    "0 1 0 1 1 1 0 1 0 0 0 1 1 0","0 1 1 0 1 1 0 1 1 0 1 0 1 1",
]

print("=== LACUNA 1: concatenacao ordenada dos tokens -> sha256 ===")
concat_ns = "".join(TOK)
concat_z  = "z".join(TOK)
for label, s in [("tok_concat_nospace", concat_ns), ("tok_concat_z", concat_z),
                 ("tok_concat_upper", concat_ns.upper()),
                 ("firsthint_matrixsum", "ourfirsthintisyourlastcommandmatrixsumlist"),
                 ("matrixsum_firsthint", "matrixsumlistourfirsthintisyourlastcommand")]:
    test(label+"_sha256", hashlib.sha256(s.encode()).hexdigest())
    test(label+"_raw", s)

print("=== LACUNA 2: HASHTHETEXT = sha256(texto da matriz) ===")
mat_spaces = "\n".join(MATRIX_ROWS)
mat_nospace_nl = "\n".join(r.replace(" ", "") for r in MATRIX_ROWS)
mat_flat = "".join(r.replace(" ", "") for r in MATRIX_ROWS)
mat_spaced_flat = " ".join(MATRIX_ROWS)
for label, s in [("mat_spaces_nl", mat_spaces), ("mat_nospace_nl", mat_nospace_nl),
                 ("mat_flat", mat_flat), ("mat_spaced_flat", mat_spaced_flat)]:
    test("HASHTHETEXT_"+label, hashlib.sha256(s.encode()).hexdigest())
    test("HASHTHETEXT_"+label+"_double", hashlib.sha256(hashlib.sha256(s.encode()).hexdigest().encode()).hexdigest())

print("=== LACUNA 3: sha256(gsmg.io/theseedisplanted) URL ===")
for label, s in [("url_bare", "gsmg.io/theseedisplanted"),
                 ("url_https", "https://gsmg.io/theseedisplanted"),
                 ("url_seedonly", "theseedisplanted"),
                 ("url_upper", "GSMG.IO/THESEEDISPLANTED")]:
    test("url_"+label+"_sha256", hashlib.sha256(s.encode()).hexdigest())
    test("url_"+label+"_raw", s)

print("=== LACUNA 4: 101 mod 9 = 2 como deslocamento ESCALAR uniforme sobre faed ===")
scorer = Scorer()
faed = O.sources()["faed"]
digits = [ord(c)-ord('a') for c in faed]  # 0..8
for shift in [101 % 9, -(101 % 9), 101 % 26]:
    for m in (9,):
        shifted = [(d + shift) % m for d in digits]
        sym = "".join("abcdefghi"[d % 9] for d in shifted)
        for period in (570, 190, 95, 57, 38):
            pt = bifid_decrypt(sym.upper(), CANON, period)
            sc = scorer(pt) if set(pt) <= set(ALPHA25) else -9.9
            log.write(json.dumps({"label": f"scalar101_s{shift}_p{period}", "score": round(sc,3), "head": pt[:40]}, ensure_ascii=False)+"\n")
            hit = hard_oracles(pt)
            if hit: hits.append((f"scalar101_s{shift}_p{period}", hit)); print(f"!!! HIT scalar101 {hit}")

print("=== LACUNA 5: sha256(matrixsumlist) e sha256(101) ===")
for label, s in [("matrixsumlist", "matrixsumlist"), ("101", "101"),
                 ("matrixsumlist101", "matrixsumlist101"), ("101matrixsumlist", "101matrixsumlist")]:
    test("kw_"+label+"_sha256", hashlib.sha256(s.encode()).hexdigest())
    test("kw_"+label+"_raw", s)

log.close()
print("\n=== VEREDITO ===")
if hits:
    print(f"ABRIU! {hits}")
else:
    print("Todas as 5 lacunas -> NEGATIVO. Rotas deterministicas de endpoint TOTALMENTE esgotadas.")
