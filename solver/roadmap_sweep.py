# -*- coding: utf-8 -*-
"""
Roadmap 2023-02-25 (binario revertido, atribuido ao criador):
  yellowblueprimes -> matrixsumlist -> lastwordsbeforearchichoice -> yinyang
  + "wewontgiveawaythepassworditsinfrontofyoureyesbutyourenotseeingit"
  + "verylaststepisatruegiveawaypromised"
Testa essa gramatica (concatenacao ordenada -> sha256 -> AES) contra SMALL/COSMIC.
Tambem as extracoes de Denis Golovkin 2026-03-03 (YB-primes do dbbi sobre
'incaseyoumanage...') e as frases do 'tiny hint' 2026-01-01.
"""
import hashlib, json, os, itertools, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_work", "roadmap_sweep.jsonl")
log = open(OUT, "w", encoding="utf-8")
hits = []

def test(label, pw):
    h = O.aes_open(pw)
    log.write(json.dumps({"label": label, "pw": pw[:80], "hits": h}, ensure_ascii=False) + "\n")
    if h:
        hits.append((label, h)); print(f"!!! HIT {label} -> {h}")

ROAD = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang"]
TAIL1 = "wewontgiveawaythepassworditsinfrontofyoureyesbutyourenotseeingit"
TAIL2 = "verylaststepisatruegiveawaypromised"

cands = []
# 1) roadmap completo e prefixos/sufixos ordenados
for r in range(1, len(ROAD) + 1):
    for combo in itertools.permutations(ROAD, r):
        cands.append(("road_" + "+".join(combo), "".join(combo)))
# ordem canonica + caudas
base = "".join(ROAD)
for extra in ["", TAIL1, TAIL1 + TAIL2, TAIL2]:
    cands.append(("road_full+" + extra[:12], base + extra))
    cands.append(("road_full_yinyang2+" + extra[:12], base + "yinyang" + extra))
# 2) com 'shabef'(=sha256) e 'enter' infixados (gramatica da pagina)
for mid in ["enter", "shabef", "matrixsumlistenter"]:
    cands.append(("road_mid_" + mid, "yellowblueprimes" + mid + "lastwordsbeforearchichoicethispasswordyinyang"))
# 3) extracoes Denis Golovkin 2026-03-03
DENIS = "ncsyangcahiriasogaleafayanestve"
cands.append(("denis_extract", DENIS))
cands.append(("denis_extract_yinyang", "yinyang" + DENIS))
cands.append(("denis_extract2", DENIS + "yinyang"))
# 4) tiny hint 2026-01-01
for s in ["makethebestofeverything", "tinyhint", "happynewyearmakethebestofeverything",
          "ohandheresatinyhint", "makethebestofeverythingyinyang",
          "yinyangmakethebestofeverything", "12345", "salvation",
          "yinyangsalvation", "salvationyinyang"]:
    cands.append(("tiny_" + s[:20], s))
# 5) 'in front of your eyes' literal (o Bingo)
for s in ["itsinfrontofyoureyesbutyourenotseeingit",
          "infrontofyoureyes", "itsinfrontofyoureyes",
          "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyangwewontgiveawaythepassworditsinfrontofyoureyesbutyourenotseeingitverylaststepisatruegiveawaypromised"]:
    cands.append(("eyes_" + s[:24], s))

for label, s in cands:
    test(label + "_sha256", hashlib.sha256(s.encode()).hexdigest())
    test(label + "_raw", s)
    test(label + "_sha256up", hashlib.sha256(s.upper().encode()).hexdigest())
    test(label + "_dbl", hashlib.sha256(hashlib.sha256(s.encode()).hexdigest().encode()).hexdigest())

log.close()
print(f"\ntestados: {len(cands)*4}")
print("=== VEREDITO ===")
print(f"ABRIU! {hits}" if hits else "Roadmap/tiny-hint/Denis-extract -> NEGATIVO em SMALL e COSMIC.")
