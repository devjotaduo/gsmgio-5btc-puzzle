"""checkerboard_phrases — faed/dbbi como straddling checkerboard com alfabeto keyed por FRASE do puzzle.

Hipotese (falsificavel, espaco finito): assim como a fase 3.2.2 usou o alfabeto
FUBCDORA.LETHINGKYMVPS.JQZXW derivado da frase "fubcd-king & oracle-queen, thingky mvps",
faed (inteiro / sem prefixo / metades 285) e/ou dbbi sao um straddling checkerboard cujo
alfabeto vem de uma frase-chave ja conhecida do puzzle, com digitos a=1..i=9 (identidade)
e 2 escapes (ou o layout 3.2.2: universo 0-9 com i->0). Se verdadeiro, o decode tem
score de ingles > -4.5 e sha256(plaintext) abre SMALL/COSMIC/TAIL32 ou e' a privkey.
"""
import sys, json, hashlib, itertools, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\checkerboard_phrases.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"hypothesis": __doc__.strip()})

# ---------------------------------------------------------------- controle positivo (fase 3.2.2)
alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
d322 = [int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"]
pt322 = G.checkerboard_decode(d322, alpha322, (1, 4), "0123456789")
assert pt322.startswith("INCASEYOUMANAGETOCRACKTHIS")
G.jsonl(LOG, {"control": "fase 3.2.2 reproduzida", "score": round(G.english_score(pt322), 3), "head": pt322[:40]})

# ---------------------------------------------------------------- frases
PHRASES = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
 "ourfirsthintisyourlastcommand", "anstoo", "shabef", "shabefanstoo", "yellowblueprimes",
 "rosesarewhitebutoftenred", "yellowhasanumberandsodoesblue", "hushhush", "salphaseion",
 "salvation", "cosmicduality", "yinyang", "yingyang", "followthewhiterabbit", "theseedisplanted",
 "gsmgmeganigma", "gsmgio5btcpuzzlechallenge", "hashthetext", "thematrixhasyou", "causality",
 "theflowerblossomsthroughwhatseemstobeaconcretesurface", "jacquefresco",
 "lastwordsbeforearchichoicethispassword", "halfandbetterhalf", "thewarning", "logic",
 "knockknockneo", "temetnosce", "whiterabbit", "keymaker", "merovingian", "architect", "oracle",
 "zion", "source", "purplepill", "globallysupportingmygeneration", "gsmg", "bitcoin",
 "safenetlunahsm", "heisenbergsuncertaintyprinciple", "giveitjustonesecond",
 "lifeanddeath", "lemiroirdelavieetdelamort", "killprocess", "betterhalf", "primebasics",
 "returntothesourcecodes", "thedoortoyourright", "fubcdkingoraclequeenthingkymvps",
 "dbbi", "faed", "abcdefghijklmnopqrstuvwxyz", "etaoinshrdlcumwfgypbvkjxqz",
 "qwertyuiopasdfghjklzxcvbnm", "zyxwvutsrqponmlkjihgfedcba"]

def dedupe(s, merge=None):
    """1a ocorrencia; merge=('J','I') troca J por I antes."""
    out = []
    for c in s.upper():
        if merge and c == merge[0]: c = merge[1]
        if "A" <= c <= "Z" and c not in out: out.append(c)
    return "".join(out)
def dotstyle(s):
    """Convencao 3.2.2: letra repetida vira '.' (celula vazia)."""
    out = []
    for c in s.upper():
        if "A" <= c <= "Z": out.append(c if c not in out else ".")
    return "".join(out)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def alphabets25(p):
    for merge, base in ((("J", "I"), AZ.replace("J", "")), (("I", "J"), AZ.replace("I", ""))):
        kw = dedupe(p, merge); fill = "".join(c for c in base if c not in kw)
        yield f"kw+fill_{merge[0]}={merge[1]}", kw + fill
        yield f"fill+kw_{merge[0]}={merge[1]}", fill + kw
    ds = dotstyle(p); fill = "".join(c for c in AZ if c not in ds)
    yield "dot322_trunc25", (ds + fill)[:25]
    yield "dot322_IJ_trunc25", (dotstyle(p.upper().replace("J", "I")) + "".join(c for c in AZ.replace("J", "") if c not in ds))[:25]
def alphabets28(p):
    kw = dedupe(p); fill = "".join(c for c in AZ if c not in kw)
    yield "kw+fill+..", kw + fill + ".."
    yield "..+fill+kw", ".." + fill + kw
    yield "kw+.+fill+.", kw + "." + fill + "."
    ds = dotstyle(p); fill = "".join(c for c in AZ if c not in ds)
    yield "dot322", (ds + "." + fill + "." * 28)[:28]

# ---------------------------------------------------------------- textos
TEXTS = {"faed": G.FAED, "faed_noprefix": G.FAED[4:], "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:], "dbbi": G.DBBI}
D1 = {k: G.digits(v) for k, v in TEXTS.items()}                                   # a=1..i=9
D0 = {k: [0 if d == 9 else d for d in v] for k, v in D1.items()}                  # i->0 (layout 3.2.2)
ESC9 = [(a, b) for a in range(1, 10) for b in range(1, 10) if a != b]             # 72 ordenados
ESC10 = [(a, b) for a in range(10) for b in range(10) if a != b]                  # 90 ordenados

n_tests = 0; n_cand = 0; hard = []; soft = []; best = {"score": -99}
def check(pt, how):
    """Detector -> oraculo duro."""
    global n_cand, best
    sc = G.english_score(pt)
    if sc > best["score"]: best = {"score": round(sc, 3), "text": pt[:120], "how": how}
    wh = [w for w in G.word_hits(pt, 6)] if sc > -5.2 else []
    if sc > -4.5 or len(wh) >= 2:
        n_cand += 1
        rec = {"cand": how, "score": round(sc, 3), "words": wh[:8], "head": pt[:80]}
        for pw in (pt, pt.lower(), G.shahex(pt), G.shahex(pt.lower())):
            h, s = G.try_password_all(pw)
            if h: hard.append({"pw": pw, "hits": h, **rec})
            if s: soft.append({"pw": pw[:64], "soft": s, **rec})
        for k in (G.sha(pt.encode()), G.sha(pt.lower().encode())):
            r = G.priv_hit(k)
            if r: hard.append({"privkey": k.hex(), "addr": r, **rec})
        G.jsonl(LOG, rec)

t0 = time.time()
for p in PHRASES:
    # frase como brainwallet / senha direta (sobrepoe familia fechada de ~230k senhas; contado a parte)
    for r in G.phrase_priv(p): hard.append({"brainwallet": p, "hit": r})
    for pw in (p, G.shahex(p)):
        h, s = G.try_password_all(pw)
        if h: hard.append({"pw": pw, "hits": h, "src": "phrase"})
        if s: soft.append({"pw": pw, "soft": s, "src": "phrase"})
    for an, alpha in alphabets25(p):
        assert len(alpha) == 25, (an, alpha)
        for tn, digs in D1.items():
            for e in ESC9:
                n_tests += 1
                check(G.checkerboard_decode(digs, alpha, e, "123456789"), f"{p}|{an}|{tn}|esc{e}|u1-9")
    for an, alpha in alphabets28(p):
        assert len(alpha) == 28, (an, alpha)
        for tn, digs in D0.items():
            for e in ESC10:
                n_tests += 1
                check(G.checkerboard_decode(digs, alpha, e, "0123456789"), f"{p}|{an}|{tn}|esc{e}|u0-9,i=0")
    print(p, n_tests, n_cand, best["score"], round(time.time() - t0), flush=True)

# controle interno: o proprio alfabeto 3.2.2 no universo 1-9 e 0-9 (i->0) com escapes (1,4) sobre faed/dbbi
for tn in D1:
    n_tests += 2
    check(G.checkerboard_decode(D1[tn], alpha322.replace(".", "")[:25], (1, 4), "123456789"), f"alpha322|{tn}|esc(1,4)|u1-9")
    check(G.checkerboard_decode(D0[tn], alpha322, (1, 4), "0123456789"), f"alpha322|{tn}|esc(1,4)|u0-9,i=0")

summary = {"n_tests": n_tests, "n_candidates": n_cand, "n_phrase_pw": len(PHRASES) * 2, "hard": hard, "soft": soft, "best": best, "secs": round(time.time() - t0)}
G.jsonl(LOG, summary)
print(json.dumps(summary, ensure_ascii=False, indent=1))
