# -*- coding: utf-8 -*-
"""
FAMILIA dbbi_geometry — dbbi (91) como MATRIZ cujo "sum list" e a chave do faed.
Geometrias: tri 1..13, tri 13..1, tri-superior 14x14 (sem diagonal, + simetrica),
espiral 10x10 truncada (2 sentidos), 7x13/13x7 (so nos usos NOVOS: checkerboard,
mod-25/26 sobre BIF, transposicao, periodo, senha — keystream->Bifid ja fechado
em dbbi_repeat_attack.py). Mais: dbbi como texto (letra->0 + z-method, a1z26 de
pares, dbbi +- faed mod 9) e dbbi nas 24 posicoes primas <-> 24 cores.
Oraculos duros: G.try_password_all / G.priv_hit / G.scan_priv. Triagem: english_score.
"""
import sys, os, json, itertools, random, hashlib
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = os.path.join(SP, "dbbi_geometry.jsonl")
if os.path.exists(LOG): os.remove(LOG)
def log(o): G.jsonl(LOG, o)
log({"hypothesis": "dbbi (91) e uma matriz cujo 'sum list' (matrixsumlist) e a chave do faed; "
     "geometrias finitas (7x13,13x7,tri1..13,tri13..1,tri-sup 14x14,espiral 10x10) x a=0/1; "
     "lista usada como keystream mod-9 (->Bifid/checkerboard), mod-25/26 sobre BIF, chave de "
     "transposicao, periodo Bifid e senha. Mais dbbi-como-texto e dbbi@primos<->cores."})

N = {"constr": 0, "aes": 0, "priv": 0}
HARD, SOFT, BEST = [], [], []   # BEST: (score, text, how)
DBBI, FAED = G.DBBI, G.FAED
BIF = G.bif_full()
REST = BIF[7:]
BASE = G.english_score(BIF)
def d9(s, a0): return [ord(c) - 97 + (0 if a0 else 1) for c in s]
def letters(v): return "".join(chr(97 + x % 9) for x in v)

# ---------------------------------------------------------------- oraculos
def keep(score, text, how):
    BEST.append((score, text[:80], how)); BEST.sort(reverse=True); del BEST[30:]
def oracle_text(t, how):
    """t: str. Senha raw + sha256hex nos 3 blobs; sha256(t) como privkey."""
    for pw in (t, G.shahex(t)):
        h, s = G.try_password_all(pw); N["aes"] += 6
        for x in h: x["pw"] = pw; x["how"] = how; HARD.append(x); log({"HARD": x})
        for x in s: x["pw"] = pw[:64]; x["how"] = how; SOFT.append(x)
    N["priv"] += 1
    r = G.priv_hit(G.sha(t))
    if r: HARD.append({"priv": G.sha(t).hex(), "how": how, "r": r}); log({"HARD_PRIV": how, "key": G.sha(t).hex()})
def oracle_bytes(b, how):
    if not b: return
    N["priv"] += max(1, len(b) - 31)
    for hit in G.scan_priv(b, how):
        HARD.append({"scan": hit, "how": how, "hex": b.hex()}); log({"HARD_SCAN": str(hit), "hex": b.hex()})
    if G.printable(b) >= 0.85: keep(G.english_score(b.decode("latin-1")), b.decode("latin-1"), how)
    oracle_text(b.decode("latin-1"), how + "|bytes-as-pw")
def score_text(t, how, oracle=True):
    N["constr"] += 1
    sc = G.english_score(t)
    keep(sc, t, how)
    if sc > -4.5 or G.semantic(t.encode()) and sc > -5.0:
        log({"READABLE?": how, "score": sc, "text": t[:120]})
    if oracle: oracle_text(t, how)

# ---------------------------------------------------------------- geometrias
def tri_rows(v, asc=True):
    lens = list(range(1, 14)) if asc else list(range(13, 0, -1))
    rows, i = [], 0
    for L in lens: rows.append(v[i:i + L]); i += L
    return rows
def rowsums(rows): return [sum(r) for r in rows]
def colsums(rows):
    w = max(map(len, rows))
    return [sum(r[j] for r in rows if j < len(r)) for j in range(w)]
def tri14(v):
    """triangulo superior de 14x14 sem diagonal, preenchido por linhas."""
    M = [[0] * 14 for _ in range(14)]; k = 0
    for r in range(14):
        for c in range(r + 1, 14): M[r][c] = v[k]; k += 1
    assert k == 91
    rs = [sum(M[r]) for r in range(14)]; cs = [sum(M[r][c] for r in range(14)) for c in range(14)]
    return rs, cs, [rs[i] + cs[i] for i in range(14)]
def spiral10(v, rev=False):
    order = G.spiral_ccw(10)
    if rev: order = order[::-1]
    M = [[0] * 10 for _ in range(10)]
    for (r, c), x in zip(order, v): M[r][c] = x
    return [sum(r) for r in M], [sum(M[r][c] for r in range(10)) for c in range(10)]
def grid(v, w): return [v[i:i + w] for i in range(0, 91, w)]

LISTS = {}   # nome -> lista de somas
for a0 in (True, False):
    tag = "a0" if a0 else "a1"; v = d9(DBBI, a0)
    for asc in (True, False):
        rows = tri_rows(v, asc); t = f"tri{'13' if asc else '13rev'}"
        LISTS[f"{t}_rows_{tag}"] = rowsums(rows); LISTS[f"{t}_cols_{tag}"] = colsums(rows)
    rs, cs, sym = tri14(v)
    LISTS[f"tri14_rows_{tag}"] = rs; LISTS[f"tri14_cols_{tag}"] = cs; LISTS[f"tri14_sym_{tag}"] = sym
    for rev in (False, True):
        rs, cs = spiral10(v, rev)
        LISTS[f"spiral10{'rev' if rev else ''}_rows_{tag}"] = rs; LISTS[f"spiral10{'rev' if rev else ''}_cols_{tag}"] = cs
    for w in (7, 13):
        g = grid(v, w)
        LISTS[f"g{len(g)}x{w}_rows_{tag}"] = rowsums(g); LISTS[f"g{len(g)}x{w}_cols_{tag}"] = colsums(g)
LISTS["dbbi91_a1"] = d9(DBBI, False)   # 91 x 1: a propria lista (apenas usos novos)
log({"lists": {k: v for k, v in LISTS.items()}})
CLOSED_KS = {k for k in LISTS if k.startswith(("g7x13", "g13x7", "dbbi91"))}   # keystream mod-9->Bifid ja fechado

# ---------------------------------------------------------------- controles positivos
def ks_apply(f, K, off, mode):
    L = len(K)
    if mode == "add": return [(f[i] + K[(i + off) % L]) % 9 for i in range(len(f))]
    if mode == "sub": return [(f[i] - K[(i + off) % L]) % 9 for i in range(len(f))]
    return [(K[(i + off) % L] - f[i]) % 9 for i in range(len(f))]
F0 = d9(FAED, True)
assert G.bifid(letters(F0).upper(), G.CANON, 570).startswith("BTCSEED")
rng = random.Random(7); Kp = [rng.randrange(9) for _ in range(13)]
enc = ks_apply(F0, Kp, 5, "add")
assert G.bifid(letters(ks_apply(enc, Kp, 5, "sub")).upper(), G.CANON, 570).startswith("BTCSEED")
enc = ks_apply(F0, Kp, 3, "beau")
assert G.bifid(letters(ks_apply(enc, Kp, 3, "beau")).upper(), G.CANON, 570).startswith("BTCSEED")
alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
digs = [int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"]
assert G.checkerboard_decode(digs, alpha322, (1, 4), "0123456789").startswith("INCASEYOUMANAGE")
log({"control": "keystream add/sub/beau recupera BTCSEED com alvo plantado; checkerboard reproduz 3.2.2"})

PERIODS = (570, 285, 91, 38, 15, 14, 13, 7)
CB_ALPHAS = {"canon": G.CANON, "p322": "FUBCDORALETHINGKYMVPSQZXW"}   # 25 letras (sem J)
ESC = [(a, b) for a in range(1, 10) for b in range(a + 1, 10)]      # 36

# ---------------------------------------------------------------- (i) keystream mod-9 -> Bifid / checkerboard
for name, K in LISTS.items():
    for kname, KK in ((name, K), (name + "_rev", K[::-1])):
        for off in range(len(KK)):
            for mode in ("add", "sub", "beau"):
                s = letters(ks_apply(F0, KK, off, mode))
                if kname.split("_rev")[0] not in CLOSED_KS:
                    for p in PERIODS:
                        score_text(G.bifid(s.upper(), G.CANON, p), f"ks9:{kname}:off{off}:{mode}->bifid{p}", oracle=(p == 570))
                # checkerboard (novo para todas as listas)
                dg = [x + 1 for x in ks_apply(F0, KK, off, mode)]
                for an, al in CB_ALPHAS.items():
                    for e in ESC:
                        pt = G.checkerboard_decode(dg, al, e)
                        N["constr"] += 1
                        sc = G.english_score(pt); keep(sc, pt, f"ks9:{kname}:off{off}:{mode}->cb:{an}:{e}")
                        if sc > -4.5: log({"READABLE?": f"cb {kname} {off} {mode} {an} {e}", "score": sc, "text": pt[:120]})
print("(i) done", N, BEST[0][:1], BEST[0][2])

# ---------------------------------------------------------------- (ii) keystream mod-25/26 sobre BIF (BTCSEED...)
A26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def ks_alpha(t, K, off, mode, alpha):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}; out = []
    for i, c in enumerate(t):
        x = idx[c]; k = K[(i + off) % len(K)]
        y = (x + k) if mode == "add" else (x - k) if mode == "sub" else (k - x)
        out.append(alpha[y % n])
    return "".join(out)
for name, K in LISTS.items():
    for kname, KK in ((name, K), (name + "_rev", K[::-1])):
        for tname, t in (("BIF", BIF), ("REST", REST)):
            for an, al in (("A26", A26), ("CANON", G.CANON)):
                for off in range(len(KK)):
                    for mode in ("add", "sub", "beau"):
                        score_text(ks_alpha(t, KK, off, mode, al), f"ks{len(al)}:{kname}:{tname}:{an}:off{off}:{mode}", oracle=False)
print("(ii) done", N, BEST[0][:1], BEST[0][2])

# ---------------------------------------------------------------- (iii) transposicao colunar do faed
def col_order(K):
    return sorted(range(len(K)), key=lambda i: (K[i], i))
def transpose_read_cols(text, K):
    """escreve por linhas em len(K) colunas (ultima linha parcial), le colunas na ordem da chave."""
    w = len(K); rows = [text[i:i + w] for i in range(0, len(text), w)]
    return "".join(r[c] for c in col_order(K) for r in rows if c < len(r))
def transpose_write_cols(text, K):
    """inverso: o CT foi lido por colunas na ordem da chave; recupera as linhas."""
    w = len(K); n = len(text); full, extra = divmod(n, w)
    lens = {c: full + (1 if c < extra else 0) for c in range(w)}
    cols = {}; i = 0
    for c in col_order(K): cols[c] = text[i:i + lens[c]]; i += lens[c]
    return "".join(cols[c][r] for r in range(full + 1) for c in range(w) if r < lens[c])
assert transpose_write_cols(transpose_read_cols(FAED, [3, 1, 2]), [3, 1, 2]) == FAED
for name, K in LISTS.items():
    if name.startswith("dbbi91"): continue
    for kname, KK in ((name, K), (name + "_rev", K[::-1]), (name + "_neg", [-x for x in K])):
        for fn, f in (("readcols", transpose_read_cols), ("writecols", transpose_write_cols)):
            s = f(FAED, KK)
            score_text(s, f"transp:{kname}:{fn}:raw", oracle=True)
            for p in (570, 285, 91):
                score_text(G.bifid(s.upper(), G.CANON, p), f"transp:{kname}:{fn}->bifid{p}", oracle=(p == 570))
            dg = d9(s, False)
            for an, al in CB_ALPHAS.items():
                for e in ESC:
                    pt = G.checkerboard_decode(dg, al, e); N["constr"] += 1
                    keep(G.english_score(pt), pt, f"transp:{kname}:{fn}->cb:{an}:{e}")
    # transposicao POS-Bifid (BIF como texto)
    for kname, KK in ((name, K), (name + "_rev", K[::-1])):
        for fn, f in (("readcols", transpose_read_cols), ("writecols", transpose_write_cols)):
            score_text(f(BIF, KK), f"transpBIF:{kname}:{fn}", oracle=False)
print("(iii) done", N, BEST[0][:1], BEST[0][2])

# ---------------------------------------------------------------- (iv) periodo Bifid = valores das somas
pers = set()
for K in LISTS.values():
    pers.update(x for x in K if 2 <= x <= 570); pers.add(sum(K))
pers = sorted(p for p in pers if 2 <= p <= 570)
for p in pers:
    score_text(G.bifid(FAED.upper(), G.CANON, p), f"bifid-period{p}", oracle=False)
    score_text(G.bifid(FAED.upper(), G.CANON, p, mode="encrypt"), f"bifid-enc-period{p}", oracle=False)
log({"periods_tested": pers})
print("(iv) done", N)

# ---------------------------------------------------------------- (v) senha = lista como string
def list_forms(name, K):
    yield ",".join(map(str, K)); yield " ".join(map(str, K)); yield "".join(map(str, K))
    yield str(K); yield "-".join(map(str, K)); yield ";".join(map(str, K))
    yield "matrixsumlist" + "".join(map(str, K)); yield "matrixsumlist" + ",".join(map(str, K))
    yield "".join(map(str, K)) + "matrixsumlist"; yield str(sum(K))
    yield "".join(chr(97 + x % 9) for x in K); yield "".join(chr(65 + x % 26) for x in K)
for name, K in LISTS.items():
    for f in list_forms(name, K):
        oracle_text(f, f"pw:{name}:{f[:40]}")
        oracle_text(f.upper(), f"pw:{name}:upper:{f[:40]}")
    # somas como bytes -> privkey (14 somas ~ nao 32B; hash)
    b = bytes(x % 256 for x in K); oracle_bytes(b, f"bytes:{name}")
print("(v) done", N, "hard", len(HARD), "soft", len(SOFT))

# ---------------------------------------------------------------- dbbi como TEXTO
# (a) uma letra -> 0, resto a=1..i=9 (com deslocamento para manter 1..9? nao: as 8 restantes ficam com seu valor)
for zero in "abcdefghi":
    for shift in (False, True):
        digs = []
        for c in DBBI:
            v = ord(c) - 96
            if c == zero: v = 0
            elif shift and c > zero: v -= 1
            digs.append(v)
        b = G.z_method(digs); N["constr"] += 1
        pr = G.printable(b); how = f"dbbi-text:zero={zero}{'-shift' if shift else ''}"
        log({"z_method": how, "printable": round(pr, 3), "head": b[:40].decode('latin-1')})
        oracle_bytes(b, how)
        # tambem como dígitos -> string senha
        oracle_text("".join(map(str, digs)), how + "|digits-pw")
# (b) a1z26 de pares (a=1..9 -> 2 digitos -> letra 1..26)
for a0 in (True, False):
    v = d9(DBBI, a0)
    for base in (10, 9):
        for order in ("hi-lo", "lo-hi"):
            out = []
            for i in range(0, 90, 2):
                x = v[i] * base + v[i + 1] if order == "hi-lo" else v[i + 1] * base + v[i]
                out.append(chr(64 + x) if 1 <= x <= 26 else "?")
            t = "".join(out); how = f"dbbi-a1z26:pairs:{'a0' if a0 else 'a1'}:b{base}:{order}"
            N["constr"] += 1; keep(G.english_score(t), t, how); log({"a1z26": how, "text": t})
            oracle_text(t.replace("?", ""), how)
    # a1z26 "greedy" (1 ou 2 digitos)
    s = "".join(map(str, v)); out = []; i = 0
    while i < len(s):
        if i + 1 < len(s) and 10 <= int(s[i:i + 2]) <= 26: out.append(chr(64 + int(s[i:i + 2]))); i += 2
        else: out.append(chr(64 + int(s[i])) if s[i] != "0" else "?"); i += 1
    t = "".join(out); how = f"dbbi-a1z26:greedy:{'a0' if a0 else 'a1'}"
    N["constr"] += 1; keep(G.english_score(t), t, how); log({"a1z26": how, "text": t}); oracle_text(t, how)
# (c) dbbi +-/xor faed[0:91], faed[-91:], faed[285:376] mod 9
D0 = d9(DBBI, True); D1 = d9(DBBI, False)
for seg_name, seg in (("faed0", FAED[:91]), ("faedEnd", FAED[-91:]), ("faed285", FAED[285:376]), ("faed91", FAED[91:182])):
    f0 = d9(seg, True); f1 = d9(seg, False)
    combos = {"add": [(a + b) % 9 for a, b in zip(D0, f0)], "sub": [(b - a) % 9 for a, b in zip(D0, f0)],
              "beau": [(a - b) % 9 for a, b in zip(D0, f0)], "xor0": [(a ^ b) % 9 for a, b in zip(D0, f0)],
              "xor1": [(a ^ b) for a, b in zip(D1, f1)], "add1": [((a + b - 1) % 9) + 1 for a, b in zip(D1, f1)]}
    for cn, cv in combos.items():
        t = letters(cv) if cn != "xor1" else "".join(str(x) for x in cv); how = f"dbbi-op-{seg_name}:{cn}"
        N["constr"] += 1
        if cn != "xor1":
            keep(G.english_score(t), t, how)
            oracle_text(t, how)
            dg = [ord(c) - 96 for c in t]; b = G.z_method(dg); oracle_bytes(b, how + "|z")
            for an, al in CB_ALPHAS.items():
                for e in ESC:
                    pt = G.checkerboard_decode(dg, al, e); N["constr"] += 1; keep(G.english_score(pt), pt, how + f"|cb:{an}:{e}")
            score_text(G.bifid(t.upper(), G.CANON, 91), how + "|bifid91", oracle=False)
        else:
            oracle_text(t, how)
            b = G.z_method(cv); oracle_bytes(b, how + "|z")
print("dbbi-text done", N, "hard", len(HARD))

# ---------------------------------------------------------------- dbbi nas 24 posicoes primas <-> 24 cores
PR = [p for p in range(2, 91) if G.is_prime(p)]; assert len(PR) == 24
COL = G.COLOR_SEQ; assert len(COL) == 24
for base in (0, 1):
    sym = [DBBI[p - base] for p in PR]
    allp = "".join(sym); blue = "".join(s for s, c in zip(sym, COL) if c == "B"); yel = "".join(s for s, c in zip(sym, COL) if c == "Y")
    log({"primes_base": base, "all": allp, "blue": blue, "yellow": yel})
    for nm, s in (("all24", allp), ("blue15", blue), ("yellow9", yel), ("blue+yellow", blue + yel), ("yellow+blue", yel + blue)):
        how = f"primes-b{base}:{nm}:{s}"
        # senha / privkey / z-method
        oracle_text(s, how); oracle_text(s.upper(), how + "|upper")
        dg = [ord(c) - 96 for c in s]; oracle_bytes(G.z_method(dg), how + "|z"); oracle_text("".join(map(str, dg)), how + "|digits")
        # keyword -> alfabeto Bifid (A-I mapeados) sobre faed
        al = G.keyed_alphabet(s.upper());
        for p in (570, 285, 91):
            score_text(G.bifid(FAED.upper(), al, p), how + f"|bifid-keyed{p}", oracle=(p == 570))
        # keystream mod-9 sobre faed -> Bifid CANON 570 (a0 e a1)
        for a0 in (True, False):
            K = d9(s, a0)
            for off in range(len(K)):
                for mode in ("add", "sub", "beau"):
                    t = letters(ks_apply(F0, K, off, mode))
                    score_text(G.bifid(t.upper(), G.CANON, 570), how + f"|ks9:{'a0' if a0 else 'a1'}:off{off}:{mode}", oracle=False)
        # keystream mod-25 sobre BIF/REST
        K = d9(s, False)
        for tname, t in (("BIF", BIF), ("REST", REST)):
            for an, alx in (("A26", A26), ("CANON", G.CANON)):
                for off in range(len(K)):
                    for mode in ("add", "sub", "beau"):
                        score_text(ks_alpha(t, K, off, mode, alx), how + f"|ks{len(alx)}:{tname}:{an}:off{off}:{mode}", oracle=False)
    # contagens como senhas (yellow has a number, blue too)
    for f in ("159", "915", "15 9", "9 15", "blue15yellow9", "yellow9blue15", "yellowblueprimes", "yellowblueprimes915", "yellowblueprimes159"):
        oracle_text(f, f"pw-count:{f}")
print("primes done", N, "hard", len(HARD))

n_tests = sum(N.values())
summary = {"n_tests": n_tests, "counts": N, "hard": HARD, "n_soft": len(SOFT), "baseline_BIF": BASE,
           "best": [{"score": round(s, 3), "text": t, "how": h} for s, t, h in BEST[:15]],
           "soft_sample": SOFT[:10]}
log({"summary": summary})
print(json.dumps(summary, ensure_ascii=False, indent=1)[:6000])
