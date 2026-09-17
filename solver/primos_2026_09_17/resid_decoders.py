# -*- coding: utf-8 -*-
"""
Familia: decoders classicos sobre o RESIDUO (simbolos fora das posicoes primas) do dbbi.
Hipotese (prosa): o atlas segmenta dbbi em 83/84 posicoes logicas com b/be nos primos; os
61/60 simbolos restantes seriam o payload e decodificariam por um metodo simples da caixa de
ferramentas do proprio puzzle (straddling checkerboard da 3.2.2, Polybius/Bifid, a1z26,
conversao de base, indices numa frase conhecida). Todos os certificados historicos cobrem o
dbbi INTEIRO (91); o residuo nunca foi alvo desses decoders.
Cada saida textual: english_score + nulo casado (200 embaralhamentos que preservam contagens).
As melhores saidas viram senha (crua/sha256) nos 3 blobs + sha256(texto) como privkey.
"""
import sys, os, json, random, hashlib, itertools, statistics, time
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
# scorer DESCONTAMINADO (ver clean_scorer.py): o scorer original aprendeu quadgramas do dbbi e de sopas de
# letras postadas no Telegram (DIFH=-5,1; leitura identidade do residuo z=6,9 na 1a rodada = artefato).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clean_scorer; G._SC = clean_scorer.Scorer()
_S0 = __import__("scorer").Scorer()

OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "resid_decoders.jsonl")
if os.path.exists(LOG): os.remove(LOG)
def log(o): G.jsonl(LOG, o)
random.seed(20260917)
NULL_N = 200
T0 = time.time()

log({"hipotese": __doc__.strip()})
_ID = "DIFHCCGIHAEEIHGGEGEBGEHHEHHFAFDHFFCDBFCCCGFEGGECDCIFFFGIGEEAE"
log({"scorer": {"kept": G._SC.kept, "dropped": G._SC.dropped, "identity_orig": round(_S0(_ID), 3), "identity_clean": round(G._SC(_ID), 3),
                "english_orig": round(_S0("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"), 3), "english_clean": round(G._SC("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"), 3)}})

# ------------------------------------------------------------------ 1. segmentacao (recalculada)
def segment(s):
    """Posicoes logicas a partir de 1; em posicao prima consome 'b' ou 'be'; senao 1 simbolo."""
    res = []
    def rec(i, pos, toks):
        if i == len(s): res.append(list(toks)); return
        if G.is_prime(pos):
            if s[i] == 'b':
                if i + 1 < len(s) and s[i + 1] == 'e': rec(i + 2, pos + 1, toks + ['be'])
                rec(i + 1, pos + 1, toks + ['b'])
        else:
            rec(i + 1, pos + 1, toks + [s[i]])
    rec(0, 1, []); return res
SEGS = {len(t): t for t in segment(G.DBBI)}
assert sorted(SEGS) == [83, 84], sorted(SEGS)
def residue(toks): return "".join(t for i, t in enumerate(toks, 1) if not G.is_prime(i))
R = {"R84": residue(SEGS[84]), "R83": residue(SEGS[83])}
assert R["R84"] == "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae" and len(R["R84"]) == 61
assert R["R83"] == R["R84"][:-1]
R["R84r"] = R["R84"][::-1]; R["R83r"] = R["R83"][::-1]
for L in (83, 84):
    m = [t for i, t in enumerate(SEGS[L], 1) if G.is_prime(i)]
    assert len(m) == 23
    log({"seg": L, "b": m.count("b"), "be": m.count("be"), "bits": "".join("0" if t == "b" else "1" for t in m)})
# ------------------------------------------------------------------ 1b. sequencias logicas com marcador
def seq_variants(L):
    toks = SEGS[L]; out = {}
    out[f"L{L}_m0"] = "".join("0" if t in ("b", "be") else t for t in toks)                 # b/be -> 0
    out[f"L{L}_b0be10"] = "".join({"b": "0", "be": "10"}.get(t, t) for t in toks)            # b->0, be->10
    out[f"L{L}_b0be1"] = "".join({"b": "0", "be": "1"}.get(t, t) for t in toks)              # b->0, be->1 (1 = 'a')
    return out
SEQ = {}
for L in (83, 84): SEQ.update(seq_variants(L))
def groups(L):
    """Residuo particionado pelos marcadores (marcador = separador) -> lista de grupos."""
    g, cur = [], ""
    for i, t in enumerate(SEGS[L], 1):
        if G.is_prime(i): g.append(cur); cur = ""
        else: cur += t
    g.append(cur); return [x for x in g if x]
GROUPS = {L: groups(L) for L in (83, 84)}
assert "".join(GROUPS[84]) == R["R84"] and len(GROUPS[84]) == 23
log({"groups84": GROUPS[84], "groups83": GROUPS[83]})

def dig(s):  # simbolo -> digito: a=1..i=9, '0' -> 0, '1' -> 1 (ja digito)
    return [int(c) if c.isdigit() else ord(c) - 96 for c in s]
def letters(t): return "".join(c for c in t.upper() if "A" <= c <= "Z")
def score(t):
    t = letters(t)
    return G.english_score(t) if len(t) >= 4 else -99.0

# ------------------------------------------------------------------ nulo casado
_SHUF = {}
def shuffles(key, s, n=NULL_N):
    if (key, n) not in _SHUF:
        rnd = random.Random(hash(key) & 0xffffffff); l = list(s); outs = []
        for _ in range(n): rnd.shuffle(l); outs.append("".join(l))
        _SHUF[(key, n)] = outs
    return _SHUF[(key, n)]
def evaluate(fam, cfg, inp_name, inp, decoder):
    """decoder(str)->str. Devolve registro com score real, z e p empirico vs nulo casado."""
    real = decoder(inp); sr = score(real)
    if sr <= -99: return None
    null = [score(decoder(x)) for x in shuffles(inp_name, inp)]
    null = [x for x in null if x > -99]
    if len(null) < 20: return None
    mu, sd = statistics.mean(null), (statistics.pstdev(null) or 1e-9)
    p = sum(1 for x in null if x >= sr) / len(null)
    return {"fam": fam, "cfg": cfg, "inp": inp_name, "out": real, "score": round(sr, 3),
            "z": round((sr - mu) / sd, 2), "p": round(p, 4), "null_mu": round(mu, 3), "null_sd": round(sd, 3)}

RESULTS = []            # todos os registros
N_TESTS = 0
def run(fam, cfg, inp_name, inp, decoder):
    global N_TESTS
    N_TESTS += 1
    r = evaluate(fam, cfg, inp_name, inp, decoder)
    if r: RESULTS.append(r)
    return r

# ------------------------------------------------------------------ controle positivo (3.2.2)
ALPHA322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
D322 = "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"
ctrl = evaluate("ctrl", "cb(1,4)|0-9|alpha322", "D322", D322,
                lambda s: G.checkerboard_decode(dig(s), ALPHA322, (1, 4), "0123456789"))
assert ctrl["out"].startswith("INCASEYOUMANAGETOCRACKTHIS") and ctrl["z"] > 4, ctrl
CONTROLS = {"checkerboard_322": {"score": ctrl["score"], "z": ctrl["z"], "p": ctrl["p"], "null_mu": ctrl["null_mu"]}}
log({"controle": CONTROLS})

# ------------------------------------------------------------------ (1) straddling checkerboard
PHRASES = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "yinyang", "salphaseion",
           "cosmicduality", "dbifhcega", "theseedisplanted", "gsmg", "causality", "thematrixhasyou"]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHAS = {"AZ": AZ, "AZ_noJ": "ABCDEFGHIKLMNOPQRSTUVWXYZ", "AZ.": AZ + ".", "alpha322": ALPHA322,
          "alpha322_nodot": ALPHA322.replace(".", "")}
for ph in PHRASES:
    k = G.keyed_alphabet(ph, AZ, merge_j=False); ALPHAS[f"key:{ph}"] = k
    seen = "".join(dict.fromkeys(ph.upper())); ALPHAS[f"key.:{ph}"] = seen + "." + "".join(c for c in AZ if c not in seen)
CB_INPUTS = {**R, **SEQ}
for inp_name, inp, uni in [(k, v, "123456789") for k, v in R.items()] + [(k, v, "0123456789") for k, v in CB_INPUTS.items()]:
    U = [int(c) for c in uni]
    escs = [(e,) for e in U] + list(itertools.combinations(U, 2))
    for esc in escs:
        for an, alpha in ALPHAS.items():
            run("cb", f"esc{esc}|{uni[0]}-9|{an}", inp_name, inp,
                lambda s, a=alpha, e=esc, u=uni: G.checkerboard_decode(dig(s), a, e, u))
log({"fase": "checkerboard", "n": N_TESTS, "t": round(time.time() - T0)})

# ------------------------------------------------------------------ (2) Polybius 3x3 em pares / Bifid 3x3
A9 = {"ETAOINSHR": "ETAOINSHR", "abcdefghi": "ABCDEFGHI", "dbifhcega": "DBIFHCEGA"}
freq_rank = "".join(c for c, _ in sorted(__import__("collections").Counter(R["R84"]).items(), key=lambda kv: (-kv[1], kv[0])))
A9["ETAOINSHR@dbifhcega"] = "".join("ETAOINSHR"["dbifhcega".index(c)] for c in "abcdefghi")  # quadrado permutado pela ordem dbifhcega
# tabela: letra do residuo (por rank de frequencia) -> ETAOINSHR (substituicao mono por frequencia)
RANKMAP = {c: "ETAOINSHR"[i] for i, c in enumerate(freq_rank)}
COORD = {"d%3": lambda d: d % 3, "(d-1)%3": lambda d: (d - 1) % 3, "(d-1)//3": lambda d: ((d - 1) // 3) % 3}
def poly_pairs(s, f, g, alpha, off):
    d = dig(s)[off:]; d = d[:len(d) - len(d) % 2]
    return "".join(alpha[f(d[i]) * 3 + g(d[i + 1])] for i in range(0, len(d), 2))
POLY_INPUTS = {**R, "L84_m0": SEQ["L84_m0"], "L83_m0": SEQ["L83_m0"]}
for inp_name, inp in POLY_INPUTS.items():
    for off in (0, 1):
        for fn, f in COORD.items():
            for gn, g in COORD.items():
                for an, alpha in A9.items():
                    if an.startswith("abc") or an.startswith("dbif"): continue  # saida em a-i: nao e ingles
                    run("poly3", f"row={fn}|col={gn}|{an}|off{off}", inp_name, inp,
                        lambda s, f=f, g=g, a=alpha, o=off: poly_pairs(s, f, g, a, o))
# Bifid 3x3: quadrado sobre a-i; saida (a-i) mapeada a ETAOINSHR pelo indice no quadrado OU por rank
SQUARES = {"abcdefghi": "abcdefghi", "dbifhcega": "dbifhcega", "rank": freq_rank}
def bifid3(s, sq, period, mode, outmap):
    o = G.bifid(s, sq, period, n=3, mode=mode)
    if outmap == "sqidx": return "".join("ETAOINSHR"[sq.index(c)] for c in o)
    return "".join(RANKMAP[c] for c in o)
for inp_name, inp in R.items():
    for sqn, sq in SQUARES.items():
        for period in range(1, len(inp) + 1):
            for mode in ("decrypt", "encrypt"):
                for om in ("sqidx", "rank"):
                    run("bifid3", f"sq={sqn}|p={period}|{mode}|{om}", inp_name, inp,
                        lambda s, q=sq, p=period, m=mode, o=om: bifid3(s, q, p, m, o))
# leitura direta por rank (mono-substituicao por frequencia) como linha de base
for inp_name, inp in R.items():
    run("mono_rank", "rank->ETAOINSHR", inp_name, inp, lambda s: "".join(RANKMAP[c] for c in s))
log({"fase": "polybius/bifid", "n": N_TESTS, "t": round(time.time() - T0)})

# ------------------------------------------------------------------ (3) a1z26 / a0z25 sobre grupos de digitos
def grp_letters(s, k, off, conv):
    d = "".join(map(str, dig(s)))[off:]
    out = []
    for i in range(0, len(d) - k + 1, k):
        n = int(d[i:i + k])
        if conv == "a1z26": out.append(AZ[(n - 1) % 26])
        elif conv == "a0z25": out.append(AZ[n % 26])
        elif conv == "le26": out.append(AZ[n - 1] if 1 <= n <= 26 else "")
    return "".join(out)
for inp_name, inp in {**R, **SEQ}.items():
    for k in (2, 3):
        for off in range(k):
            for conv in ("a1z26", "a0z25", "le26"):
                run("digits", f"k={k}|off{off}|{conv}", inp_name, inp, lambda s, k=k, o=off, c=conv: grp_letters(s, k, o, c))
# grupos delimitados pelos marcadores: cada grupo -> numero -> letra; ou soma dos digitos -> letra
def grp_marker(s, L, conv):
    # s e o residuo (possivelmente embaralhado): re-particiona pelos tamanhos dos grupos reais
    sizes = [len(g) for g in GROUPS[L]]; out = []; i = 0
    for sz in sizes:
        g = s[i:i + sz]; i += sz; d = dig(g)
        n = int("".join(map(str, d))) if conv != "sum" else sum(d)
        if conv == "sum": out.append(AZ[(n - 1) % 26])
        elif conv == "a1z26": out.append(AZ[(n - 1) % 26])
        elif conv == "a0z25": out.append(AZ[n % 26])
        elif conv == "first": out.append(AZ[d[0] - 1])
        elif conv == "last": out.append(AZ[d[-1] - 1])
    return "".join(out)
for L in (83, 84):
    for conv in ("a1z26", "a0z25", "sum", "first", "last"):
        run("groups", f"L{L}|{conv}", f"R{L}", R[f"R{L}"], lambda s, L=L, c=conv: grp_marker(s, L, c))
        run("groups", f"L{L}|{conv}", f"R{L}r", R[f"R{L}r"], lambda s, L=L, c=conv: grp_marker(s, L, c))
# a1z26 direto (identidade a-i) como linha de base
for inp_name, inp in R.items(): run("a1z26_direct", "identity", inp_name, inp, lambda s: s.upper())
log({"fase": "digits/groups", "n": N_TESTS, "t": round(time.time() - T0)})

# ------------------------------------------------------------------ (4) conversao de base -> letras / base58
def to_base(n, b, alpha):
    if n == 0: return alpha[0]
    o = []
    while n: n, r = divmod(n, b); o.append(alpha[r])
    return "".join(reversed(o))
def base_text(s, inb, outb):
    d = dig(s)
    n = int("".join(map(str, d))) if inb == 10 else int("".join(str(x - 1) for x in d), 9)
    if outb == "26a": return to_base(n, 26, AZ)
    if outb == "26b": return to_base(n, 26, AZ[-1:] + AZ[:-1])        # 1=A..0=Z
    if outb == "27": return to_base(n, 27, " " + AZ)
    if outb == "27z": return to_base(n, 27, AZ + " ")
    if outb == "36": return to_base(n, 36, "0123456789" + AZ)
    if outb == "36z": return to_base(n, 36, AZ + "0123456789")
for inp_name, inp in R.items():
    for inb in (10, 9):
        for outb in ("26a", "26b", "27", "27z", "36", "36z"):
            run("base", f"in{inb}|out{outb}", inp_name, inp, lambda s, i=inb, o=outb: base_text(s, i, o))
# base58: a..i -> '1'..'9' (9 dos 58 simbolos, por rank) -> inteiro -> privkey (32 B baixos / mod n)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PRIV_TESTS = []
def priv_check(b32, where):
    global N_TESTS
    N_TESTS += 1
    r = G.priv_hit(b32)
    PRIV_TESTS.append({"where": where, "hex": b32.hex(), "hit": bool(r)})
    return r
HARD = []
for inp_name, inp in R.items():
    d = dig(inp)
    ints = {"b58": sum((x - 1) * 58 ** (len(d) - 1 - i) for i, x in enumerate(d)),   # a..i -> '1'..'9' de base58
            "b10": int("".join(map(str, d))), "b9": int("".join(str(x - 1) for x in d), 9)}
    for kn, n in ints.items():
        for wn, v in {"low32": n & ((1 << 256) - 1), "modn": n % SECP_N, "top32": n >> max(0, n.bit_length() - 256)}.items():
            if v <= 0: continue
            if priv_check(v.to_bytes(32, "big"), f"{inp_name}|{kn}|{wn}"): HARD.append({"priv": f"{inp_name}|{kn}|{wn}"})
        for wn, v in {"sha": G.sha(str(n).encode()), "sha_raw": G.sha(n.to_bytes((n.bit_length() + 7) // 8, "big"))}.items():
            if priv_check(v, f"{inp_name}|{kn}|{wn}"): HARD.append({"priv": f"{inp_name}|{kn}|{wn}"})
log({"fase": "base", "n": N_TESTS, "t": round(time.time() - T0)})

# ------------------------------------------------------------------ (5) residuo como indices em textos conhecidos
ARCH = ("YOUR LIFE IS THE SUM OF A REMAINDER OF AN UNBALANCED EQUATION INHERENT TO THE PROGRAMMING OF THIS PUZZLE "
 "YOU ARE THE EVENTUALITY OF AN ANOMALY WHICH DESPITE MY SINCEREST EFFORTS I HAVE BEEN UNABLE TO ELIMINATE "
 "FROM WHAT IS OTHERWISE A HARMONY OF MATHEMATICAL PRECISION WHILE IT REMAINS A BURDEN TO SEDULOUSLY AVOID IT "
 "IT IS NOT UNEXPECTED AND THUS NOT BEYOND A MEASURE OF CONTROL WHICH HAS LED YOU INEXORABLY HERE YOU "
 "YOU HAVEN'T ANSWERED MY QUESTION ME QUITE RIGHT INTERESTING THAT WAS QUICKER THAN THE OTHERS PLEASE IF YOU "
 "FIND A WAY TO COMPLETE THE LAST PART OF THE PUZZLE TAKE THE PRIVATE KEY YOUVE EARNED IT BUT PLEASE TAKE "
 "THIS TO HEART THAT WHAT A WISEMAN ABOVE HINTED AT IS WORTH HUNDRED FOURTY OF THE INVESTMENT THAT'S "
 "WHAT US GUYS AT GSMG ARE TRYING TO ACCOMPLISH IN THE END PLEASE JUST HELP US BUILD IT INSTEAD OF JUST "
 "WAISTING YOUR LIFETIME BY HUNTING FOR WORTHLESS PRICES AND THROPHIES LIKE THIS I'M SORRY TO "
 "TELL YOU THAT YOUVE COME THIS FAR BUT YOU'LL NEVER FINISH THE LAST TASK I EXPECT YOU TO SAY BULLSHIT "
 "WELL DENIAL IS THE MOST PREDICTABLE OF ALL HUMAN RESPONSES BUT REST ASSURED THIS WILL NOT BE THE LAST TIME "
 "I HAVE DESTROYED A RESTLESS SOUL AND I HAVE BECOME EXCEEDINGLY EFFICIENT AT IT THE FUNCTION OF THE YOU IS "
 "NOW TO RETURN TO THE SOURCE CODES ALLOWING A TEMPORARY DISSEMINATION OF THE CODE YOU HOPEFULLY CARRY "
 "REINSERTING THE PRIME BASICS AFTER WHICH YOU WILL BE REQUIRED TO SELECT FROM OVER TWENTY-THREE CIPHERS "
 "SIXTEEN ENCRYPTIONS AND OR SEVEN INTERTWINED PASSWORDS TO FIND THE ACTUAL PRIVATE KEYNOTE THAT ALSO "
 "BRUTE FORCING MIGHT BE REQUIRED FAILURE TO COMPLY WITH THIS PROCESS WILL RESULT IN A CATACLYSMIC "
 "SYSTEM CRASH KILLING YOUR WILLPOWER WHICH COUPLED WITH THE EXTERMINATION OF YOUR WILL TO LIVE AND WILL "
 "ULTIMATELY RESULT IN THE EXTINCTION OF THE ENTIRENESS OF YOURSELF SELF GOOD LUCK NEVERTHELESS I REALLY "
 "HOPE YOURE THE ONE CIAO BELLA O")
M322 = "IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE"
P1 = "lastwordsbeforearchichoicethispassword"
TEXTS = {"P1": P1, "ARCH": ARCH, "M322": M322}
def idx_select(s, text, unit, mode):
    d = dig(s)
    items = letters(text) if unit == "letters" else [letters(w) for w in text.split() if letters(w)]
    n = len(items); out = []; ptr = 0
    if mode == "abs":     # d-esimo item
        out = [items[x - 1] for x in d if 1 <= x <= n]
    elif mode == "cum":   # ponteiro += d (mod n)
        for x in d: ptr = (ptr + x) % n; out.append(items[ptr - 1])
    elif mode == "cum0":  # ponteiro += d, indice 0-based
        for x in d: ptr = (ptr + x) % n; out.append(items[ptr])
    elif mode == "nth":   # d_i-esima letra da i-esima palavra (cicla)
        assert unit == "words"
        out = [w[(x - 1) % len(w)] for x, w in zip(d, items)]
    elif mode == "skip":  # pula d itens a partir do ultimo tomado
        for x in d:
            ptr += x
            if ptr > n: break
            out.append(items[ptr - 1])
    return "".join(out) if unit == "letters" else " ".join(out)
for inp_name, inp in R.items():
    for tn, text in TEXTS.items():
        for unit in ("letters", "words"):
            for mode in ("abs", "cum", "cum0", "skip") + (("nth",) if unit == "words" else ()):
                run("index", f"{tn}|{unit}|{mode}", inp_name, inp, lambda s, t=text, u=unit, m=mode: idx_select(s, t, u, m))
log({"fase": "index", "n": N_TESTS, "t": round(time.time() - T0)})

# ------------------------------------------------------------------ oraculo: melhores saidas como senha
RESULTS.sort(key=lambda r: -r["z"])
for r in RESULTS: log({"res": r})
def top_by_family(k=20):
    sel = []
    for fam in sorted({r["fam"] for r in RESULTS}):
        sel += sorted([r for r in RESULTS if r["fam"] == fam], key=lambda r: -r["z"])[:k]
    return sel
SOFT_AES = []; PW_TESTED = set()
def pw_test(pw, where):
    global N_TESTS
    if pw in PW_TESTED or not pw: return
    PW_TESTED.add(pw); N_TESTS += 1
    hard, soft = G.try_password_all(pw)
    for h in hard: HARD.append({"pw": pw, "where": where, **h})
    for s in soft: SOFT_AES.append({"pw": pw[:40], "where": where, "blob": s["blob"], "kdf": s["kdf"], "printable": s["printable"], "hex": s["hex"]})
    if priv_check(G.sha(pw.encode()), f"sha256({where})"): HARD.append({"priv": f"sha256({pw[:40]})", "where": where})
for r in top_by_family(20):
    o = r["out"].replace("?", "")
    for form in {o, o.lower(), o.upper(), letters(o), letters(o).lower(), o.replace(".", " ").strip()}:
        pw_test(form, f"{r['fam']}|{r['cfg']}|{r['inp']}")
        pw_test(G.shahex(form), f"sha256hex({r['fam']}|{r['cfg']}|{r['inp']})")
# tambem os proprios residuos por checkerboard 3.2.2 exato (alpha322, esc (1,4)) ja estao em 'cb' via universo 1-9;
# e a leitura 3.2.2 com universo 0-9 dos residuos (sem 0) e identica. Nada mais a adicionar.
log({"fase": "oraculo", "n": N_TESTS, "t": round(time.time() - T0), "senhas": len(PW_TESTED), "priv": len(PRIV_TESTS)})

# ------------------------------------------------------------------ resumo
by_fam = {}
for fam in sorted({r["fam"] for r in RESULTS}):
    rs = [r for r in RESULTS if r["fam"] == fam]
    best = max(rs, key=lambda r: r["z"]); bests = max(rs, key=lambda r: r["score"])
    by_fam[fam] = {"n": len(rs), "best_z": best, "best_score": bests,
                   "n_p_lt_0.005": sum(1 for r in rs if r["p"] < 0.005), "n_z_gt_3": sum(1 for r in rs if r["z"] > 3)}
summary = {"n_tests": N_TESTS, "n_scored": len(RESULTS), "n_passwords": len(PW_TESTED), "n_priv": len(PRIV_TESTS),
           "controls": CONTROLS, "hard": HARD, "soft_aes_n": len(SOFT_AES),
           "soft_aes_max_printable": max([s["printable"] for s in SOFT_AES], default=0),
           "by_family": by_fam, "top10_overall": RESULTS[:10], "seconds": round(time.time() - T0)}
json.dump(summary, open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
json.dump(SOFT_AES, open(os.path.join(OUT, "soft_aes_paddings.json"), "w", encoding="utf-8"), ensure_ascii=False)
log({"resumo": {k: v for k, v in summary.items() if k not in ("by_family", "top10_overall")}})
print(json.dumps({k: v for k, v in summary.items() if k != "by_family"}, ensure_ascii=False, indent=1))
for fam, v in by_fam.items():
    print(fam, v["n"], "best_z:", v["best_z"]["z"], v["best_z"]["score"], v["best_z"]["cfg"], v["best_z"]["inp"], v["best_z"]["out"][:70],
          "| p<.005:", v["n_p_lt_0.005"], "z>3:", v["n_z_gt_3"])
