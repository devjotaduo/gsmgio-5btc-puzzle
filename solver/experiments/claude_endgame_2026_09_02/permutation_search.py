# -*- coding: utf-8 -*-
"""permutation_search — faed/dbbi como TRANSPOSICAO (permutacao por indice) de um stream de digitos
com memoria serial (checkerboard/VIC ou digitos de um numero).

Hipotese (falsificavel, espaco finito): existe uma permutacao ESTRUTURADA (primos/coloridos/residuo mod k,
leituras de grade, colunar keyed por token, ou composicao curta dessas) cuja inversa restaura a dependencia
lag-1 do stream original. Fitness INVARIANTE ao mapeamento de simbolos: MI lag-1 (= H1 - H_cond, com H1 fixo
sob permutacao) e IoC de digrafos, em z contra nulo de embaralhados (mesmo unigrama). Calibracao: o
checkerboard real da 3.2.2 (n=149) da z~+6; para n=570 estruturado espera-se |z|>=8. Se nenhuma permutacao
das familias nem o hill-climb ultrapassa o que o MESMO procedimento atinge em faed embaralhado, a hipotese
"faed = transposicao de stream serial" e refutada no espaco coberto.
"""
import sys, json, math, time, random
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\permutation_search.jsonl"
random.seed(1327); np.random.seed(1327)
T0 = time.time()
N = {"perm_eval": 0, "decode": 0, "aes": 0, "priv": 0}

# ------------------------------------------------------------------ fitness
def mi1(a, k=9):
    """MI lag-1 em bits (a: np.array de ints 0..k-1)."""
    n = len(a) - 1
    pab = np.bincount(a[:-1] * k + a[1:], minlength=k * k).astype(float)
    pa = np.bincount(a[:-1], minlength=k).astype(float); pb = np.bincount(a[1:], minlength=k).astype(float)
    m = pab > 0
    return float((pab[m] / n * np.log2(pab[m] * n / (np.outer(pa, pb).ravel()[m]))).sum())
def ioc2(a, k=9):
    n = len(a) - 1
    c = np.bincount(a[:-1] * k + a[1:], minlength=k * k).astype(float)
    return float((c * (c - 1)).sum() / (n * (n - 1)))
class Null:
    """Nulo de embaralhados (mesmo unigrama) — vale para TODA permutacao da mesma sequencia."""
    def __init__(self, a, k, n=3000):
        b = a.copy(); mis = []; ios = []
        for _ in range(n):
            np.random.shuffle(b); mis.append(mi1(b, k)); ios.append(ioc2(b, k))
        self.k = k; self.mi_m, self.mi_s = np.mean(mis), np.std(mis); self.io_m, self.io_s = np.mean(ios), np.std(ios)
    def z(self, a): return (mi1(a, self.k) - self.mi_m) / self.mi_s
    def zio(self, a): return (ioc2(a, self.k) - self.io_m) / self.io_s

# ------------------------------------------------------------------ familias de permutacao (listas de indices)
def inv(p):
    q = [0] * len(p)
    for j, i in enumerate(p): q[i] = j
    return q
def apply(a, p): return a[np.array(p)]
def fam_index(n):
    """(1) primalidade / coloridos / residuo mod k."""
    out = {}
    for base in (0, 1):
        pr = [i for i in range(n) if G.is_prime(i + base)]; npr = [i for i in range(n) if not G.is_prime(i + base)]
        out[f"primes_first_b{base}"] = pr + npr; out[f"primes_last_b{base}"] = npr + pr
        out[f"primes_first_rev_b{base}"] = pr[::-1] + npr; out[f"primes_last_rev_b{base}"] = npr + pr[::-1]
    col = [i for i in sorted(G.COLORED) if i < n]; rest = [i for i in range(n) if i not in col]
    out["colored_first"] = col + rest; out["colored_last"] = rest + col
    blue = [i for i in G.BLUE_IDX if i < n]; yel = [i for i in G.YELLOW_IDX if i < n]
    out["blue_yellow_rest"] = blue + yel + [i for i in range(n) if i not in blue and i not in yel]
    for m in (7, 8, 16, 24):  # coloridos periodicos: indices == 7 mod 8 etc.
        sel = [i for i in range(n) if i % 8 == 7] if m == 8 else [i for i in range(n) if (i - 7) % m == 0]
        out[f"idx7mod{m}_first"] = sel + [i for i in range(n) if i not in sel]
    for k in range(2, 39):
        out[f"deinter{k}"] = [i for r in range(k) for i in range(r, n, k)]
    return out
def grid_reads(r, c):
    """(2) leituras de uma grade r x c: rowmajor/boustrophedon/espiral(in,out)/diagonais(+zigzag) x 4 flips."""
    def flips(cells):
        yield "id", cells
        yield "fh", [(i, c - 1 - j) for i, j in cells]
        yield "fv", [(r - 1 - i, j) for i, j in cells]
        yield "rot", [(r - 1 - i, c - 1 - j) for i, j in cells]
    base = {}
    base["row"] = [(i, j) for i in range(r) for j in range(c)]
    base["bous"] = [(i, j if i % 2 == 0 else c - 1 - j) for i in range(r) for j in range(c)]
    sp = []; top, bot, left, right = 0, r - 1, 0, c - 1
    while top <= bot and left <= right:
        sp += [(top, j) for j in range(left, right + 1)]
        sp += [(i, right) for i in range(top + 1, bot + 1)]
        if top < bot: sp += [(bot, j) for j in range(right - 1, left - 1, -1)]
        if left < right: sp += [(i, left) for i in range(bot - 1, top, -1)]
        top += 1; bot -= 1; left += 1; right -= 1
    base["spiral_in"] = sp; base["spiral_out"] = sp[::-1]
    dg = []; dz = []
    for d in range(r + c - 1):
        run = [(i, d - i) for i in range(r) if 0 <= d - i < c]
        dg += run; dz += run if d % 2 == 0 else run[::-1]
    base["diag"] = dg; base["diagzig"] = dz
    out = {}
    for name, cells in base.items():
        for fn, cl in flips(cells):
            out[f"g{r}x{c}_{name}_{fn}"] = [i * c + j for i, j in cl]
    return out
def fam_grid(n):
    out = {}
    for r in range(1, n + 1):
        if n % r == 0: out.update(grid_reads(r, n // r))
    return out
def fam_halves(n):
    """grades sobre cada metade n/2, concatenadas (half & better half)."""
    h = n // 2; out = {}
    for name, p in fam_grid(h).items():
        out["half_" + name] = p + [i + h for i in p]
        out["halfswap_" + name] = [i + h for i in p] + p
    out["halfswap"] = list(range(h, n)) + list(range(h))
    out["half_interleave"] = [x for i in range(h) for x in (i, i + h)]
    out["half_rev2"] = list(range(h)) + list(range(n - 1, h - 1, -1))
    return out
KEYS = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "yellowblueprimes",
        "salphaseion", "cosmicduality", "yinyang", "hashthetext", "theseedisplanted", "sha256",
        "ourfirsthintisyourlastcommand", "anstoo", "halfandbetterhalf"]
def col_order(key):
    return [i for _, i in sorted((ch, i) for i, ch in enumerate(key))]
def columnar_encrypt_perm(n, key):
    w = len(key); return [i * w + cidx for cidx in col_order(key) for i in range((n - cidx + w - 1) // w)]
def fam_columnar(n, dbbi_keys=True):
    out = {}
    keys = {k: k for k in KEYS}
    if dbbi_keys:
        for k in range(5, 41): keys[f"dbbi[:{k}]"] = G.DBBI[:k]
    for kn, key in keys.items():
        widths = {len(key)} | set(range(5, 41))
        for w in widths:
            kw = (key * (w // len(key) + 1))[:w]
            out[f"col_{kn}_w{w}"] = columnar_encrypt_perm(n, kw)
    return out
def all_families(n, with_halves=True):
    fams = {"index": fam_index(n), "grid": fam_grid(n), "columnar": fam_columnar(n)}
    if with_halves and n % 2 == 0: fams["halves"] = fam_halves(n)
    return fams

def scan_families(a, null, tag, with_halves=True):
    """Avalia cada permutacao e sua inversa; devolve lista ordenada por |z| e distribuicao por familia."""
    n = len(a); res = []; seen = {}
    for fam, d in all_families(n, with_halves).items():
        zs = []
        for name, p in d.items():
            for side, q in (("perm", p), ("inv", inv(p))):
                key = tuple(q)
                if key in seen: continue
                seen[key] = 1
                b = apply(a, q); z = null.z(b); zi = null.zio(b); N["perm_eval"] += 1
                zs.append(z); res.append((z, zi, fam, f"{name}/{side}", q))
        zs = np.array(zs) if zs else np.zeros(1)
        G.jsonl(LOG, {"tag": tag, "family": fam, "n_perms": int(len(zs)), "z_mi1_mean": round(float(zs.mean()), 3),
                      "z_mi1_sd": round(float(zs.std()), 3), "z_max": round(float(zs.max()), 3), "z_min": round(float(zs.min()), 3),
                      "n_abs_z_ge4": int((np.abs(zs) >= 4).sum())})
    res.sort(key=lambda t: -abs(t[0]))
    return res

# ------------------------------------------------------------------ (5) hill-climb com movimentos estruturados
def hill(a, null, steps=30000, restarts=20, tag="", seed=0):
    n = len(a); rng = random.Random(seed); best_all = []
    def move(p):
        q = p[:]; m = rng.random()
        if m < 0.3:   # troca de blocos
            L1, L2 = rng.randint(3, 60), rng.randint(3, 60)
            if n - L1 - L2 < 2: return p
            i = rng.randrange(0, n - L1 - L2); j = rng.randrange(i + L1, n - L2 + 1)
            q = p[:i] + p[j:j + L2] + p[i + L1:j] + p[i:i + L1] + p[j + L2:]
        elif m < 0.5:  # rotacao de segmento
            i, j = sorted(rng.sample(range(n + 1), 2))
            if j - i < 3: return p
            k = rng.randrange(1, j - i); q = p[:i] + p[i + k:j] + p[i:i + k] + p[j:]
        elif m < 0.65:  # reversao de segmento
            i, j = sorted(rng.sample(range(n + 1), 2)); q = p[:i] + p[i:j][::-1] + p[j:]
        elif m < 0.85:  # (des)intercalar segmento
            i, j = sorted(rng.sample(range(n + 1), 2)); L = j - i
            if L < 6: return p
            k = rng.randint(2, min(38, L // 2)); seg = p[i:j]
            seq = [t for r in range(k) for t in range(r, L, k)]
            if rng.random() < .5: seq = inv(seq)
            q = p[:i] + [seg[t] for t in seq] + p[j:]
        else:            # leitura de grade num segmento
            i, j = sorted(rng.sample(range(n + 1), 2)); L = j - i
            divs = [r for r in range(2, L) if L % r == 0]
            if not divs: return p
            r = rng.choice(divs); reads = list(grid_reads(r, L // r).values()); rd = rng.choice(reads); seg = p[i:j]
            q = p[:i] + [seg[t] for t in rd] + p[j:]
        return q
    for rs in range(restarts):
        p = list(range(n)); cur = null.z(apply(a, p)); best = (cur, p)
        for s in range(steps):
            q = move(p)
            if q is p: continue
            z = null.z(apply(a, q)); N["perm_eval"] += 1
            T = 0.5 * (1 - s / steps)
            if z >= cur or rng.random() < math.exp((z - cur) / max(T, 1e-9)):
                p, cur = q, z
                if z > best[0]: best = (z, q)
        best_all.append(best)
        G.jsonl(LOG, {"tag": tag, "hill_restart": rs, "best_z": round(best[0], 3)})
    best_all.sort(key=lambda t: -t[0])
    return best_all

# ------------------------------------------------------------------ decodificadores sobre os top-K
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
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def kw25(p):
    seen = []
    for ch in p.upper():
        if ch == "J": ch = "I"
        if "A" <= ch <= "Z" and ch not in seen: seen.append(ch)
    return "".join(seen) + "".join(ch for ch in AZ.replace("J", "") if ch not in seen)
ALPHAS = {"322": "FUBCDORALETHINGKYMVPSJQZXW"[:25], "CANON": G.CANON, "AZ": AZ.replace("J", "")}
ALPHAS.update({f"ph:{p}": kw25(p) for p in PHRASES})
ESC9 = [(x, y) for x in range(1, 10) for y in range(1, 10) if x != y]
hard, soft, best = [], [], {"score": -99}
def oracle_text(pt, how):
    """texto de decoder: semantic_text (quadgramas/palavras) -> so entao senha/privkey."""
    global best
    N["decode"] += 1
    sc = G.english_score(pt)
    if sc > best["score"]: best = {"score": round(sc, 3), "text": pt[:120], "how": how}
    if G.semantic_text(pt):
        rec = {"cand": how, "score": round(sc, 3), "words": G.word_hits(pt, 6)[:8], "head": pt[:100]}
        G.jsonl(LOG, rec); oracle_pw(pt, how); oracle_pw(pt.lower(), how + "|lower")
def oracle_pw(pw, how):
    for cand in (pw, G.shahex(pw)):
        for blob in ("SMALL", "COSMIC", "TAIL32"):
            N["aes"] += 1
            for kdf, p in G.aes_try(cand, blob, kdf="sha256"):
                rec = {"pw": cand[:80], "blob": blob, "kdf": kdf, "how": how, "head": p[:48].hex()}
                (hard if G.semantic(p) else soft).append(rec); G.jsonl(LOG, {"aes_pad_ok": rec, "hard": G.semantic(p)})
    N["priv"] += 1
    r = G.priv_hit(G.sha(pw.encode()))
    if r: hard.append({"privkey": G.sha(pw.encode()).hex(), "addr": r, "how": how}); G.jsonl(LOG, {"HARD": hard[-1]})
def decode_seq(sym, how):
    """sym: string a-i permutada."""
    digs = [ord(ch) - 96 for ch in sym]
    for an, al in ALPHAS.items():
        for e in ESC9: oracle_text(G.checkerboard_decode(digs, al, e, "123456789"), f"{how}|cb:{an}|esc{e}")
    # layout 3.2.2 (i->0, escapes 1,4)
    d0 = [0 if d == 9 else d for d in digs]
    oracle_text(G.checkerboard_decode(d0, "FUBCDORA.LETHINGKYMVPS.JQZXW", (1, 4), "0123456789"), f"{how}|cb322_i0")
    # z-method (bytes reais -> semantic legitimo) + privkey scan
    zb = G.z_method(digs); N["decode"] += 1
    if G.semantic(zb): hard.append({"z_method": zb[:80].hex(), "how": how}); G.jsonl(LOG, {"HARD_z": hard[-1]})
    for h in G.fast_priv_scan(zb, how): hard.append({"priv": h}); G.jsonl(LOG, {"HARD_priv": h})
    N["priv"] += max(1, len(zb) - 31)
    # Bifid CANON (periodo total e 285)
    for per in (len(sym), len(sym) // 2 or len(sym)):
        oracle_text(G.bifid(sym, G.CANON, per), f"{how}|bifid{per}")
    # a string permutada como senha / sha256 como senha e privkey
    oracle_pw(sym, how + "|raw")

def main():
    global best
    open(LOG, "w").close()
    G.jsonl(LOG, {"hypothesis": __doc__.strip()})
    # ============================================================== CONTROLE POSITIVO
    D322 = np.array([int(ch) for ch in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"])
    null322 = Null(D322, 10)
    z_real = null322.z(D322)
    ctrl = {"control": "3.2.2 checkerboard n=149", "z_mi1_real": round(z_real, 2), "z_ioc2_real": round(null322.zio(D322), 2)}
    for pname, p in (("deinter7", [i for r in range(7) for i in range(r, 149, 7)]),
                     ("primes_first_b1", [i for i in range(149) if G.is_prime(i + 1)] + [i for i in range(149) if not G.is_prime(i + 1)])):
        scr = apply(D322, p); z_scr = null322.z(scr)
        res = scan_families(scr, null322, "ctrl_" + pname, with_halves=False)
        top = res[0]
        ctrl[pname] = {"z_scrambled": round(z_scr, 2), "top_name": top[3], "top_z": round(top[0], 2),
                       "recovered": bool(np.array_equal(apply(scr, top[4]), D322))}
    p = list(range(149)); rng = random.Random(7)
    for _ in range(3):
        i, j = sorted(rng.sample(range(150), 2)); p = p[:i] + p[i:j][::-1] + p[j:]
        k = rng.randint(2, 9); p = [p[t] for r in range(k) for t in range(r, 149, k)]
    scr = apply(D322, p); z_scr = null322.z(scr)
    hb = hill(scr, null322, steps=8000, restarts=4, tag="ctrl_hill", seed=1)
    ctrl["hill_3moves"] = {"z_scrambled": round(z_scr, 2), "hill_best_z": round(hb[0][0], 2), "target_z": round(z_real, 2)}
    shuf = D322.copy(); np.random.shuffle(shuf)
    hb0 = hill(shuf, null322, steps=8000, restarts=4, tag="ctrl_hill_nullshuf", seed=2)
    ctrl["hill_on_shuffled_149"] = round(hb0[0][0], 2)
    G.jsonl(LOG, ctrl); print(json.dumps(ctrl, indent=1), flush=True)

    # ============================================================== FAED
    FA = np.array([ord(ch) - 97 for ch in G.FAED]); nullF = Null(FA, 9)
    base_z = {"faed_identity_z_mi1": round(nullF.z(FA), 2), "faed_identity_z_ioc2": round(nullF.zio(FA), 2)}
    G.jsonl(LOG, base_z); print(base_z, flush=True)
    resF = scan_families(FA, nullF, "faed")
    topF = resF[:20]
    G.jsonl(LOG, {"faed_top20": [(round(z, 2), round(zi, 2), f, nm) for z, zi, f, nm, _ in topF]})
    print("faed familias top5:", [(round(z, 2), nm) for z, zi, f, nm, _ in topF[:5]], "n=", len(resF), "t=", round(time.time() - T0), flush=True)
    hF = hill(FA, nullF, steps=30000, restarts=20, tag="faed_hill", seed=3)
    shufF = FA.copy(); np.random.shuffle(shufF)
    hF0 = hill(shufF, nullF, steps=30000, restarts=5, tag="faed_hill_nullshuf", seed=4)
    hill_rep = {"faed_hill_best": [round(z, 2) for z, _ in hF], "faed_hill_on_shuffled": [round(z, 2) for z, _ in hF0]}
    G.jsonl(LOG, hill_rep); print(hill_rep, "t=", round(time.time() - T0), flush=True)

    # ============================================================== DBBI
    DB = np.array([ord(ch) - 97 for ch in G.DBBI]); nullD = Null(DB, 9)
    base_zD = {"dbbi_identity_z_mi1": round(nullD.z(DB), 2), "dbbi_identity_z_ioc2": round(nullD.zio(DB), 2)}
    G.jsonl(LOG, base_zD); print(base_zD, flush=True)
    resD = scan_families(DB, nullD, "dbbi", with_halves=False)
    topD = resD[:20]
    G.jsonl(LOG, {"dbbi_top20": [(round(z, 2), round(zi, 2), f, nm) for z, zi, f, nm, _ in topD]})
    hD = hill(DB, nullD, steps=10000, restarts=10, tag="dbbi_hill", seed=5)
    shufD = DB.copy(); np.random.shuffle(shufD)
    hD0 = hill(shufD, nullD, steps=10000, restarts=5, tag="dbbi_hill_nullshuf", seed=6)
    hill_repD = {"dbbi_hill_best": [round(z, 2) for z, _ in hD], "dbbi_hill_on_shuffled": [round(z, 2) for z, _ in hD0]}
    G.jsonl(LOG, hill_repD); print(hill_repD, "t=", round(time.time() - T0), flush=True)

    # ============================================================== decode dos top-20 (familias) + top-5 hill
    todo = [("faed", G.FAED, [(nm, q) for _, _, _, nm, q in topF] + [(f"hill{i}_z{z:.1f}", q) for i, (z, q) in enumerate(hF[:5])]),
            ("dbbi", G.DBBI, [(nm, q) for _, _, _, nm, q in topD] + [(f"hill{i}_z{z:.1f}", q) for i, (z, q) in enumerate(hD[:5])])]
    for tag, s, lst in todo:
        for nm, q in lst:
            sym = "".join(s[i] for i in q)
            decode_seq(sym, f"{tag}:{nm}")
        print(tag, "decode ok, best", best, "t=", round(time.time() - T0), flush=True)

    summary = {"n_tests": N, "n_tests_total": sum(N.values()), "hard": hard, "soft": soft, "best": best,
               "control": ctrl, "faed_identity": base_z, "faed_top": [(round(z, 2), nm) for z, _, _, nm, _ in topF[:10]],
               "faed_hill": hill_rep, "dbbi_identity": base_zD, "dbbi_top": [(round(z, 2), nm) for z, _, _, nm, _ in topD[:10]],
               "dbbi_hill": hill_repD, "secs": round(time.time() - T0)}
    G.jsonl(LOG, summary)
    with open(SP + r"\permutation_search_summary.json", "w", encoding="utf-8") as f: json.dump(summary, f, ensure_ascii=False, indent=1)
    print(json.dumps(summary, ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
