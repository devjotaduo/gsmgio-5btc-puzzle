# -*- coding: utf-8 -*-
"""Familia: regra dos marcadores nos primos (atlas/Doober) aplicada a `faed`.
Hipotese (prosa): se `yellowblueprimes` e um passo geral, faed tambem se segmenta com um
marcador (x ou xy) em toda posicao logica prima e um simbolo nas demais. Testamos todas as
variantes de regra (81 pares, x simples, y livre, triplas, primos 0-based, primos do fim,
primos fisicos, compostos), medimos p com nulo casado e, para regras significativas,
extraimos residuo + bits e comparamos com a matriz.
"""
import sys, os, json, random, itertools, time
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G

OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "faed_primes.jsonl")
open(LOG, "w").close()
def log(**kw): G.jsonl(LOG, kw)
log(hypothesis=__doc__.strip())

L = "abcdefghi"
random.seed(20260917)

# ------------------------------------------------------------------ predicados de posicao
def primes_upto(n):
    return {p for p in range(2, n + 1) if G.is_prime(p)}
def marker_mask(kind, N):
    """bitmask sobre posicoes logicas q (1..N): bit q ligado se q e' posicao de marcador."""
    P = primes_upto(N + 1)
    if kind == "prime1":   S = {q for q in range(1, N + 1) if q in P}          # 1-based
    elif kind == "prime0": S = {q for q in range(1, N + 1) if (q - 1) in P}    # 0-based ('First or zero')
    elif kind == "comp1":  S = {q for q in range(1, N + 1) if q >= 4 and q not in P}  # compostos
    else: raise ValueError(kind)
    m = 0
    for q in S: m |= 1 << q
    return m

# ------------------------------------------------------------------ DP por bitset (alcance) e DP contadora
def reach(s, markers, mmask):
    """R[i] = bitmask dos p (tokens logicos ja consumidos) alcancaveis apos i chars fisicos.
    Devolve lista de L finais (p com bit em R[N])."""
    N = len(s); FULL = (1 << (N + 2)) - 1; NM = (~mmask) & FULL
    R = [0] * (N + 3); R[0] = 1
    for i in range(N):
        r = R[i]
        if not r: continue
        sh = r << 1
        R[i + 1] |= sh & NM
        for m in markers:
            k = len(m)
            if i + k <= N and s[i:i + k] == m:
                R[i + k] |= sh & mmask
    r = R[N]; return [p for p in range(N + 1) if r >> p & 1]

def count_segs(s, markers, mmask):
    """DP contadora: numero de segmentacoes completas por L."""
    N = len(s); C = [dict() for _ in range(N + 3)]; C[0][0] = 1
    for i in range(N):
        for p, c in C[i].items():
            q = p + 1
            if not (mmask >> q & 1):
                C[i + 1][q] = C[i + 1].get(q, 0) + c
            else:
                for m in markers:
                    k = len(m)
                    if i + k <= N and s[i:i + k] == m:
                        C[i + k][q] = C[i + k].get(q, 0) + c
    return dict(C[N])

def enumerate_segs(s, markers, mmask, limit=64):
    """Backtracking; devolve lista de (L, tokens)."""
    N = len(s); out = []
    def go(i, q, toks):
        if len(out) >= limit: return
        if i == N: out.append((q - 1, list(toks))); return
        if mmask >> q & 1:
            for m in markers:
                k = len(m)
                if i + k <= N and s[i:i + k] == m:
                    toks.append(m); go(i + k, q + 1, toks); toks.pop()
        else:
            toks.append(s[i]); go(i + 1, q + 1, toks); toks.pop()
    go(0, 1, []); return out

# ------------------------------------------------------------------ catalogo de regras
def rules():
    R = []
    for x in L:
        R.append((f"{x}|{x}?", [x] + [x + y for y in L]))          # y livre
        R.append((f"{x}", [x]))                                     # x simples
        for y in L: R.append((f"{x}|{x}{y}", [x, x + y]))           # 81 pares
        for y, z in itertools.combinations(L, 2):
            R.append((f"{x}|{x}{y}|{x}{z}", [x, x + y, x + z]))     # triplas
    return R
RULES = rules()

def run_rules(name, s, kinds=("prime1", "prime0", "comp1"), rev=False):
    """Roda todas as regras x posicoes; para 'do fim' usa s invertido e marcadores invertidos."""
    N = len(s); hits = []
    for kind in kinds:
        mm = marker_mask(kind, N)
        for rn, mk in RULES:
            if rev:
                Ls = reach(s[::-1], [m[::-1] for m in mk], mm)
            else:
                Ls = reach(s, mk, mm)
            if Ls: hits.append((kind + ("/fim" if rev else ""), rn, mk, Ls))
    return hits

def physical_check(s, x, zero_based):
    """posicoes FISICAS primas: o simbolo nelas tem de ser x. Devolve as posicoes que violam."""
    N = len(s); P = primes_upto(N)
    if zero_based: return [p for p in P if p < N and s[p] != x]
    return [p for p in P if s[p - 1] != x]

# ------------------------------------------------------------------ nulo
def null_p(s, markers, mmask, n=2000, rev=False):
    """Fracao de embaralhamentos (mesmas contagens) que admitem >=1 segmentacao completa."""
    chars = list(s); k = 0
    mk = [m[::-1] for m in markers] if rev else markers
    for _ in range(n):
        random.shuffle(chars); t = "".join(chars)
        if reach(t[::-1] if rev else t, mk, mmask): k += 1
    return k, n

# ------------------------------------------------------------------ referencias da matriz
COLOR25 = "".join('B' if G.COLORED[i][0] in ('B', 'W*') else 'Y' for i in sorted(G.COLORED))
assert COLOR25 == "BBBBYBBBYYBBBBYBBYYBWYYBY".replace("W", "B"), COLOR25
COLOR25_BITS = COLOR25.replace("B", "0").replace("Y", "1")
OMIT2 = {}
for a, b in itertools.combinations(range(25), 2):
    OMIT2["".join(c for i, c in enumerate(COLOR25_BITS) if i not in (a, b))] = (a + 1, b + 1)
SPIRAL_IMG = "".join(str(G.MATRIX_IMG[r][c]) for r, c in G.SPIRAL)
SPIRAL_RME = "".join(str(G.MATRIX_README[r][c]) for r, c in G.SPIRAL)
DBBI_BITS_L84 = "00001000110000100110010"; DBBI_BITS_L83 = "00001000110000100110011"
CMP = str.maketrans("01", "10")

def best_window(bits, ref):
    """menor distancia de Hamming de `bits` (ou reverso/complemento) contra janelas de ref."""
    n = len(bits); best = (n + 1, None)
    for tag, b in (("id", bits), ("rev", bits[::-1]), ("cmp", bits.translate(CMP)), ("revcmp", bits[::-1].translate(CMP))):
        for j in range(0, len(ref) - n + 1):
            d = sum(u != v for u, v in zip(b, ref[j:j + n]))
            if d < best[0]: best = (d, (tag, j))
    return best

def compare_bits(bits, tag):
    rep = {"tag": tag, "n_bits": len(bits), "bits": bits, "ones": bits.count("1")}
    found = []
    for j in range(0, len(bits) - 22):
        w = bits[j:j + 23]
        if w in OMIT2: found.append((j, OMIT2[w]))
        wr = w[::-1]
        if wr in OMIT2: found.append((j, "rev", OMIT2[wr]))
    rep["omit2_windows"] = found[:20]
    if len(bits) <= 192:
        rep["spiral_img_best"] = best_window(bits, SPIRAL_IMG); rep["spiral_readme_best"] = best_window(bits, SPIRAL_RME)
    else:
        rep["spiral_img_best"] = best_window(SPIRAL_IMG, bits); rep["spiral_readme_best"] = best_window(SPIRAL_RME, bits)
    rep["dbbi84_in"] = [j for j in range(len(bits) - 22) if bits[j:j + 23] == DBBI_BITS_L84]
    rep["dbbi83_in"] = [j for j in range(len(bits) - 22) if bits[j:j + 23] == DBBI_BITS_L83]
    if len(bits) >= 25:
        rep["dbbi84_best"] = best_window(DBBI_BITS_L84, bits)
        rep["color25_best"] = best_window(COLOR25_BITS, bits)
        bl = list(bits); ds = []
        for _ in range(200):
            random.shuffle(bl); ds.append(best_window(COLOR25_BITS, "".join(bl))[0])
        rep["color25_null_min_mean"] = (min(ds), sum(ds) / len(ds))
        ds = []
        for _ in range(200):
            random.shuffle(bl); ds.append(best_window(DBBI_BITS_L84, "".join(bl))[0])
        rep["dbbi84_null_min_mean"] = (min(ds), sum(ds) / len(ds))
    return rep

# ------------------------------------------------------------------ testes rapidos no residuo
def bytes_report(b, where):
    rec = {"where": where, "len": len(b), "printable": round(G.printable(b), 3), "head_hex": b[:32].hex()}
    if len(b) >= 32:
        pk = G.fast_priv_scan(b, where)
        if pk: rec["PRIVKEY"] = pk
    if G.semantic(b): rec["SEMANTIC"] = True; rec["text"] = b.decode("latin-1")[:120]
    if G.nested_blob(b): rec["NESTED"] = True
    return rec

def int_to_bytes(n):
    h = format(n, "x"); h = "0" + h if len(h) % 2 else h
    return bytes.fromhex(h)

def quick_tests(res, tag):
    out = []; n_tests = 0
    rs, cs = G.row_sums(G.MATRIX_README), G.col_sums(G.MATRIX_README)
    for dirn, r in (("fwd", res), ("rev", res[::-1])):
        d10 = G.digits(r, True); d9 = G.digits(r, False)
        out.append(bytes_report(G.z_method(d10), f"{tag}/{dirn}/b10")); n_tests += 1
        out.append(bytes_report(G.z_method(d9), f"{tag}/{dirn}/b9dec")); n_tests += 1
        n = 0
        for v in d9: n = n * 9 + v
        out.append(bytes_report(int_to_bytes(n), f"{tag}/{dirn}/base9int")); n_tests += 1
        for z in L:  # z-method: cada letra como zero
            dl = [0 if c == z else G.A2I[c] for c in r]
            out.append(bytes_report(G.z_method(dl), f"{tag}/{dirn}/zero={z}")); n_tests += 1
        for kn, ks in (("row", rs), ("col", cs), ("rowcol", rs + cs), ("colrow", cs + rs), ("101", [1, 0, 1])):
            for mod in (9, 10):
                base = d10 if mod == 10 else d9
                for op in ("add", "sub", "ksub"):
                    dl = []
                    for i, v in enumerate(base):
                        k = ks[i % len(ks)]
                        dl.append((v + k) % mod if op == "add" else (v - k) % mod if op == "sub" else (k - v) % mod)
                    out.append(bytes_report(G.z_method(dl), f"{tag}/{dirn}/ks={kn}/mod{mod}/{op}")); n_tests += 1
                    t = "".join(str(x) for x in dl)
                    pairs = bytes(int(t[i:i + 2]) for i in range(0, len(t) - 1, 2))
                    out.append(bytes_report(pairs, f"{tag}/{dirn}/ks={kn}/mod{mod}/{op}/pairs")); n_tests += 1
    return out, n_tests

def oracle(pws, tag):
    hard, soft = [], []; n = 0
    for pw in pws:
        for cand in (pw, G.shahex(pw)):
            h, s = G.try_password_all(cand); n += 6
            for r in h: r["pw"] = cand[:80]; r["tag"] = tag
            for r in s: r["pw"] = cand[:80]; r["tag"] = tag
            hard += h; soft += s
    return hard, soft, n

# ================================================================== MAIN
t0 = time.time()
summary = {"n_tests": 0, "hard_hits": [], "soft_hits": [], "controls": [], "rules_faed": [], "rules_dbbi": []}

# --- controle positivo: dbbi com b/be (1-based) deve dar exatamente L=83 e L=84
mm = marker_mask("prime1", 91)
c = count_segs(G.DBBI, ["b", "be"], mm)
assert c == {83: 1, 84: 1}, c
segs = enumerate_segs(G.DBBI, ["b", "be"], mm)
for Lc, toks in segs:
    P = primes_upto(Lc)
    mk = [t for q, t in enumerate(toks, 1) if q in P]
    bits = "".join("1" if len(t) == 2 else "0" for t in mk)
    res = "".join(t for q, t in enumerate(toks, 1) if q not in P)
    summary["controls"].append({"dbbi": Lc, "n_markers": len(mk), "bits": bits, "residue": res})
    assert bits in (DBBI_BITS_L84, DBBI_BITS_L83)
# controle sintetico: planta uma segmentacao aleatoria e recupera
for trial in range(5):
    Lc = random.randint(60, 120); P = primes_upto(Lc); x, y = random.choice(L), random.choice(L)
    toks = [(x if random.random() < .6 else x + y) if q in P else random.choice(L) for q in range(1, Lc + 1)]
    t = "".join(toks); assert Lc in reach(t, [x, x + y], marker_mask("prime1", len(t))), "controle sintetico falhou"
summary["controls"].append("5 segmentacoes sinteticas recuperadas; dbbi b/be -> {83:1,84:1}")
log(step="controls", ok=True, dbbi=summary["controls"])

# --- look-elsewhere em dbbi: todas as regras / posicoes
hits_dbbi = run_rules("dbbi", G.DBBI) + run_rules("dbbi", G.DBBI, kinds=("prime1", "prime0"), rev=True)
n_rules_dbbi = len(RULES) * 5
summary["n_tests"] += n_rules_dbbi
summary["rules_dbbi"] = [{"pos": k, "rule": rn, "Ls": Ls} for k, rn, mk, Ls in hits_dbbi]
for x in L:
    for zb in (False, True):
        bad = physical_check(G.DBBI, x, zb)
        summary["n_tests"] += 1
        if not bad: summary["rules_dbbi"].append({"pos": "fisico" + ("0" if zb else "1"), "rule": x, "Ls": [91]})
log(step="dbbi_look_elsewhere", n_rules=n_rules_dbbi + 18, n_hit_rules=len(summary["rules_dbbi"]),
    hits=summary["rules_dbbi"][:80])
dbbi_nulls = []
for k, rn, mk, Ls in hits_dbbi:
    rev = k.endswith("/fim"); kind = k.split("/")[0]
    kk, n = null_p(G.DBBI, mk, marker_mask(kind, 91), n=2000, rev=rev)
    dbbi_nulls.append({"pos": k, "rule": rn, "Ls": Ls, "null_hits": kk, "n": n, "p": (kk + 1) / (n + 1)})
summary["dbbi_nulls"] = dbbi_nulls
log(step="dbbi_nulls", nulls=dbbi_nulls)
print("dbbi look-elsewhere:", len(summary["rules_dbbi"]), "regras batem;", round(time.time() - t0), "s"); sys.stdout.flush()

# --- faed: todas as regras / posicoes
hits_faed = run_rules("faed", G.FAED) + run_rules("faed", G.FAED, kinds=("prime1", "prime0"), rev=True)
summary["n_tests"] += len(RULES) * 5
for x in L:
    for zb in (False, True):
        bad = physical_check(G.FAED, x, zb); summary["n_tests"] += 1
        if not bad: hits_faed.append(("fisico" + ("0" if zb else "1"), x, [x], [570]))
log(step="faed_rules", n_rules=len(RULES) * 5 + 18, n_hit_rules=len(hits_faed),
    hits=[(k, rn, Ls) for k, rn, mk, Ls in hits_faed])
print("faed: regras que batem:", len(hits_faed), round(time.time() - t0), "s"); sys.stdout.flush()

# --- nulos para cada regra que bate em faed
faed_sig = []
for k, rn, mk, Ls in hits_faed:
    if k.startswith("fisico"): continue
    rev = k.endswith("/fim"); kind = k.split("/")[0]
    mm = marker_mask(kind, 570)
    cnt = count_segs(G.FAED[::-1] if rev else G.FAED, [m[::-1] for m in mk] if rev else mk, mm)
    kk, n = null_p(G.FAED, mk, mm, n=2000, rev=rev)
    rec = {"pos": k, "rule": rn, "Ls": Ls, "count_by_L": cnt, "null_hits": kk, "n": n, "p": (kk + 1) / (n + 1)}
    summary["rules_faed"].append(rec); log(step="faed_null", **rec)
    if kk < 0.05 * n: faed_sig.append((k, rn, mk, Ls, cnt))
print("faed: regras significativas (p<0.05):", len(faed_sig), round(time.time() - t0), "s"); sys.stdout.flush()

# --- para regras significativas: residuo + bits + comparacoes + testes rapidos + oraculo
best_readable = {"score": -99}
for k, rn, mk, Ls, cnt in faed_sig:
    rev = k.endswith("/fim"); kind = k.split("/")[0]; mm = marker_mask(kind, 570)
    s = G.FAED[::-1] if rev else G.FAED; mks = [m[::-1] for m in mk] if rev else mk
    segs = enumerate_segs(s, mks, mm, limit=16)
    for Lc, toks in segs:
        mpos = [q for q in range(1, Lc + 1) if mm >> q & 1]
        markers = [t for q, t in enumerate(toks, 1) if q in mpos]
        bits = "".join("0" if len(t) == 1 else "1" for t in markers)
        res = "".join(t for q, t in enumerate(toks, 1) if q not in mpos)
        if rev: res = res[::-1]; bits = bits[::-1]; markers = [m[::-1] for m in markers][::-1]
        tag = f"faed/{k}/{rn}/L{Lc}"
        cb = compare_bits(bits, tag)
        suf = "".join(m[1] if len(m) > 1 else "_" for m in markers)
        rec = {"tag": tag, "L": Lc, "n_markers": len(markers), "residue": res, "suffixes": suf, "bits_cmp": cb}
        qt, nt = quick_tests(res, tag); summary["n_tests"] += nt
        rec["quick_flags"] = [r for r in qt if "PRIVKEY" in r or "SEMANTIC" in r or "NESTED" in r]
        rec["quick_max_printable"] = max(r["printable"] for r in qt)
        es = G.english_score(res); rl = list(res); nulls = []
        for _ in range(100): random.shuffle(rl); nulls.append(G.english_score("".join(rl)))
        rec["english"] = {"score": es, "null_mean": sum(nulls) / 100, "null_max": max(nulls)}
        if es > best_readable["score"]: best_readable = {"score": es, "tag": tag, "text": res[:80], "null_max": max(nulls)}
        pws = [res, res[::-1], bits, suf.replace("_", ""), "".join(markers), "".join(toks)]
        h, sft, n = oracle(pws, tag); summary["n_tests"] += n
        summary["hard_hits"] += h
        summary["soft_hits"] += [{"tag": r["tag"], "pw": r["pw"], "blob": r["blob"], "kdf": r["kdf"], "printable": r["printable"], "plain_hex": r["hex"]} for r in sft]
        log(step="faed_sig_detail", **rec)
        print(tag, "L", Lc, "markers", len(markers), "res", len(res), "english", round(es, 2), "null_max", round(max(nulls), 2)); sys.stdout.flush()
summary["best_readable"] = best_readable
summary["elapsed_s"] = round(time.time() - t0, 1)
with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f: json.dump(summary, f, ensure_ascii=False, indent=1, default=str)
print("DONE", summary["n_tests"], "tests;", len(summary["hard_hits"]), "hard;", len(summary["soft_hits"]), "soft;", summary["elapsed_s"], "s")
