# -*- coding: utf-8 -*-
"""FAMÍLIA computed_lists — dbbi/faed são LISTAS CALCULADAS (não cifra)?

Hipótese (falsificável, espaço finito): dbbi (91 = C(14,2)) é uma função de pares de linhas/colunas da
matriz 14×14 (dot/AND/OR/XOR/soma/diferença/produto, reduzida mod 9/10/26); faed (570) é uma lista
derivada da matriz (janelas deslizantes), de constantes matemáticas (π, e, √2, φ, ln2, γ, primos), de
dígitos de hashes/endereço/pubkey, ou é um número N (base 10/9/8) ou string base58 que codifica a
privkey. Se nenhuma comparação supera o nulo (≈ n/9 acertos, LCS ≈ log10(|A||B|)) e nenhum decode
gera a privkey, a hipótese é refutada para este espaço.
"""
import sys, json, math, itertools, hashlib, random
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
import numpy as np
from scipy.stats import pearsonr, spearmanr
import mpmath, base58
from coincurve import PublicKey

LOG = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02\computed_lists.jsonl"
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)
log({"hypothesis": __doc__.strip()})

N_TESTS = 0
HARD, SOFT, LEADS = [], [], []
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

D1 = G.digits(G.DBBI)            # a=1..9
D0 = G.digits(G.DBBI, False)     # a=0..8
F1 = G.digits(G.FAED); F0 = G.digits(G.FAED, False)
S_D1 = "".join(map(str, D1)); S_D0 = "".join(map(str, D0))
S_F1 = "".join(map(str, F1)); S_F0 = "".join(map(str, F0))

# ------------------------------------------------------------------ pool de listas calculadas
# Toda lista que passa pelo comparador vira também MATERIAL DE SENHA (ponte lista→AES/privkey).
POOL = {}          # string -> primeiro nome que a gerou
POOL_CAP = 20000
def pool_add(name, L):
    if len(POOL) >= POOL_CAP: return
    if not L or len(L) < 8: return
    if all(isinstance(v, (int, np.integer)) and 0 <= v <= 9 for v in L):
        POOL.setdefault("".join(str(int(v)) for v in L), name)
    else:
        POOL.setdefault(",".join(str(int(v)) for v in L), name)

def hist_cmp(L, T):
    """Distância de variação total entre histogramas + igualdade de multiconjunto."""
    hL = {}; hT = {}
    for v in L: hL[v] = hL.get(v, 0) + 1
    for v in T: hT[v] = hT.get(v, 0) + 1
    keys = set(hL) | set(hT)
    tv = 0.5 * sum(abs(hL.get(k, 0) / len(L) - hT.get(k, 0) / len(T)) for k in keys)
    return round(tv, 4), (len(L) == len(T) and hL == hT)

# ------------------------------------------------------------------ comparador genérico
def compare(L, T, name, tname):
    """Compara lista de ints L com alvo T (lista de ints) em todos os alinhamentos.
    Devolve melhor nº de acertos e z contra nulo binomial (p=1/9 se ambos ∈ 1..9)."""
    global N_TESTS
    L = list(L); T = list(T)
    if len(L) < 20: return None
    pool_add(name, L)
    best = (0, 0, 20); bestv = -1e9  # (acertos, offset, n)
    for off in range(-len(L) + 20, len(T) - 19):
        a0 = max(0, -off); b0 = max(0, off)
        n = min(len(L) - a0, len(T) - b0)
        if n < 20: continue
        m = sum(1 for k in range(n) if L[a0 + k] == T[b0 + k])
        N_TESTS += 1
        if m - n / 9 > bestv: bestv = m - n / 9; best = (m, off, n)
    m, off, n = best
    p = 1 / 9; z = (m - n * p) / math.sqrt(n * p * (1 - p))
    # correlação no alinhamento 0 se comprimentos compatíveis
    r_p = r_s = None
    n0 = min(len(L), len(T))
    if n0 >= 20 and np.std(L[:n0]) > 0 and np.std(T[:n0]) > 0:
        r_p = float(pearsonr(L[:n0], T[:n0])[0]); r_s = float(spearmanr(L[:n0], T[:n0])[0])
    tv, same_multiset = hist_cmp(L, T)
    rec = {"list": name, "target": tname, "len": len(L), "best_matches": m, "of": n, "offset": off,
           "z": round(z, 2), "pearson": None if r_p is None else round(r_p, 3),
           "spearman": None if r_s is None else round(r_s, 3), "exact": (m == n and n == len(T)),
           "tv_hist": tv, "same_multiset": same_multiset}
    return rec

def lcs_len(a, b):
    """maior substring comum entre strings de dígitos (a pequeno, b grande) — por hashing de janelas."""
    lo, hi = 0, min(len(a), len(b))
    def has(k):
        if k == 0: return True
        S = {b[i:i + k] for i in range(len(b) - k + 1)}
        return any(a[i:i + k] in S for i in range(len(a) - k + 1))
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if has(mid): lo = mid
        else: hi = mid - 1
    return lo

RESULTS = []
def judge(rec, thr_z=4.0):
    if rec is None: return
    RESULTS.append(rec)
    if rec["exact"]: HARD.append(dict(rec, kind="exact_list_match"))  # revisado manualmente depois
    elif rec["z"] >= thr_z: SOFT.append(rec)
    elif rec["same_multiset"]: SOFT.append(dict(rec, why="mesmo multiconjunto (permutação)"))

# ------------------------------------------------------------------ (A) pares da matriz → dbbi
def red(vals, how):
    if how == "mod9+1": return [v % 9 + 1 for v in vals]
    if how == "mod9": return [v % 9 for v in vals]
    if how == "mod10": return [v % 10 for v in vals]
    if how == "mod26": return [v % 26 for v in vals]
    return list(vals)

def pair_ops(a, b):
    a = np.array(a); b = np.array(b)
    return {"dot": int(a @ b), "and": int((a & b).sum()), "or": int((a | b).sum()), "xor": int((a ^ b).sum()),
            "sum+sum": int(a.sum() + b.sum()), "absdiff": int(abs(a.sum() - b.sum())), "prod": int(a.sum() * b.sum()),
            "hamm_eq": int((a == b).sum())}

def vectors(M, kind):
    if kind == "row": return [M[r] for r in range(14)]
    if kind == "col": return [[M[r][c] for r in range(14)] for c in range(14)]

def pair_orders():
    lex = list(itertools.combinations(range(14), 2))
    yield "lex", lex
    yield "revlex", lex[::-1]
    yield "jmajor", sorted(lex, key=lambda p: (p[1], p[0]))
    yield "spiral_dist", sorted(lex, key=lambda p: (p[1] - p[0], p[0]))   # por distância
    yield "by_diff_desc", sorted(lex, key=lambda p: (-(p[1] - p[0]), p[0]))

TARGETS_D = {"dbbi_a1": D1, "dbbi_a0": D0}
for mname, M in (("IMG102", G.MATRIX_IMG), ("README101", G.MATRIX_README)):
    for kind in ("row", "col"):
        V = vectors(M, kind)
        for oname, order in pair_orders():
            ops = [pair_ops(V[i], V[j]) for i, j in order]
            for op in ops[0]:
                vals = [o[op] for o in ops]
                for how in ("mod9+1", "mod9", "mod10", "mod26", "raw"):
                    L = red(vals, how)
                    for tn, T in TARGETS_D.items():
                        judge(compare(L, T, f"{mname}/{kind}pairs/{oname}/{op}/{how}", tn))
        # (linha, coluna): 196 pares, ordem linha-major e coluna-major
        R = vectors(M, "row"); C = vectors(M, "col")
        if kind == "row":
            for oname, order in (("rc", [(r, c) for r in range(14) for c in range(14)]),
                                 ("cr", [(r, c) for c in range(14) for r in range(14)]),
                                 ("rc_offdiag", [(r, c) for r in range(14) for c in range(14) if r != c]),
                                 ("rc_upper", [(r, c) for r in range(14) for c in range(r + 1, 14)]),
                                 ("rc_lower", [(r, c) for r in range(14) for c in range(r)])):
                ops = [pair_ops(R[r], C[c]) for r, c in order]
                for op in ops[0]:
                    vals = [o[op] for o in ops]
                    for how in ("mod9+1", "mod9", "mod10", "mod26", "raw"):
                        L = red(vals, how)
                        for tn, T in TARGETS_D.items():
                            judge(compare(L, T, f"{mname}/rowcol/{oname}/{op}/{how}", tn))

# (A2) pares de SOMAS (14 somas de linha / coluna / ambas) — 91 = C(14,2)
for mname, M in (("IMG102", G.MATRIX_IMG), ("README101", G.MATRIX_README)):
    for sname, S in (("rowsums", G.row_sums(M)), ("colsums", G.col_sums(M))):
        for oname, order in pair_orders():
            for op, f in (("sum", lambda x, y: x + y), ("absdiff", lambda x, y: abs(x - y)), ("prod", lambda x, y: x * y),
                          ("xor", lambda x, y: x ^ y), ("and", lambda x, y: x & y), ("or", lambda x, y: x | y),
                          ("max", max), ("min", min), ("gcd", math.gcd), ("concat_mod", lambda x, y: int(f"{x}{y}"))):
                vals = [f(S[i], S[j]) for i, j in order]
                for how in ("mod9+1", "mod9", "mod10", "mod26", "raw"):
                    for tn, T in TARGETS_D.items():
                        judge(compare(red(vals, how), T, f"{mname}/{sname}pairs/{oname}/{op}/{how}", tn))
    # 28 somas (linhas+colunas): C(28,2)=378 ⊃ 91? compara prefixo
    S28 = G.row_sums(M) + G.col_sums(M)
    for op, f in (("sum", lambda x, y: x + y), ("absdiff", lambda x, y: abs(x - y)), ("prod", lambda x, y: x * y)):
        vals = [f(S28[i], S28[j]) for i, j in itertools.combinations(range(28), 2)]
        for how in ("mod9+1", "mod10"):
            for tn, T in TARGETS_D.items():
                judge(compare(red(vals, how), T, f"{mname}/sums28pairs/{op}/{how}", tn))
            judge(compare(red(vals, how), F1, f"{mname}/sums28pairs/{op}/{how}", "faed_a1"))

print("[fase B] n_tests=%d pool=%d" % (N_TESTS, len(POOL)), file=sys.stderr, flush=True)
# ------------------------------------------------------------------ (B) faed 570 como lista derivada
def readings(M):
    """4 leituras da matriz: normal, transposta, rot180, espelho-h; + espiral como grid 14x14? (não: lista)"""
    A = np.array(M)
    return {"id": A, "T": A.T.copy(), "rot180": A[::-1, ::-1].copy(), "fliph": A[:, ::-1].copy(), "flipv": A[::-1, :].copy()}

def windows(A):
    n = 14; out = {}
    out["w2x2"] = [int(A[r:r + 2, c:c + 2].sum()) for r in range(n - 1) for c in range(n - 1)]
    out["w3x3"] = [int(A[r:r + 3, c:c + 3].sum()) for r in range(n - 2) for c in range(n - 2)]
    out["cross"] = [int(A[r, c] + A[r - 1, c] + A[r + 1, c] + A[r, c - 1] + A[r, c + 1]) for r in range(1, n - 1) for c in range(1, n - 1)]
    out["cross8"] = [int(A[r - 1:r + 2, c - 1:c + 2].sum()) - int(A[r, c]) for r in range(1, n - 1) for c in range(1, n - 1)]
    out["w2x2_wrap"] = [int(A[r, c] + A[(r + 1) % n, c] + A[r, (c + 1) % n] + A[(r + 1) % n, (c + 1) % n]) for r in range(n) for c in range(n)]
    out["cross_wrap"] = [int(A[r, c] + A[(r - 1) % n, c] + A[(r + 1) % n, c] + A[r, (c - 1) % n] + A[r, (c + 1) % n]) for r in range(n) for c in range(n)]
    out["cross8_wrap"] = [int(sum(A[(r + dr) % n, (c + dc) % n] for dr in (-1, 0, 1) for dc in (-1, 0, 1) if dr or dc)) for r in range(n) for c in range(n)]
    out["w3x3_wrap"] = [int(sum(A[(r + dr) % n, (c + dc) % n] for dr in (-1, 0, 1) for dc in (-1, 0, 1))) for r in range(n) for c in range(n)]
    # janelas ao longo da espiral (lista 1D de 196 bits)
    sp = [int(A[r, c]) for r, c in G.SPIRAL]
    for w in (2, 3, 4, 5, 8, 9):
        out[f"spiral_win{w}"] = [sum(sp[i:i + w]) for i in range(196 - w + 1)]
        out[f"spiral_bin{w}"] = [int("".join(map(str, sp[i:i + w])), 2) for i in range(196 - w + 1)]
    rm = [int(x) for x in A.flatten()]
    for w in (3, 4, 8, 9):
        out[f"rowmajor_bin{w}"] = [int("".join(map(str, rm[i:i + w])), 2) for i in range(196 - w + 1)]
    # índices espirais × valor, prefix sums
    out["spiral_prefix"] = list(np.cumsum(sp))
    out["spiral_idx_ones"] = [i for i, v in enumerate(sp) if v]
    out["spiral_idx_zeros"] = [i for i, v in enumerate(sp) if not v]
    out["spiral_gaps_ones"] = list(np.diff(out["spiral_idx_ones"]))
    out["spiral_gaps_zeros"] = list(np.diff(out["spiral_idx_zeros"]))
    return out

TARGETS_F = {"faed_a1": F1, "faed_a0": F0, "dbbi_a1": D1, "dbbi_a0": D0}
for mname, M in (("IMG102", G.MATRIX_IMG), ("README101", G.MATRIX_README)):
    for rname, A in readings(M).items():
        for wname, L in windows(A).items():
            for how in ("mod9+1", "mod9", "mod10", "raw"):
                for tn, T in TARGETS_F.items():
                    judge(compare(red(L, how), T, f"{mname}/{rname}/{wname}/{how}", tn))

print("[fase B2] n_tests=%d pool=%d" % (N_TESTS, len(POOL)), file=sys.stderr, flush=True)
# (B2) constantes matemáticas — LCS + comparação por alinhamento
mpmath.mp.dps = 5100
CONSTS = {"pi": mpmath.pi, "e": mpmath.e, "sqrt2": mpmath.sqrt(2), "phi": mpmath.phi, "ln2": mpmath.ln(2),
          "euler_gamma": mpmath.euler, "sqrt3": mpmath.sqrt(3), "sqrt5": mpmath.sqrt(5), "cbrt2": mpmath.cbrt(2),
          "catalan": mpmath.catalan, "zeta3": mpmath.zeta(3), "ln10": mpmath.ln(10), "pi_sq": mpmath.pi ** 2,
          "e_pi": mpmath.e ** mpmath.pi, "champernowne": None, "primes_concat": None, "fib_concat": None,
          "primes_mod9": None, "primes_mod10": None, "primes_mod9p1": None, "kth_prime_digits": None}
def const_digits(name):
    if name == "champernowne": return "".join(str(i) for i in range(1, 1700))
    if name in ("primes_concat", "primes_mod9", "primes_mod10", "primes_mod9p1", "kth_prime_digits"):
        ps = [p for p in range(2, 60000) if G.is_prime(p)][:5000]
        if name == "primes_concat": return "".join(map(str, ps))
        if name == "primes_mod9": return "".join(str(p % 9) for p in ps)
        if name == "primes_mod9p1": return "".join(str(p % 9 + 1) for p in ps)
        if name == "primes_mod10": return "".join(str(p % 10) for p in ps)
        if name == "kth_prime_digits": return "".join(str(p)[-1] for p in ps)
    if name == "fib_concat":
        a, b, s = 1, 1, ""
        while len(s) < 5000: s += str(a); a, b = b, a + b
        return s
    s = mpmath.nstr(CONSTS[name], 5050, strip_zeros=False).replace(".", "")
    return s[:5000]

null_lcs = math.log10(5000 * 570) + 0.5  # ≈ 6.9 esperado p/ dígitos i.i.d.
const_hits = []
for cname in CONSTS:
    s = const_digits(cname)
    variants = {"raw": s, "nozero": s.replace("0", ""), "zero9": s.replace("0", "9"), "zero_to_1": s.replace("0", "1")}
    for vn, v in variants.items():
        for tn, t in (("faed_a1", S_F1), ("faed_a0", S_F0), ("dbbi_a1", S_D1), ("dbbi_a0", S_D0)):
            k = lcs_len(t, v); N_TESTS += 1
            rec = {"const": cname, "variant": vn, "target": tn, "lcs": k, "null_expected": round(math.log10(len(v) * len(t)), 1)}
            log(rec)
            if k >= 9: const_hits.append(rec)
            if k >= 12: SOFT.append(rec)
            # comparação alinhada (mod 9 +1 do dígito) — só variante nozero e raw
            if vn in ("raw", "nozero"):
                L = [int(c) for c in v]
                judge(compare(L, [int(c) for c in t], f"const/{cname}/{vn}", tn))
        # dígito(constante) mod 9 +1 (0→9 e 9→9 fundem)
        L = [int(c) % 9 + 1 for c in s]
        judge(compare(L, F1, f"const/{cname}/mod9+1", "faed_a1")); judge(compare(L, D1, f"const/{cname}/mod9+1", "dbbi_a1"))

print("[fase B3] n_tests=%d pool=%d" % (N_TESTS, len(POOL)), file=sys.stderr, flush=True)
# (B3) dígitos de hashes / endereço / pubkey
def dec_digits(b): return str(int.from_bytes(b, "big"))
HASH_SRC = {}
for tname, tv in G.TOKENS.items():
    HASH_SRC[f"sha256({tname})"] = hashlib.sha256(tv.encode()).digest()
    HASH_SRC[f"sha512({tname})"] = hashlib.sha512(tv.encode()).digest()
    HASH_SRC[f"md5({tname})"] = hashlib.md5(tv.encode()).digest()
url = "89727c1e8ee1e97d7d0f5e9a8e7f5e3b"  # placeholder; substituído abaixo se o kit tiver
try:
    url = G.URL_HASH if hasattr(G, "URL_HASH") else G.shahex("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
except Exception: pass
HASH_SRC["urlhash"] = bytes.fromhex(url)
HASH_SRC["sha256(urlhash)"] = hashlib.sha256(url.encode()).digest()
HASH_SRC["sha512(urlhash)"] = hashlib.sha512(url.encode()).digest()
HASH_SRC["pubkey"] = TGT
HASH_SRC["pubkey_x"] = TGT[1:33]; HASH_SRC["pubkey_y"] = TGT[33:]
HASH_SRC["addr_b58dec"] = base58.b58decode(G.PRIZE_ADDR)
allcat = "".join(G.TOKENS.values())
HASH_SRC["sha256(alltokens)"] = hashlib.sha256(allcat.encode()).digest()
HASH_SRC["sha512(alltokens)"] = hashlib.sha512(allcat.encode()).digest()
for hn, hb in HASH_SRC.items():
    for vn, v in (("dec", dec_digits(hb)), ("dec_nozero", dec_digits(hb).replace("0", "")), ("hex_digits_only", "".join(c for c in hb.hex() if c.isdigit())),
                  ("hex_nibbles_mod9p1", "".join(str(x % 9 + 1) for x in hb.hex().encode())), ("bytes_mod9p1", "".join(str(x % 9 + 1) for x in hb))):
        for tn, t in (("faed_a1", S_F1), ("faed_a0", S_F0), ("dbbi_a1", S_D1), ("dbbi_a0", S_D0)):
            k = lcs_len(t, v); N_TESTS += 1
            log({"hash": hn, "variant": vn, "target": tn, "lcs": k, "null_expected": round(math.log10(max(1, len(v)) * len(t)), 1)})
            if k >= 8: SOFT.append({"hash": hn, "variant": vn, "target": tn, "lcs": k})
            if len(v) >= 20: judge(compare([int(c) for c in v], [int(c) for c in t], f"hash/{hn}/{vn}", tn))
# endereço / pubkey em base58 → dígitos '1'..'9' → alfabeto a-i?
addr_digits = "".join(c for c in G.PRIZE_ADDR if c.isdigit())
for tn, t in (("faed_a1", S_F1), ("dbbi_a1", S_D1)):
    k = lcs_len(t, addr_digits); N_TESTS += 1
    log({"src": "prize_addr_digits", "target": tn, "lcs": k, "addr_digits": addr_digits})

print("[fase C] n_tests=%d pool=%d" % (N_TESTS, len(POOL)), file=sys.stderr, flush=True)
# ------------------------------------------------------------------ (C) faed/dbbi como número N
def factor_light(n, limit=200000):
    fs = []; m = n
    for p in range(2, limit):
        if m % p == 0:
            e = 0
            while m % p == 0: m //= p; e += 1
            fs.append((p, e))
        if p * p > m: break
    return fs, m
def isqrt_ok(n):
    r = math.isqrt(n); return r * r == n
def mr_prime(n, rounds=20):
    """Miller-Rabin (mpmath NÃO tem isprime — era o bug que matava a rodada anterior)."""
    if n < 2: return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0: return n == p
    d = n - 1; r = 0
    while d % 2 == 0: d //= 2; r += 1
    rr = random.Random(1)
    for _ in range(rounds):
        a = rr.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True
def priv_check(sec):
    global N_TESTS
    N_TESTS += 1
    try:
        return PublicKey.from_valid_secret(sec).format(False) == TGT
    except Exception: return False
def num_analysis(name, digs, base):
    global N_TESTS
    try: n = int("".join(map(str, digs)), base) if base <= 10 else None
    except ValueError: return
    if n is None: return
    fs, rest = factor_light(n)
    rec = {"number": name, "base": base, "bits": n.bit_length(), "small_factors": fs, "rest_bits": rest.bit_length(),
           "rest_prime_MR": mr_prime(rest) if 1 < rest.bit_length() <= 4000 else None, "is_square": isqrt_ok(n),
           "is_pow2": n & (n - 1) == 0, "trailing_hex": format(n, "x")[-16:], "leading_hex": format(n, "x")[:16]}
    # privkey: N mod ordem; primeiros/últimos 32 bytes; sha256 de N
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    cands = {"N_mod_order": (n % ORDER).to_bytes(32, "big"), "N_head32": nb[:32], "N_tail32": nb[-32:],
             "sha256(Nbytes)": hashlib.sha256(nb).digest(), "sha256(Ndec)": hashlib.sha256(str(n).encode()).digest()}
    for cn, c in cands.items():
        if len(c) == 32 and priv_check(c):
            HARD.append({"kind": "privkey", "how": f"{name} base{base} {cn}", "priv_hex": c.hex()})
    h = G.fast_priv_scan(nb, f"{name}_base{base}_bytes"); N_TESTS += max(0, len(nb) - 31)
    if h: HARD.append({"kind": "privkey", "how": h})
    log(rec)
    return rec
NUMS = []
for name, digs in (("faed_a1", F1), ("faed_a0", F0), ("dbbi_a1", D1), ("dbbi_a0", D0),
                   ("faed_a1_rev", F1[::-1]), ("dbbi_a1_rev", D1[::-1]),
                   ("faed_half1_a1", F1[:285]), ("faed_half2_a1", F1[285:]),
                   ("faed_a0_half1", F0[:285]), ("faed_a0_half2", F0[285:])):
    for base in (10, 9, 8):
        if base == 8 and max(digs) > 7: continue
        if base == 9 and max(digs) > 8: continue
        r = num_analysis(name, digs, base)
        if r: NUMS.append(r)
# base 8 com i removido / i como 0 / i como 8 (dígitos a-h = 0..7)
for name, S in (("faed", G.FAED), ("dbbi", G.DBBI)):
    for iname, imap in (("i_drop", None), ("i_as0", 0)):
        digs = [(ord(c) - 97) if c != "i" else imap for c in S]
        digs = [d for d in digs if d is not None]
        r = num_analysis(f"{name}_{iname}", digs, 8)
        if r: NUMS.append(r)
    # base 9 com a=1..i=9 onde i→0 (o método z da página usa o=0; talvez i=0)
    digs = [0 if c == "i" else ord(c) - 96 for c in S]
    r = num_analysis(f"{name}_i_as0_base9", digs, 9)
    if r: NUMS.append(r)

print("[fase D] n_tests=%d pool=%d" % (N_TESTS, len(POOL)), file=sys.stderr, flush=True)
# ------------------------------------------------------------------ (D) faed/dbbi como base58 de dígitos '1'..'9'
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58_scan(s, name):
    global N_TESTS
    try: raw = base58.b58decode(s)
    except Exception: return
    h = G.fast_priv_scan(raw, name); N_TESTS += max(1, len(raw) - 31)
    if h: HARD.append({"kind": "privkey", "how": h, "b58_input": s})
    return raw
for name, S in (("faed", G.FAED), ("dbbi", G.DBBI)):
    for mname, m in (("a=1", lambda c: str(ord(c) - 96)), ("a=0→'1'..'9'", lambda c: B58[ord(c) - 97]),
                     ("a=A", lambda c: chr(ord(c) - 32)), ("a=a", lambda c: c)):
        s = "".join(m(c) for c in S)
        b58_scan(s, f"{name}/{mname}/full"); b58_scan(s[::-1], f"{name}/{mname}/rev")
        if name == "faed":
            b58_scan(s[:285], f"{name}/{mname}/h1"); b58_scan(s[285:], f"{name}/{mname}/h2")
        # janelas de 44 chars (≈32 B) e 51/52 (WIF) — cada decode varrido
        for w in (43, 44, 45, 51, 52):
            for i in range(0, len(s) - w + 1):
                raw = b58_scan(s[i:i + w], f"{name}/{mname}/win{w}@{i}")
                if raw and w in (51, 52) and len(raw) in (37, 38) and raw[0] == 0x80:
                    chk = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
                    if chk == raw[-4:]: HARD.append({"kind": "wif_checksum_valid", "wif": s[i:i + w]})
# WIF grammar check on a-i alphabets is impossible (no '5','K','L' start) — covered by raw scan only.

print("[fase E] n_tests=%d pool=%d" % (N_TESTS, len(POOL)), file=sys.stderr, flush=True)
# ------------------------------------------------------------------ (E) ponte lista→senha/privkey
# Se dbbi/faed SÃO listas calculadas, a própria lista calculada é material de senha plausível
# (gramática provada: sha256(concatenação) → openssl -pass). Testa toda lista distinta do POOL.
BRIDGE = 0
BRIDGE_PAD = []          # todo padding PKCS7 válido (soft) da ponte
for s, origin in list(POOL.items()):
    forms = (s, G.shahex(s))
    for f in forms:
        h, so = G.try_password_all(f)
        BRIDGE += 3
        N_TESTS += 3
        for x in h: HARD.append(dict(x, kind="aes_semantic", pw=f, origin=origin))
        for x in so:
            BRIDGE_PAD.append(dict(x, pw=f[:64], origin=origin))
            if x["printable"] >= 0.55: SOFT.append(dict(x, pw=f[:64], origin=origin))
    sec = hashlib.sha256(s.encode()).digest()
    N_TESTS += 1
    if G.priv_hit(sec): HARD.append({"kind": "privkey", "how": f"sha256(list:{origin})", "priv_hex": sec.hex()})
BRIDGE_PAD.sort(key=lambda x: -x["printable"])
log({"bridge_lists": len(POOL), "bridge_aes_decrypts": BRIDGE * 2, "bridge_pad_ok": len(BRIDGE_PAD),
     "bridge_pad_rate": round(len(BRIDGE_PAD) / max(1, BRIDGE * 2), 5), "bridge_top_printable": BRIDGE_PAD[:5]})

print("[fase CTL] n_tests=%d pool=%d" % (N_TESTS, len(POOL)), file=sys.stderr, flush=True)
# ------------------------------------------------------------------ CONTROLES POSITIVOS
# 1) comparador detecta lista plantada (dbbi deslocada 3 com 10% de ruído)
rng = random.Random(7)
planted = [0] * 3 + [d if rng.random() > 0.1 else rng.randint(1, 9) for d in D1]
c1 = compare(planted, D1, "control/planted", "dbbi_a1")
assert c1["offset"] == -3 and c1["z"] > 8, c1
# 2) LCS acha substring plantada
assert lcs_len(S_D1, "5" * 100 + S_D1[20:45] + "7" * 100) == 25
# 3) base58 → fast_priv_scan detecta chave plantada (alvo temporário)
sec = hashlib.sha256(b"controle").digest()
_tgt_backup = G.TARGET_PUBKEY_HEX
G.TARGET_PUBKEY_HEX = PublicKey.from_valid_secret(sec).format(False).hex()
assert G.fast_priv_scan(base58.b58decode(base58.b58encode(b"xx" + sec + b"yy")), "ctl")
G.TARGET_PUBKEY_HEX = _tgt_backup
# 3b) controle positivo da PONTE AES: blob da fase 2 abre com sha256hex("causality") e é SEMÂNTICO
import base64 as _b64
_raw = _b64.b64decode(G.PHASE2_B64); _s2, _c2 = _raw[8:16], _raw[16:]
_k, _iv = G.evp(G.shahex("causality").encode(), _s2, G.SHA256)
_pt = G.unpad(G.AES.new(_k, G.AES.MODE_CBC, _iv).decrypt(_c2))
assert _pt is not None and G.semantic(_pt) and _pt.startswith(b"The ironic"), "controle AES falhou"
# 4) nulo do comparador: listas aleatórias 1..9 vs dbbi → z ~ N(0,1)+viés de max
zs = [compare([rng.randint(1, 9) for _ in range(91)], D1, "null", "dbbi")["z"] for _ in range(200)]
null_max_z = round(max(zs), 2); null_mean_z = round(float(np.mean(zs)), 2)
N_TESTS -= 200 * 145  # não contar o nulo

# ------------------------------------------------------------------ RESUMO
RESULTS.sort(key=lambda r: -r["z"])
top = RESULTS[:15]
for r in top: log(dict(r, top=True))
multi = [r for r in RESULTS if r.get("same_multiset")]
best_tv = sorted(RESULTS, key=lambda r: r["tv_hist"])[:10]
summary = {"n_tests": N_TESTS, "n_lists_compared": len(RESULTS), "n_pool": len(POOL), "top_z": top,
           "const_lcs_hits": const_hits, "same_multiset": multi[:10], "n_same_multiset": len(multi),
           "best_tv_hist": best_tv, "null_max_z_200": null_max_z, "null_mean_z_200": null_mean_z,
           "numbers": NUMS, "hard": HARD, "soft": SOFT[:40], "n_soft": len(SOFT),
           "bridge": {"lists": len(POOL), "aes_decrypts": BRIDGE * 2, "pad_ok": len(BRIDGE_PAD),
                      "pad_rate": round(len(BRIDGE_PAD) / max(1, BRIDGE * 2), 5),
                      "top_printable": BRIDGE_PAD[:5]}}
log({"summary": summary})
print(json.dumps(summary, default=str, indent=1)[:12000])
