# Reproduz a cadeia do Codex (dbbi/faed em primos -> filtro por bits -> base 9 -> bytes -> 23/16/7 -> &8 -> "Hb_m!%D")
# e mede cada encaixe contra o nulo do PRÓPRIO espaço de variantes que o Codex enumerou.
import sys, random, itertools
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
def primes(n): return [x for x in range(2, n + 1) if all(x % d for d in range(2, int(x ** .5) + 1))]
def b9(s, rev=False, inv=False):
    ds = [ord(c) - 97 for c in (s[::-1] if rev else s)]
    if inv: ds = [8 - d for d in ds]
    n = 0
    for d in ds: n = n * 9 + d
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
url = "gsmg.io/theseedisplanted"; urlbits = "".join(str(ord(c) & 1) for c in url)
pdb = "".join(G.DBBI[p - 1] for p in primes(91))
exact_db = b9("".join(c for c, b in zip(pdb, urlbits) if b == "1"))
inds = [i for i in range(570) if (i + 1) >= 2 and all((i + 1) % d for d in range(2, int((i + 1) ** .5) + 1))]
pf = "".join(G.FAED[i] for i in inds)
mb = "".join(f"{ord(c):08b}" for c in "matrixsumlist")
exact_fa = b9("".join(c for c, b in zip(pf, mb) if b == "0"))
print("EXACT_DB", exact_db.hex(), "EXACT_FA", exact_fa.hex())
assert exact_db.hex() == "176c386f4f4b" and exact_fa.hex() == "10eb5a8d5890c25ab7eddc6908d5294145842c"
src = exact_db[1:] + exact_fa[1:]; ct = bytes(b for b in src if b & 8); pw = bytes(b for b in src if not b & 8)
rm8 = lambda x: ((x >> 4) << 3) | (x & 7)
print("src", len(src), "ct", len(ct), "pw", len(pw), bytes(map(rm8, pw)))
# --- nulo 1: espaço de variantes do Codex (dbbi: 3 máscaras × 2 bits × rev × inv = 24; faed: 2 bases × 5 máscaras × 2 × 2 × 2 = 80)
def bits_variants(text):
    raw = "".join(f"{ord(c):08b}" for c in text); br = "".join(raw[i:i + 8][::-1] for i in range(0, len(raw), 8))
    return {raw, raw[::-1], br, br[::-1], "".join("1" if x == "0" else "0" for x in raw)}
dbch = []
for m in {urlbits, urlbits[::-1], "".join("1" if x == "0" else "0" for x in urlbits)}:
    for want in "01":
        s = "".join(c for c, b in zip(pdb, m) if b == want)
        for rev in (0, 1):
            for inv in (0, 1): dbch.append(b9(s, rev, inv))
fach = []
for base in (0, 1):
    ii = [i for i in range(570) if i + base >= 2 and all((i + base) % d for d in range(2, int((i + base) ** .5) + 1))]
    p2 = "".join(G.FAED[i] for i in ii)
    for m in bits_variants("matrixsumlist"):
        for want in "01":
            s = "".join(c for c, b in zip(p2, m) if b == want)
            for rev in (0, 1):
                for inv in (0, 1): fach.append(b9(s, rev, inv))
MEAN = {7, 16, 23}
lead_db = sum(b[0] in MEAN for b in dbch); lead_fa = sum(b[0] in MEAN for b in fach)
pairs = sum(1 for a in dbch for b in fach if a[0] in MEAN and b[0] in MEAN and a[0] != b[0])
print(f"nulo do próprio espaço: dbbi streams {len(dbch)} com 1º byte em {{7,16,23}}: {lead_db}; faed streams {len(fach)}: {lead_fa}; pares 'significativos' entre {len(dbch)*len(fach)} pares: {pairs}")
# --- nulo 2: para cada par, aplicar a MESMA regra (bit k que dá corte 16/7 em 23 bytes; rm-bit -> 7 bytes imprimíveis)
def chain_ok(a, b):
    s = a[1:] + b[1:]
    if len(s) != 23: return None
    out = []
    for k in range(8):
        sel = [bool(x & (1 << k)) for x in s]
        if sum(sel) == 16:
            p = bytes(x for x, m in zip(s, sel) if not m)
            def rmk(x): return ((x >> (k + 1)) << k) | (x & ((1 << k) - 1))
            q = bytes(map(rmk, p)); out.append(all(32 <= c < 127 for c in q))
    return out
n23 = 0; nsplit = 0; nprint = 0
for a in dbch:
    for b in fach:
        r = chain_ok(a, b)
        if r is None: continue
        n23 += 1
        if r: nsplit += 1
        if any(r): nprint += 1
print(f"pares com 23 bytes: {n23}; com algum bit dando corte 16/7: {nsplit}; desses, 7 bytes todos imprimíveis após remover o bit: {nprint}")
# --- nulo 3: 7 valores de 7 bits aleatórios todos imprimíveis
random.seed(0); N = 200000
print("P(7 valores de 7 bits todos imprimíveis) =", sum(all(32 <= random.randrange(128) < 127 for _ in range(7)) for _ in range(N)) / N)
# --- senha Hb_m!%D nos 3 blobs (EVP sha256 e md5) + privkey
n = 0; hard = []; pads = 0
base = "Hb_m!%D"
forms = {base, base.lower(), base.upper(), base[::-1], G.shahex(base), G.shahex(base).upper(), G.sha(base), pw, pw.hex(), ct.hex(), src.hex(), G.shahex(src), G.shahex(ct), G.shahex(pw)}
for f in forms:
    h, s = G.try_password_all(f); n += 3; pads += len(s); hard += h
    hard += [(f, r) for r in G.phrase_priv(f)] if isinstance(f, str) else []
print("senha Hb_m!%D e derivados:", n, "AES, paddings", pads, "HARD", hard)
