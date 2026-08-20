# -*- coding: utf-8 -*-
"""
Hipotese "neighbors, half and double" (OP_RETURN do criador, 2021-07-18, tx do
endereco operacional 3GSMG24Tu... pagando 5000 sats a 4 enderecos-vizinhos).

Leitura: a privkey do premio = operacao aritmetica secp256k1 sobre os artefatos
da cadeia (half / better_half / blocos do chain4 / chain1[:32] / cc[833:865]):
  - double: 2*k mod n        - half: k * inv(2) mod n
  - neighbors: k +/- d       - pares: a+b, a-b, a^b (XOR), sha256(a||b)
Oraculo duro: O.check_privkey (endereco-premio ou h160-alvo). Secundos a minutos.
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O
import final_chain as FC

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order
INV2 = (N + 1) // 2  # inverso de 2 mod n

R = FC.reproduce()
ART = {
    "half": R["half"],
    "better_half": R["better_half"],
    "chain1_0_32": R["chain1"][:32],
    "chain2_0_32": R["chain2"][:32],
    "cc_833_865": R["cosmic"][833:865],
    "header32": R["chain4"][:32],
}
BLOCKS = [R["blocks"][i*32:(i+1)*32] for i in range(35)]

def i2b(x): return (x % N).to_bytes(32, "big")
def b2i(b): return int.from_bytes(b, "big")

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_work", "neighbors_attack.jsonl")
log = open(OUT, "w", encoding="utf-8")
hits, tested = [], 0

def test(label, priv32):
    global tested
    tested += 1
    r = O.check_privkey(priv32)
    rec = {"label": label, "hit": bool(r)}
    log.write(json.dumps(rec) + "\n")
    if r:
        hits.append((label, r)); print("!!! HIT", label, r)

# --- Fato 0: relacao half/double entre os artefatos? ---
h, bh = b2i(ART["half"]), b2i(ART["better_half"])
print("better_half == 2*half mod n? ", (2*h) % N == bh)
print("half == 2*better_half mod n? ", (2*bh) % N == h)
print("half + better_half mod n =", i2b(h+bh).hex()[:16], "...")

# --- A) half/double/neighbors sobre cada artefato-base ---
DELTAS = list(range(1, 10001)) + [101, 163, 227, 1141, 140, 38, 103, 570, 91, 1327, 1151]
for name, b in ART.items():
    k = b2i(b)
    test(f"{name}", b)
    test(f"{name}*2", i2b(2*k))
    test(f"{name}/2", i2b(k*INV2))
    for d in set(DELTAS):
        test(f"{name}+{d}", i2b(k+d))
        test(f"{name}-{d}", i2b(k-d))
        test(f"{name}*2+{d}", i2b(2*k+d))
        test(f"{name}/2+{d}", i2b(k*INV2+d))

# --- B) pares half/better_half ---
test("half+better_half", i2b(h+bh))
test("half-better_half", i2b(h-bh))
test("better_half-half", i2b(bh-h))
test("(half+better_half)/2", i2b((h+bh)*INV2))
test("(half+better_half)*2", i2b(2*(h+bh)))
test("half^better_half", bytes(x^y for x, y in zip(ART["half"], ART["better_half"])))
test("sha256(half||bh)", hashlib.sha256(ART["half"]+ART["better_half"]).digest())
test("sha256(bh||half)", hashlib.sha256(ART["better_half"]+ART["half"]).digest())
test("sha256(half||bh||tail)", hashlib.sha256(ART["half"]+ART["better_half"]+R["matrix_tail"]).digest())
for d in range(1, 1001):
    test(f"(h+bh)+{d}", i2b(h+bh+d)); test(f"(h+bh)-{d}", i2b(h+bh-d))
    test(f"(h^bh)+{d}", i2b(b2i(bytes(x^y for x,y in zip(ART['half'],ART['better_half'])))+d))

# --- C) pares de blocos do chain4 (soma/diff/double), "neighbors" = blocos adjacentes ---
for i, bi in enumerate(BLOCKS):
    ki = b2i(bi)
    test(f"block{i}*2", i2b(2*ki)); test(f"block{i}/2", i2b(ki*INV2))
    if i+1 < len(BLOCKS):
        kj = b2i(BLOCKS[i+1])
        test(f"block{i}+block{i+1}", i2b(ki+kj))
        test(f"block{i}^block{i+1}", bytes(x^y for x,y in zip(bi, BLOCKS[i+1])))
for i in range(len(BLOCKS)):
    for j in range(i+1, len(BLOCKS)):
        test(f"block{i}+block{j}", i2b(b2i(BLOCKS[i])+b2i(BLOCKS[j])))

# --- D) half/better_half combinados com cada bloco ---
for i, bi in enumerate(BLOCKS):
    ki = b2i(bi)
    test(f"half+block{i}", i2b(h+ki))
    test(f"bh+block{i}", i2b(bh+ki))
    test(f"half^block{i}", bytes(x^y for x,y in zip(ART["half"], bi)))
    test(f"bh^block{i}", bytes(x^y for x,y in zip(ART["better_half"], bi)))

# --- E) h160 dos 4 enderecos "neighbors" da tx de 2021-07-18 (informativo) ---
import base58
NEIGH = ["1G1kRAFR68y6CUq1SAJMzHmjd6sEEgtVUT", "16eEXbSuKN8tvcos1iKjdju6dAaWWRBMEs",
         "1KHMK2C8uBptRz67FbrXy43yHzhZG16Hbm", "1PhXF3xVQ8Sg9FomBcmRwRbvvGfm3Y2os1"]
def h160_of(addr):
    raw = base58.b58decode(addr)
    return int.from_bytes(raw[1:21], "big")
prize_h = int(O.TARGET_H160, 16)
print("\n--- h160 analysis (informativo) ---")
print("prize h160:", hex(prize_h))
for a in NEIGH:
    v = h160_of(a)
    rel = []
    if (2*v) % (1<<160) == prize_h: rel.append("DOUBLE")
    if (v*INV2) % (1<<160) == prize_h: rel.append("HALF")
    print(f"{a}: h160={hex(v)[:18]}... diff_prize={v-prize_h:+#x}"[:100], rel)

log.close()
print(f"\ntestados: {tested}, HITS: {len(hits)}")
print("=== VEREDITO ===")
print(f"ABRIU! {hits}" if hits else "neighbors/half-and-double -> NEGATIVO (oraculo duro).")
