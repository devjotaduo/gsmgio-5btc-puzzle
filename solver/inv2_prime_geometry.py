# -*- coding: utf-8 -*-
"""INV2 — GEOMETRIA DO PRIMO 1327.

cc = plaintext Cosmic (1327 bytes, primo). 1327*8 = 10616 bits.
A comunidade forcou 103^2=10609 bits (leitura terminal, sobra 7 bits).
Aqui testamos leituras que respeitam a fatoracao real:
  10616 = 8*1327 (divisores: 1,2,4,8,1327,2654,5308,10616)
  1326  = 2*3*13*17 (grade de BYTES altamente composta, cc[:1326])

Cada leitura produz um fluxo de bytes; toda janela de 32B vira candidato a
privkey e passa pelo ORACULO DURO (alvo + espelho EC + endereco-premio,
comprimido e nao-comprimido). Alem disso `strong_oracle_35.scan` cobre
WIF/hex-ascii/BIP39 em todo offset de cada fluxo. Estrutura (Salted__, bytes do
alvo, ASCII, 1GSMG, WIF-prefix) tambem e reportada, nao so hits.
"""
import hashlib, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import strong_oracle_35 as S
from coincurve import PublicKey

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
X_T = TARGET[1:33]
Y_T = int.from_bytes(TARGET[33:65], "big")
MIRROR = b"\x04" + X_T + ((P - Y_T) % P).to_bytes(32, "big")
TARGET_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")  # = prize addr


def _h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def hard(sec: bytes):
    """32B -> privkey? bate alvo/espelho (pub) ou prize (h160 comp/unc)."""
    n = int.from_bytes(sec, "big")
    if n == 0 or n >= N:
        return None
    try:
        pk = PublicKey.from_valid_secret(sec)
    except Exception:
        return None
    unc = pk.format(False)
    if unc == TARGET:
        return "target-pub"
    if unc == MIRROR:
        return "mirror-pub"
    if _h160(unc) == TARGET_H160:
        return "prize-unc"
    if _h160(pk.format(True)) == TARGET_H160:
        return "prize-comp"
    return None


def scan_stream(stream: bytes, where: str, hits: list):
    """Oraculo duro em toda janela 32B + scan textual (WIF/hex/BIP39)."""
    for j in range(0, len(stream) - 31):
        r = hard(stream[j:j + 32])
        if r:
            hits.append((r, f"{where}@{j}", stream[j:j + 32].hex()))
    S.scan(stream, where, hits)  # WIF/hexpriv/BIP39/target-mirror em todo offset


# estrutura interessante (nao-hit) para reportar
_TARG_SUBS = [TARGET[i:i + 8] for i in range(0, 57, 8)] + [X_T[:8], X_T[-8:]]


def structure(stream: bytes, where: str, notes: list):
    for tag, pat in [("Salted__", b"Salted__"), ("1GSMG", b"1GSMG")]:
        i = stream.find(pat)
        if i >= 0:
            notes.append((where, tag, i))
    for sub in _TARG_SUBS:
        i = stream.find(sub)
        if i >= 0:
            notes.append((where, "target-bytes", i, sub.hex()))
    # maior run ASCII imprimivel
    best = cur = 0
    for b in stream:
        cur = cur + 1 if 32 <= b < 127 else 0
        best = max(best, cur)
    if best >= 20:
        notes.append((where, "ascii-run", best))


def main():
    R = F.reproduce()
    cc = R["cosmic"]
    assert len(cc) == 1327
    t0 = time.time()
    hits, notes = [], []
    reads = 0

    # ---- H1: bit-transpose (MSB-first), grades R*C=10616 ----
    bits = [(cc[i >> 3] >> (7 - (i & 7))) & 1 for i in range(10616)]

    def regroup(bitseq):
        return bytes(sum(bitseq[8 * k + j] << (7 - j) for j in range(8)) for k in range(1327))

    grids_bit = [(2, 5308), (4, 2654), (8, 1327), (1327, 8), (2654, 4), (5308, 2)]
    for Rr, Cc in grids_bit:
        colmajor = [bits[r * Cc + c] for c in range(Cc) for r in range(Rr)]
        stream = regroup(colmajor)
        for tag, s in [("fwd", stream), ("rev", stream[::-1])]:
            w = f"bitT:{Rr}x{Cc}:{tag}"
            scan_stream(s, w, hits); structure(s, w, notes); reads += 1

    # classicas tambem em LSB-first
    bits_lsb = [(cc[i >> 3] >> (i & 7)) & 1 for i in range(10616)]
    for Rr, Cc in [(8, 1327), (1327, 8)]:
        colmajor = [bits_lsb[r * Cc + c] for c in range(Cc) for r in range(Rr)]
        s = regroup(colmajor)
        w = f"bitT-lsb:{Rr}x{Cc}"
        scan_stream(s, w, hits); structure(s, w, notes); reads += 1

    # ---- H2: byte-transpose de 1326 = 2*3*13*17 ----
    B = cc[:1326]
    pairs = [(2, 663), (3, 442), (6, 221), (13, 102), (17, 78), (26, 51),
             (34, 39), (39, 34), (51, 26), (78, 17), (102, 13), (221, 6),
             (442, 3), (663, 2)]
    for Rr, Cc in pairs:
        s = bytes(B[r * Cc + c] for c in range(Cc) for r in range(Rr))  # column-major
        w = f"byteT:{Rr}x{Cc}"
        scan_stream(s, w, hits); structure(s, w, notes); reads += 1

    # diagonais quebradas nas grades quase-quadradas
    for Rr, Cc in [(34, 39), (39, 34)]:
        s = bytes(B[r * Cc + ((r + d) % Cc)] for d in range(Cc) for r in range(Rr))
        w = f"byteDiag:{Rr}x{Cc}"
        scan_stream(s, w, hits); structure(s, w, notes); reads += 1

    # ---- H3: 7 bits sobrando + numero 1327 como material ----
    leftover = 0
    for i in range(10609, 10616):
        leftover = (leftover << 1) | bits[i]           # 7 bits -> byte
    keys = {
        "x052F": bytes([0x05, 0x2F]),
        "x2F05": bytes([0x2F, 0x05]),
        "leftover": bytes([leftover]),
        "052F+left": bytes([0x05, 0x2F, leftover]),
    }
    for name, k in keys.items():
        s = bytes(b ^ k[i % len(k)] for i, b in enumerate(cc))
        w = f"xor:{name}"
        scan_stream(s, w, hits); structure(s, w, notes); reads += 1

    # ---- H4: cc como inteiro (base-256 fwd/rev mod N; base-38 digit-wise) ----
    def _int_reads():
        out = {}
        v = int.from_bytes(cc, "big")
        out["int256:modN"] = (v % N).to_bytes(32, "big")
        out["int256rev:modN"] = (int.from_bytes(cc[::-1], "big") % N).to_bytes(32, "big")
        # base-38 digit-wise (cada byte mod 38 -> digito; big number -> mod N)
        num = 0
        for b in cc:
            num = num * 38 + (b % 38)
        out["b38dw:modN"] = (num % N).to_bytes(32, "big")
        return out
    int_cands = _int_reads()
    for name, sec in int_cands.items():
        r = hard(sec)
        reads += 1
        if r:
            hits.append((r, f"intread:{name}", sec.hex()))

    dt = time.time() - t0
    log = os.path.join(os.path.dirname(__file__), "..", "_work",
                       "inv2_prime_geometry.jsonl")
    with open(log, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": "summary", "reads": reads,
                             "hits": len(hits), "notes": len(notes),
                             "seconds": round(dt, 1)}) + "\n")
        for h in hits:
            fh.write(json.dumps({"kind": "HIT", "data": h}) + "\n")
        for nt in notes:
            fh.write(json.dumps({"kind": "note", "data": nt}) + "\n")

    print(f"reads={reads} hits={len(hits)} notes={len(notes)} t={dt:.1f}s")
    for h in hits:
        print("HIT", h)
    # amostra de estrutura
    for nt in notes[:40]:
        print("note", nt)
    print("int-reads:", {k: v.hex()[:16] + "..." for k, v in int_cands.items()})
    return hits


if __name__ == "__main__":
    h = main()
    # self-check: hard() reconhece a privkey=1 (pub conhecido != alvo -> None)
    assert hard((1).to_bytes(32, "big")) is None
    # e reconhece formato: injeta pub alvo? nao temos priv; checa mecanica so.
    print("[selfcheck] hard(priv=1)->None OK; total HITs =", len(h))
