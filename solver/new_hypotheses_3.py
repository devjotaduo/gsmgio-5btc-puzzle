# -*- coding: utf-8 -*-
"""Camada 3: encodings binarios/base-N do Bifid output + Bifid encrypt + mais hipoteses."""
from __future__ import annotations
import hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
from search import bifid_decrypt

from coincurve import PublicKey
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
CANON_ALPHA = "DBIFHCEGAKLMNOPQRSTUVWXYZ"


def matches_pubkey(s: bytes) -> bool:
    if len(s) != 32 or not any(s):
        return False
    try:
        return PublicKey.from_valid_secret(s).format(compressed=False) == TARGET_PUBKEY
    except ValueError:
        return False


def pr(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data)


def valid_pt(d: bytes) -> bool:
    if not d or len(d) % 16:
        return False
    p = d[-1]
    if not 1 <= p <= 16 or not d.endswith(bytes([p]) * p):
        return False
    body = d[:-p]
    return bool(body) and pr(body) >= 0.80


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def baseN_to_bytes(chars: str, base: int, alpha_order: str) -> bytes:
    """Converte string em base-N (usando alpha_order como ordem dos digitos) para 32 bytes."""
    val = 0
    for c in chars:
        d = alpha_order.index(c)
        val = val * base + d
    # reduzir mod 2^256 se muito grande
    val = val % (1 << 256)
    return val.to_bytes(32, "big")


def baseN_to_bytes_modn(chars: str, base: int, alpha_order: str) -> bytes:
    val = 0
    for c in chars:
        d = alpha_order.index(c)
        val = val * base + d
    val = val % N
    return val.to_bytes(32, "big")


def bifid_encrypt(pt, square, period):
    """Encrypt do Bifid (inverso do decrypt)."""
    pos = {c: (i // 5, i % 5) for i, c in enumerate(square)}
    out = []
    for off in range(0, len(pt), period):
        blk = pt[off:off + period]
        seq = []
        for c in blk:
            r, co = pos[c]
            seq += [r, co]
        n = len(blk)
        rows, cols = seq[0::2], seq[1::2]  # intercalar
        # encrypt: coordenadas intercaladas primeiro, depois lidas em pares
        inter = []
        for i in range(n):
            inter += [rows[i], cols[i]]
        # ler em pares como (row, col) da primeira metade e segunda metade
        half = len(inter) // 2
        first, second = inter[:half], inter[half:]
        for i in range(len(second)):
            out.append(square[first[i] * 5 + second[i]])
    return "".join(out)


def main():
    R = F.reproduce()
    header = R["header"]
    header28 = header[2:30]
    body = R["blocks"]
    blocks = [body[i*32:(i+1)*32] for i in range(35)]
    half = R["half"]
    bh = R["better_half"]
    cosmic = R["cosmic"]
    chain4_blob = R["chain4_blob"]
    salt_c4 = chain4_blob[8:16]

    hard = []
    soft = []

    src = O.sources()
    faed = src["faed"].upper().replace("J", "I")
    bif = bifid_decrypt(faed, CANON_ALPHA, 570)
    rest = bif[7:]

    # ====== A. Encodings binarios do BIF_REST ======
    # A1. A-M=0, N-Z=1 (primeira metade do alfabeto = 0)
    for name, func in [
        ("A-M=0,N-Z=1", lambda c: 0 if c < 'N' else 1),
        ("A-M=1,N-Z=0", lambda c: 1 if c < 'N' else 0),
        ("A-I=0,K-Z=1", lambda c: 0 if c < 'K' else 1),
        ("A-I=1,K-Z=0", lambda c: 1 if c < 'K' else 0),
        ("vowel=0,cons=1", lambda c: 0 if c in "AEIOU" else 1),
        ("vowel=1,cons=0", lambda c: 1 if c in "AEIOU" else 0),
    ]:
        # comecando de varios offsets apos BTCSEED
        for start in range(0, min(100, len(rest) - 256), 8):
            bits = "".join(str(func(c)) for c in rest[start:start+256])
            key = int(bits, 2).to_bytes(32, "big")
            if matches_pubkey(key):
                hard.append({"label": f"bin_{name}_off{start}", "priv": key.hex()})
            # SHA256 do key como outra chave
            sha = hashlib.sha256(key).digest()
            if matches_pubkey(sha):
                hard.append({"label": f"sha256(bin_{name}_off{start})", "priv": sha.hex()})

    # A2. Base-25 (alfabeto Bifid: A-Z sem J) do BIF_REST
    alpha25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # sem J
    for start in range(0, min(60, len(rest) - 55), 5):
        chunk = rest[start:start+55]
        # garantir que todos os chars estao no alfabeto
        if all(c in alpha25 for c in chunk):
            key = baseN_to_bytes(chunk, 25, alpha25)
            if matches_pubkey(key):
                hard.append({"label": f"b25_off{start}", "priv": key.hex()})
            key_n = baseN_to_bytes_modn(chunk, 25, alpha25)
            if matches_pubkey(key_n):
                hard.append({"label": f"b25n_off{start}", "priv": key_n.hex()})
            sha = hashlib.sha256(key).digest()
            if matches_pubkey(sha):
                hard.append({"label": f"sha256(b25_off{start})", "priv": sha.hex()})

    # A3. Base-25 do BIF inteiro (incluindo BTCSEED)
    for start in range(0, min(60, len(bif) - 55), 5):
        chunk = bif[start:start+55]
        if all(c in alpha25 for c in chunk):
            key = baseN_to_bytes(chunk, 25, alpha25)
            if matches_pubkey(key):
                hard.append({"label": f"b25full_off{start}", "priv": key.hex()})

    # A4. Coordenadas do quadrado Bifid (base 5) do BIF_REST
    pos_map = {c: (i // 5, i % 5) for i, c in enumerate(CANON_ALPHA)}
    coords = []
    for c in bif:
        r, co = pos_map[c]
        coords.extend([r, co])
    # 570 chars -> 1140 coordenadas (base 5)
    # 256 bits em base 5: ~110 digitos
    for start in range(0, min(200, len(coords) - 110), 10):
        chunk = coords[start:start+110]
        val = 0
        for d in chunk:
            val = val * 5 + d
        val = val % (1 << 256)
        key = val.to_bytes(32, "big")
        if matches_pubkey(key):
            hard.append({"label": f"coords_b5_off{start}", "priv": key.hex()})
        # tambem mod N
        val_n = val % N
        key_n = val_n.to_bytes(32, "big")
        if matches_pubkey(key_n):
            hard.append({"label": f"coords_b5n_off{start}", "priv": key_n.hex()})

    # ====== B. Bifid ENCRYPT (nao decrypt) ======
    for period in [570, 285, 190, 114, 95, 57, 38, 13, 7, 5]:
        try:
            enc = bifid_encrypt(faed, CANON_ALPHA, period)
            # escanar por privkey
            for i in range(0, len(enc) - 31):
                chunk = enc[i:i+32].encode("latin-1")
                if matches_pubkey(chunk):
                    hard.append({"label": f"bif_enc_p{period}_off{i}", "priv": chunk.hex()})
            # sha256 do output
            sha = hashlib.sha256(enc.encode("latin-1")).digest()
            if matches_pubkey(sha):
                hard.append({"label": f"sha256(bif_enc_p{period})", "priv": sha.hex()})
            # sha256 como AES key
            for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
                try:
                    pt = AES.new(sha, AES.MODE_CBC, iv).decrypt(body)
                    if valid_pt(pt) or b"Salted__" in pt:
                        soft.append({"label": f"bif_enc_p{period}_aes_{iv_name}", "head": pt[:80].hex()})
                    for j in range(0, len(pt)-31, 16):
                        if matches_pubkey(pt[j:j+32]):
                            hard.append({"label": f"bif_enc_p{period}_aes_off{j}", "priv": pt[j:j+32].hex()})
                except ValueError:
                    pass
        except Exception:
            pass

    # ====== C. Primes como indices para selecionar blocos -> AES key ======
    primes_11 = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    sel = [blocks[i] for i in primes_11]
    xor_sel = bytes(32)
    for b in sel:
        xor_sel = xor_bytes(xor_sel, b)
    # testar como AES key
    for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16]), ("half", half[:16])]:
        try:
            pt = AES.new(xor_sel, AES.MODE_CBC, iv).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"prime_xor_aes_{iv_name}", "head": pt[:80].hex()})
            for j in range(0, len(pt)-31, 16):
                if matches_pubkey(pt[j:j+32]):
                    hard.append({"label": f"prime_xor_aes_{iv_name}_off{j}", "priv": pt[j:j+32].hex()})
        except ValueError:
            pass
    # soma mod 2^256
    t = 0
    for b in sel:
        t = (t + int.from_bytes(b, "big")) % (1 << 256)
    add_sel = t.to_bytes(32, "big")
    if matches_pubkey(add_sel):
        hard.append({"label": "prime_add", "priv": add_sel.hex()})
    for iv_name, iv in [("zero", b"\x00"*16)]:
        try:
            pt = AES.new(add_sel, AES.MODE_CBC, iv).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"prime_add_aes_{iv_name}", "head": pt[:80].hex()})
        except ValueError:
            pass

    # ====== D. 7 primeiros primos (2,3,5,7,11,13,17) -> 7 blocos -> combinar ======
    primes_7 = [2, 3, 5, 7, 11, 13, 17]
    sel7 = [blocks[i] for i in primes_7]
    xor7 = bytes(32)
    for b in sel7:
        xor7 = xor_bytes(xor7, b)
    if matches_pubkey(xor7):
        hard.append({"label": "7primes_xor", "priv": xor7.hex()})
    for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
        try:
            pt = AES.new(xor7, AES.MODE_CBC, iv).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"7primes_xor_aes_{iv_name}", "head": pt[:80].hex()})
            for j in range(0, len(pt)-31, 16):
                if matches_pubkey(pt[j:j+32]):
                    hard.append({"label": f"7primes_xor_aes_off{j}", "priv": pt[j:j+32].hex()})
        except ValueError:
            pass

    # ====== E. Interleave das 7 partes da fase 3 ======
    parts7 = [
        "causality", "Safenet", "Luna", "HSM", "11110",
        "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
        "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
    ]
    # interleave character by character
    max_len = max(len(p) for p in parts7)
    interleaved = ""
    for i in range(max_len):
        for p in parts7:
            if i < len(p):
                interleaved += p[i]
    sha_il = hashlib.sha256(interleaved.encode()).digest()
    if matches_pubkey(sha_il):
        hard.append({"label": "sha256(7parts_interleaved)", "priv": sha_il.hex()})
    for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
        try:
            pt = AES.new(sha_il, AES.MODE_CBC, iv).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"7parts_il_aes_{iv_name}", "head": pt[:80].hex()})
        except ValueError:
            pass

    # ====== F. 16 rounds de AES (decifrar 16 vezes) ======
    # "sixteen encryptions" -> decifrar 16 vezes com a mesma chave
    for key_name, key in [("half", half), ("bh", bh), ("sha_matrix", hashlib.sha256(b"matrixsumlist").digest())]:
        pt = body
        for round_i in range(16):
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                pt = cipher.decrypt(pt)
            except ValueError:
                break
        if valid_pt(pt) or b"Salted__" in pt:
            soft.append({"label": f"16x_aes_{key_name}", "head": pt[:80].hex()})
        for j in range(0, len(pt)-31, 16):
            if matches_pubkey(pt[j:j+32]):
                hard.append({"label": f"16x_aes_{key_name}_off{j}", "priv": pt[j:j+32].hex()})

    # ====== G. SHA256 de half+bh em varias combinacoes ======
    combos = [
        ("sha256(half+bh)", hashlib.sha256(half + bh).digest()),
        ("sha256(bh+half)", hashlib.sha256(bh + half).digest()),
        ("sha256(half^bh)", hashlib.sha256(xor_bytes(half, bh)).digest()),
        ("sha256(half-bh)", hashlib.sha256(bytes((a-b) % 256 for a, b in zip(half, bh))).digest()),
        ("sha256(half+bh_bytewise)", hashlib.sha256(bytes((a+b) % 256 for a, b in zip(half, bh))).digest()),
    ]
    for name, key in combos:
        if matches_pubkey(key):
            hard.append({"label": name, "priv": key.hex()})
        for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
                if valid_pt(pt) or b"Salted__" in pt:
                    soft.append({"label": f"{name}_aes_{iv_name}", "head": pt[:80].hex()})
                for j in range(0, len(pt)-31, 16):
                    if matches_pubkey(pt[j:j+32]):
                        hard.append({"label": f"{name}_aes_off{j}", "priv": pt[j:j+32].hex()})
            except ValueError:
                pass
            # ECB por bloco
            try:
                plains = [AES.new(key, AES.MODE_ECB).decrypt(blk) for blk in blocks]
                joined = b"".join(plains)
                if valid_pt(joined) or b"Salted__" in joined:
                    soft.append({"label": f"{name}_ecb", "head": joined[:80].hex()})
                for j in range(0, len(joined)-31, 16):
                    if matches_pubkey(joined[j:j+32]):
                        hard.append({"label": f"{name}_ecb_off{j}", "priv": joined[j:j+32].hex()})
            except ValueError:
                pass

    # ====== H. Half/better_half escalares +/-/x/^ combinados (todos como privkey + AES) ======
    h_int = int.from_bytes(half, "big")
    bh_int = int.from_bytes(bh, "big")
    scalar_combos = [
        ("h+bh", (h_int + bh_int) % N),
        ("h-bh", (h_int - bh_int) % N),
        ("bh-h", (bh_int - h_int) % N),
        ("h*bh", (h_int * bh_int) % N),
        ("h^bh_int", (h_int ^ bh_int)),
        ("h<<7", (h_int << 7) % N),
        ("bh<<7", (bh_int << 7) % N),
        ("h>>7", h_int >> 7),
        ("bh>>7", bh_int >> 7),
        ("h*7", (h_int * 7) % N),
        ("bh*7", (bh_int * 7) % N),
        ("h+7", (h_int + 7) % N),
        ("bh+7", (bh_int + 7) % N),
        ("h-bh+7", (h_int - bh_int + 7) % N),
        ("h+bh+7", (h_int + bh_int + 7) % N),
    ]
    for name, val in scalar_combos:
        if 0 < val < N:
            key = val.to_bytes(32, "big")
            if matches_pubkey(key):
                hard.append({"label": f"scalar_{name}", "priv": key.hex()})
            sha = hashlib.sha256(key).digest()
            if matches_pubkey(sha):
                hard.append({"label": f"sha256(scalar_{name})", "priv": sha.hex()})
            # como AES key
            for iv_name, iv in [("zero", b"\x00"*16)]:
                try:
                    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
                    if valid_pt(pt) or b"Salted__" in pt:
                        soft.append({"label": f"scalar_{name}_aes", "head": pt[:80].hex()})
                except ValueError:
                    pass

    # ====== I. Chave derivada da matriz 14x14 (matrixsumlist row/col sums) ======
    row_sums = [6, 10, 8, 7, 6, 6, 5, 4, 9, 9, 7, 8, 7, 9]
    col_sums = [8, 10, 8, 10, 8, 7, 3, 6, 7, 5, 9, 6, 6, 8]
    # row_sums como keystream AES (14 bytes -> expandir para 32)
    row_str = bytes(row_sums)
    col_str = bytes(col_sums)
    combos_k = [
        ("row_sums_x2+101", row_str * 2 + bytes([101])),
        ("col_sums_x2+101", col_str * 2 + bytes([101])),
        ("row+col", row_str + col_str + row_str[:4]),
        ("sha256(row_sums)", hashlib.sha256(row_str).digest()),
        ("sha256(col_sums)", hashlib.sha256(col_str).digest()),
        ("sha256(row+col)", hashlib.sha256(row_str + col_str).digest()),
        ("sha256(101)", hashlib.sha256(b"101").digest()),
    ]
    for name, key in combos_k:
        if len(key) == 32:
            if matches_pubkey(key):
                hard.append({"label": name, "priv": key.hex()})
            for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
                try:
                    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
                    if valid_pt(pt) or b"Salted__" in pt:
                        soft.append({"label": f"{name}_aes_{iv_name}", "head": pt[:80].hex()})
                    for j in range(0, len(pt)-31, 16):
                        if matches_pubkey(pt[j:j+32]):
                            hard.append({"label": f"{name}_aes_off{j}", "priv": pt[j:j+32].hex()})
                except ValueError:
                    pass

    # ====== Relatorio ======
    print("=" * 60)
    print("HIPOTESES CAMADA 3 - oraculo duro")
    print("=" * 60)
    print(f"HARD hits: {len(hard)}")
    print(f"SOFT hits: {len(soft)}")
    if hard:
        print("\n!!! SOLVE !!!")
        for h in hard:
            print(f"  {h}")
    if soft:
        print("\n--- soft hits ---")
        for s in soft:
            print(f"  {s}")
    if not hard and not soft:
        print("NEGATIVO — todas as hipoteses camada 3 falharam no oraculo.")
        # imprimir alguns valores para debug
        print(f"\nBifid encrypt p570 (primeiros 60): {bifid_encrypt(faed, CANON_ALPHA, 570)[:60]}")


if __name__ == "__main__":
    main()
