# -*- coding: utf-8 -*-
"""Camada 4: Bifid encrypt CORRETO, BTCSEED como senha, decodificacoes extras."""
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


def bifid_encrypt_correct(pt, square, period):
    """Bifid encryption CORRETA: coords em duas linhas (rows/cols), lidas como pares consecutivos."""
    pos = {c: (i // 5, i % 5) for i, c in enumerate(square)}
    out = []
    for off in range(0, len(pt), period):
        blk = pt[off:off + period]
        n = len(blk)
        rows, cols = [], []
        for c in blk:
            r, co = pos[c]
            rows.append(r)
            cols.append(co)
        combined = rows + cols
        for i in range(n):
            out.append(square[combined[2*i] * 5 + combined[2*i + 1]])
    return "".join(out)


def evp_decrypt(data: bytes, password: bytes) -> bytes | None:
    """OpenSSL EVP_BytesToKey + AES-256-CBC."""
    if len(data) < 32 or data[:8] != b"Salted__":
        return None
    salt = data[8:16]
    d = d_i = b""
    while len(d) < 48:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    key, iv = d[:32], d[32:48]
    try:
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data[16:])
        p = pt[-1]
        if 1 <= p <= 16 and pt.endswith(bytes([p]) * p):
            return pt[:-p]
    except ValueError:
        pass
    return None


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

    # ====== A. Bifid ENCRYPT correto de faed ======
    print("Bifid ENCRYPT correto de faed:")
    for period in [570, 285, 190, 114, 95, 57, 38, 19, 13, 7, 5, 3, 1]:
        try:
            enc = bifid_encrypt_correct(faed, CANON_ALPHA, period)
            printable = sum(c.isalpha() for c in enc) / len(enc) if enc else 0
            # escanear por privkey
            for i in range(0, len(enc) - 31):
                chunk = enc[i:i+32].encode("latin-1")
                if matches_pubkey(chunk):
                    hard.append({"label": f"bif_enc_p{period}_off{i}", "priv": chunk.hex()})
            # sha256 como key/privkey
            sha = hashlib.sha256(enc.encode("latin-1")).digest()
            if matches_pubkey(sha):
                hard.append({"label": f"sha256(bif_enc_p{period})", "priv": sha.hex()})
            # como AES key para os blocos
            for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
                try:
                    pt = AES.new(sha, AES.MODE_CBC, iv).decrypt(body)
                    if valid_pt(pt) or b"Salted__" in pt:
                        soft.append({"label": f"bif_enc_p{period}_aes_{iv_name}", "head": pt[:80].hex()})
                    for j in range(0, len(pt)-31, 16):
                        if matches_pubkey(pt[j:j+32]):
                            hard.append({"label": f"bif_enc_p{period}_aes_{iv_name}_off{j}", "priv": pt[j:j+32].hex()})
                except ValueError:
                    pass
            if period in [570, 7, 5]:
                print(f"  p={period}: {enc[:60]}... (alpha_ratio={printable:.2f})")
        except Exception as e:
            print(f"  p={period}: ERRO {e}")

    # ====== B. Bifid DECRYPT de novo (double decrypt) ======
    print("\nDouble Bifid decrypt:")
    bif2 = bifid_decrypt(bif, CANON_ALPHA, 570)
    print(f"  bif2[:60]: {bif2[:60]}")
    # escanear
    for i in range(0, len(bif2) - 31):
        chunk = bif2[i:i+32].encode("latin-1")
        if matches_pubkey(chunk):
            hard.append({"label": f"bif2_off{i}", "priv": chunk.hex()})
    sha_bif2 = hashlib.sha256(bif2.encode("latin-1")).digest()
    if matches_pubkey(sha_bif2):
        hard.append({"label": "sha256(bif2)", "priv": sha_bif2.hex()})
    for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
        try:
            pt = AES.new(sha_bif2, AES.MODE_CBC, iv).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"bif2_aes_{iv_name}", "head": pt[:80].hex()})
            for j in range(0, len(pt)-31, 16):
                if matches_pubkey(pt[j:j+32]):
                    hard.append({"label": f"bif2_aes_{iv_name}_off{j}", "priv": pt[j:j+32].hex()})
        except ValueError:
            pass

    # bif3 (triple)
    bif3 = bifid_decrypt(bif2, CANON_ALPHA, 570)
    print(f"  bif3[:60]: {bif3[:60]}")
    for i in range(0, len(bif3) - 31):
        chunk = bif3[i:i+32].encode("latin-1")
        if matches_pubkey(chunk):
            hard.append({"label": f"bif3_off{i}", "priv": chunk.hex()})

    # ====== C. "BTCSEED" como password ======
    pw_candidates = [
        b"BTCSEED",
        b"btcseed",
        b"BTCSEED" + rest[:100].encode("latin-1"),
        rest[:100].encode("latin-1"),
        rest.encode("latin-1"),
        bif.encode("latin-1"),
        b"BTC SEED",
        b"btc seed",
        b"BTCSeed",
    ]
    print("\nBTCSEED e variantes como senha:")
    for pw in pw_candidates:
        # direto como privkey (se 32 bytes)
        if len(pw) == 32 and matches_pubkey(pw):
            hard.append({"label": f"direct_{pw[:10]}", "priv": pw.hex()})
        # sha256 como privkey
        sha = hashlib.sha256(pw).digest()
        if matches_pubkey(sha):
            hard.append({"label": f"sha256({pw[:10]}...)", "priv": sha.hex()})
        # como AES key (zero IV e header IV)
        for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
            try:
                pt = AES.new(sha, AES.MODE_CBC, iv).decrypt(body)
                if valid_pt(pt) or b"Salted__" in pt:
                    soft.append({"label": f"sha256({pw[:10]}...)_aes_{iv_name}", "head": pt[:80].hex()})
                for j in range(0, len(pt)-31, 16):
                    if matches_pubkey(pt[j:j+32]):
                        hard.append({"label": f"sha256({pw[:10]}...)_aes_off{j}", "priv": pt[j:j+32].hex()})
            except ValueError:
                pass
        # EVP (OpenSSL) no chain4_blob
        result = evp_decrypt(chain4_blob, pw)
        if result:
            soft.append({"label": f"evp_{pw[:10]}", "head": result[:80]})

    # ====== D. Chain4_blob como se fosse "Salted__" ======
    # ja testado, mas com senha "BTCSEED" e variantes
    for pw_name, pw in [
        ("BTCSEED", b"BTCSEED"),
        ("matrixsumlist", b"matrixsumlist"),
        ("bif_output", bif.encode("latin-1")),
        ("rest", rest.encode("latin-1")),
        ("half_hex", half.hex().encode()),
        ("bh_hex", bh.hex().encode()),
        ("header_hex", header.hex().encode()),
        ("header28_hex", header28.hex().encode()),
    ]:
        result = evp_decrypt(chain4_blob, pw)
        if result:
            soft.append({"label": f"evp_chain4_{pw_name}", "head": result[:80]})

    # ====== E. Blocos como BIP39 entropy (12/24 words) ======
    # BIP39: 128 bits = 12 words, 256 bits = 24 words
    # cada bloco 32 bytes = 256 bits = 24 words + 8 bits checksum
    from oracles import check_mnemonic
    import binascii
    for i in range(35):
        # 24 words from full 32-byte block
        mn = O.check_mnemonic(blocks[i])
        if mn:
            soft.append({"label": f"bip39_block{i}", "mnemonic": mn})
        # 12 words from first 16 bytes
        mn12 = O.check_mnemonic(blocks[i][:16])
        if mn12:
            soft.append({"label": f"bip39_12w_block{i}", "mnemonic": mn12})

    # ====== F. XOR de TODOS os 35 blocos ======
    xor_all = bytes(32)
    for b in blocks:
        xor_all = xor_bytes(xor_all, b)
    if matches_pubkey(xor_all):
        hard.append({"label": "xor_all_35", "priv": xor_all.hex()})
    sha_xa = hashlib.sha256(xor_all).digest()
    if matches_pubkey(sha_xa):
        hard.append({"label": "sha256(xor_all)", "priv": sha_xa.hex()})
    for iv_name, iv in [("zero", b"\x00"*16), ("header", header28[:16])]:
        try:
            pt = AES.new(xor_all, AES.MODE_CBC, iv).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"xor_all_aes_{iv_name}", "head": pt[:80].hex()})
            for j in range(0, len(pt)-31, 16):
                if matches_pubkey(pt[j:j+32]):
                    hard.append({"label": f"xor_all_aes_off{j}", "priv": pt[j:j+32].hex()})
        except ValueError:
            pass
    # soma
    t = 0
    for b in blocks:
        t = (t + int.from_bytes(b, "big")) % (1 << 256)
    add_all = t.to_bytes(32, "big")
    if matches_pubkey(add_all):
        hard.append({"label": "sum_all_35", "priv": add_all.hex()})
    try:
        pt = AES.new(add_all, AES.MODE_CBC, b"\x00"*16).decrypt(body)
        if valid_pt(pt) or b"Salted__" in pt:
            soft.append({"label": "sum_all_aes", "head": pt[:80].hex()})
    except ValueError:
        pass

    # ====== G. Blocos em pares consecutivos XOR/ADD ======
    for i in range(34):
        x = xor_bytes(blocks[i], blocks[i+1])
        if matches_pubkey(x):
            hard.append({"label": f"xor_pair_{i}_{i+1}", "priv": x.hex()})
    # blocos em pares simetricos (0+34, 1+33, etc.)
    for i in range(17):
        x = xor_bytes(blocks[i], blocks[34-i])
        if matches_pubkey(x):
            hard.append({"label": f"xor_sym_{i}_{34-i}", "priv": x.hex()})
        s = (int.from_bytes(blocks[i], "big") + int.from_bytes(blocks[34-i], "big")) % (1 << 256)
        s_b = s.to_bytes(32, "big")
        if matches_pubkey(s_b):
            hard.append({"label": f"add_sym_{i}_{34-i}", "priv": s_b.hex()})

    # ====== Relatorio ======
    print()
    print("=" * 60)
    print("HIPOTESES CAMADA 4 - oraculo duro")
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
        print("NEGATIVO — todas as hipoteses camada 4 falharam no oraculo.")


if __name__ == "__main__":
    main()
