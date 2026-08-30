# -*- coding: utf-8 -*-
"""Hipoteses camada 2: saida Bifid como chave, 7 passwords das fases, cifras alternativas."""
from __future__ import annotations
import hashlib, os, sys, struct, base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
from search import bifid_decrypt

from coincurve import PublicKey
from Crypto.Cipher import AES, DES3, DES, ARC4, ChaCha20
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


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def evp(pw: bytes, salt: bytes, hmod, klen=32, ivlen=16):
    d = b""; prev = b""
    while len(d) < klen + ivlen:
        prev = hmod.new(prev + pw + salt).digest()
        d += prev
    return d[:klen], d[klen:klen + ivlen]


def scan_privkey(data: bytes, label: str, hard: list):
    """Escaneia todas janelas de 32 bytes em data buscando a privkey."""
    for i in range(0, len(data) - 31):
        if matches_pubkey(data[i:i+32]):
            hard.append({"label": f"{label}/off{i}", "priv": data[i:i+32].hex()})


def scan_privkey_aligned(data: bytes, label: str, hard: list):
    """Escaneia janelas alinhadas em 16 bytes."""
    for i in range(0, len(data) - 31, 16):
        if matches_pubkey(data[i:i+32]):
            hard.append({"label": f"{label}/off{i}", "priv": data[i:i+32].hex()})


def main():
    R = F.reproduce()
    header = R["header"]
    header28 = header[2:30]
    body = R["blocks"]
    blocks = [body[i*32:(i+1)*32] for i in range(35)]
    half = R["half"]
    bh = R["better_half"]
    tail = R["matrix_tail"]
    cosmic = R["cosmic"]
    chain4_blob = R["chain4_blob"]
    salt_c4 = chain4_blob[8:16]

    hard = []
    soft = []
    n = 0

    # ====== A. Saida Bifid e suas decodificacoes ======
    src = O.sources()
    faed = src["faed"].upper().replace("J", "I")
    bif = bifid_decrypt(faed, CANON_ALPHA, 570)
    print(f"Bifid output (570): {bif[:40]}... (len={len(bif)})")
    rest = bif[7:]  # apos "BTCSEED"
    print(f"BIF_REST: {rest[:40]}... (len={len(rest)})")

    # A1. BIF_REST como hex (cada letra -> numero)
    # A-Z -> 0-25, agrupar como hex
    for offset in [0, 2, 4]:
        # converter letras para numeros 0-25 e tentar como bytes
        nums = [ord(c) - ord('A') for c in rest]
        # base 26 -> inteiro -> bytes
        big_int = 0
        for num in nums:
            big_int = big_int * 26 + num
        try:
            key_bytes = big_int.to_bytes(32, "big")
            if matches_pubkey(key_bytes):
                hard.append({"label": "bif_rest_base26->32B", "priv": key_bytes.hex()})
            # sha256
            sha = hashlib.sha256(key_bytes).digest()
            if matches_pubkey(sha):
                hard.append({"label": "sha256(bif_rest_base26)", "priv": sha.hex()})
        except OverflowError:
            # dividir em chunks de ~55 letras (26^55 > 2^256)
            chunk_size = 55
            for ci in range(0, len(nums) - chunk_size + 1):
                chunk = nums[ci:ci+chunk_size]
                val = 0
                for num in chunk:
                    val = val * 26 + num
                try:
                    kb = val.to_bytes(32, "big")
                    if matches_pubkey(kb):
                        hard.append({"label": f"bif_rest_base26_chunk{ci}", "priv": kb.hex()})
                except OverflowError:
                    pass

    # A2. BIF_REST mod 9 -> base 9 -> bytes
    nums9 = [(ord(c) - ord('A')) % 9 for c in rest]
    big_int = 0
    for num in nums9:
        big_int = big_int * 9 + num
    try:
        key_bytes = big_int.to_bytes(32, "big")
        if matches_pubkey(key_bytes):
            hard.append({"label": "bif_rest_base9->32B", "priv": key_bytes.hex()})
        scan_privkey(key_bytes + b"\x00"*32, "bif_rest_base9", hard)
    except OverflowError:
        chunk_size = 81  # 9^81 > 2^256
        for ci in range(0, len(nums9) - chunk_size + 1, 10):
            chunk = nums9[ci:ci+chunk_size]
            val = 0
            for num in chunk:
                val = val * 9 + num
            try:
                kb = val.to_bytes(32, "big")
                if matches_pubkey(kb):
                    hard.append({"label": f"bif_rest_base9_chunk{ci}", "priv": kb.hex()})
            except OverflowError:
                pass

    # A3. BIF_REST como WIF (base58) -- pegar substring que decodifica
    for start in range(0, min(60, len(rest))):
        for length in [44, 51, 52]:
            if start + length > len(rest):
                break
            substr = rest[start:start+length]
            try:
                import base58
                decoded = base58.b58decode(substr)
                if len(decoded) >= 33:
                    # possivel WIF: 0x80 + 32 bytes + 4 checksum
                    if decoded[0] == 0x80:
                        priv = decoded[1:33]
                        if matches_pubkey(priv):
                            hard.append({"label": f"bif_rest_WIF(off{start})", "priv": priv.hex()})
            except Exception:
                pass

    # A4. BIF como AES key (diversas fatias de 32 bytes)
    for i in range(0, len(bif) - 31):
        chunk = bif[i:i+32].encode("latin-1")
        if matches_pubkey(chunk):
            hard.append({"label": f"bif_raw32(off{i})", "priv": chunk.hex()})
    # SHA256 de fatias
    for i in range(0, len(bif) - 31, 8):
        chunk = bif[i:i+32].encode("latin-1")
        sha = hashlib.sha256(chunk).digest()
        if matches_pubkey(sha):
            hard.append({"label": f"sha256(bif_slice32_off{i})", "priv": sha.hex()})

    # A5. BIF_REST convertido de A-Z para a-i (base 9 original) -> Bifid novamente
    # BIF_REST usa 25 letras; converter para base 9 e aplicar Bifid com outro quadrado
    bif_rest_alpha = rest  # A-Z sem J
    # converter cada letra para 0-24, depois mod 9 -> a-i
    ai_map = "abcdefghi"
    ai_str = "".join(ai_map[(ord(c) - ord('A')) % 9] for c in bif_rest_alpha)
    # Bifid no ai_str com varios quadrados
    for kw in ["DBIFHCEGA", "ABCDEFGHI", "HALFBETTE", "MATRIXHAS", "YINYANGSA"]:
        square = kw + "".join(c for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ" if c not in kw.upper().replace("J", "I"))[:25-len(kw)]
        if len(square) == 25:
            for per in [570, 285, 563, 190, 114, 95, 57, 38, 13, 7]:
                try:
                    pt2 = bifid_decrypt(ai_str.upper().replace("J", "I"), square, per)
                    scan_privkey(pt2.encode("latin-1"), f"bif2_{kw[:6]}_p{per}", hard)
                    sha = hashlib.sha256(pt2.encode("latin-1")).digest()
                    if matches_pubkey(sha):
                        hard.append({"label": f"sha256(bif2_{kw[:6]}_p{per})", "priv": sha.hex()})
                except Exception:
                    pass

    # ====== B. 7 passwords das fases do puzzle ======
    SEVEN_PASSWORDS = [
        b"causality",
        b"Safenet",
        b"Luna",
        b"HSM",
        b"11110",
        bytes.fromhex("736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"),
        b"B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
    ]

    # B1. SHA256 de cada password -> descriptografar grupo de 5 blocos
    for i, pw in enumerate(SEVEN_PASSWORDS):
        key = hashlib.sha256(pw).digest()
        group = blocks[i*5:(i+1)*5]
        group_data = b"".join(group)
        # ECB
        try:
            plains = [AES.new(key, AES.MODE_ECB).decrypt(blk) for blk in group]
            joined = b"".join(plains)
            scan_privkey_aligned(joined, f"7pw_sha256_ecb_g{i}", hard)
            if valid_pt(joined):
                soft.append({"label": f"7pw_sha256_ecb_g{i}", "head": joined[:80].hex()})
        except ValueError:
            pass
        # CBC IV=0
        try:
            iv = b"\x00" * 16
            plains = [AES.new(key, AES.MODE_CBC, iv).decrypt(blk) for blk in group]
            joined = b"".join(plains)
            scan_privkey_aligned(joined, f"7pw_sha256_cbc_g{i}", hard)
        except ValueError:
            pass

    # B2. Os 7 SHA256 XORed -> chave unica
    seven_hashes = [hashlib.sha256(pw).digest() for pw in SEVEN_PASSWORDS]
    xor_key = bytes(32)
    for h in seven_hashes:
        xor_key = xor_bytes(xor_key, h)
    if matches_pubkey(xor_key):
        hard.append({"label": "7pw_sha256_xor", "priv": xor_key.hex()})
    # testar como AES key nos 35 blocos
    for mode_name, mode_fn in [("ECB", lambda k, b: AES.new(k, AES.MODE_ECB).decrypt(b)),
                                ("CBC0", lambda k, b: AES.new(k, AES.MODE_CBC, b"\x00"*16).decrypt(b))]:
        try:
            plains = [mode_fn(xor_key, blk) for blk in blocks]
            joined = b"".join(plains)
            scan_privkey_aligned(joined, f"7pw_xor_{mode_name}", hard)
            if valid_pt(joined):
                soft.append({"label": f"7pw_xor_{mode_name}", "head": joined[:80].hex()})
        except ValueError:
            pass

    # B3. Concatenacao dos 7 SHA256 (224 bytes) -> SHA256 -> chave
    concat_hash = hashlib.sha256(b"".join(seven_hashes)).digest()
    if matches_pubkey(concat_hash):
        hard.append({"label": "sha256(7pw_concat)", "priv": concat_hash.hex()})

    # B4. Cada password como passphrase EVP -> descriptografar grupo de 5
    for i, pw in enumerate(SEVEN_PASSWORDS):
        group = blocks[i*5:(i+1)*5]
        group_data = b"".join(group)
        for hmod in (MD5, SHA256):
            for salt in [salt_c4, b"\x00"*8, b"7"*8]:
                k, iv = evp(pw, salt, hmod)
                try:
                    pt = AES.new(k, AES.MODE_CBC, iv).decrypt(group_data)
                    scan_privkey_aligned(pt, f"7pw_evp_g{i}_{hmod.__name__}", hard)
                    if valid_pt(pt):
                        soft.append({"label": f"7pw_evp_g{i}_{hmod.__name__}", "head": pt[:80].hex()})
                except ValueError:
                    pass

    # ====== C. Cifras alternativas (DES, 3DES, RC4, ChaCha20) ======
    # C1. DES3 com header28[:24] como chave
    try:
        k24 = header28[:24]
        cipher = DES3.new(k24, DES3.MODE_ECB)
        plains = [cipher.decrypt(blk[:24] + b"\x00"*8) for blk in blocks]  # DES3 block=8
        # na verdade DES3 block = 8 bytes, cada bloco de 32 = 4 blocos DES3
        plains2 = []
        for blk in blocks:
            p = b""
            for j in range(0, 32, 8):
                p += cipher.decrypt(blk[j:j+8])
            plains2.append(p)
        joined = b"".join(plains2)
        scan_privkey_aligned(joined, "3des_header28_ecb", hard)
    except Exception:
        pass

    # C2. RC4 com varias chaves
    for key_name, key in [("+-7", b"+-7"), ("header28", header28), ("half", half),
                           ("bh", bh), ("7", b"7"), ("enter", b"enter")]:
        cipher = ARC4.new(key)
        pt = cipher.decrypt(body)
        scan_privkey(pt, f"rc4_{key_name}", hard)
        if valid_pt(pt) or b"Salted__" in pt:
            soft.append({"label": f"rc4_{key_name}", "head": pt[:80].hex()})

    # C3. XOR simples com byte 0x07
    xored = bytes(b ^ 0x07 for b in body)
    scan_privkey(xored, "xor_0x07", hard)
    # XOR com 7 repetido (32 bytes)
    xored7 = bytes(body[i] ^ 7 for i in range(len(body)))
    scan_privkey(xored7, "xor_7_all", hard)
    # XOR com "+-" repetido
    key_pm = (b"+-" * 560)[:len(body)]
    xored_pm = bytes(a ^ b for a, b in zip(body, key_pm))
    scan_privkey(xored_pm, "xor_+-_cycle", hard)

    # C4. ChaCha20 com header28 como key+nonce
    try:
        key32 = header28 + b"\x00\x00\x00\x00"
        nonce = b"\x00" * 12
        cipher = ChaCha20.new(key=key32, nonce=nonce)
        pt = cipher.decrypt(body)
        scan_privkey(pt, "chacha20_header28", hard)
    except Exception:
        pass

    # ====== D. BIF_REST / BIF como passphrase para AES dos 35 blocos ======
    for bif_key_name, bif_key in [("bif_full", bif), ("bif_rest", rest), ("btcseed", bif[:7])]:
        for hmod in (MD5, SHA256):
            for salt in [salt_c4, b"\x00"*8]:
                k, iv = evp(bif_key.encode("latin-1"), salt, hmod)
                try:
                    pt = AES.new(k, AES.MODE_CBC, iv).decrypt(body)
                    scan_privkey_aligned(pt, f"evp_{bif_key_name}_{hmod.__name__}", hard)
                    if valid_pt(pt) or b"Salted__" in pt:
                        soft.append({"label": f"evp_{bif_key_name}_{hmod.__name__}", "head": pt[:80].hex()})
                except ValueError:
                    pass
                # ECB
                try:
                    plains = [AES.new(k, AES.MODE_ECB).decrypt(blk) for blk in blocks]
                    joined = b"".join(plains)
                    scan_privkey_aligned(joined, f"evp_ecb_{bif_key_name}_{hmod.__name__}", hard)
                    if valid_pt(joined) or b"Salted__" in joined:
                        soft.append({"label": f"evp_ecb_{bif_key_name}_{hmod.__name__}", "head": joined[:80].hex()})
                except ValueError:
                    pass

    # ====== E. Reversed blocks ======
    for i, blk in enumerate(blocks):
        rev = blk[::-1]
        if matches_pubkey(rev):
            hard.append({"label": f"block{i}_reversed", "priv": rev.hex()})
        # swap endianness (4-byte words)
        swapped = b"".join(blk[j:j+4][::-1] for j in range(0, 32, 4))
        if matches_pubkey(swapped):
            hard.append({"label": f"block{i}_wordswap", "priv": swapped.hex()})

    # ====== F. SHA256 de cada bloco como privkey ======
    for i, blk in enumerate(blocks):
        h = hashlib.sha256(blk).digest()
        if matches_pubkey(h):
            hard.append({"label": f"sha256(block{i})", "priv": h.hex()})
        h2 = hashlib.sha256(h).digest()
        if matches_pubkey(h2):
            hard.append({"label": f"dblsha256(block{i})", "priv": h2.hex()})

    # ====== G. matrix bits como fonte de chave ======
    # A matriz 14x14 como bits row-major -> SHA256
    matrix_bits = "".join([
        "00110100101100", "11110011101011", "11011101001001", "0110100011101",
        "01100011000110", "1001100010011", "10011100010000", "11100000001000",
        "00011101111101", "11111100110001", "11010000101101", "11110010101100",
        "01011101001110", "01101101101011"
    ])
    # como bytes (bits -> bytes)
    matrix_bytes = int(matrix_bits, 2).to_bytes((len(matrix_bits) + 7) // 8, "big")
    sha_matrix = hashlib.sha256(matrix_bytes).digest()
    if matches_pubkey(sha_matrix):
        hard.append({"label": "sha256(matrix_bits_bytes)", "priv": sha_matrix.hex()})
    sha_matrix_str = hashlib.sha256(matrix_bits.encode()).digest()
    if matches_pubkey(sha_matrix_str):
        hard.append({"label": "sha256(matrix_bits_str)", "priv": sha_matrix_str.hex()})
    # matriz como AES key
    for iv in [b"\x00"*16, header28[:16], half[:16]]:
        try:
            pt = AES.new(sha_matrix, AES.MODE_CBC, iv).decrypt(body)
            scan_privkey_aligned(pt, "sha_matrix_aes", hard)
        except ValueError:
            pass

    # ====== H. "half and better half" = concatenar as duas como 64 bytes, pegar fatias ======
    concat_hbh = half + bh  # 64 bytes
    for i in range(33):
        slice_32 = concat_hbh[i:i+32]
        if len(slice_32) == 32 and matches_pubkey(slice_32):
            hard.append({"label": f"half+bh_slice{i}", "priv": slice_32.hex()})
    # SHA256 de cada metade da concatenacao
    for i in range(33):
        s = hashlib.sha256(concat_hbh[i:i+32]).digest()
        if matches_pubkey(s):
            hard.append({"label": f"sha256(half+bh_slice{i})", "priv": s.hex()})

    # ====== I. 35 blocos como 7 grupos de 5, descriptografar cada grupo com half/bh alternado ======
    for key_name, key in [("half", half), ("bh", bh)]:
        for gi in range(7):
            group = blocks[gi*5:(gi+1)*5]
            group_data = b"".join(group)
            try:
                pt = AES.new(key, AES.MODE_ECB).decrypt(group_data)
                scan_privkey_aligned(pt, f"{key_name}_ecb_g{gi}", hard)
                if valid_pt(pt):
                    soft.append({"label": f"{key_name}_ecb_g{gi}", "head": pt[:80].hex()})
            except ValueError:
                pass

    # ====== Relatorio ======
    print("=" * 60)
    print("HIPOTESES CAMADA 2 - oraculo duro")
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
        print("NEGATIVO — todas as hipoteses camada 2 falharam no oraculo.")


if __name__ == "__main__":
    main()
