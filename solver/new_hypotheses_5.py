# -*- coding: utf-8 -*-
"""Camada 5: ordens de leitura dos 35 blocos - transposta, diagonal, strides."""
from __future__ import annotations
import hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")


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


def try_key(label, key, body, hard, soft, use_aes=True):
    """Testa uma chave de 32 bytes como privkey e como AES key."""
    if len(key) != 32:
        return
    if matches_pubkey(key):
        hard.append({"label": label, "priv": key.hex()})
    sha = hashlib.sha256(key).digest()
    if matches_pubkey(sha):
        hard.append({"label": f"sha256({label})", "priv": sha.hex()})
    if use_aes:
        for iv_name, iv in [("zero", b"\x00"*16)]:
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
                if valid_pt(pt) or b"Salted__" in pt:
                    soft.append({"label": f"{label}_aes", "head": pt[:80].hex()})
                for j in range(0, len(pt)-31, 16):
                    if matches_pubkey(pt[j:j+32]):
                        hard.append({"label": f"{label}_aes_off{j}", "priv": pt[j:j+32].hex()})
            except ValueError:
                pass


def main():
    R = F.reproduce()
    header = R["header"]
    header28 = header[2:30]
    body = R["blocks"]
    blocks = [body[i*32:(i+1)*32] for i in range(35)]
    full_blob = header + body  # 1151 bytes
    half = R["half"]
    bh = R["better_half"]

    hard = []
    soft = []

    # ====== A. Transposta: coluna j dos blocos ======
    # col j = [block[0][j], block[1][j], ..., block[34][j]] — 35 bytes
    # pegar subsets de 32:
    for j in range(32):
        col_full = bytes(block[j] for block in blocks)  # 35 bytes
        # primeiros 32
        try_key(f"col{j}_b0_31", col_full[:32], body, hard, soft)
        # ultimos 32 (blocos 3-34)
        try_key(f"col{j}_b3_34", col_full[3:], body, hard, soft)
        # blocos 0-31 pulando o header? blocos 2-33
        try_key(f"col{j}_b2_33", col_full[2:34], body, hard, soft)

    # ====== B. Diagonal ======
    # diagonal: block[i][i mod 32] para i=0..34 — 35 bytes, pegar 32
    diag = bytes(blocks[i][i % 32] for i in range(35))
    try_key("diag_b0_31", diag[:32], body, hard, soft)
    try_key("diag_b3_34", diag[3:], body, hard, soft)
    # anti-diagonal: block[i][31 - (i mod 32)]
    anti = bytes(blocks[i][31 - (i % 32)] for i in range(35))
    try_key("anti_b0_31", anti[:32], body, hard, soft)
    try_key("anti_b3_34", anti[3:], body, hard, soft)

    # ====== C. Strides no blob completo ======
    # cada stride-th byte do body (1120 bytes)
    for stride in [35, 33, 34, 36, 37, 7, 5, 23, 16, 17, 19]:
        seq = body[::stride]
        if len(seq) >= 32:
            try_key(f"stride{stride}_start0", seq[:32], body, hard, soft)
        # com offsets
        for off in range(1, min(stride, 8)):
            seq = body[off::stride]
            if len(seq) >= 32:
                try_key(f"stride{stride}_off{off}", seq[:32], body, hard, soft)

    # ====== D. Strides no blob completo (header + body = 1151) ======
    for stride in [35, 32, 36, 7, 23, 16]:
        for off in range(0, min(stride, 4)):
            seq = full_blob[off::stride]
            if len(seq) >= 32:
                try_key(f"fullstride{stride}_off{off}", seq[:32], body, hard, soft)

    # ====== E. Bytes nas posicoes indicadas pelo header ======
    # header28 (28 bytes) + '7' como indices no body
    # header[i] mod 1120 como posicao
    positions = [b % 1120 for b in header28]
    # completar para 32 posicoes com o '7' e derivados
    for extra in [3, 5, 7, 11, 13, 17, 19, 23]:
        pos32 = positions + [(7 * extra) % 1120, (7 + extra) % 1120, (extra * 35) % 1120, (extra * 32) % 1120]
        key = bytes(body[p] for p in pos32[:32])
        try_key(f"hdrpos_x{extra}", key, body, hard, soft)

    # ====== F. Interleave bytes dos blocos ======
    # pegar byte 0 do bloco 0, byte 0 do bloco 1, ..., byte 0 do bloco 31, byte 1 do bloco 0, ...
    # = coluna j (ja testado acima)
    # diferente: pegar byte 0 do bloco 0, byte 1 do bloco 0, byte 0 do bloco 1, byte 1 do bloco 1, ...
    # = interleaving de pares
    for group_size in [2, 4, 7, 8]:
        inter = b""
        for byte_pos in range(32):
            for blk_idx in range(0, 35, group_size):
                if len(inter) >= 32:
                    break
                if blk_idx < 35:
                    inter += bytes([blocks[blk_idx][byte_pos]])
            if len(inter) >= 32:
                break
        try_key(f"interleave_g{group_size}", inter[:32], body, hard, soft)

    # ====== G. Reversed ======
    body_rev = body[::-1]
    try_key("body_rev32", body_rev[:32], body, hard, soft)
    # blocos em ordem reversa, primeiro bloco
    try_key("block34_rev", blocks[34][::-1], body, hard, soft)
    try_key("block34", blocks[34], body, hard, soft)
    # blob completo reversed
    full_rev = full_blob[::-1]
    try_key("full_rev32", full_rev[:32], body, hard, soft)

    # ====== H. Cada bloco como chave para o PROXIMO bloco ======
    for i in range(34):
        try:
            pt = AES.new(blocks[i], AES.MODE_ECB).decrypt(blocks[i+1])
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"blk2blk_{i}", "head": pt[:48].hex()})
            if matches_pubkey(pt):
                hard.append({"label": f"blk2blk_{i}_priv", "priv": pt.hex()})
        except ValueError:
            pass
    # bloco 34 como chave para bloco 0
    try:
        pt = AES.new(blocks[34], AES.MODE_ECB).decrypt(blocks[0])
        if valid_pt(pt) or b"Salted__" in pt:
            soft.append({"label": "blk34_2_blk0", "head": pt[:48].hex()})
        if matches_pubkey(pt):
            hard.append({"label": "blk34_2_blk0_priv", "priv": pt.hex()})
    except ValueError:
        pass

    # ====== I. Primeiros 32 primos como bytes ======
    primes32 = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131]
    key_primes = bytes(primes32)
    try_key("first32primes", key_primes, body, hard, soft)
    # primeiros 7 primos repetidos
    primes7 = bytes([2,3,5,7,11,13,17])
    try_key("7primes_x4+4", primes7*4 + primes7[:4], body, hard, soft)
    # 23 primos
    primes23 = bytes(primes32[:23])
    try_key("23primes+pad", primes23 + b"\x00"*9, body, hard, soft)
    try_key("23primes+9s", primes23 + b"\x09"*9, body, hard, soft)
    # 16 primos x2
    primes16 = bytes(primes32[:16])
    try_key("16primes_x2", primes16*2, body, hard, soft)

    # SHA256 de varias concatenacoes de primos
    prime_strs = [
        "23571113171923",  # digitos concatenados
        "2,3,5,7,11,13,17,19,23",
        "2 3 5 7 11 13 17 19 23",
        "2357111317",
        "2357111317192329313741",
        "123571113171923",
        "73571113171923",
    ]
    for ps in prime_strs:
        sha = hashlib.sha256(ps.encode()).digest()
        if matches_pubkey(sha):
            hard.append({"label": f"sha256({ps})", "priv": sha.hex()})
        try_key(f"sha256p_{ps[:8]}", sha, body, hard, soft)

    # ====== J. Key = header28 + padding variado ======
    paddings = [
        b"\x00" * 3,
        b"\x07" * 3,
        b"\x37" * 3,  # '7'
        b"\xff" * 3,
        b"7\x00\x00",
        b"\x00\x007",
        b"\x00\x007",
        b"7  ",
        b"   ",
        b"\x2b\x2d\x37",  # "+-7"
        b"\x37\x2b\x2d",  # "7+-"
        b"+-7",
        b"7+-",
        b"\x00\x00\x00",
        b"\x01\x02\x03",
        b"\x03\x02\x01",
    ]
    for pad in paddings:
        key = header28 + pad
        try_key(f"hdr28+{pad[:3].hex()}", key, body, hard, soft)
        # tambem pad antes
        key2 = pad + header28
        try_key(f"{pad[:3].hex()}+hdr28", key2, body, hard, soft)

    # ====== K. Key = '+-' + header28 + '7' estendido ======
    prefix31 = header  # 2b2d + header28 + 37
    # prefix31 e 31 bytes; completar para 32
    for pad in [b"\x00", b"\x07", b"\x37", b"\xff", b"\x2b", b"\x2d", b"7", b" ", b"\x01"]:
        key = prefix31 + pad
        try_key(f"p31+{pad.hex()}", key, body, hard, soft)
        key2 = pad + prefix31
        try_key(f"{pad.hex()}+p31", key2, body, hard, soft)
    # sha256 do prefix31
    sha_p31 = hashlib.sha256(prefix31).digest()
    try_key("sha256(p31)", sha_p31, body, hard, soft)
    # ja testado antes, mas com pad
    for extra in [b"7", b"0", b"\x00", b" ", b"1"]:
        sha = hashlib.sha256(prefix31 + extra).digest()
        try_key(f"sha256(p31+{extra.hex()})", sha, body, hard, soft)

    # ====== L. XOR de colunas (32 colunas de 35 bytes) ======
    # para cada subset de blocos, XOR das colunas
    subsets = {
        "prime_idx": [2,3,5,7,11,13,17,19,23,29,31],
        "mult5": [0,5,10,15,20,25,30],
        "mult7": [0,7,14,21,28],
        "first7": [0,1,2,3,4,5,6],
        "last7": [28,29,30,31,32,33,34],
        "sym": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17],  # 18 blocos, pegar 32 bytes? nao
    }
    for name, idxs in subsets.items():
        if len(idxs) >= 1:
            # XOR dos blocos selecionados — 32 bytes
            x = bytes(32)
            for i in idxs:
                x = xor_bytes(x, blocks[i])
            try_key(f"xor_{name}", x, body, hard, soft)
            # soma
            t = 0
            for i in idxs:
                t = (t + int.from_bytes(blocks[i], "big")) % (1 << 256)
            try_key(f"add_{name}", t.to_bytes(32, "big"), body, hard, soft)

    # ====== M. Grupos de 5 blocos (7 grupos) — combinacoes ======
    # 7 grupos de 5: XOR de cada grupo (32 bytes cada), depois combinar os 7 resultados
    group_xors = []
    for g in range(7):
        grp = blocks[g*5:(g+1)*5]
        x = bytes(32)
        for b in grp:
            x = xor_bytes(x, b)
        group_xors.append(x)
    # XOR dos 7 group-xors
    x7 = bytes(32)
    for gx in group_xors:
        x7 = xor_bytes(x7, gx)
    try_key("xor_7groups", x7, body, hard, soft)
    # concatenar primeiros ~4.5 bytes de cada group-xor (7*4=28, +4 = 32)
    concat = b""
    for gx in group_xors:
        concat += gx[:4]  # 7*4=28 bytes
    concat += group_xors[0][:4]  # +4 = 32
    try_key("concat4of7", concat, body, hard, soft)
    # 7 bytes de cada: 7*7=49 > 32; primeiros 32
    concat7 = b""
    for gx in group_xors:
        concat7 += gx[:7]  # 49 bytes
    try_key("concat7of7_32", concat7[:32], body, hard, soft)
    try_key("concat7of7_last", concat7[17:], body, hard, soft)  # 49-17=32

    # ====== N. Grupos de 7 blocos (5 grupos) ======
    group7_xors = []
    for g in range(5):
        grp = blocks[g*7:(g+1)*7]
        x = bytes(32)
        for b in grp:
            x = xor_bytes(x, b)
        group7_xors.append(x)
    x5 = bytes(32)
    for gx in group7_xors:
        x5 = xor_bytes(x5, gx)
    try_key("xor_5groups7", x5, body, hard, soft)
    # concatenar 6 bytes de cada: 5*6=30, +2
    concat6 = b""
    for gx in group7_xors:
        concat6 += gx[:6]  # 30 bytes
    concat6 += group7_xors[0][:2]  # 32
    try_key("concat6of5", concat6, body, hard, soft)
    # 7 bytes de cada: 5*7=35, primeiros 32
    concat7b = b""
    for gx in group7_xors:
        concat7b += gx[:7]  # 35 bytes
    try_key("concat7of5_32", concat7b[:32], body, hard, soft)
    try_key("concat7of5_last", concat7b[3:], body, hard, soft)  # 35-3=32

    # ====== O. Bit operations: rotacoes do body ======
    # rotacionar body por N bits e pegar 32 bytes
    for rot_bits in [7, 1, 3, 5, 8, 16, 32]:
        # converter body para inteiro e rotacionar
        val = int.from_bytes(body[:64], "big")  # primeiros 64 bytes para caber
        rotated = ((val << rot_bits) | (val >> (512 - rot_bits))) & ((1 << 512) - 1)
        rot_bytes = rotated.to_bytes(64, "big")
        try_key(f"rot{rot_bits}_0_31", rot_bytes[:32], body, hard, soft)
        try_key(f"rot{rot_bits}_32_63", rot_bytes[32:], body, hard, soft)

    # ====== P. 7th byte de cada bloco ======
    seventh = bytes(block[6] for block in blocks)  # 35 bytes
    try_key("7th_byte_b0_31", seventh[:32], body, hard, soft)
    try_key("7th_byte_b3_34", seventh[3:], body, hard, soft)
    # 7th from end
    seventh_end = bytes(block[-7] for block in blocks)
    try_key("7th_end_b0_31", seventh_end[:32], body, hard, soft)

    # ====== Q. Byte 23 de cada bloco ======
    byte23 = bytes(block[22] for block in blocks)
    try_key("byte23_b0_31", byte23[:32], body, hard, soft)
    # byte 16
    byte16 = bytes(block[15] for block in blocks)
    try_key("byte16_b0_31", byte16[:32], body, hard, soft)

    # ====== R. Header como indices de BLOCOS ======
    # header28[i] mod 35 seleciona bloco, pegar 1 byte especifico
    for byte_pos in [0, 7, 16, 23, 31, 6, 22]:
        sel = bytes(blocks[header28[i] % 35][byte_pos] for i in range(28))
        # completar com mais 4 bytes
        for extra_src in ["hdr0", "hdr1", "seven", "zero"]:
            if extra_src == "hdr0":
                extra = bytes([header28[0]] * 4)
            elif extra_src == "seven":
                extra = bytes([7] * 4)
            else:
                extra = b"\x00" * 4
            key = sel + extra
            try_key(f"hdrsel_bp{byte_pos}_{extra_src}", key, body, hard, soft)

    # ====== Relatorio ======
    print("=" * 60)
    print("HIPOTESES CAMADA 5 - ordens de leitura")
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
        print("NEGATIVO — todas as hipoteses camada 5 falharam no oraculo.")
        # debug: imprimir colunas
        col0 = bytes(block[0] for block in blocks)
        print(f"\ncol0[:32]: {col0[:32].hex()}")
        col7 = bytes(block[7] for block in blocks)
        print(f"col7[:32]: {col7[:32].hex()}")
        diag = bytes(blocks[i][i % 32] for i in range(35))
        print(f"diag[:32]: {diag[:32].hex()}")


if __name__ == "__main__":
    main()
