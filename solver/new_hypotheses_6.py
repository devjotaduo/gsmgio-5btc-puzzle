# -*- coding: utf-8 -*-
"""Camada 6: header28 como 7 senhas entrelaçadas (7 uint32) para 7 grupos de 5 blocos.
Interpretacao literal de 'seven intertwined passwords': cada palavra de 4 bytes do header
e uma 'senha' (via EVP_BytesToKey ou SHA256) que abre um grupo de 5 blocos."""
from __future__ import annotations
import hashlib, os, sys, struct

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
    return pr(d[:-p]) >= 0.80


def evp_kdf(password: bytes, salt: bytes, keylen=32, ivlen=16):
    d = d_i = b""
    while len(d) < keylen + ivlen:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:keylen], d[keylen:keylen+ivlen]


def main():
    R = F.reproduce()
    header = R["header"]
    header28 = header[2:30]
    body = R["blocks"]
    blocks = [body[i*32:(i+1)*32] for i in range(35)]
    half = R["half"]
    bh = R["better_half"]

    hard, soft = [], []

    # 7 palavras de 4 bytes do header28
    words = [header28[i*4:(i+1)*4] for i in range(7)]
    print("7 palavras do header28:")
    for i, w in enumerate(words):
        print(f"  w{i+1} = {w.hex()} = {struct.unpack('>I', w)[0]}")

    # formas de derivar chave de cada palavra
    def key_forms(w: bytes, salt: bytes):
        forms = {}
        forms["sha256_raw"] = hashlib.sha256(w).digest()
        forms["sha256_hex"] = hashlib.sha256(w.hex().encode()).digest()
        forms["word_x8"] = w * 8  # 32 bytes
        k, iv = evp_kdf(w, salt)
        forms["evp_md5"] = k
        forms["sha256_dec"] = hashlib.sha256(str(struct.unpack('>I', w)[0]).encode()).digest()
        return forms

    salts = {
        "zero": b"\x00" * 8,
        "chain4": R["chain4_blob"][8:16],
        "hdr28_8": header28[:8],
        "hdr28_last8": header28[-8:],
        "sevens": b"\x07" * 8,
    }

    # ====== A. 7 grupos de 5 blocos, cada grupo com a senha da sua palavra ======
    for salt_name, salt in salts.items():
        for layout in ["contig", "roundrobin"]:
            groups = []
            if layout == "contig":
                for g in range(7):
                    groups.append([blocks[g*5 + j] for j in range(5)])
            else:
                for g in range(7):
                    groups.append([blocks[j*7 + g] for j in range(5)])
            for kform in ["sha256_raw", "sha256_hex", "word_x8", "evp_md5", "sha256_dec"]:
                ok_count = 0
                group_pts = []
                for g in range(7):
                    kf = key_forms(words[g], salt)[kform]
                    if len(kf) != 32:
                        continue
                    ct = b"".join(groups[g])
                    # CBC com IV zero
                    try:
                        pt = AES.new(kf, AES.MODE_CBC, b"\x00"*16).decrypt(ct)
                        if valid_pt(pt) or b"Salted__" in pt:
                            ok_count += 1
                            group_pts.append((g, pt[:48].hex()))
                        for j in range(0, len(pt)-31, 16):
                            if matches_pubkey(pt[j:j+32]):
                                hard.append({"label": f"7pw_{layout}_{kform}_{salt_name}_g{g}_off{j}", "priv": pt[j:j+32].hex()})
                    except ValueError:
                        pass
                    # ECB
                    try:
                        pt_ecb = AES.new(kf, AES.MODE_ECB).decrypt(ct)
                        if valid_pt(pt_ecb) or b"Salted__" in pt_ecb:
                            ok_count += 1
                            group_pts.append((g, "ecb:" + pt_ecb[:48].hex()))
                        for j in range(0, len(pt_ecb)-31, 16):
                            if matches_pubkey(pt_ecb[j:j+32]):
                                hard.append({"label": f"7pw_{layout}_{kform}_{salt_name}_ecb_g{g}_off{j}", "priv": pt_ecb[j:j+32].hex()})
                    except ValueError:
                        pass
                if ok_count >= 3:
                    soft.append({"label": f"7pw_{layout}_{kform}_{salt_name}", "ok": ok_count, "pts": group_pts[:3]})

    # ====== B. palavra g como senha do bloco g (35 blocos, ciclando 7 palavras) ======
    for salt_name, salt in salts.items():
        for kform in ["sha256_raw", "evp_md5", "word_x8"]:
            hits = 0
            for i in range(35):
                w = words[i % 7]
                kf = key_forms(w, salt)[kform]
                if len(kf) != 32:
                    continue
                blk = blocks[i]
                try:
                    pt = AES.new(kf, AES.MODE_ECB).decrypt(blk)
                    if valid_pt(pt) or b"Salted__" in pt:
                        hits += 1
                        soft.append({"label": f"blk{i}_w{i%7}_{kform}_{salt_name}", "pt": pt[:32].hex()})
                    if matches_pubkey(pt):
                        hard.append({"label": f"blk{i}_w{i%7}_{kform}_{salt_name}_priv", "priv": pt.hex()})
                except ValueError:
                    pass

    # ====== C. as 7 palavras concatenadas = chave de 28 bytes + algo ======
    for pad in [b"\x00"*4, b"\x07"*4, b"\x37"*4, words[0], b"+-7!", b"\x2b\x2d\x37\x00"]:
        key28 = header28 + pad
        if matches_pubkey(key28):
            hard.append({"label": f"hdr28+{pad.hex()}", "priv": key28.hex()})
        try:
            pt = AES.new(key28, AES.MODE_CBC, b"\x00"*16).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"hdr28+{pad.hex()}_aes", "head": pt[:80].hex()})
            for j in range(0, len(pt)-31, 16):
                if matches_pubkey(pt[j:j+32]):
                    hard.append({"label": f"hdr28+{pad.hex()}_aes_off{j}", "priv": pt[j:j+32].hex()})
        except ValueError:
            pass

    # ====== D. cada palavra como uint32 -> escalar secp256k1 ======
    for i, w in enumerate(words):
        val = struct.unpack('>I', w)[0]
        if 0 < val < N:
            key = val.to_bytes(32, "big")
            if matches_pubkey(key):
                hard.append({"label": f"w{i+1}_scalar", "priv": key.hex()})
        # palavra repetida 8x como privkey
        key8 = w * 8
        if matches_pubkey(key8):
            hard.append({"label": f"w{i+1}_x8_priv", "priv": key8.hex()})

    # ====== E. 23 blocos (0-22) + 16 bytes de IV + 7 palavras: composicao ======
    # pegar os primeiros 23 blocos, XOR com as 7 palavras ciclando
    sel23 = blocks[:23]
    for mode in ["xor_cycle", "add_cycle"]:
        result = b""
        for i, blk in enumerate(sel23):
            w = words[i % 7]
            if mode == "xor_cycle":
                w32 = (w * 8)
                result += bytes(a ^ b for a, b in zip(blk, w32))
            else:
                result += bytes((a + b) % 256 for a, b in zip(blk, w * 8))
        # primeiros 32 bytes como privkey
        if matches_pubkey(result[:32]):
            hard.append({"label": f"23blk_{mode}", "priv": result[:32].hex()})
        # como AES key para o body inteiro
        try:
            pt = AES.new(result[:32], AES.MODE_CBC, b"\x00"*16).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"23blk_{mode}_aes", "head": pt[:80].hex()})
        except ValueError:
            pass

    # ====== F. "16 encryptions": decifrar body 16x com chaves rotativas das 7 palavras ======
    # key muda a cada round: words[round % 7] sha256
    for start_word in range(7):
        pt = body
        for rnd in range(16):
            kf = hashlib.sha256(words[(start_word + rnd) % 7]).digest()
            try:
                pt = AES.new(kf, AES.MODE_ECB).decrypt(pt)
            except ValueError:
                break
        if valid_pt(pt) or b"Salted__" in pt:
            soft.append({"label": f"16x_rot7_start{start_word}", "head": pt[:80].hex()})
        for j in range(0, len(pt)-31, 16):
            if matches_pubkey(pt[j:j+32]):
                hard.append({"label": f"16x_rot7_start{start_word}_off{j}", "priv": pt[j:j+32].hex()})

    # ====== G. body decifrado com key = sha256 de CADA palavra, concatenadas ======
    # sha256(w1)+sha256(w2)+... seria 7*32=224 bytes; pegar primeiros 32
    concat_sha = b"".join(hashlib.sha256(w).digest() for w in words)
    if matches_pubkey(concat_sha[:32]):
        hard.append({"label": "concat7sha", "priv": concat_sha[:32].hex()})
    try:
        pt = AES.new(concat_sha[:32], AES.MODE_CBC, b"\x00"*16).decrypt(body)
        if valid_pt(pt) or b"Salted__" in pt:
            soft.append({"label": "concat7sha_aes", "head": pt[:80].hex()})
    except ValueError:
        pass
    # XOR dos 7 sha256
    x = bytes(32)
    for w in words:
        x = bytes(a ^ b for a, b in zip(x, hashlib.sha256(w).digest()))
    if matches_pubkey(x):
        hard.append({"label": "xor7sha", "priv": x.hex()})
    try:
        pt = AES.new(x, AES.MODE_CBC, b"\x00"*16).decrypt(body)
        if valid_pt(pt) or b"Salted__" in pt:
            soft.append({"label": "xor7sha_aes", "head": pt[:80].hex()})
    except ValueError:
        pass

    # ====== Relatorio ======
    print()
    print("=" * 60)
    print("HIPOTESES CAMADA 6 - 7 senhas entrelacadas (header words)")
    print("=" * 60)
    print(f"HARD hits: {len(hard)}")
    print(f"SOFT hits: {len(soft)}")
    if hard:
        print("\n!!! SOLVE !!!")
        for h in hard:
            print(f"  {h}")
    if soft:
        print("\n--- soft hits ---")
        for s in soft[:20]:
            print(f"  {s}")
    if not hard and not soft:
        print("NEGATIVO — todas as hipoteses camada 6 falharam no oraculo.")


if __name__ == "__main__":
    main()
