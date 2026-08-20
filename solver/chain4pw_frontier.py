# -*- coding: utf-8 -*-
"""Teste focal: a senha do Chain4 (32 bytes exatos) e a chave AES do Chain4
sao a chave do ULTIMO passo (os 35 blocos).

Motivacao literal: "our first hint is your last command" + "give away" +
"in front of your eyes". A senha/comando ja usado para abrir o Chain4 e
reusada como chave da ultima camada (35 blocos). A Chain4_PASSWORD =
E_C||E_S||E_B[:2] tem EXATAMENTE 32 bytes = AES-256.

Nunca testado antes (grep confirma: CHAIN4_PASSWORD so abre chain4, nunca
aplicada aos 35 blocos). Solve = matches_pubkey OU AES com padding valido
+ ascii/Salted__/pubkey-alvo.
"""
from __future__ import annotations
import hashlib, os, sys
from coincurve import PublicKey
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

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
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data) if data else 0.0


def valid_pt(d: bytes) -> bool:
    if not d or len(d) % 16:
        return False
    p = d[-1]
    return 1 <= p <= 16 and d.endswith(bytes([p]) * p) and pr(d[:-p]) >= 0.80


def main():
    R = F.reproduce()
    header = R["header"]; header28 = header[2:30]
    body = R["blocks"]
    blocks = [body[i*32:(i+1)*32] for i in range(35)]
    half, bh, tail = R["half"], R["better_half"], R["matrix_tail"]
    cosmic, c1, c2 = R["cosmic"], R["chain1"], R["chain2"]
    blob = R["chain4_blob"]
    salt_c4 = blob[8:16]

    # A chave AES-256 real que decifrou o chain4 (via EVP/MD5):
    k_real, iv_real = O._evp(F.CHAIN4_PASSWORD, salt_c4, MD5)
    # e via SHA256:
    k_real_s, iv_real_s = O._evp(F.CHAIN4_PASSWORD, salt_c4, SHA256)

    keys = {
        "CHAIN4_PASSWORD(32B)": F.CHAIN4_PASSWORD,
        "sha256(CHAIN4_PASSWORD)": hashlib.sha256(F.CHAIN4_PASSWORD).digest(),
        "sha256_hex(CHAIN4_PASSWORD)": hashlib.sha256(F.CHAIN4_PASSWORD).hexdigest().encode(),
        "chain4_key_EVP_MD5": k_real,
        "chain4_key_EVP_SHA256": k_real_s,
        "E_C=chain1[64:79]pad32": (c1[64:79] + b"\x00"*17)[:32],
        "E_S=chain2[64:79]pad32": (c2[64:79] + b"\x00"*17)[:32],
        "E_B=cosmic[64:66]pad32": (cosmic[64:66] + b"\x00"*30)[:32],
        "chain1[:32]": c1[:32],
        "chain2[:32]": c2[:32],
        "chain1[32:64]": c1[32:64],
        "chain2[32:64]": c2[32:64],
        "cosmic[:32]": cosmic[:32],
        "cosmic[32:64]": cosmic[32:64],
        "sha256(chain4_pt)": hashlib.sha256(R["chain4"]).digest(),
        "chain4[:32]": R["chain4"][:32],
        "chain4[31:63]": R["chain4"][31:63],
    }
    ivs = {
        "zero": b"\x00"*16, "iv_real_MD5": iv_real, "iv_real_SHA256": iv_real_s,
        "header16": header28[:16], "header28lo": header28[12:28],
        "half16": half[:16], "bh16": bh[:16], "tailpad": (tail*4)[:16],
        "sevenpad": b"7"*16, "sha7": hashlib.sha256(b"+-"+header28+b"7").digest()[:16],
        "salt_c4": salt_c4, "cosmic16": cosmic[:16],
    }

    hard = []; soft = []; top = []; n_aes = n_priv = 0
    for kn, key in keys.items():
        if len(key) != 32:
            continue
        if matches_pubkey(key):
            hard.append({"DIRECT": kn, "priv": key.hex()})
        # stream 1120 CBC
        for ivn, iv in ivs.items():
            try: pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError: continue
            n_aes += 1; r = pr(pt)
            top.append((r, f"{kn}/CBC-stream/{ivn}", pt[:32].hex()))
            if valid_pt(pt) or b"Salted__" in pt or TARGET_PUBKEY in pt:
                soft.append({"label": f"{kn}/CBC-stream/{ivn}", "ratio": round(r,4), "head": pt[:80].hex()})
            for i in range(0, len(pt)-31, 16):
                n_priv += 1
                if matches_pubkey(pt[i:i+32]):
                    hard.append({"label": f"{kn}/CBC-stream/{ivn}", "off": i, "priv": pt[i:i+32].hex()})
        # per-block CBC + ECB
        for ivn, iv in ivs.items():
            plains = []
            for blk in blocks:
                try: plains.append(AES.new(key, AES.MODE_CBC, iv).decrypt(blk))
                except ValueError: plains.append(b"")
            n_aes += 35; joined = b"".join(plains); r = pr(joined)
            top.append((r, f"{kn}/CBC-pb/{ivn}", joined[:32].hex()))
            if valid_pt(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
                soft.append({"label": f"{kn}/CBC-pb/{ivn}", "ratio": round(r,4), "head": joined[:80].hex()})
            for i, p in enumerate(plains):
                n_priv += 1
                if matches_pubkey(p):
                    hard.append({"label": f"{kn}/CBC-pb/{ivn}", "blk": i, "priv": p.hex()})
        plains = []
        for blk in blocks:
            try: plains.append(AES.new(key, AES.MODE_ECB).decrypt(blk))
            except ValueError: plains.append(b"")
        n_aes += 35; joined = b"".join(plains); r = pr(joined)
        top.append((r, f"{kn}/ECB-pb", joined[:32].hex()))
        if valid_pt(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
            soft.append({"label": f"{kn}/ECB-pb", "ratio": round(r,4), "head": joined[:80].hex()})
        for i, p in enumerate(plains):
            n_priv += 1
            if matches_pubkey(p):
                hard.append({"label": f"{kn}/ECB-pb", "blk": i, "priv": p.hex()})

    # bônus: os 35 blocos como um blob salted com salt_c4 + CHAIN4_PASSWORD (EVP)
    for hmod in (MD5, SHA256):
        k, iv = O._evp(F.CHAIN4_PASSWORD, salt_c4, hmod)
        try:
            pt = AES.new(k, AES.MODE_CBC, iv).decrypt(body)
            if valid_pt(pt) or b"Salted__" in pt or TARGET_PUBKEY in pt:
                soft.append({"label": f"salted-c4-body/{hmod.__name__}", "ratio": round(pr(pt),4), "head": pt[:80].hex()})
        except Exception: pass

    top.sort(reverse=True)
    print("=== Chain4 password = chave dos 35 blocos ===")
    print(f"AES: {n_aes} | privkey: {n_priv}")
    print(f"HARD: {len(hard)} | SOFT: {len(soft)}")
    if hard:
        print("!!! SOLVE !!!")
        for h in hard: print(" ", h)
    if soft:
        print("--- soft ---")
        for s in soft: print(" ", s)
    print("--- top ---")
    for r, lbl, head in top[:8]:
        print(f"  {r:.3f}  {lbl}  {head}")


if __name__ == "__main__":
    main()
