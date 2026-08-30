# -*- coding: utf-8 -*-
"""Hipoteses NOVAS nao cobertas pelo ENDGAME, testadas contra oraculo duro.

Gaps identificados apos leitura exaustiva de todos os scripts de ataque:
1. SHA256(prefixo31) como CHAVE AES (so foi testado como IV em first_hint_frontier)
2. +/- alternado em grupos de 7 como CHAVE AES (MITM so testou como privkey)
3. +/- alternado em todos os 35 blocos como CHAVE AES
4. Step-7 (0,7,14,21,28) com +/- alternado como CHAVE AES
5. header7words mod 5 -> seleciona 1 por grupo de 5 -> XOR -> CHAVE AES
6. SHA256 de cada header word -> descriptografar grupo correspondente de 5 blocos
7. Chaves simples: 0x07*32, SHA256("7"), SHA256("+-7"), SHA256("+-")
8. half * better_half mod N como privkey
9. header28 + paddings como CHAVE AES direta
10. prefixo31 como passphrase via EVP_BytesToKey
11. XOR dos blocos com half/bh cycling -> privkey
12. AES-CTR com header28 como nonce
13. EBCDIC decode do header28 -> senha
14. header7words padded to 32 -> descriptografar grupo de 5
15. SHA256(half*bh mod N) como chave AES
16. "enter" como senha (Decentraland "press enter and start talking")
17. HASHTHETEXT sobre o prefixo inteiro
18. SHA256(cosmic) como chave AES dos 35 blocos (o "anchor" 4f7a1e...)
19. OS 35 blocos como entropia BIP39 (32B -> 24 palavras)
20. half+better_half concatenado como chave AES-256 dos 35 blocos
"""
from __future__ import annotations
import hashlib, os, sys, struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

from coincurve import PublicKey
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

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


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def add_mod256(blocks) -> bytes:
    t = 0
    for b in blocks:
        t = (t + int.from_bytes(b, "big")) % (1 << 256)
    return t.to_bytes(32, "big")


def sub_mod256(blocks) -> bytes:
    t = 0
    for b in blocks:
        t = (t - int.from_bytes(b, "big")) % (1 << 256)
    return t.to_bytes(32, "big")


def signed_sum(blocks, signs, mod=1 << 256) -> bytes:
    t = 0
    for b, s in zip(blocks, signs):
        t = (t + s * int.from_bytes(b, "big")) % mod
    return t.to_bytes(32, "big")


def evp(pw: bytes, salt: bytes, hmod, klen=32, ivlen=16):
    d = b""; prev = b""
    while len(d) < klen + ivlen:
        prev = hmod.new(prev + pw + salt).digest()
        d += prev
    return d[:klen], d[klen:klen + ivlen]


IVS = {}

def build_ivs(header28, half, bh, tail, cosmic):
    return {
        "zero": b"\x00" * 16,
        "header16": header28[:16],
        "header28lo": header28[12:28],
        "half16": half[:16],
        "bh16": bh[:16],
        "tailpad": (tail * 4)[:16],
        "sevenpad": b"7" * 16,
        "sha_prefix": hashlib.sha256(b"+-" + header28 + b"7").digest()[:16],
        "cosmic16": cosmic[:16],
        "cosmic32_16": cosmic[16:32],
        "half_hi": half[16:32],
        "bh_hi": bh[16:32],
    }


def test_aes(key: bytes, label: str, body: bytes, blocks, ivs, hard, soft, top):
    if len(key) != 32:
        return
    # stream CBC
    for ivn, iv in ivs.items():
        try:
            pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
        except ValueError:
            continue
        r = pr(pt)
        top.append((r, f"{label}/CBC-stream/{ivn}"))
        if valid_pt(pt) or b"Salted__" in pt or TARGET_PUBKEY in pt:
            soft.append({"label": f"{label}/CBC-stream/{ivn}", "ratio": round(r, 4),
                         "head": pt[:80].hex()})
        for i in range(0, len(pt) - 31, 16):
            if matches_pubkey(pt[i:i + 32]):
                hard.append({"label": f"{label}/CBC-stream/{ivn}", "off": i,
                             "priv": pt[i:i + 32].hex()})
    # per-block CBC + ECB
    for ivn, iv in ivs.items():
        plains = []
        for blk in blocks:
            try:
                plains.append(AES.new(key, AES.MODE_CBC, iv).decrypt(blk))
            except ValueError:
                plains.append(b"")
        joined = b"".join(plains)
        r = pr(joined)
        top.append((r, f"{label}/CBC-pb/{ivn}"))
        if valid_pt(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
            soft.append({"label": f"{label}/CBC-pb/{ivn}", "ratio": round(r, 4),
                         "head": joined[:80].hex()})
        for i, p in enumerate(plains):
            if matches_pubkey(p):
                hard.append({"label": f"{label}/CBC-pb/{ivn}", "blk": i, "priv": p.hex()})
    plains = []
    for blk in blocks:
        try:
            plains.append(AES.new(key, AES.MODE_ECB).decrypt(blk))
        except ValueError:
            plains.append(b"")
    joined = b"".join(plains)
    r = pr(joined)
    top.append((r, f"{label}/ECB-pb"))
    if valid_pt(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
        soft.append({"label": f"{label}/ECB-pb", "ratio": round(r, 4),
                     "head": joined[:80].hex()})
    for i, p in enumerate(plains):
        if matches_pubkey(p):
            hard.append({"label": f"{label}/ECB-pb", "blk": i, "priv": p.hex()})

    # AES-CTR (NOVO: nunca testado no ENDGAME)
    for ivn, iv in ivs.items():
        try:
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=int.from_bytes(iv[8:], "big"))
            pt = cipher.decrypt(body)
        except (ValueError, Exception):
            continue
        r = pr(pt)
        top.append((r, f"{label}/CTR/{ivn}"))
        if valid_pt(pt) or b"Salted__" in pt or TARGET_PUBKEY in pt:
            soft.append({"label": f"{label}/CTR/{ivn}", "ratio": round(r, 4),
                         "head": pt[:80].hex()})
        for i in range(0, len(pt) - 31, 16):
            if matches_pubkey(pt[i:i + 32]):
                hard.append({"label": f"{label}/CTR/{ivn}", "off": i,
                             "priv": pt[i:i + 32].hex()})


def main():
    R = F.reproduce()
    header = R["header"]          # 31 bytes (+- + header28 + 7)
    header28 = header[2:30]       # 28 bytes
    prefix31 = header              # 31 bytes
    body = R["blocks"]            # 1120 bytes
    blocks = [body[i * 32:(i + 1) * 32] for i in range(35)]
    half = R["half"]
    bh = R["better_half"]
    tail = R["matrix_tail"]
    cosmic = R["cosmic"]
    chain1 = R["chain1"]
    chain2 = R["chain2"]
    chain4 = R["chain4"]
    chain4_blob = R["chain4_blob"]
    salt_c4 = chain4_blob[8:16]

    ivs = build_ivs(header28, half, bh, tail, cosmic)

    hard = []
    soft = []
    top = []
    seen = set()
    n_keys = 0

    def emit(key: bytes, label: str):
        nonlocal n_keys
        if key in seen or len(key) != 32:
            return
        seen.add(key)
        n_keys += 1
        if matches_pubkey(key):
            hard.append({"DIRECT": label, "priv": key.hex()})
        test_aes(key, label, body, blocks, ivs, hard, soft, top)

    # ====== 1. SHA256(prefixo31) como CHAVE AES ======
    emit(hashlib.sha256(prefix31).digest(), "sha256(prefix31)")
    emit(hashlib.sha256(b"+-" + header28 + b"7").digest(), "sha256(+-header28-7)")
    emit(hashlib.sha256(header28).digest(), "sha256(header28)")
    emit(hashlib.sha256(header28 + b"7").digest(), "sha256(header28+7)")
    emit(hashlib.sha256(b"+-" + header28).digest(), "sha256(+-header28)")

    # ====== 2. +/- alternado em grupos de 7 como CHAVE AES ======
    groups7 = [blocks[i*7:(i+1)*7] for i in range(5)]
    signs_5 = [1, -1, 1, -1, 1]
    result = 0
    for g, s in zip(groups7, signs_5):
        for b in g:
            result = (result + s * int.from_bytes(b, "big")) % (1 << 256)
    emit(result.to_bytes(32, "big"), "+-groups7_mod2^256")
    result_n = result % N
    if 0 < result_n < N:
        emit(result_n.to_bytes(32, "big"), "+-groups7_modN")

    # ====== 3. +/- alternado em todos os 35 blocos como CHAVE AES ======
    signs_35 = [1 if i % 2 == 0 else -1 for i in range(35)]
    emit(signed_sum(blocks, signs_35, 1 << 256), "+-alternating35_mod2^256")
    emit(signed_sum(blocks, signs_35, N), "+-alternating35_modN")
    # comecando com -
    signs_35b = [-1 if i % 2 == 0 else 1 for i in range(35)]
    emit(signed_sum(blocks, signs_35b, 1 << 256), "-+alternating35_mod2^256")

    # ====== 4. Step-7 (0,7,14,21,28) com +/- alternado ======
    step7 = [blocks[i] for i in [0, 7, 14, 21, 28]]
    emit(signed_sum(step7, [1, -1, 1, -1, 1], 1 << 256), "step7_+-+_mod2^256")
    emit(signed_sum(step7, [1, -1, 1, -1, 1], N), "step7_+-+_modN")
    emit(signed_sum(step7, [-1, 1, -1, 1, -1], 1 << 256), "step7_-+-_mod2^256")
    # XOR do step-7
    emit(bytes(a ^ b ^ c ^ d ^ e for a, b, c, d, e in zip(*step7)), "step7_xor")
    # soma do step-7
    emit(add_mod256(step7), "step7_add_mod2^256")

    # ====== 5. header7words mod 5 -> seleciona 1 por grupo de 5 -> XOR ======
    for endian in ("big", "little"):
        words = [int.from_bytes(header28[i*4:(i+1)*4], endian) for i in range(7)]
        # grupos de 5: [0:5], [5:10], [10:15], [15:20], [20:25], [25:30], [30:35]
        selected = []
        for gi in range(7):
            idx = words[gi] % 5
            selected.append(blocks[gi * 5 + idx])
        xor_sel = bytes(32)
        for b in selected:
            xor_sel = xor_bytes(xor_sel, b)
        emit(xor_sel, f"hdr7w_mod5_xor_{endian}")
        emit(add_mod256(selected), f"hdr7w_mod5_add_{endian}")
        emit(signed_sum(selected, [1, -1, 1, -1, 1, -1, 1], 1 << 256),
             f"hdr7w_mod5_+-+-+-+_{endian}")
        # SHA256 dos 7 selecionados concatenados
        emit(hashlib.sha256(b"".join(selected)).digest(),
             f"sha256(hdr7w_mod5_sel_{endian})")

    # ====== 6. SHA256 de cada header word -> descriptografar grupo de 5 ======
    for endian in ("big", "little"):
        words = [int.from_bytes(header28[i*4:(i+1)*4], endian) for i in range(7)]
        for wi in range(7):
            w_bytes = header28[wi*4:(wi+1)*4]
            key = hashlib.sha256(w_bytes).digest()
            emit(key, f"sha256(hdrword{wi}_{endian})")
            # padded to 32
            padded = w_bytes + b"\x00" * 28
            emit(padded, f"hdrword{wi}_pad32_{endian}")

    # ====== 7. Chaves simples ======
    emit(b"\x07" * 32, "0x07_x32")
    emit(b"7" * 32, "7char_x32")
    emit(hashlib.sha256(b"7").digest(), "sha256(7)")
    emit(hashlib.sha256(b"+-7").digest(), "sha256(+-7)")
    emit(hashlib.sha256(b"+-").digest(), "sha256(+-)")
    emit(hashlib.sha256(b"+-7").hexdigest().encode(), "sha256hex(+-7)")
    emit(hashlib.sha256(b"11111").digest(), "sha256(11111)")
    emit(bytes([31]) * 32, "0x1f_x32")

    # ====== 8. half * better_half mod N como privkey ======
    h_int = int.from_bytes(half, "big")
    bh_int = int.from_bytes(bh, "big")
    prod = (h_int * bh_int) % N
    if 0 < prod < N:
        emit(prod.to_bytes(32, "big"), "half*bh_modN")
    prod2 = (h_int * bh_int) % (1 << 256)
    emit(prod2.to_bytes(32, "big"), "half*bh_mod2^256")
    # SHA256 do produto
    emit(hashlib.sha256(prod.to_bytes(32, "big")).digest(), "sha256(half*bh_modN)")
    # half / better_half mod N
    try:
        bh_inv = pow(bh_int, N - 2, N)
        quot = (h_int * bh_inv) % N
        if 0 < quot < N:
            emit(quot.to_bytes(32, "big"), "half/bh_modN")
    except Exception:
        pass

    # ====== 9. header28 + paddings como CHAVE AES direta ======
    for pad_byte in [0x00, 0x01, 0x07, 0x20, 0x31, 0x37, 0xff]:
        padded = header28 + bytes([pad_byte]) * 4
        emit(padded, f"header28+pad{pad_byte:#x}")
    # +- + header28 + 7 + pad
    for pad_byte in [0x00, 0x01, 0x07, 0x0a, 0x20, 0x31, 0x37, 0xff]:
        padded = prefix31 + bytes([pad_byte])
        emit(padded, f"prefix31+pad{pad_byte:#x}")
    # header28 + fc0c1b02 (tail)
    emit(header28 + tail, "header28+tail")

    # ====== 10. prefixo31 como passphrase via EVP_BytesToKey ======
    for pw in [prefix31, header28, b"+-" + header28 + b"7", b"7", b"+-7"]:
        for salt_name, salt in [("chain4", salt_c4), ("zero", b"\x00"*8),
                                 ("sevens", b"7"*8)]:
            for hmod in (MD5, SHA256):
                k, iv = evp(pw, salt, hmod)
                emit(k, f"EVP/{pw[:8].hex()}/{salt_name}/{hmod.__name__}")

    # ====== 11. XOR dos blocos com half/bh cycling -> privkey ======
    for key_name, key in [("half", half), ("bh", bh), ("half^bh", xor_bytes(half, bh))]:
        xored = bytes(body[i] ^ key[i % 32] for i in range(len(body)))
        # checar cada janela de 32 bytes
        for i in range(0, len(xored) - 31, 16):
            if matches_pubkey(xored[i:i+32]):
                hard.append({"label": f"XOR_{key_name}/off{i}", "priv": xored[i:i+32].hex()})
        # SHA256 do resultado como chave AES
        emit(hashlib.sha256(xored).digest(), f"sha256(xor_body_{key_name})")
        # primeiro bloco como chave
        emit(xored[:32], f"xor_body_{key_name}[:32]")

    # ====== 12. "enter" como senha ======
    emit(hashlib.sha256(b"enter").digest(), "sha256(enter)")
    emit(hashlib.sha256(b"ENTER").digest(), "sha256(ENTER)")
    emit(hashlib.sha256(b"matrixsumlistenter").digest(), "sha256(matrixsumlistenter)")

    # ====== 13. HASHTHETEXT sobre o prefixo ======
    emit(hashlib.sha256(prefix31.upper().replace(b" ", b"")).digest(),
         "HASHTHETEXT(prefix31)")
    emit(hashlib.sha256(b"MATRIXSUMLISTENTER").digest(), "HASHTHETEXT(matrixsumlistenter)")

    # ====== 14. SHA256(cosmic) como chave AES dos 35 blocos ======
    cosmic_hash = bytes.fromhex(F.COSMIC_SHA256)
    emit(cosmic_hash, "sha256(cosmic)_bytes")
    emit(hashlib.sha256(cosmic_hash).digest(), "sha256(sha256(cosmic))")

    # ====== 15. half + better_half concatenado como chave AES ======
    emit(hashlib.sha256(half + bh).digest(), "sha256(half+bh)")
    emit(hashlib.sha256(bh + half).digest(), "sha256(bh+half)")
    # 16 bytes de cada intercalados
    interleaved = bytes()
    for i in range(32):
        if i < 16:
            interleaved += bytes([half[i], bh[i]])
        else:
            interleaved += bytes([half[i], bh[i]])
    # nao vai ter 32 bytes, pular
    # metade de cada
    emit(half[:16] + bh[:16], "half[:16]+bh[:16]")
    emit(half[16:] + bh[16:], "half[16:]+bh[16:]")
    emit(half[:16] + bh[16:], "half[:16]+bh[16:]")
    emit(half[16:] + bh[:16], "half[16:]+bh[:16]")

    # ====== 16. BIP39 dos 35 blocos (32B = 24 palavras) ======
    for i in range(35):
        result = O.check_mnemonic(_bytes_to_mnemonic(blocks[i]))
        if result and result.get("match"):
            hard.append({"label": f"BIP39/block{i}", **result})
        # SHA256 do bloco como entropia
        h = hashlib.sha256(blocks[i]).digest()
        result = O.check_mnemonic(_bytes_to_mnemonic(h))
        if result and result.get("match"):
            hard.append({"label": f"BIP39/sha256(block{i})", **result})

    # ====== 17. chain4[:31] (prefixo) como privkey (31 bytes -> pad) ======
    for pad_byte in [0x00, 0x01, 0x07, 0x37]:
        emit(prefix31 + bytes([pad_byte]), f"prefix31+{pad_byte:#x}_as_priv")
        if matches_pubkey(prefix31 + bytes([pad_byte])):
            hard.append({"DIRECT": f"prefix31+{pad_byte:#x}", "priv": (prefix31 + bytes([pad_byte])).hex()})

    # ====== 18. SHA256(chain4) completo como chave ======
    emit(hashlib.sha256(chain4).digest(), "sha256(chain4)")
    emit(hashlib.sha256(chain4[:31]).digest(), "sha256(chain4[:31])")
    emit(hashlib.sha256(chain4[31:]).digest(), "sha256(chain4[31:])")

    # ====== 19. EBCDIC decode do header28 ======
    try:
        ebcdic = header28.decode("cp1141")
        emit(hashlib.sha256(ebcdic.encode()).digest(), "sha256(ebcdic_header28)")
    except Exception:
        pass
    try:
        ebcdic = prefix31.decode("cp1141")
        emit(hashlib.sha256(ebcdic.encode()).digest(), "sha256(ebcdic_prefix31)")
    except Exception:
        pass

    # ====== 20. Senhas tematicas adicionais ======
    extra_passwords = [
        "HASHTHETEXT", "hashthetext", "HashTheText",
        "theflowerblossomssthroughwhatseemstobeaconcretesurface",
        "causality", "CAUSALITY",
        "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
        "THEMATRIXHASYOU", "thematrixhasyou",
        "yinyang", "YINYANG", "YinYang",
        "salphaseion", "SALPHASEION", "SalPhaseIon",
        "cosmicduality", "COSMICDUALITY", "CosmicDuality",
        "giveitjustonesecond", "GIVEITJUSTONESECOND",
        "betterhalf", "BETTERHALF",
        "halfandbetterhalf", "HALFANDBETTERHALF",
        "neighborshalfanddouble", "NEIGHBORSHALFANDDOUBLE",
        "shabefanstoo", "SHABEFANSTOO",
        "shabefourfirsthintisyourlastcommand",
        "rewatchep35withthebetterhalf",
        "eps3.5kill-process.inc",
        "eps35killprocessinc",
        "killprocess", "KILLPROCESS",
        "redwheelbarrow", "REDWHEELBARROW",
        "thefutureisours", "THEFUTUREISOURS",
        "thefutureisourstodirect", "THEFUTUREISOURSTODIRECT",
        "lookingforward", "LOOKINGFORWARD",
        "thechoiceisours", "THECHOICEISOURS",
        "venusproject", "VENUSPROJECT",
    ]
    for pw in extra_passwords:
        emit(hashlib.sha256(pw.encode()).digest(), f"sha256({pw[:25]})")
        if len(pw) == 32:
            emit(pw.encode(), f"raw32({pw[:25]})")
        # HASHTHETEXT gramatica (UPPER sem espaco)
        upper = pw.upper().replace(" ", "")
        emit(hashlib.sha256(upper.encode()).digest(), f"HASHTHETEXT({pw[:20]})")

    # ====== 21. Combinacoes com a senha do chain1 ======
    chain1_pw = F.CHAIN1_PASSWORD
    emit(hashlib.sha256(chain1_pw).digest(), "sha256(chain1_password)")
    emit(hashlib.sha256(chain1_pw).hexdigest().encode(), "sha256hex(chain1_password)")

    # ====== 22. matrixsumlist como keystream mod-256 sobre os blocos ======
    msl = [6, 10, 8, 7, 6, 6, 5, 4, 9, 9, 7, 8, 7, 9]
    # somar cada byte dos blocos pelo keystream ciclico
    shifted = bytes((body[i] + msl[i % 14]) % 256 for i in range(len(body)))
    emit(hashlib.sha256(shifted).digest(), "sha256(msl_shift_body)")
    for i in range(0, len(shifted) - 31, 16):
        if matches_pubkey(shifted[i:i+32]):
            hard.append({"label": f"msl_shift/off{i}", "priv": shifted[i:i+32].hex()})
    # subtrair
    shifted2 = bytes((body[i] - msl[i % 14]) % 256 for i in range(len(body)))
    emit(hashlib.sha256(shifted2).digest(), "sha256(msl_sub_body)")
    for i in range(0, len(shifted2) - 31, 16):
        if matches_pubkey(shifted2[i:i+32]):
            hard.append({"label": f"msl_sub/off{i}", "priv": shifted2[i:i+32].hex()})

    # ====== Relatorio ======
    top.sort(reverse=True)
    print("=" * 60)
    print("HIPOTESES NOVAS - oraculo duro (pubkey + AES padding + BIP39)")
    print("=" * 60)
    print(f"Chaves unicas testadas: {n_keys}")
    print(f"HARD hits (pubkey/privkey): {len(hard)}")
    print(f"SOFT hits (padding/ascii): {len(soft)}")
    if hard:
        print("\n!!! SOLVE !!!")
        for h in hard:
            print(f"  {h}")
    if soft:
        print("\n--- soft hits ---")
        for s in soft:
            print(f"  {s}")
    print("\n--- top print ratios ---")
    for r, lbl in top[:15]:
        print(f"  {r:.3f}  {lbl}")

    # info de debug
    for endian in ("big", "little"):
        words = [int.from_bytes(header28[i*4:(i+1)*4], endian) for i in range(7)]
        print(f"  header7words({endian}) mod5 = {[w%5 for w in words]}")
        print(f"  header7words({endian}) mod35 = {[w%35 for w in words]}")


def _bytes_to_mnemonic(entropy: bytes):
    """Converte 32 bytes (ou 16/24) em palavras BIP39."""
    from mnemonic import Mnemonic
    m = Mnemonic("english")
    return m.to_mnemonic(entropy).split()


if __name__ == "__main__":
    main()
