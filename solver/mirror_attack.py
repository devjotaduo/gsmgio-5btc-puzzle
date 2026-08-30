# -*- coding: utf-8 -*-
"""Ataque 'Le Miroir de la Vie et de la Mort' (livro Cosmic Duality p.39, hint
CONFIRMADO pelo criador 2023-01-08: '@barrystyle... (Cosmic Duality Book Page -
Life and Death)').

Mecanica do ESPELHO em secp256k1: para cada x ha dois y (y e p-y); a privkey do
ponto-espelho e N-k. A gravura (viva vs esqueleto no mesmo espelho) = a dualidade
yin-yang dos dois y. NUNCA testado no campaign inteiro:
  1. better_half == N - half? (as 'duas metades' seriam gemeas-espelho - mesmo x)
  2. oráculo-espelho: candidato s tal que pub(s) == (x_alvo, p-y_alvo)
     (equivalente: N-s bate o alvo). Se o puzzle ENTREGA N-k, todo scan da
     historia errou por um sinal.
  3. re-teste dos candidatos naturais (negacoes, blocos, combos, janelas) vs
     o ponto-espelho.
"""
from __future__ import annotations
import hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")


def pub(s: bytes) -> bytes:
    return PublicKey.from_valid_secret(s).format(compressed=False)


def matches_target(s: bytes) -> bool:
    return len(s) == 32 and any(s) and pub(s) == TARGET_PUBKEY


def main():
    R = F.reproduce()
    half, bh = R["half"], R["better_half"]
    body = R["blocks"]
    blocks = [body[i * 32:(i + 1) * 32] for i in range(35)]
    header28 = R["header"][2:30]
    h_i, bh_i = int.from_bytes(half, "big"), int.from_bytes(bh, "big")

    # ================= 1. o espelho estrutural: half/better_half =================
    print("=" * 62)
    print("1. ESPELHO ESTRUTURAL: better_half == N - half?")
    print("=" * 62)
    neg_half = (N - h_i) % N
    neg_bh = (N - bh_i) % N
    print(f"   N - half        = {neg_half.to_bytes(32, 'big').hex()}")
    print(f"   better_half     = {bh.hex()}")
    print(f"   bh == N - half  : {neg_half == bh_i}")
    print(f"   half == N - bh  : {neg_bh == h_i}")
    xh = pub(half)[1:33]
    xb = pub(bh)[1:33]
    print(f"   mesmo x (half/bh): {xh == xb}   [x_half={xh.hex()[:16]}… x_bh={xb.hex()[:16]}…]")
    # espelho dos dois: pub(N-half) == pub(bh) espelhado?
    if neg_half != bh_i:
        pub_neg_h = pub(neg_half.to_bytes(32, "big"))
        print(f"   pub(N-half)[1:33] == x_bh : {pub_neg_h[1:33] == xb}")

    # ================= 2. ponto-espelho do alvo =================
    print()
    print("=" * 62)
    print("2. PONTO-ESPELHO DO ALVO: (x_alvo, P - y_alvo)")
    print("=" * 62)
    x_t = TARGET_PUBKEY[1:33]
    y_t = int.from_bytes(TARGET_PUBKEY[33:65], "big")
    mirror_y = (P - y_t) % P
    MIRROR_PUBKEY = b"\x04" + x_t + mirror_y.to_bytes(32, "big")
    print(f"   mirror pubkey: {MIRROR_PUBKEY.hex()}")

    import base64, hashlib as hl
    try:
        import base58
        from Crypto.Hash import RIPEMD160
        h160 = RIPEMD160.new(hl.sha256(MIRROR_PUBKEY).digest()).digest()
        mirror_addr = base58.b58encode_check(b"\x00" + h160)
        print(f"   mirror address (endereço-'morte'): {mirror_addr.decode()}")
    except Exception as e:
        print(f"   (address skip: {e})")

    def matches_mirror(s: bytes) -> bool:
        if len(s) != 32 or not any(s):
            return False
        try:
            return pub(s) == MIRROR_PUBKEY
        except ValueError:
            return False

    def check(label: str, s: bytes):
        if len(s) != 32:
            return
        if matches_target(s):
            print(f"   !!! TARGET DIRETO: {label} = {s.hex()}")
        if matches_mirror(s):
            print(f"   !!! ESPELHO (resposta = N - k): {label} = {s.hex()}  ->  privkey = {(N - int.from_bytes(s, 'big')) % N:064x}")

    # ================= 3. bateria de candidatos vs espelho =================
    print()
    print("=" * 62)
    print("3. CANDIDATOS vs ORACULO-ESPELHO")
    print("=" * 62)
    hits = 0

    def try_c(label: str, s: bytes):
        nonlocal hits
        if len(s) != 32 or not any(s):
            return
        if matches_mirror(s):
            hits += 1
            k = (N - int.from_bytes(s, "big")) % N
            print(f"   !!! ESPELHO HIT: {label} | entregue={s.hex()} | privkey={k:064x}")
        if matches_target(s):
            hits += 1
            print(f"   !!! TARGET HIT: {label} | privkey={s.hex()}")

    # 3a. negacoes dos artefatos base
    bases = {
        "half": half, "better_half": bh,
        "half^bh": bytes(a ^ b for a, b in zip(half, bh)),
        "half+bh": ((h_i + bh_i) % N).to_bytes(32, "big"),
        "half-bh": ((h_i - bh_i) % N).to_bytes(32, "big"),
        "bh-half": ((bh_i - h_i) % N).to_bytes(32, "big"),
        "half*bh": ((h_i * bh_i) % N).to_bytes(32, "big"),
        "sha256(half+bh)": hl.sha256(half + bh).digest(),
        "sha256(bh+half)": hl.sha256(bh + half).digest(),
        "chain4pw": F.CHAIN4_PASSWORD,
        "sha256(chain4pw)": hl.sha256(F.CHAIN4_PASSWORD).digest(),
        "matrix_tail32": R["matrix_tail"] + b"\x00" * 28,
        "chain1_0_32": R["chain1"][:32],
        "chain2_0_32": R["chain2"][:32],
        "cosmic_64_96": R["cosmic"][64:96],
        "sha256(half)": hl.sha256(half).digest(),
        "sha256(bh)": hl.sha256(bh).digest(),
    }
    for name, b in bases.items():
        try_c(f"{name}", b)
        try_c(f"N-{name}", ((N - int.from_bytes(b, "big")) % N).to_bytes(32, "big"))

    # 3b. blocos direto e espelhado
    for i, blk in enumerate(blocks):
        try_c(f"block{i}", blk)
        try_c(f"N-block{i}", ((N - int.from_bytes(blk, "big")) % N).to_bytes(32, "big"))
        try_c(f"sha256(block{i})", hl.sha256(blk).digest())

    # 3c. combos estruturais (subsets das camadas 5/6)
    def xor_all(sel):
        x = bytes(32)
        for i in sel:
            x = bytes(a ^ b for a, b in zip(x, blocks[i]))
        return x

    def sum_all(sel):
        t = 0
        for i in sel:
            t = (t + int.from_bytes(blocks[i], "big")) % (1 << 256)
        return t.to_bytes(32, "big")

    subsets = {
        "all35": list(range(35)),
        "primes": [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31],
        "first7": list(range(7)), "last7": list(range(28, 35)),
        "mult5": [0, 5, 10, 15, 20, 25, 30], "mult7": [0, 7, 14, 21, 28],
        "first16": list(range(16)), "first23": list(range(23)),
        "hdr7w_big": [int.from_bytes(header28[i * 4:(i + 1) * 4], "big") % 35 for i in range(7)],
        "hdr7w_little": [int.from_bytes(header28[i * 4:(i + 1) * 4], "little") % 35 for i in range(7)],
    }
    for name, sel in subsets.items():
        try_c(f"xor_{name}", xor_all(sel))
        try_c(f"sum_{name}", sum_all(sel))
        try_c(f"N-sum_{name}", ((N - int.from_bytes(sum_all(sel), "big")) % N).to_bytes(32, "big"))
    # pares simetricos
    for i in range(17):
        x = bytes(a ^ b for a, b in zip(blocks[i], blocks[34 - i]))
        try_c(f"xor_sym_{i}", x)
        s = (int.from_bytes(blocks[i], "big") + int.from_bytes(blocks[34 - i], "big")) % (1 << 256)
        try_c(f"sum_sym_{i}", s.to_bytes(32, "big"))

    # 3d. janelas de 32B em todos os estagios (scan espelho)
    artifacts = {
        "chain1": R["chain1"], "chain2": R["chain2"], "cosmic": R["cosmic"],
        "chain4": R["chain4"], "blocks": body,
        "half+bh": half + bh, "sha256s": hl.sha256(half).digest() + hl.sha256(bh).digest(),
        "matrix_components": F.MATRIX_COMPONENTS,
    }
    nwin = 0
    for aname, data in artifacts.items():
        for off in range(0, len(data) - 31):
            nwin += 1
            try_c(f"win_{aname}_{off}", data[off:off + 32])

    # 3e. plaintexts AES (chaves naturais) escaneados vs espelho
    print(f"   [scan] {nwin} janelas testadas")
    aes_keys = {
        "half": half, "bh": bh, "chain4pw": F.CHAIN4_PASSWORD,
        "sha256(half+bh)": hl.sha256(half + bh).digest(),
        "sha256(chain4pw)": hl.sha256(F.CHAIN4_PASSWORD).digest(),
    }
    for kn, key in aes_keys.items():
        for ivn, iv in (("zero", b"\x00" * 16), ("hdr", header28[:16])):
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            for j in range(0, len(pt) - 31, 16):
                try_c(f"aes_{kn}_{ivn}_off{j}", pt[j:j + 32])

    print()
    print("=" * 62)
    print(f"RESULTADO: {hits} hits (espelho ou direto)")
    print("=" * 62)
    if not hits:
        print("NEGATIVO — nenhum candidato natural bate o ponto-espelho do alvo.")


if __name__ == "__main__":
    main()
