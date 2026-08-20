# -*- coding: utf-8 -*-
"""Teste focal: leituras DIRETAS (sem AES) dos 35 blocos como privkey.

Novo vs ENDGAME: o header28 como 7 uint32 -> INDICES (mod 35) que selecionam
7 blocos -> combinam. Testes anteriores usaram as 7 palavras como
checksums/operadores/ordem, nunca como indices de selecao direta. Tambem:
XOR de todos os 35, XOR dos indices primos, ápice do triangulo XOR 1D
(C(34,i) impar => posicoes 0,2,32,34), e variantes com `+-`/`7`.

Solve = matches_pubkey (gera a pubkey on-chain do premio). Sem AES aqui:
leituras diretas baratas (escalar secp256k1).
"""
from __future__ import annotations
import hashlib, os, sys
from coincurve import PublicKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F

TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def matches(s: bytes) -> bool:
    if len(s) != 32 or not any(s):
        return False
    try:
        return PublicKey.from_valid_secret(s).format(compressed=False) == TARGET_PUBKEY
    except ValueError:
        return False


def xor(blocks):
    out = bytearray(32)
    for b in blocks:
        for i in range(32):
            out[i] ^= b[i]
    return bytes(out)


def add_mod(blocks, mod):
    t = 0
    for b in blocks:
        t = (t + int.from_bytes(b, "big")) % mod
    return t.to_bytes(32, "big")


def main():
    R = F.reproduce()
    header = R["header"]; header28 = header[2:30]
    blocks = [R["blocks"][i*32:(i+1)*32] for i in range(35)]
    half, bh, tail = R["half"], R["better_half"], R["matrix_tail"]

    cands = []  # (label, 32B)
    # 1) combinacoes diretas simples
    cands.append(("xor_all_35", xor(blocks)))
    cands.append(("add_all_35_mod2^256", add_mod(blocks, 1 << 256)))
    cands.append(("add_all_35_modN", add_mod(blocks, N)))
    cands.append(("block0", blocks[0]))
    cands.append(("block34", blocks[-1]))
    cands.append(("block0^block34", xor([blocks[0], blocks[-1]])))
    # 2) indices primos (2,3,5,7,11,13,17,19,23,29,31) <- 35
    primes = [2,3,5,7,11,13,17,19,23,29,31]
    cands.append(("xor_prime_idx", xor([blocks[i] for i in primes])))
    cands.append(("add_prime_idx_modN", add_mod([blocks[i] for i in primes], N)))
    # 3) ápice do triangulo XOR 1D: C(34,i) impar => i subset dos bits de 34=100010
    #    bits: 0,2,32,34  (e tambem i onde C(34,i) impar; 34=0b100010 -> subconjuntos:
    #    0b000000=0, 0b000010=2, 0b100000=32, 0b100010=34)
    apex_idx = [0, 2, 32, 34]
    cands.append(("xor_triangle_apex", xor([blocks[i] for i in apex_idx])))
    cands.append(("add_triangle_apex_modN", add_mod([blocks[i] for i in apex_idx], N)))
    # 4) NOVO: header28 como 7 uint32 (big/little) -> indices mod 35 -> seleciona 7
    for endian in ("big", "little"):
        words = [int.from_bytes(header28[i*4:(i+1)*4], endian) for i in range(7)]
        idx7 = [w % 35 for w in words]
        cands.append((f"hdr7idx_{endian}_xor", xor([blocks[i] for i in idx7])))
        cands.append((f"hdr7idx_{endian}_addN", add_mod([blocks[i] for i in idx7], N)))
        cands.append((f"hdr7idx_{endian}_add2^256", add_mod([blocks[i] for i in idx7], 1 << 256)))
        # com `+-`: primeira metade +, segunda - (sinais naturais do prefixo)
        signs = [1,1,1,1, -1,-1,-1]  # 4 + entao 3 - (cabem em +-=2 chars)
        t = 0
        for w, s in zip(idx7, signs):
            t = (t + s * int.from_bytes(blocks[w], "big")) % N
        cands.append((f"hdr7idx_{endian}_pmN", t.to_bytes(32, "big") if 0 < t < N else b"\x00"*32))
        # todos + e todos -
        cands.append((f"hdr7idx_{endian}_all+N", add_mod([blocks[i] for i in idx7], N)))
        # tambem: os 7 words como escalares diretos (nao indices) combinados
        cands.append((f"hdr7words_{endian}_xor", xor([words[i].to_bytes(4, endian)+b"\x00"*28 for i in range(7)])))
    # 5) header28 como 28 bytes -> 28 indices mod 35 -> seleciona 28 blocos
    idx28 = [b % 35 for b in header28]
    cands.append(("hdr28idx_xor", xor([blocks[i] for i in idx28])))
    cands.append(("hdr28idx_addN", add_mod([blocks[i] for i in idx28], N)))
    # 6) `7` como numero de blocos a selecionar do inicio/fim
    cands.append(("xor_first7", xor(blocks[:7])))
    cands.append(("xor_last7", xor(blocks[-7:])))
    cands.append(("add_first7_N", add_mod(blocks[:7], N)))
    cands.append(("add_last7_N", add_mod(blocks[-7:], N)))
    # 7) 35 = 7x5: por grupo de 5, xor -> 7 valores -> xor -> 1
    groups = [blocks[r*5:(r+1)*5] for r in range(7)]
    g7 = [xor(g) for g in groups]
    cands.append(("xor_7groups_then_xor", xor(g7)))
    cands.append(("add_7groups_modN", add_mod(g7, N)))
    # round-robin groups
    rr = [blocks[r::7] for r in range(7)]
    rr7 = [xor(g) for g in rr]
    cands.append(("xor_7rr_then_xor", xor(rr7)))
    cands.append(("add_7rr_modN", add_mod(rr7, N)))
    # 8) sha256 de concatenacoes naturais
    cands.append(("sha256(all_blocks)", hashlib.sha256(R["blocks"]).digest()))
    cands.append(("sha256(header+blocks)", hashlib.sha256(header + R["blocks"]).digest()))
    cands.append(("sha256(blocks+header)", hashlib.sha256(R["blocks"] + header).digest()))
    cands.append(("sha256(header28)", hashlib.sha256(header28).digest()))
    # 9) combinacoes com half/better_half (yin-yang duality)
    cands.append(("xor_all_35^half", xor([xor(blocks), half])))
    cands.append(("xor_all_35^bh", xor([xor(blocks), bh])))
    cands.append(("xor_all_35^half^bh", xor([xor(blocks), half, bh])))
    cands.append(("add_all35+half+bh_modN", add_mod([add_mod(blocks, N), half, bh], N)))

    hits = []
    for label, val in cands:
        if len(val) != 32:
            continue
        if matches(val):
            hits.append((label, val.hex()))
    print("=== leituras diretas dos 35 blocos como privkey ===")
    print(f"candidatos: {len(cands)}")
    if hits:
        print("!!! SOLVE !!!")
        for l, h in hits:
            print(f"  {l}: {h}")
    else:
        print("NEGATIVO — nenhuma leitura direta gera a pubkey do premio.")
        # mostrar alguns indices para inspecao
        for endian in ("big", "little"):
            words = [int.from_bytes(header28[i*4:(i+1)*4], endian) for i in range(7)]
            print(f"  header7words({endian}) mod35 = {[w%35 for w in words]}")
        print(f"  header28 bytes mod35 = {idx28}")


if __name__ == "__main__":
    main()
