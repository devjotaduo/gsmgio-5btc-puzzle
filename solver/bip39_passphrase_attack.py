# -*- coding: utf-8 -*-
"""Variante BIP39 + passphrase: "Press ENTER and start talking" (Decentraland).

A passphrase BIP39 (a "25a palavra") muda completamente a seed. Entropias da
matriz 14x14 (que ja sabemos que geram mnemonics validos) + passphrases tematicas
do puzzle. Ninguem testou BIP39 com passphrase antes.
"""
from __future__ import annotations
import hashlib, os, sys
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O

PRIZE = O.PRIZE_ADDR
_M = Mnemonic("english")

MATRIX_ROWS = [
    "0 0 1 1 0 1 0 0 1 0 1 1 0 0","1 1 1 1 0 0 1 1 1 0 1 0 1 1",
    "1 1 0 1 1 1 0 1 0 0 1 0 0 1","0 1 1 0 1 0 0 0 0 1 1 1 0 1",
    "0 1 1 0 0 0 1 1 0 0 0 1 1 0","1 0 0 1 1 0 0 0 1 0 0 0 1 1",
    "1 0 0 1 1 1 0 0 0 1 0 0 0 0","1 1 1 0 0 0 0 0 0 0 1 0 0 0",
    "0 0 0 1 1 1 0 1 1 1 1 1 0 1","1 1 1 1 1 1 0 0 1 1 0 0 0 1",
    "1 1 0 1 0 0 0 0 0 1 1 0 1 1","1 1 1 1 0 0 1 0 1 0 1 1 0 0",
    "0 1 0 1 1 1 0 1 0 0 0 1 1 0","0 1 1 0 1 1 0 1 1 0 1 0 1 1",
]
GRID = [[int(b) for b in row.replace(" ", "")] for row in MATRIX_ROWS]

def spiral_bits(grid, n, direction):
    dirs = [(0,1),(1,0),(0,-1),(-1,0)] if direction == "cw" else [(1,0),(0,1),(-1,0),(0,-1)]
    result, visited = [], [[False]*n for _ in range(n)]
    r, c, d = 0, 0, 0
    for _ in range(n*n):
        result.append(grid[r][c]); visited[r][c] = True
        nr, nc = r+dirs[d][0], c+dirs[d][1]
        if nr<0 or nr>=n or nc<0 or nc>=n or visited[nr][nc]:
            d = (d+1) % 4; nr, nc = r+dirs[d][0], c+dirs[d][1]
        r, c = nr, nc
    return result

def bits_to_bytes(bits):
    n = len(bits) // 8 * 8
    return bytes(int("".join(str(b) for b in bits[i:i+8]), 2) for i in range(0, n, 8))

def derive_addr(mnemonic_str, passphrase, max_acct=3, max_idx=5):
    hits = []
    try:
        seed = Bip39SeedGenerator(mnemonic_str, passphrase).Generate()
    except Exception:
        seed = _M.to_seed(mnemonic_str, passphrase)
    acct = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    for a in range(max_acct):
        for chg in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            ck = acct.Purpose().Coin().Account(a).Change(chg)
            for i in range(max_idx):
                try:
                    if ck.AddressIndex(i).PublicKey().ToAddress() == PRIZE:
                        hits.append(f"m/44'/0'/{a}'/{int(chg)}/{i}")
                except Exception:
                    pass
    # tambem: a seed master como privkey direta (BIP32 master key)
    try:
        from bip_utils import Bip32Slip10Secp256k1
        master = Bip32Slip10Secp256k1.FromSeed(seed)
        priv = master.PrivateKey().Raw().ToBytes()
        r = O.check_privkey(priv)
        if r: hits.append(f"master-priv:{priv.hex()}")
    except Exception:
        pass
    return hits

# entropias
bits_rm = [GRID[r][c] for r in range(14) for c in range(14)]
bits_ccw = spiral_bits(GRID, 14, "ccw")
bits_cw = spiral_bits(GRID, 14, "cw")
bits_cm = [GRID[r][c] for c in range(14) for r in range(14)]

ENTROPIES = {}
for rname, bits in [("rm", bits_rm), ("ccw", bits_ccw), ("cw", bits_cw), ("cm", bits_cm)]:
    for ent_len in (16, 20, 24):
        ENTROPIES[f"{rname}/{ent_len}B"] = bits_to_bytes(bits[:ent_len*8])
    # sha256 de todos os bits = 32 bytes = 24 palavras
    all_bits = "".join(str(b) for b in bits).encode()
    ENTROPIES[f"{rname}/sha32B"] = hashlib.sha256(all_bits).digest()
# URL como entropia
ENTROPIES["url/24B"] = b"gsmg.io/theseedisplanted"
# "theseedisplanted" tem 17 bytes (nao valido); sha256 = 32 bytes
ENTROPIES["seedplanted/sha32B"] = hashlib.sha256(b"theseedisplanted").digest()
# a senha da fase 2 (flor) como entropia sha256
ENTROPIES["flower/sha32B"] = hashlib.sha256(b"theflowerblossomsthroughwhatseemstobeaconcretesurface").digest()

# passphrases tematicas
PASSPHRASES = [
    "",  # sem passphrase (baseline, ja testado mas confirmar)
    "enter",  # Decentraland: "Press enter and start talking"
    "HASHTHETEXT",  # operacao terminal
    "hashthetext",
    "matrixsumlist",
    "yinyang",
    "yin yang",
    "yinyangmatrixsumlist",
    "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
    "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "causality",  # fase 3
    "theflowerblossomsthroughwhatseemstobeaconcretesurface",  # fase 2
    "shabefanstoo",  # do SalPhaseion
    "shabef",  # sha256
    "7",  # o marker final
    "+-",  # o marker inicial
    "101",  # matrixsum
    "gsmg.io/theseedisplanted",  # a URL da fase 1
    "the seed is planted",  # traducao
    "theseedisplanted",
    "jacquefresco",  # fase 3.2
    "thechoiceisours",  # Venus Project
    "kill-process",  # eps3.5
    "eps3.5_kill-process.inc",
]

hard = []
n = 0
print("=== BIP39 matriz + passphrase tematica ===")
for ename, ent in ENTROPIES.items():
    if len(ent) not in (16, 20, 24, 28, 32):
        continue
    try:
        mnem = _M.to_mnemonic(ent)
    except Exception:
        continue
    for pp in PASSPHRASES:
        n += 1
        hits = derive_addr(mnem, pp)
        if hits:
            hard.append({"entropy": ename, "passphrase": pp, "mnemonic": mnem, "paths": hits})
            print(f"!!! SOLVE: {ename} + pp={pp!r} -> {mnem[:40]}... -> {hits}")

print(f"\ntotal: {n} combinacoes (entropias x passphrases)")
print(f"HARD hits: {len(hard)}")
if hard:
    for h in hard:
        print(f"  {h}")
else:
    print("NEGATIVO — BIP39 da matriz + passphrase tematica nao derivam o endereco do premio.")
