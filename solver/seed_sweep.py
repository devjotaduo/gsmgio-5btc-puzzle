# -*- coding: utf-8 -*-
"""
Hipotese de MATERIAL DE SEED (nao prosa): apos 3 negativos control-validados de
cifra de fracionacao, testa faed/BIF/BIF_REST/trigramas como bytes de chave/entropia
diretamente contra os oraculos DUROS (endereco P2PKH + BIP39 c/ checksum).
Deterministico, finito, sem falsos-positivos (o oraculo so aceita match real).

Cobre angulos MENOS testados: faed cru em base-9, BIF inteiro em base-26,
trigramas base-27; ambas as endianidades; varios comprimentos de bits.
"""
import hashlib, itertools
import oracles as O
from mnemonic import Mnemonic
WORDLIST = Mnemonic("english").wordlist

CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"
ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
_MNEMO = Mnemonic("english")

def bifid_decrypt(ct, alpha, period):
    p = {c: (i // 5, i % 5) for i, c in enumerate(alpha)}
    out = []
    for off in range(0, len(ct), period):
        blk = ct[off:off + period]; seq = []
        for c in blk:
            r, co = p[c]; seq += [r, co]
        n = len(blk); rows, cols = seq[:n], seq[n:]
        out.append("".join(alpha[rows[i] * 5 + cols[i]] for i in range(n)))
    return "".join(out)

def sources_num():
    """Dict nome -> (lista de digitos, base)."""
    faed = O.sources()["faed"]
    BIF = bifid_decrypt(faed.upper(), CANON, 570)
    out = {}
    out["faed_a0"] = ([ord(c) - ord('a') for c in faed], 9)       # a=0..i=8
    out["faed_a1"] = ([ord(c) - ord('a') + 1 for c in faed], 10)  # a=1..i=9 (base 10, 0 ausente)
    out["BIF_A0"] = ([ALPHA25.index(c) for c in BIF], 25)
    out["BIFrest_A0"] = ([ALPHA25.index(c) for c in BIF[7:]], 25)
    # trigramas base-27 (hilo, sem transposicao)
    trits = []
    for c in faed:
        v = ord(c) - ord('a'); trits += [v // 3, v % 3]
    L = len(trits) // 3 * 3
    out["trigram27"] = ([9 * trits[i] + 3 * trits[i + 1] + trits[i + 2] for i in range(0, L, 3)], 27)
    return out

def to_bignum(digits, base, msb_first=True):
    n = 0
    seq = digits if msb_first else digits[::-1]
    for d in seq:
        n = n * base + d
    return n

def candidates_from_num(n):
    """Gera priv32 candidatos a partir de um bignum: low/high 256 bits, e bytes diretos."""
    cands = []
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    # low 32 bytes
    cands.append((n % (1 << 256)).to_bytes(32, "big"))
    cands.append((n % (1 << 256)).to_bytes(32, "little"))
    # high 32 bytes
    if len(b) >= 32:
        cands.append(b[:32])
        cands.append(b[-32:])
    # sha256 do bignum bytes
    cands.append(hashlib.sha256(b).digest())
    return cands

def sweep():
    src = sources_num()
    tried_priv = 0; tried_bip = 0
    for name, (digits, base) in src.items():
        for msb in (True, False):
            n = to_bignum(digits, base, msb)
            # ---- como PRIVATE KEY ----
            for pk in candidates_from_num(n):
                tried_priv += 1
                r = O.check_privkey(pk)
                if r:
                    print(f"!!! PRIVKEY HIT [{name} msb={msb}]: {r}"); return r
            # ---- como ENTROPIA BIP39 (canonica) ----
            b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
            # ---- BIP39 por INDICES de palavra (11 bits cada), low/high bits ----
            for nwords in (12, 15, 18, 21, 24):
                bits = nwords * 11
                for chunk_n in (n & ((1 << bits) - 1), n >> max(0, n.bit_length() - bits)):
                    idxs = [(chunk_n >> (11 * (nwords - 1 - k))) & 0x7FF for k in range(nwords)]
                    words = [WORDLIST[i] for i in idxs]
                    tried_bip += 1
                    res = O.check_mnemonic(words)
                    if res and res.get("match"):
                        print(f"!!! BIP39-idx HIT [{name} msb={msb} nw={nwords}]: {res}"); return res
            for ent_len in (16, 20, 24, 28, 32):
                for chunk in (b[:ent_len], b[-ent_len:],
                              (n % (1 << (ent_len * 8))).to_bytes(ent_len, "big")):
                    if len(chunk) != ent_len:
                        continue
                    try:
                        mnem = _MNEMO.to_mnemonic(chunk)
                    except Exception:
                        continue
                    tried_bip += 1
                    res = O.check_mnemonic(mnem.split())
                    if res and res.get("match"):
                        print(f"!!! BIP39 HIT [{name} msb={msb} ent={ent_len}]: {res}"); return res
    print(f"[sweep] sem hit. priv testados={tried_priv}, bip39 canonicos testados={tried_bip}")
    return None

if __name__ == "__main__":
    print("=== SEED SWEEP (hipotese: faed/BIF = material de chave) ===")
    r = sweep()
    if r:
        import json, os
        os.makedirs("out", exist_ok=True)
        json.dump({"kind": "seed_sweep", **r}, open("out/SOLVED.json", "w"), indent=2)
        print("SOLVE -> out/SOLVED.json")
    else:
        print("negativo — faed/BIF nao sao material de chave direto nas codificacoes testadas")
