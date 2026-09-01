# -*- coding: utf-8 -*-
"""TERCEIRA GRAMATICA — sobre ARTEFATOS-BYTES intermediarios da cadeia.

Fato provado: o puzzle tem gramaticas de senha por etapa.
  SMALL  = concat->sha256 dos tokens de texto.
  COSMIC = XOR(sha256_individual) dos tokens da pagina  (a795de11...).

`intertwine_attack.py` ja aplicou XOR-of-sha256 SOBRE STRINGS de token e sobre
as 4 senhas de cadeia. NUNCA sobre os ARTEFATOS-BYTES intermediarios. Este
script preenche exatamente essa lacuna: a MESMA familia de gramatica
(XOR-of-sha256 / sha256-of-concat / leitura por seletor do header), mas aplicada
aos bytes de half, better_half, E_C, E_S, keymat SMALL(79B), cc[833:865],
header28 e aos proprios 35 blocos.

Cada chave candidata (32B) passa pelo detector FORTE `strong_oracle_35`:
  - a chave E o privkey do alvo/espelho? (pub == TARGET/MIRROR, ou h160/endereco)
  - decifra os 35 blocos (AES-CBC varios IV + ECB) e varre TODO offset de byte
    procurando privkey raw / hex-ASCII(64) / WIF(base58) / mnemonic BIP39.
  - PKCS7 valido + ASCII, ou presenca de 'Salted__' -> SOFT hit (proxima camada).
"""
from __future__ import annotations

import hashlib
import itertools
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F  # noqa: E402
import oracles as O  # noqa: E402

import base58  # noqa: E402
from coincurve import PublicKey  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402

# ---------------------------------------------------------------- alvos DUROS
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
_XT = TARGET_PUBKEY[1:33]
_YT = int.from_bytes(TARGET_PUBKEY[33:65], "big")
MIRROR_PUBKEY = b"\x04" + _XT + ((P - _YT) % P).to_bytes(32, "big")


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b if isinstance(b, (bytes, bytearray)) else b.encode()).digest()


def _h160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def _addr(h: bytes) -> str:
    payload = b"\x00" + h
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()


def hard_hit(priv32: bytes):
    """Oraculo DURO. None se nao bate; senao ('motivo', hex)."""
    if len(priv32) != 32:
        return None
    n = int.from_bytes(priv32, "big")
    if n == 0 or n >= N:
        return None
    try:
        pk = PublicKey.from_valid_secret(priv32)
    except Exception:
        return None
    unc = pk.format(compressed=False)
    if unc == TARGET_PUBKEY:
        return ("PUBKEY_ALVO", priv32.hex())
    if unc == MIRROR_PUBKEY:
        return ("PUBKEY_ESPELHO", priv32.hex())
    comp = pk.format(compressed=True)
    hu, hc = _h160(unc).hex(), _h160(comp).hex()
    if O.TARGET_H160 in (hu, hc):
        return ("H160_ALVO", priv32.hex())
    if O.PRIZE_ADDR in (_addr(_h160(unc)), _addr(_h160(comp))):
        return ("ENDERECO_PREMIO", priv32.hex())
    return None


def pr(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data)


def valid_pt(d: bytes) -> bool:
    if not d or len(d) % 16:
        return False
    p = d[-1]
    return 1 <= p <= 16 and d.endswith(bytes([p]) * p) and pr(d[:-p]) >= 0.80


_WIF_RE = re.compile(rb"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}")
_HEX_RE = re.compile(rb"[0-9a-fA-F]{64}")
_WORDSET = set(O.WORDLIST)


def _wif_priv(b58: bytes):
    try:
        raw = base58.b58decode(b58)
    except Exception:
        return None
    if len(raw) not in (37, 38) or raw[0] != 0x80:
        return None
    body, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != chk:
        return None
    return body[1:33]


def scan_plaintext(pt: bytes):
    """Varredura FORTE de um plaintext: retorna lista de hits DUROS achados."""
    found = []
    # 1) privkey raw em TODO offset de byte
    for j in range(0, len(pt) - 31):
        h = hard_hit(pt[j:j + 32])
        if h:
            found.append(("raw_off%d" % j, h))
    # 2) hex-ASCII de 64 chars
    for m in _HEX_RE.finditer(pt):
        try:
            h = hard_hit(bytes.fromhex(m.group().decode()))
        except Exception:
            h = None
        if h:
            found.append(("hexascii", h))
    # 3) WIF base58
    for m in _WIF_RE.finditer(pt):
        pk = _wif_priv(m.group())
        if pk:
            h = hard_hit(pk)
            if h:
                found.append(("wif", h))
    # 4) BIP39 mnemonic (janelas de palavras validas)
    words = re.findall(r"[a-z]+", pt.decode("latin-1").lower())
    words = [w for w in words if w in _WORDSET]
    for length in (12, 15, 18, 21, 24):
        for i in range(0, len(words) - length + 1):
            res = O.check_mnemonic(words[i:i + length])
            if res and res.get("match"):
                found.append(("bip39", res))
    return found


def strong_oracle_35(label, key, blocks, ivs, hits, softs):
    """Detector forte para uma chave de 32B contra os 35 blocos."""
    if len(key) != 32:
        return
    # a propria chave e o privkey?
    h = hard_hit(key)
    if h:
        hits.append(f"!!! {label} == {h[0]} priv={h[1]}")
        print(hits[-1])
    # AES-CBC em varios IV + ECB
    trials = [("cbc_" + nm, AES.new(key, AES.MODE_CBC, iv)) for nm, iv in ivs]
    for nm, cipher in trials:
        try:
            pt = cipher.decrypt(blocks)
        except ValueError:
            continue
        if valid_pt(pt):
            softs.append(f"SOFT {label}/{nm}: PKCS7+ASCII {pt[:48].hex()}")
            print(softs[-1])
        if b"Salted__" in pt:
            softs.append(f"SOFT {label}/{nm}: contem Salted__ @ {pt.find(b'Salted__')}")
            print(softs[-1])
        for how, h in scan_plaintext(pt):
            hits.append(f"!!! {label}/{nm}/{how} -> {h}")
            print(hits[-1])
    # ECB por bloco de 32B (cada bloco = 2 blocos AES de 16)
    try:
        ecb = AES.new(key, AES.MODE_ECB)
        pt = ecb.decrypt(blocks)
        if valid_pt(pt):
            softs.append(f"SOFT {label}/ecb: PKCS7+ASCII {pt[:48].hex()}")
            print(softs[-1])
        if b"Salted__" in pt:
            softs.append(f"SOFT {label}/ecb: contem Salted__")
            print(softs[-1])
        for how, h in scan_plaintext(pt):
            hits.append(f"!!! {label}/ecb/{how} -> {h}")
            print(hits[-1])
    except ValueError:
        pass


def xorr(parts):
    x = bytearray(32)
    for p in parts:
        for i in range(32):
            x[i] ^= p[i]
    return bytes(x)


def banner(t):
    print("=" * 66)
    print(t)
    print("=" * 66)


def main():
    R = F.reproduce()
    half = R["half"]
    bh = R["better_half"]
    cosmic = R["cosmic"]
    chain1 = R["chain1"]
    chain2 = R["chain2"]
    blocks = R["blocks"]
    header = R["header"]
    header28 = header[2:30]
    E_C = chain1[64:79]           # 15B  38d4f4c9...
    E_S = chain2[64:79]           # 15B  740a25de...
    E_B = cosmic[64:66]           # 2B   59cc
    keymat = chain1               # 79B  1449a217...
    cc_slice = cosmic[833:865]    # 32B
    c4pw = F.CHAIN4_PASSWORD      # 32B  E_C||E_S||E_B

    # sanity: artefatos batem com o checkpoint da cadeia
    assert sha(half).hex().startswith("b9736fe0")
    assert sha(bh).hex().startswith("37ec1d87")
    assert sha(keymat).hex().startswith("1449a217")
    assert E_C.hex().startswith("38d4f4c9") and E_S.hex().startswith("740a25de")
    assert E_B.hex() == "59cc" and c4pw == E_C + E_S + E_B
    assert len(blocks) == 35 * 32 and header[:2] == b"+-" and header[30] == 0x37

    ivs = [
        ("iv0", b"\x00" * 16),
        ("hdr0", header[:16]),
        ("hdr_last", header[15:31]),
        ("h28", header28[:16]),
        ("half", half[:16]),
        ("bh", bh[:16]),
    ]
    hits, softs = [], []

    def run(label, key):
        strong_oracle_35(label, key, blocks, ivs, hits, softs)

    counts = {}

    # ---- Familia 1: half x better_half -------------------------------------
    banner("FAMILIA 1: half x better_half")
    f1 = {
        "1.xor_sha(half,bh)": xorr([sha(half), sha(bh)]),
        "1.sha(half||bh)": sha(half + bh),
        "1.sha(bh||half)": sha(bh + half),
    }
    for lbl, k in f1.items():
        run(lbl, k)
    counts["F1"] = len(f1)

    # ---- Familia 2: XOR(sha) subsets 2..4 de {half,bh,E_C,E_S} --------------
    banner("FAMILIA 2: XOR(sha) subsets 2..4 de {half, bh, E_C, E_S}")
    base2 = [("half", half), ("bh", bh), ("E_C", E_C), ("E_S", E_S)]
    n2 = 0
    for r in (2, 3, 4):
        for combo in itertools.combinations(base2, r):
            lbl = "2.xorsha[" + "+".join(n for n, _ in combo) + "]"
            run(lbl, xorr([sha(b) for _, b in combo]))
            n2 += 1
    counts["F2"] = n2

    # ---- Familia 3: XOR(sha) subsets de {keymat79, cc[833:865], header28} ---
    banner("FAMILIA 3: XOR(sha) subsets de {keymat79, cc[833:865], header28}")
    base3 = [("keymat79", keymat), ("cc833", cc_slice), ("h28", header28)]
    n3 = 0
    for r in (1, 2, 3):
        for combo in itertools.combinations(base3, r):
            lbl = "3.xorsha[" + "+".join(n for n, _ in combo) + "]"
            run(lbl, xorr([sha(b) for _, b in combo]))
            n3 += 1
    counts["F3"] = n3

    # ---- Familia 4: sha256(concat) das mesmas listas, varias ordens ---------
    banner("FAMILIA 4: sha256(concat), permutacoes")
    n4 = 0
    for perm in itertools.permutations(base2):
        lbl = "4.sha(" + "||".join(n for n, _ in perm) + ")"
        run(lbl, sha(b"".join(b for _, b in perm)))
        n4 += 1
    for perm in itertools.permutations(base3):
        lbl = "4.sha(" + "||".join(n for n, _ in perm) + ")"
        run(lbl, sha(b"".join(b for _, b in perm)))
        n4 += 1
    counts["F4"] = n4

    # ---- Familia 5: header28 como seletor (7 grupos x 4 bytes) --------------
    banner("FAMILIA 5: header28 = 7 grupos x 4 seletores -> selecao no XOR")
    # pools de 4 artefatos que os 4 bits/sinais de cada grupo selecionam
    pools = {
        "core": [sha(half), sha(bh), sha(E_C), sha(E_S)],
        "chainpw": [sha(F.FULL69.encode()) if hasattr(F, "FULL69") else sha(chain1),
                    sha(F.CHAIN2_WIF), sha(F.COSMIC_PASSWORD), sha(c4pw)],
    }
    n5 = 0
    for pname, pool in pools.items():
        groups = [header28[i * 4:(i + 1) * 4] for i in range(7)]  # 7 grupos de 4 bytes
        # sinal (bit alto) de cada byte do grupo -> 4-bit selector sobre o pool
        per_group_keys = []
        for gi, g in enumerate(groups):
            sel = [pool[bi] for bi in range(4) if g[bi] & 0x80]
            if sel:
                k = xorr(sel)
                per_group_keys.append(k)
                run(f"5.{pname}.g{gi}.sign", k)
                n5 += 1
        # XOR combinado de todos os grupos
        if per_group_keys:
            run(f"5.{pname}.all_groups.sign", xorr(per_group_keys))
            n5 += 1
        # leitura alternativa: nibble alto de cada byte (par/impar) como seletor
        for gi, g in enumerate(groups):
            sel = [pool[bi] for bi in range(4) if (g[bi] >> 4) & 1]
            if sel:
                run(f"5.{pname}.g{gi}.nibble", xorr(sel))
                n5 += 1
    counts["F5"] = n5

    # ---- Familia 6: XOR(sha) dos 35 blocos em janelas + sha256 disso --------
    banner("FAMILIA 6: XOR(sha/raw) dos 35 blocos em janelas")
    blk = [blocks[i * 32:(i + 1) * 32] for i in range(35)]

    def primes_below(n):
        return [x for x in range(2, n) if all(x % d for d in range(2, int(x ** 0.5) + 1))]

    windows = {
        "all": list(range(35)),
        "first7": list(range(7)),
        "primes": primes_below(35),
    }
    n6 = 0
    for wname, idx in windows.items():
        xs = xorr([sha(blk[i]) for i in idx])   # XOR de sha256 dos blocos
        xr = xorr([blk[i] for i in idx])        # XOR raw dos blocos
        run(f"6.{wname}.xorsha", xs)
        run(f"6.{wname}.xorsha.sha", sha(xs))
        run(f"6.{wname}.xorraw", xr)
        run(f"6.{wname}.xorraw.sha", sha(xr))
        n6 += 4
    counts["F6"] = n6

    # ---- Familia 0: singles derivados (sha256 de cada artefato) -------------
    banner("FAMILIA 0: singles sha256(artefato) (base derivada)")
    singles = {
        "0.sha(half)": sha(half), "0.sha(bh)": sha(bh),
        "0.sha(E_C)": sha(E_C), "0.sha(E_S)": sha(E_S), "0.sha(E_B)": sha(E_B),
        "0.sha(keymat79)": sha(keymat), "0.sha(cc833)": sha(cc_slice),
        "0.sha(h28)": sha(header28), "0.sha(hdr31)": sha(header),
        "0.sha(c4pw)": sha(c4pw), "0.sha(cosmic)": sha(cosmic),
        "0.sha(chain2)": sha(chain2),
    }
    for lbl, k in singles.items():
        run(lbl, k)
    counts["F0"] = len(singles)

    # ---- relatorio ----------------------------------------------------------
    banner("RESUMO")
    total = sum(counts.values())
    for fam in ("F0", "F1", "F2", "F3", "F4", "F5", "F6"):
        print(f"  {fam}: {counts.get(fam, 0)} chaves")
    print(f"  TOTAL de chaves testadas: {total}")
    print(f"  HITS DUROS: {len(hits)}   SOFT hits: {len(softs)}")
    if hits:
        print("\n  >>> HITS DUROS:")
        for h in hits:
            print("   ", h)
    if softs:
        print("\n  >>> SOFT hits (candidatos a proxima camada):")
        for s in softs:
            print("   ", s)
    if not hits and not softs:
        print("\n  NEGATIVO TOTAL — a 'terceira gramatica sobre artefatos' esta")
        print("  FECHADA sob o detector forte (alvo+espelho, raw/hex/WIF/BIP39,")
        print("  todos os offsets, CBC 6 IVs + ECB).")


if __name__ == "__main__":
    main()
