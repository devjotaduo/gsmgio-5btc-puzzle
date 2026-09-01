# -*- coding: utf-8 -*-
"""A3 — RELEITURAS INTERNAS INEDITAS (Fase 1.1-1.3), 3 hipoteses falsificaveis.

Oraculo DUPLO por candidato de 32B:
  (1) O.check_privkey(cand)      -> endereco-premio / h160-alvo (comp+uncomp)
  (2) S.detect(cand, label, R)   -> keyself==pub ALVO/ESPELHO  (privkey direta)
                                    + decifra os 35 blocos (CBC 6 IV + ECB) e
                                      varre TODO offset: privkey raw / hex-ASCII /
                                      WIF / BIP39. (cand como CHAVE AES)
Assim cada candidato e testado ao mesmo tempo como PRIVKEY e como CHAVE AES.

H1: header28 = os 28B centrais do header ("+-"+28B+"7", 31B) sao a PROPRIA
    privkey crua, completada a 32B (pad 00, molduras "+-"/"7"/marcadores) ou
    sha256(header...). Alvo do hint 2024: "Regular Bitcoin Private key".

H2: gramatica concat->sha256 do SMALL aplicada aos PLAINTEXTS dos 35 blocos.
    Decifra os blocos com as 5 chaves ja retidas em CBC(6 IV)+ECB; para cada
    plaintext, sha256(pt) e sha256(concat dos pt) -> privkey E chave AES.

H3: XOR-de-sha256 (gramatica Cosmic provada) sobre os PLAINTEXTS de cada etapa
    {chain1 79B, cosmic 1327B, chain4 1151B, matrix half 32B, matrix better_half
    32B}, subsets 2..5 -> cada resultado privkey E chave AES.

Log jsonl em ../_work/a3_rereads_attack.jsonl. Reporta contagem EXATA por H.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F  # noqa: E402
import oracles as O  # noqa: E402
import strong_oracle_35 as S  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_work",
                   "a3_rereads_attack.jsonl")


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def double_oracle(cand: bytes, label: str, R, hard: list, soft: list, logf):
    """Testa `cand` (32B) como PRIVKEY (endereco/pub) e como CHAVE AES (35 blocos).
    Retorna 1 se o candidato foi valido (32B) e testado, 0 caso contrario."""
    if not isinstance(cand, (bytes, bytearray)) or len(cand) != 32:
        return 0
    cand = bytes(cand)
    # (1) privkey -> endereco-premio / h160-alvo
    hp = O.check_privkey(cand)
    if hp:
        rec = {"H": label.split(".")[0], "kind": "check_privkey", "label": label,
               "hit": hp}
        hard.append(rec)
        logf.write(json.dumps(rec) + "\n")
    # (2) detector forte: privkey->pub alvo/espelho (keyself) + AES scan dos blocos
    for h in S.detect(cand, label, R):
        tag = h[0]
        rec = {"H": label.split(".")[0], "kind": "detect", "label": label,
               "tag": tag, "where": h[1], "data": h[2], "extra": h[3]}
        if tag in ("PRIVKEY", "BIP39-ADDR"):
            hard.append(rec)
            logf.write(json.dumps(rec) + "\n")
        else:  # SOFT-PKCS7 = so triagem
            soft.append(rec)
    return 1


# --------------------------------------------------------------------------- H1
def build_h1(R):
    """Constroi os candidatos de 32B de H1 a partir do header28 (28B)."""
    header = R["header"]                    # 31B: 2b2d + 28B + 37
    assert header[:2] == b"+-" and header[30] == 0x37 and len(header) == 31
    h28 = header[2:30]                       # 28B centrais
    Z = b"\x00"
    PM = b"+-"       # 2b 2d
    SV = b"7"        # 37
    cand = {}

    # --- pad 00 (28B -> 32B, +4 bytes) ---
    cand["H1.pad00_pre"] = Z * 4 + h28
    cand["H1.pad00_suf"] = h28 + Z * 4
    cand["H1.pad00_split"] = Z * 2 + h28 + Z * 2

    # --- header inteiro (31B "+-"+h28+"7") + 1 byte -> 32B ---
    cand["H1.hdr31_suf00"] = header + Z
    cand["H1.hdr31_pre00"] = Z + header
    cand["H1.hdr31_suf37"] = header + SV
    cand["H1.hdr31_pre2b"] = b"+" + header      # +byte '2b' na frente

    # --- header28+"7" (29B) + 3 pad 00 ---
    cand["H1.h28_7_suf00"] = h28 + SV + Z * 3
    cand["H1.h28_7_pre00"] = Z * 3 + h28 + SV

    # --- header28 + 1 marcador (29B) + 3 pad 00, e simetrico ---
    for mk, name in ((b"\x2b", "2b"), (b"\x2d", "2d"), (b"\x37", "37")):
        cand[f"H1.h28+{name}_suf00"] = h28 + mk + Z * 3
        cand[f"H1.{name}+h28_pre00"] = Z * 3 + mk + h28

    # --- "+-"+h28+"7" com molduras completas variando o byte final ---
    cand["H1.pm_h28_7_z"] = PM + h28 + SV + Z      # 2b2d+28+37+00 = 32
    cand["H1.z_pm_h28_7"] = Z + PM + h28 + SV      # 00+2b2d+28+37 = 32

    # --- sha256 (byte-forms) ---
    cand["H1.sha(h28)"] = sha(h28)
    cand["H1.sha(header31)"] = sha(header)          # = sha("+-"+h28+"7")
    cand["H1.sha(h28+7)"] = sha(h28 + SV)
    cand["H1.sha(pm+h28)"] = sha(PM + h28)

    # --- sha256 (hex-string-forms: header lido como texto) ---
    hx = h28.hex().encode()
    cand["H1.sha(hex(h28))"] = sha(hx)
    cand["H1.sha('+-'+hex(h28)+'7')"] = sha(b"+-" + hx + b"7")

    # dedup por valor mantendo rotulo
    seen, out = {}, {}
    for lbl, v in cand.items():
        if v not in seen:
            seen[v] = lbl
            out[lbl] = v
    return out


# --------------------------------------------------------------------------- H2
def h2_plaintexts(R):
    """Decifra os 35 blocos (1120B) com as 5 chaves retidas em CBC(6 IV)+ECB."""
    body = R["blocks"]
    keys = {
        "COSMIC_PW": F.COSMIC_PASSWORD,
        "sha(COSMIC_PW)": sha(F.COSMIC_PASSWORD),
        "half": R["half"],
        "better_half": R["better_half"],
        "CHAIN4_PW": F.CHAIN4_PASSWORD,
    }
    for kname, k in keys.items():
        assert len(k) == 32, f"{kname} nao e 32B"
    ivs = S._iv_list(R)  # [(nome, iv16), ...] os 6 IV naturais
    pts = {}
    for kname, k in keys.items():
        for ivn, iv in ivs:
            pts[f"{kname}/cbc:{ivn}"] = AES.new(k, AES.MODE_CBC, iv).decrypt(body)
        ecb = b"".join(AES.new(k, AES.MODE_ECB).decrypt(body[i * 32:(i + 1) * 32])
                       for i in range(35))
        pts[f"{kname}/ecb"] = ecb
    return pts


# --------------------------------------------------------------------------- H3
def h3_plaintexts(R):
    """Os PLAINTEXTS completos de cada etapa da cadeia."""
    return {
        "chain1_79": R["chain1"],
        "cosmic_1327": R["cosmic"],
        "chain4_1151": R["chain4"],
        "half_32": R["half"],
        "better_half_32": R["better_half"],
    }


def main():
    R = F.reproduce()
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    hard, soft = [], []
    counts = {}
    with open(LOG, "w", encoding="utf-8") as logf:
        # ---------------- H1 ----------------
        h1 = build_h1(R)
        n1 = 0
        for lbl, cand in h1.items():
            n1 += double_oracle(cand, lbl, R, hard, soft, logf)
        counts["H1"] = n1

        # ---------------- H2 ----------------
        pts = h2_plaintexts(R)
        n2 = 0
        concat_all = b""
        for pl_lbl, pt in pts.items():
            concat_all += pt
            n2 += double_oracle(sha(pt), f"H2.sha({pl_lbl})", R, hard, soft, logf)
        # sha256 do concat de TODOS os plaintexts
        n2 += double_oracle(sha(concat_all), "H2.sha(concat_all)", R, hard, soft, logf)
        # sha256 do concat por-chave (agrupando os 7 modos de cada chave)
        by_key = {}
        for pl_lbl, pt in pts.items():
            by_key.setdefault(pl_lbl.split("/")[0], b"")
            by_key[pl_lbl.split("/")[0]] += pt
        for kname, blob in by_key.items():
            n2 += double_oracle(sha(blob), f"H2.sha(concat[{kname}])", R, hard, soft, logf)
        counts["H2"] = n2

        # ---------------- H3 ----------------
        p3 = h3_plaintexts(R)
        digests = {name: sha(pt) for name, pt in p3.items()}
        items = list(digests.items())
        n3 = 0
        for r in (2, 3, 4, 5):
            for combo in itertools.combinations(items, r):
                x = bytearray(32)
                for _, d in combo:
                    for i in range(32):
                        x[i] ^= d[i]
                lbl = "H3.xorsha[" + "+".join(n for n, _ in combo) + "]"
                n3 += double_oracle(bytes(x), lbl, R, hard, soft, logf)
        counts["H3"] = n3

    # ------------- relatorio -------------
    print("=" * 70)
    print("A3 — RELEITURAS INTERNAS (H1 header-privkey / H2 pt-concat / H3 pt-xor)")
    print("=" * 70)
    for h in ("H1", "H2", "H3"):
        print(f"  {h}: {counts[h]} chaves testadas (oraculo duplo)")
    print(f"  TOTAL: {sum(counts.values())} chaves")
    print(f"  HITS DUROS (byte-exatos): {len(hard)}")
    print(f"  SOFT (PKCS7, so triagem): {len(soft)}")
    if hard:
        print("\n  >>> HITS DUROS:")
        for h in hard:
            print("   ", json.dumps(h))
    else:
        print("\n  NEGATIVO TOTAL — H1, H2 e H3 FECHADAS sob o oraculo forte")
        print("  (privkey->pub alvo/espelho, privkey->endereco/h160,")
        print("   AES 35 blocos CBC 6 IV + ECB, scan byte-a-byte raw/hex/WIF/BIP39).")
    if soft:
        print(f"\n  ({len(soft)} SOFT-PKCS7 registrados em {LOG})")
    print(f"\n  log: {LOG}")


if __name__ == "__main__":
    main()
