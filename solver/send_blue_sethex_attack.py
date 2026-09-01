# -*- coding: utf-8 -*-
"""Ataque à instrução `SEND THE BLUE TO SET HEX` (checkpoint DBBI/FAED de X).

Trata a leitura publicada `SEND THE BLUE TO SET HEX` como o "first hint" que
fixa o parâmetro da 2ª camada. Operacionaliza o verbo em 5 hipóteses concretas
que NÃO foram cobertas por `blue_net_attack.py` (que já testou as strings-
instrução como senha/chave). Aqui o foco novo é:

  H1  "SET HEX" = decode a-i→dígito→HEX de FAED/DBBI é diretamente um valor hex
      → testado como privkey (alvo/espelho), seed BIP32/BIP39 e chave AES dos 35 blocos.
  H2  "SEND THE BLUE" = usar SÓ as posições/arestas azuis para SELECIONAR os
      caracteres → subsequência azul, decode a-i→hex, testada como privkey/chave.
  H3  cores como VALOR hex direto (0xBE2B9B azul, 0x41D464 amarelo) em usos NÃO
      testados: IV dos 35 blocos, concat repetida até 32B, sha256 das cores.
  H5  a própria string decodificada como senha (variantes) — cobertura + gaps.

H4 (rota/transposição) é discutida no relatório: não é fixável de forma única a
partir do material publicado, então não gera candidato cego.

Oráculos DUROS reutilizados de oracles.py / final_chain.py / blue_net_attack.py:
alvo `04f4d1bbd9…` + espelho, endereço-prêmio, WIF/BIP39, blobs SMALL/COSMIC.
Nada é declarado solução sem bater pubkey-alvo/espelho, endereço, ou plaintext
semântico dos blobs.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O
import final_chain as F
import blue_net_attack as B  # classify_secret, TARGET/MIRROR_PUBKEY, helpers, blue/yellow

from Crypto.Cipher import AES
from bip_utils import Bip44, Bip44Coins, Bip44Changes, Bip32Slip10Secp256k1

# cores provadas na "segunda porta" (ENDGAME.md ~l.270)
BLUE_HEX = "BE2B9B"   # azul=1 (complemento)
YELLOW_HEX = "41D464"  # amarelo=1
BLUE3 = bytes.fromhex(BLUE_HEX)
YELLOW3 = bytes.fromhex(YELLOW_HEX)


def ai_digits(text: str, base_one: bool = True) -> str:
    """a-i → dígito. base_one: a=1..i=9 (método 3.2.2). senão a=0..i=8."""
    off = 96 if base_one else 97
    return "".join(str(ord(c) - off) for c in text)


def hexpad(digitstr: str) -> bytes:
    """Interpreta a string de dígitos como hex; completa nibble ímpar com '0'."""
    s = digitstr if len(digitstr) % 2 == 0 else digitstr + "0"
    return bytes.fromhex(s)


def repeat_to(data: bytes, n: int) -> bytes:
    if not data:
        return b"\x00" * n
    return (data * (n // len(data) + 1))[:n]


# ---------------------------------------------------------------- oráculos
def bip32_seed_hit(seed: bytes) -> dict | None:
    """seed → BIP44 BTC legacy m/44'/0'/{0,1}'/{ext,int}/{0..4} vs PRIZE_ADDR.
    Também tenta a seed como chave-mestra BIP32 direta (seed curto)."""
    if len(seed) < 16:
        return None
    try:
        acct = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    except Exception:
        return None
    for a in range(2):
        for chg in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            ck = acct.Purpose().Coin().Account(a).Change(chg)
            for i in range(5):
                try:
                    addr = ck.AddressIndex(i).PublicKey().ToAddress()
                except Exception:
                    return None
                if addr == O.PRIZE_ADDR:
                    return {"kind": "bip44_seed", "path": f"m/44'/0'/{a}'/{int(chg)}/{i}"}
    return None


def privkey_hits(secret: bytes) -> list[dict]:
    """Oráculo duro para um escalar de 32B: alvo/espelho (pubkey) + endereço."""
    out = []
    if len(secret) != 32:
        return out
    hit = B.classify_secret(secret)  # target / mirror pubkey (04f4d1bbd9…)
    if hit:
        out.append(hit)
    addr = O.check_privkey(secret)  # PRIZE_ADDR / TARGET_H160
    if addr:
        out.append({"kind": "address_match", **addr})
    return out


def scan_35_blocks(label: str, key: bytes, ivs: dict[str, bytes],
                   priv_hits: list, marker_hits: list, pad_hits: list,
                   blocks: bytes) -> None:
    """Decifra os 35 blocos (ECB + CBC c/ vários IV) e roda o scanner de oráculo."""
    if len(key) != 32:
        return
    # ECB
    pt = AES.new(key, AES.MODE_ECB).decrypt(blocks)
    B.scan_decryption(f"{label}:ECB", pt, priv_hits, marker_hits)
    up = B.unpad_or_none(pt)
    if up is not None:
        pad_hits.append({"label": f"{label}:ECB", "ratio": round(B.printable_ratio(up), 3),
                         "head": up[:48].hex()})
    for ivn, iv in ivs.items():
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(blocks)
        B.scan_decryption(f"{label}:CBC:{ivn}", pt, priv_hits, marker_hits)
        up = B.unpad_or_none(pt)
        if up is not None:
            pad_hits.append({"label": f"{label}:CBC:{ivn}", "ratio": round(B.printable_ratio(up), 3),
                             "head": up[:48].hex()})


# ---------------------------------------------------------------- materiais
def build_keys() -> dict[str, bytes]:
    src = O.sources()
    dbbi, faed, faednp = src["dbbi"], src["faed"], src["faed_no_prefix"]
    keys: dict[str, bytes] = {}

    def add(label, val):
        if isinstance(val, str):
            val = val.encode()
        if len(val) == 32:
            keys.setdefault(label, val)

    # ---- H1: a-i→dígito→HEX de FAED/DBBI ----
    for name, text in (("faed", faed), ("faednp", faednp), ("dbbi", dbbi)):
        for tag, base_one in (("d1", True), ("d0", False)):
            ds = ai_digits(text, base_one)
            raw = hexpad(ds)                       # dígitos lidos como hex
            add(f"H1:{name}:{tag}:hex[:32]", raw[:32])
            add(f"H1:{name}:{tag}:hex[-32:]", raw[-32:])
            add(f"H1:{name}:{tag}:sha256(digits)", hashlib.sha256(ds.encode()).digest())
        add(f"H1:{name}:sha256(raw)", hashlib.sha256(text.encode()).digest())

    # ---- H2: subsequência AZUL (seleção) → hex ----
    # (a) FAED nas 15 posições azuis (índices lineares 1-based do grid 14x14)
    faed_blue = "".join(faed[p - 1] for p in B.BLUE_POSITIONS if p - 1 < len(faed))
    # (b) letras dbbi nas arestas azuis (15 letras)
    be = B.BLUE_EDGES & set(B.CANONICAL_EDGES)
    dbbi_blue = "".join(s for s, e in zip(dbbi, B.CANONICAL_EDGES) if e in be)
    # (c) FAED nas posições azuis mod 570 (todas as 15 caem <570, igual a 'a')
    for name, seq in (("faed_blue15", faed_blue), ("dbbi_blueedge15", dbbi_blue)):
        ds = ai_digits(seq, True)
        add(f"H2:{name}:sha256(digits)", hashlib.sha256(ds.encode()).digest())
        add(f"H2:{name}:sha256(letters)", hashlib.sha256(seq.encode()).digest())
        raw = hexpad(ds)
        add(f"H2:{name}:hexpad(repeat32)", repeat_to(raw, 32))
    # subsequência amarela também (9 posições) — simétrico ao "SET" (SET~yellow?)
    faed_yellow = "".join(faed[p - 1] for p in B.YELLOW_POSITIONS if p - 1 < len(faed))
    dsy = ai_digits(faed_yellow, True)
    add("H2:faed_yellow9:sha256(digits)", hashlib.sha256(dsy.encode()).digest())

    # ---- H3: cores como VALOR hex ----
    color_mats = {
        "blue_repeat32": repeat_to(BLUE3, 32),
        "yellow_repeat32": repeat_to(YELLOW3, 32),
        "bluepair_repeat32": repeat_to(BLUE3 + YELLOW3, 32),
        "yellowpair_repeat32": repeat_to(YELLOW3 + BLUE3, 32),
        "sha256(blue_raw)": hashlib.sha256(BLUE3).digest(),
        "sha256(yellow_raw)": hashlib.sha256(YELLOW3).digest(),
        "sha256(blue+yellow_raw)": hashlib.sha256(BLUE3 + YELLOW3).digest(),
        "sha256(yellow+blue_raw)": hashlib.sha256(YELLOW3 + BLUE3).digest(),
        "sha256(BE2B9B)": hashlib.sha256(BLUE_HEX.encode()).digest(),
        "sha256(be2b9b)": hashlib.sha256(BLUE_HEX.lower().encode()).digest(),
        "sha256(41D464)": hashlib.sha256(YELLOW_HEX.encode()).digest(),
        "sha256(41d464)": hashlib.sha256(YELLOW_HEX.lower().encode()).digest(),
        "sha256(BE2B9B41D464)": hashlib.sha256((BLUE_HEX + YELLOW_HEX).encode()).digest(),
        "sha256(41D464BE2B9B)": hashlib.sha256((YELLOW_HEX + BLUE_HEX).encode()).digest(),
        # 54/47/101/7 já sabidos como somas — cores como decimais
        "sha256(0xBE2B9B_dec)": hashlib.sha256(str(int(BLUE_HEX, 16)).encode()).digest(),
        "sha256(0x41D464_dec)": hashlib.sha256(str(int(YELLOW_HEX, 16)).encode()).digest(),
    }
    for k, v in color_mats.items():
        add(f"H3:{k}", v)

    # ---- H5: strings-instrução como sha256 (chave AES direta p/ 35 blocos) ----
    for s in ("SENDTHEBLUETOSETHEX", "sendthebluetosethex",
              "SEND THE BLUE TO SET HEX", "send the blue to set hex",
              "SENDTHEBLUENETTOSETHEX", "SETHEX", "SET HEX", "sethex"):
        add(f"H5:sha256({s!r})", hashlib.sha256(s.encode()).digest())

    return keys


def build_passphrases() -> dict[bytes, str]:
    """Senhas p/ blobs salted SMALL/COSMIC (EVP). Foco: cores + faed-hex (novo)."""
    src = O.sources()
    faed, dbbi = src["faed"], src["dbbi"]
    pw: dict[bytes, str] = {}

    def add(label, val):
        if isinstance(val, str):
            val = val.encode()
        pw.setdefault(val, label)

    # cores como passphrase crua (uso não coberto por blue_net)
    for s in (BLUE_HEX, BLUE_HEX.lower(), YELLOW_HEX, YELLOW_HEX.lower(),
              BLUE_HEX + YELLOW_HEX, YELLOW_HEX + BLUE_HEX,
              "0x" + BLUE_HEX, "0x" + YELLOW_HEX):
        add(f"color_raw:{s}", s)
        add(f"color_sha256hex:{s}", hashlib.sha256(s.encode()).hexdigest())
    # faed/dbbi decode → dígitos como passphrase (novo)
    for name, text in (("faed", faed), ("dbbi", dbbi)):
        ds = ai_digits(text, True)
        add(f"{name}_digits_raw", ds)
        add(f"{name}_digits_sha256hex", hashlib.sha256(ds.encode()).hexdigest())
    return pw


def _xor_to(a: bytes, b: bytes, n: int) -> bytes:
    """XOR ciclando ambos os operandos até n bytes (composição 'yinyang')."""
    return bytes(repeat_to(a, n)[i] ^ repeat_to(b, n)[i] for i in range(n))


def build_yinyang_keys() -> dict[str, bytes]:
    """H6: os marcadores são VERIFICADORES; a chave real viria de uma composição
    binária adicional ('yinyang' que Jrk citou). Testa duplas concretas do
    endgame (HALF/BETTER HALF, cores complementares, seleção azul vs set-hex).
    Reframe dos solvers seniores (gnosis id 64922, Vasilis Dragon id 65629)."""
    r = F.reproduce()
    half, bh, tail = r["half"], r["better_half"], r["matrix_tail"]
    src = O.sources()
    blue_raw = bytes(B.BLUE_POSITIONS)          # 15B — "the blue"
    yellow_raw = bytes(B.YELLOW_POSITIONS)      # 9B
    hexset = b"0123456789abcdef"                # "set hex" (16B)
    keys: dict[str, bytes] = {}

    def add(label, v):
        if len(v) == 32:
            keys.setdefault(label, v)

    # (1) as duas metades da Cosmic Duality — a leitura mais literal de yinyang
    add("H6:half^better_half", bytes(a ^ b for a, b in zip(half, bh)))
    add("H6:half+better_half_mod256", bytes((a + b) & 0xFF for a, b in zip(half, bh)))
    add("H6:sha256(half||better_half)", hashlib.sha256(half + bh).digest())
    add("H6:sha256(better_half||half)", hashlib.sha256(bh + half).digest())
    add("H6:half^tail_rep", _xor_to(half, tail, 32))
    # (2) cores complementares (blue^yellow=FFFFFF) — mas via posições/rails
    add("H6:bluepos^yellowpos", _xor_to(blue_raw, yellow_raw, 32))
    add("H6:sha256(bluepos^yellowpos)", hashlib.sha256(_xor_to(blue_raw, yellow_raw, 15)).digest())
    # (3) "SEND THE BLUE" (seleção azul) yinyang "SET HEX" (set completo)
    add("H6:bluepos^hexset", _xor_to(blue_raw, hexset, 32))
    add("H6:sha256(bluepos^hexset)", hashlib.sha256(_xor_to(blue_raw, hexset, 16)).digest())
    add("H6:sha256(blueraw||hexset)", hashlib.sha256(blue_raw + hexset).digest())
    # (4) as duas rails decodificadas (base vs blue) como bytes A-Z, XOR
    base = B.EXPECTED_RAILS["base"].encode()
    bluer = B.EXPECTED_RAILS["blue"].encode()
    yelr = B.EXPECTED_RAILS["yellow"].encode()
    add("H6:sha256(base_rail^blue_rail)", hashlib.sha256(_xor_to(base, bluer, len(base))).digest())
    add("H6:sha256(base_rail^yellow_rail)", hashlib.sha256(_xor_to(base, yelr, len(base))).digest())
    add("H6:sha256(blue_rail^yellow_rail)", hashlib.sha256(_xor_to(bluer, yelr, len(base))).digest())
    return keys, {"half": half, "better_half": bh}


def build_eie_keys() -> dict[str, bytes]:
    """H7: lead EI E (id 66216). BLUENET as hex = 061119242f3a5863767e81a3aab9c1
    (15B); único dígito hex faltante = 'd' (0x0d); 'd' em DBBI soma 178 → último
    amarelo. Testa o hex de 15B e completações com 'd' como material de chave.
    (blue_net_attack.py já cobre sha256/repeat16 de blue16 e do set completo;
    aqui adiciono as formas de 32B diretas não cobertas.)"""
    braw = bytes(B.BLUE_POSITIONS)  # 15B = 061119242f3a5863767e81a3aab9c1
    keys: dict[str, bytes] = {}

    def add(label, v):
        if len(v) == 32:
            keys.setdefault(label, v)

    add("H7:blue15_rpad0_32", braw + b"\x00" * 17)
    add("H7:blue15_lpad0_32", b"\x00" * 17 + braw)
    add("H7:blue15+0d_rpad0_32", braw + b"\x0d" + b"\x00" * 16)   # completa com 'd'
    add("H7:blue16(+0d)_repeat32", repeat_to(braw + b"\x0d", 32))
    add("H7:sha256(blue15+0d)", hashlib.sha256(braw + b"\x0d").digest())
    add("H7:sha256(0d+blue15)", hashlib.sha256(b"\x0d" + braw).digest())
    # 'd' soma 178 em DBBI → índice do último amarelo; usa 178 como material
    add("H7:sha256(blue15||178)", hashlib.sha256(braw + b"\xb2").digest())  # 178=0xb2
    add("H7:hexset0d_repeat32", repeat_to(b"0123456789abcdef", 32))
    return keys


def color_ivs() -> dict[str, bytes]:
    """IVs derivados das cores (16B) + IVs de referência p/ os 35 blocos."""
    r = F.reproduce()
    return {
        "zero": bytes(16),
        "header_left": r["header"][2:18],
        "blue_repeat16": repeat_to(BLUE3, 16),
        "yellow_repeat16": repeat_to(YELLOW3, 16),
        "bluepair_repeat16": repeat_to(BLUE3 + YELLOW3, 16),
        "blue+yellow_lpad16": (b"\x00" * 10 + BLUE3 + YELLOW3),
    }


# ---------------------------------------------------------------- main
def main() -> int:
    chain = F.reproduce()
    blocks = chain["blocks"]
    assert len(blocks) == 35 * 32

    keys = build_keys()
    yinyang, halves = build_yinyang_keys()
    keys.update(yinyang)
    keys.update(build_eie_keys())
    passphrases = build_passphrases()
    ivs = color_ivs()

    priv_hits: list = []
    marker_hits: list = []
    pad_hits: list = []
    seed_hits: list = []
    salted_semantic: list = []

    # 1) chaves diretas: privkey + BIP32 seed + AES 35 blocos
    for label, key in keys.items():
        for h in privkey_hits(key):
            priv_hits.append({"label": f"direct:{label}", **h})
        sh = bip32_seed_hit(key)
        if sh:
            seed_hits.append({"label": f"seed32:{label}", **sh})
        scan_35_blocks(f"blocks:{label}", key, ivs, priv_hits, marker_hits, pad_hits, blocks)

    # 1a) as duas metades já decodificadas (HALF/BETTER HALF) como privkey direta
    for name, v in halves.items():
        for h in privkey_hits(v):
            priv_hits.append({"label": f"halfdirect:{name}", **h})

    # 1b) seeds mais longos (285B hex de faed) → BIP32
    src = O.sources()
    for name, text in (("faed", src["faed"]), ("faednp", src["faed_no_prefix"])):
        raw = hexpad(ai_digits(text, True))
        sh = bip32_seed_hit(raw)
        if sh:
            seed_hits.append({"label": f"seedlong:{name}:{len(raw)}B", **sh})

    # 2) passphrases → blobs salted SMALL/COSMIC (oráculo aes_open, ascii>=0.90)
    for raw, label in passphrases.items():
        for h in O.aes_open(raw):
            salted_semantic.append({"label": label, **h})

    report = {
        "script": "solver/send_blue_sethex_attack.py",
        "counts": {"keys": len(keys), "passphrases": len(passphrases), "ivs": len(ivs),
                   "aes_per_key": 1 + len(ivs)},
        "colors": {"blue": BLUE_HEX, "yellow": YELLOW_HEX},
        "key_labels": sorted(keys),
        "hard_oracle_results": {
            "private_key_hits": priv_hits,          # alvo/espelho/endereço
            "bip32_seed_hits": seed_hits,           # PRIZE_ADDR via BIP44
            "pubkey_marker_hits": marker_hits,      # bytes do pubkey no plaintext dos blocos
            "aes35_pkcs7_padding_hits": pad_hits,   # padding válido (ruído se ratio baixo)
            "salted_semantic_hits": salted_semantic,  # SMALL/COSMIC abriram ascii>=0.90
        },
        "verdict": (
            "PRIVATE_KEY_OR_ADDRESS_HIT" if (priv_hits or seed_hits) else
            "SEMANTIC_BLOB_OPEN" if salted_semantic else
            "PUBKEY_MARKER_IN_BLOCKS" if marker_hits else
            "NO_HARD_ORACLE_HIT"
        ),
    }
    out = Path(__file__).resolve().parents[1] / "_work" / "send_blue_sethex_attack.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"keys={len(keys)} passphrases={len(passphrases)} ivs={len(ivs)}")
    print(f"priv/addr hits : {len(priv_hits)}")
    print(f"bip32 seed hits: {len(seed_hits)}")
    print(f"pubkey markers : {len(marker_hits)}")
    print(f"aes35 padding  : {len(pad_hits)} (ratios: "
          f"{sorted({h['ratio'] for h in pad_hits}) if pad_hits else '—'})")
    print(f"salted semantic: {len(salted_semantic)}")
    print("verdict        :", report["verdict"])
    print("report         :", out)
    return 0 if not (priv_hits or seed_hits) else 2


def _selfcheck() -> None:
    """ponytail: caminho money/cripto — um check que quebra se a lógica quebrar."""
    # a-i→dígito base-1 é o método 3.2.2; "faed" precisa decodificar 6154.
    assert ai_digits("faed", True) == "6154", ai_digits("faed", True)
    assert ai_digits("a", False) == "0" and ai_digits("i", True) == "9"
    # oráculo duro reconhece a chave-alvo quando (e só quando) ela aparece.
    kat = B.classify_secret(hashlib.sha256(b"nope").digest())
    assert kat is None
    # hexpad de dígitos 1-9 sempre produz bytes válidos.
    assert hexpad("6154") == bytes.fromhex("6154")
    # IV/keys têm os tamanhos esperados.
    assert len(repeat_to(BLUE3, 16)) == 16 and len(repeat_to(BLUE3, 32)) == 32


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
        print("selfcheck OK")
        raise SystemExit(0)
    raise SystemExit(main())
