# -*- coding: utf-8 -*-
"""Ataque bounded: interpretar o header BTCSEED como BIP32 "Bitcoin seed".

Hipoteses novas cobertas:

1. O Bifid de periodo 570 entrelaca duas metades de 285 simbolos. Emparelhar
   essas metades antes de converter a-i para hex/base-9 nao foi coberto pelos
   ataques que converteram o FAED linear.
2. Das 104 posicoes primas (1-based) do BIF completo, 103 sao B/C/D/E; a unica
   excecao e T na posicao 2. Zerar esse caractere produz 104 nibbles hex.
3. B/C/D/E tambem formam um canal natural de dois bits; testamos todas as 24
   ordens, sem escolher a que melhor pontua.
4. BTCSEED pode nomear a derivacao BIP32 padrao:
   HMAC-SHA512(key=b"Bitcoin seed", data=seed), cujo IL e uma privkey de 32 B.

Nao ha busca de senha nem scorer. Um resultado so e SOLVE se ``check_privkey``
reproduzir o endereco-premio/h160-alvo.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os

from bip_utils import Bip32Secp256k1

import dsl
import oracles as O


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "_work", "btcseed_standard_attack.json")
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    return all(value % divisor for divisor in range(2, int(value**0.5) + 1))


def int_bytes(digits: list[int], base: int) -> bytes:
    value = 0
    for digit in digits:
        value = value * base + digit
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def pack_bits(bits: list[int]) -> bytes:
    padding = (-len(bits)) % 8
    value = 0
    for bit in bits + [0] * padding:
        value = (value << 1) | bit
    return value.to_bytes((len(bits) + padding) // 8, "big")


def bip32_master(seed: bytes) -> tuple[bytes, bytes]:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def decode_wif(candidate: bytes) -> bytes | None:
    """Return the 32-byte secret only for a valid mainnet Base58Check WIF."""
    try:
        text = candidate.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text or any(char not in B58 for char in text):
        return None
    value = 0
    for char in text:
        value = value * 58 + B58.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) not in (37, 38):
        return None
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected or payload[0] != 0x80:
        return None
    if len(payload) == 34 and payload[-1] == 1:
        return payload[1:33]
    if len(payload) == 33:
        return payload[1:33]
    return None


def control() -> None:
    """BIP32 test vector 1, seed 000102...0f."""
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    private, chain = bip32_master(seed)
    assert private.hex() == (
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    )
    assert chain.hex() == (
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    )


def natural_materials() -> dict[str, bytes]:
    sources = O.sources()
    faed = sources["faed"]
    bif = dsl.bif_full()
    rest = bif[7:]
    left, right = faed[:285], faed[285:]

    digit0 = lambda char: ord(char) - ord("a")
    digit1 = lambda char: digit0(char) + 1
    hex1 = lambda text: "".join(str(digit1(char)) for char in text)

    paired_ab = [value for pair in zip(left, right) for value in pair]
    paired_ba = [value for pair in zip(right, left) for value in pair]

    materials = {
        "faed_ascii": faed.encode(),
        "bif_ascii": bif.encode(),
        "bif_rest_ascii": rest.encode(),
        "faed_base9": int_bytes([digit0(char) for char in faed], 9),
        "paired_ab_base9": int_bytes([digit0(char) for char in paired_ab], 9),
        "paired_ba_base9": int_bytes([digit0(char) for char in paired_ba], 9),
        "faed_hex_linear": bytes.fromhex(hex1(faed)),
        "paired_ab_hex": bytes.fromhex(hex1(paired_ab)),
        "paired_ba_hex": bytes.fromhex(hex1(paired_ba)),
    }

    # Prime -> zero -> hex. Mantemos full/rest e indexacao 0/1 para que o
    # negativo nao dependa de uma convencao silenciosa de indice.
    for source_name, text in (("full", bif), ("rest", rest)):
        for index_base in (0, 1):
            selected = "".join(
                char for index, char in enumerate(text) if is_prime(index + index_base)
            )
            # Preserva tambem o pacote de primos sem reinterpretar letras como
            # hex. Em particular, full/idx0 tem 104 simbolos = 2 x 52, o
            # tamanho exato de duas WIFs comprimidas; as duas metades entram
            # separadamente nos testes diretos e BIP32 abaixo.
            raw_label = f"prime_{source_name}_idx{index_base}_raw_ascii"
            materials[raw_label] = selected.encode()
            if len(selected) in (102, 103, 104):
                midpoint = len(selected) // 2
                materials[raw_label + "_left"] = selected[:midpoint].encode()
                materials[raw_label + "_right"] = selected[midpoint:].encode()
                materials[raw_label + "_alternating0"] = selected[0::2].encode()
                materials[raw_label + "_alternating1"] = selected[1::2].encode()
            for mode in ("zero_nonhex", "drop_nonhex"):
                if mode == "zero_nonhex":
                    encoded = "".join(
                        char if char in "ABCDEF" else "0" for char in selected
                    )
                else:
                    encoded = "".join(char for char in selected if char in "ABCDEF")
                if not encoded:
                    continue
                for pad_name, padded in (
                    ("pad_left", encoded if len(encoded) % 2 == 0 else "0" + encoded),
                    ("pad_right", encoded if len(encoded) % 2 == 0 else encoded + "0"),
                ):
                    label = f"prime_{source_name}_idx{index_base}_{mode}_{pad_name}"
                    materials[label] = bytes.fromhex(padded)
                    materials[label + "_ascii"] = encoded.encode()

    # No BIF completo, os primos 1-based (exceto a posicao 2) caem no canal
    # estrutural B/C/D/E. Todas as ordens de 2 bits sao pequenas (24), finitas
    # e evitam escolher um mapeamento a posteriori.
    prime_chars = [char for index, char in enumerate(bif, 1) if is_prime(index)]
    bcde = [char for char in prime_chars if char in "BCDE"]
    assert len(prime_chars) == 104 and len(bcde) == 103
    for order in itertools.permutations("BCDE"):
        mapping = {char: value for value, char in enumerate(order)}
        for position_two in ("drop", "zero"):
            bits = []
            for char in prime_chars:
                if char not in mapping:
                    if position_two == "drop":
                        continue
                    value = 0
                else:
                    value = mapping[char]
                bits.extend((value >> 1, value & 1))
            materials[f"prime_2bit_{''.join(order)}_{position_two}"] = pack_bits(bits)

    return materials


def candidate_forms(material: bytes) -> dict[str, bytes]:
    forms = {
        "raw": material,
        "reverse": material[::-1],
        "sha256": hashlib.sha256(material).digest(),
        "double_sha256": hashlib.sha256(hashlib.sha256(material).digest()).digest(),
        "sha256_hex_ascii": hashlib.sha256(material.hex().encode()).digest(),
    }
    return forms


def common_paths() -> list[str]:
    paths = ["m"]
    paths.extend(f"m/{index}" for index in range(21))
    paths.extend(f"m/{index}'" for index in range(21))
    paths.extend(f"m/44'/0'/0'/0/{index}" for index in range(21))
    paths.extend(f"m/0'/0/{index}" for index in range(21))
    return paths


def run() -> dict:
    control()
    materials = natural_materials()
    paths = common_paths()
    hits = []
    direct_checks = 0
    bip32_checks = 0
    wif_checks = 0
    valid_wifs = 0

    for material_name, material in materials.items():
        if len(material) in (51, 52):
            wif_checks += 1
            private = decode_wif(material)
            if private is not None:
                valid_wifs += 1
                match = O.check_privkey(private)
                if match:
                    hits.append(
                        {
                            "kind": "wif",
                            "material": material_name,
                            "wif": material.decode("ascii"),
                            "match": match,
                        }
                    )
        for form_name, form in candidate_forms(material).items():
            # Material de 32 B e toda janela de 32 B, em ambas as ordens.
            for direction_name, directed in (("forward", form), ("reverse", form[::-1])):
                for offset in range(max(1, len(directed) - 31)):
                    private = directed[offset : offset + 32]
                    if len(private) != 32:
                        continue
                    direct_checks += 1
                    match = O.check_privkey(private)
                    if match:
                        hits.append(
                            {
                                "kind": "direct",
                                "material": material_name,
                                "form": form_name,
                                "direction": direction_name,
                                "offset": offset,
                                "match": match,
                            }
                        )

            # Semantica literal BTCSEED/BIP32: IL, IR e filhos naturais.
            for seed_name, seed in (("form", form), ("form_reverse", form[::-1])):
                if not seed:
                    continue
                master_private, chain_code = bip32_master(seed)
                for part_name, private in (
                    ("master_IL", master_private),
                    ("master_IR", chain_code),
                ):
                    direct_checks += 1
                    match = O.check_privkey(private)
                    if match:
                        hits.append(
                            {
                                "kind": "bip32_master",
                                "material": material_name,
                                "form": form_name,
                                "seed_direction": seed_name,
                                "part": part_name,
                                "match": match,
                            }
                        )

                if not 16 <= len(seed) <= 64:
                    # BIP32 recomenda seeds de 128 a 512 bits. O HMAC master
                    # acima continua definido para qualquer tamanho, mas filhos
                    # por biblioteca ficam limitados ao intervalo normativo.
                    continue
                try:
                    root = Bip32Secp256k1.FromSeed(seed)
                except (ValueError, TypeError):
                    continue
                for path in paths:
                    try:
                        node = root if path == "m" else root.DerivePath(path[2:])
                        private = node.PrivateKey().Raw().ToBytes()
                    except (ValueError, TypeError):
                        continue
                    bip32_checks += 1
                    match = O.check_privkey(private)
                    if match:
                        hits.append(
                            {
                                "kind": "bip32_child",
                                "material": material_name,
                                "form": form_name,
                                "seed_direction": seed_name,
                                "path": path,
                                "match": match,
                            }
                        )

    report = {
        "control_bip32_vector_1": True,
        "materials": len(materials),
        "paths_per_normative_seed": len(paths),
        "direct_checks": direct_checks,
        "bip32_child_checks": bip32_checks,
        "wif_checks": wif_checks,
        "valid_wifs": valid_wifs,
        "hits": hits,
        "solve": bool(hits),
    }
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return report


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
