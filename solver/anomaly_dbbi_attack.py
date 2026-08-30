# -*- coding: utf-8 -*-
"""Teste falsificável da hipótese ``anomalia nas duas pontas``.

Contrato da hipótese:

* ``dbbi`` é lido como uma matriz 7x13 sobre a-i;
* os 11 índices primos coloridos, com FEFEFE=163 nas duas pontas, formam a
  lista de 13 colunas;
* o produto matriz-lista gera sete escalares, alinhados às sete palavras de
  quatro bytes do header e aos sete grupos de cinco blocos do Chain4;
* ``yin-yang`` permite somente sinais naturais: cores opostas, alternância,
  metades opostas e os sinais +/- explícitos do header.

Um resultado só conta se bater a pubkey pública do prêmio ou produzir uma
abertura AES estruturalmente forte. Padding isolado não é solve.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import os
import random
import re

from coincurve import PublicKey
from Crypto.Cipher import AES

import final_chain as F
import oracles as O
from colored_prime_dbbi_attack import bifid_decrypt, keyword_square
from scorer import Scorer


OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "_work", "anomaly_dbbi_attack.json")
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
ANOMALY = 163
PRIME_INDICES = (7, 23, 31, 47, 71, 79, 103, 127, 151, 167, 191)
# Cores dos 11 índices acima, na ordem espiral zero-based.
PRIME_COLORS = "BBBBYYBBYYY"


def sign_patterns() -> dict[str, tuple[int, ...]]:
    patterns: dict[str, tuple[int, ...]] = {
        "all+": (1,) * 13,
        "all-": (-1,) * 13,
        "alternating+": tuple(1 if i % 2 == 0 else -1 for i in range(13)),
        "alternating-": tuple(-1 if i % 2 == 0 else 1 for i in range(13)),
        "halves+": (1,) * 7 + (-1,) * 6,
        "halves-": (-1,) * 7 + (1,) * 6,
        "center0+": (1,) * 6 + (0,) + (-1,) * 6,
        "center0-": (-1,) * 6 + (0,) + (1,) * 6,
    }
    colors = "W" + PRIME_COLORS + "W"
    for polarity, blue_sign in (("BY", 1), ("YB", -1)):
        for ends in ((1, 1), (1, -1), (-1, 1), (-1, -1), (0, 0)):
            signs = []
            for color in colors:
                if color == "B":
                    signs.append(blue_sign)
                elif color == "Y":
                    signs.append(-blue_sign)
                else:
                    signs.append(ends[0] if not signs else ends[1])
            patterns[f"colors-{polarity}-ends{ends[0]:+d}{ends[1]:+d}"] = tuple(signs)
    assert len(patterns) == 18 and all(len(p) == 13 for p in patterns.values())
    return patterns


def hypotheses(dbbi: str) -> list[dict]:
    grid0 = [[ord(char) - ord("a") for char in dbbi[r * 13:(r + 1) * 13]]
             for r in range(7)]
    assert len(dbbi) == 91 and all(len(row) == 13 for row in grid0)
    out = []
    for checksum_name, last_prime in (("raw191", 191), ("checksum190", 190)):
        core = list(PRIME_INDICES)
        core[-1] = last_prime
        original = [ANOMALY, *core, ANOMALY]
        for direction in ("forward", "reverse"):
            values0 = original if direction == "forward" else original[::-1]
            for base_name, matrix in (("a0", grid0),
                                      ("a1", [[v + 1 for v in row] for row in grid0])):
                for list_mode in ("raw", "mod9"):
                    values = values0 if list_mode == "raw" else [v % 9 for v in values0]
                    for sign_name, signs0 in sign_patterns().items():
                        # Cores pertencem aos itens; ao inverter a lista, invertem junto.
                        signs = signs0[::-1] if direction == "reverse" and sign_name.startswith("colors-") else signs0
                        signed = tuple(value * sign for value, sign in zip(values, signs))
                        dots = tuple(sum(row[c] * signed[c] for c in range(13))
                                     for row in matrix)
                        shifted = tuple((grid0[r][c] + signed[c]) % 9
                                        for r in range(7) for c in range(13))
                        out.append({
                            "label": f"{checksum_name}/{direction}/{base_name}/{list_mode}/{sign_name}",
                            "dots": dots,
                            "shifted": shifted,
                        })
    assert len(out) == 288
    return out


def pack_ints(values, width: int, endian: str) -> bytes:
    mask = (1 << (8 * width)) - 1
    return b"".join((value & mask).to_bytes(width, endian) for value in values)


def matrix_materials(hyp: dict, header28: bytes):
    values = hyp["dots"]
    for separator in (b"", b",", b" ", b"|"):
        yield f"dots-dec-{separator!r}", separator.join(str(v).encode() for v in values)
        yield f"dots-abs-{separator!r}", separator.join(str(abs(v)).encode() for v in values)
    for width in (2, 4, 8):
        for endian in ("big", "little"):
            yield f"dots-u{width * 8}-{endian}", pack_ints(values, width, endian)
    yield "dots-byte", bytes(v % 256 for v in values)
    yield "dots-mod9", bytes(v % 9 for v in values)
    yield "dots-bip39", " ".join(O.WORDLIST[v % 2048] for v in values).encode()

    shifted = hyp["shifted"]
    row_major = bytes(ord("a") + value for value in shifted)
    col_major = bytes(row_major[r * 13 + c] for c in range(13) for r in range(7))
    yield "shift-row", row_major
    yield "shift-row-reverse", row_major[::-1]
    yield "shift-column", col_major
    yield "shift-column-reverse", col_major[::-1]
    shifted_rows = [shifted[r * 13:(r + 1) * 13] for r in range(7)]
    row_sums = tuple(sum(row) for row in shifted_rows)
    col_sums = tuple(sum(shifted_rows[r][c] for r in range(7)) for c in range(13))
    for name, sums in (("shift-row-sums", row_sums), ("shift-column-sums", col_sums)):
        yield name + "-decimal", b",".join(str(value).encode() for value in sums)
        yield name + "-bytes", bytes(value % 256 for value in sums)
        yield name + "-u16", pack_ints(sums, 2, "big")
        yield name + "-bip39", " ".join(O.WORDLIST[value] for value in sums).encode()

    for row, value in enumerate(values):
        word = header28[row * 4:(row + 1) * 4]
        packed = pack_ints((value,), 4, "big")
        yield f"row{row}-decimal", str(value).encode()
        yield f"row{row}-word+dot", word + packed
        yield f"row{row}-dot+word", packed + word


def header_keys(hyp: dict, header28: bytes):
    values = hyp["dots"]
    for endian in ("big", "little"):
        words = [int.from_bytes(header28[i * 4:(i + 1) * 4], endian) for i in range(7)]
        # Os sete bits enumeram somente a leitura literal +/- de cada par.
        for mask in range(1 << 7):
            transformed = [
                (word + (value if mask & (1 << i) else -value)) & 0xFFFFFFFF
                for i, (word, value) in enumerate(zip(words, values))
            ]
            raw = pack_ints(transformed, 4, endian)
            yield f"header-{endian}-pm-{mask:02x}", hashlib.sha256(b"+-" + raw + b"7").digest()
        xored = [word ^ (value & 0xFFFFFFFF) for word, value in zip(words, values)]
        raw = pack_ints(xored, 4, endian)
        yield f"header-{endian}-xor", hashlib.sha256(b"+-" + raw + b"7").digest()
        packed_values = pack_ints(values, 4, endian)
        yield f"header-{endian}-append", hashlib.sha256(b"+-" + header28 + packed_values + b"7").digest()
        yield f"header-{endian}-prepend", hashlib.sha256(b"+-" + packed_values + header28 + b"7").digest()


def selected_block_keys(hyp: dict, header28: bytes, blocks: list[bytes]):
    values = hyp["dots"]
    header_words = [int.from_bytes(header28[i * 4:(i + 1) * 4], "big") for i in range(7)]
    layouts = {
        "contiguous": [blocks[r * 5:(r + 1) * 5] for r in range(7)],
        "roundrobin": [blocks[r::7] for r in range(7)],
    }
    selectors = {
        "dot": values,
        "dot+header": tuple(v + h for v, h in zip(values, header_words)),
        "dot-header": tuple(v - h for v, h in zip(values, header_words)),
        "header-dot": tuple(h - v for v, h in zip(values, header_words)),
        "dot-xor-header": tuple((v & 0xFFFFFFFF) ^ h for v, h in zip(values, header_words)),
    }
    for layout_name, groups in layouts.items():
        assert all(len(group) == 5 for group in groups)
        for selector_name, selector in selectors.items():
            for offset in (0, -1):  # zero-based e one-based
                picked = [group[(value + offset) % 5] for group, value in zip(groups, selector)]
                joined = b"".join(picked)
                xored = bytes(a ^ b ^ c ^ d ^ e ^ f ^ g for a, b, c, d, e, f, g in zip(*picked))
                total = sum(int.from_bytes(block, "big") for block in picked) % (1 << 256)
                stem = f"select-{layout_name}/{selector_name}/off{offset}"
                yield stem + "/join", hashlib.sha256(joined).digest()
                yield stem + "/join-reverse", hashlib.sha256(joined[::-1]).digest()
                yield stem + "/xor", xored
                yield stem + "/sum", total.to_bytes(32, "big")


def genesis_140() -> bytes:
    match = re.search(r"6part is (0x[0-9A-Fa-f]+)", O._readme())
    assert match and len(match.group(1)) == 140
    return match.group(1).encode()


def genesis_chunk_attack(header28: bytes, blocks: list[bytes], hypotheses_: list[dict]) -> dict:
    """Testa 140 chars = 35 quartetos, um por bloco final de 32 bytes."""
    natural = [row for row in hypotheses_
               if row["label"] == "checksum190/forward/a1/raw/alternating+"][0]
    dots = natural["dots"]
    genesis = genesis_140()
    source_variants = {"upper": genesis.upper(), "lower": genesis.lower()}
    top: list[tuple[float, str, str]] = []
    soft_hits = []
    hard_hits = []
    seen_families = set()
    families = aes_candidates = direct_tests = 0

    for source_name, source in source_variants.items():
        chunks = [source[i:i + 4] for i in range(0, 140, 4)]
        orders = {
            "direct": chunks,
            "reverse": chunks[::-1],
            "columns-7x5": [chunks[r * 5 + c] for c in range(5) for r in range(7)],
            "columns-5x7": [chunks[r * 7 + c] for c in range(7) for r in range(5)],
        }
        for order_name, ordered0 in orders.items():
            for reverse_chunks in (False, True):
                ordered = [chunk[::-1] for chunk in ordered0] if reverse_chunks else ordered0
                for group_mode in ("contiguous", "roundrobin"):
                    rows = [i // 5 if group_mode == "contiguous" else i % 7 for i in range(35)]
                    for mode in ("sha", "repeat", "header+chunk", "chunk+header",
                                 "dot+chunk", "chunk+dot", "framed"):
                        for dot_polarity in ((1, -1) if "dot" in mode else (1,)):
                            keys = []
                            ivs = []
                            for index, (chunk, row) in enumerate(zip(ordered, rows)):
                                word = header28[row * 4:(row + 1) * 4]
                                dot = str(dots[row] * dot_polarity).encode()
                                if mode == "sha":
                                    key = hashlib.sha256(chunk).digest()
                                elif mode == "repeat":
                                    key = chunk * 8
                                elif mode == "header+chunk":
                                    key = hashlib.sha256(word + chunk).digest()
                                elif mode == "chunk+header":
                                    key = hashlib.sha256(chunk + word).digest()
                                elif mode == "dot+chunk":
                                    key = hashlib.sha256(dot + chunk).digest()
                                elif mode == "chunk+dot":
                                    key = hashlib.sha256(chunk + dot).digest()
                                else:
                                    key = hashlib.sha256(b"+-" + word + chunk + b"7").digest()
                                keys.append(key)
                                ivs.append(word * 4)
                            signature = (tuple(keys), tuple(ivs))
                            if signature in seen_families:
                                continue
                            seen_families.add(signature)
                            family = (f"{source_name}/{order_name}/chunkrev={reverse_chunks}/"
                                      f"{group_mode}/{mode}/dot={dot_polarity:+d}")
                            families += 1
                            for index, key in enumerate(keys):
                                direct_tests += 1
                                if matches_pubkey(key):
                                    hard_hits.append({"kind": "genesis-chunk-direct",
                                                      "family": family, "block": index,
                                                      "private_key": key.hex()})
                            for aes_mode in ("ECB", "CBC-header"):
                                plains = []
                                for index, (key, block, iv) in enumerate(zip(keys, blocks, ivs)):
                                    if aes_mode == "ECB":
                                        plain = AES.new(key, AES.MODE_ECB).decrypt(block)
                                    else:
                                        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(block)
                                    aes_candidates += 1
                                    plains.append(plain)
                                    if matches_pubkey(plain):
                                        hard_hits.append({"kind": f"genesis-chunk-{aes_mode}",
                                                          "family": family, "block": index,
                                                          "private_key": plain.hex()})
                                joined = b"".join(plains)
                                ratio = printable_ratio(joined)
                                label = family + "/" + aes_mode
                                item = (ratio, label, joined[:32].hex())
                                if len(top) < 12:
                                    heapq.heappush(top, item)
                                elif ratio > top[0][0]:
                                    heapq.heapreplace(top, item)
                                if (valid_plaintext(joined) or b"Salted__" in joined
                                        or TARGET_PUBKEY in joined):
                                    soft_hits.append({"label": label, "ratio": round(ratio, 4),
                                                      "head": joined[:80].hex()})
    return {
        "genesis": genesis.decode(),
        "families": families,
        "direct_private_key_tests": direct_tests,
        "aes_candidates": aes_candidates,
        "hard_hits": hard_hits,
        "soft_hits": soft_hits,
        "top_printable": [
            {"ratio": round(ratio, 4), "label": label, "head": head}
            for ratio, label, head in sorted(top, reverse=True)
        ],
    }


def natural_mod26_words(hypotheses_: list[dict]) -> tuple[str, str]:
    by_label = {row["label"]: row["dots"] for row in hypotheses_}
    raw = by_label["raw191/forward/a1/raw/alternating-"]
    corrected = by_label["checksum190/forward/a1/raw/alternating+"]
    def encode(values):
        return "".join(chr(ord("A") + value % 26) for value in values)

    return encode(raw), encode(corrected)


def emergent_word_attack(header28: bytes, body: bytes, hypotheses_: list[dict]) -> dict:
    """Testa somente as palavras literais que emergem: HASH e YIN."""
    raw_word, corrected_word = natural_mod26_words(hypotheses_)
    genesis = genesis_140()
    decoded_genesis = bytes.fromhex(genesis[2:].decode())[::-1]
    tokens = {
        raw_word, corrected_word, "HASH", "YIN", "YANG", "YINYANG",
        "HASHYIN", "YINHASH", "HASH(YIN)", "SHA256(YIN)",
    }
    materials = set()
    for token in tokens:
        for text in (token, token.lower()):
            raw = text.encode()
            materials.update({raw, b"+-" + raw + b"7", header28 + raw, raw + header28,
                              genesis + raw, raw + genesis,
                              decoded_genesis + raw, raw + decoded_genesis})
    raw_mnemonic, corrected_mnemonic = mnemonic_pair()
    mnemonic_materials = {
        raw_mnemonic.encode(), corrected_mnemonic.encode(),
        raw_mnemonic.replace(" ", "").encode(),
        corrected_mnemonic.replace(" ", "").encode(),
        bytes(O._MNEMO.to_entropy(corrected_mnemonic)),
        O._MNEMO.to_seed(corrected_mnemonic),
    }
    for material in mnemonic_materials:
        materials.update({material, b"+-" + material + b"7",
                          header28 + material, material + header28,
                          genesis + material, material + genesis})

    keys = set()
    for material in materials:
        digest = hashlib.sha256(material).digest()
        keys.add(digest)
        keys.add(hashlib.sha256(digest).digest())
        if material:
            keys.add((material * ((32 + len(material) - 1) // len(material)))[:32])

    dual_operands = set()
    for yin_text, yang_text in ((b"YIN", b"YANG"), (b"yin", b"yang")):
        yin = hashlib.sha256(yin_text).digest()
        yang = hashlib.sha256(yang_text).digest()
        yin_int = int.from_bytes(yin, "big")
        yang_int = int.from_bytes(yang, "big")
        dual_operands.update({
            yin, yang,
            bytes(a ^ b for a, b in zip(yin, yang)),
            ((yin_int + yang_int) % (1 << 256)).to_bytes(32, "big"),
            ((yin_int - yang_int) % (1 << 256)).to_bytes(32, "big"),
            ((yang_int - yin_int) % (1 << 256)).to_bytes(32, "big"),
            hashlib.sha256(yin + yang).digest(),
            hashlib.sha256(yang + yin).digest(),
            yin[:16] + yang[16:], yang[:16] + yin[16:],
            yin[16:] + yang[:16], yang[16:] + yin[:16],
            bytes(value for pair in zip(yin[:16], yang[:16]) for value in pair),
        })
    keys.update(dual_operands)

    hard_hits = []
    soft_hits = []
    top = []
    aes_tests = algebra_tests = 0
    ivs = {"zero": bytes(16), "header-first": header28[:16], "header-last": header28[-16:]}
    for key in keys:
        if matches_pubkey(key):
            hard_hits.append({"kind": "word-direct", "private_key": key.hex()})
        decryptions = {"ECB": AES.new(key, AES.MODE_ECB).decrypt(body)}
        decryptions.update({f"CBC-{name}": AES.new(key, AES.MODE_CBC, iv).decrypt(body)
                            for name, iv in ivs.items()})
        for mode, plain in decryptions.items():
            ratio = printable_ratio(plain)
            aes_tests += 35
            for index in range(35):
                candidate = plain[index * 32:(index + 1) * 32]
                if matches_pubkey(candidate):
                    hard_hits.append({"kind": f"word-{mode}", "key": key.hex(),
                                      "block": index, "private_key": candidate.hex()})
            item = (ratio, mode, key.hex(), plain[:32].hex())
            if len(top) < 12:
                heapq.heappush(top, item)
            elif ratio > top[0][0]:
                heapq.heapreplace(top, item)
            if valid_plaintext(plain) or b"Salted__" in plain or TARGET_PUBKEY in plain:
                soft_hits.append({"mode": mode, "key": key.hex(),
                                  "ratio": round(ratio, 4), "head": plain[:80].hex()})

    curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    blocks = [body[i:i + 32] for i in range(0, len(body), 32)]
    for operand in dual_operands:
        operand_int = int.from_bytes(operand, "big")
        for index, block in enumerate(blocks):
            block_int = int.from_bytes(block, "big")
            candidates = {
                "xor": bytes(a ^ b for a, b in zip(block, operand)),
                "add-2^256": ((block_int + operand_int) % (1 << 256)).to_bytes(32, "big"),
                "sub-2^256": ((block_int - operand_int) % (1 << 256)).to_bytes(32, "big"),
                "operand-sub-2^256": ((operand_int - block_int) % (1 << 256)).to_bytes(32, "big"),
                "add-secp": ((block_int + operand_int) % curve_order).to_bytes(32, "big"),
                "sub-secp": ((block_int - operand_int) % curve_order).to_bytes(32, "big"),
                "sha-block+operand": hashlib.sha256(block + operand).digest(),
                "sha-operand+block": hashlib.sha256(operand + block).digest(),
            }
            for mode, candidate in candidates.items():
                algebra_tests += 1
                if matches_pubkey(candidate):
                    hard_hits.append({"kind": "word-block-algebra", "mode": mode,
                                      "operand": operand.hex(), "block": index,
                                      "private_key": candidate.hex()})
    return {
        "raw_mod26": raw_word,
        "corrected_mod26": corrected_word,
        "unique_keys": len(keys),
        "aes_private_key_tests": aes_tests,
        "block_algebra_private_key_tests": algebra_tests,
        "hard_hits": hard_hits,
        "soft_hits": soft_hits,
        "top_printable": [
            {"ratio": round(ratio, 4), "mode": mode, "key": key, "head": head}
            for ratio, mode, key, head in sorted(top, reverse=True)
        ],
    }


def seven_password_attack(header28: bytes, blocks: list[bytes], hypotheses_: list[dict]) -> dict:
    """Sete letras como sete senhas, cada uma aplicada a cinco blocos."""
    raw_word, corrected_word = natural_mod26_words(hypotheses_)
    by_label = {row["label"]: row["dots"] for row in hypotheses_}
    dots = by_label["checksum190/forward/a1/raw/alternating+"]
    tokens = {"HASHYIN", "YINYANG", raw_word, corrected_word}
    seen_families = set()
    direct_seen = set()
    hard_hits = []
    soft_hits = []
    top = []
    families = aes_candidates = aggregate_tests = 0

    for token0 in tokens:
        for token in (token0, token0.lower(), token0[::-1], token0[::-1].lower()):
            for layout in ("contiguous", "roundrobin"):
                rows = [i // 5 if layout == "contiguous" else i % 7 for i in range(35)]
                for key_mode in ("sha-letter", "repeat-letter", "word+letter",
                                 "letter+word", "dot+letter", "letter+dot", "framed"):
                    for polarity in ((1, -1) if "dot" in key_mode else (1,)):
                        row_keys = []
                        row_ivs = []
                        for row, letter in enumerate(token.encode()):
                            char = bytes([letter])
                            word = header28[row * 4:(row + 1) * 4]
                            dot = str(dots[row] * polarity).encode()
                            if key_mode == "sha-letter":
                                key = hashlib.sha256(char).digest()
                            elif key_mode == "repeat-letter":
                                key = char * 32
                            elif key_mode == "word+letter":
                                key = hashlib.sha256(word + char).digest()
                            elif key_mode == "letter+word":
                                key = hashlib.sha256(char + word).digest()
                            elif key_mode == "dot+letter":
                                key = hashlib.sha256(dot + char).digest()
                            elif key_mode == "letter+dot":
                                key = hashlib.sha256(char + dot).digest()
                            else:
                                key = hashlib.sha256(b"+-" + word + char + b"7").digest()
                            row_keys.append(key)
                            row_ivs.append(word * 4)
                        signature = (tuple(row_keys), tuple(row_ivs), tuple(rows))
                        if signature in seen_families:
                            continue
                        seen_families.add(signature)
                        family = f"{token}/{layout}/{key_mode}/dot={polarity:+d}"
                        families += 1
                        for key in row_keys:
                            if key not in direct_seen:
                                direct_seen.add(key)
                                if matches_pubkey(key):
                                    hard_hits.append({"kind": "seven-password-direct",
                                                      "family": family,
                                                      "private_key": key.hex()})
                        for aes_mode in ("ECB", "CBC-header"):
                            plains = []
                            for index, (block, row) in enumerate(zip(blocks, rows)):
                                key = row_keys[row]
                                if aes_mode == "ECB":
                                    plain = AES.new(key, AES.MODE_ECB).decrypt(block)
                                else:
                                    plain = AES.new(key, AES.MODE_CBC, row_ivs[row]).decrypt(block)
                                aes_candidates += 1
                                plains.append(plain)
                                if matches_pubkey(plain):
                                    hard_hits.append({"kind": f"seven-password-{aes_mode}",
                                                      "family": family, "block": index,
                                                      "private_key": plain.hex()})

                            grouped = [[plain for plain, row0 in zip(plains, rows) if row0 == row]
                                       for row in range(7)]
                            group_xors = [bytes(a ^ b ^ c ^ d ^ e for a, b, c, d, e in zip(*group))
                                          for group in grouped]
                            group_sums = [(sum(int.from_bytes(value, "big") for value in group)
                                           % (1 << 256)).to_bytes(32, "big")
                                          for group in grouped]
                            aggregates = {
                                "sha-all": hashlib.sha256(b"".join(plains)).digest(),
                                "sha-group-xors": hashlib.sha256(b"".join(group_xors)).digest(),
                                "sha-group-sums": hashlib.sha256(b"".join(group_sums)).digest(),
                                "xor-group-xors": bytes(a ^ b ^ c ^ d ^ e ^ f ^ g
                                                         for a, b, c, d, e, f, g in zip(*group_xors)),
                                "sum-group-sums": (sum(int.from_bytes(value, "big")
                                                       for value in group_sums) % (1 << 256)).to_bytes(32, "big"),
                            }
                            aggregates.update({f"group{row}-xor": value
                                               for row, value in enumerate(group_xors)})
                            aggregates.update({f"group{row}-sum": value
                                               for row, value in enumerate(group_sums)})
                            for name, candidate in aggregates.items():
                                aggregate_tests += 1
                                if matches_pubkey(candidate):
                                    hard_hits.append({"kind": "seven-password-aggregate",
                                                      "family": family, "mode": aes_mode,
                                                      "aggregate": name,
                                                      "private_key": candidate.hex()})
                            joined = b"".join(plains)
                            ratio = printable_ratio(joined)
                            label = family + "/" + aes_mode
                            item = (ratio, label, joined[:32].hex())
                            if len(top) < 12:
                                heapq.heappush(top, item)
                            elif ratio > top[0][0]:
                                heapq.heapreplace(top, item)
                            if (valid_plaintext(joined) or b"Salted__" in joined
                                    or TARGET_PUBKEY in joined):
                                soft_hits.append({"label": label, "ratio": round(ratio, 4),
                                                  "head": joined[:80].hex()})
    return {
        "tokens": sorted(tokens),
        "families": families,
        "unique_direct_keys": len(direct_seen),
        "aes_private_key_tests": aes_candidates,
        "aggregate_private_key_tests": aggregate_tests,
        "hard_hits": hard_hits,
        "soft_hits": soft_hits,
        "top_printable": [
            {"ratio": round(ratio, 4), "label": label, "head": head}
            for ratio, label, head in sorted(top, reverse=True)
        ],
    }


def bifid_variants(hypotheses_: list[dict], faed: str) -> list[dict]:
    scorer = Scorer()
    variants = []
    seen_squares = set()
    for hyp in hypotheses_:
        keyword = bytes(ord("a") + value for value in hyp["shifted"]).decode()
        square = keyword_square(keyword)
        if square in seen_squares:
            continue
        seen_squares.add(square)
        plain = bifid_decrypt(faed.upper(), square, 570)
        anchors = [word for word in ("BTCSEED", "PRIVATE", "PASSWORD", "MATRIX",
                                     "YINYANG", "KEY") if word in plain]
        variants.append({"label": hyp["label"], "square": square, "plain": plain,
                         "score": round(scorer(plain), 4), "anchors": anchors})
    return variants


def candidate_keys(hypotheses_: list[dict], bifids: list[dict],
                   header28: bytes, blocks: list[bytes]):
    for hyp in hypotheses_:
        label = hyp["label"]
        for material_name, material in matrix_materials(hyp, header28):
            yield f"{label}/{material_name}/sha", hashlib.sha256(material).digest()
            yield f"{label}/{material_name}/framed-sha", hashlib.sha256(b"+-" + material + b"7").digest()
            if len(material) == 32:
                yield f"{label}/{material_name}/raw", material
        for name, key in header_keys(hyp, header28):
            yield f"{label}/{name}", key
        for name, key in selected_block_keys(hyp, header28, blocks):
            yield f"{label}/{name}", key
    for row in bifids:
        bases = {
            "keyword-square": row["square"].encode(),
            "plain": row["plain"].encode(),
            "plain-lower": row["plain"].lower().encode(),
            "plain-rest": row["plain"][7:].encode(),
        }
        for name, material in bases.items():
            stem = f"bifid/{row['label']}/{name}"
            yield stem + "/sha", hashlib.sha256(material).digest()
            yield stem + "/framed-sha", hashlib.sha256(b"+-" + material + b"7").digest()
            if len(material) >= 32:
                yield stem + "/first32", material[:32]
                yield stem + "/last32", material[-32:]


def matches_pubkey(secret: bytes, target: bytes = TARGET_PUBKEY) -> bool:
    if len(secret) != 32 or not any(secret):
        return False
    try:
        return PublicKey.from_valid_secret(secret).format(compressed=False) == target
    except ValueError:
        return False


def mnemonic_pair() -> tuple[str, str]:
    raw_indices = (*PRIME_INDICES[:-2], ANOMALY, *PRIME_INDICES[-2:])
    corrected_indices = (*PRIME_INDICES[:-2], ANOMALY, PRIME_INDICES[-2], 190)
    return (" ".join(O.WORDLIST[i] for i in raw_indices),
            " ".join(O.WORDLIST[i] for i in corrected_indices))


def null_model_140(dbbi: str, trials: int = 1_000_000) -> dict:
    """Embaralha o mesmo multiconjunto a-i e mede o encaixe |dot|=140."""
    values = [ord(char) - ord("a") + 1 for char in dbbi]
    corrected = [ANOMALY, *PRIME_INDICES[:-1], 190, ANOMALY]
    weights = [value * (1 if i % 2 == 0 else -1)
               for i, value in enumerate(corrected)]
    raw = [ANOMALY, *PRIME_INDICES, ANOMALY]
    raw_weights = [value * (-1 if i % 2 == 0 else 1)
                   for i, value in enumerate(raw)]
    rng = random.Random(0)
    first_hits = any_row_hits = yin_hits = hash_hits = joint_hits = triple_hits = 0
    for _ in range(trials):
        rng.shuffle(values)
        dots = [sum(values[r * 13 + c] * weights[c] for c in range(13))
                for r in range(7)]
        raw_dots = [sum(values[r * 13 + c] * raw_weights[c] for c in range(13))
                    for r in range(7)]
        first_hit = abs(dots[0]) == 140
        letters = "".join(chr(ord("A") + value % 26) for value in dots)
        yin_hit = "YIN" in letters
        hash_hit = "HASH" in "".join(chr(ord("A") + value % 26) for value in raw_dots)
        first_hits += first_hit
        any_row_hits += any(abs(value) == 140 for value in dots)
        yin_hits += yin_hit
        hash_hits += hash_hit
        joint_hits += hash_hit and yin_hit
        triple_hits += first_hit and hash_hit and yin_hit
    return {
        "trials": trials,
        "first_row_hits": first_hits,
        "first_row_rate": first_hits / trials,
        "any_row_hits": any_row_hits,
        "any_row_rate": any_row_hits / trials,
        "yin_substring_hits": yin_hits,
        "yin_substring_rate": yin_hits / trials,
        "hash_substring_hits": hash_hits,
        "hash_substring_rate": hash_hits / trials,
        "joint_hash_and_yin_hits": joint_hits,
        "joint_hash_and_yin_rate": joint_hits / trials,
        "triple_first140_hash_yin_hits": triple_hits,
        "triple_first140_hash_yin_rate": triple_hits / trials,
    }


def printable_ratio(data: bytes) -> float:
    return sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data) / len(data)


def valid_plaintext(data: bytes) -> bool:
    pad = data[-1]
    if not 1 <= pad <= 16 or not data.endswith(bytes([pad]) * pad):
        return False
    body = data[:-pad]
    return bool(body) and printable_ratio(body) >= 0.80


def self_check() -> None:
    raw_mnemonic, checksum_mnemonic = mnemonic_pair()
    assert raw_mnemonic.endswith("belt blood") and not O._MNEMO.check(raw_mnemonic)
    assert checksum_mnemonic.endswith("belt blind") and O._MNEMO.check(checksum_mnemonic)
    assert O.WORDLIST[1188] == "nest"
    corrected_indices = (*PRIME_INDICES[:-2], ANOMALY, PRIME_INDICES[-2], 190)
    assert sum(corrected_indices) == 1159 and O.WORDLIST[1159] == "movie"
    natural = [row for row in hypotheses(O.sources()["dbbi"])
               if row["label"] == "checksum190/forward/a1/raw/alternating+"]
    assert len(natural) == 1 and natural[0]["dots"][0] == -140
    assert natural_mod26_words(hypotheses(O.sources()["dbbi"])) == ("PHASHFG", "QYINZXW")
    secret = F.MATRIX_COMPONENTS[:32]
    pubkey = PublicKey.from_valid_secret(secret).format(compressed=False)
    assert matches_pubkey(secret, pubkey)
    key = hashlib.sha256(b"anomaly-dbbi-control").digest()
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(secret)
    assert matches_pubkey(AES.new(key, AES.MODE_ECB).decrypt(encrypted), pubkey)


def main() -> None:
    self_check()
    chain = F.reproduce()
    header = chain["header"]
    header28 = header[2:-1]
    body = chain["blocks"]
    blocks = [body[i:i + 32] for i in range(0, len(body), 32)]
    assert header[:2] == b"+-" and header[-1:] == b"7"
    assert len(header28) == 28 and len(blocks) == 35

    hs = hypotheses(O.sources()["dbbi"])
    bifids = bifid_variants(hs, O.sources()["faed"])
    seen: set[bytes] = set()
    hard_hits = []
    soft_hits = []
    top_printable: list[tuple[float, str, str, str]] = []
    direct_tests = ecb_tests = 0

    for label, key in candidate_keys(hs, bifids, header28, blocks):
        if key in seen:
            continue
        seen.add(key)
        direct_tests += 1
        if matches_pubkey(key):
            hard_hits.append({"kind": "direct-private-key", "label": label, "key": key.hex()})
            break

        plain = AES.new(key, AES.MODE_ECB).decrypt(body)
        ratio = printable_ratio(plain)
        item = (ratio, label, key.hex(), plain[:32].hex())
        if len(top_printable) < 12:
            heapq.heappush(top_printable, item)
        elif ratio > top_printable[0][0]:
            heapq.heapreplace(top_printable, item)
        if valid_plaintext(plain) or b"Salted__" in plain or TARGET_PUBKEY in plain:
            soft_hits.append({"mode": "ECB", "label": label, "key": key.hex(),
                              "printable": round(ratio, 4), "head": plain[:80].hex()})

        for index in range(35):
            ecb_tests += 1
            candidate = plain[index * 32:(index + 1) * 32]
            if matches_pubkey(candidate):
                hard_hits.append({"kind": "AES-ECB-private-key", "label": label,
                                  "key": key.hex(), "block": index,
                                  "private_key": candidate.hex()})
                break
        if hard_hits:
            break
        if len(seen) % 5000 == 0:
            print(f"[progress] keys={len(seen):,} AES-ECB candidates={ecb_tests:,}", flush=True)

    chunk_report = genesis_chunk_attack(header28, blocks, hs)
    word_report = emergent_word_attack(header28, body, hs)
    seven_report = seven_password_attack(header28, blocks, hs)
    hard_hits.extend(chunk_report["hard_hits"])
    hard_hits.extend(word_report["hard_hits"])
    hard_hits.extend(seven_report["hard_hits"])
    soft_hits.extend(chunk_report["soft_hits"])
    soft_hits.extend(word_report["soft_hits"])
    soft_hits.extend(seven_report["soft_hits"])
    report = {
        "contract": "DBBI(7x13) dot anomaly-prime list(13) -> 7 header words / 7x5 Chain4",
        "raw_mnemonic": mnemonic_pair()[0],
        "checksum_mnemonic": mnemonic_pair()[1],
        "hypotheses": len(hs),
        "natural_alternating_dots": [row for row in hs if
                                      row["label"] == "checksum190/forward/a1/raw/alternating+"][0]["dots"],
        "null_model_140": null_model_140(O.sources()["dbbi"]),
        "unique_bifid_squares": len(bifids),
        "bifid_anchor_hits": [
            {"label": row["label"], "square": row["square"],
             "anchors": row["anchors"], "head": row["plain"][:80]}
            for row in bifids if row["anchors"]
        ],
        "bifid_top": [
            {"score": row["score"], "label": row["label"],
             "square": row["square"], "head": row["plain"][:80]}
            for row in sorted(bifids, key=lambda item: item["score"], reverse=True)[:12]
        ],
        "unique_aes_keys": len(seen),
        "direct_private_key_tests": direct_tests,
        "aes_ecb_private_key_tests": ecb_tests,
        "hard_hits": hard_hits,
        "soft_hits": soft_hits[:100],
        "genesis_140_chunk_attack": chunk_report,
        "emergent_word_attack": word_report,
        "seven_password_attack": seven_report,
        "top_printable": [
            {"ratio": round(ratio, 4), "label": label, "key": key, "head": head}
            for ratio, label, key, head in sorted(top_printable, reverse=True)
        ],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
    print(json.dumps({key: report[key] for key in (
        "hypotheses", "unique_aes_keys", "direct_private_key_tests",
        "aes_ecb_private_key_tests", "natural_alternating_dots",
        "null_model_140", "hard_hits", "soft_hits")}, indent=2))
    print("genesis chunk attack:", json.dumps({key: chunk_report[key] for key in
          ("families", "direct_private_key_tests", "aes_candidates",
           "hard_hits", "soft_hits")}, indent=2))
    print("emergent word attack:", json.dumps({key: word_report[key] for key in
          ("raw_mod26", "corrected_mod26", "unique_keys",
           "aes_private_key_tests", "block_algebra_private_key_tests",
           "hard_hits", "soft_hits")}, indent=2))
    print("seven password attack:", json.dumps({key: seven_report[key] for key in
          ("tokens", "families", "unique_direct_keys", "aes_private_key_tests",
           "aggregate_private_key_tests", "hard_hits", "soft_hits")}, indent=2))
    print(f"report: {OUT}")


if __name__ == "__main__":
    main()
