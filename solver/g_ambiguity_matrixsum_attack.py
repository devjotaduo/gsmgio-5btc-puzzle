# -*- coding: utf-8 -*-
"""Resolve a ambiguidade 0/7 de ``g`` em ``faed`` com ``matrixsumlist``.

Hipótese falsificável
--------------------
O diagnóstico estatístico preservado pelo Claude indica que o unigrama de
``faed`` é compatível com dígitos decimais uniformes se ``g`` representar ora
0, ora 7. A página fornece uma máscara binária objetiva de 104 bits: o trecho
a/b que decodifica para ``matrixsumlist``. Existem 107 ocorrências de ``g``.
Este ataque alinha a máscara às ocorrências de ``g`` e trata os três símbolos
excedentes de todas as maneiras binárias, ou os remove literalmente como
"extra". As únicas rotas são as leituras naturais do fluxo e das grades 15x38
e 38x15, incluindo espelhos e boustrophedon.

Cada saída passa pelo método decimal->hex ensinado pela própria página, pela
gramática SHA256->senha e por oráculos duros AES/secp256k1. Padding válido ou
legibilidade isolada são apenas sinais fracos, nunca solução.
"""

from __future__ import annotations

import hashlib
import json
import sys
from itertools import product, zip_longest
from pathlib import Path
from typing import Iterable, Sequence

from coincurve import PublicKey


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "solver" / "experiments" / "claude_endgame_2026_09_02"
sys.path.insert(0, str(EXPERIMENTS))

import gsmg_common as G  # noqa: E402


OUT = ROOT / "_work" / "new_approach_claude" / "g_ambiguity_matrixsum_attack.json"
WORD = "matrixsumlist"
BLOBS = ("SMALL", "COSMIC", "TAIL32")
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBLIC_KEY = bytes.fromhex(G.TARGET_PUBKEY_HEX)
TARGET_X = TARGET_PUBLIC_KEY[1:33]
TARGET_Y = int.from_bytes(TARGET_PUBLIC_KEY[33:], "big")
NEGATED_PUBLIC_KEY = b"\x04" + TARGET_X + (FIELD_PRIME - TARGET_Y).to_bytes(32, "big")


def page_sources() -> tuple[str, str, str]:
    """Extrai as três sequências contíguas diretamente do README."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    line = next(line for line in readme.splitlines() if line.startswith("> d b b i"))
    compact = line[2:].replace(" ", "").replace("*", "")
    dbbi = compact[:91]
    mask = compact[91:195]
    faed = compact[195:765]
    assert dbbi == G.DBBI
    assert faed == G.FAED
    assert len(mask) == 104 and set(mask) == {"a", "b"}
    return dbbi, mask, faed


def ascii_bits(text: str) -> tuple[int, ...]:
    return tuple(int(bit) for byte in text.encode("ascii") for bit in f"{byte:08b}")


def decode_ab(mask: str) -> str:
    bits = "".join("0" if char == "a" else "1" for char in mask)
    return bytes(int(bits[index : index + 8], 2) for index in range(0, len(bits), 8)).decode()


def bit_orientations(bits: Sequence[int]) -> dict[str, tuple[int, ...]]:
    chunks = [tuple(bits[index : index + 8]) for index in range(0, len(bits), 8)]
    variants = {
        "direct": tuple(bits),
        "mirror": tuple(reversed(bits)),
        "bytes_reverse": tuple(bit for chunk in reversed(chunks) for bit in chunk),
        "bits_in_bytes_reverse": tuple(bit for chunk in chunks for bit in reversed(chunk)),
    }
    unique: dict[tuple[int, ...], str] = {}
    for name, value in variants.items():
        unique.setdefault(value, name)
    return {name: value for value, name in unique.items()}


def route_indices(width: int, snake_rows: bool = False, snake_cols: bool = False) -> tuple[int, ...]:
    height = 570 // width
    if snake_cols:
        return tuple(
            row * width + column
            for column in range(width)
            for row in (
                range(height) if column % 2 == 0 else range(height - 1, -1, -1)
            )
        )
    if snake_rows:
        return tuple(
            row * width + column
            for row in range(height)
            for column in (
                range(width) if row % 2 == 0 else range(width - 1, -1, -1)
            )
        )
    return tuple(row * width + column for column in range(width) for row in range(height))


def routes() -> dict[str, tuple[int, ...]]:
    linear = tuple(range(570))
    variants = {
        "linear": linear,
        "linear_reverse": tuple(reversed(linear)),
        "grid_w38_columns": route_indices(38),
        "grid_w38_rows_snake": route_indices(38, snake_rows=True),
        "grid_w38_columns_snake": route_indices(38, snake_cols=True),
        "grid_w15_columns": route_indices(15),
        "grid_w15_rows_snake": route_indices(15, snake_rows=True),
        "grid_w15_columns_snake": route_indices(15, snake_cols=True),
    }
    unique: dict[tuple[int, ...], str] = {}
    for name, route in variants.items():
        assert len(route) == len(set(route)) == 570
        unique.setdefault(route, name)
    return {name: route for route, name in unique.items()}


def public_key_relation(secret: bytes) -> str | None:
    if len(secret) != 32:
        return None
    value = int.from_bytes(secret, "big")
    if not 1 <= value < CURVE_ORDER:
        return None
    public_key = PublicKey.from_valid_secret(secret).format(compressed=False)
    if public_key == TARGET_PUBLIC_KEY:
        return "target_public_key"
    if public_key == NEGATED_PUBLIC_KEY:
        return "negated_target_public_key"
    return None


def scan_keys(data: bytes) -> Iterable[dict[str, object]]:
    for offset in range(len(data) - 31):
        secret = data[offset : offset + 32]
        relation = public_key_relation(secret)
        if relation:
            yield {"offset": offset, "secret_hex": secret.hex(), "relation": relation}


def interleave(left: Sequence[int], right: Sequence[int]) -> list[int]:
    return [item for pair in zip_longest(left, right) for item in pair if item is not None]


def add_materializations(
    candidates: dict[bytes, list[str]], name: str, digits: Sequence[int]
) -> None:
    def add(label: str, data: bytes) -> None:
        if data:
            candidates.setdefault(data, []).append(f"{name}/{label}")
            candidates.setdefault(data[::-1], []).append(f"{name}/{label}/mirror_bytes")

    digit_text = "".join(str(value) for value in digits)
    symbol_text = "".join("o" if value == 0 else chr(96 + value) for value in digits)
    add("digits", digit_text.encode("ascii"))
    add("symbols", symbol_text.encode("ascii"))
    add("symbols_upper", symbol_text.upper().encode("ascii"))
    try:
        add("zmethod", G.z_method(list(digits)))
    except (ValueError, OverflowError):
        pass


def build_candidates(
    mask_bits: Sequence[int], faed: str
) -> tuple[dict[bytes, list[str]], int]:
    source = G.digits(faed, base1=True)
    candidates: dict[bytes, list[str]] = {}
    assignments = 0

    for route_name, route in routes().items():
        g_order = [index for index in route if faed[index] == "g"]
        assert len(g_order) == 107
        for bit_name, oriented in bit_orientations(mask_bits).items():
            for zero_bit in (0, 1):
                for edge in ("prefix", "suffix"):
                    for extras in product((0, 1), repeat=3):
                        assignment = extras + oriented if edge == "prefix" else oriented + extras
                        digits = source[:]
                        for index, bit in zip(g_order, assignment, strict=True):
                            digits[index] = 0 if bit == zero_bit else 7
                        stem = f"{route_name}/{bit_name}/zero_bit{zero_bit}/{edge}{''.join(map(str, extras))}"
                        routed = [digits[index] for index in route]
                        add_materializations(candidates, f"{stem}/linear", digits)
                        add_materializations(candidates, f"{stem}/routed", routed)
                        add_materializations(candidates, f"{stem}/half_a", digits[:285])
                        add_materializations(candidates, f"{stem}/half_b", digits[285:])
                        add_materializations(
                            candidates,
                            f"{stem}/halves_interleaved",
                            interleave(digits[:285], digits[285:]),
                        )
                        add_materializations(
                            candidates,
                            f"{stem}/g_assignment",
                            [digits[index] for index in g_order],
                        )
                        assignments += 1

                for edge in ("drop_prefix3", "drop_suffix3"):
                    selected = g_order[3:] if edge == "drop_prefix3" else g_order[:-3]
                    dropped = set(g_order) - set(selected)
                    digits = source[:]
                    for index, bit in zip(selected, oriented, strict=True):
                        digits[index] = 0 if bit == zero_bit else 7
                    compact = [value for index, value in enumerate(digits) if index not in dropped]
                    stem = f"{route_name}/{bit_name}/zero_bit{zero_bit}/{edge}"
                    add_materializations(candidates, f"{stem}/linear", compact)
                    add_materializations(
                        candidates,
                        f"{stem}/g_assignment",
                        [digits[index] for index in selected],
                    )
                    assignments += 1
    return candidates, assignments


def phase2_control() -> dict[str, object]:
    salt, ciphertext = G._parse(G.PHASE2_B64)
    password = G.shahex("causality").encode("ascii")
    key, iv = G.evp(password, salt, G.SHA256)
    plaintext = G.unpad(G.AES.new(key, G.AES.MODE_CBC, iv).decrypt(ciphertext))
    assert plaintext is not None and G.semantic(plaintext)
    return {
        "password": password.decode("ascii"),
        "plaintext_prefix": plaintext[:48].decode("latin-1"),
        "printable": round(G.printable(plaintext), 3),
    }


def run() -> dict[str, object]:
    _, raw_mask, faed = page_sources()
    bits = tuple(0 if char == "a" else 1 for char in raw_mask)
    assert bits == ascii_bits(WORD)
    assert decode_ab(raw_mask) == WORD
    assert faed.count("g") == 107

    candidates, assignment_count = build_candidates(bits, faed)
    hard: list[dict[str, object]] = []
    soft: list[dict[str, object]] = []
    readable: list[dict[str, object]] = []
    decoded: list[dict[str, object]] = []
    key_windows = 0

    for data, origins in candidates.items():
        digest = hashlib.sha256(data).digest()
        relation = public_key_relation(digest)
        if relation:
            hard.append(
                {
                    "kind": "sha256_private_key",
                    "origins": origins,
                    "secret_hex": digest.hex(),
                    "relation": relation,
                }
            )

        # Dígitos/símbolos ASCII não podem conter a privkey binária diretamente;
        # a varredura byte-a-byte só é informativa após decimal->hex.
        is_decoded = any("/zmethod" in origin for origin in origins)
        if is_decoded:
            key_windows += max(0, len(data) - 31)
            for private_hit in scan_keys(data):
                hard.append(
                    {"kind": "embedded_private_key", "origins": origins, **private_hit}
                )

        printable = G.printable(data)
        text = data.decode("latin-1")
        if is_decoded:
            decoded.append(
                {
                    "origins": origins,
                    "printable": round(printable, 3),
                    "score": round(G.english_score(text), 3),
                    "data_hex": data[:160].hex(),
                }
            )
        if printable >= 0.55:
            readable.append(
                {
                    "origins": origins,
                    "printable": round(printable, 3),
                    "score": round(G.english_score(text), 3),
                    "text": text[:240],
                }
            )

        passwords = {
            "raw": data,
            "sha256hex": digest.hex().encode("ascii"),
            "sha256raw": digest,
        }
        for password_name, password in passwords.items():
            for blob in BLOBS:
                for kdf, plaintext in G.aes_try(password, blob, kdf="both"):
                    record = {
                        "blob": blob,
                        "kdf": kdf,
                        "password_form": password_name,
                        "origins": origins,
                        "printable": round(G.printable(plaintext), 3),
                        "plaintext_hex": plaintext.hex(),
                    }
                    if G.semantic(plaintext):
                        hard.append({"kind": "aes", **record})
                    else:
                        soft.append(record)

    readable.sort(key=lambda item: (item["score"], item["printable"]), reverse=True)
    decoded.sort(key=lambda item: (item["printable"], item["score"]), reverse=True)
    aes_tests = len(candidates) * 3 * len(BLOBS) * 2
    result = {
        "family": "g_ambiguity_matrixsum",
        "hypothesis": __doc__.split("Hipótese falsificável", 1)[1].split(
            "Cada saída", 1
        )[0].strip(),
        "controls": {
            "raw_mask_length": len(raw_mask),
            "raw_mask_decodes_to": decode_ab(raw_mask),
            "faed_length": len(faed),
            "g_count": faed.count("g"),
            "route_count": len(routes()),
            "bit_orientation_count": len(bit_orientations(bits)),
            "phase2": phase2_control(),
        },
        "assignment_count": assignment_count,
        "candidate_count": len(candidates),
        "aes_tests": aes_tests,
        "expected_random_paddings": round(aes_tests / 256, 2),
        "key_window_checks": key_windows,
        "hard": hard,
        "soft_padding_count": len(soft),
        "soft": soft,
        "best_readable": readable[:20],
        "best_zmethod": decoded[:20],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    report = run()
    summary_keys = (
        "family",
        "controls",
        "assignment_count",
        "candidate_count",
        "aes_tests",
        "expected_random_paddings",
        "key_window_checks",
        "hard",
        "soft_padding_count",
        "best_readable",
        "best_zmethod",
    )
    print(json.dumps({key: report[key] for key in summary_keys}, ensure_ascii=False, indent=2))
