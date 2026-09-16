# -*- coding: utf-8 -*-
"""Decodificacao intrinseca dos dois canais do ``BIF_REST``.

Depois do header de sete letras, o Bifid canônico separa-se em:

* ``payload = rest[0::2]``: 282 simbolos no alfabeto base-25;
* ``structure = rest[1::2]``: 281 simbolos em ``B,C,D,E``.

No quadrado CANON, ``D/B/C/E`` sao exatamente as quatro coordenadas do
canto 2x2, portanto formam um digito base-4. Como ``563 = 2*281 + 1`` e
``4*25 = 100``, emparelhar os canais da um digito base-100 sem chave livre.
Este script testa as duas ordens de coordenadas, as duas posicoes possiveis do
simbolo excedente e as duas ordens naturais base-4/base-25. Tambem testa a
leitura geometrica minima: os dois bits somam/subtraem/refletem as coordenadas
do simbolo base-25.

Legibilidade e somente diagnostico. ``solve`` exige o endereco-premio ou a
abertura de um blob AES original.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
from pathlib import Path

import dsl
import oracles as O
from scorer import Scorer


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_work" / "btcseed_duality_attack.json"
STANDARD25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def int_bytes(digits: list[int], base: int) -> bytes:
    value = 0
    for digit in digits:
        if not 0 <= digit < base:
            raise ValueError(f"digit {digit} outside base {base}")
        value = value * base + digit
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def pack_two_bit(digits: list[int]) -> bytes:
    bits: list[int] = []
    for digit in digits:
        bits.extend((digit >> 1, digit & 1))
    bits.extend([0] * ((-len(bits)) % 8))
    value = 0
    for bit in bits:
        value = value * 2 + bit
    return value.to_bytes(len(bits) // 8, "big")


def text_oracles(label: str, text: str) -> list[dict]:
    hits: list[dict] = []
    passwords = {
        text,
        text.lower(),
        hashlib.sha256(text.encode()).hexdigest(),
        hashlib.sha256(text.lower().encode()).hexdigest(),
    }
    for password in passwords:
        for hit in O.aes_open(password):
            hits.append({"label": label, "oracle": "aes_open", "password": password, "hit": hit})
    for key in {
        hashlib.sha256(text.encode()).digest(),
        hashlib.sha256(text.lower().encode()).digest(),
    }:
        hit = O.check_privkey(key)
        if hit:
            hits.append({"label": label, "oracle": "privkey", "key_hex": key.hex(), "hit": hit})
    return hits


def byte_oracles(label: str, data: bytes) -> tuple[list[dict], int]:
    hits: list[dict] = []
    checks = 0
    forms = {
        "raw": data,
        "reverse": data[::-1],
        "sha256": hashlib.sha256(data).digest(),
        "double_sha256": hashlib.sha256(hashlib.sha256(data).digest()).digest(),
    }
    for form_name, form in forms.items():
        for offset in range(max(1, len(form) - 31)):
            key = form[offset : offset + 32]
            if len(key) != 32:
                continue
            checks += 1
            hit = O.check_privkey(key)
            if hit:
                hits.append(
                    {
                        "label": label,
                        "oracle": "privkey",
                        "form": form_name,
                        "offset": offset,
                        "key_hex": key.hex(),
                        "hit": hit,
                    }
                )

    passwords = {
        data.hex(),
        base64.b64encode(data).decode(),
        hashlib.sha256(data).hexdigest(),
    }
    for password in passwords:
        for hit in O.aes_open(password):
            hits.append({"label": label, "oracle": "aes_open", "password": password, "hit": hit})
    return hits, checks


def coordinate_value_maps() -> dict[str, dict[str, int]]:
    # CANON starts with rows "DBIFH" / "CEGAK". The structural symbols
    # therefore encode (row, col) in the 2x2 upper-left corner exactly.
    return {
        "row_col": {"D": 0, "B": 1, "C": 2, "E": 3},
        "col_row": {"D": 0, "C": 1, "B": 2, "E": 3},
    }


def coordinate_transform(
    payload: str,
    structure: str,
    swap_bits: bool,
    row_op: str,
    col_op: str,
) -> str:
    positions = {char: divmod(index, 5) for index, char in enumerate(dsl.CANON)}

    def apply(value: int, bit: int, operation: str) -> int:
        if operation == "add":
            return (value + bit) % 5
        if operation == "sub":
            return (value - bit) % 5
        if operation == "reflect":
            return 4 - value if bit else value
        raise ValueError(operation)

    plaintext: list[str] = []
    for payload_char, structure_char in zip(payload, structure):
        row, column = positions[payload_char]
        bit_row, bit_column = positions[structure_char]
        if swap_bits:
            bit_row, bit_column = bit_column, bit_row
        out_row = apply(row, bit_row, row_op)
        out_column = apply(column, bit_column, col_op)
        plaintext.append(dsl.CANON[out_row * 5 + out_column])
    return "".join(plaintext)


def main() -> None:
    # Independently checks the positional base conversion used below.
    control_digits = [12, 34, 56, 78, 90]
    control_value = int.from_bytes(int_bytes(control_digits, 100), "big")
    recovered: list[int] = []
    while control_value:
        control_value, digit = divmod(control_value, 100)
        recovered.append(digit)
    if recovered[::-1] != control_digits:
        raise AssertionError("base-100 control failed")

    rest = dsl.bif_full()[7:]
    payload = rest[0::2]
    structure = rest[1::2]
    if not (len(rest) == 563 and len(payload) == 282 and len(structure) == 281):
        raise AssertionError("unexpected BTCSEED channel geometry")
    if set(structure) != set("BCDE"):
        raise AssertionError("structural channel is not the CANON 2x2 corner")

    byte_candidates: dict[str, bytes] = {}
    text_candidates: dict[str, str] = {}

    q_maps = coordinate_value_maps()
    for alignment, aligned_payload in (
        ("drop_payload_last", payload[:-1]),
        ("drop_payload_first", payload[1:]),
    ):
        for alphabet_name, alphabet in (("canon", dsl.CANON), ("standard", STANDARD25)):
            payload_digits = [alphabet.index(char) for char in aligned_payload]
            for map_name, q_map in q_maps.items():
                structure_digits = [q_map[char] for char in structure]
                combined = {
                    "q25_plus_p": [
                        q_digit * 25 + p_digit
                        for q_digit, p_digit in zip(structure_digits, payload_digits)
                    ],
                    "p4_plus_q": [
                        p_digit * 4 + q_digit
                        for q_digit, p_digit in zip(structure_digits, payload_digits)
                    ],
                }
                for order_name, digits in combined.items():
                    stem = f"{alignment}/{alphabet_name}/{map_name}/{order_name}"
                    byte_candidates[stem + "/direct"] = bytes(digits)
                    byte_candidates[stem + "/direct_plus32"] = bytes(digit + 32 for digit in digits)
                    byte_candidates[stem + "/base100"] = int_bytes(digits, 100)
                    byte_candidates[stem + "/base100_digit_reverse"] = int_bytes(digits[::-1], 100)
                    text_candidates[stem + "/decimal2"] = "".join(f"{digit:02d}" for digit in digits)

        for swap_bits in (False, True):
            for row_op, col_op in itertools.product(("add", "sub", "reflect"), repeat=2):
                label = f"{alignment}/coords/swap={swap_bits}/{row_op}/{col_op}"
                text_candidates[label] = coordinate_transform(
                    aligned_payload, structure, swap_bits, row_op, col_op
                )

    for map_name, q_map in q_maps.items():
        structural_digits = [q_map[char] for char in structure]
        byte_candidates[f"structure/{map_name}/2bit"] = pack_two_bit(structural_digits)
        byte_candidates[f"structure/{map_name}/base4"] = int_bytes(structural_digits, 4)
    for alphabet_name, alphabet in (("canon", dsl.CANON), ("standard", STANDARD25)):
        payload_digits = [alphabet.index(char) for char in payload]
        byte_candidates[f"payload/{alphabet_name}/base25"] = int_bytes(payload_digits, 25)

    scorer = Scorer()
    text_rows: list[dict] = []
    hits: list[dict] = []
    checks = 0
    for label, text in text_candidates.items():
        row_hits = text_oracles(label, text)
        hits.extend(row_hits)
        text_rows.append(
            {"label": label, "score": scorer(text), "head": text[:100], "hits": row_hits}
        )
    text_rows.sort(key=lambda row: row["score"], reverse=True)

    byte_rows: list[dict] = []
    seen: set[bytes] = set()
    for label, data in byte_candidates.items():
        if data in seen:
            continue
        seen.add(data)
        row_hits, row_checks = byte_oracles(label, data)
        checks += row_checks
        hits.extend(row_hits)
        printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data) / len(data)
        byte_rows.append(
            {
                "label": label,
                "length": len(data),
                "printable_ratio": printable,
                "head_hex": data[:32].hex(),
                "hits": row_hits,
            }
        )
    byte_rows.sort(key=lambda row: row["printable_ratio"], reverse=True)

    report = {
        "control_base100": True,
        "invariants": {
            "rest": 563,
            "payload": 282,
            "structure": 281,
            "safe_prime_relation": "563 = 2*281 + 1",
            "structure_alphabet": "BCDE = CANON upper-left 2x2",
        },
        "text_candidates": len(text_candidates),
        "unique_byte_candidates": len(seen),
        "privkey_window_checks": checks,
        "hits": hits,
        "solve": bool(hits),
        "top_text": text_rows[:20],
        "top_bytes": byte_rows[:20],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=== BTCSEED / SAFE-PRIME DUALITY ===")
    print(
        f"text={len(text_candidates)} bytes={len(seen)} "
        f"privkey_checks={checks} hits={len(hits)}"
    )
    for row in text_rows[:8]:
        print(f"{row['score']:.4f} {row['label']:<62} {row['head'][:40]}")
    print(f"report={OUT}")


if __name__ == "__main__":
    main()
