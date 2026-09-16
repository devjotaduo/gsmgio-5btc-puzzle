# -*- coding: utf-8 -*-
"""Ataque curto e falsificavel: Bazeries sobre o payload pos-``BTCSEED``.

Motivacao anterior ao teste:

* a mensagem do Telegram imediatamente posterior ao achado de ``BTCSEED`` relata
  que o restante teve o melhor casamento do classificador com Bazeries;
* ``len(BIF_REST) == 563`` e 563 e exatamente o 103o primo;
* Bazeries precisa de um numero e de um alfabeto misto. Assim, testamos somente
  563, 103, o comprimento total 570 e o ``matrixsumlist`` provado (101).

Nao ha busca de chave livre. A implementacao e validada pelo vetor publico
``UNIVERSITY --900004--> QMHATRMGXS`` antes de tocar no artefato real.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import dsl
import oracles as O
from scorer import Scorer


ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_work" / "btcseed_bazeries_attack.json"

ONES = {
    0: "zero",
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
    10: "ten",
    11: "eleven",
    12: "twelve",
    13: "thirteen",
    14: "fourteen",
    15: "fifteen",
    16: "sixteen",
    17: "seventeen",
    18: "eighteen",
    19: "nineteen",
}
TENS = {
    20: "twenty",
    30: "thirty",
    40: "forty",
    50: "fifty",
    60: "sixty",
    70: "seventy",
    80: "eighty",
    90: "ninety",
}


def number_name(number: int) -> str:
    """English cardinal name sufficient for the bounded keys in this attack."""
    if number < 20:
        return ONES[number]
    if number < 100:
        return TENS[number // 10 * 10] + (ONES[number % 10] if number % 10 else "")
    if number < 1000:
        rest = number % 100
        return ONES[number // 100] + "hundred" + (number_name(rest) if rest else "")
    raise ValueError("Bazeries key outside the bounded range")


def digit_name(number: int) -> str:
    return "".join(ONES[int(digit)] for digit in str(number))


def keyed_alphabet(keyword: str, filler: str = ALPHA25) -> str:
    seen: list[str] = []
    for char in (keyword + filler).upper().replace("J", "I"):
        if char in ALPHA25 and char not in seen:
            seen.append(char)
    if len(seen) != 25:
        raise ValueError("keyword/filler did not produce a 25-letter alphabet")
    return "".join(seen)


def block_reverse(text: str, number: int) -> str:
    """Reverse successive groups given by non-zero digits of the numeric key."""
    sizes = [int(digit) for digit in str(number) if digit != "0"]
    if not sizes:
        raise ValueError("Bazeries key has no non-zero block size")
    chunks: list[str] = []
    offset = 0
    group = 0
    while offset < len(text):
        size = sizes[group % len(sizes)]
        chunks.append(text[offset : offset + size][::-1])
        offset += size
        group += 1
    return "".join(chunks)


def standard_column_alphabet() -> str:
    """Row-wise view of the standard alphabet filled column by column."""
    return "".join(ALPHA25[row + 5 * column] for row in range(5) for column in range(5))


def bazeries_encrypt(plaintext: str, number: int, keyword: str) -> str:
    standard = standard_column_alphabet()
    mixed = keyed_alphabet(keyword)
    table = str.maketrans(standard, mixed)
    return block_reverse(plaintext.upper().replace("J", "I"), number).translate(table)


def bazeries_decrypt(ciphertext: str, number: int, keyword: str) -> str:
    standard = standard_column_alphabet()
    mixed = keyed_alphabet(keyword)
    table = str.maketrans(mixed, standard)
    substituted = ciphertext.upper().replace("J", "I").translate(table)
    return block_reverse(substituted, number)


def hard_oracles(text: str) -> list[dict]:
    hits: list[dict] = []
    password_forms = {
        text,
        text.lower(),
        hashlib.sha256(text.encode()).hexdigest(),
        hashlib.sha256(text.lower().encode()).hexdigest(),
    }
    for password in password_forms:
        for hit in O.aes_open(password):
            hits.append({"oracle": "aes_open", "password": password, "hit": hit})

    key_forms = {
        hashlib.sha256(text.encode()).digest(),
        hashlib.sha256(text.lower().encode()).digest(),
    }
    for key in key_forms:
        hit = O.check_privkey(key)
        if hit:
            hits.append({"oracle": "privkey", "key_hex": key.hex(), "hit": hit})
    return hits


def main() -> None:
    control = bazeries_encrypt("UNIVERSITY", 900004, digit_name(900004))
    if control != "QMHATRMGXS":
        raise AssertionError(f"Bazeries control mismatch: {control}")
    if bazeries_decrypt(control, 900004, digit_name(900004)) != "UNIVERSITY":
        raise AssertionError("Bazeries control did not round-trip")

    rest = dsl.bif_full()[7:]
    if len(rest) != 563:
        raise AssertionError(f"expected BIF_REST=563, got {len(rest)}")

    scorer = Scorer()
    baseline = scorer(rest)
    rows: list[dict] = []
    hits: list[dict] = []

    for number in (563, 103, 570, 101):
        keywords = {
            "traditional/digits": digit_name(number),
            "traditional/full": number_name(number),
            "header/BTCSEED": "BTCSEED",
            "source/DBIFHCEG": "DBIFHCEG",
        }
        for key_kind, keyword in keywords.items():
            plaintext = bazeries_decrypt(rest, number, keyword)
            oracle_hits = hard_oracles(plaintext)
            row = {
                "number": number,
                "key_kind": key_kind,
                "keyword": keyword,
                "score": scorer(plaintext),
                "head": plaintext[:80],
                "hits": oracle_hits,
            }
            rows.append(row)
            hits.extend({"candidate": row, **hit} for hit in oracle_hits)

    rows.sort(key=lambda row: row["score"], reverse=True)
    report = {
        "control": {
            "ciphertext": control,
            "expected": "QMHATRMGXS",
            "roundtrip": True,
        },
        "hypothesis": "Bazeries(BIF_REST), keys fixed by 563=prime_103 / 103 / 570 / matrixsumlist=101",
        "baseline_score": baseline,
        "candidates": len(rows),
        "hits": hits,
        "solve": bool(hits),
        "top": rows,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=== BTCSEED / BAZERIES ===")
    print(f"control={control} roundtrip=ok")
    print(f"baseline={baseline:.4f} candidates={len(rows)} hits={len(hits)}")
    for row in rows[:8]:
        print(
            f"{row['score']:.4f} n={row['number']} {row['key_kind']:<20} "
            f"{row['head'][:52]}"
        )
    print(f"report={OUT}")


if __name__ == "__main__":
    main()
