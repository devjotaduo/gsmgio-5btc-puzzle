# -*- coding: utf-8 -*-
"""Criptoanalise bounded do canal de payload isolado apos BTCSEED.

O BIF completo alterna um canal estrutural B/C/D/E com um canal de 25 letras.
Depois de remover os sete caracteres ``BTCSEED``, ``rest[0::2]`` contem 282
simbolos do canal de payload, enquanto ``rest[1::2]`` contem 281 simbolos do
canal estrutural. Campanhas anteriores testaram o canal de payload como chave
direta e sob chaves tematicas; este script recupera estatisticamente chaves
Vigenere desconhecidas, sem lista de palavras.

Legibilidade e apenas triagem. SOLVE continua exigindo ``aes_open`` ou a chave
privada do endereco-premio.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
import random

import dsl
import oracles as O
from scorer import Scorer


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "_work", "btcseed_payload_attack.json")
STANDARD25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
CANON25 = dsl.CANON
ENGLISH_FREQ = {
    "A": 0.0817, "B": 0.0149, "C": 0.0278, "D": 0.0425, "E": 0.1270,
    "F": 0.0223, "G": 0.0202, "H": 0.0609, "I": 0.0697, "K": 0.0077,
    "L": 0.0403, "M": 0.0241, "N": 0.0675, "O": 0.0751, "P": 0.0193,
    "Q": 0.0010, "R": 0.0599, "S": 0.0633, "T": 0.0906, "U": 0.0276,
    "V": 0.0098, "W": 0.0236, "X": 0.0015, "Y": 0.0197, "Z": 0.0007,
}


def decode(text: str, alphabet: str, shifts: list[int], direction: int) -> str:
    positions = {char: index for index, char in enumerate(alphabet)}
    size = len(alphabet)
    return "".join(
        alphabet[(direction * positions[char] - shifts[index % len(shifts)]) % size]
        for index, char in enumerate(text)
    )


def column_chi(column: str, alphabet: str, shift: int, direction: int) -> float:
    plaintext = decode(column, alphabet, [shift], direction)
    counts = Counter(plaintext)
    length = len(plaintext)
    score = 0.0
    for char in alphabet:
        expected = max(ENGLISH_FREQ.get(char, 0.0005) * length, 0.01)
        score += (counts.get(char, 0) - expected) ** 2 / expected
    return score


def initial_key(text: str, alphabet: str, period: int, direction: int) -> list[int]:
    return [
        min(
            range(len(alphabet)),
            key=lambda shift: column_chi(text[offset::period], alphabet, shift, direction),
        )
        for offset in range(period)
    ]


def coordinate_ascent(
    text: str,
    alphabet: str,
    shifts: list[int],
    direction: int,
    scorer: Scorer,
    passes: int = 5,
) -> tuple[float, str, list[int]]:
    current = shifts[:]
    plaintext = decode(text, alphabet, current, direction)
    best_score = scorer(plaintext)
    for _ in range(passes):
        changed = False
        for position in range(len(current)):
            original = current[position]
            local_best = best_score
            local_shift = original
            for shift in range(len(alphabet)):
                if shift == original:
                    continue
                current[position] = shift
                candidate_score = scorer(decode(text, alphabet, current, direction))
                if candidate_score > local_best:
                    local_best = candidate_score
                    local_shift = shift
            current[position] = local_shift
            if local_shift != original:
                changed = True
                best_score = local_best
        if not changed:
            break
    plaintext = decode(text, alphabet, current, direction)
    return best_score, plaintext, current


def crack(
    text: str,
    alphabet: str,
    period: int,
    direction: int,
    scorer: Scorer,
    restarts: int = 2,
) -> dict:
    starts = [initial_key(text, alphabet, period, direction)]
    rng = random.Random(period * 101 + direction * 17 + sum(map(ord, alphabet)))
    for _ in range(restarts):
        starts.append([rng.randrange(len(alphabet)) for _ in range(period)])

    best = (-math.inf, "", [])
    for start in starts:
        result = coordinate_ascent(text, alphabet, start, direction, scorer)
        if result[0] > best[0]:
            best = result
    score, plaintext, shifts = best
    return {
        "score": round(score, 6),
        "period": period,
        "alphabet": "standard25" if alphabet == STANDARD25 else "canon25",
        "direction": direction,
        "key_shifts": shifts,
        "key_letters": "".join(alphabet[shift] for shift in shifts),
        "plaintext": plaintext,
    }


def hard_checks(row: dict) -> list[dict]:
    plaintext = row["plaintext"]
    hits = []
    forms = {
        plaintext,
        plaintext.lower(),
        hashlib.sha256(plaintext.encode()).hexdigest(),
        hashlib.sha256(plaintext.lower().encode()).hexdigest(),
    }
    for form in forms:
        for hit in O.aes_open(form):
            hits.append({"kind": "aes_open", "password": form, "detail": hit})
        private = hashlib.sha256(form.encode()).digest()
        match = O.check_privkey(private)
        if match:
            hits.append({"kind": "privkey", "source": "sha256(form)", "detail": match})
    return hits


def decode_thematic(text: str, alphabet: str, key: str, mode: str) -> str:
    """Exact title-derived Vigenere/Beaufort candidate, without key search."""
    positions = {char: index for index, char in enumerate(alphabet)}
    shifts = [positions[char.replace("J", "I")] for char in key]
    output = []
    for index, char in enumerate(text):
        value = positions[char]
        shift = shifts[index % len(shifts)]
        if mode == "decrypt":
            decoded = value - shift
        elif mode == "encrypt":
            decoded = value + shift
        elif mode == "beaufort":
            decoded = shift - value
        else:
            raise ValueError(mode)
        output.append(alphabet[decoded % len(alphabet)])
    return "".join(output)


def run() -> dict:
    scorer = Scorer()
    full = dsl.bif_full()
    rest = full[7:]
    payload = rest[0::2]
    structural = rest[1::2]
    assert len(payload) == 282 and len(structural) == 281
    assert set(structural) <= set("BCDE")

    periods = list(range(1, 51)) + [57, 91, 94, 141]
    rows = []
    for alphabet in (STANDARD25, CANON25):
        for direction in (1, -1):
            for period in periods:
                rows.append(crack(payload, alphabet, period, direction, scorer))
    rows.sort(key=lambda row: row["score"], reverse=True)

    hits = []
    for row in rows[:20]:
        for hit in hard_checks(row):
            hits.append({"candidate": {key: row[key] for key in row if key != "plaintext"}, **hit})

    # O titulo SalPhaseIon e um anagrama exato de ALPHA NOESIS. Ele ja fora
    # testado como quadrado da primeira camada, mas nao como parametro da
    # segunda camada. Mantemos apenas o anagrama e a segmentacao literal do
    # proprio titulo; nao ha lista de palavras aberta.
    thematic_rows = []
    thematic_keys = ("SALPHASEION", "ALPHANOESIS", "NOESIS", "SAL", "PHASE", "ION")
    for surface_name, surface in (("rest", rest), ("payload", payload)):
        for alphabet in (STANDARD25, CANON25):
            for key in thematic_keys:
                for mode in ("decrypt", "encrypt", "beaufort"):
                    plaintext = decode_thematic(surface, alphabet, key, mode)
                    row = {
                        "score": round(scorer(plaintext), 6),
                        "surface": surface_name,
                        "alphabet": "standard25" if alphabet == STANDARD25 else "canon25",
                        "key": key,
                        "mode": mode,
                        "plaintext": plaintext,
                    }
                    thematic_rows.append(row)
                    for hit in hard_checks(row):
                        hits.append(
                            {
                                "candidate": {
                                    item: row[item] for item in row if item != "plaintext"
                                },
                                **hit,
                            }
                        )
    thematic_rows.sort(key=lambda row: row["score"], reverse=True)

    report = {
        "payload_length": len(payload),
        "structural_length": len(structural),
        "periods": periods,
        "candidates": len(rows),
        "top": rows[:20],
        "thematic_title_candidates": len(thematic_rows),
        "thematic_title_top": thematic_rows[:20],
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
    summary = {key: value for key, value in result.items() if key != "top"}
    summary["top"] = [
        {key: value for key, value in row.items() if key != "plaintext"} | {"head": row["plaintext"][:100]}
        for row in result["top"][:10]
    ]
    print(json.dumps(summary, ensure_ascii=False, indent=2))
