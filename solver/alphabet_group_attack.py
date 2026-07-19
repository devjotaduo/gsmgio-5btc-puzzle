# -*- coding: utf-8 -*-
"""
Ataque focado na pista nova encontrada pelo grafo vetorial / Telegram:

    "our first hint shabef ... hinting to abcdefghi 2 56 1 34 789"

Leitura testável: abcdefghi -> 256134789, isto é, uma permutação dos símbolos
a-i / dígitos 1-9. Também testa o par recente "yellow blue prime sum list"
(17, 41). Nada aqui declara solução sem passar pelos oráculos duros de
oracles.py (AES, privkey, etc.).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter

import oracles as O
from scorer import Scorer


OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(OUT, exist_ok=True)

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"
PREFIX = "DBIFHCEGA"
PERM_HINT = "256134789"
PERIODS = [570, 285, 190, 114, 95, 57, 41, 38, 19, 17, 15, 13, 7]


def sha256hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def bifid_decrypt(ct: str, alpha: str, period: int) -> str:
    pos = {c: (i // 5, i % 5) for i, c in enumerate(alpha)}
    out: list[str] = []
    for off in range(0, len(ct), period):
        block = ct[off:off + period]
        coords: list[int] = []
        for char in block:
            row, col = pos[char]
            coords.extend([row, col])
        n = len(block)
        rows, cols = coords[:n], coords[n:]
        out.append("".join(alpha[rows[i] * 5 + cols[i]] for i in range(n)))
    return "".join(out)


def keyword_square(keyword: str) -> str:
    seen: list[str] = []
    for char in (keyword.upper().replace("J", "I") + ALPHA25):
        if char in ALPHA25 and char not in seen:
            seen.append(char)
    assert len(seen) == 25
    return "".join(seen)


def permutation_maps() -> dict[str, dict[str, str]]:
    symbols = "abcdefghi"
    hinted = {sym: symbols[int(digit) - 1] for sym, digit in zip(symbols, PERM_HINT)}
    inverse = {value: key for key, value in hinted.items()}
    return {
        "identity": {sym: sym for sym in symbols},
        "hint_256134789": hinted,
        "hint_inverse": inverse,
    }


def translate_symbols(text: str, mapping: dict[str, str]) -> str:
    return "".join(mapping.get(char, char) for char in text)


def square_variants(dbbi: str) -> dict[str, str]:
    symbols = "abcdefghi"
    p_digits = [int(d) for d in PERM_HINT]

    # Prefixo canônico, mas reordenado pela pista em duas leituras defensáveis.
    by_symbol_hint = "".join(PREFIX[d - 1] for d in p_digits)
    by_digit_rank = "".join(char for _, char in sorted(zip(p_digits, PREFIX)))

    # Ordem de primeira ocorrência depois de aplicar a permutação ao dbbi.
    transformed = translate_symbols(dbbi, permutation_maps()["hint_256134789"])
    first_occurrence = "".join(dict.fromkeys(transformed.upper()))

    return {
        "canon": CANON,
        "prefix_by_hint": keyword_square(by_symbol_hint),
        "prefix_by_digit_rank": keyword_square(by_digit_rank),
        "dbbi_after_hint_firstocc": keyword_square(first_occurrence),
        "yellow_blue_prime_17_41": keyword_square("YELLOWBLUEPRIME1741"),
        "yellow_blue_prime_41_17": keyword_square("YELLOWBLUEPRIME4117"),
        "matrixsum_101_17_41": keyword_square("MATRIXSUMLIST1011741"),
    }


def candidate_passwords(pt: str, label: str) -> set[str]:
    bases = {
        pt,
        pt.lower(),
        pt.upper(),
        pt[:120],
        pt[:120].lower(),
        pt[7:] if pt.startswith("BTCSEED") else pt,
        label,
        label.replace("|", ""),
    }
    thematic = {
        "yellowblueprimes",
        "yellowblueprimesmatrixsumlistyinyang",
        "yellowblueprimes1741",
        "yellowblueprime1741",
        "yellowblueprimes4117",
        "matrixsumlist1011741",
        "abcdefghi256134789",
        "256134789",
        "ourfirsthintisyourlastcommand",
        "GSMGIO5BTCPUZZLECHALLENGE",
    }
    bases |= thematic
    out = set(bases)
    for base in list(bases):
        if base:
            out.add(sha256hex(base))
            out.add(sha256hex(base.replace(" ", "")))
    return {item for item in out if item}


def run_oracles(pt: str, label: str) -> dict | None:
    for password in candidate_passwords(pt, label):
        hits = O.aes_open(password, min_ascii=0.80)
        if hits:
            return {"kind": "aes_open", "label": label, "password": password, "hits": hits, "head": pt[:120]}
        for material in (password, password.lower(), password.upper()):
            hit = O.check_privkey(hashlib.sha256(material.encode()).digest())
            if hit:
                return {"kind": "privkey_sha256", "label": label, "password": password, "hit": hit, "head": pt[:120]}
    return None


def main() -> None:
    src = O.sources()
    faed = src["faed"]
    dbbi = src["dbbi"]
    scorer = Scorer()
    rows: list[dict] = []

    maps = permutation_maps()
    squares = square_variants(dbbi)

    for map_name, mapping in maps.items():
        transformed_faed = translate_symbols(faed, mapping).upper()
        for square_name, square in squares.items():
            for period in PERIODS:
                if period > len(transformed_faed):
                    continue
                pt = bifid_decrypt(transformed_faed, square, period)
                score = scorer(pt)
                label = f"{map_name}|{square_name}|p{period}"
                rows.append({"score": round(score, 4), "label": label, "head": pt[:80]})
                hit = run_oracles(pt, label)
                if hit:
                    path = os.path.join(OUT, "SOLVED.json")
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(hit, f, indent=2, ensure_ascii=False)
                    print(f"!!! SOLVE via {label} -> {path}")
                    print(json.dumps(hit, indent=2, ensure_ascii=False))
                    return

    # Também testa senhas diretas sem Bifid, porque 17/41 pode ser só componente.
    direct_rows = []
    for direct in candidate_passwords("", "direct"):
        hits = O.aes_open(direct, min_ascii=0.80)
        if hits:
            hit = {"kind": "aes_open_direct", "password": direct, "hits": hits}
            path = os.path.join(OUT, "SOLVED.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(hit, f, indent=2, ensure_ascii=False)
            print(f"!!! SOLVE direct -> {path}")
            print(json.dumps(hit, indent=2, ensure_ascii=False))
            return
        direct_rows.append(direct)

    rows.sort(key=lambda row: row["score"], reverse=True)
    path = os.path.join(OUT, "alphabet_group_attack.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tested": len(rows), "top": rows[:80]}, f, indent=2, ensure_ascii=False)

    print(f"=== ALPHABET GROUP ATTACK: {len(rows)} construções testadas ===")
    print("Nenhum oráculo duro abriu SMALL/COSMIC nem bateu chave privada.")
    print("Top 15 por score de inglês:")
    for row in rows[:15]:
        print(f"  {row['score']:8.4f}  {row['label']:<48} {row['head']}")
    print(f"Relatório: {path}")
    print("Prefixos mais comuns nos heads:", Counter(row["head"][:7] for row in rows).most_common(8))


if __name__ == "__main__":
    main()