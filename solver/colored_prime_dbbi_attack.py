# -*- coding: utf-8 -*-
"""
Ataque focado na leitura mais principiada da pista:

  yellow blue primes
  24 casas coloridas = 24 primos menores que 91 = len(dbbi)
  "some characters need to be zeroed out"

Mapeia a sequência de cores das 24 casas coloridas (em ordem espiral, conforme
o Telegram) aos 24 índices primos de dbbi. Em seguida, zera/remove/substitui
letras nos índices amarelos/azuis e usa o dbbi resultante como fonte de keyword
para o quadrado Bifid. Cada candidato é julgado pelos oráculos duros.
"""

from __future__ import annotations

import hashlib
import json
import os

import oracles as O
from scorer import Scorer


OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(OUT, exist_ok=True)

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"
PERIODS = [570, 285, 190, 114, 95, 57, 41, 38, 19, 17, 15, 13, 7]

# Ordem reportada no Telegram para as casas coloridas em espiral:
# 8 B, 16 B, 24 B, 32 B, 40 Y, 48 B, 56 B, 64 B, 72 Y, 80 Y,
# 88 B, 96 B, 104 B, 112 B, 120 Y, 128 B, 136 B, 144 Y,
# 152 Y, 160 B, 168 Y, 176 Y, 184 B, 192 Y.
COLOR_SEQ = "BBBBYBBBYYBBBBYBBYYBYYBY"


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


PRIMES_1IDX = [n for n in range(1, 92) if is_prime(n)]  # primos 1-indexados <= 91 (91 não é primo)
assert len(PRIMES_1IDX) == 24
assert len(COLOR_SEQ) == 24


def sha256hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def keyword_square(keyword: str) -> str:
    seen: list[str] = []
    for char in (keyword.upper().replace("J", "I") + ALPHA25):
        if char in ALPHA25 and char not in seen:
            seen.append(char)
    assert len(seen) == 25
    return "".join(seen)


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


def mutate_dbbi(dbbi: str) -> dict[str, str]:
    prime_to_color = dict(zip(PRIMES_1IDX, COLOR_SEQ))
    variants: dict[str, str] = {}

    for target in ("Y", "B"):
        target_name = "yellow" if target == "Y" else "blue"
        keep = []
        remove = []
        to_a = []
        to_i = []
        to_zero_char = []
        for idx, char in enumerate(dbbi, start=1):
            is_target_prime = prime_to_color.get(idx) == target
            if is_target_prime:
                remove.append("")
                to_a.append("a")
                to_i.append("i")
                to_zero_char.append("0")
            else:
                remove.append(char)
                to_a.append(char)
                to_i.append(char)
                to_zero_char.append(char)
            if is_target_prime:
                keep.append(char)

        variants[f"remove_{target_name}_prime_colors"] = "".join(remove)
        variants[f"{target_name}_prime_colors_to_a"] = "".join(to_a)
        variants[f"{target_name}_prime_colors_to_i"] = "".join(to_i)
        variants[f"{target_name}_prime_colors_to_0"] = "".join(to_zero_char)
        variants[f"keep_{target_name}_prime_colors_only"] = "".join(keep)

    # Leituras complementares: só letras nos primos coloridos, nas duas cores.
    variants["colored_prime_letters_all"] = "".join(dbbi[p - 1] for p in PRIMES_1IDX)
    variants["colored_prime_letters_blue"] = "".join(dbbi[p - 1] for p, c in zip(PRIMES_1IDX, COLOR_SEQ) if c == "B")
    variants["colored_prime_letters_yellow"] = "".join(dbbi[p - 1] for p, c in zip(PRIMES_1IDX, COLOR_SEQ) if c == "Y")
    variants["canon_dbbi"] = dbbi
    return variants


def candidate_passwords(pt: str, label: str) -> set[str]:
    bases = {
        pt,
        pt.lower(),
        pt[:120],
        pt[7:] if pt.startswith("BTCSEED") else pt,
        label,
        label.replace("|", ""),
        "".join(str(p) for p in PRIMES_1IDX),
        COLOR_SEQ,
        "yellowblueprimes",
        "yellowblueprimesmatrixsumlistyinyang",
    }
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
        hit = O.check_privkey(hashlib.sha256(password.encode()).digest())
        if hit:
            return {"kind": "privkey_sha256", "label": label, "password": password, "hit": hit, "head": pt[:120]}
    return None


def main() -> None:
    src = O.sources()
    dbbi = src["dbbi"]
    faed = src["faed"].upper()
    scorer = Scorer()
    rows: list[dict] = []

    variants = mutate_dbbi(dbbi)
    for name, keyword in variants.items():
        square = keyword_square(keyword)
        for period in PERIODS:
            if period > len(faed):
                continue
            pt = bifid_decrypt(faed, square, period)
            score = scorer(pt)
            label = f"{name}|square={square[:9]}|p{period}"
            rows.append({"score": round(score, 4), "label": label, "keyword": keyword, "square": square, "head": pt[:90]})
            hit = run_oracles(pt, label)
            if hit:
                path = os.path.join(OUT, "SOLVED.json")
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(hit, f, indent=2, ensure_ascii=False)
                print(f"!!! SOLVE via {label} -> {path}")
                print(json.dumps(hit, indent=2, ensure_ascii=False))
                return

    rows.sort(key=lambda row: row["score"], reverse=True)
    path = os.path.join(OUT, "colored_prime_dbbi_attack.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"prime_positions": PRIMES_1IDX, "color_sequence": COLOR_SEQ, "tested": len(rows), "top": rows[:100]}, f, indent=2, ensure_ascii=False)

    print(f"=== COLORED PRIME DBBI ATTACK: {len(rows)} construções testadas ===")
    print("Nenhum oráculo duro abriu SMALL/COSMIC nem bateu chave privada.")
    print(f"Primos mapeados: {PRIMES_1IDX}")
    print(f"Cores: {COLOR_SEQ}")
    print("Top 15 por score de inglês:")
    for row in rows[:15]:
        print(f"  {row['score']:8.4f}  {row['label']:<64} {row['head']}")
    print(f"Relatório: {path}")


if __name__ == "__main__":
    main()