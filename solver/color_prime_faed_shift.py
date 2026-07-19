# -*- coding: utf-8 -*-
"""
Teste da hipótese: yellow/blue prime-sum como keystream modular em base 9
aplicado DIRETAMENTE ao faed, não ao dbbi/quadrado.

Estrutura usada:
- len(dbbi)=91; 24 primos < 91; 24 casas coloridas.
- len(faed)=570 = 6*91 + 24.
- sequência de cores em ordem espiral: BBBBYBBBYYBBBBYBBYYBYYBY.
- números de cor: Y=17, B=41; mod 9 => Y=8, B=5.
- pista abcdefghi -> 2 56 1 34 789 => a->2,b->5,c->6,d->1,e->3,f->4,g->7,h->8,i->9.

Depois de deslocar faed, roda Bifid canônico e valida via oráculos duros.
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
COLOR_SEQ = "BBBBYBBBYYBBBBYBBYYBYYBY"
PERM_DIGITS = "256134789"
PRIMES_91 = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89]
PERIODS = [570, 285, 190, 114, 95, 57, 41, 38, 19, 17, 15, 13, 7]


SYM_TO_DIGIT = {sym: int(d) for sym, d in zip("abcdefghi", PERM_DIGITS)}
DIGIT_TO_SYM = {int(d): sym for sym, d in zip("abcdefghi", PERM_DIGITS)}


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


def shifted_symbol(sym: str, shift: int, direction: int) -> str:
    """Aplica shift mod 9 nos dígitos 1..9 preservando domínio 1..9."""
    digit0 = SYM_TO_DIGIT[sym] - 1
    shifted0 = (digit0 + direction * shift) % 9
    return DIGIT_TO_SYM[shifted0 + 1]


def transform_faed(faed: str, direction: int, grey_mode: str, nonprime_mode: str) -> str:
    """
    grey_mode: original | neutral | blue | yellow
        O Telegram associa o quadrado FEFEFE a um marcador primo. Como o teste
        aplica COLOR_SEQ aos 24 primos <91, o valor 73 recebe um tratamento
        exploratório especial mesmo que COLOR_SEQ contenha apenas B/Y. Em
        `original`, a posição 73 usa a cor original de COLOR_SEQ.
    nonprime_mode: keep | to_a
    """
    assert len(faed) == 570
    chars = list(faed)

    def color_shift(color: str, prime: int) -> int:
        if prime == 73:
            if grey_mode == "neutral":
                return 0
            if grey_mode == "blue":
                return 41 % 9
            if grey_mode == "yellow":
                return 17 % 9
        if color == "B":
            return 41 % 9
        if color == "Y":
            return 17 % 9
        raise ValueError(color)

    # 6 blocos de 91: aplica nas posições primas 1-indexadas.
    for block in range(6):
        base = block * 91
        prime_positions = set(PRIMES_91)
        for prime, color in zip(PRIMES_91, COLOR_SEQ):
            idx = base + prime - 1
            shift = color_shift(color, prime)
            chars[idx] = shifted_symbol(chars[idx], shift, direction)
        if nonprime_mode == "to_a":
            for pos in range(1, 92):
                if pos not in prime_positions:
                    chars[base + pos - 1] = "a"

    # Cauda de 24: aplica COLOR_SEQ em todos os 24 caracteres finais. O valor
    # de `prime` aqui é o marcador estrutural pareado ao offset, não a posição
    # absoluta no faed; ele só existe para reaplicar a exceção FEFEFE/73.
    tail_base = 6 * 91
    for offset, color in enumerate(COLOR_SEQ):
        prime = PRIMES_91[offset]
        shift = color_shift(color, prime)
        chars[tail_base + offset] = shifted_symbol(chars[tail_base + offset], shift, direction)

    return "".join(chars)


def candidate_passwords(pt: str, label: str, transformed: str) -> set[str]:
    bases = {
        pt,
        pt.lower(),
        pt[:120],
        pt[7:] if pt.startswith("BTCSEED") else pt,
        transformed,
        transformed.lower(),
        label,
        label.replace("|", ""),
        "yellowblueprimesmatrixsumlistyinyang",
        "yellowblueprimes1741",
        "yellowblueprime1741",
        "BBBBYBBBYYBBBBYBBYYBYYBY",
        "256134789",
    }
    out = set(bases)
    for base in list(bases):
        if base:
            out.add(sha256hex(base))
            out.add(sha256hex(base.replace(" ", "")))
    return {item for item in out if item}


def run_oracles(pt: str, label: str, transformed: str) -> dict | None:
    for password in candidate_passwords(pt, label, transformed):
        hits = O.aes_open(password, min_ascii=0.80)
        if hits:
            return {"kind": "aes_open", "label": label, "password": password, "hits": hits, "head": pt[:160]}
        hit = O.check_privkey(hashlib.sha256(password.encode()).digest())
        if hit:
            return {"kind": "privkey_sha256", "label": label, "password": password, "hit": hit, "head": pt[:160]}
    return None


def main() -> None:
    faed = O.sources()["faed"]
    scorer = Scorer()
    rows: list[dict] = []

    for direction in (-1, 1):
        for grey_mode in ("original", "neutral", "blue", "yellow"):
            for nonprime_mode in ("keep", "to_a"):
                transformed = transform_faed(faed, direction, grey_mode, nonprime_mode)
                for period in PERIODS:
                    pt = bifid_decrypt(transformed.upper(), CANON, period)
                    score = scorer(pt)
                    label = f"dir={'minus' if direction < 0 else 'plus'}|grey={grey_mode}|nonprime={nonprime_mode}|p{period}"
                    rows.append({
                        "score": round(score, 4),
                        "label": label,
                        "transformed_head": transformed[:90],
                        "head": pt[:120],
                    })
                    hit = run_oracles(pt, label, transformed)
                    if hit:
                        path = os.path.join(OUT, "SOLVED.json")
                        with open(path, "w", encoding="utf-8") as f:
                            json.dump(hit, f, indent=2, ensure_ascii=False)
                        print(f"!!! SOLVE via {label} -> {path}")
                        print(json.dumps(hit, indent=2, ensure_ascii=False))
                        return

    rows.sort(key=lambda row: row["score"], reverse=True)
    path = os.path.join(OUT, "color_prime_faed_shift.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "color_sequence": COLOR_SEQ,
            "primes_91": PRIMES_91,
            "symbol_digit_map": {k: SYM_TO_DIGIT[k] for k in sorted(SYM_TO_DIGIT)},
            "tested": len(rows),
            "top": rows[:120],
        }, f, indent=2, ensure_ascii=False)

    print(f"=== COLOR PRIME FAED SHIFT: {len(rows)} construções testadas ===")
    print("Nenhum oráculo duro abriu SMALL/COSMIC nem bateu chave privada.")
    print("Top 20 por score de inglês:")
    for row in rows[:20]:
        print(f"  {row['score']:8.4f}  {row['label']:<52} {row['head']}")
    print(f"Relatório: {path}")


if __name__ == "__main__":
    main()