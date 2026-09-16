# -*- coding: utf-8 -*-
"""Ataque focado: a máscara ASCII ``matrixsumlist`` nas posições primas de faed.

Hipótese falsificável
--------------------
O trecho a/b entre ``dbbi`` e ``faed`` tem 104 bits porque codifica o texto
ASCII ``matrixsumlist``. Também existem exatamente 104 índices primos menores
que 570. As pistas "prime positions", "some characters need to be zeroed out"
e "First or zero" instruem a alinhar esses 104 bits às posições primas de
``faed`` (base 0 ou 1) e zerar uma das polaridades. A gravura da página 39
motiva testar a ordem direta/espelhada e ambas as polaridades a/b.

O espaço é deliberadamente pequeno. Cada materialização segue o padrão já
provado do puzzle: SHA256 do candidato em hexadecimal como senha OpenSSL
AES-256-CBC/EVP-SHA256. O mesmo digest e bytes decodificados são verificados
como possíveis chaves privadas.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "solver" / "experiments" / "claude_endgame_2026_09_02"
sys.path.insert(0, str(EXPERIMENTS))

import gsmg_common as G  # noqa: E402


OUT = ROOT / "_work" / "new_approach_page39" / "prime_ascii_mask_attack.json"
WORD = "matrixsumlist"
BLOBS = ("SMALL", "COSMIC", "TAIL32")


def page_sources() -> tuple[str, str, str]:
    """Extrai dbbi, a máscara a/b e faed da linha verbatim do README."""
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


def ascii_bits(text: str) -> list[int]:
    return [int(bit) for byte in text.encode("ascii") for bit in f"{byte:08b}"]


def decode_ab(mask: str) -> str:
    bits = "".join("0" if char == "a" else "1" for char in mask)
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)).decode("ascii")


def prime_indices(length: int, base: int) -> list[int]:
    if base == 0:
        return [index for index in range(length) if G.is_prime(index)]
    return [index for index in range(length) if G.is_prime(index + 1)]


def symbol_string(digits: Iterable[int]) -> str:
    """Representação ensinada na página: o=0, a=1, ..., i=9."""
    alphabet = "oabcdefghi"
    return "".join(alphabet[digit] for digit in digits)


def add_materializations(
    candidates: dict[bytes, list[str]], name: str, digits: list[int]
) -> None:
    """Adiciona as formas naturais, deduplicadas pelo conteúdo em bytes."""

    def add(label: str, data: bytes) -> None:
        if not data:
            return
        candidates.setdefault(data, []).append(f"{name}/{label}")
        candidates.setdefault(data[::-1], []).append(f"{name}/{label}/mirror")

    add("digits", "".join(str(value) for value in digits).encode("ascii"))
    add("symbols", symbol_string(digits).encode("ascii"))
    add("symbols_upper", symbol_string(digits).upper().encode("ascii"))
    try:
        add("zmethod", G.z_method(digits))
    except (ValueError, OverflowError):
        pass


def build_candidates(mask_bits: list[int], faed: str) -> dict[bytes, list[str]]:
    source = G.digits(faed, base1=True)
    candidates: dict[bytes, list[str]] = {}

    for base in (0, 1):
        primes = prime_indices(len(source), base)
        assert len(primes) == len(mask_bits) == 104
        for order, bits in (("direct", mask_bits), ("mirror", mask_bits[::-1])):
            for dead_bit in (0, 1):
                full = source[:]
                prime_values = []
                living_values = []
                dead_values = []
                dead_positions = set()

                for index, bit in zip(primes, bits):
                    value = source[index]
                    if bit == dead_bit:
                        full[index] = 0
                        prime_values.append(0)
                        dead_values.append(value)
                        dead_positions.add(index)
                    else:
                        prime_values.append(value)
                        living_values.append(value)

                stem = f"base{base}/{order}/dead_{dead_bit}"
                add_materializations(candidates, f"{stem}/full_zero", full)
                add_materializations(candidates, f"{stem}/prime_zero", prime_values)
                add_materializations(candidates, f"{stem}/living_prime", living_values)
                add_materializations(candidates, f"{stem}/dead_prime", dead_values)
                add_materializations(
                    candidates,
                    f"{stem}/full_drop_dead",
                    [value for index, value in enumerate(source) if index not in dead_positions],
                )
    return candidates


def phase2_control() -> dict[str, object]:
    """Prova que a mesma cadeia SHA256→EVP-SHA256 abre um blob conhecido."""
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
    bits = [0 if char == "a" else 1 for char in raw_mask]
    assert bits == ascii_bits(WORD)
    assert decode_ab(raw_mask) == WORD

    candidates = build_candidates(bits, faed)
    hard: list[dict[str, object]] = []
    soft: list[dict[str, object]] = []
    readable: list[dict[str, object]] = []

    for data, origins in candidates.items():
        digest = hashlib.sha256(data).digest()
        password = digest.hex()

        private_hit = G.priv_hit(digest)
        if private_hit:
            hard.append(
                {
                    "kind": "sha256_private_key",
                    "origins": origins,
                    "digest": password,
                    "hit": str(private_hit),
                }
            )

        for hit in G.scan_priv(data, origins[0]):
            hard.append({"kind": "embedded_private_key", "origins": origins, "hit": str(hit)})

        if G.printable(data) >= 0.85:
            text = data.decode("latin-1")
            if G.semantic_text(text):
                readable.append(
                    {
                        "origins": origins,
                        "score": round(G.english_score(text), 3),
                        "text": text[:240],
                    }
                )

        for blob in BLOBS:
            for kdf, plaintext in G.aes_try(password, blob, kdf="sha256"):
                record = {
                    "blob": blob,
                    "kdf": kdf,
                    "origins": origins,
                    "password": password,
                    "printable": round(G.printable(plaintext), 3),
                    "plaintext_hex": plaintext.hex(),
                }
                if G.semantic(plaintext):
                    hard.append({"kind": "aes", **record})
                else:
                    soft.append(record)

    result = {
        "family": "prime_ascii_mask",
        "hypothesis": __doc__.split("Hipótese falsificável", 1)[1].split(
            "O espaço", 1
        )[0].strip(),
        "controls": {
            "raw_mask_length": len(raw_mask),
            "raw_mask_decodes_to": decode_ab(raw_mask),
            "prime_count_base0": len(prime_indices(570, 0)),
            "prime_count_base1": len(prime_indices(570, 1)),
            "phase2": phase2_control(),
        },
        "candidate_count": len(candidates),
        "aes_tests": len(candidates) * len(BLOBS),
        "hard": hard,
        "soft_padding_count": len(soft),
        "soft": soft,
        "readable": sorted(readable, key=lambda item: item["score"], reverse=True),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    report = run()
    print(json.dumps(report, ensure_ascii=False, indent=2))
