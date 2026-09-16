# -*- coding: utf-8 -*-
"""Ataque focado: os 104 bits ASCII ordenam as 104 posições primas de ``faed``.

Hipótese falsificável
--------------------
O trecho a/b decodifica ``matrixsumlist`` e tem 104 bits. ``faed`` possui
exatamente 104 posições primas (tanto na convenção base 0 quanto na base 1).
Em vez de tratar os bits como uma máscara que apaga caracteres, este ataque os
trata como instruções de rota: partição estável 0/1, intercalação dos grupos,
deque esquerda/direita e rotas locais numa matriz de 13 bytes por 8 bits.

Cada rota e sua inversa são aplicadas ao fluxo dos 104 caracteres primos. O
resultado é testado isoladamente e reinserido nas posições primas do texto de
570 caracteres. As poucas orientações testadas correspondem a leitura direta,
espelhada, ordem inversa dos bytes e inversão dos bits dentro de cada byte.

Os candidatos seguem a cadeia observada no puzzle: materialização, SHA256 em
hexadecimal e AES-256-CBC/EVP-SHA256 nos três blobs. Digestos e janelas de 32
bytes também passam pelo oráculo da chave pública, incluindo o ponto negado.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import deque
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "solver" / "experiments" / "claude_endgame_2026_09_02"
sys.path.insert(0, str(EXPERIMENTS))

import gsmg_common as G  # noqa: E402
from coincurve import PublicKey  # noqa: E402


OUT = ROOT / "_work" / "new_approach_page39" / "prime_ascii_permutation_attack.json"
WORD = "matrixsumlist"
BLOBS = ("SMALL", "COSMIC", "TAIL32")
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBLIC_KEY = bytes.fromhex(G.TARGET_PUBKEY_HEX)
TARGET_X = TARGET_PUBLIC_KEY[1:33]
TARGET_Y = int.from_bytes(TARGET_PUBLIC_KEY[33:], "big")
NEGATED_PUBLIC_KEY = b"\x04" + TARGET_X + (FIELD_PRIME - TARGET_Y).to_bytes(32, "big")


def page_sources() -> tuple[str, str, str]:
    """Extrai dbbi, a camada a/b e faed da transcrição verbatim."""
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


def inverse_route(route: Sequence[int]) -> tuple[int, ...]:
    inverse = [0] * len(route)
    for output_index, source_index in enumerate(route):
        inverse[source_index] = output_index
    return tuple(inverse)


def interleave(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    output: list[int] = []
    for index in range(max(len(left), len(right))):
        if index < len(left):
            output.append(left[index])
        if index < len(right):
            output.append(right[index])
    return tuple(output)


def oriented_bits(bits: Sequence[int]) -> dict[str, tuple[int, ...]]:
    chunks = [tuple(bits[i : i + 8]) for i in range(0, len(bits), 8)]
    variants = {
        "direct": tuple(bits),
        "mirror": tuple(reversed(bits)),
        "bytes_reverse": tuple(bit for chunk in reversed(chunks) for bit in chunk),
        "bits_in_each_byte_reverse": tuple(bit for chunk in chunks for bit in reversed(chunk)),
    }
    output: dict[str, tuple[int, ...]] = {}
    seen: set[tuple[int, ...]] = set()
    for name, variant in variants.items():
        if variant not in seen:
            output[name] = variant
            seen.add(variant)
    return output


def route_families(bits: Sequence[int]) -> dict[str, tuple[int, ...]]:
    """Gera somente rotas binárias diretamente motivadas pelas pistas."""
    n = len(bits)
    assert n == 104 and n % 8 == 0
    groups = {
        0: tuple(index for index, bit in enumerate(bits) if bit == 0),
        1: tuple(index for index, bit in enumerate(bits) if bit == 1),
    }
    routes: dict[str, tuple[int, ...]] = {
        "stable_01": groups[0] + groups[1],
        "stable_10": groups[1] + groups[0],
        "stable_01_reverse_groups": groups[0][::-1] + groups[1][::-1],
        "stable_10_reverse_groups": groups[1][::-1] + groups[0][::-1],
        "interleave_01": interleave(groups[0], groups[1]),
        "interleave_10": interleave(groups[1], groups[0]),
    }

    for left_bit in (0, 1):
        routed: deque[int] = deque()
        for index, bit in enumerate(bits):
            if bit == left_bit:
                routed.appendleft(index)
            else:
                routed.append(index)
        routes[f"deque_left_{left_bit}"] = tuple(routed)

    for first_bit in (0, 1):
        rows: list[tuple[int, ...]] = []
        for offset in range(0, n, 8):
            block = tuple(range(offset, offset + 8))
            first = tuple(index for index in block if bits[index] == first_bit)
            second = tuple(index for index in block if bits[index] != first_bit)
            rows.append(first + second)
        routes[f"byte_stable_{first_bit}{1 - first_bit}_row"] = tuple(
            index for row in rows for index in row
        )
        routes[f"byte_stable_{first_bit}{1 - first_bit}_column"] = tuple(
            rows[row][column] for column in range(8) for row in range(13)
        )

    for route in routes.values():
        assert sorted(route) == list(range(n))
        sample = tuple(range(n))
        routed = tuple(sample[index] for index in route)
        restored = tuple(routed[index] for index in inverse_route(route))
        assert restored == sample
    return routes


def unique_routes(bits: Sequence[int]) -> dict[str, tuple[int, ...]]:
    output: dict[tuple[int, ...], list[str]] = {}
    for orientation, oriented in oriented_bits(bits).items():
        for family, route in route_families(oriented).items():
            output.setdefault(route, []).append(f"{orientation}/{family}/forward")
            output.setdefault(inverse_route(route), []).append(f"{orientation}/{family}/inverse")
    return {" + ".join(names): route for route, names in output.items()}


def apply_route(text: str, route: Sequence[int]) -> str:
    return "".join(text[index] for index in route)


def reinsert(source: str, positions: Sequence[int], replacement: str) -> str:
    output = list(source)
    for position, char in zip(positions, replacement, strict=True):
        output[position] = char
    return "".join(output)


def add_candidate(
    candidates: dict[bytes, list[str]], name: str, data: bytes, mirror: bool = True
) -> None:
    if not data:
        return
    candidates.setdefault(data, []).append(name)
    if mirror:
        candidates.setdefault(data[::-1], []).append(f"{name}/text_mirror")


def add_materializations(candidates: dict[bytes, list[str]], name: str, text: str) -> None:
    add_candidate(candidates, f"{name}/symbols", text.encode("ascii"))
    add_candidate(candidates, f"{name}/symbols_upper", text.upper().encode("ascii"))
    digits = G.digits(text, base1=True)
    add_candidate(candidates, f"{name}/digits", "".join(map(str, digits)).encode("ascii"))
    try:
        add_candidate(candidates, f"{name}/zmethod", G.z_method(digits))
    except (ValueError, OverflowError):
        pass

    periods = {len(text), 13}
    if len(text) == len(G.FAED):
        periods.update((104, 285))
    for period in sorted(periods):
        for mode in ("decrypt", "encrypt"):
            decoded = G.bifid(text, G.CANON, period=period, n=5, mode=mode)
            add_candidate(
                candidates,
                f"{name}/bifid_{mode}_period_{period}",
                decoded.encode("ascii"),
            )


def build_candidates(
    bits: Sequence[int], faed: str
) -> tuple[dict[bytes, list[str]], dict[str, int]]:
    candidates: dict[bytes, list[str]] = {}
    routes = unique_routes(bits)
    stream_count = 0
    for base in (0, 1):
        positions = prime_indices(len(faed), base)
        assert len(positions) == len(bits) == 104
        prime_stream = "".join(faed[index] for index in positions)
        for route_name, route in routes.items():
            permuted = apply_route(prime_stream, route)
            stem = f"base{base}/{route_name}"
            add_materializations(candidates, f"{stem}/prime_stream", permuted)
            add_materializations(
                candidates,
                f"{stem}/full_reinsert",
                reinsert(faed, positions, permuted),
            )
            stream_count += 2
    return candidates, {"unique_routes": len(routes), "streams": stream_count}


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


def scan_private_keys(data: bytes) -> Iterable[dict[str, object]]:
    for offset in range(len(data) - 31):
        secret = data[offset : offset + 32]
        relation = public_key_relation(secret)
        if relation:
            yield {"offset": offset, "secret_hex": secret.hex(), "relation": relation}


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
    bits = [0 if char == "a" else 1 for char in raw_mask]
    assert bits == ascii_bits(WORD)
    assert decode_ab(raw_mask) == WORD

    candidates, route_stats = build_candidates(bits, faed)
    hard: list[dict[str, object]] = []
    soft: list[dict[str, object]] = []
    heuristic: list[dict[str, object]] = []

    for data, origins in candidates.items():
        digest = hashlib.sha256(data).digest()
        password = digest.hex()
        relation = public_key_relation(digest)
        if relation:
            hard.append(
                {
                    "kind": "sha256_private_key",
                    "origins": origins,
                    "secret_hex": password,
                    "relation": relation,
                }
            )

        for private_hit in scan_private_keys(data):
            hard.append(
                {"kind": "embedded_private_key", "origins": origins, **private_hit}
            )

        text = data.decode("latin-1")
        if any("/bifid_" in origin for origin in origins):
            score = G.english_score(text)
            words = G.word_hits(text, minlen=6)
            if score > -4.5 or len(words) >= 2:
                heuristic.append(
                    {
                        "origins": origins,
                        "score": round(score, 3),
                        "word_hits": words[:12],
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

    heuristic.sort(key=lambda item: (item["score"], len(item["word_hits"])), reverse=True)
    result = {
        "family": "prime_ascii_permutation",
        "hypothesis": __doc__.split("Hipótese falsificável", 1)[1]
        .split("Cada rota", 1)[0]
        .strip(),
        "controls": {
            "raw_mask_length": len(raw_mask),
            "raw_mask_decodes_to": decode_ab(raw_mask),
            "mask_zero_count": bits.count(0),
            "mask_one_count": bits.count(1),
            "prime_count_base0": len(prime_indices(len(faed), 0)),
            "prime_count_base1": len(prime_indices(len(faed), 1)),
            "route_roundtrips": True,
            "phase2": phase2_control(),
        },
        **route_stats,
        "candidate_count": len(candidates),
        "aes_tests": len(candidates) * len(BLOBS),
        "hard": hard,
        "soft_padding_count": len(soft),
        "soft": soft,
        "heuristic_count": len(heuristic),
        "heuristic_top": heuristic[:50],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    report = run()
    summary = {
        key: report[key]
        for key in (
            "family",
            "unique_routes",
            "streams",
            "candidate_count",
            "aes_tests",
            "hard",
            "soft_padding_count",
            "heuristic_count",
            "heuristic_top",
        )
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
