# -*- coding: utf-8 -*-
"""Reproduce and test the ``SEND THE BLUE NET TO SET HEX`` checkpoint.

The checkpoint recipe was published with the GSMG Telegram discussion and a
copy of the original program at https://ideone.com/fZkIsw.  DBBI and FAED are
*not* copied here: they are loaded from :mod:`oracles`, the repository's
canonical source extractor.

This script deliberately separates three claims:

1. reproduction -- the three reported rails must match byte-for-byte;
2. significance -- a seeded permutation null model measures the fixed-target
   coincidence, while explicitly retaining the post-selection caveat;
3. cryptographic consequence -- a small, named set of low-freedom encodings is
   tested against the existing AES and secp256k1 hard oracles.

No PKCS#7 padding event in the final 35-block layer is called a solution on its
own.  A solution requires a target/mirror pubkey hit or a meaningful plaintext
from one of the canonical salted blobs.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import math
import os
import random
import sys
from pathlib import Path
from typing import Callable, Iterable

from coincurve import PublicKey
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from ecdsa import SECP256k1

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

# Verbatim 14x14 phase-1 grid used by the public checkpoint program.  ``b`` and
# ``y`` retain colour information that is intentionally absent from the binary
# transcription in README.md.
GRID = (
    "00110b0010110y",
    "11b1001110b011",
    "1101110b001001",
    "0110b000011101",
    "0b1000110y0110",
    "100110y010y011",
    "100b1100010y00",
    "b11000000010y0",
    "00011b0111110b",
    "11b111y0110001",
    "1101000y011011",
    "11110010b01100",
    "0b0111010y0110",
    "01b0110110b011",
)

EXPECTED_RAILS = {
    "base": "JLIQFOPGVBLSENDTHECZAGJJYDSWCGUDJNFTWB",
    "blue": "JLUPFLPGLBLUENETDICZAGAJQDSWCGUDONFHWB",
    "yellow": "OLIQUBROVQLTOSETHEXQYOJSSICJFGUDCCVBWQ",
}
PRIMARY_TARGETS = ("SENDTHE", "BLUE", "TOSETHEX")
# ``NET`` is present immediately after BLUE in the rail, but the author of the
# program explicitly described the recovered markers as SENDTHE / BLUE /
# TOSETHEX.  BLUENET was a later community interpretation, so it is evaluated
# separately rather than silently promoted to ground truth.
EXTENDED_TARGETS = ("SENDTHE", "BLUENET", "TOSETHEX")
TARGETS = EXTENDED_TARGETS
TARGET_OFFSETS = (11, 9, 11)
ANCHOR = 11  # zero-based anchor for SENDTHE and TOSETHEX
RELATIVE_OFFSETS = tuple(offset - ANCHOR for offset in TARGET_OFFSETS)

CURVE_N = SECP256k1.order
FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
_target_y = int.from_bytes(TARGET_PUBKEY[33:], "big")
MIRROR_PUBKEY = TARGET_PUBKEY[:33] + (FIELD_P - _target_y).to_bytes(32, "big")


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    return all(value % divisor for divisor in range(2, math.isqrt(value) + 1))


def positions(mark: str) -> list[tuple[int, int, int]]:
    """Return (row, column, row-major-position), all one-based."""
    return [
        (row + 1, column + 1, row * 14 + column + 1)
        for row, line in enumerate(GRID)
        for column, value in enumerate(line)
        if value == mark
    ]


def mod_set(values: Iterable[int], modulus: int) -> set[int]:
    return {(value - 1) % modulus + 1 for value in values}


BLUE_POSITIONS = [linear for _, _, linear in positions("b")]
YELLOW_POSITIONS = [linear for _, _, linear in positions("y")]
BLUE_EDGES = {tuple(sorted((row, column))) for row, column, _ in positions("b")}
YELLOW_EDGES = {tuple(sorted((row, column))) for row, column, _ in positions("y")}
CANONICAL_EDGES = [
    (left, right) for left in range(1, 15) for right in range(left + 1, 15)
]


def graph_key(
    dbbi: str, zero_edges: set[tuple[int, int]] | frozenset = frozenset()
) -> list[int]:
    """Put DBBI on K14's canonical upper triangle and sum each node."""
    if len(dbbi) != 91:
        raise ValueError(f"DBBI must contain 91 edge weights, got {len(dbbi)}")
    matrix = [[0] * 14 for _ in range(14)]
    for value, (left, right) in zip(dbbi, CANONICAL_EDGES):
        weight = 0 if (left, right) in zero_edges else ord(value) - 96
        matrix[left - 1][right - 1] = weight
        matrix[right - 1][left - 1] = weight
    return [sum(row) for row in matrix]


def faed_row_sums(
    faed: str,
    zero: Callable[[int, int, str], bool] | None = None,
) -> list[int]:
    """Split FAED into 38 rows of 15 and sum a=1..i=9 after masking."""
    if len(faed) != 570:
        raise ValueError(f"FAED must contain 570 symbols, got {len(faed)}")
    zero = zero or (lambda _row, _column, _symbol: False)
    result = []
    for offset in range(0, len(faed), 15):
        total = 0
        for index, symbol in enumerate(faed[offset : offset + 15], offset):
            row, column = index // 15 + 1, index % 15 + 1
            if not zero(row, column, symbol):
                total += ord(symbol) - 96
        result.append(total)
    return result


def decode(row_sums: list[int], key: list[int]) -> str:
    return "".join(
        chr(((value ^ key[index % 14]) % 26) + 65)
        for index, value in enumerate(row_sums)
    )


def rail_outputs(dbbi: str, faed: str) -> dict[str, str]:
    blue_rows = mod_set(BLUE_POSITIONS, 38)
    yellow_columns = mod_set(YELLOW_POSITIONS, 15)
    prime_blue_symbols = {
        "abcdefghi"[value - 1]
        for value in mod_set(
            (position for position in BLUE_POSITIONS if is_prime(position)), 9
        )
    }

    def blue_zero(row: int, column: int, symbol: str) -> bool:
        return (
            row in blue_rows
            and column in yellow_columns
            and symbol in prime_blue_symbols
        )

    base_key = graph_key(dbbi)
    return {
        "base": decode(faed_row_sums(faed), base_key),
        "blue": decode(faed_row_sums(faed, blue_zero), base_key),
        "yellow": decode(faed_row_sums(faed), graph_key(dbbi, YELLOW_EDGES)),
    }


def reproduce_checkpoint() -> dict:
    source = O.sources()
    rails = rail_outputs(source["dbbi"], source["faed"])
    if rails != EXPECTED_RAILS:
        raise AssertionError(f"checkpoint drift: {rails!r}")

    blue_rows = mod_set(BLUE_POSITIONS, 38)
    yellow_columns = mod_set(YELLOW_POSITIONS, 15)
    prime_blue_mod9 = mod_set((value for value in BLUE_POSITIONS if is_prime(value)), 9)
    zeroed_faed = [
        index + 1
        for index, symbol in enumerate(source["faed"])
        if index // 15 + 1 in blue_rows
        and index % 15 + 1 in yellow_columns
        and ord(symbol) - 96 in prime_blue_mod9
    ]
    return {
        "dbbi_length": len(source["dbbi"]),
        "faed_length": len(source["faed"]),
        "dbbi_sha256": hashlib.sha256(source["dbbi"].encode()).hexdigest(),
        "faed_sha256": hashlib.sha256(source["faed"].encode()).hexdigest(),
        "dbbi_edges": len(CANONICAL_EDGES),
        "anchor_zero_based": ANCHOR,
        "anchor_one_based": ANCHOR + 1,
        "primary_marker_offsets_zero_based": dict(zip(PRIMARY_TARGETS, TARGET_OFFSETS)),
        "extended_marker_offsets_zero_based": dict(
            zip(EXTENDED_TARGETS, TARGET_OFFSETS)
        ),
        "strictly_same_start": len(set(TARGET_OFFSETS)) == 1,
        "relative_offsets_from_sendthe": dict(zip(TARGETS, RELATIVE_OFFSETS)),
        "rails": rails,
        "primary_markers": list(PRIMARY_TARGETS),
        "extended_community_interpretation": list(EXTENDED_TARGETS),
        "blue_positions_one_based": BLUE_POSITIONS,
        "blue_positions_hex": bytes(BLUE_POSITIONS).hex(),
        "yellow_positions_one_based": YELLOW_POSITIONS,
        "blue_mask": {
            "rows_mod_38": sorted(blue_rows),
            "columns_mod_15": sorted(yellow_columns),
            "prime_blue_mod_9": sorted(prime_blue_mod9),
            "zeroed_faed_count": len(zeroed_faed),
            "zeroed_faed_positions_one_based": zeroed_faed,
        },
        "yellow_zeroed_edges": sorted(list(YELLOW_EDGES)),
    }


def layout_score(
    rails: dict[str, str], anchor: int, targets: tuple[str, str, str] = TARGETS
) -> int:
    return sum(
        actual == expected
        for rail, target, delta in zip(
            ("base", "blue", "yellow"), targets, RELATIVE_OFFSETS
        )
        for actual, expected in zip(
            rails[rail][anchor + delta : anchor + delta + len(target)], target
        )
    )


def exact_layout_at(
    rails: dict[str, str],
    anchor: int,
    targets: tuple[str, str, str] = TARGETS,
) -> bool:
    return all(
        rails[rail][anchor + delta : anchor + delta + len(target)] == target
        for rail, target, delta in zip(
            ("base", "blue", "yellow"), targets, RELATIVE_OFFSETS
        )
    )


def percentile(sorted_values: list[int], fraction: float) -> int:
    if not sorted_values:
        return 0
    return sorted_values[round((len(sorted_values) - 1) * fraction)]


def binomial_upper_95(successes: int, trials: int) -> float:
    """One-sided 95% upper bound (exact for zero, Wilson otherwise)."""
    if not trials:
        return 1.0
    if successes == 0:
        return 1.0 - 0.05 ** (1.0 / trials)
    z = 1.6448536269514722
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = proportion + z * z / (2.0 * trials)
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / trials + z * z / (4.0 * trials * trials)
    )
    return min(1.0, (centre + radius) / denominator)


def one_null_model(
    name: str,
    dbbi: str,
    faed: str,
    trials: int,
    seed: int,
    shuffle_dbbi: bool,
) -> dict:
    rng = random.Random(seed)
    a, b = list(dbbi), list(faed)
    scores_at_anchor: list[int] = []
    maximum_scores: list[int] = []
    primary_scores_at_anchor: list[int] = []
    primary_maximum_scores: list[int] = []
    exact_anchor = exact_layout_anywhere = strict_aligned_anywhere = (
        score_ge_observed
    ) = 0
    primary_exact_anchor = primary_exact_layout_anywhere = primary_score_ge_observed = 0
    individual_anywhere = [0, 0, 0]
    observed_score = sum(map(len, TARGETS))
    first_anchor = max(-delta for delta in RELATIVE_OFFSETS)
    last_anchor = min(
        38 - len(target) - delta for target, delta in zip(TARGETS, RELATIVE_OFFSETS)
    )

    for _ in range(trials):
        if shuffle_dbbi:
            rng.shuffle(a)
        rng.shuffle(b)
        rails = rail_outputs("".join(a) if shuffle_dbbi else dbbi, "".join(b))
        anchor_score = layout_score(rails, ANCHOR)
        maximum_score = max(
            layout_score(rails, anchor)
            for anchor in range(first_anchor, last_anchor + 1)
        )
        primary_anchor_score = layout_score(rails, ANCHOR, PRIMARY_TARGETS)
        primary_maximum_score = max(
            layout_score(rails, anchor, PRIMARY_TARGETS)
            for anchor in range(first_anchor, last_anchor + 1)
        )
        scores_at_anchor.append(anchor_score)
        maximum_scores.append(maximum_score)
        primary_scores_at_anchor.append(primary_anchor_score)
        primary_maximum_scores.append(primary_maximum_score)
        exact_anchor += exact_layout_at(rails, ANCHOR)
        exact_layout_anywhere += any(
            exact_layout_at(rails, anchor)
            for anchor in range(first_anchor, last_anchor + 1)
        )
        strict_aligned_anywhere += any(
            all(
                rails[rail][offset : offset + len(target)] == target
                for rail, target in zip(("base", "blue", "yellow"), TARGETS)
            )
            for offset in range(min(38 - len(target) for target in TARGETS) + 1)
        )
        score_ge_observed += maximum_score >= observed_score
        primary_exact_anchor += exact_layout_at(rails, ANCHOR, PRIMARY_TARGETS)
        primary_exact_layout_anywhere += any(
            exact_layout_at(rails, anchor, PRIMARY_TARGETS)
            for anchor in range(first_anchor, last_anchor + 1)
        )
        primary_score_ge_observed += primary_maximum_score >= sum(
            map(len, PRIMARY_TARGETS)
        )
        for index, (rail, target) in enumerate(
            zip(("base", "blue", "yellow"), TARGETS)
        ):
            individual_anywhere[index] += target in rails[rail]

    scores_at_anchor.sort()
    maximum_scores.sort()
    primary_scores_at_anchor.sort()
    primary_maximum_scores.sort()
    return {
        "name": name,
        "seed": seed,
        "trials": trials,
        "preserves": "exact symbol counts; fixed 14x14 colour grid and published mask recipe",
        "shuffles": "FAED" if not shuffle_dbbi else "DBBI and FAED independently",
        "observed_aligned_score": observed_score,
        "exact_triple_at_anchor": exact_anchor,
        "exact_triple_any_same_relative_layout": exact_layout_anywhere,
        "exact_triple_strict_same_start": strict_aligned_anywhere,
        "max_score_ge_observed": score_ge_observed,
        "individual_target_anywhere": dict(zip(TARGETS, individual_anywhere)),
        "empirical_p_smoothed_for_max_score": (score_ge_observed + 1) / (trials + 1),
        "one_sided_95pct_upper_for_max_score": binomial_upper_95(
            score_ge_observed, trials
        ),
        "anchor_score": {
            "mean": sum(scores_at_anchor) / trials if trials else 0.0,
            "p50": percentile(scores_at_anchor, 0.50),
            "p90": percentile(scores_at_anchor, 0.90),
            "p99": percentile(scores_at_anchor, 0.99),
            "maximum": max(scores_at_anchor, default=0),
        },
        "maximum_relative_layout_score": {
            "mean": sum(maximum_scores) / trials if trials else 0.0,
            "p50": percentile(maximum_scores, 0.50),
            "p90": percentile(maximum_scores, 0.90),
            "p99": percentile(maximum_scores, 0.99),
            "p999": percentile(maximum_scores, 0.999),
            "maximum": max(maximum_scores, default=0),
        },
        "primary_published_markers_SENDTHE_BLUE_TOSETHEX": {
            "observed_score": sum(map(len, PRIMARY_TARGETS)),
            "exact_at_published_offsets": primary_exact_anchor,
            "exact_any_same_relative_layout": primary_exact_layout_anywhere,
            "max_score_ge_observed": primary_score_ge_observed,
            "empirical_p_smoothed_for_max_score": (primary_score_ge_observed + 1)
            / (trials + 1),
            "one_sided_95pct_upper_for_max_score": binomial_upper_95(
                primary_score_ge_observed, trials
            ),
            "anchor_score_mean": (
                sum(primary_scores_at_anchor) / trials if trials else 0.0
            ),
            "anchor_score_maximum": max(primary_scores_at_anchor, default=0),
            "maximum_layout_score_p99": percentile(primary_maximum_scores, 0.99),
            "maximum_layout_score_maximum": max(primary_maximum_scores, default=0),
        },
    }


def run_null_models(trials: int, seed: int) -> dict:
    source = O.sources()
    canonical = rail_outputs(source["dbbi"], source["faed"])
    observed = layout_score(canonical, ANCHOR)
    if observed != 22 or not exact_layout_at(canonical, ANCHOR):
        raise AssertionError("canonical relative-layout checkpoint was not reproduced")
    models = [
        one_null_model(
            "shuffle_faed", source["dbbi"], source["faed"], trials, seed, False
        ),
        one_null_model(
            "shuffle_dbbi_and_faed",
            source["dbbi"],
            source["faed"],
            trials,
            seed ^ 0x9E3779B97F4A7C15,
            True,
        ),
    ]
    return {
        "extended_BLUENET_observed_score": observed,
        "primary_BLUE_observed_score": sum(map(len, PRIMARY_TARGETS)),
        "strictly_aligned": len(set(TARGET_OFFSETS)) == 1,
        "observed_offsets_zero_based": dict(zip(TARGETS, TARGET_OFFSETS)),
        "models": models,
        "interpretation": (
            "The Monte Carlo p-values condition on the already-published mask recipe and fixed target words. "
            "They do not price in researcher degrees of freedom or the post-hoc choice of the target words. "
            "The program author described SENDTHE/BLUE/TOSETHEX; NET is a later community extension. "
            "The markers are not strictly aligned: BLUE (and BLUENET) begins two characters earlier."
        ),
    }


def pack_bits(bits: Iterable[bool]) -> bytes:
    bit_string = "".join("1" if value else "0" for value in bits)
    bit_string += "0" * (-len(bit_string) % 8)
    return int(bit_string, 2).to_bytes(len(bit_string) // 8, "big")


def candidate_materials(checkpoint: dict) -> dict[str, bytes]:
    source = O.sources()
    blue_raw = bytes(BLUE_POSITIONS)
    blue_hex = blue_raw.hex().encode("ascii")
    blue_edges = BLUE_EDGES & set(CANONICAL_EDGES)
    edge_letters = bytes(
        ord(symbol)
        for symbol, edge in zip(source["dbbi"], CANONICAL_EDGES)
        if edge in blue_edges
    )
    edge_weights = bytes(
        ord(symbol) - 96
        for symbol, edge in zip(source["dbbi"], CANONICAL_EDGES)
        if edge in blue_edges
    )
    weighted_blue_graph = bytes(
        (ord(symbol) - 96) if edge in blue_edges else 0
        for symbol, edge in zip(source["dbbi"], CANONICAL_EDGES)
    )
    degree = bytes(sum(node in edge for edge in blue_edges) for node in range(1, 15))
    weighted_degree = bytes(
        sum(
            ord(symbol) - 96
            for symbol, edge in zip(source["dbbi"], CANONICAL_EDGES)
            if node in edge and edge in blue_edges
        )
        for node in range(1, 15)
    )
    blue_coords = bytes(
        value for row, column, _ in positions("b") for value in (row, column)
    )
    blue16 = (
        blue_raw + b"\x0d"
    )  # community's observed missing hex digit d, encoded as byte 0x0d
    blue_rows = mod_set(BLUE_POSITIONS, 38)
    yellow_columns = mod_set(YELLOW_POSITIONS, 15)
    prime_blue_symbols = {
        "abcdefghi"[value - 1]
        for value in mod_set(
            (position for position in BLUE_POSITIONS if is_prime(position)), 9
        )
    }

    def blue_zero(row: int, column: int, symbol: str) -> bool:
        return (
            row in blue_rows
            and column in yellow_columns
            and symbol in prime_blue_symbols
        )

    return {
        "original_instruction_compact": b"SENDTHEBLUETOSETHEX",
        "original_instruction_compact_lower": b"sendthebluetosethex",
        "original_instruction_spaced": b"SEND THE BLUE TO SET HEX",
        "original_instruction_spaced_lower": b"send the blue to set hex",
        "extended_instruction_compact": b"SENDTHEBLUENETTOSETHEX",
        "extended_instruction_compact_lower": b"sendthebluenettosethex",
        "extended_instruction_spaced": b"SEND THE BLUE NET TO SET HEX",
        "extended_instruction_spaced_lower": b"send the blue net to set hex",
        "three_rails": (
            EXPECTED_RAILS["base"] + EXPECTED_RAILS["blue"] + EXPECTED_RAILS["yellow"]
        ).encode(),
        "three_rails_lower": (
            EXPECTED_RAILS["base"] + EXPECTED_RAILS["blue"] + EXPECTED_RAILS["yellow"]
        )
        .lower()
        .encode(),
        "blue_positions_u8_one_based": blue_raw,
        "blue_positions_u8_zero_based": bytes(value - 1 for value in BLUE_POSITIONS),
        "blue_positions_hex_ascii": blue_hex,
        "blue_positions_hex_plus_0d_ascii": blue_hex + b"0d",
        "0d_plus_blue_positions_hex_ascii": b"0d" + blue_hex,
        "blue_positions_plus_missing_d_byte": blue16,
        "complete_hex_digit_set_ascii": b"0123456789abcdef",
        "blue_coordinates_u8_one_based": blue_coords,
        "blue_grid_mask_row_major": pack_bits(
            value == "b" for row in GRID for value in row
        ),
        "blue_edge_mask_canonical": pack_bits(
            edge in blue_edges for edge in CANONICAL_EDGES
        ),
        "blue_edge_dbbi_letters": edge_letters,
        "blue_edge_dbbi_weights": edge_weights,
        "blue_weighted_graph_91": weighted_blue_graph,
        "blue_graph_degree_14": degree,
        "blue_graph_weighted_degree_14": weighted_degree,
        "blue_masked_faed_row_sums": bytes(faed_row_sums(source["faed"], blue_zero)),
        "blue_zeroed_faed_indices_u16be": b"".join(
            int(value).to_bytes(2, "big")
            for value in checkpoint["blue_mask"]["zeroed_faed_positions_one_based"]
        ),
    }


def derive_keys(materials: dict[str, bytes]) -> dict[str, bytes]:
    candidates: dict[str, bytes] = {}
    seen: dict[bytes, str] = {}

    def add(label: str, value: bytes) -> None:
        if len(value) != 32 or value in seen:
            return
        seen[value] = label
        candidates[label] = value

    for label, raw in materials.items():
        add(f"{label}:sha256", hashlib.sha256(raw).digest())
        add(
            f"{label}:double_sha256",
            hashlib.sha256(hashlib.sha256(raw).digest()).digest(),
        )
        add(f"{label}:raw32", raw)
        if len(raw) == 16:
            add(f"{label}:repeat16", raw * 2)
    return candidates


@functools.lru_cache(maxsize=None)
def classify_secret(secret: bytes) -> dict | None:
    if len(secret) != 32:
        return None
    scalar = int.from_bytes(secret, "big")
    if not 1 <= scalar < CURVE_N:
        return None
    pubkey = PublicKey.from_valid_secret(secret).format(compressed=False)
    if pubkey == TARGET_PUBKEY:
        validation = O.check_privkey(secret)
        if validation is None:
            raise AssertionError(
                "target pubkey matched but address oracle rejected the scalar"
            )
        return {
            "kind": "target_private_key",
            "private_key": secret.hex(),
            "address": validation,
        }
    if pubkey == MIRROR_PUBKEY:
        recovered = (CURVE_N - scalar).to_bytes(32, "big")
        validation = O.check_privkey(recovered)
        if validation is None:
            raise AssertionError(
                "mirror pubkey matched but recovered target scalar failed the address oracle"
            )
        return {
            "kind": "mirror_private_key",
            "mirror_scalar": secret.hex(),
            "recovered_target_private_key": recovered.hex(),
            "address": validation,
        }
    return None


def unpad_or_none(data: bytes) -> bytes | None:
    if not data or len(data) % 16:
        return None
    amount = data[-1]
    if not 1 <= amount <= 16 or not data.endswith(bytes([amount]) * amount):
        return None
    return data[:-amount]


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(value in (9, 10, 13) or 32 <= value < 127 for value in data) / len(data)


def scan_decryption(
    label: str,
    plaintext: bytes,
    private_key_hits: list[dict],
    pubkey_marker_hits: list[dict],
) -> None:
    if TARGET_PUBKEY in plaintext:
        pubkey_marker_hits.append({"label": label, "kind": "target_pubkey_bytes"})
    if MIRROR_PUBKEY in plaintext:
        pubkey_marker_hits.append({"label": label, "kind": "mirror_pubkey_bytes"})
    # Do not assume that a recovered 32-byte scalar is AES-block aligned.
    for offset in range(0, len(plaintext) - 31):
        hit = classify_secret(plaintext[offset : offset + 32])
        if hit:
            private_key_hits.append({"label": f"{label}:secret@{offset}", **hit})


def salted_attempts(password: bytes) -> list[dict]:
    """Open canonical blobs with EVP key *and IV*, retaining padding separately."""
    attempts = []
    for blob_name, (salt, ciphertext) in O.blobs().items():
        for digest_module in (MD5, SHA256):
            key, iv = O._evp(password, salt, digest_module)
            padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
            plaintext = unpad_or_none(padded)
            if plaintext is None:
                continue
            attempts.append(
                {
                    "blob": blob_name,
                    "kdf": digest_module.__name__,
                    "plaintext": plaintext,
                    "printable_ratio": printable_ratio(plaintext),
                }
            )
    return attempts


def known_answer_tests(chain: dict[str, bytes]) -> dict:
    cases = {
        "SMALL": (F.CHAIN1_PASSWORD, chain["chain1"]),
        "COSMIC": (F.COSMIC_PASSWORD, chain["cosmic"]),
    }
    results = {}
    for blob_name, (password, expected) in cases.items():
        matches = [
            attempt
            for attempt in salted_attempts(password)
            if attempt["blob"] == blob_name and attempt["plaintext"] == expected
        ]
        if not matches:
            raise AssertionError(f"AES known-answer test failed for {blob_name}")
        results[blob_name] = {
            "kdfs": sorted(attempt["kdf"] for attempt in matches),
            "plaintext_length": len(expected),
            "plaintext_sha256": hashlib.sha256(expected).hexdigest(),
            "printable_ratio": round(printable_ratio(expected), 4),
        }

    if (
        O._h160(TARGET_PUBKEY).hex() != O.TARGET_H160
        or O._p2pkh(O._h160(TARGET_PUBKEY)) != O.PRIZE_ADDR
    ):
        raise AssertionError("target pubkey/address known-answer test failed")
    # Both constants must also parse as points on secp256k1.
    PublicKey(TARGET_PUBKEY)
    PublicKey(MIRROR_PUBKEY)

    scanner_private_hits: list[dict] = []
    scanner_marker_hits: list[dict] = []
    scan_decryption(
        "KAT",
        b"x" + TARGET_PUBKEY + b"y" + MIRROR_PUBKEY + b"z",
        scanner_private_hits,
        scanner_marker_hits,
    )
    scanner_kinds = {hit["kind"] for hit in scanner_marker_hits}
    if not {"target_pubkey_bytes", "mirror_pubkey_bytes"} <= scanner_kinds:
        raise AssertionError("target/mirror pubkey scanner known-answer test failed")
    if scanner_private_hits:
        raise AssertionError("public marker KAT was misclassified as a private-key hit")
    results["pubkey_marker_scanner"] = {
        "kinds": sorted(scanner_kinds),
        "stride": 1,
        "classified_as_private_key": False,
        "target_address": O.PRIZE_ADDR,
        "target_h160": O.TARGET_H160,
    }
    return results


def test_hypotheses(checkpoint: dict) -> dict:
    materials = candidate_materials(checkpoint)
    keys = derive_keys(materials)
    chain = F.reproduce()
    kat = known_answer_tests(chain)
    private_key_hits: list[dict] = []
    pubkey_marker_hits: list[dict] = []
    salted_padding_hits: list[dict] = []
    salted_semantic_hits: list[dict] = []
    salted_checkpoint_hits: list[dict] = []
    final_padding_hits: list[dict] = []

    for label, key in keys.items():
        hit = classify_secret(key)
        if hit:
            private_key_hits.append({"label": f"direct:{label}", **hit})

    passwords: dict[bytes, str] = {}
    for label, raw in materials.items():
        for suffix, candidate in (
            ("raw", raw),
            ("hex_ascii", raw.hex().encode("ascii")),
            ("sha256_hex", hashlib.sha256(raw).hexdigest().encode("ascii")),
        ):
            passwords.setdefault(candidate, f"{label}:{suffix}")
    for password, label in passwords.items():
        for attempt in salted_attempts(password):
            plaintext = attempt.pop("plaintext")
            record = {
                "label": label,
                **attempt,
                "printable_ratio": round(attempt["printable_ratio"], 4),
                "head_hex": plaintext[:64].hex(),
                "head_ascii": plaintext[:64].decode("ascii", "replace"),
            }
            salted_padding_hits.append(record)
            if attempt["printable_ratio"] >= 0.80:
                salted_semantic_hits.append(record)
            expected = (
                chain["chain1"] if attempt["blob"] == "SMALL" else chain["cosmic"]
            )
            if plaintext == expected:
                salted_checkpoint_hits.append(record)
            scan_decryption(
                f"salted:{label}:{attempt['blob']}:{attempt['kdf']}",
                plaintext,
                private_key_hits,
                pubkey_marker_hits,
            )

    ciphertext = chain["blocks"]
    blue16 = bytes(BLUE_POSITIONS) + b"\x0d"
    ivs = {
        "zero": bytes(16),
        "header_left": chain["header"][2:18],
        "header_right": chain["header"][14:30],
        "blue_plus_missing_d": blue16,
        "complete_hex_set": b"0123456789abcdef",
    }

    for key_label, key in keys.items():
        plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
        scan_decryption(
            f"final:{key_label}:ECB", plaintext, private_key_hits, pubkey_marker_hits
        )
        unpadded = unpad_or_none(plaintext)
        if unpadded is not None:
            final_padding_hits.append(
                {
                    "label": f"{key_label}:ECB",
                    "printable_ratio": round(printable_ratio(unpadded), 4),
                    "head_hex": unpadded[:64].hex(),
                    "head_ascii": unpadded[:64].decode("ascii", "replace"),
                }
            )
        for iv_label, iv in ivs.items():
            plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
            scan_decryption(
                f"final:{key_label}:CBC:{iv_label}",
                plaintext,
                private_key_hits,
                pubkey_marker_hits,
            )
            unpadded = unpad_or_none(plaintext)
            if unpadded is not None:
                final_padding_hits.append(
                    {
                        "label": f"{key_label}:CBC:{iv_label}",
                        "printable_ratio": round(printable_ratio(unpadded), 4),
                        "head_hex": unpadded[:64].hex(),
                        "head_ascii": unpadded[:64].decode("ascii", "replace"),
                    }
                )

    semantic_padding_hits = [
        hit for hit in final_padding_hits if hit["printable_ratio"] >= 0.80
    ]
    return {
        "materials": {label: value.hex() for label, value in materials.items()},
        "keys": {label: value.hex() for label, value in keys.items()},
        "material_count": len(materials),
        "key_count": len(keys),
        "password_count": len(passwords),
        "aes_decryptions_per_key": 1 + len(ivs),
        "aes_modes": {"ECB": 1, "CBC_IVs": list(ivs)},
        "known_answer_tests": kat,
        "secret_scan_stride_bytes": 1,
        "private_key_hits": private_key_hits,
        "pubkey_marker_hits": pubkey_marker_hits,
        "canonical_salted_padding_hits": salted_padding_hits,
        "canonical_salted_semantic_hits": salted_semantic_hits,
        "canonical_salted_checkpoint_hits": salted_checkpoint_hits,
        "final_pkcs7_padding_hits": final_padding_hits,
        "final_semantic_padding_hits": semantic_padding_hits,
        "verdict": (
            "PRIVATE_KEY_HIT"
            if private_key_hits
            else (
                "KNOWN_CHAIN_CHECKPOINT_REDISCOVERED"
                if salted_checkpoint_hits
                else "NO_HIT_IN_TESTED_HYPOTHESES"
            )
        ),
    }


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--null-trials",
        type=int,
        default=20_000,
        help="trials per null model (default: 20000)",
    )
    parser.add_argument(
        "--seed", type=parse_int, default=0xB10E5E7, help="PRNG seed (decimal or 0x...)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "_work" / "blue_net_attack.json",
        help="JSON report path",
    )
    args = parser.parse_args()
    if args.null_trials < 1:
        parser.error("--null-trials must be positive")

    checkpoint = reproduce_checkpoint()
    report = {
        "script": "solver/blue_net_attack.py",
        "checkpoint": checkpoint,
        "null_model": run_null_models(args.null_trials, args.seed),
        "hypotheses": test_hypotheses(checkpoint),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print("checkpoint original:", " / ".join(checkpoint["primary_markers"]))
    print(
        "checkpoint extended:",
        " / ".join(checkpoint["extended_community_interpretation"]),
    )
    print(
        "offsets:",
        checkpoint["extended_marker_offsets_zero_based"],
        "strictly aligned:",
        checkpoint["strictly_same_start"],
    )
    print("blue hex:", checkpoint["blue_positions_hex"])
    for model in report["null_model"]["models"]:
        print(
            f"null {model['name']}: {model['trials']} trials, "
            f"max={model['maximum_relative_layout_score']['maximum']}/22, "
            f"p95<={model['one_sided_95pct_upper_for_max_score']:.6g}"
        )
    hypotheses = report["hypotheses"]
    print(
        f"hypotheses: {hypotheses['material_count']} materials, {hypotheses['key_count']} keys, "
        f"private={len(hypotheses['private_key_hits'])}, "
        f"pubkey_markers={len(hypotheses['pubkey_marker_hits'])}, "
        f"salted_padding={len(hypotheses['canonical_salted_padding_hits'])}, "
        f"salted_semantic={len(hypotheses['canonical_salted_semantic_hits'])}, "
        f"padding={len(hypotheses['final_pkcs7_padding_hits'])}, "
        f"semantic_padding={len(hypotheses['final_semantic_padding_hits'])}"
    )
    print("verdict:", hypotheses["verdict"])
    print("report:", args.output)
    return 0 if not hypotheses["private_key_hits"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
