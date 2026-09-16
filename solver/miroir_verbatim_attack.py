# -*- coding: utf-8 -*-
"""Ataque focal no verso verbatim da gravura ``Le Miroir...`` (p. 39).

O scan anterior usava OCR parcial e continha palavras reconstruídas. A camada
MRC de 300 DPI do PDF torna as seis linhas legíveis. A pista já decodificada
``lastwordsbeforearchichoice`` dá uma seleção objetiva: as últimas palavras das
linhas. ``Miroir`` e o desenho vida/morte motivam somente ordens direta,
reversa e de fora para dentro; ``intertwined`` já foi provado como XOR de
SHA256 individuais, então o mesmo operador é testado nos grupos de palavras.

Nada é aceito por aparência isolada. Os oráculos duros são a chave pública do
prêmio (e seu ponto negado), AES-256-CBC/EVP-MD5 e EVP-SHA256 nos três blobs e busca da
chave pública em todas as janelas de 32 bytes das decifrações dos 35 blocos.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from itertools import zip_longest
from pathlib import Path
from typing import Iterable, Sequence

from Crypto.Cipher import AES
from coincurve import PublicKey


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "solver" / "experiments" / "claude_endgame_2026_09_02"
sys.path.insert(0, str(ROOT / "solver"))
sys.path.insert(0, str(EXPERIMENTS))

import final_chain as F  # noqa: E402
import gsmg_common as G  # noqa: E402


OUT = ROOT / "_work" / "new_approach_skills" / "miroir_verbatim_attack.json"
VERSE_FILE = ROOT / "_work" / "miroir_verse.txt"
BLOBS = ("SMALL", "COSMIC", "TAIL32")
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBLIC_KEY = bytes.fromhex(G.TARGET_PUBKEY_HEX)
TARGET_X = TARGET_PUBLIC_KEY[1:33]
TARGET_Y = int.from_bytes(TARGET_PUBLIC_KEY[33:], "big")
NEGATED_PUBLIC_KEY = b"\x04" + TARGET_X + (FIELD_PRIME - TARGET_Y).to_bytes(32, "big")

TITLE = "LE MIROIR DE LA VIE ET DE LA MORT"
LINES = (
    "Mondains qui faictes cas des beautez d'un visage",
    "Scachez que les aymer ce n'est pas estre sage",
    "Puis que le temps enfin les doibt faire perir",
    "Nous n'auons icy bas chose aucune asseurée",
    "Tout change et nostre vie a si peu de durée",
    "Quen commencent a vivre on commence a mourir",
)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xor_all(parts: Iterable[bytes]) -> bytes:
    output = bytearray(32)
    for part in parts:
        assert len(part) == 32
        for index, value in enumerate(part):
            output[index] ^= value
    return bytes(output)


def outside_in(items: Sequence[str]) -> tuple[str, ...]:
    output: list[str] = []
    left, right = 0, len(items) - 1
    while left <= right:
        output.append(items[left])
        if left != right:
            output.append(items[right])
        left += 1
        right -= 1
    return tuple(output)


def inside_out(items: Sequence[str]) -> tuple[str, ...]:
    return tuple(reversed(outside_in(tuple(reversed(items)))))


def prime_subset(items: Sequence[str], base: int) -> tuple[str, ...]:
    return tuple(
        item
        for index, item in enumerate(items)
        if G.is_prime(index if base == 0 else index + 1)
    )


def ascii_fold(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def normalize_forms(text: str) -> dict[str, bytes]:
    collapsed = " ".join(text.split())
    ascii_folded = ascii_fold(text)
    ascii_collapsed = " ".join(ascii_folded.split())
    letters = re.sub(r"[^A-Za-z]", "", ascii_folded)
    return {
        "verbatim": text.encode("utf-8"),
        "collapsed": collapsed.encode("utf-8"),
        "lower": collapsed.lower().encode("utf-8"),
        "upper": collapsed.upper().encode("utf-8"),
        "ascii_collapsed": ascii_collapsed.encode("ascii"),
        "letters": letters.encode("ascii"),
        "letters_lower": letters.lower().encode("ascii"),
        "letters_upper": letters.upper().encode("ascii"),
    }


def candidate_texts() -> dict[bytes, list[str]]:
    first = tuple(line.split()[0] for line in LINES)
    last = tuple(line.split()[-1] for line in LINES)
    initials = "".join(word[0] for word in first)
    finals = "".join(word[0] for word in last)
    verse = "\n".join((TITLE, *[f"{line}," for line in LINES]))
    assert VERSE_FILE.read_text(encoding="utf-8").strip() == verse
    assert last == ("visage", "sage", "perir", "asseurée", "durée", "mourir")

    sources: dict[str, str] = {
        "verse_with_title": verse,
        "verse_without_title": "\n".join(LINES),
        "verse_modern_v": "\n".join(LINES).replace("n'auons", "n'avons"),
        "title": TITLE,
        "acrostic": initials,
        "telestich": finals,
        "acrostic_telestich": initials + finals,
        "telestich_acrostic": finals + initials,
        "first_lengths": "".join(str(len(word)) for word in first),
        "last_lengths": "".join(str(len(word)) for word in last),
        "line_lengths_letters": "".join(
            str(len(re.sub(r"[^A-Za-z]", "", ascii_fold(line)))) for line in LINES
        ),
    }

    groups = {"first_words": first, "last_words": last, "full_lines": LINES}
    for group_name, words in groups.items():
        orders = {
            "forward": tuple(words),
            "reverse": tuple(reversed(words)),
            "outside_in": outside_in(words),
            "inside_out": inside_out(words),
            "prime_base0": prime_subset(words, 0),
            "prime_base1": prime_subset(words, 1),
        }
        for order_name, ordered in orders.items():
            for separator_name, separator in (
                ("joined", ""),
                ("spaces", " "),
                ("commas", ","),
                ("newlines", "\n"),
            ):
                sources[f"{group_name}/{order_name}/{separator_name}"] = separator.join(ordered)

    pairs = list(zip(first, last, strict=True))
    for pair_order_name, ordered_pairs in (
        ("forward", pairs),
        ("reverse", list(reversed(pairs))),
        ("outside_in", [pairs[index] for index in (0, 5, 1, 4, 2, 3)]),
    ):
        sources[f"line_edges/{pair_order_name}/first_last"] = "".join(
            first_word + last_word for first_word, last_word in ordered_pairs
        )
        sources[f"line_edges/{pair_order_name}/last_first"] = "".join(
            last_word + first_word for first_word, last_word in ordered_pairs
        )

    sources["first_last/interleave"] = "".join(
        item for pair in zip_longest(first, last, fillvalue="") for item in pair
    )

    candidates: dict[bytes, list[str]] = {}
    for source_name, text in sources.items():
        for form_name, data in normalize_forms(text).items():
            candidates.setdefault(data, []).append(f"{source_name}/{form_name}")
            candidates.setdefault(data[::-1], []).append(f"{source_name}/{form_name}/mirror")
    return candidates


def xor_candidates() -> dict[bytes, list[str]]:
    first = tuple(line.split()[0] for line in LINES)
    last = tuple(line.split()[-1] for line in LINES)
    line_edges = tuple(a + b for a, b in zip(first, last, strict=True))
    groups = {
        "first_words": first,
        "last_words": last,
        "line_edges": line_edges,
        "full_lines": LINES,
        "last_prime_base0": prime_subset(last, 0),
        "last_prime_base1": prime_subset(last, 1),
    }
    output: dict[bytes, list[str]] = {}
    for group_name, values in groups.items():
        for form_name, transform in (
            ("original", lambda value: value.encode("utf-8")),
            ("lower", lambda value: value.lower().encode("utf-8")),
            ("upper", lambda value: value.upper().encode("utf-8")),
            (
                "letters_lower",
                lambda value: re.sub(r"[^a-z]", "", ascii_fold(value).lower()).encode(),
            ),
        ):
            digest = xor_all(sha256(transform(value)) for value in values)
            output.setdefault(digest, []).append(f"xorsha/{group_name}/{form_name}")
    return output


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


def decrypt_final_blocks(key: bytes, chain: dict[str, bytes]) -> Iterable[tuple[str, bytes]]:
    body = chain["blocks"]
    ivs = {
        "zero": bytes(16),
        "header": chain["header"][2:18],
        "half": chain["half"][:16],
        "better_half": chain["better_half"][:16],
        "block0": body[:16],
    }
    for name, iv in ivs.items():
        yield f"cbc/{name}", AES.new(key, AES.MODE_CBC, iv).decrypt(body)
    yield "ecb", AES.new(key, AES.MODE_ECB).decrypt(body)


def phase_controls() -> dict[str, object]:
    salt, ciphertext = G._parse(G.PHASE2_B64)
    password = G.shahex("causality").encode("ascii")
    key, iv = G.evp(password, salt, G.SHA256)
    phase2_plaintext = G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))
    cosmic = G.aes_try(F.COSMIC_PASSWORD, "COSMIC", kdf="md5")
    assert phase2_plaintext is not None and G.semantic(phase2_plaintext)
    assert cosmic and hashlib.sha256(cosmic[0][1]).hexdigest() == F.COSMIC_SHA256
    return {
        "phase2_prefix": phase2_plaintext[:40].decode("latin-1"),
        "cosmic_sha256": hashlib.sha256(cosmic[0][1]).hexdigest(),
    }


def run() -> dict[str, object]:
    controls = phase_controls()
    chain = F.reproduce()
    texts = candidate_texts()
    xor_keys = xor_candidates()
    hard: list[dict[str, object]] = []
    soft: list[dict[str, object]] = []
    tested_keys: dict[bytes, list[str]] = {}

    for data, origins in texts.items():
        digest = sha256(data)
        tested_keys.setdefault(digest, []).extend(f"sha256/{origin}" for origin in origins)
        for private_hit in scan_keys(data):
            hard.append({"kind": "embedded_source_key", "origins": origins, **private_hit})

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
                        "origins": origins,
                        "password_form": password_name,
                        "printable": round(G.printable(plaintext), 3),
                        "plaintext_hex": plaintext.hex(),
                    }
                    if G.semantic(plaintext):
                        hard.append({"kind": "aes_blob", **record})
                    else:
                        soft.append(record)

    for key, origins in xor_keys.items():
        tested_keys.setdefault(key, []).extend(origins)

    final_decryptions = 0
    for key, origins in tested_keys.items():
        relation = public_key_relation(key)
        if relation:
            hard.append(
                {
                    "kind": "derived_private_key",
                    "origins": origins,
                    "secret_hex": key.hex(),
                    "relation": relation,
                }
            )
        for mode, plaintext in decrypt_final_blocks(key, chain):
            final_decryptions += 1
            for private_hit in scan_keys(plaintext):
                hard.append(
                    {
                        "kind": "final_blocks_private_key",
                        "origins": origins,
                        "mode": mode,
                        **private_hit,
                    }
                )
            printable = G.printable(plaintext)
            if printable >= 0.80 or b"Salted__" in plaintext:
                soft.append(
                    {
                        "kind": "final_blocks_text",
                        "origins": origins,
                        "mode": mode,
                        "printable": round(printable, 3),
                        "plaintext_hex": plaintext[:160].hex(),
                    }
                )

    report = {
        "family": "miroir_verbatim_last_words",
        "verbatim_lines": list(LINES),
        "first_words": [line.split()[0] for line in LINES],
        "last_words": [line.split()[-1] for line in LINES],
        "acrostic": "".join(line[0] for line in LINES),
        "telestich": "".join(line.split()[-1][0] for line in LINES),
        "controls": controls,
        "text_candidate_count": len(texts),
        "xor_key_count": len(xor_keys),
        "unique_final_key_count": len(tested_keys),
        "aes_blob_tests": len(texts) * len(BLOBS) * 3 * 2,
        "final_block_decryptions": final_decryptions,
        "hard": hard,
        "soft_count": len(soft),
        "soft": soft,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    result = run()
    summary = {
        key: result[key]
        for key in (
            "family",
            "first_words",
            "last_words",
            "acrostic",
            "telestich",
            "controls",
            "text_candidate_count",
            "xor_key_count",
            "unique_final_key_count",
            "aes_blob_tests",
            "final_block_decryptions",
            "hard",
            "soft_count",
        )
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
