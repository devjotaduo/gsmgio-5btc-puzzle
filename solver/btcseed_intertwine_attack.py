# -*- coding: utf-8 -*-
"""Apply the puzzle's proven ``intertwined`` grammar to the seven-letter header.

The positive control is the exact Cosmic passphrase already established in the
repository. The only candidate hypothesis is then::

    XOR(SHA256(letter) for letter in "BTCSEED")

Uppercase is authoritative; lowercase is recorded only as the conventional
case-sensitivity diagnostic used throughout the puzzle.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import oracles as O


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_work" / "btcseed_intertwine_attack.json"
COSMIC_PASSWORD = "a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735"


def xor_hashes(parts: list[str]) -> bytes:
    result = bytes(32)
    for part in parts:
        digest = hashlib.sha256(part.encode()).digest()
        result = bytes(left ^ right for left, right in zip(result, digest))
    return result


def main() -> None:
    control_parts = [
        "enter",
        "lastwordsbeforearchichoice",
        "thispassword",
        "yourlastcommand",
        "secondanswer",
    ]
    control = xor_hashes(control_parts).hex()
    if control != COSMIC_PASSWORD:
        raise AssertionError(f"intertwine control mismatch: {control}")

    rows: list[dict] = []
    hits: list[dict] = []
    for case, header in (("authoritative_upper", "BTCSEED"), ("diagnostic_lower", "btcseed")):
        key = xor_hashes(list(header))
        private_hit = O.check_privkey(key)
        aes_hits: list[dict] = []
        for form_name, password in (
            ("raw_latin1", key.decode("latin-1")),
            ("hex", key.hex()),
            ("hex_upper", key.hex().upper()),
        ):
            for hit in O.aes_open(password):
                aes_hits.append({"form": form_name, "password": password, "hit": hit})
        row = {
            "case": case,
            "header": header,
            "key_hex": key.hex(),
            "private_hit": private_hit,
            "aes_hits": aes_hits,
        }
        rows.append(row)
        if private_hit or aes_hits:
            hits.append(row)

    report = {
        "control_cosmic_xor": control,
        "control_matches": True,
        "candidates": rows,
        "hits": hits,
        "solve": bool(hits),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"report={OUT}")


if __name__ == "__main__":
    main()
