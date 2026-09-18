"""Controles positivos, de fronteira e nulo casado do oráculo isolado."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import subprocess
import sys
import time
from pathlib import Path

import base58

from oracle import (
    ORDER, TARGETS, Oracle, address_payload, cp273_inverse_view,
    decoded_candidates, independent_address,
)


def phase32_codec_control(source_root: Path) -> dict:
    """Confere o trecho inteiro da fase real por derivação AES independente do kit."""
    from Crypto.Cipher import AES

    readme = (source_root / "README.md").read_text(encoding="utf-8")
    expected = next(line.strip() for line in readme.splitlines()
                    if line.startswith("vtkvplmepphluwaht")).encode("ascii")
    encoded_lines = []
    for line in readme[readme.index("U2FsdGVkX1/u/Exb78Fl"):].splitlines():
        line = line.strip()
        if not line or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                           for char in line):
            break
        encoded_lines.append(line)
    raw = base64.b64decode("".join(encoded_lines), validate=True)
    assert raw[:8] == b"Salted__"
    password = hashlib.sha256(
        b"jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
    ).hexdigest().encode("ascii")
    derived, previous = b"", b""
    while len(derived) < 48:
        previous = hashlib.sha256(previous + password + raw[8:16]).digest()
        derived += previous
    padded = AES.new(derived[:32], AES.MODE_CBC, derived[32:48]).decrypt(raw[16:])
    padding = padded[-1]
    assert 1 <= padding <= 16 and padded.endswith(bytes([padding]) * padding)
    plain = padded[:-padding]
    inverse = expected.decode("cp273").encode("latin-1")
    position = plain.find(inverse)
    assert len(expected) == 1539 and position == 447
    assert cp273_inverse_view(plain[position:position + len(expected)]) == expected
    assert expected.decode("ascii").encode("cp273") not in plain
    return {"passed": True, "plaintext_bytes": len(plain), "beaufort_bytes": len(expected),
            "offset": position, "beaufort_sha256": hashlib.sha256(expected).hexdigest(),
            "ciphertext_sha256": hashlib.sha256(raw).hexdigest(),
            "readme_sha256": hashlib.sha256((source_root / "README.md").read_bytes()).hexdigest(),
            "operation": "ASCII.decode('cp273').encode('latin-1')",
            "restored_exactly": True, "conventional_representation_present": False}


def cp273_direction_controls(key_a: bytes, key_b: bytes) -> dict:
    """Duas direções, dois alvos, três formatos e separadores sem perda de offset."""
    targets = (independent_address(key_a, False), independent_address(key_b, True))
    oracle = Oracle(targets)
    cases = []
    for direction in ("cp273", "cp273-inverse"):
        for key_index, (secret, target) in enumerate(zip((key_a, key_b), targets), 1):
            texts = {"hex64": secret.hex(),
                     "wif-uncompressed": base58.b58encode_check(b"\x80" + secret).decode("ascii"),
                     "wif-compressed": base58.b58encode_check(b"\x80" + secret + b"\x01").decode("ascii")}
            for form, text in texts.items():
                encoded = (text.encode("cp273") if direction == "cp273"
                           else text.encode("ascii").decode("cp273").encode("latin-1"))
                for prefix in (b"", b"\xaf\xaf"):
                    result = oracle.scan(prefix + encoded, decoded_only=True)
                    assert any(hit["format"] == f"{direction}:{form}"
                               and hit["address"] == target and hit["offset"] == len(prefix)
                               for hit in result["hits"])
                    cases.append({"direction": direction, "key_index": key_index,
                                  "form": form, "offset": len(prefix)})
                split = len(encoded) // 2
                interrupted = encoded[:split] + b"\xaf" + encoded[split:]
                assert not any(hit["format"].startswith(direction + ":")
                               and hit["address"] == target
                               for hit in oracle.scan(interrupted, decoded_only=True)["hits"])
    # Compara os 256 valores com chamadas estritas do codec, independentemente da tabela.
    unmappable = []
    for value in range(256):
        raw = bytes([value])
        try:
            expected = raw.decode("latin-1").encode("cp273")
        except UnicodeEncodeError:
            expected = b"?"
            unmappable.append(value)
        assert cp273_inverse_view(raw) == expected
    assert unmappable == [0xaf]
    # Cada embaralhamento permanece hex64 após a inversão: o nulo exercita
    # efetivamente o teste ECC, em vez de morrer só na regex/checksum WIF.
    text = key_a.hex().encode("ascii")
    encoded = text.decode("cp273").encode("latin-1")
    rng = random.Random(18092026)
    attempts = 0
    for _ in range(100):
        shuffled = list(encoded)
        rng.shuffle(shuffled)
        result = oracle.scan(bytes(shuffled), decoded_only=True)
        assert not result["hits"]
        attempts += sum(result["attempts"].values())
    return {"passed": True, "cases": cases, "unmappable_bytes": unmappable,
            "all_byte_mappings_verified": 256, "interrupted_candidates_rejected": 12,
            "matched_null": {"shuffles": 100, "seed": 18092026,
                             "attempts": attempts, "hits": 0}}


def run_controls() -> dict:
    started = time.monotonic()
    one = (1).to_bytes(32, "big")
    known = ("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    assert independent_address(one, False) == known[0]
    assert independent_address(one, True) == known[1]
    assert {hit["address"] for hit in Oracle(known).check(one)} == set(known)
    assert address_payload(TARGETS[0]).hex() == "a9553269572a317e39f0f518cb87c1a0ee1dbae4"
    assert address_payload(TARGETS[1]).hex() == "4bc468447fe1b048ad030a2f9a125478eabc4ed6"

    key_a = hashlib.sha256(b"GSMG dual-address planted A").digest()
    key_b = hashlib.sha256(b"GSMG dual-address planted B").digest()
    direction_controls = cp273_direction_controls(key_a, key_b)
    positive_cases = []
    for comp_a, comp_b in ((False, True), (True, False)):
        targets = (independent_address(key_a, comp_a), independent_address(key_b, comp_b))
        oracle = Oracle(targets)
        # Início, offset intermediário e janela terminando no último byte.
        for prefix in (b"", b"prefix!", bytes(range(31))):
            payload = prefix + key_a + b"separator!" + key_b
            result = oracle.scan(payload)
            assert result["attempts"]["raw32"] == len(payload) - 31
            hits = [h for h in result["hits"] if h["format"] == "raw32"]
            assert {(h["address"], h["offset"]) for h in hits} == {
                (targets[0], len(prefix)), (targets[1], len(payload) - 32)}
            for hit in hits:
                assert independent_address(bytes.fromhex(hit["private_key"]), hit["compressed"]) == hit["address"]
            positive_cases.append({"kind": "raw32", "prefix_length": len(prefix), "compressions": [comp_a, comp_b]})
        for secret, target in zip((key_a, key_b), targets):
            payload = b"f" + secret.hex().upper().encode() + b"c"
            hits = oracle.scan(payload)["hits"]
            assert any(h["format"] == "hex64" and h["offset"] == 1 and h["address"] == target for h in hits)
            for wif_compressed in (False, True):
                payload = b"\x80" + secret + (b"\x01" if wif_compressed else b"")
                wif = base58.b58encode_check(payload)
                result = oracle.scan(b"key=" + wif + b";")
                assert any(h["address"] == target and h["format"].startswith("wif-") and h["offset"] == 4 for h in result["hits"])
                mutated = wif[:-1] + (b"1" if wif[-1:] != b"1" else b"2")
                assert not list(decoded_candidates(mutated))
            assert not list(decoded_candidates(base58.b58encode_check(b"\x80" + secret + b"\x02")))
            assert not list(decoded_candidates(base58.b58encode_check(b"\xef" + secret)))
            positive_cases.append({"kind": "hex64-and-wif", "target": target})

    oracle = Oracle((independent_address(key_a, False), independent_address(key_b, True)))
    encoded_cases = []
    for codec in ("cp273", "utf-16-le", "utf-16-be"):
        for prefix in (b"", b"\xff"):
            for form in ("hex64", "wif"):
                text = key_b.hex() if form == "hex64" else base58.b58encode_check(b"\x80" + key_b + b"\x01").decode()
                payload = prefix + text.encode(codec)
                hits = oracle.scan(payload)["hits"]
                assert any(h["address"] == oracle.targets[1] and h["offset"] == len(prefix)
                           and h["format"].startswith(codec) for h in hits), (codec, form, len(prefix))
                encoded_cases.append([codec, len(prefix), form])
    # Surrogate pair antes da chave: offset em bytes deve permanecer exato.
    for codec in ("utf-16-le", "utf-16-be"):
        prefix = "\U0001f600!".encode(codec)
        hits = oracle.scan(prefix + key_b.hex().encode(codec))["hits"]
        assert any(h["format"].startswith(codec) and h["offset"] == len(prefix) for h in hits)
    for invalid in (b"", bytes(31), bytes(33), bytes(32), ORDER.to_bytes(32, "big"), bytes([255]) * 32):
        assert oracle.check(invalid) == []
    assert len(Oracle((independent_address((ORDER - 1).to_bytes(32, "big"), True),)).check((ORDER - 1).to_bytes(32, "big"))) == 1
    for invalid_targets in ((), (TARGETS[0], TARGETS[0]), ("bad-address",), (TARGETS[0][:-1] + "f",)):
        try:
            Oracle(invalid_targets)
        except ValueError:
            pass
        else:
            raise AssertionError("Alvo inválido aceito")

    payload = b"start" + key_a + b"split" + key_b + b"finish"
    rng = random.Random(17092026)
    null_attempts = 0
    for _ in range(100):
        shuffled = list(payload)
        rng.shuffle(shuffled)
        result = oracle.scan(bytes(shuffled))
        assert not result["hits"]
        null_attempts += sum(result["attempts"].values())
    for index in range(16):
        secret = hashlib.sha256(f"independent-key-{index}".encode()).digest()
        targets = tuple(independent_address(secret, comp) for comp in (False, True))
        assert {h["address"] for h in Oracle(targets).check(secret)} == set(targets)
    return {"passed": True, "known_bitcoin_vector": True, "positive_cases": positive_cases,
            "independent_random_scalars": 16, "encoded_text_cases": encoded_cases,
            "cp273_directions": direction_controls,
            "invalid_scalars_and_wif_rejected": True,
            "matched_null": {"shuffles": 100, "seed": 17092026, "attempts": null_attempts, "hits": 0},
            "elapsed_seconds": round(time.monotonic() - started, 3)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    kit = args.source_root / "solver/experiments/claude_endgame_2026_09_02/gsmg_common.py"
    kit_run = subprocess.run([sys.executable, "-B", str(kit)], cwd=args.source_root, capture_output=True, text=True, check=True)
    if "gsmg_common OK" not in kit_run.stdout:
        raise RuntimeError("Controle do kit não confirmou sucesso")
    result = run_controls()
    result["phase32_codec"] = phase32_codec_control(args.source_root)
    result["phase2_and_checkerboard_original_kit"] = True
    result["kit_sha256"] = hashlib.sha256(kit.read_bytes()).hexdigest()
    result["oracle_sha256"] = hashlib.sha256(Path(__file__).with_name("oracle.py").read_bytes()).hexdigest()
    result["controls_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.out.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "positive_cases"}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
