# -*- coding: utf-8 -*-
"""Degrau reproduzível da lacuna de fluxo/raw32 (ENDGAME §4.D)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import re
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parents[2]
MODES = ("aes-256-cfb", "aes-256-ofb", "aes-256-ctr", "chacha20")
DIGESTS = ("sha256", "md5")
BLOBS = ("SMALL", "COSMIC")
HEX64 = re.compile(rb"[0-9a-fA-F]{64}")
WIF = re.compile(rb"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}")

SMALL_B64 = (
    "U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z"
    "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ"
)


def parse_blobs() -> dict[str, tuple[bytes, bytes]]:
    def parse(b64: str):
        raw = base64.b64decode(b64)
        assert raw[:8] == b"Salted__"
        return raw[8:16], raw[16:]

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"\*\*Cosmic Duality:\*\*\n\n```text\n(.*?)```", readme, re.S)
    if not m:
        raise RuntimeError("Bloco Cosmic Duality não encontrado no README.md")
    cosmic_b64 = m.group(1).replace("\n", "").strip()
    return {"SMALL": parse(SMALL_B64), "COSMIC": parse(cosmic_b64)}


def digest_once(data: bytes, digest_name: str) -> bytes:
    if digest_name == "sha256":
        h = hashes.Hash(hashes.SHA256())
    elif digest_name == "md5":
        h = hashes.Hash(hashes.MD5())
    else:
        raise ValueError(digest_name)
    h.update(data)
    return h.finalize()


def evp48(material_bytes: bytes, salt: bytes, digest_name: str):
    data = prev = b""
    while len(data) < 48:
        prev = digest_once(prev + material_bytes + salt, digest_name)
        data += prev
    return data[:48]


def dec_stream(mode: str, key: bytes, iv: bytes, ct: bytes) -> bytes:
    if mode == "aes-256-cfb":
        d = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
        return d.update(ct) + d.finalize()
    if mode == "aes-256-ofb":
        d = Cipher(algorithms.AES(key), modes.OFB(iv)).decryptor()
        return d.update(ct) + d.finalize()
    if mode == "aes-256-ctr":
        d = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return d.update(ct) + d.finalize()
    if mode == "chacha20":
        d = Cipher(algorithms.ChaCha20(key, iv), mode=None).decryptor()
        return d.update(ct) + d.finalize()
    raise ValueError(mode)


def enc_stream(mode: str, key: bytes, iv: bytes, plain: bytes) -> bytes:
    if mode == "aes-256-cfb":
        e = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
        return e.update(plain) + e.finalize()
    if mode == "aes-256-ofb":
        e = Cipher(algorithms.AES(key), modes.OFB(iv)).encryptor()
        return e.update(plain) + e.finalize()
    if mode == "aes-256-ctr":
        e = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return e.update(plain) + e.finalize()
    if mode == "chacha20":
        e = Cipher(algorithms.ChaCha20(key, iv), mode=None).encryptor()
        return e.update(plain) + e.finalize()
    raise ValueError(mode)


def scan_raw32_dual(buf: bytes, marker: bytes | None = None):
    checks = 0
    marker_hits = []
    for off in range(max(0, len(buf) - 31)):
        chunk = buf[off:off + 32]
        checks += 2
        if marker is not None:
            if chunk == marker:
                marker_hits.append({"orient": "BE", "offset": off})
            if chunk[::-1] == marker:
                marker_hits.append({"orient": "LE", "offset": off})
    return checks, marker_hits


def forms_from_tokens(tokens: list[str]):
    out = []
    seen = set()
    for token in tokens:
        base = token.encode("utf-8")
        for form in (base, hashlib.sha256(base).hexdigest().encode(), hashlib.sha256(base).hexdigest().upper().encode()):
            if form in seen:
                continue
            seen.add(form)
            out.append(form)
    return out


def control_positive():
    planted = hashlib.sha256(b"fluxo-raw32-piloto-plantio").digest()
    plain = bytes([0xA5]) * 17 + planted + bytes([0x5A]) * 79
    control_material = b"fluxo-piloto-control-password"
    salt = b"12345678"

    detections = []
    for digest in DIGESTS:
        km = evp48(control_material, salt, digest)
        key, iv = km[:32], km[32:48]
        for mode in MODES:
            ct = enc_stream(mode, key, iv, plain)
            recovered = dec_stream(mode, key, iv, ct)
            assert recovered == plain
            checks, hits = scan_raw32_dual(recovered, marker=planted)
            ok = any(hit["offset"] == 17 and hit["orient"] == "BE" for hit in hits)
            assert ok, (mode, digest, hits[:2])
            detections.append({"mode": mode, "digest": digest, "checks": checks, "marker_hits": len(hits)})

    return {
        "planted_marker_hex": planted.hex(),
        "controls_checked": len(detections),
        "detections": detections,
    }


def run_null(sample_plain: bytes, n: int, seed: int):
    rng = random.Random(seed)
    attempts = 0
    hits = 0
    marker = hashlib.sha256(b"fluxo-raw32-piloto-plantio").digest()
    for _ in range(n):
        items = list(sample_plain)
        rng.shuffle(items)
        checks, found = scan_raw32_dual(bytes(items), marker=marker)
        attempts += checks
        hits += len(found)
    return {"shuffle_runs": n, "seed": seed, "raw32_checks": attempts, "hits": hits}


def run_pilot(forms: list[bytes], blobs: dict[str, tuple[bytes, bytes]], max_forms: int):
    chosen = forms[:max_forms]
    totals = {
        "forms": len(chosen),
        "decryptions": 0,
        "raw32_checks": 0,
        "hex64_candidates": 0,
        "wif_candidates": 0,
        "sample_candidates": [],
    }
    started = time.perf_counter()

    for form in chosen:
        for blob in BLOBS:
            salt, ct = blobs[blob]
            for digest in DIGESTS:
                km = evp48(form, salt, digest)
                key, iv = km[:32], km[32:48]
                for mode in MODES:
                    plain = dec_stream(mode, key, iv, ct)
                    checks, _ = scan_raw32_dual(plain)
                    totals["decryptions"] += 1
                    totals["raw32_checks"] += checks

                    hx = HEX64.search(plain)
                    wf = WIF.search(plain)
                    if hx:
                        totals["hex64_candidates"] += 1
                    if wf:
                        totals["wif_candidates"] += 1
                    if (hx or wf) and len(totals["sample_candidates"]) < 20:
                        totals["sample_candidates"].append(
                            {
                                "mode": mode,
                                "digest": digest,
                                "blob": blob,
                                "form_preview": form[:64].decode("latin-1", errors="replace"),
                                "hex64": hx.group().decode() if hx else None,
                                "wif": wf.group().decode() if wf else None,
                            }
                        )

    elapsed = time.perf_counter() - started
    totals["seconds"] = round(elapsed, 3)
    totals["windows_per_second"] = round(totals["raw32_checks"] / elapsed, 2) if elapsed else 0.0
    return totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-forms", type=int, default=128)
    parser.add_argument("--null-runs", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20260919)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "_work" / "fluxo_raw32_2026-09-19" / "fluxo_piloto",
    )
    args = parser.parse_args()

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    tokens = [
        "causality", "thematrixhasyou", "lastwordsbeforearchichoice", "matrixsumlist",
        "fubcd", "oraclequeen", "thingky", "mvps", "half", "betterhalf",
        "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa",
        "our first hint is your last command", "seven intertwined", "salphaseion", "cosmic duality",
    ]
    forms = forms_from_tokens(tokens)
    blobs = parse_blobs()

    controls = {
        "phase2_and_checkerboard": True,
        "positive": control_positive(),
    }

    sample_pw = forms[0]
    salt, ct = blobs["SMALL"]
    km = evp48(sample_pw, salt, "sha256")
    sample_plain = dec_stream("aes-256-ctr", km[:32], km[32:48], ct)
    controls["null"] = run_null(sample_plain, args.null_runs, args.seed)

    summary = run_pilot(forms, blobs, args.max_forms)
    summary.update(
        {
            "campaign": "fluxo_raw32_2026-09-19",
            "front": "fluxo_piloto",
            "tokens": len(tokens),
            "forms_total": len(forms),
            "forms_tested": min(args.max_forms, len(forms)),
            "modes": list(MODES),
            "digests": list(DIGESTS),
            "blobs": list(BLOBS),
            "controls_ok": controls["null"]["hits"] == 0,
            "scope": "degrau técnico (cobertura parcial, sem oráculo duro de privkey)",
        }
    )

    with (out / "controls.json").open("w", encoding="utf-8") as f:
        json.dump(controls, f, ensure_ascii=False, indent=2)
        f.write("\n")
    with (out / "summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(json.dumps({k: v for k, v in summary.items() if k != "sample_candidates"}, ensure_ascii=False, indent=2))
    print("sample_candidates:", len(summary["sample_candidates"]))


if __name__ == "__main__":
    main()
