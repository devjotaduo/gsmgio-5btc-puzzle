"""Triagem semântica finita de corpus SQLite fechado; sem rede e sem operações ECC."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import re
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "solver/oraculo_duplo_2026_09_17"))
from oracle import cp273_inverse_view
from scan import file_sha256, require_standalone_sqlite

sys.path.insert(0, str(ROOT / "solver/experiments/claude_endgame_2026_09_02"))
import gsmg_common as G

ASCII_RUN = re.compile(rb"[\t\n\r\x20-\x7e]{48,}")
BASE64_NESTED = re.compile(rb"U2FsdGVk[A-Za-z0-9+/\r\n]*={0,2}")
VIEW_NAMES = ("original", "cp273", "cp273-inverse")


def views(data: bytes):
    yield "original", data
    # Latin-1 mantém bytes altos; ASCII/errors=replace fabricaria texto imprimível.
    yield "cp273", data.decode("cp273").encode("latin-1", errors="replace")
    yield "cp273-inverse", cp273_inverse_view(data)


def inspect(data: bytes) -> dict:
    reasons = []
    if G.semantic(data):
        reasons.append("semantic_whole")
    if G.nested_blob(data):
        reasons.append("nested_prefix")
    runs = [{"offset": match.start(), "length": len(match[0])} for match in ASCII_RUN.finditer(data)]
    if runs:
        reasons.append("ascii_run_ge48")
    nested = []
    offset = data.find(b"Salted__")
    while offset >= 0:
        if len(data) - offset >= 32:
            nested.append({"offset": offset, "kind": "raw", "remaining": len(data) - offset})
        offset = data.find(b"Salted__", offset + 1)
    for match in BASE64_NESTED.finditer(data):
        candidate = re.sub(rb"[\r\n]", b"", match[0])
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except ValueError:
            continue
        if decoded.startswith(b"Salted__") and len(decoded) >= 32:
            nested.append({"offset": match.start(), "kind": "base64", "decoded_bytes": len(decoded)})
    if nested:
        reasons.append("nested_any_offset")
    return {"reasons": reasons, "ascii_runs": runs, "nested": nested}


def positive_and_null_controls(lengths: list[int]) -> dict:
    kit = ROOT / "solver/experiments/claude_endgame_2026_09_02/gsmg_common.py"
    result = subprocess.run([sys.executable, "-B", str(kit)], cwd=ROOT,
                            capture_output=True, text=True, check=True)
    assert "gsmg_common OK" in result.stdout
    raw = base64.b64decode(G.PHASE32_B64)
    password = G.shahex("jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple").encode()
    key, iv = G.evp(password, raw[8:16], SHA256)
    phase32 = G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw[16:]))
    assert phase32 is not None and len(phase32) == 2422
    phase_checks = {name: inspect(value) for name, value in views(phase32)}
    assert "semantic_whole" in phase_checks["original"]["reasons"]
    assert any(run["length"] >= 1539 for run in phase_checks["cp273-inverse"]["ascii_runs"])

    message = b"This is a synthetic instruction for a semantic audit; it is not a puzzle solution."
    padding = 16 - len(message) % 16
    salt = b"12345678"
    key, iv = G.evp(b"public synthetic control", salt, SHA256)
    nested = b"Salted__" + salt + AES.new(key, AES.MODE_CBC, iv).encrypt(message + bytes([padding]) * padding)
    positives = []
    for prefix in (b"", b"\xff" * 19):
        for representation, payload in (("raw", nested), ("base64", base64.b64encode(nested))):
            found = inspect(prefix + payload)
            assert any(item["offset"] == len(prefix) and item["kind"] == representation for item in found["nested"])
            positives.append({"nested": representation, "offset": len(prefix)})
    for name, payload in (("original", message), ("cp273", message.decode().encode("cp273")),
                          ("cp273-inverse", message.decode("cp273").encode("latin-1"))):
        value = dict(views(b"\xff" * 19 + payload + b"\xff" * 21))[name]
        assert any(run["offset"] == 19 and run["length"] == len(message) for run in inspect(value)["ascii_runs"])
        positives.append({"text_view": name, "offset": 19, "length": len(message)})

    rng = random.Random(1809202602)
    uniform = Counter()
    samples = 0
    for length in lengths:
        for _ in range(100):
            samples += 1
            for name, value in views(rng.randbytes(length)):
                uniform.update(f"{name}:{reason}" for reason in inspect(value)["reasons"])
    shuffled = Counter()
    for _ in range(100):
        data = list(phase32)
        rng.shuffle(data)
        for name, value in views(bytes(data)):
            shuffled.update(f"{name}:{reason}" for reason in inspect(value)["reasons"])
    return {"passed": True, "phase2_and_checkerboard": True,
            "phase32_sha256": hashlib.sha256(phase32).hexdigest(),
            "phase32_checks": phase_checks, "synthetic_positives": positives,
            "uniform_null": {"seed": 1809202602, "samples_per_length": 100,
                             "lengths": lengths, "samples": samples, "reasons": dict(uniform)},
            "matched_phase32_null": {"shuffles": 100, "reasons": dict(shuffled),
                                     "interpretation": "G.semantic pode ser invariante ao embaralhamento: é triagem, não autenticação."}}


def save(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    corpus = args.corpus.resolve(strict=True)
    out = args.out.resolve()
    if corpus.is_relative_to(out):
        parser.error("Corpus deve ficar fora da saída")
    out.mkdir(parents=True, exist_ok=True)
    if any((out / name).exists() for name in ("controls.json", "summary.json", "candidates.jsonl")):
        parser.error("A saída deve ter controles/resumo/candidatos novos")
    require_standalone_sqlite(corpus)
    evidence_paths = [corpus, Path(__file__), Path(G.__file__),
                      ROOT / "solver/oraculo_duplo_2026_09_17/oracle.py"]
    hashes = {str(path): file_sha256(path) for path in evidence_paths}
    con = sqlite3.connect(corpus.as_uri() + "?mode=ro&immutable=1", uri=True)
    expected = con.execute("SELECT count(*),sum(length(data)) FROM payloads").fetchone()
    lengths = [row[0] for row in con.execute("SELECT DISTINCT length(data) FROM payloads ORDER BY 1")]
    controls = positive_and_null_controls(lengths)
    controls["input_hashes"] = hashes
    save(out / "controls.json", controls)
    counters = Counter()
    scanned = byte_count = candidates = 0
    started = time.monotonic()
    with (out / "candidates.jsonl").open("x", encoding="utf-8") as output:
        for payload_id, digest, data in con.execute("SELECT id,sha256,data FROM payloads ORDER BY id"):
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError(f"Hash divergente no payload {payload_id}")
            scanned += 1
            byte_count += len(data)
            found = []
            for name, view in views(data):
                result = inspect(view)
                counters.update(f"{name}:{reason}" for reason in result["reasons"])
                if result["reasons"]:
                    found.append({"view": name, "view_hex": view.hex(), **result})
            if found:
                candidates += 1
                output.write(json.dumps({"payload_id": payload_id, "sha256": digest,
                                         "payload_hex": data.hex(), "views": found}) + "\n")
                output.flush()
            if scanned % 10000 == 0:
                print(json.dumps({"status": "running", "payloads": scanned, "bytes": byte_count,
                                  "candidate_payloads": candidates}), flush=True)
    con.close()
    require_standalone_sqlite(corpus)
    if (scanned, byte_count) != expected:
        raise RuntimeError("Cobertura incompleta")
    for path, digest in hashes.items():
        if file_sha256(Path(path)) != digest:
            raise RuntimeError("Corpus ou código alterado durante execução")
    summary = {"status": "complete", "payloads": scanned, "bytes": byte_count,
               "candidate_payloads": candidates, "reasons": dict(counters),
               "seconds": round(time.monotonic() - started, 3),
               "input_hashes": hashes, "finished_utc": datetime.now(timezone.utc).isoformat(),
               "candidate_file_sha256": file_sha256(out / "candidates.jsonl"),
               "solution_declared": False,
               "limits": ["Triagem por propriedades locais, sem autenticar instruções ou chaves.",
                          "Só as três visões declaradas; ASCII contínuo de pelo menos48 bytes.",
                          "Nenhuma operação ECC e nenhum acesso à rede."]}
    save(out / "summary.json", summary)
    print(json.dumps({key: summary[key] for key in ("status", "payloads", "bytes", "candidate_payloads", "reasons", "seconds")}), flush=True)


if __name__ == "__main__":
    main()
