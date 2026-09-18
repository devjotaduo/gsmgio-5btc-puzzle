"""Controles end-to-end do scanner: hits, retomada e integridade do corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from scan_delta import ROOT, controls, independent_address


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--scanner", choices=("scan_delta.py", "scan_delta_v2.py"),
                        default="scan_delta_v2.py")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "_work"):
        parser.error("Saída deve ficar sob _work")
    out.mkdir(parents=True, exist_ok=False)
    key = hashlib.sha256(b"multiagente scan_delta end-to-end control").digest()
    target = independent_address(key, False)
    payloads = [b"seven!!" + key + b"z", b"five!" + key[::-1] + b"done",
                b"!!" + key.hex().encode() + b".", b"short"]
    database = out / "input.sqlite"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE payloads(id INTEGER PRIMARY KEY,sha256 TEXT,data BLOB)")
        conn.executemany("INSERT INTO payloads VALUES(?,?,?)", [
            (i, hashlib.sha256(data).hexdigest(), data) for i, data in enumerate(payloads)])
    scanner = Path(__file__).with_name(args.scanner)
    command = [sys.executable, str(scanner),
               "--corpus", str(database), "--out", str(out / "run"),
               "--mode", "both", "--workers", "2", "--batch-windows", "15",
               "--targets", target]
    subprocess.run(command, check=True, capture_output=True, text=True)
    summary = json.loads((out / "run/summary.json").read_text())
    hits = [json.loads(line) for line in (out / "run/hits.jsonl").read_text().splitlines()]
    expected = {(0, "raw32", 7), (1, "raw32-le", 5), (2, "hex64", 2)}
    assert {(h["payload_id"], h["format"], h["offset"]) for h in hits} == expected
    assert all(h["independently_verified"] for h in hits)
    checkpoints = sqlite3.connect(out / "run/checkpoint.sqlite")
    before = checkpoints.execute("SELECT * FROM completed ORDER BY batch_id").fetchall()
    subprocess.run(command, check=True, capture_output=True, text=True)
    after = checkpoints.execute("SELECT * FROM completed ORDER BY batch_id").fetchall()
    checkpoints.close()
    assert before == after
    default_resume = None
    if args.scanner == "scan_delta_v2.py":
        default_command = command[:-2]
        default_command[default_command.index("--out") + 1] = str(out / "default_run")
        subprocess.run(default_command, check=True, capture_output=True, text=True)
        with sqlite3.connect(out / "default_run/checkpoint.sqlite") as conn:
            default_before = conn.execute("SELECT * FROM completed ORDER BY batch_id").fetchall()
        subprocess.run(default_command, check=True, capture_output=True, text=True)
        with sqlite3.connect(out / "default_run/checkpoint.sqlite") as conn:
            default_after = conn.execute("SELECT * FROM completed ORDER BY batch_id").fetchall()
        default_summary = json.loads((out / "default_run/summary.json").read_text())
        assert default_summary["status"] == "complete"
        assert default_summary["attempts"] == summary["attempts"]
        assert default_summary["hard_hits"] == 0
        assert default_before == default_after
        default_resume = True
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE payloads SET sha256=? WHERE id=0", ("0" * 64,))
    refused = subprocess.run(command, capture_output=True, text=True)
    assert refused.returncode != 0 and "Contrato alterado" in refused.stderr
    fresh_command = command.copy()
    fresh_command[fresh_command.index("--out") + 1] = str(out / "tampered")
    refused_data = subprocess.run(fresh_command, capture_output=True, text=True)
    assert refused_data.returncode != 0 and "Digest divergente" in refused_data.stderr
    record = {"passed": True, "unit": controls(), "expected_hits": len(expected),
              "scanner": args.scanner,
              "scanner_sha256": hashlib.sha256(scanner.read_bytes()).hexdigest(),
              "actual_hits": len(hits), "end_to_end_status": summary["status"],
              "attempts": summary["attempts"], "resume_exact": before == after,
              "default_targets_resume_exact": default_resume,
              "changed_contract_refused": True, "tampered_payload_refused": True}
    (out / "controls.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
