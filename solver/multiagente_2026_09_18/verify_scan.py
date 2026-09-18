"""Audita uma varredura scan_delta concluída, sem ECC e sem importar o scanner.

Reconstrói o particionamento de scan.batches, reconcilia todos os checkpoints e
confere hashes/estabilidade dos arquivos. Só escreve final_qa.json no diretório
da execução, sob o _work desta worktree. Chaves nunca entram no relatório/stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "_work"
CODE_FILES = (
    "solver/multiagente_2026_09_18/scan_delta.py",
    "solver/oraculo_duplo_2026_09_17/oracle.py",
    "solver/oraculo_duplo_2026_09_17/scan.py",
)
TEXT_FORMATS = ("hex64", "wif-uncompressed", "wif-compressed")
FORMATS = {"raw32", "raw32-le", *TEXT_FORMATS}
FORMATS.update(prefix + kind for prefix in (
    "cp273:", "cp273-inverse:", "utf-16-le@0:", "utf-16-le@1:",
    "utf-16-be@0:", "utf-16-be@1:",
) for kind in TEXT_FORMATS)


class VerificationError(Exception):
    """Erro com código estático, sem incorporar conteúdo potencialmente secreto."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise VerificationError(code)


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def signature(path: Path) -> tuple[int, int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, stat.st_ino


def pairs_unique(pairs: list[tuple[str, Any]]) -> dict:
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate_json_key")
        obj[key] = value
    return obj


def decode_json(data: str | bytes) -> Any:
    try:
        return json.loads(data, object_pairs_hook=pairs_unique)
    except (ValueError, UnicodeError) as exc:
        raise VerificationError("invalid_json") from exc


def natural(value: Any) -> bool:
    return type(value) is int and value >= 0


def digest_valid(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value)


def attempts_checked(value: Any) -> Counter:
    require(isinstance(value, dict), "invalid_attempts")
    require(all(key in FORMATS and natural(count) for key, count in value.items()),
            "invalid_attempts")
    return Counter(value)


def no_sidecars(path: Path) -> None:
    # Mesmo WAL vazio é recusado: esta auditoria exige um banco já fechado.
    require(not any(Path(str(path) + suffix).exists()
                    for suffix in ("-wal", "-shm", "-journal")), "sqlite_sidecar_present")


def read_only_db(path: Path) -> sqlite3.Connection:
    no_sidecars(path)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA cache_size=-2048")
    connection.execute("PRAGMA mmap_size=0")
    connection.execute("PRAGMA temp_store=FILE")
    try:
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                "sqlite_integrity_failed")
    except Exception:
        connection.close()
        raise
    return connection


class Files:
    """Hashes e stat antes/depois; não retém conteúdo dos arquivos na memória."""

    def __init__(self) -> None:
        self.items: dict[Path, dict] = {}

    def capture(self, path: Path) -> str:
        before = signature(path)
        digest = file_hash(path)
        require(signature(path) == before, "file_changed_during_hash")
        self.items[path] = {"sha256": digest, "stat": before}
        return digest

    def finish(self) -> None:
        for path, item in self.items.items():
            require(signature(path) == item["stat"], "input_stat_changed")
            require(file_hash(path) == item["sha256"], "input_hash_changed")
            require(signature(path) == item["stat"], "input_stat_changed")


def reconstructed_batches(db: sqlite3.Connection, budget: int) -> Iterator[dict]:
    """Espelho independente de scan.batches; mantém só contadores e hash dos IDs."""
    index = 0
    weight = 0
    count = 0
    size = 0
    raw = 0
    first = None
    previous = None
    identity = hashlib.sha256()
    for pid, digest, data in db.execute("SELECT id,sha256,data FROM payloads ORDER BY id"):
        require(type(pid) is int and (previous is None or pid > previous), "payload_ids_invalid")
        require(isinstance(data, bytes) and digest_valid(digest), "payload_schema_invalid")
        require(hashlib.sha256(data).hexdigest() == digest, "payload_digest_mismatch")
        if first is None:
            first = pid
        previous = pid
        count += 1
        size += len(data)
        raw += max(0, len(data) - 31)
        weight += max(1, len(data) - 31)
        identity.update(f"{pid}:{digest}\n".encode("ascii"))
        if weight >= budget:
            yield {"batch_id": index, "payloads": count, "bytes": size,
                   "raw32_windows_per_direction": raw, "first_payload_id": first,
                   "last_payload_id": pid, "ordered_ids_and_sha256": identity.hexdigest()}
            index += 1
            weight = count = size = raw = 0
            first = None
            identity = hashlib.sha256()
    if count:
        yield {"batch_id": index, "payloads": count, "bytes": size,
               "raw32_windows_per_direction": raw, "first_payload_id": first,
               "last_payload_id": previous, "ordered_ids_and_sha256": identity.hexdigest()}


def verify_hit(hit: Any, expected: dict, source: sqlite3.Connection,
               targets: list[str], attempts: Counter) -> None:
    require(isinstance(hit, dict), "invalid_hit")
    pid = hit.get("payload_id")
    require(type(pid) is int and expected["first_payload_id"] <= pid <= expected["last_payload_id"],
            "hit_outside_batch")
    row = source.execute("SELECT sha256,data FROM payloads WHERE id=?", (pid,)).fetchone()
    require(row is not None and hit.get("payload_sha256") == row[0], "hit_payload_mismatch")
    kind = hit.get("format")
    require(kind in FORMATS and attempts[kind] > 0, "hit_format_mismatch")
    require(hit.get("independently_verified") is True, "hit_not_verified_by_scanner")
    require(type(hit.get("compressed")) is bool and hit.get("address") in targets,
            "hit_target_invalid")
    require(digest_valid(hit.get("private_key")), "hit_key_invalid")
    offset = hit.get("offset")
    require(natural(offset) and offset < len(row[1]), "hit_offset_invalid")
    if kind in ("raw32", "raw32-le"):
        candidate = row[1][offset:offset + 32]
        if kind == "raw32-le":
            candidate = candidate[::-1]
        require(candidate.hex() == hit["private_key"], "hit_raw_bytes_mismatch")


def write_qa(run: Path, report: dict) -> None:
    target = run / "final_qa.json"
    require(not target.is_symlink(), "qa_symlink_refused")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=run,
                                     prefix="final_qa.", suffix=".tmp", delete=False) as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        temporary = Path(stream.name)
    os.replace(temporary, target)


def verify_campaign(run: Path, *, write: bool = True) -> dict:
    run = run.resolve(strict=True)
    require(run.is_dir() and run != WORK and run.is_relative_to(WORK.resolve()),
            "campaign_outside_worktree_work")
    summary_path = run / "summary.json"
    summary_bytes = summary_path.read_bytes()
    summary = decode_json(summary_bytes)
    # O checkpoint só pode ser aberto após esta barreira.
    require(isinstance(summary, dict) and summary.get("status") == "complete",
            "scan_not_complete")
    report: dict = {"version": 1, "status": "failed", "pass": False,
                    "scan_status": "complete", "ecc_performed": False,
                    "network_used": False, "verifier_sha256": file_hash(Path(__file__)),
                    "run": str(run), "verified_utc": datetime.now(timezone.utc).isoformat()}
    source = checkpoint = None
    try:
        files = Files()
        require(files.capture(summary_path) == hashlib.sha256(summary_bytes).hexdigest(),
                "summary_changed_before_verification")
        spec_path = run / "spec.json"
        files.capture(spec_path)
        spec = decode_json(spec_path.read_bytes())
        require(isinstance(spec, dict) and isinstance(spec.get("contract"), dict), "invalid_spec")
        contract = spec["contract"]
        mode = contract.get("mode")
        budget = contract.get("batch_windows")
        targets = contract.get("targets")
        require(mode in ("text", "both") and natural(budget) and budget > 0, "invalid_contract")
        require(isinstance(targets, (list, tuple)) and bool(targets)
                and all(isinstance(value, str) for value in targets), "invalid_targets")
        targets = list(targets)
        require(summary.get("mode") == mode and summary.get("targets") == targets,
                "summary_contract_mismatch")
        require(isinstance(contract.get("code"), dict), "invalid_code_contract")
        normalized = {key.replace("\\", "/"): value for key, value in contract["code"].items()}
        require(len(normalized) == len(CODE_FILES) == len(contract["code"])
                and set(normalized) == set(CODE_FILES), "code_contract_members_mismatch")
        for relative in CODE_FILES:
            path = (ROOT / relative).resolve(strict=True)
            require(path.is_relative_to(ROOT), "code_outside_worktree")
            require(files.capture(path) == normalized[relative], "code_hash_mismatch")
        require(isinstance(spec.get("corpus"), str), "invalid_corpus_path")
        corpus = Path(spec["corpus"]).resolve(strict=True)
        no_sidecars(corpus)
        require(files.capture(corpus) == contract.get("corpus_sha256"), "corpus_hash_mismatch")
        checkpoint_path = run / "checkpoint.sqlite"
        no_sidecars(checkpoint_path)
        files.capture(checkpoint_path)
        hits_path = run / "hits.jsonl"
        files.capture(hits_path)
        source = read_only_db(corpus)
        checkpoint = read_only_db(checkpoint_path)
        cursor = iter(checkpoint.execute("SELECT batch_id,result FROM completed ORDER BY batch_id"))
        total: Counter = Counter()
        attempts: Counter = Counter()
        ledger = []
        with hits_path.open("r", encoding="utf-8") as hit_stream:
            for expected in reconstructed_batches(source, budget):
                row = next(cursor, None)
                require(row is not None and type(row[0]) is int and row[0] == expected["batch_id"],
                        "checkpoint_batch_ids_mismatch")
                result = decode_json(row[1])
                require(isinstance(result, dict), "invalid_checkpoint_result")
                for field in ("payloads", "bytes"):
                    require(natural(result.get(field)) and result[field] == expected[field],
                            "batch_counts_mismatch")
                current = attempts_checked(result.get("attempts"))
                wanted = expected["raw32_windows_per_direction"] if mode == "both" else 0
                require(current["raw32"] == wanted and current["raw32-le"] == wanted,
                        "batch_raw32_counts_mismatch")
                valid = result.get("valid_scalars")
                require(natural(valid) and valid <= sum(current.values()), "invalid_valid_scalars")
                hits = result.get("hits")
                require(isinstance(hits, list) and len(hits) <= 2 * valid, "invalid_hit_count")
                for hit in hits:
                    verify_hit(hit, expected, source, targets, current)
                    line = hit_stream.readline()
                    require(bool(line) and decode_json(line) == hit, "hits_file_mismatch")
                total.update({"payloads": expected["payloads"], "bytes": expected["bytes"],
                              "raw32_windows_per_direction": expected["raw32_windows_per_direction"],
                              "valid_scalars": valid, "hits": len(hits)})
                attempts.update(current)
                ledger.append({**expected, "expected_raw32_attempts_each_direction": wanted,
                               "attempts": dict(current), "valid_scalars": valid, "hits": len(hits)})
            require(next(cursor, None) is None, "checkpoint_extra_batches")
            require(hit_stream.read(1) == "", "hits_file_extra_records")
        expected_fields = {"total_payloads": total["payloads"], "payloads_scanned": total["payloads"],
                           "total_bytes": total["bytes"], "bytes_scanned": total["bytes"],
                           "completed_batches": len(ledger), "valid_scalars": total["valid_scalars"],
                           "hard_hits": total["hits"], "expected_raw32_windows_per_direction":
                           total["raw32_windows_per_direction"] if mode == "both" else 0}
        for field, expected_value in expected_fields.items():
            require(natural(summary.get(field)) and summary[field] == expected_value,
                    "summary_counts_mismatch")
        require(attempts_checked(summary.get("attempts")) == attempts, "summary_attempts_mismatch")
        source.close()
        checkpoint.close()
        source = checkpoint = None
        no_sidecars(corpus)
        no_sidecars(checkpoint_path)
        files.finish()
        report.update({"status": "passed", "pass": True, "mode": mode, "targets": targets,
                       "corpus": str(corpus), "corpus_sha256": contract["corpus_sha256"],
                       "code_sha256": normalized, "counts": dict(total), "attempts": dict(attempts),
                       "batch_windows": budget, "batches": ledger,
                       "input_files": {str(path): item for path, item in files.items.items()},
                       "checks": {"sqlite_integrity": True, "sqlite_sidecars_absent": True,
                                  "all_payload_digests": True, "exact_batch_ids": True,
                                  "per_batch_counts": True, "summary_reconciled": True,
                                  "hits_match_checkpoints": True, "input_files_unchanged": True},
                       "limits": [
                           "O checkpoint não registra a lista de IDs processada pelo worker; os IDs são reconstruídos pelo batching contratado.",
                           "Contagens textuais e valid_scalars são reconciliadas, sem repetir extração/ECC.",
                           "A confirmação ECC independente dos hits é a declaração persistida pelo scanner; este auditor não a repete.",
                       ]})
    except (VerificationError, OSError, sqlite3.Error, TypeError, KeyError) as exc:
        report["error"] = str(exc) if isinstance(exc, VerificationError) else type(exc).__name__
    finally:
        if source is not None:
            source.close()
        if checkpoint is not None:
            checkpoint.close()
    if write:
        write_qa(run, report)
    return report


def self_test() -> dict:
    """Fixtures sintéticas de contabilidade; não fingem executar um oráculo ECC."""
    WORK.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="verify_scan_control_", dir=WORK) as folder:
        run = Path(folder).resolve()
        require(run.is_relative_to(WORK.resolve()), "control_path_invalid")
        corpus = run / "fixture.sqlite"
        data = b"A" * 32 + b"B"
        digest = hashlib.sha256(data).hexdigest()
        with closing(sqlite3.connect(corpus)) as db, db:
            db.execute("CREATE TABLE payloads(id INTEGER PRIMARY KEY,sha256 TEXT,data BLOB)")
            db.executemany("INSERT INTO payloads VALUES(?,?,?)", [(3, digest, data),
                           (9, hashlib.sha256(b"x").hexdigest(), b"x")])
        hit = {"payload_id": 3, "payload_sha256": digest, "format": "raw32", "offset": 0,
               "address": "fixture-only-no-ecc", "compressed": True, "private_key": (b"A" * 32).hex(),
               "independently_verified": True}
        results = [{"payloads": 1, "bytes": 33, "attempts": {"raw32": 2, "raw32-le": 2},
                    "valid_scalars": 4, "hits": [hit]},
                   {"payloads": 1, "bytes": 1, "attempts": {"raw32": 0, "raw32-le": 0},
                    "valid_scalars": 0, "hits": []}]
        spec = {"corpus": str(corpus), "contract": {"corpus_sha256": file_hash(corpus),
                "code": {relative: file_hash(ROOT / relative) for relative in CODE_FILES},
                "mode": "both", "targets": ["fixture-only-no-ecc"], "batch_windows": 2}}
        summary = {"status": "complete", "mode": "both", "targets": ["fixture-only-no-ecc"],
                   "total_payloads": 2, "payloads_scanned": 2, "total_bytes": 34, "bytes_scanned": 34,
                   "completed_batches": 2, "expected_raw32_windows_per_direction": 2,
                   "attempts": {"raw32": 2, "raw32-le": 2}, "valid_scalars": 4, "hard_hits": 1}

        def publish() -> None:
            (run / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
            (run / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            (run / "hits.jsonl").write_text(json.dumps(hit) + "\n", encoding="utf-8")
            with closing(sqlite3.connect(run / "checkpoint.sqlite")) as db, db:
                db.execute("CREATE TABLE IF NOT EXISTS completed(batch_id INTEGER PRIMARY KEY,result TEXT)")
                db.execute("DELETE FROM completed")
                db.executemany("INSERT INTO completed VALUES(?,?)", enumerate(map(json.dumps, results)))

        publish()
        require(verify_campaign(run)["pass"], "self_test_positive_failed")
        cases = 1
        mutations = ((0, "payloads", 2, "batch_counts_mismatch"),
                     (0, "attempts", {"raw32": 1, "raw32-le": 3}, "batch_raw32_counts_mismatch"),
                     (0, "valid_scalars", -1, "invalid_valid_scalars"))
        for batch, field, value, error in mutations:
            old = results[batch][field]
            results[batch][field] = value
            publish()
            require(verify_campaign(run, write=False).get("error") == error, "self_test_negative_failed")
            results[batch][field] = old
            cases += 1
        publish()
        with closing(sqlite3.connect(run / "checkpoint.sqlite")) as db, db:
            db.execute("UPDATE completed SET batch_id=7 WHERE batch_id=1")
        require(verify_campaign(run, write=False).get("error") == "checkpoint_batch_ids_mismatch",
                "self_test_ids_failed")
        cases += 1
        publish()
        (run / "hits.jsonl").write_text("", encoding="utf-8")
        require(verify_campaign(run, write=False).get("error") == "hits_file_mismatch", "self_test_hits_failed")
        cases += 1
        publish()
        summary["valid_scalars"] += 1
        (run / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        require(verify_campaign(run, write=False).get("error") == "summary_counts_mismatch",
                "self_test_summary_failed")
        summary["valid_scalars"] -= 1
        cases += 1
        publish()
        sidecar = Path(str(corpus) + "-wal")
        sidecar.touch()
        require(verify_campaign(run, write=False).get("error") == "sqlite_sidecar_present",
                "self_test_wal_failed")
        sidecar.unlink()
        cases += 1
        publish()
        spec["contract"]["code"][CODE_FILES[0]] = "0" * 64
        (run / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
        require(verify_campaign(run, write=False).get("error") == "code_hash_mismatch", "self_test_code_failed")
        cases += 1
        summary["status"] = "running"
        (run / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        (run / "checkpoint.sqlite").unlink()
        try:
            verify_campaign(run, write=False)
        except VerificationError as exc:
            require(str(exc) == "scan_not_complete", "self_test_gate_failed")
        else:
            raise VerificationError("self_test_gate_failed")
        cases += 1
        return {"pass": True, "cases": cases, "ecc_performed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps({"self_test": self_test()}))
        return
    if args.run is None:
        parser.error("Informe --run ou --self-test")
    try:
        report = verify_campaign(args.run)
    except (VerificationError, OSError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc) if isinstance(exc, VerificationError)
                          else type(exc).__name__}))
        raise SystemExit(2) from None
    print(json.dumps({"status": report["status"], "counts": report.get("counts", {}),
                      "batches": len(report.get("batches", [])), "error": report.get("error"),
                      "final_qa": str(args.run.resolve() / "final_qa.json")}))
    if not report["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
