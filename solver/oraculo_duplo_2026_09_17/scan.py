"""Varredura paralela e retomável do SQLite produzido por collect.py.

Só lê o corpus; checkpoints e chaves eventualmente encontradas ficam no --out.
Uma execução concluída cobre cada payload único e ambos os alvos/serializações.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import sqlite3
import sys
import time
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from oracle import TARGETS, Oracle, address_payload, independent_address

_ORACLE: Oracle | None = None


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_standalone_sqlite(path: Path) -> None:
    """O contrato cobre um snapshot fechado; WAL/journal externo não é admitido."""
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise ValueError(f"Corpus SQLite ainda tem {suffix}; feche/consolide o coletor antes da varredura")


def save_json(path: Path, data: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def initialize(targets: tuple[str, ...]) -> None:
    global _ORACLE
    _ORACLE = Oracle(targets)


def scan_batch(rows: list[tuple[int, str, bytes]]) -> dict:
    if _ORACLE is None:
        raise RuntimeError("Worker não inicializado")
    attempts: Counter = Counter()
    hits = []
    valid_scalars = 0
    for payload_id, digest, data in rows:
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"SHA256 divergente no payload {payload_id}")
        result = _ORACLE.scan(data)
        attempts.update(result["attempts"])
        valid_scalars += result["valid_scalars"]
        for hit in result["hits"]:
            # Implementação ECC independente confirma todo resultado positivo.
            if independent_address(bytes.fromhex(hit["private_key"]), hit["compressed"]) != hit["address"]:
                raise RuntimeError("Coincidência não confirmada pelo oráculo independente")
            hits.append({"payload_id": payload_id, "payload_sha256": digest,
                         "independently_verified": True, **hit})
    return {"payloads": len(rows), "bytes": sum(len(row[2]) for row in rows),
            "attempts": dict(attempts), "valid_scalars": valid_scalars, "hits": hits}


def batches(connection: sqlite3.Connection, max_windows: int) -> Iterator[tuple[int, list[tuple[int, str, bytes]]]]:
    rows = []
    windows = 0
    index = 0
    for row in connection.execute("SELECT id, sha256, data FROM payloads ORDER BY id"):
        rows.append(row)
        windows += max(1, len(row[2]) - 31)
        if windows >= max_windows:
            yield index, rows
            rows = []
            windows = 0
            index += 1
    if rows:
        yield index, rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--batch-windows", type=int, default=25000)
    parser.add_argument("--targets", nargs="+", default=TARGETS)
    args = parser.parse_args()
    if args.workers < 1 or args.batch_windows < 1:
        parser.error("workers e batch-windows devem ser positivos")
    corpus = args.corpus.resolve(strict=True)
    out = args.out.resolve()
    if out == corpus or corpus.is_relative_to(out):
        parser.error("O corpus precisa ficar fora da pasta de saída")
    targets = tuple(args.targets)
    Oracle(targets)
    require_standalone_sqlite(corpus)
    out.mkdir(parents=True, exist_ok=True)
    script = Path(__file__)
    contract = {"corpus_sha256": file_sha256(corpus), "targets": list(targets),
                "target_hash160": {a: address_payload(a).hex() for a in targets},
                "oracle_sha256": file_sha256(script.with_name("oracle.py")),
                "scanner_sha256": file_sha256(script), "batch_windows": args.batch_windows,
                "python_version": sys.version}
    spec_path = out / "spec.json"
    if spec_path.exists():
        previous = json.loads(spec_path.read_text(encoding="utf-8"))
        if previous["contract"] != contract:
            raise ValueError("Corpus/código/alvos mudaram: use outra pasta de saída")
    else:
        if any(out.iterdir()):
            raise ValueError("Saída contém arquivos sem spec.json; use uma pasta nova")
        save_json(spec_path, {"contract": contract, "corpus": str(corpus),
                             "created_utc": datetime.now(timezone.utc).isoformat()})

    # A URI read-only impede escritas acidentais no corpus.
    source = sqlite3.connect(corpus.as_uri() + "?mode=ro&immutable=1", uri=True)
    counts = source.execute("SELECT COUNT(*), COALESCE(SUM(length(data)),0), "
                            "COALESCE(SUM(MAX(length(data)-31,0)),0) FROM payloads").fetchone()
    checkpoint = sqlite3.connect(out / "checkpoint.sqlite")
    checkpoint.execute("CREATE TABLE IF NOT EXISTS completed (batch_id INTEGER PRIMARY KEY, result TEXT NOT NULL)")
    checkpoint.commit()
    completed: set[int] = set()
    total_attempts: Counter = Counter()
    totals: Counter = Counter()

    def accumulate(index: int, result: dict) -> None:
        completed.add(index)
        total_attempts.update(result["attempts"])
        totals.update({k: result[k] for k in ("payloads", "bytes", "valid_scalars")})
        totals["hits"] += len(result["hits"])

    for index, encoded in checkpoint.execute("SELECT batch_id, result FROM completed"):
        accumulate(index, json.loads(encoded))
    started = time.monotonic()
    initial_attempts = sum(total_attempts.values())
    last_progress = 0.0

    def progress(status: str) -> dict:
        elapsed = time.monotonic() - started
        attempted_now = sum(total_attempts.values()) - initial_attempts
        rate = attempted_now / elapsed if elapsed else 0.0
        result = {"status": status, "targets": list(targets), "corpus_sha256": contract["corpus_sha256"],
                  "total_payloads": counts[0], "total_bytes": counts[1], "expected_raw32_windows": counts[2],
                  "completed_batches": len(completed), "payloads_scanned": totals["payloads"],
                  "bytes_scanned": totals["bytes"], "attempts": dict(total_attempts),
                  "valid_scalars": totals["valid_scalars"], "hard_hits": totals["hits"],
                  "workers": args.workers, "session_seconds": round(elapsed, 3),
                  "session_candidates_per_second": round(rate, 1),
                  "updated_utc": datetime.now(timezone.utc).isoformat()}
        save_json(out / "summary.json", result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return result

    iterator = batches(source, args.batch_windows)
    pending: dict[concurrent.futures.Future, int] = {}
    exhausted = False
    progress("running")
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers, initializer=initialize, initargs=(targets,)) as pool:
        while pending or not exhausted:
            while not exhausted and len(pending) < args.workers * 2:
                try:
                    index, rows = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                if index in completed:
                    continue
                pending[pool.submit(scan_batch, rows)] = index
            if not pending:
                continue
            done, _ = concurrent.futures.wait(pending, timeout=15, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                index = pending.pop(future)
                result = future.result()
                checkpoint.execute("INSERT INTO completed VALUES (?, ?)", (index, json.dumps(result)))
                checkpoint.commit()
                accumulate(index, result)
            if time.monotonic() - last_progress >= 20:
                progress("running")
                last_progress = time.monotonic()

    if totals["payloads"] != counts[0] or totals["bytes"] != counts[1] or total_attempts["raw32"] != counts[2]:
        raise RuntimeError("Cobertura incompleta: totais não coincidem com o corpus")
    # Falha fechada se alguém alterar o snapshot durante a execução.
    source.close()
    require_standalone_sqlite(corpus)
    if file_sha256(corpus) != contract["corpus_sha256"]:
        raise RuntimeError("Corpus alterado durante a execução")
    if (file_sha256(script) != contract["scanner_sha256"]
            or file_sha256(script.with_name("oracle.py")) != contract["oracle_sha256"]):
        raise RuntimeError("Código alterado durante a execução; resultados não serão marcados completos")
    with (out / "hits.jsonl").open("w", encoding="utf-8") as stream:
        for encoded, in checkpoint.execute("SELECT result FROM completed ORDER BY batch_id"):
            for hit in json.loads(encoded)["hits"]:
                stream.write(json.dumps(hit) + "\n")
    checkpoint.close()
    progress("complete")


if __name__ == "__main__":
    main()
