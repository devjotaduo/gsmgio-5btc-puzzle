"""Varredura finita: codecs completos e, opcionalmente, raw32 nas duas ordens.

Lê apenas snapshots SQLite fechados. Checkpoints guardam lotes efetivamente
concluídos; estimativa de janelas nunca é evidência de execução. Chaves de hits
ficam apenas no diretório local de saída, nunca no stdout.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import hashlib
import json
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "solver" / "oraculo_duplo_2026_09_17"))
import oracle as oracle_module
from oracle import Oracle, TARGETS, independent_address, valid_scalar
from scan import batches, file_sha256, require_standalone_sqlite, save_json

_oracle: Oracle | None = None
_mode = "text"


def initialize(targets: tuple[str, ...], mode: str) -> None:
    global _oracle, _mode
    _oracle = Oracle(targets)
    _mode = mode


def scan_one(data: bytes, oracle: Oracle, mode: str) -> dict:
    result = oracle.scan(data, decoded_only=mode == "text")
    if mode == "both":
        count = 0
        for offset in range(max(0, len(data) - 31)):
            secret = data[offset:offset + 32][::-1]
            count += 1
            if not valid_scalar(secret):
                continue
            result["valid_scalars"] += 1
            for hit in oracle.check(secret):
                result["hits"].append({"format": "raw32-le", "offset": offset, **hit})
        result["attempts"]["raw32-le"] = count
    return result


def scan_batch(rows: list[tuple[int, str, bytes]]) -> dict:
    if _oracle is None:
        raise RuntimeError("Worker não inicializado")
    attempts: Counter = Counter()
    hits = []
    valid = 0
    for pid, digest, data in rows:
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"Digest divergente: payload {pid}")
        result = scan_one(data, _oracle, _mode)
        attempts.update(result["attempts"])
        valid += result["valid_scalars"]
        for hit in result["hits"]:
            secret = bytes.fromhex(hit["private_key"])
            if independent_address(secret, hit["compressed"]) != hit["address"]:
                raise RuntimeError("Hit não confirmado por segunda implementação ECC")
            hits.append({"payload_id": pid, "payload_sha256": digest,
                         "independently_verified": True, **hit})
    return {"payloads": len(rows), "bytes": sum(len(row[2]) for row in rows),
            "attempts": dict(attempts), "valid_scalars": valid, "hits": hits}


def controls() -> dict:
    import random
    key = hashlib.sha256(b"multiagente scan_delta planted").digest()
    target = independent_address(key, True)
    oracle = Oracle((target,))
    data = b"prefix!" + key[::-1] + b"suffix"
    result = scan_one(data, oracle, "both")
    assert any(h["format"] == "raw32-le" and h["offset"] == 7
               and h["address"] == target for h in result["hits"])
    assert result["attempts"]["raw32"] == len(data) - 31
    assert result["attempts"]["raw32-le"] == len(data) - 31
    assert not scan_one(data, oracle, "text")["hits"]
    encoded = b"!" + key.hex().encode() + b"!"
    assert scan_one(encoded, oracle, "text")["hits"]
    rng = random.Random(18092026)
    n_windows = 0
    for _ in range(100):
        shuffled = list(data)
        rng.shuffle(shuffled)
        out = scan_one(bytes(shuffled), oracle, "both")
        assert not out["hits"]
        n_windows += out["attempts"]["raw32"] + out["attempts"]["raw32-le"]
    return {"pass": True, "planted_le_offset": 7, "null_replicates": 100,
            "null_raw32_attempts": n_windows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=("text", "both"), required=True)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--batch-windows", type=int, default=100000)
    parser.add_argument("--targets", nargs="+", default=TARGETS)
    args = parser.parse_args()
    if not 1 <= args.workers <= 20 or args.batch_windows < 1:
        parser.error("Número de workers/lote inválido")
    corpus = args.corpus.resolve(strict=True)
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "_work") or corpus.is_relative_to(out):
        parser.error("Saída deve ficar no _work desta worktree, fora do corpus")
    Oracle(args.targets)
    require_standalone_sqlite(corpus)
    ctrl = controls()
    deps = [Path(__file__), Path(oracle_module.__file__),
            ROOT / "solver" / "oraculo_duplo_2026_09_17" / "scan.py"]
    code = {str(path.relative_to(ROOT)): file_sha256(path) for path in deps}
    contract = {"corpus_sha256": file_sha256(corpus), "code": code,
                "targets": args.targets, "mode": args.mode,
                "batch_windows": args.batch_windows, "python": sys.version}
    out.mkdir(parents=True, exist_ok=True)
    spec_path = out / "spec.json"
    if spec_path.exists():
        if json.loads(spec_path.read_text(encoding="utf-8"))["contract"] != contract:
            raise ValueError("Contrato alterado: use outro diretório")
    else:
        if any(out.iterdir()):
            raise ValueError("Saída não vazia sem contrato")
        save_json(spec_path, {"contract": contract, "corpus": str(corpus),
                             "controls": ctrl, "created_utc": datetime.now(timezone.utc).isoformat()})
    source = sqlite3.connect(corpus.as_uri() + "?mode=ro&immutable=1", uri=True)
    n_payloads, n_bytes, windows = source.execute(
        "SELECT COUNT(*),COALESCE(SUM(length(data)),0),"
        "COALESCE(SUM(MAX(length(data)-31,0)),0) FROM payloads").fetchone()
    checkpoint = sqlite3.connect(out / "checkpoint.sqlite")
    checkpoint.execute("CREATE TABLE IF NOT EXISTS completed (batch_id INTEGER PRIMARY KEY,result TEXT NOT NULL)")
    checkpoint.commit()
    done: set[int] = set()
    totals: Counter = Counter()
    attempts: Counter = Counter()

    def add(index: int, result: dict) -> None:
        done.add(index)
        attempts.update(result["attempts"])
        totals.update({k: result[k] for k in ("payloads", "bytes", "valid_scalars")})
        totals["hits"] += len(result["hits"])

    for index, encoded in checkpoint.execute("SELECT batch_id,result FROM completed"):
        add(index, json.loads(encoded))
    start = time.monotonic()
    initial_attempts = sum(attempts.values())
    initial_bytes = totals["bytes"]
    last_progress = start

    def progress(status: str) -> None:
        elapsed = time.monotonic() - start
        save = {"status": status, "mode": args.mode, "targets": args.targets,
                "total_payloads": n_payloads, "total_bytes": n_bytes,
                "expected_raw32_windows_per_direction": windows if args.mode == "both" else 0,
                "completed_batches": len(done), "payloads_scanned": totals["payloads"],
                "bytes_scanned": totals["bytes"], "attempts": dict(attempts),
                "valid_scalars": totals["valid_scalars"], "hard_hits": totals["hits"],
                "workers": args.workers, "seconds": round(elapsed, 3),
                "session_attempts_per_second": round((sum(attempts.values()) - initial_attempts) / max(elapsed, .001), 1),
                "session_bytes_per_second": round((totals["bytes"] - initial_bytes) / max(elapsed, .001), 1),
                "updated_utc": datetime.now(timezone.utc).isoformat()}
        save_json(out / "summary.json", save)
        print(json.dumps(save), flush=True)

    iterator = batches(source, args.batch_windows)
    pending: dict = {}
    exhausted = False
    progress("running")
    with futures.ProcessPoolExecutor(max_workers=args.workers, initializer=initialize,
                                     initargs=(tuple(args.targets), args.mode)) as pool:
        while pending or not exhausted:
            while not exhausted and len(pending) < args.workers * 2:
                try:
                    index, rows = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                if index not in done:
                    pending[pool.submit(scan_batch, rows)] = index
            if pending:
                completed, _ = futures.wait(pending, timeout=10, return_when=futures.FIRST_COMPLETED)
                for task in completed:
                    index = pending.pop(task)
                    result = task.result()
                    checkpoint.execute("INSERT INTO completed VALUES (?,?)", (index, json.dumps(result)))
                    checkpoint.commit()
                    add(index, result)
            if time.monotonic() - last_progress >= 30:
                progress("running")
                last_progress = time.monotonic()
    assert totals["payloads"] == n_payloads and totals["bytes"] == n_bytes
    expected = windows if args.mode == "both" else 0
    assert attempts["raw32"] == expected
    assert attempts["raw32-le"] == expected
    source.close()
    require_standalone_sqlite(corpus)
    if file_sha256(corpus) != contract["corpus_sha256"]:
        raise RuntimeError("Corpus alterado durante varredura")
    if any(file_sha256(path) != code[str(path.relative_to(ROOT))] for path in deps):
        raise RuntimeError("Código alterado durante varredura")
    with (out / "hits.jsonl").open("w", encoding="utf-8") as stream:
        for encoded, in checkpoint.execute("SELECT result FROM completed ORDER BY batch_id"):
            for hit in json.loads(encoded)["hits"]:
                stream.write(json.dumps(hit) + "\n")
    checkpoint.close()
    progress("complete")


if __name__ == "__main__":
    main()
