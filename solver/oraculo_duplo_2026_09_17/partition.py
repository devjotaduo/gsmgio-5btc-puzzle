"""Separa o complemento de snapshots já varridos, conferindo cada byte comum."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from scan import file_sha256, require_standalone_sqlite


def readonly(path: Path) -> sqlite3.Connection:
    require_standalone_sqlite(path)
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", type=Path, required=True)
    parser.add_argument("--previous", type=Path, nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("A saída deve ser nova")
    hashes = {str(path.resolve()): file_sha256(path) for path in [args.full, *args.previous]}
    seen: dict[str, bytes] = {}
    prior_count = 0
    for path in args.previous:
        with readonly(path) as connection:
            for digest, data in connection.execute("SELECT sha256,data FROM payloads"):
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError("Payload anterior com hash inválido")
                if digest in seen:
                    raise ValueError("Snapshots anteriores se sobrepõem")
                seen[digest] = data
                prior_count += 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    output = sqlite3.connect(args.out)
    output.execute("CREATE TABLE payloads(id INTEGER PRIMARY KEY,sha256 TEXT UNIQUE,data BLOB)")
    counts = {"full": 0, "common": 0, "complement": 0, "complement_bytes": 0, "complement_windows": 0}
    with readonly(args.full) as connection:
        for identifier, digest, data in connection.execute("SELECT id,sha256,data FROM payloads ORDER BY id"):
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("Payload completo com hash inválido")
            counts["full"] += 1
            if digest in seen:
                if seen.pop(digest) != data:
                    raise ValueError("Os bytes comuns não coincidem")
                counts["common"] += 1
            else:
                output.execute("INSERT INTO payloads VALUES (?,?,?)", (identifier, digest, data))
                counts["complement"] += 1
                counts["complement_bytes"] += len(data)
                counts["complement_windows"] += max(0, len(data) - 31)
    if seen or counts["common"] != prior_count:
        raise ValueError("Snapshot anterior contém payload ausente no corpus completo")
    for name, digest in hashes.items():
        if file_sha256(Path(name)) != digest:
            raise ValueError("Snapshot foi modificado durante partição")
    output.commit()
    output.close()
    summary = {"passed": True, "input_hashes": hashes, "counts": counts,
               "output_sha256": file_sha256(args.out), "source_sha256": file_sha256(Path(__file__)),
               "coverage": "união disjunta dos snapshots anteriores e complemento = corpus completo, bytes conferidos"}
    args.out.with_suffix(".partition.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
