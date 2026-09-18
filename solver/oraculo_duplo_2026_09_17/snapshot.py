"""Congela só payloads já commitados de um coletor ativo, em transação de leitura."""

import argparse
import json
import sqlite3
from pathlib import Path

from scan import file_sha256


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Saída precisa ser nova")
    source = sqlite3.connect(args.source.resolve(strict=True).as_uri() + "?mode=ro", uri=True)
    source.execute("BEGIN")
    expected = source.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    output = sqlite3.connect(args.out)
    output.execute("CREATE TABLE payloads(id INTEGER PRIMARY KEY,sha256 TEXT UNIQUE,data BLOB)")
    count = 0
    for row in source.execute("SELECT id,sha256,data FROM payloads ORDER BY id"):
        output.execute("INSERT INTO payloads VALUES (?,?,?)", row)
        count += 1
    if count != expected:
        raise RuntimeError("Contagem de snapshot inconsistente")
    output.commit()
    output.close()
    source.rollback()
    source.close()
    result = {"passed": True, "committed_payloads": count,
              "snapshot_sha256": file_sha256(args.out), "source_script_sha256": file_sha256(Path(__file__)),
              "scope": "snapshot transacional dos payloads commitados; não cobre dados posteriores"}
    args.out.with_suffix(".snapshot.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
