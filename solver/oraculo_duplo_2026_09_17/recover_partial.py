"""Recupera o prefixo hex comprovado da linha JSONL cortada no snapshot v3."""

import argparse
import hashlib
import json
import re
import sqlite3
from pathlib import Path

from scan import file_sha256

SOURCE = "_work/operador_ensinado_2026-09-17/critico_familia5/critico_familia5.jsonl"
FILE_BYTES = 8716188
FILE_HASH = "be32b6a2e0a68c16a2adb3e59912e991d2fe65d629dfec5c3a5b7c3a0c7ee703"
PREFIX_HASH = "396c7f0d499abfdff11273feaf28aa53c0dfb01a2e7e42ac51f9b27e7c4ea5fc"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Saída precisa ser nova")
    with (args.source_root / SOURCE).open("rb") as stream:
        raw = stream.read(FILE_BYTES)
    if len(raw) != FILE_BYTES or hashlib.sha256(raw).hexdigest() != FILE_HASH:
        raise ValueError("A fonte não reproduz exatamente o snapshot auditado")
    lines = raw.splitlines()
    if len(lines) != 6215:
        raise ValueError("Número de linhas divergente")
    match = re.search(rb'"hex"\s*:\s*"([0-9a-fA-F]+)$', lines[-1])
    if match is None or len(match[1]) != 1578:
        raise ValueError("Prefixo final não corresponde ao caso auditado")
    data = bytes.fromhex(match[1].decode("ascii"))
    if len(data) != 789 or hashlib.sha256(data).hexdigest() != PREFIX_HASH:
        raise ValueError("Prefixo recuperado diverge da auditoria independente")
    args.out.mkdir(parents=True)
    con = sqlite3.connect(args.out / "corpus.sqlite")
    con.execute("CREATE TABLE payloads(id INTEGER PRIMARY KEY,sha256 TEXT UNIQUE,data BLOB)")
    con.execute("INSERT INTO payloads VALUES (1,?,?)", (PREFIX_HASH, data))
    con.commit()
    con.close()
    result = {"passed": True, "source": SOURCE, "source_snapshot_bytes": FILE_BYTES,
              "source_snapshot_sha256": FILE_HASH, "locator": "line:6215.hex",
              "prefix_bytes": len(data), "prefix_sha256": PREFIX_HASH,
              "declared_plaintext_bytes": 1327, "absent_tail_bytes": 538,
              "truncated": True, "dropped_nibbles": 0,
              "corpus_sha256": file_sha256(args.out / "corpus.sqlite"),
              "source_script_sha256": file_sha256(Path(__file__))}
    (args.out / "spec.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
