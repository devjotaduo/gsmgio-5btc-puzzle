"""Auditoria independente: campos explicitamente rotulados como plaintext hex.

Não reutiliza o parser do coletor. Compara valores encontrados por regex aos
bytes do corpus, apenas quando a fonte ainda reproduz o hash do snapshot.
"""

import argparse
import hashlib
import json
import re
import sqlite3
import zlib
from pathlib import Path

from scan import file_sha256, require_standalone_sqlite

FIELD = re.compile(rb'''(?i)["']?\b(plain_?hex|plaintext_?hex|pt_?hex|p_?hex|head_?hex|hex128)["']?\s*[:=]\s*["']([0-9a-f]+)["']''')


def decompress(raw: bytes) -> bytes:
    parts = []
    while raw:
        decoder = zlib.decompressobj(31)
        parts.append(decoder.decompress(raw))
        if not decoder.unused_data:
            break
        raw = decoder.unused_data
    return b"".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    require_standalone_sqlite(args.corpus)
    corpus_hash = file_sha256(args.corpus)
    con = sqlite3.connect(args.corpus.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    digests = {row[0] for row in con.execute("SELECT sha256 FROM payloads")}
    result = {"corpus_sha256": corpus_hash,
              "files_with_snapshot_hash_verified": 0, "explicit_fields_checked": 0,
              "missing": [], "unverifiable_sources": [], "odd_length_fields": 0,
              "scope": "campos explicitamente rotulados com valores hex entre aspas; não cobre generic hex, representações de texto ou gzip irrecuperável"}
    for relative, expected_hash, metadata in con.execute("SELECT path,sha256,metadata FROM sources WHERE sha256 IS NOT NULL"):
        details = json.loads(metadata)
        path = args.source_root / relative
        try:
            with path.open("rb") as source:
                raw = source.read(details["snapshot_bytes"])
            if hashlib.sha256(raw).hexdigest() != expected_hash:
                raise ValueError("Fonte não reproduz o snapshot")
            result["files_with_snapshot_hash_verified"] += 1
            if relative.endswith(".gz"):
                raw = decompress(raw)
            for match in FIELD.finditer(raw):
                if len(match[2]) % 2:
                    result["odd_length_fields"] += 1
                    continue
                data = bytes.fromhex(match[2].decode("ascii"))
                digest = hashlib.sha256(data).hexdigest()
                result["explicit_fields_checked"] += 1
                if digest not in digests:
                    result["missing"].append({"source": relative, "field": match[1].decode(),
                                              "byte_offset": match.start(), "length": len(data), "sha256": digest})
        except (OSError, ValueError, zlib.error) as error:
            result["unverifiable_sources"].append({"source": relative, "error": str(error)})
    con.close()
    require_standalone_sqlite(args.corpus)
    if file_sha256(args.corpus) != corpus_hash:
        raise ValueError("Corpus alterado durante a auditoria")
    result["passed_within_scope"] = not result["missing"] and not result["unverifiable_sources"]
    result["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v if not isinstance(v, list) else len(v) for k, v in result.items()}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
