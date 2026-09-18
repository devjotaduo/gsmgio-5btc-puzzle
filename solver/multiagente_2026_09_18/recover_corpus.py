"""Recupera quatro fontes delimitadas, sem buscar senhas nem executar o scanner.

Reproduz AES dos registros Bifid já existentes, exige igualdade do prefixo e do
comprimento, e importa os registros COSMIC integrais. Cada byte novo é deduplicado
contra os três bancos concluídos de 17/09 e contra os demais bytes desta coleta.
Somente a pasta de saída nova recebe escritas; snapshots privados ficam locais.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import tempfile
from typing import Any, BinaryIO, Iterator

from Crypto.Cipher import AES


VERSION = 1
KIT = "solver/experiments/claude_endgame_2026_09_02/gsmg_common.py"
BIFID_SCRIPT = "solver/experiments/claude_endgame_2026_09_02/bifid3x3_exhaustive.py"
DATA_SOURCES = (
    ("_work/operador_ensinado_2026-09-17/critico_sete_final/cosmic_full_agente.bin", "cosmic_binary"),
    ("_work/operador_ensinado_2026-09-17/critico_sete_final/cosmic_full_o5up.bin", "cosmic_binary"),
    ("solver/experiments/claude_endgame_2026_09_02/bifid3x3_exhaustive.jsonl", "bifid_jsonl"),
    ("solver/experiments/claude_endgame_2026_09_02/b3x3_run_screen_only.jsonl", "bifid_jsonl"),
)
BASELINE_PATHS = (
    "corpus_v3/corpus.sqlite", "corpus_supplement/corpus.sqlite", "corpus_partial/corpus.sqlite",
)
KDFS = {"EVP-SHA256", "Crypto.Hash.SHA256", "sha256"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stats(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "inode": stat.st_ino}


def closed_database(path: Path) -> sqlite3.Connection:
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise ValueError(f"Banco anterior ainda tem journal ativo: {path.name}{suffix}")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)


def decrypt(password: bytes, raw: bytes, digest: str = "sha256") -> bytes:
    if raw[:8] != b"Salted__" or len(raw) < 32 or (len(raw) - 16) % 16:
        raise ValueError("Blob openssl inválido")
    derived = previous = b""
    while len(derived) < 48:
        previous = hashlib.new(digest, previous + password + raw[8:16]).digest()
        derived += previous
    padded = AES.new(derived[:32], AES.MODE_CBC, derived[32:48]).decrypt(raw[16:])
    padding = padded[-1]
    if not 1 <= padding <= 16 or padded[-padding:] != bytes([padding]) * padding:
        raise ValueError("Padding não reproduzido")
    return padded[:-padding]


def read_blobs(readme: str, kit: str) -> tuple[dict[str, bytes], dict[str, Any]]:
    constants = {}
    for node in ast.parse(kit).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"SMALL_B64", "TAIL32_B64"}:
                constants[name[:-4]] = ast.literal_eval(node.value)
    cosmic = re.search(r"\*\*Cosmic Duality:\*\*\n\n```text\n(.*?)```", readme, re.S)
    if cosmic is None:
        raise ValueError("COSMIC ausente do README")
    constants["COSMIC"] = cosmic[1].replace("\n", "").strip()
    blobs = {name: base64_decode(value) for name, value in constants.items()}
    assert {name: len(data) - 16 for name, data in blobs.items()} == {
        "SMALL": 80, "TAIL32": 80, "COSMIC": 1328}
    # Positivo autenticado do puzzle, independente dos oráculos ativos.
    lines = []
    for line in readme[readme.index("U2FsdGVkX18GKGYS"):].splitlines():
        line = line.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]{4,64}", line):
            break
        lines.append(line)
    phase2 = base64_decode("".join(lines))
    password = hashlib.sha256(b"causality").hexdigest().encode()
    plain = decrypt(password, phase2)
    assert plain.startswith(b"The ironic 2name of the keymakers")
    try:
        md5_plain = decrypt(password, phase2, "md5")
    except ValueError:
        md5_plain = b""
    assert not md5_plain.startswith(b"The ironic")
    return blobs, {"phase2_sha256": True, "phase2_md5_rejected": True,
                   "phase2_plaintext_sha256": hashlib.sha256(plain).hexdigest(),
                   "blob_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in blobs.items()}}


def base64_decode(value: str) -> bytes:
    import base64
    return base64.b64decode(value, validate=True)


def objects(value: Any, locator: str) -> Iterator[tuple[dict[str, Any], str]]:
    if isinstance(value, dict):
        yield value, locator
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield from objects(child, f"{locator}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from objects(child, f"{locator}[{index}]")


class Recovery:
    def __init__(self, source_root: Path, prior: Path, out: Path) -> None:
        self.root = source_root.resolve(strict=True)
        self.prior = prior.resolve(strict=True)
        self.out = out.resolve()
        if self.out.is_relative_to(self.root) or self.root.is_relative_to(self.out):
            raise ValueError("Saída precisa estar fora da árvore de origem")
        self.out.mkdir(parents=True, exist_ok=False)
        (self.out / "snapshots").mkdir()
        self.started = now()
        self.code_sha256 = sha_file(Path(__file__))
        self.db = sqlite3.connect(self.out / "corpus.sqlite")
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE payloads(id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE NOT NULL, data BLOB NOT NULL);
            CREATE TABLE origins(payload_id INTEGER NOT NULL, source TEXT NOT NULL, locator TEXT NOT NULL,
                field TEXT NOT NULL, truncated INTEGER NOT NULL, metadata TEXT NOT NULL);
            CREATE TABLE covered_origins(source TEXT, locator TEXT, sha256 TEXT, baseline TEXT,
                baseline_id INTEGER, metadata TEXT);
            CREATE TABLE sources(path TEXT PRIMARY KEY,sha256 TEXT,size INTEGER,metadata TEXT);
            CREATE TABLE issues(source TEXT,locator TEXT,kind TEXT,message TEXT);
            CREATE TABLE excluded_records(source TEXT,locator TEXT,reason TEXT);
            CREATE INDEX origins_payload ON origins(payload_id);
        """)
        self.counts: Counter[str] = Counter()
        self.source_counts: Counter[str] = Counter()
        self.baselines = []
        self.baseline_manifest = []
        for relative in BASELINE_PATHS:
            path = self.prior / relative
            before = stats(path)
            digest = sha_file(path)
            connection = closed_database(path)
            if stats(path) != before:
                raise ValueError("Banco anterior mudou durante abertura")
            self.baselines.append((relative, path, connection))
            self.baseline_manifest.append({"path": relative, "sha256": digest, "stat": before,
                                           "payloads": connection.execute("SELECT count(*) FROM payloads").fetchone()[0]})

    def issue(self, source: str, locator: str, kind: str, message: str) -> None:
        self.counts[f"issue:{kind}"] += 1
        self.source_counts[f"issue:{kind}"] += 1
        self.db.execute("INSERT INTO issues VALUES(?,?,?,?)", (source, locator, kind, message[:500]))

    def snapshot(self, source: str, inventory: dict[str, int], number: int) -> tuple[Path, dict[str, Any]]:
        original = self.root / source
        target = self.out / "snapshots" / f"{number:02d}_{original.name}"
        before = stats(original)
        copied = 0
        digest = hashlib.sha256()
        with original.open("rb") as src, target.open("xb") as dst:
            while copied < inventory["size"]:
                block = src.read(min(1024 * 1024, inventory["size"] - copied))
                if not block:
                    break
                dst.write(block)
                digest.update(block)
                copied += len(block)
        after = stats(original)
        metadata = {"inventory": inventory, "copy_start": before, "copy_end": after,
                    "snapshot": target.relative_to(self.out).as_posix(), "snapshot_bytes": copied,
                    "snapshot_sha256": digest.hexdigest(), "changed": before != after or before != inventory}
        if copied != inventory["size"]:
            self.issue(source, "$", "short_snapshot", "Fonte terminou antes do limite inventariado")
        if metadata["changed"]:
            self.issue(source, "$", "source_changed", "Tamanho/mtime/inode mudou; vale somente o snapshot capturado")
        assert sha_file(target) == digest.hexdigest()
        self.counts["snapshot_bytes"] += copied
        return target, metadata

    def add(self, data: bytes, source: str, locator: str, field: str, metadata: dict[str, Any]) -> None:
        digest = hashlib.sha256(data).hexdigest()
        self.counts["accepted_origins"] += 1
        self.source_counts["accepted_origins"] += 1
        encoded = json.dumps(metadata, ensure_ascii=True)
        for name, _, connection in self.baselines:
            row = connection.execute("SELECT id,data FROM payloads WHERE sha256=?", (digest,)).fetchone()
            if row is not None:
                if row[1] != data:
                    raise ValueError("Hash igual com bytes divergentes no corpus anterior")
                self.db.execute("INSERT INTO covered_origins VALUES(?,?,?,?,?,?)", (
                    source, locator, digest, name, row[0], encoded))
                self.counts["origins_already_covered"] += 1
                self.source_counts["origins_already_covered"] += 1
                return
        row = self.db.execute("SELECT id,data FROM payloads WHERE sha256=?", (digest,)).fetchone()
        if row is None:
            cursor = self.db.execute("INSERT INTO payloads(sha256,data) VALUES(?,?)", (digest, data))
            payload_id = cursor.lastrowid
            self.counts["new_payloads"] += 1
            self.counts["new_bytes"] += len(data)
        else:
            if row[1] != data:
                raise ValueError("Hash igual com bytes divergentes no novo corpus")
            payload_id = row[0]
            self.counts["origins_duplicate_new"] += 1
        self.db.execute("INSERT INTO origins VALUES(?,?,?,?,?,?)", (payload_id, source, locator, field, 0, encoded))
        self.counts["new_corpus_origins"] += 1
        if self.counts["accepted_origins"] % 10000 == 0:
            self.db.commit()
            print(json.dumps({"event": "progress", "accepted_origins": self.counts["accepted_origins"],
                              "new_payloads": self.counts["new_payloads"]}), flush=True)

    def binary(self, stream: BinaryIO, source: str) -> None:
        index = 0
        while header := stream.read(4):
            offset = stream.tell() - len(header)
            locator = f"record:{index};offset:{offset}"
            if len(header) != 4:
                self.issue(source, locator, "truncated_binary_header", "Faltam bytes do comprimento uint32-LE")
                break
            size = struct.unpack("<I", header)[0]
            if not 1312 <= size <= 1327:
                self.issue(source, locator, "invalid_cosmic_record_length", f"Comprimento {size} fora do intervalo PKCS7")
                break
            data = stream.read(size)
            if len(data) != size:
                self.issue(source, locator, "truncated_binary_payload", f"Esperados {size}; presentes {len(data)}")
                break
            self.add(data, source, locator, "binary_record", {"blob": "COSMIC", "record_length": size,
                                                            "framing": "uint32le_length_then_bytes"})
            index += 1
        self.source_counts["binary_records"] = index
        self.source_counts["parsed_bytes"] = stream.tell()

    def bifid(self, stream: BinaryIO, source: str, blobs: dict[str, bytes]) -> None:
        for number, raw in enumerate(stream, 1):
            self.source_counts["lines"] += 1
            locator = f"line:{number}"
            if not raw.strip():
                self.source_counts["empty_lines"] += 1
                continue
            if not raw.endswith(b"\n"):
                self.issue(source, locator, "unterminated_line", "Linha final sem newline")
            try:
                item = json.loads(raw.decode("utf-8-sig"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                self.issue(source, locator, "invalid_jsonl", f"{type(error).__name__}: {error}")
                continue
            self.source_counts["parsed_json_lines"] += 1
            for record, where in objects(item, locator):
                if record.get("blob") not in blobs:
                    continue
                if not isinstance(record.get("pw"), str):
                    if "head" in record:
                        self.issue(source, where, "record_missing_password", "Registro de blob com prefixo mas sem senha textual")
                    continue
                self.source_counts["aes_records"] += 1
                try:
                    if record.get("kdf") not in KDFS:
                        raise ValueError("KDF fora das grafias SHA256 conhecidas")
                    if not isinstance(record.get("len"), int) or not isinstance(record.get("head"), str):
                        raise ValueError("Registro sem comprimento/prefixo verificável")
                    password = record["pw"].encode("utf-8")
                    plain = decrypt(password, blobs[record["blob"]])
                    prefix = record["head"].encode("latin-1")
                    if len(plain) != record["len"] or plain[:48] != prefix:
                        raise ValueError("Plaintext não reproduziu comprimento e prefixo exatos")
                    for key in ("plain_hex", "plaintext_hex", "plaintextHex", "pt_hex"):
                        if isinstance(record.get(key), str) and bytes.fromhex(record[key]) != plain:
                            raise ValueError("Plaintext divergiu do hex completo também preservado")
                except (ValueError, UnicodeError) as error:
                    self.issue(source, where, "regeneration_failed", str(error))
                    continue
                self.source_counts["aes_records_verified"] += 1
                self.add(plain, source, where, "regenerated_aes", {
                    "blob": record["blob"], "kdf": "EVP-SHA256", "password_encoding": "utf-8",
                    "password_sha256": hashlib.sha256(password).hexdigest(), "declared_length": record["len"],
                    "verified_prefix_bytes": len(prefix), "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                    "prefix_and_length_verified": True})

    def run(self) -> dict[str, Any]:
        all_sources = [("README.md", "reference"), (KIT, "reference"), (BIFID_SCRIPT, "reference"), *DATA_SOURCES]
        inventory = {name: stats(self.root / name) for name, _ in all_sources}
        refs = {}
        manifest_sources = []
        controls = {}
        blobs = {}
        for number, (source, kind) in enumerate(all_sources):
            self.source_counts = Counter()
            snapshot, metadata = self.snapshot(source, inventory[source], number)
            if kind == "reference":
                refs[source] = snapshot.read_text(encoding="utf-8-sig")
                if source == KIT:
                    blobs, controls = read_blobs(refs["README.md"], refs[KIT])
            else:
                with snapshot.open("rb") as stream:
                    if kind == "cosmic_binary":
                        self.binary(stream, source)
                    else:
                        self.bifid(stream, source, blobs)
            metadata["kind"] = kind
            metadata["counts"] = dict(self.source_counts)
            self.db.execute("INSERT INTO sources VALUES(?,?,?,?)", (
                source, metadata["snapshot_sha256"], metadata["snapshot_bytes"], json.dumps(metadata)))
            manifest_sources.append({"source": source, **metadata})
            self.db.commit()
            print(json.dumps({"event": "source_complete", "source": source,
                              "counts": metadata["counts"]}), flush=True)
        # Conferir cada hash e total por leitura independente do banco produzido.
        verified = Counter()
        for digest, data in self.db.execute("SELECT sha256,data FROM payloads"):
            assert hashlib.sha256(data).hexdigest() == digest
            verified["payloads"] += 1
            verified["bytes"] += len(data)
            verified["raw32_windows_forward"] += max(0, len(data) - 31)
        assert verified["payloads"] == self.counts["new_payloads"]
        assert verified["bytes"] == self.counts["new_bytes"]
        assert self.counts["accepted_origins"] == (self.counts["new_payloads"] +
            self.counts["origins_duplicate_new"] + self.counts["origins_already_covered"])
        assert self.db.execute("SELECT count(*) FROM origins").fetchone()[0] == self.counts["new_corpus_origins"]
        assert self.db.execute("SELECT count(*) FROM covered_origins").fetchone()[0] == self.counts["origins_already_covered"]
        assert self.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        for (name, path, connection), expected in zip(self.baselines, self.baseline_manifest):
            connection.close()
            if stats(path) != expected["stat"] or sha_file(path) != expected["sha256"]:
                raise ValueError(f"Banco anterior alterado durante recuperação: {name}")
        self.db.commit()
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.close()
        summary = {"version": VERSION, "started_utc": self.started, "finished_utc": now(),
                   "status": "ready_for_scanner", "scan_performed": False,
                   "script_sha256": self.code_sha256, "source_root": str(self.root),
                   "baseline_root": str(self.prior), "baseline_databases": self.baseline_manifest,
                   "sources": manifest_sources, "counts": dict(sorted(self.counts.items())),
                   "verified_output": dict(verified), "controls": controls,
                   "corpus_sha256": sha_file(self.out / "corpus.sqlite"),
                   "limits": ["Somente os quatro arquivos de dados nomeados e seus snapshots finitos.",
                              "Linhas JSON inválidas e registros incompletos são explícitos em issues.",
                              "A reprodução de senha usa UTF-8 e só é aceita se prefixo Latin-1 e comprimento conferem.",
                              "Padding validado reproduz registros históricos; não é prova de solução.",
                              "Nenhuma varredura de chaves executada por este programa."]}
        (self.out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"event": "ready_for_scanner", "counts": summary["counts"],
                          "verified_output": summary["verified_output"]}), flush=True)
        return summary


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="gsmg_recover_controls_") as temp:
        base = Path(temp)
        root, prior, out = base / "source", base / "prior", base / "out"
        root.mkdir()
        previously_covered = b"baseline-control" * 3
        for index, relative in enumerate(BASELINE_PATHS):
            path = prior / relative
            path.parent.mkdir(parents=True)
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE payloads(id INTEGER PRIMARY KEY,sha256 TEXT UNIQUE,data BLOB)")
            if index == 0:
                connection.execute("INSERT INTO payloads(sha256,data) VALUES(?,?)", (
                    hashlib.sha256(previously_covered).hexdigest(), previously_covered))
            connection.commit()
            connection.close()
        recovery = Recovery(root, prior, out)
        recovery.add(previously_covered, "prior", "record:0", "binary_record", {})
        assert recovery.counts["origins_already_covered"] == 1
        assert recovery.db.execute("SELECT count(*) FROM payloads").fetchone()[0] == 0
        full = bytes(range(256)) * 5 + bytes(range(47))
        assert len(full) == 1327
        recovery.add(full, "first", "record:0", "binary_record", {})
        recovery.add(full, "second", "record:0", "binary_record", {})
        assert recovery.counts["new_payloads"] == 1 and recovery.counts["origins_duplicate_new"] == 1
        import io
        recovery.source_counts = Counter()
        recovery.binary(io.BytesIO(struct.pack("<I", len(full)) + full + b"\x01\x00"), "binary")
        assert recovery.source_counts["binary_records"] == 1
        assert recovery.counts["issue:truncated_binary_header"] == 1
        password, salt = b"controle", b"12345678"
        material = previous = b""
        while len(material) < 48:
            previous = hashlib.sha256(previous + password + salt).digest()
            material += previous
        raw = b"Salted__" + salt + AES.new(material[:32], AES.MODE_CBC, material[32:48]).encrypt(full + b"\x01")
        record = {"blob": "COSMIC", "kdf": "EVP-SHA256", "pw": password.decode(),
                  "len": len(full), "head": full[:48].decode("latin-1")}
        damaged = {**record, "len": 1326}
        content = json.dumps({"nested": [record, damaged]}) + '\n{"broken":'
        recovery.bifid(io.BytesIO(content.encode()), "jsonl", {"COSMIC": raw})
        assert recovery.source_counts["aes_records_verified"] == 1
        assert recovery.counts["issue:regeneration_failed"] == 1
        assert recovery.counts["issue:invalid_jsonl"] == 1
        assert recovery.counts["new_payloads"] == 1
        recovery.db.close()
        for _, _, connection in recovery.baselines:
            connection.close()
    print(json.dumps({"self_test": "passed"}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--prior-campaign", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif None in (args.source_root, args.prior_campaign, args.out):
        parser.error("Informe --source-root, --prior-campaign e --out")
    else:
        Recovery(args.source_root, args.prior_campaign, args.out).run()


if __name__ == "__main__":
    main()
