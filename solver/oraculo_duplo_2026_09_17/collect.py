"""Coleta auditável de plaintexts históricos; não executa tentativas de decifração.

Hipótese finita: um dos plaintexts/prefixos preservados contém uma chave que o
oráculo antigo não reconheceu. Este módulo apenas fixa esse corpus para o scanner.
O corpus de origem é somente leitura. Campos sem evidência de plaintext não são
promovidos a plaintext; exclusões, ambiguidades e erros ficam no manifesto/SQLite.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any, BinaryIO
import zlib


VERSION = 5
EXCLUDED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "archive",
                 "gsmg_live_2026-09", "oraculo_duplo_2026_09_17"}
HEX_FIELDS = {"plainhex", "plaintexthex", "pthex", "phex"}
PREFIX_HEX_FIELDS = {"headhex", "hex128", "prefixhex", "plaintextheadhex", "ptheadhex"}
TEXT_FIELDS = {"plain", "plaintext", "pt", "head", "text", "plainrepr", "plaintextrepr"}
CONTEXT_FIELDS = {"blob", "kdf", "printable", "digest", "cipher", "ciphertext"}
NON_PLAINTEXT_CONTAINERS = {"materials", "material", "passwords", "password", "keys",
                            "key", "pw", "candidates", "inputs", "input"}
SOFT_CONTAINERS = {"soft", "softhits", "padding", "paddings", "aeshits", "aes", "decryptions"}
HEX_RE = re.compile(r"[0-9a-fA-F]+\Z")
LOG_HEX_RE = re.compile(
    r"(?i)\b(plain_?hex|plaintext_?hex|pt_?hex|p_hex|head_?hex|prefix_?hex|hex128)"
    r"[\"']?\s*[:=]\s*[\"']?([0-9a-f]+)\b"
)
SIGNAL_RE = re.compile(r"(?i)\bplain(?:text)?\b|plain_hex|pt_hex|head_hex|hex128|padding")


def normalized(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def input_file_hint(source: str) -> bool:
    """Material/senha não vira plaintext apenas por ter hex e comprimento."""
    return bool(re.search(r"(?i)(material|password|(?:^|[_\W])keys?(?:[_\W]|$))", Path(source).name))


def stat_metadata(stat: os.stat_result) -> dict[str, int]:
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "inode": stat.st_ino}


class Collector:
    """Inventário finito, extração conservadora e proveniência de cada representação."""

    def __init__(self, source_root: Path, out: Path) -> None:
        self.code_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.root = source_root.resolve(strict=True)
        self.out = out.resolve()
        if self.out == self.root or self.root.is_relative_to(self.out):
            raise ValueError("Saída não pode ser a raiz de origem nem um ancestral dela")
        self.out.mkdir(parents=True, exist_ok=False)
        self.db = sqlite3.connect(self.out / "corpus.sqlite")
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE payloads(id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, data BLOB);
            CREATE TABLE origins(payload_id INTEGER, source TEXT, locator TEXT,
                field TEXT, truncated INTEGER, metadata TEXT);
            CREATE TABLE sources(path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER, metadata TEXT);
            CREATE TABLE issues(source TEXT, locator TEXT, kind TEXT, message TEXT);
            CREATE TABLE excluded_fields(source TEXT, locator TEXT, field TEXT, reason TEXT);
            CREATE INDEX origins_payload ON origins(payload_id);
            CREATE INDEX issues_kind ON issues(kind);
        """)
        self.counts: Counter[str] = Counter()
        self.fields: Counter[str] = Counter()
        self.exclusions: Counter[str] = Counter()
        self.started = utc_now()
        self.source_counts: Counter[str] = Counter()

    def issue(self, source: str, locator: str, kind: str, message: str) -> None:
        self.counts[f"issue:{kind}"] += 1
        self.source_counts[f"issue:{kind}"] += 1
        self.db.execute("INSERT INTO issues VALUES(?,?,?,?)", (source, locator, kind, message[:1000]))

    def add(self, data: bytes, source: str, locator: str, field: str,
            truncated: bool, metadata: dict[str, Any]) -> None:
        if not data:
            self.counts["empty_representations"] += 1
            return
        digest = hashlib.sha256(data).hexdigest()
        row = self.db.execute("SELECT id,data FROM payloads WHERE sha256=?", (digest,)).fetchone()
        if row is None:
            cursor = self.db.execute("INSERT INTO payloads(sha256,data) VALUES(?,?)", (digest, data))
            payload_id = cursor.lastrowid
            self.counts["unique_payloads"] += 1
            self.counts["unique_bytes"] += len(data)
        else:
            payload_id, previous = row
            if previous != data:
                raise RuntimeError("Colisão SHA256: bytes diferentes; interrompido")
            self.counts["duplicate_representations"] += 1
        self.db.execute("INSERT INTO origins VALUES(?,?,?,?,?,?)", (
            payload_id, source, locator, field, int(truncated), json.dumps(metadata, ensure_ascii=True)))
        self.counts["origins"] += 1
        self.counts["prefix_origins" if truncated else "nonprefix_origins"] += 1
        self.source_counts["origins"] += 1
        self.fields[field] += 1

    def exclude_field(self, source: str, locator: str, field: str, reason: str) -> None:
        self.counts[f"excluded_field:{reason}"] += 1
        self.source_counts[f"excluded_field:{reason}"] += 1
        self.db.execute("INSERT INTO excluded_fields VALUES(?,?,?,?)", (source, locator, field, reason))

    def truncation(self, obj: dict[str, Any], field: str, data: bytes) -> tuple[bool, dict[str, Any]]:
        lower = {normalized(k): v for k, v in obj.items()}
        reasons = []
        if normalized(field) in PREFIX_HEX_FIELDS or normalized(field) == "head":
            reasons.append("campo_de_prefixo")
        if any(lower.get(k) is True for k in ("trunc", "truncated", "partial")):
            reasons.append("truncamento_declarado")
        declared = next((lower[k] for k in ("plainlen", "plaintextlen", "ptlen", "len", "length")
                         if isinstance(lower.get(k), int) and not isinstance(lower[k], bool)), None)
        if declared is not None and declared > len(data):
            reasons.append("menor_que_comprimento_declarado")
        # Alguns scripts chamaram de plain_hex um slice de 96 B sem trunc:true.
        blob = str(lower.get("blob", "")).upper()
        if blob in {"COSMIC", "SMALL", "TAIL32"}:
            minimum = 1312 if blob == "COSMIC" else 64
            if len(data) < minimum:
                reasons.append("menor_que_plaintext_do_blob_padrao")
        return bool(reasons), {"truncation_reasons": reasons, "declared_length": declared,
                               "blob": lower.get("blob"), "representation_bytes": len(data)}

    def walk(self, obj: Any, source: str, locator: str = "$", *,
             parent_key: str = "", inherited_aes: bool = False,
             blocked: bool = False) -> None:
        if isinstance(obj, list):
            for index, value in enumerate(obj):
                self.walk(value, source, f"{locator}[{index}]", parent_key=parent_key,
                          inherited_aes=inherited_aes, blocked=blocked)
            return
        if not isinstance(obj, dict):
            return
        obj = {str(k): v for k, v in obj.items()}
        keys = {normalized(k) for k in obj}
        direct_aes = bool(keys & CONTEXT_FIELDS)
        direct_cipher = bool(keys & (CONTEXT_FIELDS - {"printable"}))
        context = direct_aes or inherited_aes or parent_key in SOFT_CONTAINERS
        # A indicação direta de cifra vence o nome genérico do contêiner.
        eligible = context and (not blocked or direct_cipher)
        full_hex: list[bytes] = []
        for field, value in obj.items():
            key = normalized(field)
            explicit = key in HEX_FIELDS or key in (PREFIX_HEX_FIELDS - {"prefixhex"})
            generic = key in {"hex", "prefixhex"} and eligible
            if key in {"hex", "prefixhex"} and not generic and value is not None:
                self.exclude_field(source, locator, field, "generic_hex_without_plaintext_context")
            if not (explicit or generic) or value is None:
                continue
            if not isinstance(value, str) or not value or len(value) % 2 or not HEX_RE.fullmatch(value):
                self.issue(source, f"{locator}.{field}", "invalid_hex", "Campo candidato não é hex par não vazio")
                continue
            data = bytes.fromhex(value)
            truncated, metadata = self.truncation(obj, field, data)
            metadata["representation"] = "hex_exato"
            self.add(data, source, locator, field, truncated, metadata)
            if not truncated:
                full_hex.append(data)
        for field, value in obj.items():
            key = normalized(field)
            if key in TEXT_FIELDS and isinstance(value, (str, bytes)):
                data, representation, uncertain = ((value, "python_bytes_exato", False)
                                                    if isinstance(value, bytes) else self.text_bytes(value))
                if full_hex and any(complete.startswith(data) for complete in full_hex):
                    self.counts["text_skipped_full_hex_present"] += 1
                elif key in {"plaintext", "plaintextrepr", "plainrepr"} or eligible or (
                        key in {"plain", "pt"} and not blocked):
                    truncated, metadata = self.truncation(obj, field, data)
                    metadata["representation"] = representation
                    if uncertain:
                        metadata["truncation_reasons"].append("representacao_textual_nao_reversivel_ou_ambigua")
                    self.add(data, source, locator, field, truncated or uncertain, metadata)
                    # Há produtores históricos com pt:pt.hex() e head:p[:48].hex().
                    # Conservar literal e decodificado evita escolher uma sem prova.
                    if isinstance(value, str) and len(value) % 2 == 0 and HEX_RE.fullmatch(value):
                        decoded = bytes.fromhex(value)
                        _, alternative = self.truncation(obj, field, decoded)
                        alternative["representation"] = "interpretacao_hex_ambigua_de_campo_textual"
                        alternative["truncation_reasons"].append("interpretacao_ambigua")
                        self.add(decoded, source, locator, field + ":hex_interpretation", True, alternative)
                else:
                    self.exclude_field(source, locator, field, "text_without_plaintext_context")
            if isinstance(value, (dict, list)):
                child_blocked = key in NON_PLAINTEXT_CONTAINERS or (blocked and not direct_aes)
                self.walk(value, source, f"{locator}.{field}", parent_key=key,
                          inherited_aes=eligible, blocked=child_blocked)

    @staticmethod
    def text_bytes(value: str) -> tuple[bytes, str, bool]:
        if value.startswith(("b'", 'b"')):
            try:
                literal = ast.literal_eval(value)
                if isinstance(literal, bytes):
                    return literal, "python_bytes_repr_exato", False
            except (SyntaxError, ValueError):
                pass
        # O kit registra p.decode('latin-1'). Unicode fora de Latin-1 não tem
        # reconstrução única; UTF-8 preserva a representação e tokens ASCII.
        try:
            return value.encode("latin-1"), "latin1_assumido", True
        except UnicodeEncodeError:
            return value.encode("utf-8", errors="surrogatepass"), "utf8_da_representacao", True

    def log_line(self, line: str, source: str, locator: str) -> None:
        before = self.source_counts["origins"]
        # Objetos JSON/Python completos podem ter um prefixo de timestamp/status.
        consumed_until = 0
        for opening in re.finditer(r"[\[{]", line):
            start = opening.start()
            if start < consumed_until:
                continue
            try:
                obj, end = json.JSONDecoder().raw_decode(line[start:])
                consumed_until = start + end
            except json.JSONDecodeError:
                try:
                    obj = ast.literal_eval(line[start:])
                    consumed_until = len(line)
                except (SyntaxError, ValueError):
                    obj = None
            if isinstance(obj, (dict, list)):
                self.walk(obj, source, locator, blocked=input_file_hint(source))
                if self.source_counts["origins"] > before:
                    break
        if self.source_counts["origins"] == before:
            for match in LOG_HEX_RE.finditer(line):
                self.walk({match[1]: match[2]}, source, f"{locator}:col{match.start()}")
        if self.source_counts["origins"] == before and SIGNAL_RE.search(line):
            self.issue(source, locator, "unparsed_plaintext_signal", line[:300])
        self.counts["log_lines"] += 1

    def parse_lines(self, stream: BinaryIO, source: str, jsonl: bool) -> None:
        pending: list[str] = []
        pending_start = 0
        pending_bytes = 0
        depth = 0
        quote = ""
        escaped = False
        for number, raw in enumerate(stream, 1):
            self.counts["lines"] += 1
            locator = f"line:{number}"
            if not raw.strip():
                continue
            try:
                line = raw.decode("utf-8-sig")
            except UnicodeDecodeError as error:
                self.issue(source, locator, "decode_error", str(error))
                line = raw.decode("latin-1")
            if jsonl:
                try:
                    self.walk(json.loads(line), source, locator, blocked=input_file_hint(source))
                except json.JSONDecodeError as error:
                    self.issue(source, locator, "jsonl_parse_error", str(error))
                    self.log_line(line, source, locator)
                if not raw.endswith(b"\n"):
                    self.issue(source, locator, "unterminated_final_line", "Última linha não termina em newline")
            else:
                # Blocos JSON pretty-printed em .out/.log mantêm contexto de
                # blob/kdf ao redor do campo genérico hex, inclusive arrays.
                stripped = line.lstrip()
                if pending or stripped.startswith(("{", "[")):
                    if not pending:
                        pending_start = number
                    pending.append(line)
                    pending_bytes += len(raw)
                    for char in line:
                        if quote:
                            if escaped:
                                escaped = False
                            elif char == "\\":
                                escaped = True
                            elif char == quote:
                                quote = ""
                        elif char in "\"'":
                            quote = char
                        elif char in "[{":
                            depth += 1
                        elif char in "]}":
                            depth -= 1
                    if depth <= 0 or pending_bytes > 32 * 1024 * 1024:
                        if pending_bytes > 32 * 1024 * 1024:
                            self.issue(source, locator, "log_frame_limit", "Bloco incompleto >32MiB; extração por linhas")
                            for offset, saved in enumerate(pending):
                                self.log_line(saved, source, f"line:{pending_start + offset}")
                        else:
                            self.log_line("".join(pending), source, f"lines:{pending_start}-{number}")
                        pending, pending_bytes, depth, quote, escaped = [], 0, 0, "", False
                else:
                    self.log_line(line, source, locator)
        if pending:
            self.issue(source, f"line:{pending_start}", "incomplete_log_frame", "Bloco JSON/literal não terminou")
            for offset, saved in enumerate(pending):
                self.log_line(saved, source, f"line:{pending_start + offset}")

    def classify(self, path: Path) -> tuple[str | None, str]:
        name = path.name.lower()
        if (name == "result.json" or name.startswith(("chatexport", "tg_", "creator_msgs"))
                or ("telegram" in name and name != "telegram_miner.jsonl")):
            return None, "export_telegram"
        if name.endswith(".gz"):
            name = name[:-3]
        if name.endswith((".jsonl", ".ndjson")):
            return "jsonl", ""
        if name.endswith(".json"):
            return "json", ""
        if name.endswith((".log", ".out", ".txt")):
            return "log", ""
        if name.endswith(".bin") and ("plaintext" in name or re.search(r"(^|_)plain(_|\.)", name)):
            return "binary", ""
        return None, "extensao_fora_do_escopo"

    def inventory(self, only_files: list[Path] | None = None) -> list[tuple[Path, dict[str, Any], str | None]]:
        files = []
        if only_files:
            # Complemento explícito mantém fonte/proveniência originais sem
            # reiniciar toda coleta nem copiar o corpus para uma raiz artificial.
            resolved = sorted({(self.root / path).resolve(strict=True) for path in only_files})
            for path in resolved:
                if not path.is_relative_to(self.root) or not path.is_file():
                    raise ValueError(f"--only-file precisa ser arquivo sob source-root: {path}")
                stat = path.stat()
                kind, reason = self.classify(path)
                metadata = {"inventory": stat_metadata(stat), "kind": kind,
                            "status": "pending" if kind else "excluded", "reason": reason}
                files.append((path, metadata, kind))
                self.counts["inventory_files"] += 1
                self.counts["inventory_bytes"] += stat.st_size
                if kind is None:
                    self.exclusions[reason] += 1
            return files
        for base in (self.root / "_work", self.root / "solver"):
            if not base.is_dir():
                self.issue(str(base), "$", "missing_scope_directory", "Diretório de escopo não existe")
                continue
            def walk_error(error: OSError) -> None:
                self.issue(str(error.filename), "$", "inventory_error", str(error))
            for directory, subdirs, names in os.walk(base, followlinks=False, onerror=walk_error):
                retained = []
                for name in sorted(subdirs):
                    path = Path(directory) / name
                    excluded = (name.lower() in EXCLUDED_DIRS or name.lower().startswith(("chatexport", "telegram"))
                                or path.is_symlink() or path.resolve() == self.out
                                or "oraculo_duplo" in name.lower())
                    if excluded:
                        self.exclusions["directory_pruned"] += 1
                        self.db.execute("INSERT INTO sources VALUES(?,?,?,?)", (
                            path.relative_to(self.root).as_posix() + "/", None, None,
                            json.dumps({"status": "excluded_directory", "reason": "policy_or_symlink"})))
                    else:
                        retained.append(name)
                subdirs[:] = retained
                for name in sorted(names):
                    path = Path(directory) / name
                    source = path.relative_to(self.root).as_posix()
                    try:
                        stat = path.lstat()
                    except OSError as error:
                        self.issue(source, "$", "stat_error", str(error))
                        continue
                    kind, reason = self.classify(path)
                    if path.is_symlink():
                        kind, reason = None, "symlink"
                    metadata: dict[str, Any] = {"inventory": stat_metadata(stat), "kind": kind,
                                                "status": "pending" if kind else "excluded", "reason": reason}
                    files.append((path, metadata, kind))
                    self.counts["inventory_files"] += 1
                    self.counts["inventory_bytes"] += stat.st_size
                    if kind is None:
                        self.exclusions[reason] += 1
        return sorted(files, key=lambda item: str(item[0]).lower())

    def decompress_snapshot(self, snapshot: BinaryIO, target: BinaryIO,
                            source: str) -> dict[str, Any]:
        """Preserva output antes de trailer truncado e aceita membros concatenados."""
        decoder = zlib.decompressobj(31)
        members = 0
        failed = False
        while compressed := snapshot.read(1024 * 1024):
            pending = compressed
            while pending:
                if decoder is None:
                    pending = pending.lstrip(b"\0")  # padding permitido depois do membro
                    if not pending:
                        break
                    decoder = zlib.decompressobj(31)
                try:
                    target.write(decoder.decompress(pending))
                except zlib.error as error:
                    self.issue(source, "$", "gzip_decode_error", str(error))
                    failed = True
                    break
                if decoder.eof:
                    members += 1
                    pending = decoder.unused_data
                    decoder = None
                else:
                    pending = b""
            if failed:
                break
        complete = not failed and decoder is None and members > 0
        if not complete and not failed:
            self.issue(source, "$", "gzip_incomplete", "Fim do snapshot antes do trailer; corpo disponível preservado")
        metadata = {"complete": complete, "members": members, "decompressed_bytes": target.tell()}
        target.seek(0)
        return metadata

    def process(self, path: Path, metadata: dict[str, Any], kind: str | None) -> None:
        source = path.relative_to(self.root).as_posix()
        size = metadata["inventory"]["size"]
        digest = None
        self.source_counts = Counter()
        if kind is not None:
            try:
                # Cópia limitada ao tamanho do inventário: arquivos ativos nunca
                # prolongam o universo. Hash refere-se exatamente aos bytes copiados.
                with tempfile.TemporaryFile(dir=self.out) as snapshot, path.open("rb") as original:
                    metadata["read_start"] = stat_metadata(os.fstat(original.fileno()))
                    hasher = hashlib.sha256()
                    copied = 0
                    while copied < size:
                        block = original.read(min(1024 * 1024, size - copied))
                        if not block:
                            break
                        snapshot.write(block)
                        hasher.update(block)
                        copied += len(block)
                    metadata["read_end"] = stat_metadata(os.fstat(original.fileno()))
                    metadata["snapshot_bytes"] = copied
                    self.counts["snapshot_bytes"] += copied
                    digest = hasher.hexdigest()
                    if copied != size:
                        self.issue(source, "$", "short_snapshot", f"Esperados {size}, copiados {copied}")
                    metadata["changed_since_inventory"] = (
                        metadata["inventory"] != metadata["read_start"]
                        or metadata["read_start"] != metadata["read_end"])
                    if metadata["changed_since_inventory"]:
                        self.issue(source, "$", "source_changed", "Tamanho/mtime/inode mudou após inventário")
                    snapshot.seek(0)
                    stream = tempfile.TemporaryFile(dir=self.out) if path.suffix.lower() == ".gz" else snapshot
                    try:
                        if stream is not snapshot:
                            metadata["gzip"] = self.decompress_snapshot(snapshot, stream, source)
                        if kind == "binary":
                            self.add(stream.read(), source, "$", "binary_file", False,
                                     {"representation": "arquivo_binario_exato"})
                        elif kind == "json":
                            try:
                                obj = json.load(stream)
                                self.walk(obj, source, blocked=input_file_hint(source))
                            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                                self.issue(source, "$", "json_parse_error", str(error))
                                stream.seek(0)
                                self.parse_lines(stream, source, jsonl=False)
                        else:
                            self.parse_lines(stream, source, jsonl=kind == "jsonl")
                    finally:
                        if stream is not snapshot:
                            stream.close()
                metadata["status"] = "processed"
            except (OSError, EOFError, ValueError, RecursionError, zlib.error) as error:
                # Falhas são preservadas e tornam a cobertura explicitamente parcial.
                self.issue(source, "$", "source_error", f"{type(error).__name__}: {error}")
                metadata["status"] = "error"
            metadata["counts"] = dict(self.source_counts)
            self.counts["processed_sources"] += 1
        self.db.execute("INSERT INTO sources VALUES(?,?,?,?)", (
            source, digest, size, json.dumps(metadata, ensure_ascii=True)))
        self.db.commit()

    def run(self, only_files: list[Path] | None = None) -> dict[str, Any]:
        files = self.inventory(only_files)
        selected = sum(kind is not None for _, _, kind in files)
        print(json.dumps({"event": "inventory", "files": len(files), "selected": selected}), flush=True)
        for index, (path, metadata, kind) in enumerate(files, 1):
            self.process(path, metadata, kind)
            if index % 100 == 0:
                print(json.dumps({"event": "progress", "files": index, "total": len(files),
                                  "payloads": self.counts["unique_payloads"]}), flush=True)
        manifest = {"version": VERSION, "started_utc": self.started, "finished_utc": utc_now(),
                    "source_root": str(self.root), "database": "corpus.sqlite",
                    "script_sha256": self.code_sha256,
                    "counts": dict(sorted(self.counts.items())),
                    "fields": dict(sorted(self.fields.items())),
                    "exclusions": dict(sorted(self.exclusions.items())),
                    "scope": ([path.relative_to(self.root).as_posix() for path, _, _ in files]
                              if only_files else ["_work", "solver"]),
                    "limits": [
                        "Somente arquivos existentes no inventário; inclusões/escritas posteriores não são cobertas.",
                        "SHA256 de sources refere-se aos bytes do snapshot limitado ao tamanho inventariado.",
                        "Arquivos alterados durante cópia são sinalizados; snapshot não promete atomicidade do escritor.",
                        "Prefixos e representações textuais ambíguas são marcados truncated=1; caudas ausentes não são cobertas.",
                        "Não se inferem plaintexts a partir de senhas, hashes, ciphertexts ou materiais.",
                        "Logs sem campos reconhecidos ficam em issues quando apresentam sinal de plaintext.",
                        "Exclusões por diretório não enumeram os descendentes; arquivos excluídos não são lidos nem hasheados.",
                        "Não inclui plaintexts nunca preservados nem reconstrói bytes perdidos em representações textuais.",
                    ]}
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.close()
        (self.out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"event": "complete", "counts": manifest["counts"]}), flush=True)
        return manifest


def self_test() -> None:
    """Controles de extração: positivos, negativos e corpus danificado/partido."""
    with tempfile.TemporaryDirectory(prefix="gsmg_collect_controls_") as temp:
        base = Path(temp)
        source = base / "source"
        work = source / "_work"
        work.mkdir(parents=True)
        (source / "solver").mkdir()
        complete = bytes(range(79))
        prefix = bytes(range(64))
        records = [
            {"blob": "SMALL", "plaintextHex": complete.hex(), "head": complete[:20].decode("latin-1")},
            {"blob": "SMALL", "plaintextHex": complete.hex(), "plaintext": "texto_distinto"},
            {"soft": {"hex": complete.hex(), "len": 79}},
            {"materials": [{"hex": "ff" * 32, "len": 32}], "passwordHex": "ee" * 32},
            {"blob": "COSMIC", "hex": prefix.hex(), "len": 1327, "trunc": True},
            {"blob": "COSMIC", "plain_hex": (b"q" * 96).hex()},
            {"blob": "SMALL", "head": "abc", "head_hex": "616263"},
            {"hex": "dd" * 32},
            {"hex": "cc" * 32, "len": 32},
            {"terminal": [{"mask": "", "status": "excluded", "prefixHex": "21380d6646", "reason": "ERR__ERROR_FORMAT_PADDING_1"}]},
            {"blob": "SMALL", "pt": (b"p" * 79).hex()},
            {"blob": "COSMIC", "head": (b"h" * 48).hex()},
        ]
        (work / "records.json").write_text(json.dumps(records), encoding="utf-8")
        (work / "records.jsonl").write_text(json.dumps({"pt_hex": complete.hex()}) + '\n{"plain_hex":', encoding="utf-8")
        with gzip.open(work / "records.jsonl.gz", "wt", encoding="utf-8") as stream:
            stream.write(json.dumps({"hex128": prefix.hex(), "len": 1327}) + "\n")
        compressed = gzip.compress((json.dumps({"plain_hex": "aa" * 40}) + "\n").encode())
        (work / "broken.jsonl.gz").write_bytes(compressed[:-6])
        (work / "broken.json.gz").write_bytes(gzip.compress(json.dumps({"plain_hex": "bb" * 40}).encode())[:-6])
        (work / "joined.jsonl.gz").write_bytes(gzip.compress((json.dumps({"plain_hex": "aa" * 40}) + "\n").encode()) + gzip.compress((json.dumps({"plain_hex": "bb" * 40}) + "\n").encode()))
        (work / "plaintext.bin").write_bytes(complete)
        (work / "flags.bin").write_bytes(b"excluded")
        (work / "run.log").write_text("status ok\nplain_hex=" + complete.hex() + "\n", encoding="utf-8")
        (work / "pretty.out").write_text(json.dumps({"blob": "SMALL", "hex": complete.hex()}, indent=2), encoding="utf-8")
        (work / "prefix.out").write_text('"head_hex": "616263"\n', encoding="utf-8")
        (work / "tagged.log").write_text('[timestamp] ' + json.dumps({"blob": "SMALL", "hex": complete.hex()}) + '\n', encoding="utf-8")
        (work / "numeric_tag.log").write_text('[123] ' + json.dumps({"blob": "SMALL", "hex": complete.hex()}) + '\n', encoding="utf-8")
        (work / "input_only.log").write_text(json.dumps({"passwords": [{"pt": "PRIVATE_MATERIAL_ONLY"}]}) + '\n', encoding="utf-8")
        (work / "telegram_miner.jsonl").write_text(json.dumps({"soft": {"blob": "SMALL", "head": "head_preservado"}}) + '\n', encoding="utf-8")
        collector = Collector(source, base / "out")
        manifest = collector.run()
        db = sqlite3.connect(base / "out" / "corpus.sqlite")
        contents = {bytes(row[0]) for row in db.execute("SELECT data FROM payloads")}
        assert complete in contents and prefix in contents and b"abc" in contents
        assert b"texto_distinto" in contents
        assert b"PRIVATE_MATERIAL_ONLY" not in contents
        assert b"p" * 79 in contents and b"h" * 48 in contents and b"\xbb" * 40 in contents
        assert not ({b"\xff" * 32, b"\xee" * 32, b"\xdd" * 32, b"\xcc" * 32,
                     bytes.fromhex("21380d6646"), b"excluded"} & contents)
        assert db.execute("SELECT count(*) FROM origins WHERE field='hex128' AND truncated=1").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM origins WHERE field='plain_hex' AND truncated=1").fetchone()[0] == 1
        assert manifest["counts"]["issue:jsonl_parse_error"] == 1
        assert manifest["counts"]["issue:gzip_incomplete"] == 2
        assert not manifest["counts"].get("issue:source_error")
        assert db.execute("SELECT count(*) FROM excluded_fields WHERE field='prefixHex'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM origins WHERE source='_work/pretty.out'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM origins WHERE source='_work/prefix.out'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM origins WHERE source='_work/tagged.log'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM origins WHERE source='_work/numeric_tag.log'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM origins WHERE source='_work/telegram_miner.jsonl'").fetchone()[0] == 1
        assert manifest["script_sha256"] == collector.code_sha256
        assert not db.execute("SELECT count(*) FROM sources WHERE sha256 IS NULL AND json_extract(metadata,'$.status')='processed'").fetchone()[0]
        db.close()
        supplement = Collector(source, base / "only")
        only_manifest = supplement.run([Path("_work/telegram_miner.jsonl")])
        assert only_manifest["scope"] == ["_work/telegram_miner.jsonl"]
        assert only_manifest["counts"]["inventory_files"] == 1
        assert only_manifest["counts"]["origins"] == 1
        assert supplement.classify(Path("telegram_export.json"))[0] is None
        print(json.dumps({"self_test": "OK", "payloads": len(contents)}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--out", type=Path, help="Diretório novo, obrigatório não existir")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--only-file", type=Path, action="append",
                        help="Coletar somente este arquivo sob source-root; repetível")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.source_root is None or args.out is None:
        parser.error("Informe --source-root e --out, ou --self-test")
    else:
        Collector(args.source_root, args.out).run(args.only_file)


if __name__ == "__main__":
    main()
