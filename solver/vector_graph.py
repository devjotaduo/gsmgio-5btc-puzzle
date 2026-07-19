from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "solver" / "out" / "vector_graph"
DB_PATH = OUT_DIR / "index.sqlite"
GRAPH_PATH = OUT_DIR / "signal_graph.json"

DIM = 4096
CHUNK_SIZE = 1400
OVERLAP = 220

TEXT_EXTENSIONS = {".md", ".txt", ".json"}
IGNORE_DIRS = {".git", "__pycache__", ".puzzle_vector_index"}

TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]{2,}")
AES_RE = re.compile(r"U2FsdGVkX1[0-9A-Za-z+/=\s]{40,}")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
URL_RE = re.compile(r"https?://[^\s)>'\"]+|gsmg\.io/[a-zA-Z0-9/_\-.]+")
BTC_ADDR_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BASE9_RE = re.compile(r"\b[a-i]{40,}\b")

SIGNAL_TERMS = [
    "salphaseion",
    "cosmic duality",
    "cosmic",
    "duality",
    "dbbi",
    "faed",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "thispassword",
    "shabef",
    "ans too",
    "btcseed",
    "bifid",
    "vic",
    "straddling",
    "checkerboard",
    "polybius",
    "beaufort",
    "ebcdic",
    "1141",
    "prime",
    "zeroed",
    "architect",
    "choice",
    "oracle",
    "keymaker",
    "merovingian",
    "matrix",
    "alice",
    "cheshire",
    "heisenberg",
    "uncertainty",
    "nietzsche",
    "private key",
    "seed",
    "wallet",
    "wif",
    "bip39",
    "half and better half",
    "our first hint",
    "last command",
    "enter",
    "source code",
    "source codes",
]


@dataclass(frozen=True)
class Chunk:
    path: str
    ordinal: int
    kind: str
    signals: tuple[str, ...]
    text: str


def stable_hash(token: str) -> int:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "little") % DIM


def tokenize(text: str) -> list[str]:
    return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]


def vectorize(text: str) -> dict[int, float]:
    counts = Counter(stable_hash(tok) for tok in tokenize(text))
    if not counts:
        return {}
    norm = math.sqrt(sum(v * v for v in counts.values())) or 1.0
    return {idx: val / norm for idx, val in counts.items()}


def cosine(a: dict[int, float], b: dict[int, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(val * b.get(idx, 0.0) for idx, val in a.items())


def iter_files() -> Iterable[Path]:
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS:
            yield path


def message_text(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        parts: list[str] = []
        for item in raw:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("text", "")))
        return "".join(parts)
    return ""


def read_text(path: Path) -> str:
    if path.name == "result.json":
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        rows: list[str] = []
        for msg in data.get("messages", []):
            text = message_text(msg.get("text", "")).strip()
            if not text:
                continue
            author = msg.get("from", "desconhecido")
            date = msg.get("date", "sem-data")
            msg_id = msg.get("id", "sem-id")
            rows.append(f"[telegram id={msg_id} date={date} author={author}] {text}")
        return "\n".join(rows)
    return path.read_text(encoding="utf-8", errors="ignore")


def split_chunks(text: str) -> list[str]:
    text = text.replace("\r\n", "\n")
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + CHUNK_SIZE, len(text))
        if end < len(text):
            boundary = max(text.rfind("\n\n", start, end), text.rfind("\n", start, end))
            if boundary > start + CHUNK_SIZE // 2:
                end = boundary
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - OVERLAP, start + 1)
    return chunks


def detect_signals(text: str) -> tuple[str, ...]:
    lower = text.lower()
    signals = set()
    for term in SIGNAL_TERMS:
        if term in lower:
            signals.add(term.replace(" ", "_"))
    if AES_RE.search(text):
        signals.add("aes_blob")
    if HASH_RE.search(text):
        signals.add("hash")
    if URL_RE.search(text):
        signals.add("url")
    if BTC_ADDR_RE.search(text):
        signals.add("btc_address")
    if BASE9_RE.search(text):
        signals.add("base9_ai_string")
    return tuple(sorted(signals))


def detect_kind(text: str, signals: tuple[str, ...]) -> str:
    if "aes_blob" in signals:
        return "aes"
    if "base9_ai_string" in signals:
        return "base9"
    if "telegram" in text[:80].lower():
        return "telegram"
    if "btcseed" in signals or "bifid" in signals or "matrixsumlist" in signals:
        return "cryptanalysis"
    return "text"


def build_index() -> list[Chunk]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    chunks: list[Chunk] = []

    for path in sorted(iter_files()):
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        text = read_text(path)
        for ordinal, chunk_text in enumerate(split_chunks(text)):
            signals = detect_signals(chunk_text)
            chunks.append(
                Chunk(
                    path=rel,
                    ordinal=ordinal,
                    kind=detect_kind(chunk_text, signals),
                    signals=signals,
                    text=chunk_text,
                )
            )

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DROP TABLE IF EXISTS chunks")
        conn.execute("DROP TABLE IF EXISTS vectors")
        conn.execute(
            """
            CREATE TABLE chunks(
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                kind TEXT NOT NULL,
                signals TEXT NOT NULL,
                text TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE vectors(
                chunk_id INTEGER NOT NULL,
                dim INTEGER NOT NULL,
                value REAL NOT NULL,
                PRIMARY KEY(chunk_id, dim)
            )
            """
        )
        for chunk_id, chunk in enumerate(chunks, start=1):
            conn.execute(
                "INSERT INTO chunks(id, path, ordinal, kind, signals, text) VALUES (?, ?, ?, ?, ?, ?)",
                (chunk_id, chunk.path, chunk.ordinal, chunk.kind, ",".join(chunk.signals), chunk.text),
            )
            vec = vectorize(chunk.text)
            conn.executemany(
                "INSERT INTO vectors(chunk_id, dim, value) VALUES (?, ?, ?)",
                [(chunk_id, dim, val) for dim, val in vec.items()],
            )

    write_signal_graph(chunks)
    return chunks


def write_signal_graph(chunks: list[Chunk]) -> None:
    node_counts: Counter[str] = Counter()
    edge_counts: Counter[tuple[str, str]] = Counter()
    examples: dict[str, list[str]] = defaultdict(list)

    for chunk in chunks:
        signals = list(chunk.signals)
        for signal in signals:
            node_counts[signal] += 1
            if len(examples[signal]) < 5:
                examples[signal].append(f"{chunk.path}:{chunk.ordinal}")
        for i, left in enumerate(signals):
            for right in signals[i + 1 :]:
                edge_counts[tuple(sorted((left, right)))] += 1

    graph = {
        "nodes": [
            {"id": signal, "count": count, "examples": examples[signal]}
            for signal, count in node_counts.most_common()
        ],
        "edges": [
            {"source": left, "target": right, "weight": weight}
            for (left, right), weight in edge_counts.most_common()
        ],
    }
    GRAPH_PATH.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")


def load_chunks() -> list[Chunk]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT path, ordinal, kind, signals, text FROM chunks ORDER BY id"
        ).fetchall()
    return [
        Chunk(
            path=row[0],
            ordinal=row[1],
            kind=row[2],
            signals=tuple(s for s in row[3].split(",") if s),
            text=row[4],
        )
        for row in rows
    ]


def search(query: str, top_k: int) -> list[tuple[float, Chunk]]:
    chunks = load_chunks()
    qvec = vectorize(query)
    scored = [(cosine(qvec, vectorize(chunk.text)), chunk) for chunk in chunks]
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored[:top_k]


def print_search(query: str, top_k: int) -> None:
    print(f"# QUERY: {query}")
    for score, chunk in search(query, top_k):
        print("=" * 100)
        print(f"score={score:.4f} file={chunk.path}:{chunk.ordinal} kind={chunk.kind} signals={','.join(chunk.signals) or '-'}")
        print("-" * 100)
        preview = re.sub(r"\s+", " ", chunk.text).strip()
        print(preview[:1800])


def print_signals(limit: int) -> None:
    graph = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    print("# TOP SIGNALS")
    for node in graph["nodes"][:limit]:
        print(f"{node['id']}\t{node['count']}\t{', '.join(node['examples'])}")
    print("\n# TOP EDGES")
    for edge in graph["edges"][:limit]:
        print(f"{edge['source']} -- {edge['target']}\t{edge['weight']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Grafo vetorial textual do puzzle GSMG.IO")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("index")
    q = sub.add_parser("search")
    q.add_argument("query")
    q.add_argument("--top-k", type=int, default=10)
    s = sub.add_parser("signals")
    s.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    if args.cmd == "index":
        chunks = build_index()
        print(f"chunks={len(chunks)}")
        print(f"db={DB_PATH}")
        print(f"graph={GRAPH_PATH}")
    elif args.cmd == "search":
        print_search(args.query, args.top_k)
    elif args.cmd == "signals":
        print_signals(args.limit)


if __name__ == "__main__":
    main()
