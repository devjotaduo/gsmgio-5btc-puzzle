"""Confere corpus, união das partes e checkpoints; publica só totais sem chaves."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from oracle import TARGETS
from partition import readonly
from scan import file_sha256, save_json

RUNS = (
    ("a", "part_a.sqlite"),
    ("b", "part_b.sqlite"),
    ("c", "part_c.sqlite"),
    ("supplement", "corpus_supplement/corpus.sqlite"),
    ("partial", "corpus_partial/corpus.sqlite"),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def payloads(path: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with closing(readonly(path)) as con:
        for digest, data in con.execute("SELECT sha256,data FROM payloads"):
            require(hashlib.sha256(data).hexdigest() == digest, "Hash de payload inválido")
            require(digest not in result, "Payload duplicado dentro do corpus")
            result[digest] = data
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    campaign = args.campaign.resolve(strict=True)
    script = Path(__file__)
    code = {name: file_sha256(script.with_name(name)) for name in ("oracle.py", "scan.py")}
    observed_hashes: dict[Path, str] = {}

    def observe(path: Path) -> str:
        digest = file_sha256(path)
        require(path not in observed_hashes or observed_hashes[path] == digest, "Arquivo mudou")
        observed_hashes[path] = digest
        return digest

    def observed_json(path: Path) -> dict:
        observe(path)
        return read_json(path)

    full_path = campaign / "corpus_v3/corpus.sqlite"
    full_sha = observe(full_path)
    full = payloads(full_path)
    remaining = dict(full)
    union = dict(full)
    totals: Counter = Counter()
    attempts: Counter = Counter()
    runs = []
    for name, relative in RUNS:
        path = campaign / relative
        digest = observe(path)
        data_by_hash = payloads(path)
        scan_dir = campaign / f"scan_{name}"
        summary = observed_json(scan_dir / "summary.json")
        spec = observed_json(scan_dir / "spec.json")
        contract = spec["contract"]
        require(summary["status"] == "complete", f"Varredura {name} incompleta")
        require(summary["targets"] == contract["targets"] == list(TARGETS), "Alvos divergentes")
        require(summary["corpus_sha256"] == contract["corpus_sha256"] == digest, "Corpus divergente")
        for filename, key in (("oracle.py", "oracle_sha256"), ("scan.py", "scanner_sha256")):
            require(contract[key] == code[filename], "Código não corresponde à execução")
        expected = (len(data_by_hash), sum(map(len, data_by_hash.values())),
                    sum(max(0, len(data) - 31) for data in data_by_hash.values()))
        require(expected == (summary["payloads_scanned"], summary["bytes_scanned"],
                             summary["attempts"]["raw32"]), "Cobertura divergente")
        require(expected == (summary["total_payloads"], summary["total_bytes"],
                             summary["expected_raw32_windows"]), "Totais divergentes")
        checkpoint_path = scan_dir / "checkpoint.sqlite"
        observe(checkpoint_path)
        check_counts: Counter = Counter()
        check_attempts: Counter = Counter()
        with closing(readonly(checkpoint_path)) as con:
            for encoded, in con.execute("SELECT result FROM completed ORDER BY batch_id"):
                row = json.loads(encoded)
                check_counts.update({key: row[key] for key in ("payloads", "bytes", "valid_scalars")})
                check_counts["batches"] += 1
                check_counts["hits"] += len(row["hits"])
                check_attempts.update(row["attempts"])
        require(dict(check_attempts) == summary["attempts"], "Tentativas não conferem com checkpoint")
        for key, field in (("payloads", "payloads_scanned"), ("bytes", "bytes_scanned"),
                           ("valid_scalars", "valid_scalars"), ("batches", "completed_batches"),
                           ("hits", "hard_hits")):
            require(check_counts[key] == summary[field], f"Checkpoint divergente: {key}")
        overlap = 0
        for content_hash, data in data_by_hash.items():
            if name in ("a", "b", "c"):
                require(content_hash in remaining, "Partes principais sobrepostas ou fora do corpus")
                require(remaining.pop(content_hash) == data, "Bytes da partição divergem")
            elif content_hash in union:
                require(union[content_hash] == data, "Colisão de conteúdo")
                overlap += 1
            else:
                union[content_hash] = data
        attempts.update(summary["attempts"])
        totals.update({key: summary[key] for key in ("payloads_scanned", "bytes_scanned", "valid_scalars", "hard_hits")})
        runs.append({"name": name, "corpus_sha256": digest, "payloads": expected[0],
                     "bytes": expected[1], "attempts": summary["attempts"],
                     "hard_hits": summary["hard_hits"], "supplement_overlap": overlap})
    require(not remaining, "A união das partes não cobre o corpus principal")
    controls = observed_json(campaign / "controls_codecs.json")
    require(controls["passed"] and controls["oracle_sha256"] == code["oracle.py"], "Controles divergentes")
    kit = args.source_root / "solver/experiments/claude_endgame_2026_09_02/gsmg_common.py"
    require(observe(kit) == controls["kit_sha256"], "Kit original foi alterado")
    explicit = observed_json(campaign / "explicit_hex_audit.json")
    require(explicit["corpus_sha256"] == full_sha, "Auditoria explícita pertence a outro corpus")
    require(explicit["passed_within_scope"] and not explicit["missing"]
            and not explicit["unverifiable_sources"], "Auditoria explícita incompleta")
    manifest = observed_json(campaign / "corpus_v3/manifest.json")
    require(manifest["counts"]["unique_payloads"] == len(full), "Manifesto divergente")
    for path, digest in observed_hashes.items():
        require(file_sha256(path) == digest, f"Evidência mudou durante conferência: {path.name}")
    for filename, digest in code.items():
        require(file_sha256(script.with_name(filename)) == digest, "Código mudou durante conferência")
    result = {
        "status": "complete", "targets": list(TARGETS),
        "second_target_prize_status": "unconfirmed",
        "main_corpus_sha256": full_sha, "main_payloads": len(full),
        "unique_payloads_union": len(union), "unique_bytes_union": sum(map(len, union.values())),
        "attempts": dict(attempts), "totals_across_runs": dict(totals), "runs": runs,
        "main_partition_exact_disjoint_union": True,
        "snapshot_started_utc": manifest["started_utc"], "snapshot_finished_utc": manifest["finished_utc"],
        "main_collection_counts": manifest["counts"], "code_sha256": code,
        "finalizer_sha256": file_sha256(script),
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "limits": manifest["limits"] + [
            "Tentativas não são escalares distintos; cada escalar válido testa ambas as serializações.",
            "Não reexecuta hipóteses históricas nem recupera candidatos descartados sem bytes salvos.",
            "O complemento parcial cobre 789 bytes, não os 538 bytes ausentes da cauda.",
        ],
    }
    save_json(campaign / "summary.json", result)
    save_json(campaign / "final_qa.json", {
        "passed": True, "exact_union_and_byte_comparison": True,
        "checkpoint_totals_reconciled": True, "observed_files_unchanged": len(observed_hashes),
        "original_kit_unchanged": True, "oracle_controls": controls,
        "explicit_hex_audit": explicit, "main_corpus_sha256": full_sha,
        "finalizer_sha256": result["finalizer_sha256"],
    })
    print(json.dumps({key: result[key] for key in ("status", "unique_payloads_union", "unique_bytes_union", "attempts", "totals_across_runs")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
