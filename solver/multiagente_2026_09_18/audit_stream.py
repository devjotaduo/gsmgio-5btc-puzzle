"""Reprodução pequena do filtro STREAM histórico, sem varredura de senhas reais."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

from Crypto.Cipher import AES
from coincurve import PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "solver/oraculo_duplo_2026_09_17"))
from oracle import Oracle, independent_address

MODES = ("aes-256-cfb", "aes-256-ofb", "aes-256-ctr", "chacha20")


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encrypt(module, mode: str, password: bytes, salt: bytes, plain: bytes, digest: str) -> bytes:
    material = module.evp48(password, salt, getattr(hashlib, digest))
    key, iv = material[:32], material[32:48]
    if mode == "aes-256-cfb":
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(plain)
    # Os demais modos usam o mesmo XOR tanto para cifrar quanto para decifrar.
    return module.CIPHERS[mode][4][1](key, iv, plain)


def historical_result(module, mode: str, digest: str, password: bytes,
                      plain: bytes, target_secret: bytes) -> dict:
    """Executa _work_loop exato com constantes sintéticas e saída exclusivamente em RAM."""
    salt = b"12345678"
    cipher = encrypt(module, mode, password, salt, plain, digest)
    module.KDFS = ((digest, getattr(hashlib, digest)),)
    assert module.open_with(mode, password, salt, cipher, digest) == plain
    module.BLOBS = {"SYNTHETIC": (salt, cipher)}
    module.PADDED = []
    module.STREAM = [mode]
    module.TGT = PublicKey.from_valid_secret(target_secret).format(compressed=False)
    module.G.TARGET_PUBKEY_HEX = module.TGT.hex()
    hard, soft, best, errors = [], [], {}, {}
    sink = io.StringIO()
    module._work_loop([(password, "synthetic", "raw")], True, {}, hard, soft,
                      best, errors, sink, lambda: None)
    return {"hard": len(hard), "soft": len(soft), "errors": errors,
            "persisted_full_rows": len(sink.getvalue().splitlines()),
            "printable": module.printable(plain)}


def historical_counts(source_root: Path, historical_path: Path) -> dict:
    archive = source_root / "_work/frontier_2026-09-17/rodada3_scripts/premissa_cifra/multicipher_attack.py"
    logfile = source_root / "_work/frontier_2026-09-17/rodada3_logs/premissa_cifra__multicipher_attack.jsonl"
    if historical_path.read_bytes() != archive.read_bytes():
        raise RuntimeError("O script importado não coincide com a cópia arquivada da campanha")
    summary = None
    stream_saved = 0
    with logfile.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("kind") == "summary":
                summary = row
            elif row.get("kind") in ("SOFT", "HARD") and row.get("cipher") in MODES:
                stream_saved += 1
    if summary is None or summary["hard"] != 0 or summary["errors"]:
        raise RuntimeError("Log histórico não satisfaz a contabilidade esperada")
    forms = summary["n_forms"]
    total = forms * 3 * 2 * len(MODES)
    windows = forms * 2 * len(MODES) * (2 * (80 - 31) + (1328 - 31))
    endpoints = total * 2
    return {"forms": forms, "stream_decryptions": total,
            "emitted_full_stream_rows": stream_saved,
            "not_emitted_as_full_stream_rows": total - stream_saved,
            "all_raw32_windows": windows, "endpoint_checks_already_attempted": endpoints,
            "interior_raw32_windows": windows - endpoints,
            "reported_historical_all_modes_seconds": summary["seconds"],
            "historical_log_sha256": file_hash(logfile),
            "historical_code_sha256": file_hash(historical_path),
            "code_matches_archived_campaign": True,
            "limits": "Não emitido significa ausência de registro completo no ramo STREAM; prefixes best podem existir. Não significa chave real perdida."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True,
                        help="Checkout que contém os logs históricos; somente leitura")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source_root = args.source_root.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any((out / name).exists() for name in ("controls.json", "summary.json")):
        parser.error("controls.json e summary.json devem ser novos")
    historical_path = ROOT / "solver/premissas_2026_09_17/multicipher_attack.py"
    counts = historical_counts(source_root, historical_path)
    kit = ROOT / "solver/experiments/claude_endgame_2026_09_02/gsmg_common.py"
    kit_result = subprocess.run([sys.executable, "-B", str(kit)], cwd=ROOT,
                                capture_output=True, text=True, check=True)
    assert "gsmg_common OK" in kit_result.stdout
    spec = importlib.util.spec_from_file_location("historical_multicipher_audit", historical_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Não foi possível carregar o módulo histórico")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    keys = tuple(hashlib.sha256(f"STREAM synthetic planted key {i}".encode()).digest() for i in (1, 2))
    targets = (independent_address(keys[0], False), independent_address(keys[1], True))
    broad = Oracle(targets)
    password = b"public synthetic audit password"
    cases = []
    old_kit_target = module.G.TARGET_PUBKEY_HEX
    try:
        for mode in MODES:
            for digest in ("sha256", "md5"):
                for index, key in enumerate(keys, 1):
                    for size, offset in ((80, 0), (80, 16), (80, 48), (1328, 512)):
                        plain = bytes([255]) * offset + key + bytes([255]) * (size - offset - 32)
                        old = historical_result(module, mode, digest, password, plain, key)
                        found = broad.scan(plain)["hits"]
                        assert any(hit["address"] == targets[index - 1] and hit["offset"] == offset
                                   and hit["format"] == "raw32" for hit in found)
                        interior = offset not in (0, size - 32)
                        assert not old["errors"]
                        assert old["hard"] == (0 if interior else 1)
                        assert old["persisted_full_rows"] == (0 if interior else 1)
                        cases.append({"mode": mode, "digest": digest, "key_index": index,
                                      "bytes": size, "offset": offset, "historical": old,
                                      "broad_hits": len(found), "interior": interior})

        # Contagens preservadas e blobs novamente cifrados; oráculo amplo e pipeline antigo.
        plain = bytes([255]) * 16 + keys[0] + bytes([255]) * 32
        rng = random.Random(18092026)
        null_attempts = 0
        for _ in range(100):
            shuffled = list(plain)
            rng.shuffle(shuffled)
            candidate = bytes(shuffled)
            old = historical_result(module, "aes-256-ctr", "sha256", password, candidate, keys[0])
            result = broad.scan(candidate)
            assert not result["hits"] and not old["hard"]
            null_attempts += sum(result["attempts"].values())
    finally:
        module.G.TARGET_PUBKEY_HEX = old_kit_target

    # Mede o mesmo oráculo amplo em dados sintéticos, sem executar campanhas reais.
    benchmark_rng = random.Random(20260918)
    buffers = [benchmark_rng.randbytes(size) for size in ([80, 1328] * 12)]
    timings = []
    windows = sum(max(0, len(buf) - 31) for buf in buffers)
    for _ in range(3):
        started = time.perf_counter()
        for buf in buffers:
            assert not broad.scan(buf)["hits"]
        timings.append(time.perf_counter() - started)
    seconds = statistics.median(timings)
    rate = windows / seconds
    estimates = {"benchmark_raw32_windows_per_repeat": windows,
                 "benchmark_repeats": len(timings), "benchmark_seconds": timings,
                 "median_windows_per_second_single_process": rate,
                 "estimated_all_raw32_single_process_hours": counts["all_raw32_windows"] / rate / 3600,
                 "estimated_interior_only_single_process_hours": counts["interior_raw32_windows"] / rate / 3600,
                 "limits": "Extrapolação ECC do oráculo amplo em máquina sob carga; não inclui nova geração/decriptação, I/O ou promete escalabilidade paralela."}
    controls = {"passed": True, "phase2_and_checkerboard": True,
                "synthetic_targets": targets, "cases": cases,
                "matched_null": {"shuffles": 100, "seed": 18092026,
                                 "attempts": null_attempts, "hits": 0},
                "historical_code_sha256": file_hash(historical_path),
                "oracle_sha256": file_hash(ROOT / "solver/oraculo_duplo_2026_09_17/oracle.py"),
                "audit_sha256": file_hash(Path(__file__))}
    summary = {"passed": True, "interior_false_negatives": sum(case["interior"] for case in cases),
               "endpoint_positive_controls": sum(not case["interior"] for case in cases),
               "matched_null": controls["matched_null"], "historical_counts": counts,
               "cost_estimate": estimates,
               "next_step": "Corrigir o filtro antes de futuras campanhas; decidir reexecução só com base no custo e em corpus disponível. Esta auditoria não disparou busca histórica."}
    for name, value in (("controls.json", controls), ("summary.json", summary)):
        with (out / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
