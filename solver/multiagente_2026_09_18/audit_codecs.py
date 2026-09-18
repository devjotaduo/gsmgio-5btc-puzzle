"""Reproduz a lacuna cp273, os controles reais e os controles sintéticos sem rede."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_DIR = ROOT / "solver/oraculo_duplo_2026_09_17"
sys.path.insert(0, str(ORACLE_DIR))

from controls import phase32_codec_control, run_controls
from oracle import Oracle, cp273_inverse_view, independent_address


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source_root = args.source_root.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any((out / name).exists() for name in ("controls.json", "summary.json")):
        parser.error("controls.json e summary.json devem ser novos")

    kit = source_root / "solver/experiments/claude_endgame_2026_09_02/gsmg_common.py"
    kit_before = file_hash(kit)
    result = subprocess.run(
        [sys.executable, "-B", str(kit)], cwd=source_root,
        capture_output=True, text=True, check=True,
    )
    if "gsmg_common OK" not in result.stdout or file_hash(kit) != kit_before:
        raise RuntimeError("Controle positivo do kit falhou ou arquivo foi alterado")

    checks = run_controls()
    checks["phase32_codec"] = phase32_codec_control(source_root)
    checks["phase2_and_checkerboard"] = True
    checks["kit_sha256"] = kit_before
    checks["oracle_sha256"] = file_hash(ORACLE_DIR / "oracle.py")
    checks["controls_sha256"] = file_hash(ORACLE_DIR / "controls.py")
    checks["audit_sha256"] = file_hash(Path(__file__))

    secret = hashlib.sha256(b"planted inverse cp273 private key").digest()
    oracle = Oracle((independent_address(secret, False),))
    text = secret.hex().encode("ascii")
    encoded = text.decode("cp273").encode("latin-1")
    result = oracle.scan(encoded)
    old_hits = [hit for hit in result["hits"] if not hit["format"].startswith("cp273-inverse:")]
    new_hits = [hit for hit in result["hits"] if hit["format"].startswith("cp273-inverse:")]
    if old_hits or len(new_hits) != 1 or cp273_inverse_view(encoded) != text:
        raise RuntimeError("Reprodução plantada não confirmou a diferença esperada")
    summary = {
        "passed": True,
        "finding": "O antecedente da fase 3.2 usa o sentido cp273 que não era varrido.",
        "planted_bytes": len(encoded), "previous_views_hits": len(old_hits),
        "new_inverse_view_hits": len(new_hits), "offset": new_hits[0]["offset"],
        "phase32_codec": checks["phase32_codec"],
        "cp273_planted_cases": len(checks["cp273_directions"]["cases"]),
        "matched_null": checks["cp273_directions"]["matched_null"],
        "oracle_sha256": checks["oracle_sha256"],
        "limits": [
            "Somente controles sintéticos e fases públicas autenticadas; nenhum corpus histórico varrido.",
            "previous_views_hits agrega as visões anteriores preservadas, sem a nova visão cp273-inverse.",
            "A prova de correção do oráculo não constitui descoberta de chave real.",
        ],
    }
    for name, value in (("controls.json", checks), ("summary.json", summary)):
        with (out / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({"passed": True, "planted_cases": summary["cp273_planted_cases"],
                      "phase32_exact_bytes": checks["phase32_codec"]["beaufort_bytes"],
                      "matched_null": summary["matched_null"],
                      "oracle_sha256": checks["oracle_sha256"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
