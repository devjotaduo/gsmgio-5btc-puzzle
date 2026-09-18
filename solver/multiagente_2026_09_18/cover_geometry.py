"""Fecha a lacuna declarada das coordenadas das estrelas da capa recuperada.

Hipótese de baixo prior: coordenadas ou soma/diferença dos dois centros,
serializadas como os números das fases anteriores, fornecem senha ou brainwallet.
A capa prova uma referência visual a yin-yang; não prova uso de coordenadas.
Quatro limiares, duas discretizações em grade e ordem dos eixos são fixados
antes de qualquer AES. Nulo: 100 rotações rígidas dos quatro pares medidos.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import random
import re
import sys
import time
from collections import Counter
from pathlib import Path

import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "solver/experiments/claude_endgame_2026_09_02"))
sys.path.insert(0, str(ROOT / "solver/oraculo_duplo_2026_09_17"))
import gsmg_common as G  # noqa: E402
from oracle import Oracle, independent_address  # noqa: E402
import oracle as oracle_module  # noqa: E402

IMAGE_SHA = "3a9b0a6ecacef83e1ef9f688303105570b3dcae95fd82be75f1fcbd2f5fddd04"
THRESHOLDS = (140, 170, 200, 220)


def measure(path: Path) -> list[dict]:
    if hashlib.sha256(path.read_bytes()).hexdigest() != IMAGE_SHA:
        raise ValueError("Capa difere do insumo auditado")
    with Image.open(path) as source_image:
        pixels = np.asarray(source_image.convert("RGB"), dtype=np.int16)
    if pixels.shape != (499, 377, 3):
        raise ValueError("Dimensões inesperadas")
    roi = pixels[195:411, 92:318]
    r, g, b = roi[..., 0], roi[..., 1], roi[..., 2]
    out = []
    for threshold in THRESHOLDS:
        white = (roi.min(axis=2) >= threshold) & (roi.max(axis=2) - roi.min(axis=2) <= 65)
        yellow = ((r >= threshold) & (g >= 0.8 * threshold) & (b <= 100)
                  & (r - b >= 80) & (g - b >= 60))
        row = {"threshold": threshold}
        for name, mask in (("white", white), ("yellow", yellow)):
            count, _, stats, centers = cv2.connectedComponentsWithStats(mask.astype(np.uint8), 8)
            if count < 2:
                raise ValueError("Nenhum componente")
            index = 1 + int(np.argmax(stats[1:, cv2.CC_STAT_AREA]))
            x, y = centers[index]
            row[name] = {"x": float(x + 92), "y": float(y + 195),
                         "area": int(stats[index, cv2.CC_STAT_AREA])}
        out.append(row)
    return out


def materials(rows: list[dict]) -> dict[bytes, str]:
    out: dict[bytes, str] = {}
    for row in rows:
        points = [(row[color]["x"], row[color]["y"]) for color in ("white", "yellow")]
        for model in ("pixels", "cells14", "endpoints14"):
            if model == "pixels":
                pair = [tuple(round(value) for value in point) for point in points]
            elif model == "cells14":
                pair = [(math.floor(14 * x / 377), math.floor(14 * y / 499)) for x, y in points]
            else:
                pair = [(round(13 * x / 376), round(13 * y / 498)) for x, y in points]
            for base in (0, 1):
                shifted = [tuple(value + base for value in point) for point in pair]
                for order_index, star_order in enumerate((shifted, shifted[::-1])):
                    for swap_axes in (False, True):
                        p, q = [point[::-1] if swap_axes else point for point in star_order]
                        sequences = {"coords": (*p, *q), "sum": (p[0] + q[0], p[1] + q[1]),
                                     "diff": (q[0] - p[0], q[1] - p[1]),
                                     "absdiff": (abs(q[0] - p[0]), abs(q[1] - p[1]))}
                        for kind, values in sequences.items():
                            for separator in ("", ",", " "):
                                value = separator.join(map(str, values)).encode("ascii")
                                out.setdefault(value, f"t{row['threshold']}/{model}/base{base}/{kind}"
                                               f"/star_order{order_index}/swap_axes{int(swap_axes)}/sep={separator!r}")
    return out


def decrypt(password: bytes, salt: bytes, ciphertext: bytes, digest) -> bytes | None:
    key, iv = G.evp(password, salt, digest)
    return G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))


def run(items: dict[bytes, str], blobs: dict, *, oracle: Oracle | None,
        padding_file=None, hit_file=None) -> dict:
    passwords: dict[bytes, str] = {}
    for material, provenance in items.items():
        for name, password in (("raw", material), ("sha256hex", hashlib.sha256(material).hexdigest().encode())):
            passwords.setdefault(password, provenance + "/" + name)
    trials: Counter = Counter()
    paddings: Counter = Counter()
    semantic = 0
    raw_attempts = 0
    hard = 0
    max_printable = 0.0
    brainwallets: set[bytes] = set()
    for password, provenance in passwords.items():
        if oracle is not None:
            key = hashlib.sha256(password).digest()
            if key not in brainwallets:
                brainwallets.add(key)
                for hit in oracle.check(key):
                    hard += 1
                    if independent_address(key, hit["compressed"]) != hit["address"]:
                        raise RuntimeError("Hit independente divergiu")
                    if hit_file:
                        hit_file.write(json.dumps({"provenance": provenance, **hit}) + "\n")
        for blob, (salt, ciphertext) in blobs.items():
            for digest_name, digest in (("SHA256", SHA256), ("MD5", MD5)):
                cell = blob + "/" + digest_name
                trials[cell] += 1
                plaintext = decrypt(password, salt, ciphertext, digest)
                if plaintext is None:
                    continue
                paddings[cell] += 1
                max_printable = max(max_printable, G.printable(plaintext))
                semantic += bool(G.semantic(plaintext))
                if padding_file:
                    padding_file.write(json.dumps({"provenance": provenance, "blob": blob,
                        "kdf": digest_name, "password_hex": password.hex(), "plain_hex": plaintext.hex()}) + "\n")
                if oracle is not None:
                    result = oracle.scan(plaintext)
                    raw_attempts += result["attempts"]["raw32"]
                    for hit in result["hits"]:
                        key = bytes.fromhex(hit["private_key"])
                        if independent_address(key, hit["compressed"]) != hit["address"]:
                            raise RuntimeError("Hit independente divergiu")
                        hard += 1
                        if hit_file:
                            hit_file.write(json.dumps({"provenance": provenance, "blob": blob, **hit}) + "\n")
    return {"materials": len(items), "passwords": len(passwords), "trials": dict(trials),
            "paddings": dict(paddings), "semantic_flags": semantic, "hard_hits": hard,
            "max_printable": max_printable, "brainwallets": len(brainwallets), "raw32": raw_attempts}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "_work"):
        parser.error("Saída deve ficar em _work")
    out.mkdir(parents=True, exist_ok=False)
    rows = measure(args.image)
    dependencies = [Path(__file__), Path(G.__file__), Path(oracle_module.__file__), ROOT / "README.md"]
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in dependencies}
    spec = {"hypothesis": __doc__, "image_sha256": IMAGE_SHA, "measurements": rows,
            "normalizations": ["round(pixel)", "floor(14*xy/(377,499))", "round(13*xy/(376,498))"],
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "source_sha256": hashes,
            "null": "100 rotações rígidas dos quatro pares, centro mediano fixo e ângulos uniformes; mesmo gerador; sem ECC no nulo"}
    (out / "spec.json").write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    phase2 = base64.b64decode(G.PHASE2_B64)
    phase = decrypt(hashlib.sha256(b"causality").hexdigest().encode(), phase2[8:16], phase2[16:], SHA256)
    assert phase and phase.startswith(b"The ironic")
    # Usa os dígitos autenticados no README, evitando uma transcrição nova.
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    number = re.search(r"input: (151659[0-9]+)", readme).group(1)
    checker = G.checkerboard_decode([int(c) for c in number], "FUBCDORA.LETHINGKYMVPS.JQZXW", (1, 4), "0123456789")
    assert checker == "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE"
    generated = materials(rows)
    password = hashlib.sha256(next(iter(generated))).hexdigest().encode()
    salt = b"coverctl"
    key, iv = G.evp(password, salt, SHA256)
    plain = b"This synthetic plaintext verifies the coordinate password pipeline."
    pad = 16 - len(plain) % 16
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(plain + bytes([pad]) * pad)
    assert decrypt(password, salt, encrypted, SHA256) == plain
    planted = run(generated, {"PLANTED": (salt, encrypted)}, oracle=None)
    assert planted["semantic_flags"] >= 1
    for row in rows:
        assert [math.floor(14 * row["white"]["x"] / 377), math.floor(14 * row["white"]["y"] / 499)] == [7, 6]
        assert [math.floor(14 * row["yellow"]["x"] / 377), math.floor(14 * row["yellow"]["y"] / 499)] == [7, 9]
    control = {"phase2": True, "checkerboard": True, "coordinate_pipeline_planted": True,
               "white_cell14": [7, 6], "yellow_cell14": [7, 9]}
    (out / "controls.json").write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
    started = time.monotonic()
    with (out / "paddings.jsonl").open("x", encoding="utf-8") as pf, (out / "hits.jsonl").open("x", encoding="utf-8") as hf:
        real = run(generated, G.BLOBS, oracle=Oracle(), padding_file=pf, hit_file=hf)
    w = np.median([[row["white"]["x"], row["white"]["y"]] for row in rows], axis=0)
    y = np.median([[row["yellow"]["x"], row["yellow"]["y"]] for row in rows], axis=0)
    center = (w + y) / 2
    rng = random.Random(18092026)
    nulls = []
    with (out / "null_paddings.jsonl").open("x", encoding="utf-8") as pf:
        for index in range(100):
            angle = rng.uniform(0, 2 * math.pi)
            rotation = np.array([[math.cos(angle), -math.sin(angle)], [math.sin(angle), math.cos(angle)]])
            nullrows = []
            for row in rows:
                nullrow = {"threshold": f"null{index}-t{row['threshold']}"}
                for color in ("white", "yellow"):
                    point = np.array([row[color]["x"], row[color]["y"]])
                    moved = center + rotation @ (point - center)
                    nullrow[color] = {"x": float(moved[0]), "y": float(moved[1])}
                nullrows.append(nullrow)
            nulls.append(run(materials(nullrows), G.BLOBS, oracle=None, padding_file=pf))
    summary = {"status": "complete", "real": real, "null_replicates": len(nulls),
               "nulls": nulls, "seconds": time.monotonic() - started,
               "limits": ["Geometria compatível com yin-yang padrão; coordenadas são hipótese.",
                          "Número de materiais distintos pode variar com discretização no nulo.",
                          "Raw32 no plaintext somente big-endian; chaves de hashes testadas integralmente."]}
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != hashes[str(path.relative_to(ROOT))]
           for path in dependencies):
        raise RuntimeError("Código ou fonte alterada durante a execução")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "complete", "real": real, "null_replicates": len(nulls)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
