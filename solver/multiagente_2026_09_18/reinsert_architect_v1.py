"""Complemento finito: somas com primos reinseridos + duas cláusulas históricas.

Hipótese: a ordem matrixsumlist -> lastwordsbeforearchichoice pede a lista
numérica seguida da cláusula. Não acrescenta ordens, cortes ou normalizações.
O recorte da fase 3.2 é interpretativo; a segunda cláusula vem de roteiro
pré-filme. Nenhuma das duas tem autoridade de senha conhecida.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from collections import Counter
from pathlib import Path

import reinsert_primes as R
import oracle as oracle_module
from oracle import Oracle, independent_address

ROOT = R.REPO
CLAUSES = (
    "reinsertingtheprimebasicsafterwhichyouwillberequiredto",
    "sheisgoingtodieandthereisnothingyoucandotostopit",
)


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def bases_for(tokens: dict[int, tuple[str, ...]]) -> set[str]:
    return {item["material"] for item in R.generate_materials(tokens)
            if item["composition"] == "isolated"}


def passwords_for(bases: set[str]) -> tuple[set[str], dict[bytes, list[dict]]]:
    materials = {base + clause for base in bases for clause in CLAUSES}
    passwords: dict[bytes, list[dict]] = {}
    for material in sorted(materials):
        for form, password in R.password_forms(material):
            passwords.setdefault(password, []).append({"material": material, "form": form})
    return materials, passwords


def evaluate(passwords: dict[bytes, list[dict]], out: Path,
             run: str, oracle: Oracle | None) -> dict:
    stats = {"passwords": len(passwords), "aes_decisions": 0, "paddings": 0,
             "semantic_candidates": 0, "raw32_be_attempts": 0, "key_hits": 0}
    for password in sorted(passwords):
        for blob in R.BLOB_NAMES:
            for kdf in ("sha256", "md5"):
                stats["aes_decisions"] += 1
                plain = R.aes_open(password, blob, kdf)
                if plain is None:
                    continue
                stats["paddings"] += 1
                record = {"run": run, "password_hex": password.hex(), "blob": blob,
                          "kdf": kdf, "plaintext_hex": plain.hex()}
                R.jsonl(out / "paddings.jsonl", record)
                if R.G.semantic(plain):
                    stats["semantic_candidates"] += 1
                    R.jsonl(out / "candidates.jsonl", record)
                if oracle is not None:
                    scanned = oracle.scan(plain)
                    stats["raw32_be_attempts"] += scanned["attempts"]["raw32"]
                    for hit in scanned["hits"]:
                        secret = bytes.fromhex(hit["private_key"])
                        if independent_address(secret, hit["compressed"]) != hit["address"]:
                            raise AssertionError("Falha da confirmação ECC independente")
                        stats["key_hits"] += 1
                        R.jsonl(out / "hits.jsonl", {**record, "hit": hit,
                                                   "independently_verified": True})
    return stats


def controls(tokens: dict[int, tuple[str, ...]]) -> dict:
    assert R.phase2_control() and R.checkerboard_control()
    assert R.planted_control()["passed"] and R.conservation_control(tokens)["passed"]
    secret = hashlib.sha256(b"reinsert architect synthetic key").digest()
    target = independent_address(secret, True)
    oracle = Oracle((target,))
    material = "1031" + CLAUSES[0]
    password = hashlib.sha256(material.encode("ascii")).hexdigest().encode("ascii")
    assert password in passwords_for({"1031"})[1]
    plain = b"prefix!" + secret + b"suffix"
    for kdf in ("sha256", "md5"):
        key, iv = R.evp(password, b"01234567", R.KDFS[kdf])
        pad = 16 - len(plain) % 16
        ciphertext = R.AES.new(key, R.AES.MODE_CBC, iv).encrypt(plain + bytes([pad]) * pad)
        decoded = R.unpad(R.AES.new(key, R.AES.MODE_CBC, iv).decrypt(ciphertext))
        assert decoded == plain
        assert any(hit["address"] == target and hit["offset"] == 7
                   for hit in oracle.scan(decoded)["hits"])
    return {"passed": True, "phase2": True, "checkerboard": True,
            "rectangular_sums": True, "null_conservation": True,
            "synthetic_composed_password_aes": True, "synthetic_key_offset": 7}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / "_work").resolve()) or out.exists():
        parser.error("Saída precisa ser diretório novo sob _work desta worktree")
    previous = ROOT / "_work/multiagente_2026-09-18/reinsert_primes_v2/materials.jsonl"
    dependencies = [Path(__file__), Path(R.__file__), Path(oracle_module.__file__),
                    Path(R.G.__file__), ROOT / "README.md", previous,
                    ROOT / "_work/recipe_audit_2026-09-11/FRONTEIRA_TEXTUAL.md"]
    source_hashes = {str(path.relative_to(ROOT)): R.sha256_file(path) for path in dependencies}
    out.mkdir(parents=True, exist_ok=False)
    spec = {"hypothesis": __doc__, "clauses": list(CLAUSES),
            "order": "numeric_base + clause", "forms": ["raw", "sha256hex"],
            "blobs": list(R.BLOB_NAMES), "kdfs": ["sha256", "md5"],
            "null_replicates": 100, "seed": 18092027, "null_ecc": False,
            "raw32_order": "big-endian", "source_hashes": source_hashes,
            "clause_sources": ["README.md fase 3.2; corte antes SELECT interpretativo",
                               "FRONTEIRA_TEXTUAL.md; roteiro pré-filme, p.122A/PDF130"]}
    save(out / "spec.json", spec)
    started = time.monotonic()
    tokens = {length: R.segment_dbbi(length) for length in (83, 84)}
    ctrl = controls(tokens)
    bases = bases_for(tokens)
    saved_bases = set()
    for line in previous.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["run"] == "real" and row["meta"]["composition"] == "isolated":
            saved_bases.add(row["material"])
    assert bases == saved_bases and len(bases) == 270
    ctrl["saved_bases_exact"] = True
    save(out / "controls.json", ctrl)
    materials, passwords = passwords_for(bases)
    assert len(materials) == 540 and len(passwords) == 1080
    for password, origins in sorted(passwords.items()):
        R.jsonl(out / "passwords.jsonl", {"password_hex": password.hex(), "origins": origins})
    real = evaluate(passwords, out, "real", Oracle())
    rng = random.Random(spec["seed"])
    nulls = []
    for index in range(spec["null_replicates"]):
        shuffled = {length: R.shuffle_residue(value, rng) for length, value in tokens.items()}
        for length, value in shuffled.items():
            assert R.marker_bits(value) == R.marker_bits(tokens[length])
            assert Counter(R.residue(value)) == Counter(R.residue(tokens[length]))
        _, null_passwords = passwords_for(bases_for(shuffled))
        nulls.append(evaluate(null_passwords, out, f"null{index:03d}", None))
    if any(R.sha256_file(path) != source_hashes[str(path.relative_to(ROOT))]
           for path in dependencies):
        raise RuntimeError("Fonte alterada durante a execução")
    summary = {"status": "complete", "bases": len(bases), "materials": len(materials),
               "real": real, "null_replicates": len(nulls),
               "null_totals": dict(sum((Counter(item) for item in nulls), Counter())),
               "null_password_count_min": min(item["passwords"] for item in nulls),
               "null_password_count_max": max(item["passwords"] for item in nulls),
               "hashes_unchanged": True, "seconds": round(time.monotonic() - started, 3)}
    save(out / "summary.json", summary)
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
