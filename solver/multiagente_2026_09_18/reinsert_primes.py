# -*- coding: utf-8 -*-
"""Reinsercao estrutural dos primos nos marcadores logicos de DBBI.

Hipotese finita:
    A etapa `yellowblueprimes` nao manda descartar os lugares primos depois de
    identificar `b`/`be`; ela manda reinserir o proprio primo p como numero no
    lugar logico p. Os lugares nao-primos continuam sendo a1z26 (a=1..i=9).
    Testamos L83 e L84, tres modos de marcador (ambos, so b, so be), todas as
    grades retangulares exatas, somas de linhas/colunas em ambas direcoes,
    serializacao decimal concatenada e por virgulas, isolada e composta com as
    duas clausulas decodificadas da pagina: `lastwordsbeforearchichoice` e
    `thispassword`.

Diferenca para rodadas anteriores:
    `matrixsumlist_struct__msl_struct.py` testou residuos, sequencias logicas
    com marcadores zerados/como bits e preenchimento da matriz. Esta familia
    usa o valor numerico do primo p nos marcadores logicos antes de somar grades
    retangulares exatas da propria sequencia logica.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Iterable

from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256


REPO = Path(__file__).resolve().parents[2]
KIT = REPO / "solver" / "experiments" / "claude_endgame_2026_09_02"
DUAL = REPO / "solver" / "oraculo_duplo_2026_09_17"
sys.path.insert(0, str(KIT))
sys.path.insert(0, str(DUAL))

import gsmg_common as G  # noqa: E402
from oracle import Oracle  # noqa: E402


CLAUSES = (
    {
        "id": "lastwordsbeforearchichoice",
        "text": "lastwordsbeforearchichoice",
        "source": "README.md: segmento z #1 da pagina final, a-i,o -> decimal -> hex -> ASCII",
    },
    {
        "id": "thispassword",
        "text": "thispassword",
        "source": "README.md: segmento z #2 da pagina final, a-i,o -> decimal -> hex -> ASCII",
    },
)
KDFS = {"md5": MD5, "sha256": SHA256}
BLOB_NAMES = ("SMALL", "COSMIC", "TAIL32")
ALPHA = "abcdefghi"
PKCS7_PADDING_PROBABILITY = sum(256 ** (-pad_len) for pad_len in range(1, 17))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as stream:
        json.dump(obj, stream, ensure_ascii=False, sort_keys=True)
        stream.write("\n")


def is_prime(n: int) -> bool:
    return G.is_prime(n)


def divisors_rectangles(n: int) -> list[tuple[int, int]]:
    return [(h, n // h) for h in range(1, n + 1) if n % h == 0]


def segment_dbbi(length: int, source: str | None = None) -> tuple[str, ...]:
    """Segmenta DBBI em posicoes logicas 1..length.

    Nos primos consome `b` ou `be`; nos demais consome um simbolo. Para os
    nulos, `source` e uma cadeia fisica com as mesmas letras de DBBI, obtida ao
    embaralhar apenas os residuos e preservar os marcadores.
    """

    text = G.DBBI if source is None else source
    results: list[tuple[str, ...]] = []

    def rec(pos: int, index: int, tokens: list[str]) -> None:
        if pos > length:
            if index == len(text):
                results.append(tuple(tokens))
            return
        if index >= len(text):
            return
        if is_prime(pos):
            if text[index] == "b":
                rec(pos + 1, index + 1, [*tokens, "b"])
                if index + 1 < len(text) and text[index + 1] == "e":
                    rec(pos + 1, index + 2, [*tokens, "be"])
        else:
            rec(pos + 1, index + 1, [*tokens, text[index]])

    rec(1, 0, [])
    if len(results) != 1:
        raise AssertionError((length, len(results)))
    return results[0]


def residue(tokens: tuple[str, ...]) -> str:
    return "".join(token for pos, token in enumerate(tokens, 1) if not is_prime(pos))


def marker_bits(tokens: tuple[str, ...]) -> str:
    return "".join(
        "1" if token == "be" else "0"
        for pos, token in enumerate(tokens, 1)
        if is_prime(pos)
    )


def physical_from_tokens(tokens: tuple[str, ...]) -> str:
    return "".join(tokens)


def shuffle_residue(tokens: tuple[str, ...], rng: random.Random) -> tuple[str, ...]:
    chars = list(residue(tokens))
    rng.shuffle(chars)
    out: list[str] = []
    it = iter(chars)
    for pos, token in enumerate(tokens, 1):
        out.append(token if is_prime(pos) else next(it))
    return tuple(out)


def values_for(tokens: tuple[str, ...], mode: str) -> list[int]:
    values: list[int] = []
    for pos, token in enumerate(tokens, 1):
        if is_prime(pos):
            if mode == "both":
                values.append(pos)
            elif mode == "b_only":
                values.append(pos if token == "b" else 0)
            elif mode == "be_only":
                values.append(pos if token == "be" else 0)
            else:
                raise ValueError(mode)
        else:
            values.append(ALPHA.index(token) + 1)
    return values


def grid(values: list[int], height: int, width: int) -> list[list[int]]:
    return [values[row * width:(row + 1) * width] for row in range(height)]


def row_sums(matrix: list[list[int]]) -> list[int]:
    return [sum(row) for row in matrix]


def col_sums(matrix: list[list[int]]) -> list[int]:
    return [sum(matrix[row][col] for row in range(len(matrix))) for col in range(len(matrix[0]))]


def serializations(numbers: list[int]) -> dict[str, str]:
    return {
        "concat": "".join(str(number) for number in numbers),
        "csv": ",".join(str(number) for number in numbers),
    }


def compose_materials(base: str) -> Iterable[tuple[str, str]]:
    c1, c2 = CLAUSES[0]["text"], CLAUSES[1]["text"]
    yield "isolated", base
    yield "suffix_lastwords", base + c1
    yield "prefix_lastwords", c1 + base
    yield "suffix_thispassword", base + c2
    yield "prefix_thispassword", c2 + base
    yield "lastwords_material_thispassword", c1 + base + c2


def password_forms(material: str) -> Iterable[tuple[str, bytes]]:
    raw = material.encode("ascii")
    yield "raw", raw
    yield "sha256hex", hashlib.sha256(raw).hexdigest().encode("ascii")


def generate_materials(tokens_by_len: dict[int, tuple[str, ...]]) -> list[dict]:
    materials: list[dict] = []
    seen_ids: set[str] = set()
    for length in (83, 84):
        tokens = tokens_by_len[length]
        for mode in ("both", "b_only", "be_only"):
            values = values_for(tokens, mode)
            for height, width in divisors_rectangles(length):
                matrix = grid(values, height, width)
                lists = {
                    "rows": row_sums(matrix),
                    "rows_rev": list(reversed(row_sums(matrix))),
                    "cols": col_sums(matrix),
                    "cols_rev": list(reversed(col_sums(matrix))),
                }
                for list_name, numbers in lists.items():
                    for serial_name, base in serializations(numbers).items():
                        for comp_name, material in compose_materials(base):
                            material_id = (
                                f"L{length}|{mode}|{height}x{width}|"
                                f"{list_name}|{serial_name}|{comp_name}"
                            )
                            if material_id in seen_ids:
                                raise AssertionError(material_id)
                            seen_ids.add(material_id)
                            materials.append({
                                "id": material_id,
                                "length": length,
                                "mode": mode,
                                "grid": [height, width],
                                "list": list_name,
                                "serial": serial_name,
                                "composition": comp_name,
                                "numbers": numbers,
                                "material": material,
                            })
    return materials


def evp(pw: bytes, salt: bytes, hmod, klen: int = 32, ivlen: int = 16) -> tuple[bytes, bytes]:
    data = b""
    prev = b""
    while len(data) < klen + ivlen:
        prev = hmod.new(prev + pw + salt).digest()
        data += prev
    return data[:klen], data[klen:klen + ivlen]


def unpad(buf: bytes) -> bytes | None:
    if not buf:
        return None
    pad = buf[-1]
    if 1 <= pad <= 16 and buf.endswith(bytes([pad]) * pad):
        return buf[:-pad]
    return None


def aes_open(password: bytes, blob_name: str, kdf_name: str) -> bytes | None:
    salt, ciphertext = G.BLOBS[blob_name]
    key, iv = evp(password, salt, KDFS[kdf_name])
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))


def printable_ratio(buf: bytes) -> float:
    return G.printable(buf)


def semantic(buf: bytes) -> bool:
    return G.semantic(buf)


def oracle_scan_material(oracle: Oracle, payload: bytes) -> list[dict]:
    hits: list[dict] = []
    # Hex64/WIF text, cp273 and UTF-16 views without treating arbitrary decimal
    # strings as raw32 private-key windows.
    decoded = oracle.scan(payload, decoded_only=True)
    hits.extend(decoded["hits"])
    for label, secret in (
        ("sha256(material)", hashlib.sha256(payload).digest()),
        ("sha256d(material)", hashlib.sha256(hashlib.sha256(payload).digest()).digest()),
    ):
        for hit in oracle.check(secret):
            hits.append({"format": label, "offset": 0, **hit})
    if len(payload) == 32:
        for hit in oracle.check(payload):
            hits.append({"format": "raw32-material", "offset": 0, **hit})
    return hits


def oracle_scan_plaintext(oracle: Oracle, payload: bytes) -> list[dict]:
    hits = oracle.scan(payload, decoded_only=False)["hits"]
    for label, secret in (
        ("sha256(plaintext)", hashlib.sha256(payload).digest()),
        ("sha256d(plaintext)", hashlib.sha256(hashlib.sha256(payload).digest()).digest()),
    ):
        for hit in oracle.check(secret):
            hits.append({"format": label, "offset": 0, **hit})
    return hits


def phase2_control() -> bool:
    raw = base64.b64decode(G.PHASE2_B64)
    salt, ciphertext = raw[8:16], raw[16:]
    key, iv = evp(G.shahex("causality").encode("ascii"), salt, SHA256)
    plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))
    return bool(plain and plain.startswith(b"The ironic"))


def checkerboard_control() -> bool:
    alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
    digits = [int(c) for c in (
        "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"
    )]
    plain = G.checkerboard_decode(digits, alpha322, (1, 4), "0123456789")
    return plain.startswith("INCASEYOUMANAGETOCRACKTHIS")


def planted_control() -> dict:
    values = [2, 3, 5, 7, 11, 13]
    matrix = grid(values, 2, 3)
    rows = row_sums(matrix)
    cols = col_sums(matrix)
    expected = {
        "rows": [10, 31],
        "rows_rev": [31, 10],
        "cols": [9, 14, 18],
        "cols_rev": [18, 14, 9],
    }
    ok = rows == expected["rows"] and list(reversed(rows)) == expected["rows_rev"]
    ok = ok and cols == expected["cols"] and list(reversed(cols)) == expected["cols_rev"]
    return {"passed": ok, "values": values, "expected": expected}


def conservation_control(tokens_by_len: dict[int, tuple[str, ...]]) -> dict:
    rng = random.Random(18092026)
    checks = {}
    for length, tokens in tokens_by_len.items():
        shuffled = shuffle_residue(tokens, rng)
        checks[str(length)] = {
            "same_marker_bits": marker_bits(tokens) == marker_bits(shuffled),
            "same_residue_counts": Counter(residue(tokens)) == Counter(residue(shuffled)),
            "same_physical_length": len(physical_from_tokens(tokens)) == len(physical_from_tokens(shuffled)),
            "physical_length": len(physical_from_tokens(tokens)),
        }
    return {"passed": all(all(v.values()) for v in checks.values()), "checks": checks}


def run_materials(
    materials: list[dict],
    out_dir: Path,
    oracle: Oracle,
    prefix: str,
    write_materials: bool,
) -> dict:
    materials_path = out_dir / "materials.jsonl"
    paddings_path = out_dir / "paddings.jsonl"
    hard_path = out_dir / "hard_hits.jsonl"
    stats = {
        "materials": len(materials),
        "aes_decisions": 0,
        "padding_hits": 0,
        "semantic_hits": 0,
        "key_hits": 0,
        "max_printable": 0.0,
    }
    seen_materials: set[str] = set()
    for item in materials:
        material = item["material"]
        payload = material.encode("ascii")
        digest = hashlib.sha256(payload).hexdigest()
        seen_materials.add(digest)
        if write_materials:
            jsonl(materials_path, {
                "run": prefix,
                "id": item["id"],
                "sha256": digest,
                "material": material,
                "meta": {k: item[k] for k in ("length", "mode", "grid", "list", "serial", "composition")},
                "numbers": item["numbers"],
            })
        for form_name, password in password_forms(material):
            for hit in oracle_scan_material(oracle, password):
                stats["key_hits"] += 1
                jsonl(hard_path, {
                    "run": prefix,
                    "kind": "material_key",
                    "id": item["id"],
                    "password_form": form_name,
                    "hit": hit,
                })
            for blob_name in BLOB_NAMES:
                for kdf_name in ("sha256", "md5"):
                    stats["aes_decisions"] += 1
                    plain = aes_open(password, blob_name, kdf_name)
                    if plain is None:
                        continue
                    stats["padding_hits"] += 1
                    ratio = printable_ratio(plain)
                    stats["max_printable"] = max(stats["max_printable"], ratio)
                    rec = {
                        "run": prefix,
                        "id": item["id"],
                        "password_form": form_name,
                        "blob": blob_name,
                        "kdf": kdf_name,
                        "len": len(plain),
                        "printable": round(ratio, 6),
                        "plaintext_hex": plain.hex(),
                    }
                    jsonl(paddings_path, rec)
                    key_hits = oracle_scan_plaintext(oracle, plain)
                    if key_hits:
                        stats["key_hits"] += len(key_hits)
                        jsonl(hard_path, {"run": prefix, "kind": "plaintext_key", "id": item["id"], "hit": key_hits})
                    if semantic(plain) or key_hits:
                        stats["semantic_hits"] += 1
                        jsonl(hard_path, {"run": prefix, "kind": "semantic_plaintext", **rec, "key_hits": key_hits})
    stats["unique_material_sha256"] = len(seen_materials)
    return stats


def write_report(out_dir: Path, spec: dict, controls: dict, summary: dict) -> None:
    report = f"""# Reinsercao dos primos em L83/L84

## Hipotese

{spec["hypothesis"]}

## Diferenca para cobertura anterior

{spec["difference_from_previous"]}

## Fontes das clausulas

1. `{CLAUSES[0]["text"]}` — {CLAUSES[0]["source"]}.
2. `{CLAUSES[1]["text"]}` — {CLAUSES[1]["source"]}.

## Escopo

- Segmentacoes: L83 e L84.
- Modos de marcador: ambos (`b` e `be` recebem o proprio primo), so `b` com `be=0`, so `be` com `b=0`.
- Grades exatas: todos os retangulos fatoraveis de 83 e 84.
- Listas: somas de linhas e colunas, diretas e reversas.
- Serializacoes: decimal concatenado e decimal com virgulas.
- Composicoes: material isolado; material antes/depois de cada clausula; `lastwordsbeforearchichoice + material + thispassword`.
- Formas de senha por material: `raw` e `sha256hex` minusculo.

## Controles

```json
{json.dumps(controls, indent=2, ensure_ascii=False)}
```

## Resultado

```json
{json.dumps(summary, indent=2, ensure_ascii=False)}
```

Todos os plaintexts com padding valido foram preservados em `paddings.jsonl`,
com corpo completo em hexadecimal. Hits semanticos ou de chave ficam em
`hard_hits.jsonl`. O nulo embaralha apenas os residuos, preservando posicoes e
tipos dos marcadores logicos e as contagens de letras do residuo.
"""
    (out_dir / "RELATORIO.md").write_text(report, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO / "_work" / "multiagente_2026-09-18" / "reinsert_primes")
    parser.add_argument("--nulls", type=int, default=100)
    args = parser.parse_args()
    out_dir = args.out.resolve()
    work_root = (REPO / "_work").resolve()
    if not out_dir.is_relative_to(work_root):
        raise ValueError(f"--out precisa ficar sob {work_root}: {out_dir}")
    if out_dir.exists():
        raise FileExistsError(f"--out precisa ser um diretorio novo; ja existe: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=False)

    started = time.monotonic()
    tokens_by_len = {83: segment_dbbi(83), 84: segment_dbbi(84)}
    assert marker_bits(tokens_by_len[83]) == "00001000110000100110011"
    assert marker_bits(tokens_by_len[84]) == "00001000110000100110010"
    assert residue(tokens_by_len[84]) == residue(tokens_by_len[83]) + "e"

    controls = {
        "phase2_evp_sha256": phase2_control(),
        "checkerboard_3_2_2": checkerboard_control(),
        "planted_rectangular_sums": planted_control(),
        "matched_null_conservation": conservation_control(tokens_by_len),
    }
    if not all(
        controls[key] is True if isinstance(controls[key], bool) else controls[key]["passed"]
        for key in controls
    ):
        raise AssertionError(controls)

    spec = {
        "hypothesis": (
            "Recolocar o proprio primo p nos marcadores logicos b/be de DBBI, "
            "manter a1z26 nos nao-primos, somar todas as grades retangulares "
            "exatas e testar as listas como senhas numericas compostas com as "
            "duas clausulas internas ja decodificadas."
        ),
        "difference_from_previous": (
            "A rodada matrixsumlist estrutural testou residuos, sequencias com "
            "marcadores zerados/como bits e preenchimentos da matriz. Este teste "
            "usa p como valor numerico do marcador antes das somas."
        ),
        "clauses": CLAUSES,
        "expected_materials": 2016,
        "password_forms": ["raw", "sha256hex"],
        "nulls": args.nulls,
        "source_hashes": {
            "script": sha256_file(Path(__file__)),
            "gsmg_common": sha256_file(KIT / "gsmg_common.py"),
            "dual_oracle": sha256_file(DUAL / "oracle.py"),
        },
    }
    (out_dir / "spec.json").write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "controls.json").write_text(json.dumps(controls, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    oracle = Oracle()
    real_materials = generate_materials(tokens_by_len)
    if len(real_materials) != spec["expected_materials"]:
        raise AssertionError(len(real_materials))
    real_stats = run_materials(real_materials, out_dir, oracle, "real", write_materials=True)

    rng = random.Random(18092026)
    null_stats = []
    for index in range(args.nulls):
        null_tokens = {
            length: shuffle_residue(tokens, rng)
            for length, tokens in tokens_by_len.items()
        }
        # Conservacao por nulo: mesmos marcadores, mesma multiset de residuos.
        for length in (83, 84):
            assert marker_bits(null_tokens[length]) == marker_bits(tokens_by_len[length])
            assert Counter(residue(null_tokens[length])) == Counter(residue(tokens_by_len[length]))
        mats = generate_materials(null_tokens)
        assert len(mats) == len(real_materials)
        null_stats.append(run_materials(mats, out_dir, oracle, f"null{index:03d}", write_materials=False))

    null_padding_counts = [item["padding_hits"] for item in null_stats]
    null_semantic_counts = [item["semantic_hits"] for item in null_stats]
    null_key_counts = [item["key_hits"] for item in null_stats]
    summary = {
        "status": "complete",
        "real": real_stats,
        "null": {
            "runs": args.nulls,
            "materials_per_run": len(real_materials),
            "aes_decisions_per_run": real_stats["aes_decisions"],
            "padding_hits": {
                "min": min(null_padding_counts),
                "max": max(null_padding_counts),
                "mean": sum(null_padding_counts) / len(null_padding_counts),
                "real": real_stats["padding_hits"],
                "expected_per_run": real_stats["aes_decisions"] * PKCS7_PADDING_PROBABILITY,
                "expected_model": "sum(256**(-k) for k=1..16), PKCS#7 valid padding",
            },
            "semantic_hits_total": sum(null_semantic_counts),
            "key_hits_total": sum(null_key_counts),
            "max_printable": max(item["max_printable"] for item in null_stats),
        },
        "hard_hits": real_stats["semantic_hits"] + real_stats["key_hits"],
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_report(out_dir, spec, controls, summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
