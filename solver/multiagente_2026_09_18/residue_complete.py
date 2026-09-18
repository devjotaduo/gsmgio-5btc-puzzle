"""Completa o espaço finito de resid_decoders sem seleção linguística.

Não importa o programa histórico, não escreve na árvore original e não faz rede.
Somente duas mudanças de hipótese: marcador identificado pela posição prima e
todas as saídas geradas chegam ao oráculo, inclusive as sem quatro letras.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import itertools
import json
import random
import re
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "solver" / "oraculo_duplo_2026_09_17"))
from oracle import ORDER, TARGETS, Oracle, independent_address  # noqa: E402

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SEED = 20260918
HISTORICAL = ROOT / "solver/primos_2026_09_17/resid_decoders.py"
INPUTS = ROOT / "_work/prime_geometry_2026-09-11/inputs.json"
DEFAULT_OUT = ROOT / "_work/multiagente_2026-09-18/residue"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def line(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n"


def constants() -> dict:
    """Lê apenas literais conhecidos via AST; nunca executa/importa o script."""
    wanted = {"ARCH", "M322", "PHRASES", "ALPHA322", "D322"}
    out = {}
    for node in ast.parse(HISTORICAL.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    out[target.id] = ast.literal_eval(node.value)
    if set(out) != wanted:
        raise ValueError("Constantes históricas incompletas")
    return out


def prime(value: int) -> bool:
    return value >= 2 and all(value % d for d in range(2, int(value**0.5) + 1))


def segment(source: str) -> dict[int, tuple[str, ...]]:
    found = {}

    def visit(offset: int, tokens: tuple[str, ...]) -> None:
        if offset == len(source):
            if len(tokens) in found:
                raise ValueError("Mais de uma segmentação com o mesmo comprimento")
            found[len(tokens)] = tokens
            return
        if prime(len(tokens) + 1):
            for token in ("be", "b"):
                if source.startswith(token, offset):
                    visit(offset + len(token), tokens + (token,))
        else:
            visit(offset + 1, tokens + (source[offset],))

    visit(0, ())
    return found


def residue(tokens: tuple[str, ...]) -> str:
    return "".join(t for i, t in enumerate(tokens, 1) if not prime(i))


def views(tokens: tuple[str, ...], *, legacy: bool) -> dict[str, str]:
    maps = {"m0": {"b": "0", "be": "0"},
            "b0be10": {"b": "0", "be": "10"},
            "b0be1": {"b": "0", "be": "1"}}
    return {f"L{len(tokens)}_{name}": "".join(
        mapping.get(t, t) if legacy or prime(i) else t
        for i, t in enumerate(tokens, 1)) for name, mapping in maps.items()}


def group_sizes(tokens: tuple[str, ...]) -> list[int]:
    sizes, current = [], 0
    for i in range(1, len(tokens) + 1):
        if prime(i):
            if current:
                sizes.append(current)
            current = 0
        else:
            current += 1
    if current:
        sizes.append(current)
    return sizes


def digits(source: str) -> list[int]:
    return [int(c) if c.isdigit() else ord(c) - 96 for c in source]


def letters(text: str) -> str:
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def board(alphabet: str, escapes: tuple[int, ...], universe: str) -> dict:
    top = [int(d) for d in universe if int(d) not in escapes]
    need = len(top) + 2 * len(universe)  # Preserva o layout histórico com um escape.
    alphabet = (alphabet + "." * need)[:need]
    codes = [(d,) for d in top] + [(e, int(d)) for e in escapes for d in universe]
    return dict(zip(codes, alphabet))


def checkerboard(source: str, alphabet: str, escapes: tuple[int, ...], universe: str) -> str:
    table, ds, out, offset = board(alphabet, escapes, universe), digits(source), [], 0
    while offset < len(ds):
        width = 2 if ds[offset] in escapes else 1
        if offset + width > len(ds):
            break  # Mesmo tratamento histórico do escape final isolado.
        out.append(table.get(tuple(ds[offset:offset + width]), "?"))
        offset += width
    return "".join(out)


def encode_board(text: str, alphabet: str, escapes: tuple[int, ...], universe: str) -> str:
    inverse = {}
    for code, letter in board(alphabet, escapes, universe).items():
        inverse.setdefault(letter, code)
    return "".join("".join(map(str, inverse[c])) for c in text)


def bifid(source: str, square: str, period: int, mode: str) -> str:
    pos = {c: divmod(i, 3) for i, c in enumerate(square)}
    out = []
    for start in range(0, len(source), period):
        block = source[start:start + period]
        if mode == "decrypt":
            seq = [v for c in block for v in pos[c]]
            out.extend(square[3 * seq[i] + seq[i + len(block)]] for i in range(len(block)))
        else:
            seq = [pos[c][0] for c in block] + [pos[c][1] for c in block]
            out.extend(square[3 * seq[2 * i] + seq[2 * i + 1]] for i in range(len(block)))
    return "".join(out)


def pairs(source: str, row: Callable, col: Callable, alphabet: str, offset: int) -> str:
    ds = digits(source)[offset:]
    return "".join(alphabet[row(ds[i]) * 3 + col(ds[i + 1])]
                   for i in range(0, len(ds) - 1, 2))


def grouped_digits(source: str, width: int, offset: int, mode: str) -> str:
    text = "".join(map(str, digits(source)))[offset:]
    ns = [int(text[i:i + width]) for i in range(0, len(text) - width + 1, width)]
    if mode == "le26":
        return "".join(AZ[n - 1] if 1 <= n <= 26 else "" for n in ns)
    return "".join(AZ[(n - (mode == "a1z26")) % 26] for n in ns)


def marker_groups(source: str, sizes: list[int], mode: str) -> str:
    offset, out = 0, []
    for size in sizes:
        ds = digits(source[offset:offset + size])
        offset += size
        value = sum(ds) if mode == "sum" else int("".join(map(str, ds)))
        if mode in ("sum", "a1z26"):
            out.append(AZ[(value - 1) % 26])
        elif mode == "a0z25":
            out.append(AZ[value % 26])
        else:
            out.append(AZ[ds[0 if mode == "first" else -1] - 1])
    return "".join(out)


def base_text(source: str, in_base: int, alphabet: str) -> str:
    ds = digits(source)
    number = int("".join(map(str, ds))) if in_base == 10 else int("".join(str(x - 1) for x in ds), 9)
    out = []
    while number:
        number, rem = divmod(number, len(alphabet))
        out.append(alphabet[rem])
    return "".join(out[::-1]) if out else alphabet[0]


def index_select(source: str, text: str, unit: str, mode: str) -> str:
    ds = digits(source)
    items = letters(text) if unit == "letters" else [letters(w) for w in text.split() if letters(w)]
    size, out, pointer = len(items), [], 0
    if mode == "abs":
        out = [items[x - 1] for x in ds if 1 <= x <= size]
    elif mode in ("cum", "cum0"):
        for x in ds:
            pointer = (pointer + x) % size
            out.append(items[pointer - (mode == "cum")])
    elif mode == "nth":
        out = [word[(x - 1) % len(word)] for x, word in zip(ds, items)]
    elif mode == "skip":
        for x in ds:
            pointer += x
            if pointer > size:
                break
            out.append(items[pointer - 1])
    return ("" if unit == "letters" else " ").join(out)


@dataclass(frozen=True)
class Model:
    family: str
    config: str
    input_name: str
    source: str
    decode: Callable[[str], str]

    @property
    def identity(self) -> str:
        return f"{self.family}|{self.config}|{self.input_name}"


def models(segs: dict, const: dict, *, legacy: bool = False) -> Iterator[Model]:
    """Replica as 23.164 configurações reais, sem executar o script histórico."""
    rs = {f"R{n}": residue(segs[n]) for n in (84, 83)}
    rs.update({name + "r": value[::-1] for name, value in list(rs.items())})
    seq = {name: value for n in (83, 84) for name, value in views(segs[n], legacy=legacy).items()}
    alphas = {"AZ": AZ, "AZ_noJ": AZ.replace("J", ""), "AZ.": AZ + ".",
              "alpha322": const["ALPHA322"], "alpha322_nodot": const["ALPHA322"].replace(".", "")}
    for phrase in const["PHRASES"]:
        seen = "".join(dict.fromkeys(phrase.upper()))
        alphas[f"key:{phrase}"] = seen + "".join(c for c in AZ if c not in seen)
        alphas[f"key.:{phrase}"] = seen + "." + "".join(c for c in AZ if c not in seen)
    cb_inputs = [(n, s, "123456789") for n, s in rs.items()]
    cb_inputs += [(n, s, "0123456789") for n, s in {**rs, **seq}.items()]
    for name, source, universe in cb_inputs:
        escapes = [(int(e),) for e in universe] + list(itertools.combinations(map(int, universe), 2))
        for es in escapes:
            for an, alpha in alphas.items():
                yield Model("cb", f"esc{es}|{universe[0]}-9|{an}", name, source,
                            lambda s, a=alpha, e=es, u=universe: checkerboard(s, a, e, u))
    rank = "".join(c for c, _ in sorted(Counter(rs["R84"]).items(), key=lambda x: (-x[1], x[0])))
    rankmap = dict(zip(rank, "ETAOINSHR"))
    a9 = {"ETAOINSHR": "ETAOINSHR", "ETAOINSHR@dbifhcega":
          "".join("ETAOINSHR"["dbifhcega".index(c)] for c in "abcdefghi")}
    coords = {"d%3": lambda d: d % 3, "(d-1)%3": lambda d: (d - 1) % 3,
              "(d-1)//3": lambda d: ((d - 1) // 3) % 3}
    for name, source in {**rs, "L84_m0": seq["L84_m0"], "L83_m0": seq["L83_m0"]}.items():
        for offset, (fn, f), (gn, g), (an, alpha) in itertools.product(
                (0, 1), coords.items(), coords.items(), a9.items()):
            yield Model("poly3", f"row={fn}|col={gn}|{an}|off{offset}", name, source,
                        lambda s, f=f, g=g, a=alpha, o=offset: pairs(s, f, g, a, o))
    squares = {"abcdefghi": "abcdefghi", "dbifhcega": "dbifhcega", "rank": rank}
    for name, source in rs.items():
        for (sn, square), period, mode, mapping in itertools.product(
                squares.items(), range(1, len(source) + 1), ("decrypt", "encrypt"), ("sqidx", "rank")):
            def decode(s: str, q: str = square, p: int = period, m: str = mode,
                       om: str = mapping, rm: dict = rankmap) -> str:
                result = bifid(s, q, p, m)
                return "".join("ETAOINSHR"[q.index(c)] if om == "sqidx" else rm[c] for c in result)
            yield Model("bifid3", f"sq={sn}|p={period}|{mode}|{mapping}", name, source, decode)
        yield Model("mono_rank", "rank->ETAOINSHR", name, source,
                    lambda s, rm=rankmap: "".join(rm[c] for c in s))
    for name, source in {**rs, **seq}.items():
        for width in (2, 3):
            for offset, mode in itertools.product(range(width), ("a1z26", "a0z25", "le26")):
                yield Model("digits", f"k={width}|off{offset}|{mode}", name, source,
                            lambda s, w=width, o=offset, m=mode: grouped_digits(s, w, o, m))
    for size in (83, 84):
        for mode, reverse in itertools.product(("a1z26", "a0z25", "sum", "first", "last"), (False, True)):
            name = f"R{size}" + ("r" if reverse else "")
            yield Model("groups", f"L{size}|{mode}", name, rs[name],
                        lambda s, sizes=group_sizes(segs[size]), m=mode: marker_groups(s, sizes, m))
    for name, source in rs.items():
        yield Model("a1z26_direct", "identity", name, source, str.upper)
        alphabets = {"26a": AZ, "26b": AZ[-1:] + AZ[:-1], "27": " " + AZ,
                     "27z": AZ + " ", "36": "0123456789" + AZ, "36z": AZ + "0123456789"}
        for in_base, (an, alpha) in itertools.product((10, 9), alphabets.items()):
            yield Model("base", f"in{in_base}|out{an}", name, source,
                        lambda s, b=in_base, a=alpha: base_text(s, b, a))
    texts = {"P1": "lastwordsbeforearchichoicethispassword", "ARCH": const["ARCH"], "M322": const["M322"]}
    for (name, source), (tn, text), unit in itertools.product(rs.items(), texts.items(), ("letters", "words")):
        for mode in ("abs", "cum", "cum0", "skip") + (("nth",) if unit == "words" else ()):
            yield Model("index", f"{tn}|{unit}|{mode}", name, source,
                        lambda s, t=text, u=unit, m=mode: index_select(s, t, u, m))


def forms(output: str) -> dict[str, bytes]:
    # Exatamente as seis formas do programa anterior, antes de raw/SHA256.
    text = output.replace("?", "")
    return {"output": text.encode(), "lower": text.lower().encode(), "upper": text.upper().encode(),
            "letters": letters(text).encode(), "letters_lower": letters(text).lower().encode(),
            "dots_to_spaces": text.replace(".", " ").strip().encode()}


def evp(password: bytes, salt: bytes, digest: str) -> tuple[bytes, bytes]:
    material, previous = b"", b""
    while len(material) < 48:
        previous = hashlib.new(digest, previous + password + salt).digest()
        material += previous
    return material[:32], material[32:48]


def decrypt(password: bytes, blob: dict, digest: str) -> bytes | None:
    key, iv = evp(password, bytes.fromhex(blob["salt"]), digest)
    body = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes.fromhex(blob["ciphertext"]))
    pad = body[-1]
    return body[:-pad] if 1 <= pad <= 16 and body.endswith(bytes([pad]) * pad) else None


def semantic(body: bytes) -> dict:
    """Triagem, não declaração de solução; inclui a assinatura histórica real."""
    printable = sum(32 <= b < 127 for b in body) / max(1, len(body))
    allowed = {ord(c.encode().decode("cp273")) for c in "abcdefghijklmnopqrstuvwxyz"}
    high = [b for b in body if b >= 128]
    ebcdic = sum(b in allowed for b in high) / len(high) if len(high) >= 8 else 0.0
    nested = b"Salted__" in body or b"U2FsdGVk" in body
    return {"printable": printable, "phase32_ebcdic": ebcdic, "nested_marker": nested,
            "review": printable >= 0.85 or ebcdic >= 0.75 or nested}


def set_fingerprint(values: set[bytes]) -> str:
    digest = hashlib.sha256()
    for value in sorted(values):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def controls(data: dict, const: dict, segs: dict) -> dict:
    decoded = checkerboard(const["D322"], const["ALPHA322"], (1, 4), "0123456789")
    assert decoded == const["M322"].replace(" ", "")
    assert encode_board(decoded, const["ALPHA322"], (1, 4), "0123456789") == const["D322"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("U2FsdGVkX18GKGYS")
    b64 = []
    for row in readme[start:].splitlines():
        if not re.fullmatch(r"[A-Za-z0-9+/=]{4,64}", row.strip()):
            break
        b64.append(row.strip())
    raw = base64.b64decode("".join(b64), validate=True)
    blob = {"salt": raw[8:16].hex(), "ciphertext": raw[16:].hex()}
    phase2 = decrypt(sha(b"causality").encode(), blob, "sha256")
    assert phase2 is not None and phase2.startswith(b"The ironic")
    assert decrypt(sha(b"causality").encode(), blob, "md5") is None
    positions = {}
    for size, tokens in segs.items():
        positions[size] = [i for i, t in enumerate(tokens, 1) if t == "b" and not prime(i)]
        assert positions[size]
        fixed, old = views(tokens, legacy=False), views(tokens, legacy=True)
        for i in positions[size]:
            assert fixed[f"L{size}_m0"][i - 1] == "b" and old[f"L{size}_m0"][i - 1] == "0"
        for width in range(1, size):
            source = residue(tokens)
            assert bifid(bifid(source, "abcdefghi", width, "encrypt"), "abcdefghi", width, "decrypt") == source
    synthetic_board_text = "".join(("QZXJKV",) * 3)
    encoded = encode_board(synthetic_board_text, AZ, (1, 4), "0123456789")
    candidate = checkerboard(encoded, AZ, (1, 4), "0123456789")
    assert candidate == synthetic_board_text and candidate.encode() in forms(candidate).values()
    secret = hashlib.sha256(b"residue-completion-planted-non-English").digest()
    salt, plaintext = b"finite18", b"control!" + secret
    pad = 16 - len(plaintext) % 16
    for digest in ("sha256", "md5"):
        key, iv = evp(candidate.encode(), salt, digest)
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext + bytes([pad]) * pad)
        recovered = decrypt(candidate.encode(), {"salt": salt.hex(), "ciphertext": ciphertext.hex()}, digest)
        assert recovered == plaintext
        fake = Oracle(tuple(independent_address(secret, c) for c in (False, True)))
        assert {h["address"] for h in fake.scan(recovered)["hits"]} == set(fake.targets)
    return {"phase2_sha256": sha(phase2), "phase2_wrong_kdf_rejected": True,
            "checkerboard_exact": True, "b_nonprime_positions": positions,
            "bifid_roundtrips": True, "non_English_planted_both_KDFs_both_addresses": True}


def generate(segs: dict, const: dict, out: Path) -> tuple[dict, dict]:
    legacy = {m.identity: m.decode(m.source) for m in models(segs, const, legacy=True)}
    current = list(models(segs, const))
    assert len(legacy) == len(current) == 23164
    assert len({m.identity for m in current}) == len(current)
    materials, old_materials, by_form = {}, set(), defaultdict(set)
    changed, family_counts, empty = 0, Counter(), 0
    with (out / "outputs.jsonl").open("x", encoding="utf-8") as handle:
        for model in current:
            decoded = model.decode(model.source)
            old = legacy[model.identity]
            changed += decoded != old
            empty += not decoded
            family_counts[model.family] += 1
            for value in forms(old).values():
                if value:
                    old_materials.add(value)
            handle.write(line({"model": model.identity, "input_sha256": sha(model.source.encode()),
                               "output": decoded, "legacy_output_sha256": sha(old.encode()),
                               "mask_changed_output": decoded != old}))
            for form, value in forms(decoded).items():
                if not value:
                    continue
                by_form[form].add(value)
                materials.setdefault(value, []).append({"model": model.identity, "form": form})
    passwords = {}
    with (out / "materials.jsonl").open("x", encoding="utf-8") as handle:
        for value, origins in sorted(materials.items()):
            ident = sha(value)
            handle.write(line({"id": ident, "hex": value.hex(), "origins": origins}))
            for form, password in (("raw", value), ("sha256hex", ident.encode())):
                passwords.setdefault(password, []).append({"material": ident, "form": form})
    with (out / "passwords.jsonl").open("x", encoding="utf-8") as handle:
        for password, origins in sorted(passwords.items()):
            handle.write(line({"id": sha(password), "hex": password.hex(), "origins": origins}))
    coverage = {"decoder_configurations": len(current), "family_counts": family_counts,
                "changed_outputs_from_position_fix": changed, "empty_outputs": empty,
                "materials": len(materials), "passwords": len(passwords), "AES_decisions": len(passwords) * 6,
                "legacy_generated_materials_without_gate": len(old_materials),
                "material_intersection_with_legacy_generator": len(set(materials) & old_materials),
                "new_materials_from_position_fix": len(set(materials) - old_materials),
                "legacy_materials_not_generated_after_fix": len(old_materials - set(materials)),
                "legacy_generated_set_sha256": set_fingerprint(old_materials),
                "corrected_material_set_sha256": set_fingerprint(set(materials)),
                "password_set_sha256": set_fingerprint(set(passwords)),
                "forms": {name: {"count": len(values), "set_sha256": set_fingerprint(values)}
                          for name, values in sorted(by_form.items())},
                "historical_report": {"scored_configurations": 23114, "passwords_actually_tested": 680,
                                      "AES_decisions": 4080, "padding_records": 15},
                "historical_overlap_limit": "Legacy generator means all generated forms, not the actual historical top-20 corpus. The complete 680-password set was not preserved; no exact old/new AES subtraction is claimed."}
    return coverage, passwords


def shuffle_segs(segs: dict, rng: random.Random) -> dict:
    result = {}
    for size, tokens in segs.items():
        pool = list(residue(tokens))
        rng.shuffle(pool)
        iterator = iter(pool)
        result[size] = tuple(t if prime(i) else next(iterator) for i, t in enumerate(tokens, 1))
    return result


def null_controls(segs: dict, const: dict, data: dict, out: Path, count: int) -> dict:
    """100 nulos casados: oito configurações fixas por família, todas as formas."""
    grouped = defaultdict(list)
    for model in models(segs, const):
        grouped[model.family].append(model.identity)
    selected = set()
    for family in sorted(grouped):
        ids = sorted(grouped[family])
        selected.update(ids[i * (len(ids) - 1) // (min(8, len(ids)) - 1)] for i in range(min(8, len(ids))))
    totals = Counter()
    started, rng = time.monotonic(), random.Random(SEED)
    with (out / "null.jsonl").open("x", encoding="utf-8") as handle, \
            (out / "null_padding.jsonl").open("x", encoding="utf-8") as padfile:
        for trial in range(count):
            shuffled = shuffle_segs(segs, rng)
            passwords = set()
            for model in models(shuffled, const):
                if model.identity in selected:
                    for value in forms(model.decode(model.source)).values():
                        if value:
                            passwords.update((value, sha(value).encode()))
            paddings, reviews, max_printable = 0, 0, 0.0
            for password in sorted(passwords):
                for name, digest in itertools.product(data["blobs"], ("sha256", "md5")):
                    body = decrypt(password, data["blobs"][name], digest)
                    if body is not None:
                        paddings += 1
                        info = semantic(body)
                        reviews += info["review"]
                        max_printable = max(max_printable, info["printable"])
                        padfile.write(line({"trial": trial, "password_id": sha(password), "blob": name,
                                            "kdf": digest, "hex": body.hex(), **info}))
            record = {"trial": trial, "passwords": len(passwords), "AES_decisions": 6 * len(passwords),
                      "password_set_sha256": set_fingerprint(passwords),
                      "paddings": paddings, "semantic_reviews": reviews, "max_printable": max_printable}
            handle.write(line(record))
            totals.update({k: v for k, v in record.items() if k in ("AES_decisions", "paddings", "semantic_reviews")})
            if (trial + 1) % 20 == 0:
                print(line({"stage": "null", "completed": trial + 1, "seconds": round(time.monotonic() - started, 2)}), flush=True)
    return {"replicas": count, "seed": SEED, "selected_configurations": sorted(selected), **totals,
            "scope": "Stratified fixed sample of up to eight configurations per family; nonprime symbols shuffled with counts preserved and prime markers fixed. No whole-search p-value or ECC null claim.",
            "seconds": round(time.monotonic() - started, 2)}


def numeric_scalars(segs: dict) -> Iterator[tuple[str, bytes]]:
    """Os mesmos 60 checks numéricos acessórios do script histórico."""
    for size, tokens in segs.items():
        for reverse in (False, True):
            source = residue(tokens)[::-1] if reverse else residue(tokens)
            ds = digits(source)
            numbers = {"b58": sum((x - 1) * 58 ** (len(ds) - i - 1) for i, x in enumerate(ds)),
                       "b10": int("".join(map(str, ds))), "b9": int("".join(str(x - 1) for x in ds), 9)}
            for base, number in numbers.items():
                values = {"low32": (number & ((1 << 256) - 1)).to_bytes(32, "big"),
                          "modn": (number % ORDER).to_bytes(32, "big"),
                          "top32": (number >> max(0, number.bit_length() - 256)).to_bytes(32, "big"),
                          "sha": hashlib.sha256(str(number).encode()).digest(),
                          "sha_raw": hashlib.sha256(number.to_bytes((number.bit_length() + 7) // 8, "big")).digest()}
                for form, secret in values.items():
                    yield f"R{size}|reverse={reverse}|{base}|{form}", secret


def authenticate(passwords: dict, data: dict, segs: dict, out: Path) -> dict:
    oracle, started = Oracle(), time.monotonic()
    attempts, paddings, semantic_count, key_hits = 0, 0, 0, 0
    scan_totals, decisions = Counter(), hashlib.sha256()
    seen_scalars, seen_payloads = set(), set()
    with (out / "padding.jsonl").open("x", encoding="utf-8") as padfile, \
            (out / "hits.jsonl").open("x", encoding="utf-8") as hitfile:
        numeric_count = 0
        for provenance, secret in numeric_scalars(segs):
            numeric_count += 1
            seen_scalars.add(secret)
            for hit in oracle.check(secret):
                key_hits += 1
                hitfile.write(line({"kind": "numeric_scalar", "provenance": provenance, **hit}))
        assert numeric_count == 60
        for index, password in enumerate(sorted(passwords), 1):
            ident = sha(password)
            secret = bytes.fromhex(ident)
            if secret not in seen_scalars:
                seen_scalars.add(secret)
                for hit in oracle.check(secret):
                    key_hits += 1
                    hitfile.write(line({"kind": "sha256_password", "password_id": ident, **hit}))
            for name, digest in itertools.product(data["blobs"], ("sha256", "md5")):
                attempts += 1
                body = decrypt(password, data["blobs"][name], digest)
                decisions.update(line([ident, name, digest, sha(body) if body is not None else None]).encode())
                if body is None:
                    continue
                paddings += 1
                info = semantic(body)
                semantic_count += info["review"]
                record = {"password_id": ident, "blob": name, "kdf": digest,
                          "length": len(body), "hex": body.hex(), **info}
                if body not in seen_payloads:
                    seen_payloads.add(body)
                    result = oracle.scan(body)
                    scan_totals.update(result["attempts"])
                    for hit in result["hits"]:
                        key_hits += 1
                        hitfile.write(line({"kind": "padding", "password_id": ident, "blob": name, **hit}))
                    record["key_hits"] = len(result["hits"])
                padfile.write(line(record))
            if index % 10000 == 0:
                print(line({"stage": "AES", "passwords": index, "padding": paddings,
                            "seconds": round(time.monotonic() - started, 2)}), flush=True)
    return {"AES_decisions": attempts, "padding_records": paddings,
            "unique_padding_payloads": len(seen_payloads), "numeric_scalar_records": numeric_count,
            "unique_numeric_and_sha256_password_scalars": len(seen_scalars),
            "padding_private_key_attempts": scan_totals, "semantic_review_records": semantic_count,
            "private_key_hits": key_hits, "decisions_sha256": decisions.hexdigest(),
            "seconds": round(time.monotonic() - started, 2)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--run", action="store_true", help="Executar após preparar; sem flag somente prepara")
    parser.add_argument("--null-count", type=int, default=100)
    args = parser.parse_args()
    if args.null_count < 100:
        parser.error("Exige pelo menos 100 nulos casados")
    out = args.out.resolve()
    if ROOT not in out.parents:
        parser.error("O destino precisa estar dentro desta worktree")
    out.mkdir(parents=True, exist_ok=False)
    data, const = json.loads(INPUTS.read_text(encoding="utf-8")), constants()
    segs = segment(data["dbbi"])
    assert set(segs) == {83, 84}
    source_hashes = {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in (
        Path(__file__), HISTORICAL, INPUTS, ROOT / "README.md",
        ROOT / "solver/oraculo_duplo_2026_09_17/oracle.py")}
    hypothesis = {
        "hypothesis": "A senha correta pode ser saída não linguística de uma configuração já declarada, antes excluída pelo gate top-20; ou resultado de manter b não primo na máscara correta.",
        "scope": "Exact historical decoder/configuration enumeration and six normalizations; only position-aware marker substitution and removal of score/top-20 gates. Three original blobs, EVP-SHA256/MD5, raw and lowercase SHA256-hex passwords. Full padding retained and scanned at both isolated P2PKH targets.",
        "limitations": "Keeps historical lossy decoder rules: trailing escape dropped, invalid codes '?', removal of '?' in forms, modulo mappings and only two selected Polybius output alphabets. No additional codecs or decoder families. Null sample is stratified, not the full search. Legacy generated-set comparison is not proof of the actual old 680-password list.",
        "targets": TARGETS, "source_sha256": source_hashes, "null_count": args.null_count,
        "status": "specified_before_generation"}
    save(out / "spec.json", hypothesis)
    save(out / "controls.json", controls(data, const, segs))
    started = time.monotonic()
    coverage, passwords = generate(segs, const, out)
    coverage["generation_seconds"] = round(time.monotonic() - started, 2)
    save(out / "coverage.json", coverage)
    print(line({"stage": "prepared", **{k: coverage[k] for k in (
        "decoder_configurations", "changed_outputs_from_position_fix", "materials", "passwords", "AES_decisions", "generation_seconds")}}), flush=True)
    if not args.run:
        save(out / "summary.json", {"status": "prepared_only", **coverage})
        return
    null_result = null_controls(segs, const, data, out, args.null_count)
    save(out / "null_summary.json", null_result)
    result = authenticate(passwords, data, segs, out)
    assert result["AES_decisions"] == coverage["AES_decisions"]
    for relative, expected in source_hashes.items():
        if sha((ROOT / relative).read_bytes()) != expected:
            raise ValueError(f"Fonte alterada durante execução: {relative}")
    artifacts = {p.name: sha(p.read_bytes()) for p in out.iterdir() if p.is_file()}
    summary = {"status": "complete", "coverage": coverage, "controls": "passed",
               "null": null_result, "result": result, "artifact_sha256": artifacts}
    save(out / "summary.json", summary)
    print(line({"stage": "complete", **result}), flush=True)


if __name__ == "__main__":
    main()
