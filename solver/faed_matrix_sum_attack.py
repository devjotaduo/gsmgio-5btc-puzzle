"""Test the literal FAED 15x38 sum list against AES and the BTC target."""

import hashlib
import sys

import oracles as O
from bip_utils import Bip32Secp256k1, Bip39SeedGenerator
from mnemonic import Mnemonic


PHRASE = "lastwordsbeforearchichoicethispassword"
MAPPINGS = {
    "a0": tuple(range(9)),
    "a1": tuple(range(1, 10)),
    "hint": tuple(map(int, "256134789")),
}
MNEMONIC = Mnemonic("english")
PASSPHRASES = (
    "", "BTCSEED", "btcseed", "matrixsumlist", PHRASE,
    "lastwordsbeforearchichoice", "thispassword", "enter",
    "yellowblueprimes", "yinyang", "bothbeginningandend",
    "wewontgiveawaythepassworditsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
    "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang",
)


def layouts(text, width):
    rows = [text[index:index + width] for index in range(0, len(text), width)]
    yield "forward", rows
    yield "reverse", [row[::-1] for row in rows[::-1]]
    yield "rows-reversed", rows[::-1]
    yield "columns-reversed", [row[::-1] for row in rows]


def sum_lists(rows, values):
    grid = [[values[ord(char) - ord("a")] for char in row] for row in rows]
    yield "rows", [sum(row) for row in grid]
    yield "columns", [sum(grid[row][column] for row in range(len(grid)))
                      for column in range(len(grid[0]))]


def materials(sums):
    for separator in ("", ",", " ", "-"):
        yield separator.join(map(str, sums)).encode()
    if max(sums) < 256:
        yield bytes(sums)
    yield b"".join(value.to_bytes(2, "big") for value in sums)
    yield b"".join(value.to_bytes(2, "little") for value in sums)
    yield "".join(chr(ord("a") + value % 26) for value in sums).encode()
    yield "".join(str(value % 10) for value in sums).encode()
    if len(sums) == len(PHRASE):
        for direction in (-1, 1):
            yield "".join(
                chr(ord("a") + ((ord(char) - ord("a")) + direction * value) % 26)
                for char, value in zip(PHRASE, sums)
            ).encode()


def passwords(material):
    for value in {material, material.lower(), material.upper()}:
        yield value
        yield hashlib.sha256(value).hexdigest().encode()
        yield hashlib.sha256(value).digest()
        for prefix in (b"matrixsumlist", PHRASE.encode()):
            joined = prefix + value
            yield joined
            yield hashlib.sha256(joined).hexdigest().encode()


def mnemonic_from_sums(sums):
    """Keep the 160 entropy bits and repair only the five BIP39 checksum bits."""
    words = [O.WORDLIST[index] for index in sums]
    group = sums[-1] & ~31
    valid = []
    for index in range(group, group + 32):
        candidate = words[:-1] + [O.WORDLIST[index]]
        if MNEMONIC.check(" ".join(candidate)):
            valid.append(candidate)
    assert len(valid) == 1
    return valid[0]


def hash160(value):
    return hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest()


def matching_path(root, limit=1000):
    target = bytes.fromhex(O.TARGET_H160)

    def matches(node):
        public = node.PublicKey()
        return target in (
            hash160(public.RawCompressed().ToBytes()),
            hash160(public.RawUncompressed().ToBytes()),
        )

    if matches(root):
        return "m"
    bases = [(root, "m")]
    for account in range(10):
        for change in (0, 1):
            path = f"m/44'/0'/{account}'/{change}"
            bases.append((root.DerivePath(path), path))
    for path in ("m/0", "m/0'"):
        bases.append((root.DerivePath(path), path))
    for base, path in bases:
        for index in range(limit):
            if matches(base.DerivePath(str(index))):
                return f"{path}/{index}"
    for index in range(limit):
        if matches(root.DerivePath(f"{index}'")):
            return f"m/{index}'"
    return None


def bitcoin_sweep(sums):
    original = " ".join(O.WORDLIST[index] for index in sums)
    words = mnemonic_from_sums(sums)
    mnemonic = " ".join(words)
    entropy = bytes(MNEMONIC.to_entropy(mnemonic))
    seeds = [(f"bip39:{passphrase!r}", Bip39SeedGenerator(mnemonic).Generate(passphrase))
             for passphrase in PASSPHRASES]
    seeds.extend(
        (f"unchecked-bip39:{passphrase!r}", hashlib.pbkdf2_hmac(
            "sha512", original.encode(), ("mnemonic" + passphrase).encode(), 2048
        ))
        for passphrase in PASSPHRASES
    )
    seeds.extend((
        ("raw-entropy", entropy),
        ("sha256-entropy", hashlib.sha256(entropy).digest()),
    ))
    for name, seed in seeds:
        path = matching_path(Bip32Secp256k1.FromSeed(seed))
        if path:
            return {"seed": name, "path": path, "mnemonic": mnemonic,
                    "original": original}
    return {"seed": None, "path": None, "mnemonic": mnemonic,
            "original": original}


def main():
    faed = O.sources()["faed"]
    assert len(faed) == 15 * len(PHRASE)
    rows = [faed[index:index + len(PHRASE)]
            for index in range(0, len(faed), len(PHRASE))]
    canonical_sums = [sum(ord(char) - ord("a") for char in row)
                      for row in rows]
    assert canonical_sums[0] == 140 and canonical_sums[-1] == 163
    bitcoin = bitcoin_sweep(canonical_sums)
    print(f"row_sums={canonical_sums}")
    print(f"bip39={bitcoin}")
    seen = set()
    padding_hits = []
    for width in (15, len(PHRASE)):
        for layout_name, rows in layouts(faed, width):
            for mapping_name, values in MAPPINGS.items():
                for axis, sums in sum_lists(rows, values):
                    for material in materials(sums):
                        for password in passwords(material):
                            if password in seen:
                                continue
                            seen.add(password)
                            for hit in O.aes_open(password, which=("SMALL",), min_ascii=0.0):
                                padding_hits.append((hit["ascii"], width, layout_name,
                                                     mapping_name, axis, material, hit))
    padding_hits.sort(reverse=True, key=lambda item: item[0])
    print(f"passwords={len(seen)} padding_hits={len(padding_hits)}")
    for hit in padding_hits[:20]:
        print(hit)
    if not any(hit[0] >= 0.85 for hit in padding_hits) and not bitcoin["path"]:
        print("no semantic plaintext (ASCII >= 0.85)")
        return 0
    print("possible semantic hit")
    return 1


if __name__ == "__main__":
    sys.exit(main())
