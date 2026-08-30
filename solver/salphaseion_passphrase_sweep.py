"""Test the source-grounded SalPhaseIon passphrase grammar against SMALL."""

import hashlib
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O


ANSWERS = (
    "vat",
    "phase",
    "phase ion",
    "phase inversion",
    "stereo phase inversion",
    "hope",
    "choice",
    "the problem is",
    "problem is",
    "as you adequately put the problem is",
    "the problem is choice",
    "as you adequately put the problem is choice",
    "salvation",
    "salvation of zion",
    "trinity",
    "love",
    "we wont",
    "we won't",
    "the anomaly revealed as both beginning and end",
    "which brings us at last to the moment of truth wherein the fundamental flaw is ultimately expressed and the anomaly revealed as both beginning and end",
    "Which brings us at last to the moment of truth, wherein the fundamental flaw is ultimately expressed, and the anomaly revealed as both beginning, and end.",
    "both beginning and end",
    "beginning and end",
    "the moment of truth",
    "moment of truth",
    "no",
    "vis a vis love",
    "your experience is far more specific vis a vis love",
    "at the cost of her own",
    "all im offering is the truth nothing more",
    "all i'm offering is the truth nothing more",
    "im offering truth",
    "hash the text",
    "enter the matrix",
    "reinsert the prime basics",
    "reinserting the prime basics",
    "after which you will be required to",
    "reinserting the prime basics after which you will be required to",
    "the code you hopefully carry reinserting the prime basics after which you will be required to",
    "allowing a temporary dissemination of the code you hopefully carry reinserting the prime basics after which you will be required to",
    "stop it",
    "source",
    "the source",
    "she is going to die and there is nothing you can do to stop it",
    "the door to your right leads to the source and the salvation of zion",
    "the door to your left leads back to the matrix to her and to the end of your species",
)
FIRST_HINTS = (
    "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
    "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "gsmg.io/theseedisplanted",
    "theseedisplanted",
    "our first hint is your last command",
)


def sources():
    values = {
        "matrixsumlist",
        "enter",
        "lastwordsbeforearchichoice",
        "thispassword",
        "yellowblueprimes",
        "yinyang",
        "wewontgiveawaythepassword",
        "itsinfrontofyoureyesbutyourenotseeingit",
        "verylaststepisatruegiveaway",
        "promised",
        *ANSWERS,
        *FIRST_HINTS,
    }
    for answer in ANSWERS:
        page = ("matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "enter", answer)
        for size in range(2, len(page) + 1):
            values.update("".join(parts) for parts in itertools.permutations(page, size))
        for first_hint in FIRST_HINTS:
            values.update(
                {
                    first_hint + answer,
                    answer + first_hint,
                    "matrixsumlist" + first_hint + answer,
                    "matrixsumlistlastwordsbeforearchichoicethispassword" + first_hint + answer,
                    "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang" + answer,
                }
            )
        values.update(
            {
                "matrixsumlistz" + answer + "zthispasswordz",
                "yellowblueprimesmatrixsumlistz" + answer + "zthispasswordz",
                "yellowblueprimesmatrix sum listz" + answer + "zthispasswordz",
                "matrix sum listz" + answer + "zthispasswordz",
            }
        )
    roadmap = (
        "yellowblueprimes",
        "matrixsumlist",
        "lastwordsbeforearchichoice",
        "yinyang",
        "wewontgiveawaythepassworditsinfrontofyoureyesbutyourenotseeingit",
        "verylaststepisatruegiveawaypromised",
    )
    values.update("".join(roadmap[:size]) for size in range(1, len(roadmap) + 1))
    return values


def passwords(source):
    compact = "".join(character for character in source if character.isalnum())
    for value in {source, source.lower(), source.upper(), compact.lower(), compact.upper()}:
        raw = value.encode()
        digest = hashlib.sha256(raw).digest()
        yield value, "raw", raw
        yield value, "sha256hex", digest.hex().encode()
        yield value, "sha256raw", digest
        yield value, "doublehex", hashlib.sha256(digest.hex().encode()).hexdigest().encode()
        yield value, "doubleraw", hashlib.sha256(digest).digest()


def main():
    candidates = sources()
    assert "matrixsumlistlastwordsbeforearchichoicethispasswordenterhope" in candidates
    seen = set()
    hits = []
    for source in candidates:
        for value, mode, password in passwords(source):
            if password in seen:
                continue
            seen.add(password)
            for hit in O.aes_open(password, which=("SMALL",), min_ascii=0.0):
                hits.append((hit["ascii"], source, value, mode, hit))
    hits.sort(reverse=True, key=lambda row: row[0])
    print(f"sources={len(candidates)} passwords={len(seen)} padding_hits={len(hits)}")
    for hit in hits[:20]:
        print(hit)
    if not any(hit[0] >= 0.85 for hit in hits):
        print("no semantic plaintext (ASCII >= 0.85)")


if __name__ == "__main__":
    main()
