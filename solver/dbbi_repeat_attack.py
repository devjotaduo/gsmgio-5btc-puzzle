"""Test DBBI as the exact repeating 91-symbol keystream over FAED."""

import sys

import oracles as O
from prime_attack import CANON, bifid_decrypt
from scorer import Scorer


PERIODS = (570, 273, 182, 91, 78, 57, 42, 38, 26, 24, 19, 15, 14, 13, 7)


def key_orders(dbbi):
    rows = [dbbi[index:index + 13] for index in range(0, 91, 13)]
    keys = {
        "row": [ord(char) - ord("a") for char in dbbi],
        "row-reversed": [ord(char) - ord("a") for char in dbbi[::-1]],
        "rows-reversed": [ord(char) - ord("a")
                          for char in "".join(row[::-1] for row in rows)],
        "row-order-reversed": [ord(char) - ord("a")
                               for char in "".join(rows[::-1])],
        "column": [ord(rows[row][column]) - ord("a")
                   for column in range(13) for row in range(7)],
    }
    mappings = {
        "a0": tuple(range(9)),
        "a1": tuple(range(1, 10)),
        "hint": tuple(map(int, "256134789")),
    }
    for width in (7, 13):
        matrix = [dbbi[index:index + width] for index in range(0, len(dbbi), width)]
        for mapping_name, values in mappings.items():
            grid = [[values[ord(char) - ord("a")] for char in row] for row in matrix]
            keys[f"sum-{width}-rows-{mapping_name}"] = [sum(row) % 9 for row in grid]
            keys[f"sum-{width}-columns-{mapping_name}"] = [
                sum(grid[row][column] for row in range(len(grid))) % 9
                for column in range(width)
            ]
    return keys


def combine(faed, key, offset, direction):
    return "".join(
        chr(ord("a") + ((ord(char) - ord("a"))
            + direction * key[(index + offset) % len(key)]) % 9)
        for index, char in enumerate(faed)
    )


def main():
    dbbi = O.sources()["dbbi"]
    faed = O.sources()["faed"]
    assert len(faed) == 6 * len(dbbi) + 24
    scorer = Scorer()
    results = []
    for name, key in key_orders(dbbi).items():
        for offset in range(len(key)):
            for direction in (-1, 1):
                transformed = combine(faed, key, offset, direction)
                for text in (transformed, transformed[:6 * len(dbbi)]):
                    for period in PERIODS:
                        if period > len(text):
                            continue
                        plain = bifid_decrypt(text.upper(), CANON, period)
                        results.append((scorer(plain), name, offset, direction,
                                        len(text), period, plain[:90]))
    results.sort(reverse=True)
    print(f"tested={len(results)}")
    for result in results[:20]:
        print(result)
    if results[0][0] < -4.5:
        print("no English signal")
        return 0
    print("possible signal; inspect the top candidate")
    return 1


if __name__ == "__main__":
    sys.exit(main())
