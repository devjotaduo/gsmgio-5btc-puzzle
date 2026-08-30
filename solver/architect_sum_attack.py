"""Apply the phase-1 and FAED sum lists to the Architect text."""

import hashlib
import html
import re
import sys
import urllib.request

import oracles as O


URL = "https://www.onebee.com/writing/2003/05/the_architect_scene/"
SUMS = (140, 171, 129, 168, 150, 174, 184, 176, 188, 179, 175, 179, 169, 164, 163)
MATRIX_ROW_SUMS = (6, 10, 8, 7, 6, 6, 5, 4, 9, 9, 7, 8, 7, 9)
MATRIX_COLUMN_SUMS = (8, 10, 8, 10, 8, 7, 3, 6, 7, 5, 9, 6, 6, 8)
STAGE_DIRECTIONS = ("the responses", "again, the responses", "once again",
                    "images of", "neo walks", "the architect presses")


def transcript_corpora():
    raw = urllib.request.urlopen(URL, timeout=20).read().decode("utf-8", "ignore")
    raw = re.sub(r"<(script|style).*?</\1>", "", raw, flags=re.I | re.S)
    raw = re.sub(r"</(?:p|div|li|h[1-6])>|<br\s*/?>", "\n", raw, flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", "", raw))
    lines = [" ".join(line.split()) for line in text.splitlines()]
    lines = [line for line in lines if line]
    start = next(index for index, line in enumerate(lines) if line.startswith("The Architect - Hello"))
    end = next(index for index, line in enumerate(lines[start:], start)
               if line.startswith("The Architect - We won't"))
    spoken = []
    architect = []
    speaker = None
    for line in lines[start:end + 1]:
        if line.startswith("The Architect - "):
            speaker, line = "architect", line.removeprefix("The Architect - ")
        elif line.startswith("Neo - "):
            speaker, line = "neo", line.removeprefix("Neo - ")
        elif line.lower().startswith(STAGE_DIRECTIONS):
            speaker = None
            continue
        if speaker:
            spoken.append(line)
            if speaker == "architect":
                architect.append(line)
    match = re.search(r"YOUR LIFE IS THE SUM.*?CIAO BELLA O", O._readme(), re.S)
    assert match
    return {"spoken": " ".join(spoken), "architect": " ".join(architect),
            "phase-3.2": match.group(0)}


def phase_line_extractions(text):
    before = text.split("SELECT", 1)[0]
    lines = [re.findall(r"[A-Z']+", line) for line in before.splitlines()]
    last_words = [words[-1] for words in lines if words]
    words = re.findall(r"[A-Z']+", before)
    yield "line-last-words", "".join(last_words)
    yield "line-last-letters", "".join(word[-1] for word in last_words)
    yield "last-15-words", "".join(words[-15:])
    yield "last-15-first", "".join(word[0] for word in words[-15:])
    yield "last-15-last", "".join(word[-1] for word in words[-15:])


def paired_extractions(text):
    before = text.split("SELECT", 1)[0]
    lines = [re.findall(r"[A-Z]+", line) for line in before.splitlines()]
    pairs = (
        ("faed", SUMS, re.findall(r"[A-Z]+", before)[-15:]),
        ("matrix-rows", MATRIX_ROW_SUMS, [words[-1] for words in lines if words]),
        ("matrix-columns", MATRIX_COLUMN_SUMS, [words[-1] for words in lines if words]),
    )
    for pair_name, source_sums, words in pairs:
        assert len(words) == len(source_sums)
        for sums_name, sums in (("sums", source_sums),
                                ("sums-reversed", source_sums[::-1])):
            for words_name, ordered in (("words", words), ("words-reversed", words[::-1])):
                yield from paired_word_streams(pair_name, sums_name, sums,
                                               words_name, ordered)


def paired_word_streams(pair_name, sums_name, sums, words_name, words):
    for offset in (0, -1, 17, -17, 41, -41):
        starts = [word[(value + offset) % len(word)] for word, value in zip(words, sums)]
        ends = [word[-((value + offset) % len(word)) - 1]
                for word, value in zip(words, sums)]
        label = f"paired/{pair_name}/{sums_name}/{words_name}/{offset}"
        yield f"{label}/start", "".join(starts)
        yield f"{label}/end", "".join(ends)
        yield f"{label}/yin-yang", "".join(
            start if value % 2 == 0 else end
            for start, end, value in zip(starts, ends, sums)
        )
        yield f"{label}/yang-yin", "".join(
            end if value % 2 == 0 else start
            for start, end, value in zip(starts, ends, sums)
        )


def prefixes(text):
    lower = text.lower()
    offsets = {match.start() for match in re.finditer(r"\b(?:choice|select)\b", lower)}
    doors = lower.find("there are two doors")
    if doors >= 0:
        offsets.add(doors)
    for offset in sorted(offsets):
        yield text[:offset]


def extractions(prefix):
    words = re.findall(r"[a-z]+", prefix.lower())
    compact = "".join(words)
    for order_name, sums in (("forward", SUMS), ("reverse", SUMS[::-1])):
        for base in (0, 1):
            indexes = [value - base for value in sums]
            for side, selected in (
                ("from-start", [words[index] for index in indexes if index < len(words)]),
                ("from-end", [words[-index - 1] for index in indexes if index < len(words)]),
            ):
                if len(selected) == len(sums):
                    yield f"{order_name}/{base}/{side}/words", "".join(selected)
                    yield f"{order_name}/{base}/{side}/first", "".join(word[0] for word in selected)
                    yield f"{order_name}/{base}/{side}/last", "".join(word[-1] for word in selected)
            for side, source in (("chars-start", compact), ("chars-end", compact[::-1])):
                if max(indexes) < len(source):
                    yield f"{order_name}/{base}/{side}", "".join(source[index] for index in indexes)


def password_forms(value):
    for text in {value, value.lower(), value.upper()}:
        raw = text.encode()
        yield "raw", raw
        yield "sha256hex", hashlib.sha256(raw).hexdigest().encode()
        yield "sha256raw", hashlib.sha256(raw).digest()
        for prefix in ("matrixsumlist", "lastwordsbeforearchichoice", "thispassword"):
            joined = (prefix + text).encode()
            yield prefix + "/sha256hex", hashlib.sha256(joined).hexdigest().encode()


def main():
    assert SUMS[0] == 140 and SUMS[-1] == 163
    seen = set()
    candidates = []
    hits = []
    for corpus_name, corpus in transcript_corpora().items():
        for pivot, prefix in enumerate(prefixes(corpus)):
            for extraction, value in extractions(prefix):
                candidates.append((corpus_name, pivot, extraction, value))
                for mode, password in password_forms(value):
                    if password in seen:
                        continue
                    seen.add(password)
                    for hit in O.aes_open(password, which=("SMALL",), min_ascii=0.85):
                        hits.append((corpus_name, pivot, extraction, value, mode, hit))
        if corpus_name == "phase-3.2":
            for extraction, value in (*phase_line_extractions(corpus),
                                      *paired_extractions(corpus)):
                candidates.append((corpus_name, "lines", extraction, value))
                for mode, password in password_forms(value):
                    if password in seen:
                        continue
                    seen.add(password)
                    for hit in O.aes_open(password, which=("SMALL",), min_ascii=0.85):
                        hits.append((corpus_name, "lines", extraction, value, mode, hit))
    print(f"candidates={len(candidates)} passwords={len(seen)} semantic_hits={len(hits)}")
    for candidate in candidates:
        if candidate[1] != "lines" or str(candidate[2]).startswith("paired/"):
            continue
        print(candidate)
    for hit in hits:
        print("HIT", hit)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
