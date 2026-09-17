# -*- coding: utf-8 -*-
"""Forense do segmento EBCDIC/Beaufort da fase 3.2 (bytes crus do plaintext AES).
Hipotese: bytes = latin1(cp273/1141.decode(ascii_letras)). Verifica mapa, alfabeto de 26 simbolos, se ha
simbolo fora do conjunto, Beaufort independente com THEMATRIXHASYOU, comparacao com README (glifos cp866 e
string de letras), e diff LETRA-a-LETRA contra o roteiro do filme."""
import sys, os, re, json, collections, difflib, hashlib
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
OUT = os.path.dirname(os.path.abspath(__file__))
p = open(os.path.join(OUT, "fase32_plain.bin"), "rb").read()
lines = p.split(b"\r\n")
seg = lines[4]; assert len(seg) == 1539
print("segmento: offset", p.index(seg), "len", len(seg))

# ---- (5a) mapa ascii-letra -> byte via cp273 (EBCDIC alemao = 1141 sem euro)
def enc_map(codec):
    m = {}
    for c in "abcdefghijklmnopqrstuvwxyz":
        u = bytes([ord(c)]).decode(codec)      # interpreta byte ASCII como EBCDIC
        try: m[c] = u.encode("latin-1")[0]
        except UnicodeEncodeError: m[c] = None
    return m
for codec in ("cp273", "cp037", "cp500"):
    m = enc_map(codec)
    inv = {v: k for k, v in m.items() if v is not None}
    bad = sorted(set(seg) - set(inv))
    print(f"codec {codec}: simbolos do segmento fora do mapa a-z: {[hex(b) for b in bad]}  (mapa None: {[k for k,v in m.items() if v is None]})")
    if not bad:
        letters = "".join(inv[b] for b in seg)
        break
m = enc_map("cp273"); inv = {v: k for k, v in m.items()}
print("mapa cp273 a-z ->", {k: hex(v) for k, v in m.items()})
cnt = collections.Counter(seg)
print("distintos no segmento:", len(cnt), "=", sorted(hex(b) for b in cnt))
letters = "".join(inv[b] for b in seg)
print("letras[:60] =", letters[:60])
# compara com string de letras do README
readme = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
i = readme.index("The first blob (")
rl = [l for l in readme[i:].splitlines() if re.fullmatch(r"[a-z]{100,}", l.strip())][0].strip()
print("README letras: len", len(rl), "igual ao meu decode:", rl == letters)
if rl != letters:
    for k, (a, b) in enumerate(zip(rl, letters)):
        if a != b: print("  diff @", k, a, b)
# glifos cp866 vs README
gl866 = seg.decode("cp866"); gl437 = seg.decode("cp437")
i2 = readme.index("╬╚,╬°%_")
rg = readme[i2:i2 + 1539]
print("glifos README == cp866:", rg == gl866, "| == cp437:", rg == gl437)
if rg != gl866:
    d = [(k, a, b, hex(seg[k])) for k, (a, b) in enumerate(zip(rg, gl866)) if a != b]
    print("  difs glifo (pos, readme, cp866, byte):", d[:20], "total", len(d))

# ---- (5b) Beaufort independente: P = (K - C) mod 26
KEY = "THEMATRIXHASYOU"
def beaufort(ct, key):
    return "".join(chr((ord(k) - ord(c)) % 26 + 65) for c, k in zip(ct.upper(), (key[i % len(key)] for i in range(len(ct)))))
pt = beaufort(letters, KEY)
print("Beaufort[:80] =", pt[:80])
# controle positivo: cifrar e reabrir
enc = "".join(chr((ord(k) - ord(c)) % 26 + 65) for c, k in zip(pt, (KEY[i % 15] for i in range(len(pt)))))
assert enc == letters.upper()
# texto do README (formatado) sem formatacao
i3 = readme.index("YOUR LIFE IS THE SUM")
rt = readme[i3:readme.index("```", i3)]
rt_flat = re.sub(r"[^A-Z]", "", rt.upper())
print("README texto flat len", len(rt_flat), "== Beaufort:", rt_flat == pt)
if rt_flat != pt:
    for k, (a, b) in enumerate(zip(rt_flat, pt)):
        if a != b: print("  diff @", k, a, b); break
open(os.path.join(OUT, "beaufort_pt.txt"), "w").write(pt)
open(os.path.join(OUT, "beaufort_ct_letters.txt"), "w").write(letters)

# ---- (5c) estatistica: posicoes dos 9 simbolos ASCII (bytes <0x80) dentro do segmento — algum padrao?
asc_pos = [k for k, b in enumerate(seg) if b < 0x80]
print("bytes ASCII no segmento:", len(asc_pos), "letras correspondentes:", collections.Counter(inv[seg[k]] for k in asc_pos))
# paridade / bit alto como fluxo binario: 1539 bits -> ver se e' algo (controle: Beaufort ct e' pseudo-aleatorio)
bits = "".join("1" if b >= 0x80 else "0" for b in seg)
print("bit-alto como binario: 1s =", bits.count("1"), "0s =", bits.count("0"))
by8 = bytes(int(bits[k:k+8], 2) for k in range(0, 1536, 8))
print("  8-bit printable frac:", round(G.printable(by8), 3), by8[:32])
by7 = bytes(int(bits[k:k+7], 2) for k in range(0, 1533, 7))
print("  7-bit printable frac:", round(G.printable(by7), 3), by7[:32])

# ---- (6) diff LETRA a LETRA vs roteiro do filme
FILM = """Your life is the sum of a remainder of an unbalanced equation inherent to the programming of the matrix.
You are the eventuality of an anomaly, which, despite my sincerest efforts, I have been unable to eliminate
from what is otherwise a harmony of mathematical precision. While it remains a burden to sedulously avoid
it, it is not unexpected, and thus not beyond a measure of control. Which has led you, inexorably, here.
You haven't answered my question. Quite right. Interesting. That was quicker than the others.
Bullshit. Denial is the most predictable of all human responses, but rest assured, this will be the sixth
time we have destroyed it, and we have become exceedingly efficient at it.
The function of the One is now to return to the source, allowing a temporary dissemination of the code you
carry, reinserting the prime program. After which, you will be required to select from the matrix 23
individuals, 16 female, 7 male, to rebuild Zion. Failure to comply with this process will result in a
cataclysmic system crash, killing everyone connected to the matrix, which, coupled with the extermination
of Zion, will ultimately result in the extinction of the entire human race."""
# palavras
def W(t): return re.sub(r"[^A-Z0-9' ]", " ", t.upper().replace("-", " ")).split()
pw_, fw_ = W(rt), W(FILM)
sm = difflib.SequenceMatcher(a=fw_, b=pw_, autojunk=False)
dev = []
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag != "equal": dev.append((tag, " ".join(fw_[i1:i2]), " ".join(pw_[j1:j2]), j1))
print("\n=== desvios palavra (filme -> puzzle) ===")
for d in dev: print(" ", d)
# letras: diff nas letras planas
ff = re.sub(r"[^A-Z]", "", FILM.upper())
sm2 = difflib.SequenceMatcher(a=ff, b=pt, autojunk=False)
ins, dele, rep = [], [], []
for tag, i1, i2, j1, j2 in sm2.get_opcodes():
    if tag == "insert": ins.append((j1, pt[j1:j2]))
    elif tag == "delete": dele.append((i1, ff[i1:i2]))
    elif tag == "replace": rep.append((i1, ff[i1:i2], j1, pt[j1:j2]))
print("\n=== diff letra (filme->puzzle) ===")
print("inseridas:", ins); print("removidas:", dele); print("trocadas:", rep)
json.dump({"word_dev": dev, "ins": ins, "del": dele, "rep": rep, "pt": pt, "letters": letters},
          open(os.path.join(OUT, "f2_segment.json"), "w"), indent=1)
