# -*- coding: utf-8 -*-
"""A "segunda via desde o início": outra travessia da matriz 14x14 da fase 1.

Hipótese falsificável
--------------------
Resumo de membro no Telegram (2021-02-13): *"2nd way from start wasnt founded (shared)"*, e o
criador em 2020-01-14: *"Go back to the first puzzle piece without further ado. It might have shown
you only one door, beware that the rabbits nest may contain a whole lot more."* A matriz tem
14x14 = 196 células; a URL `gsmg.io/theseedisplanted` consome 192 bits (24 bytes), logo **sobram 4
células** — as últimas da espiral, no centro, exatamente onde está desenhado o coelho ("o ninho").

Se existe uma segunda porta na mesma imagem, ela é outra ORDEM DE LEITURA das mesmas células.
O espaço é finito e enumerável: espirais nos 4 cantos x 2 sentidos x 2 eixos iniciais, linhas,
colunas, bustrofédon, diagonais, mais reverso, complemento de bits e ordem de bits por byte.
Controle positivo: a travessia conhecida TEM de reproduzir `gsmg.io/theseedisplanted`.
"""
import sys, json, itertools
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G

N = 14
def spiral(start, cw, first_vertical):
    """Espiral a partir de um dos 4 cantos, horária ou anti-horária, começando na vertical ou horizontal."""
    r0, c0 = start
    seen = set(); order = []
    dirs = [(1, 0), (0, 1), (-1, 0), (0, -1)]      # baixo, direita, cima, esquerda
    if not first_vertical: dirs = [(0, 1), (1, 0), (0, -1), (-1, 0)]
    if r0 == N - 1: dirs = [(-d[0], d[1]) for d in dirs]
    if c0 == N - 1: dirs = [(d[0], -d[1]) for d in dirs]
    if cw: dirs = [dirs[0]] + dirs[1:][::-1]
    r, c, d = r0, c0, 0
    for _ in range(N * N):
        order.append((r, c)); seen.add((r, c))
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if not (0 <= nr < N and 0 <= nc < N) or (nr, nc) in seen:
            d = (d + 1) % 4; nr, nc = r + dirs[d][0], c + dirs[d][1]
            if not (0 <= nr < N and 0 <= nc < N) or (nr, nc) in seen: break
        r, c = nr, nc
    return order

def rows(rev=False, boust=False):
    o = []
    for i in range(N):
        rng = range(N - 1, -1, -1) if (boust and i % 2) else range(N)
        o += [(i, j) for j in rng]
    return o[::-1] if rev else o
def cols(rev=False, boust=False):
    o = []
    for j in range(N):
        rng = range(N - 1, -1, -1) if (boust and j % 2) else range(N)
        o += [(i, j) for i in rng]
    return o[::-1] if rev else o
def diags(anti=False):
    o = []
    for s in range(2 * N - 1):
        for i in range(N):
            j = (s - i) if not anti else (N - 1 - (s - i))
            if 0 <= j < N: o.append((i, j))
    return o

TRAV = {}
for start in ((0, 0), (0, N - 1), (N - 1, 0), (N - 1, N - 1)):
    for cw in (False, True):
        for fv in (True, False):
            o = spiral(start, cw, fv)
            if len(o) == N * N: TRAV[f"spiral{start}{'cw' if cw else 'ccw'}{'v' if fv else 'h'}"] = o
for rev in (False, True):
    for b in (False, True):
        TRAV[f"rows{'R' if rev else ''}{'B' if b else ''}"] = rows(rev, b)
        TRAV[f"cols{'R' if rev else ''}{'B' if b else ''}"] = cols(rev, b)
TRAV["diag"] = diags(False); TRAV["antidiag"] = diags(True)
TRAV["diagR"] = diags(False)[::-1]; TRAV["antidiagR"] = diags(True)[::-1]
print("travessias distintas:", len(TRAV))

def to_bytes(bits, msb=True):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        b = bits[i:i + 8]
        if not msb: b = b[::-1]
        out.append(int("".join(map(str, b)), 2))
    return bytes(out)

results = []
for mname, M in (("README", G.MATRIX_README), ("IMG", G.MATRIX_IMG)):
    for tname, order in TRAV.items():
        base = [M[r][c] for r, c in order]
        for inv in (False, True):
            bits = [1 - b for b in base] if inv else base
            for msb in (True, False):
                by = to_bytes(bits[:192], msb)
                tail = bits[192:196]
                pr = G.printable(by)
                txt = by.decode("latin-1")
                results.append((pr, mname, tname, inv, msb, txt, "".join(map(str, tail))))
results.sort(reverse=True, key=lambda x: x[0])
print("\n=== TOP 12 por fração imprimível (de %d leituras) ===" % len(results))
for pr, mn, tn, inv, msb, txt, tail in results[:12]:
    print(f"  {pr:5.3f}  {mn:6s} {tn:22s} inv={int(inv)} msb={int(msb)}  cauda={tail}  {txt!r}")
ctrl = [r for r in results if r[5].startswith("gsmg.io/theseedisplanted")]
print("\nCONTROLE (deve achar a URL conhecida):", "OK" if ctrl else "FALHOU")
for c in ctrl: print(f"   -> {c[1]} {c[2]} inv={int(c[3])} msb={int(c[4])} cauda={c[6]}  {c[5]!r}")
# quantas leituras dão 100% imprimível além do controle?
full = [r for r in results if r[0] == 1.0]
print(f"\nleituras 100% imprimíveis: {len(full)}")
for r in full: print(f"   {r[1]} {r[2]} inv={int(r[3])} msb={int(r[4])} cauda={r[6]}  {r[5]!r}")
json.dump([{"printable": r[0], "matrix": r[1], "traversal": r[2], "inv": r[3], "msb": r[4],
            "text": r[5], "tail": r[6]} for r in results[:60]],
          open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\second_door_traversals.json", "w"), indent=1)
