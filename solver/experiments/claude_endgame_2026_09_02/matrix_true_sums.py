# -*- coding: utf-8 -*-
"""
Familia matrix_true_sums — "matrixsumlist" = lista de somas da matriz VERDADEIRA (102 uns).
Listas: somas de linha/coluna da imagem, concatenadas, diagonais, aneis espirais, cores
valoradas, matriz preenchida com os 91 simbolos do dbbi nas 91 celulas-zero da URL.
Aplicacoes: keystream mod-9 sobre faed -> Bifid CANON / checkerboard; keystream mod-25/26
sobre BIF; keystream sobre dbbi; transposicao colunar (14 col) de faed/dbbi; senhas.
Oraculo duro: G.try_password_all / G.priv_hit. Padding sem semantica = soft.
"""
import sys, itertools, json, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\matrix_true_sums.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"hypothesis": "matrixsumlist = somas da matriz VERDADEIRA da imagem (102 uns, (7,6)=1, centro 0100), "
              "nunca usada (todos usaram 101). Listas: row/col img, row+col, diagonais, aneis espirais, cores valoradas, "
              "matriz preenchida com dbbi nas 91 celulas-zero da URL. Aplicacoes: keystream mod-9 sobre faed -> Bifid/"
              "checkerboard; mod-25/26 sobre BIF; sobre dbbi; transposicao colunar 14; senhas. Falsificavel por oraculo duro."})

N = 0                     # n_tests exato (cada decode/senha julgada)
HARD, SOFT, READ = [], [], []
M, S = G.MATRIX_IMG, G.SPIRAL
FAED, DBBI = G.FAED, G.DBBI
CB_ALPHA = "FUBCDORALETHINGKYMVPSQZXW"     # frase 3.2.2 sem J (25 letras p/ universo 1-9: 7+9+9)
ESCAPES = [(a, b) for a in range(1, 10) for b in range(1, 10) if a != b]   # 72 ordenados; 36 nao-ordenados
ESCAPES = [e for e in ESCAPES if e[0] < e[1]]

# ------------------------------------------------------------------ listas
def sums_of(Mx): return {"row": G.row_sums(Mx), "col": G.col_sums(Mx), "rowcol": G.row_sums(Mx) + G.col_sums(Mx),
                         "colrow": G.col_sums(Mx) + G.row_sums(Mx)}
LISTS = {}
for k, v in sums_of(M).items(): LISTS["img_" + k] = v
LISTS["img_diag_main"] = [sum(M[i][i] for i in range(14)), sum(M[i][13 - i] for i in range(14))]
LISTS["img_diags_all"] = [sum(M[r][c] for r in range(14) for c in range(14) if r - c == d) for d in range(-13, 14)]
LISTS["img_antidiags_all"] = [sum(M[r][c] for r in range(14) for c in range(14) if r + c == d) for d in range(27)]
ring = lambda r, c: min(r, c, 13 - r, 13 - c)
LISTS["img_rings"] = [sum(M[r][c] for r in range(14) for c in range(14) if ring(r, c) == k) for k in range(7)]
LISTS["img_rings_rev"] = LISTS["img_rings"][::-1]
# cores: azul=1 amarelo=0 (so coloridas), so pretas (uns nao-azuis), valores 15/9 e 54/47
CM = {(r, c): col for i, (col, r, c) in G.COLORED.items() if col in "BY"}
def colmat(fb, fy, fblack, fwhite=0):
    return [[(fb if CM.get((r, c)) == 'B' else fy if CM.get((r, c)) == 'Y' else (fblack if M[r][c] else fwhite))
             for c in range(14)] for r in range(14)]
for name, Mx in {"blue1": colmat(1, 0, 0), "black_only": colmat(0, 0, 1), "blue15_yel9": colmat(15, 9, 1),
                 "blue54_yel47": colmat(54, 47, 1), "blue15_yel9_only": colmat(15, 9, 0),
                 "yellow1": colmat(0, 1, 0)}.items():
    for k, v in sums_of(Mx).items():
        if k in ("row", "col", "rowcol"): LISTS[f"{name}_{k}"] = v
# matriz preenchida: dbbi (a=1..9) nas 91 celulas-zero da URL (espiral 0..191)
zero_cells_spiral = [S[i] for i in range(192) if M[S[i][0]][S[i][1]] == 0]
zero_cells_rm = sorted(zero_cells_spiral)
dd = G.digits(DBBI)
for order_name, cells in (("spiral", zero_cells_spiral), ("rowmajor", zero_cells_rm)):
    for ones_val in (1, 9, 0):
        F = [[ones_val if M[r][c] else 0 for c in range(14)] for r in range(14)]
        for (r, c), d in zip(cells, dd): F[r][c] = d
        for k, v in sums_of(F).items():
            if k in ("row", "col", "rowcol"): LISTS[f"fill_{order_name}_ones{ones_val}_{k}"] = v
LISTS["total_tail"] = [102, 4]
LISTS["row_plus_tail"] = LISTS["img_row"] + [4]
LISTS["col_plus_tail"] = LISTS["img_col"] + [4]
G.jsonl(LOG, {"lists": {k: v for k, v in LISTS.items()}})
print(len(LISTS), "listas")

# ------------------------------------------------------------------ juiz
def judge(text, how, want_hard=True):
    """Triagem + oraculo duro sobre uma saida textual."""
    global N
    N += 1
    sc = G.english_score(text) if text else -9.9
    wh = G.word_hits(text, 6) if text else []
    if sc > -4.6 or len(wh) >= 3:
        READ.append({"score": round(sc, 3), "text": text[:60], "how": how, "words": wh[:6]})
    if want_hard:
        for f in {text, text.lower(), G.shahex(text)}:
            h, s = G.try_password_all(f)
            if h: HARD.append({"how": how, "pw": f, "hits": h}); G.jsonl(LOG, {"HARD": how, "pw": f, "hits": h})
            if s: SOFT.append({"how": how, "pw": f[:40], "soft": s})
        for r in G.phrase_priv(text):
            HARD.append({"how": how, "phrase_priv": r}); G.jsonl(LOG, {"HARD": how, "phrase_priv": r})
    return sc

def cb_all(digs, how):
    for e in ESCAPES:
        t = G.checkerboard_decode(digs, CB_ALPHA, e, "123456789")
        judge(t, f"{how}|cb{e}")

# ------------------------------------------------------------------ controles positivos
assert G.bif_full().startswith("BTCSEED")
ctrl = G.checkerboard_decode([int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"],
                             "FUBCDORA.LETHINGKYMVPS.JQZXW", (1, 4), "0123456789")
assert ctrl.startswith("INCASEYOUMANAGE")

def ks_apply(digs, key, mode, off, mod):
    L = len(key); out = []
    for i, x in enumerate(digs):
        k = key[(i + off) % L]
        out.append((x + k) % mod if mode == "add" else (x - k) % mod if mode == "sub" else (k - x) % mod)
    return out

# ------------------------------------------------------------------ (a) keystream mod-9 sobre faed -> Bifid / checkerboard
t0 = time.time()
fd0 = G.digits(FAED, base1=False)
for lname, key in LISTS.items():
    for off in range(len(key)):
        for mode in ("add", "sub", "beau"):
            for a in (0, 1):
                ks = ks_apply([d + a for d in fd0], key, mode, off, 9)
                digs = [d if d else 9 for d in ks] if a == 1 else [d + 1 for d in ks]   # a=1: 0 -> 9 (i)
                sym = "".join("abcdefghi"[d - 1] for d in digs)
                how = f"ks9[{lname}|{mode}|off{off}|a{a}]"
                bif = G.bifid(sym, G.CANON, 570)
                judge(bif, how + "->bifid570")
                judge(bif[7:], how + "->bifid570[7:]", want_hard=False)
                if a == 1 and mode == "add" and off == 0:      # checkerboard so no caso base (custo)
                    cb_all(digs, how)
print("(a) done", N, round(time.time() - t0), "s")

# ------------------------------------------------------------------ (a2) checkerboard em todos os offsets/modos p/ as listas principais
for lname in ("img_row", "img_col", "img_rowcol", "img_colrow", "fill_spiral_ones1_row", "fill_spiral_ones1_col"):
    key = LISTS[lname]
    for off in range(len(key)):
        for mode in ("add", "sub", "beau"):
            for a in (0, 1):
                base = [d + a for d in fd0]
                ks = ks_apply(base, key, mode, off, 9)
                digs = [d if d else 9 for d in ks] if a == 1 else [d + 1 for d in ks]
                cb_all(digs, f"ks9cb[{lname}|{mode}|off{off}|a{a}]")
print("(a2) done", N, round(time.time() - t0), "s")

# ------------------------------------------------------------------ (b) keystream mod-25/26 sobre BIF (Vigenere/Beaufort pos-Bifid)
BIF = G.bif_full()
A25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; A26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
for lname, key in LISTS.items():
    for off in range(len(key)):
        for mode in ("add", "sub", "beau"):
            for alpha in (A25, A26):
                md = len(alpha)
                for src, tag in ((BIF, "full"), (BIF[7:], "rest")):
                    idx = [alpha.index(c) for c in src]
                    out = "".join(alpha[d] for d in ks_apply(idx, key, mode, off, md))
                    judge(out, f"ksBIF[{lname}|{mode}|off{off}|m{md}|{tag}]")
print("(b) done", N, round(time.time() - t0), "s")

# ------------------------------------------------------------------ (c) keystream sobre dbbi -> z_method / checkerboard / bifid
db0 = G.digits(DBBI, base1=False)
for lname, key in LISTS.items():
    for off in range(len(key)):
        for mode in ("add", "sub", "beau"):
            for a in (0, 1):
                ks = ks_apply([d + a for d in db0], key, mode, off, 9)
                digs = [d if d else 9 for d in ks] if a == 1 else [d + 1 for d in ks]
                how = f"ksDBBI[{lname}|{mode}|off{off}|a{a}]"
                N += 1
                zb = G.z_method(digs)
                if G.printable(zb) > 0.8:
                    READ.append({"score": G.printable(zb), "text": zb.decode("latin-1")[:60], "how": how + "->z"})
                    G.jsonl(LOG, {"z_readable": how, "text": zb.decode("latin-1")})
                for r in G.scan_priv(zb, how): HARD.append({"how": how, "scan_priv": r})
                sym = "".join("abcdefghi"[d - 1] for d in digs)
                judge(G.bifid(sym, G.CANON, 91), how + "->bifid91", want_hard=False)
                if off == 0: cb_all(digs, how)
print("(c) done", N, round(time.time() - t0), "s")

# ------------------------------------------------------------------ (d) transposicao colunar 14 (ou 28) colunas
def order_of(key): return sorted(range(len(key)), key=lambda i: (key[i], i))
def grid_cols(n, W, pad_at):
    """Indices de texto por coluna numa grade W de largura, com celulas vazias no inicio ou fim."""
    rows = -(-n // W); empty = rows * W - n
    cells = [[None] * W for _ in range(rows)]
    k = 0
    for r in range(rows):
        for c in range(W):
            if pad_at == "start" and r == 0 and c < empty: continue
            if pad_at == "end" and r == rows - 1 and c >= W - empty: continue
            cells[r][c] = k; k += 1
    return [[cells[r][c] for r in range(rows) if cells[r][c] is not None] for c in range(W)]
def transpose(text, key, pad_at, direction):
    W = len(key); cols = grid_cols(len(text), W, pad_at); order = order_of(key)
    if direction == "enc":      # escreve por linhas, le colunas em ordem da chave
        return "".join(text[i] for c in order for i in cols[c])
    perm = [i for c in order for i in cols[c]]   # dec: inverso
    out = [None] * len(text)
    for j, i in enumerate(perm): out[i] = text[j]
    return "".join(out)
# controle: enc/dec sao inversas
assert transpose(transpose(FAED, LISTS["img_row"], "start", "enc"), LISTS["img_row"], "start", "dec") == FAED
for lname, key in LISTS.items():
    if len(key) not in (14, 28, 15): continue
    for pad_at in ("start", "end"):
        for direction in ("enc", "dec"):
            how = f"colT[{lname}|{pad_at}|{direction}]"
            tf = transpose(FAED, key, pad_at, direction)
            judge(G.bifid(tf, G.CANON, 570), how + "->bifid570")
            judge(transpose(BIF, key, pad_at, direction), how + "(BIF)")
            tdb = transpose(DBBI, key, pad_at, direction)
            N += 1
            zb = G.z_method(G.digits(tdb))
            if G.printable(zb) > 0.8: READ.append({"score": G.printable(zb), "text": zb.decode("latin-1")[:60], "how": how + "(dbbi)->z"})
            cb_all(G.digits(tdb), how + "(dbbi)")
            # transposicao + keystream combinado (row como transposicao, col como keystream) so p/ img
            if lname == "img_row":
                for kk in ("img_col", "img_colrow"):
                    for mode in ("add", "sub"):
                        ks = ks_apply(G.digits(tf, base1=False), LISTS[kk], mode, 0, 9)
                        judge(G.bifid("".join("abcdefghi"[d] for d in ks), G.CANON, 570), how + f"+ks9[{kk}|{mode}]->bifid570")
print("(d) done", N, round(time.time() - t0), "s")

# ------------------------------------------------------------------ (e) senhas: listas como strings
def strforms(lst):
    s = [str(x) for x in lst]
    return {"cat": "".join(s), "comma": ",".join(s), "space": " ".join(s), "dash": "-".join(s),
            "hex": "".join(format(x, "x") for x in lst), "hex2": "".join(format(x, "02x") for x in lst),
            "chr": "".join(chr(64 + x) for x in lst if 1 <= x <= 26)}
PW = set()
for lname, lst in LISTS.items():
    for fn, f in strforms(lst).items():
        for deco in ("", "102", "0100", "4", "1024", "0100_4"):
            for pw in (f + deco, deco + f, "matrixsumlist" + f + deco, f + "enter", "matrixsumlist" + f):
                PW.add(pw.replace("_", ""))
for extra in ("102", "0100", "4", "1020100", "0100102", "102enter", "matrixsumlist102", "matrixsumlist0100",
              "matrixsumlist4", "fourforone", "four for one", "1024", "193", "102193", "10240100"):
    PW.add(extra)
for pw in sorted(PW):
    for f in (pw, pw.upper(), G.shahex(pw), G.shahex(pw).upper()):
        N += 1
        h, s = G.try_password_all(f)
        if h: HARD.append({"how": "pw", "pw": f, "hits": h}); G.jsonl(LOG, {"HARD": "pw", "pw": f, "hits": h})
        if s: SOFT.append({"how": "pw", "pw": f[:50], "soft": s})
    for r in G.phrase_priv(pw): HARD.append({"how": "pw_brain", "phrase": pw, "hit": r}); G.jsonl(LOG, {"HARD": "brain", "pw": pw, "hit": r})
for lname, lst in LISTS.items():
    b = bytes(x % 256 for x in lst)
    for cand in (b, G.sha(b), G.sha(strforms(lst)["cat"].encode())):
        N += 1
        r = G.priv_hit(cand) if len(cand) == 32 else None
        if r: HARD.append({"how": f"listbytes[{lname}]", "hit": r})
print("(e) done", N, len(PW), "senhas", round(time.time() - t0), "s")

# ------------------------------------------------------------------ (f) bifid com periodos = somas / 102 / 4 / 193 (parcialmente fechado: so novos)
for p in sorted({102, 4, 193, 5, 6, 7, 8, 9, 10, 51, 34, 17}):
    judge(G.bifid(FAED, G.CANON, p), f"bifid_period{p}", want_hard=True)
    judge(G.bifid(FAED, G.CANON, p, mode="encrypt"), f"bifid_enc_period{p}", want_hard=False)
print("(f) done", N)

READ.sort(key=lambda x: -x["score"])
summary = {"n_tests": N, "hard": len(HARD), "soft": len(SOFT), "readable_top": READ[:15], "sec": round(time.time() - t0)}
G.jsonl(LOG, summary)
print(json.dumps(summary, ensure_ascii=False, indent=1))
print("SOFT sample:", SOFT[:5])
