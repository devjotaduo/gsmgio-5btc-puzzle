# -*- coding: utf-8 -*-
"""FAMILIA grid_reads_faed — releituras GEOMETRICAS NATURAIS de faed (570) e dbbi (91)
antes de decodificar. Grades = todos os pares de divisores; leituras = colunas (4 sentidos),
serpentina (linhas/colunas), espirais inward dos 4 cantos CW/CCW, diagonais/antidiagonais
(2 sentidos), + reverso de cada. Decoders por releitura:
  (i)  Bifid CANON n=5 periodo completo
  (ii) z-method (a=1..i=9 -> decimal -> hex -> bytes)
  (iii) straddling checkerboard, alfabetos fase-3.2.2 e CANON, 36 pares de escape
  (iv) Bifid 3x3 (abcdefghi / dbifhcega) -> digitos -> z-method
Detectores: english_score > -4.6, word_hits >=2 (>=6 letras), printable>=0.85 (semantic),
G.scan_priv, sha256(saida) como senha nos 3 blobs e como privkey.
dbbi: releituras 7x13 / 13x7 / triangulo 1..13 e 13..1 -> alfabeto keyed p/ Bifid(faed),
z-method, checkerboard, senha.
NAO repete F4 (transposicao keyed por matrixsumlist/rowsum/colsum/espiral-como-chave).
"""
import sys, hashlib, itertools, json, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
TASK = sys.argv[1] if len(sys.argv) > 1 else "all"
LOG = SP + r"\grid_reads_faed.jsonl" if TASK == "all" else SP + rf"\grid_reads_faed_{TASK}.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"hypothesis": "faed/dbbi foram escritos numa grade (divisores de 570/91) e lidos em ordem geometrica natural "
              "(colunas, serpentina, espiral de canto CW/CCW, diagonais) antes de Bifid/z-method/checkerboard/Bifid3x3; "
              "a releitura correta da ingles (score>-4.6), privkey ou senha sha256 que abre SMALL/COSMIC/TAIL32."})

# ---------------------------------------------------------------- leituras geometricas
def grid(s, R, C):
    assert R * C == len(s)
    return [list(s[r * C:(r + 1) * C]) for r in range(R)]

def spiral_order(R, C, corner, cw):
    """Ordem espiral inward a partir de um canto. corner in TL,TR,BL,BR."""
    # direcoes: 0=right,1=down,2=left,3=up
    start = {"TL": (0, 0), "TR": (0, C - 1), "BL": (R - 1, 0), "BR": (R - 1, C - 1)}[corner]
    # primeira direcao: TL cw=right, ccw=down ; TR cw=down, ccw=left ; BR cw=left, ccw=up ; BL cw=up, ccw=right
    first = {("TL", True): 0, ("TL", False): 1, ("TR", True): 1, ("TR", False): 2,
             ("BR", True): 2, ("BR", False): 3, ("BL", True): 3, ("BL", False): 0}[(corner, cw)]
    dirs = [(0, 1), (1, 0), (0, -1), (-1, 0)]
    seen = set(); out = []; r, c = start; d = first
    for _ in range(R * C):
        out.append((r, c)); seen.add((r, c))
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if not (0 <= nr < R and 0 <= nc < C) or (nr, nc) in seen:
            d = (d + 1) % 4 if cw else (d - 1) % 4
            nr, nc = r + dirs[d][0], c + dirs[d][1]
        r, c = nr, nc
    return out

def reads(s, R, C):
    """dict nome -> string relida. Inclui reverso de cada. Dedupe feito pelo chamador."""
    g = grid(s, R, C); out = {}
    out["col_tb_lr"] = "".join(g[r][c] for c in range(C) for r in range(R))
    out["col_bt_lr"] = "".join(g[r][c] for c in range(C) for r in range(R - 1, -1, -1))
    out["col_tb_rl"] = "".join(g[r][c] for c in range(C - 1, -1, -1) for r in range(R))
    out["row_lr_bt"] = "".join(g[r][c] for r in range(R - 1, -1, -1) for c in range(C))
    out["row_rl_tb"] = "".join(g[r][c] for r in range(R) for c in range(C - 1, -1, -1))
    out["snake_rows"] = "".join(g[r][c] for r in range(R) for c in (range(C) if r % 2 == 0 else range(C - 1, -1, -1)))
    out["snake_rows_r1"] = "".join(g[r][c] for r in range(R) for c in (range(C) if r % 2 == 1 else range(C - 1, -1, -1)))
    out["snake_cols"] = "".join(g[r][c] for c in range(C) for r in (range(R) if c % 2 == 0 else range(R - 1, -1, -1)))
    out["snake_cols_r1"] = "".join(g[r][c] for c in range(C) for r in (range(R) if c % 2 == 1 else range(R - 1, -1, -1)))
    for corner in ("TL", "TR", "BL", "BR"):
        for cw in (True, False):
            out[f"spiral_{corner}_{'cw' if cw else 'ccw'}"] = "".join(g[r][c] for r, c in spiral_order(R, C, corner, cw))
    # diagonais (r-c const) e antidiagonais (r+c const), 2 sentidos + zigzag
    diag = [[] for _ in range(R + C - 1)]; anti = [[] for _ in range(R + C - 1)]
    for r in range(R):
        for c in range(C):
            diag[c - r + R - 1].append(g[r][c]); anti[r + c].append(g[r][c])
    out["diag"] = "".join("".join(d) for d in diag)
    out["diag_revlines"] = "".join("".join(d[::-1]) for d in diag)
    out["diag_zigzag"] = "".join("".join(d if i % 2 == 0 else d[::-1]) for i, d in enumerate(diag))
    out["anti"] = "".join("".join(d) for d in anti)
    out["anti_revlines"] = "".join("".join(d[::-1]) for d in anti)
    out["anti_zigzag"] = "".join("".join(d if i % 2 == 0 else d[::-1]) for i, d in enumerate(anti))
    for k in list(out): out[k + "_REV"] = out[k][::-1]
    return out

def triangle_reads(s, n=13, rev=False):
    """Triangulo com linhas de comprimento 1..n (ou n..1), alinhado a esquerda."""
    lens = list(range(1, n + 1)); lens = lens[::-1] if rev else lens
    assert sum(lens) == len(s)
    rows = []; i = 0
    for L in lens: rows.append(list(s[i:i + L])); i += L
    W = n; out = {}
    out["tri_cols"] = "".join(rows[r][c] for c in range(W) for r in range(len(rows)) if c < len(rows[r]))
    out["tri_cols_bt"] = "".join(rows[r][c] for c in range(W) for r in range(len(rows) - 1, -1, -1) if c < len(rows[r]))
    out["tri_cols_rl"] = "".join(rows[r][c] for c in range(W - 1, -1, -1) for r in range(len(rows)) if c < len(rows[r]))
    out["tri_snake_rows"] = "".join("".join(r if i % 2 == 0 else r[::-1]) for i, r in enumerate(rows))
    out["tri_snake_cols"] = "".join(rows[r][c] for c in range(W) for r in (range(len(rows)) if c % 2 == 0 else range(len(rows) - 1, -1, -1)) if c < len(rows[r]))
    # alinhado a direita (centrado seria fracionario): coluna j = ultimos
    out["tri_cols_rightalign"] = "".join(rows[r][len(rows[r]) - 1 - c] for c in range(W) for r in range(len(rows)) if c < len(rows[r]))
    # diagonais do triangulo esquerdo: (r - c) const
    D = {}
    for r in range(len(rows)):
        for c in range(len(rows[r])): D.setdefault(r - c, []).append(rows[r][c])
    out["tri_diag"] = "".join("".join(D[k]) for k in sorted(D))
    out["tri_diag_rev"] = "".join("".join(D[k][::-1]) for k in sorted(D))
    for k in list(out): out[k + "_REV"] = out[k][::-1]
    return {(("rtri_" if rev else "tri_") + k): v for k, v in out.items()}

# ---------------------------------------------------------------- decoders + detectores
N = {"tests": 0, "aes": 0, "priv": 0}
HARD, SOFT, BEST = [], [], {"score": -99, "text": "", "how": ""}
CB_ALPHAS = {"cb322": "FUBCDORA.LETHINGKYMVPS.JQZXW", "cbCANON": G.CANON}  # 25 letras = 7+18 (universo 1-9)
ESCAPES = [(a, b) for a in range(1, 10) for b in range(a + 1, 10)]  # 36
B3 = {"b3_abc": "abcdefghi", "b3_canon": "dbifhcega"}
B3_PERIODS = [None, 5, 7, 13, 14, 15, 19, 30, 38]
BIG_WORDS = None

def big_words(t):
    global BIG_WORDS
    if BIG_WORDS is None:
        BIG_WORDS = sorted({w.upper() for w in G.O.WORDLIST if len(w) >= 6}, key=len, reverse=True)
    T = t.upper(); return [w for w in BIG_WORDS if w in T]

def check_text(t, how):
    """Texto de letras: score, palavras, sha256->senha/privkey."""
    N["tests"] += 1
    sc = G.english_score(t)
    if sc > BEST["score"]: BEST.update(score=round(sc, 3), text=t[:80], how=how)
    wh = big_words(t)
    if sc > -4.6 or len(wh) >= 2:
        rec = {"how": how, "score": round(sc, 3), "words": wh[:8], "head": t[:60]}
        SOFT.append(rec); G.jsonl(LOG, {"soft_text": rec})
    hash_oracles(t.encode(), how)

def hash_oracles(b, how):
    """sha256(b) como senha (3 blobs x 2 kdf) e como privkey; b cru como senha."""
    for pw in (G.shahex(b), b):
        hard, soft = G.try_password_all(pw); N["aes"] += 6
        for h in hard:
            h.update(how=how, pw=pw if isinstance(pw, str) else pw.hex()); HARD.append(h); G.jsonl(LOG, {"HARD": h})
        for s_ in soft:
            s_.update(how=how); SOFT.append(s_); G.jsonl(LOG, {"soft_pad": s_})
    N["priv"] += 1
    r = G.priv_hit(G.sha(b))
    if r: HARD.append({"how": how, "priv": G.sha(b).hex(), "hit": r}); G.jsonl(LOG, {"HARD": HARD[-1]})

def check_bytes(b, how):
    N["tests"] += 1
    pr = G.printable(b)
    if G.semantic(b):
        rec = {"how": how, "printable": round(pr, 3), "head": b[:60].decode("latin-1")}
        HARD.append(rec); G.jsonl(LOG, {"HARD_semantic": rec})
    elif pr >= 0.6:
        SOFT.append({"how": how, "printable": round(pr, 3), "head": b[:40].decode("latin-1")})
    hits = G.scan_priv(b, how); N["priv"] += max(1, len(b) - 31)
    for h in hits: HARD.append({"how": how, "scan": str(h)}); G.jsonl(LOG, {"HARD": HARD[-1]})
    hash_oracles(b, how)

def decode_faed_like(s, how):
    """Os 4 decoders sobre uma string de 570 (ou 91) simbolos a-i."""
    L = len(s)
    check_text(G.bifid(s, G.CANON, L), how + "|bifidCANON")
    digs = G.digits(s)
    check_bytes(G.z_method(digs), how + "|zmethod")
    for an, al in CB_ALPHAS.items():
        for e in ESCAPES:
            check_text(G.checkerboard_decode(digs, al, e), how + f"|{an}{e[0]}{e[1]}")
    for bn, al in B3.items():
        for p in B3_PERIODS:
            if p and p >= L: continue
            o = G.bifid(s, al, p, n=3)
            check_bytes(G.z_method(G.digits(o)), how + f"|{bn}p{p or L}")

# ---------------------------------------------------------------- controle positivo
def control():
    plain = "THEQUICKBROWNFOXLEAPSOVERTHELAZYDOGANDTHEPRIVATEKEYBELONGSTOHALFANDBETTERHALF" * 8
    plain = plain[:570]
    enc = G.bifid(plain, G.CANON, 570, mode="encrypt")          # cifra Bifid
    assert G.bifid(enc, G.CANON, 570) == plain
    # o criador teria escrito enc row-major em 15x38 e publicado lido em espiral TL cw
    g = grid(enc.lower(), 15, 38)
    published = "".join(g[r][c] for r, c in spiral_order(15, 38, "TL", True))
    # para inverter, o solver precisa colocar published de volta nas posicoes espirais e ler row-major:
    inv = [[None] * 38 for _ in range(15)]
    for ch, (r, c) in zip(published, spiral_order(15, 38, "TL", True)): inv[r][c] = ch
    rec = "".join("".join(row) for row in inv)
    assert G.bifid(rec, G.CANON, 570) == plain
    assert G.english_score(plain) > -4.6
    # sanity: e o inverso da leitura espiral esta coberto pelos nossos reads? -> sim, via unspiral abaixo
    return True

def unreads(s, R, C):
    """INVERSO das leituras: se o texto publicado foi produzido lendo a grade na ordem X,
    recupera-se o row-major colocando s de volta nas posicoes da ordem X."""
    out = {}
    orders = {}
    for corner in ("TL", "TR", "BL", "BR"):
        for cw in (True, False): orders[f"unspiral_{corner}_{'cw' if cw else 'ccw'}"] = spiral_order(R, C, corner, cw)
    orders["uncol"] = [(r, c) for c in range(C) for r in range(R)]
    orders["uncol_bt"] = [(r, c) for c in range(C) for r in range(R - 1, -1, -1)]
    orders["unsnake_rows"] = [(r, c) for r in range(R) for c in (range(C) if r % 2 == 0 else range(C - 1, -1, -1))]
    orders["unsnake_cols"] = [(r, c) for c in range(C) for r in (range(R) if c % 2 == 0 else range(R - 1, -1, -1))]
    diag = [[] for _ in range(R + C - 1)]; anti = [[] for _ in range(R + C - 1)]
    for r in range(R):
        for c in range(C): diag[c - r + R - 1].append((r, c)); anti[r + c].append((r, c))
    orders["undiag"] = [p for d in diag for p in d]; orders["unanti"] = [p for d in anti for p in d]
    orders["undiag_zz"] = [p for i, d in enumerate(diag) for p in (d if i % 2 == 0 else d[::-1])]
    orders["unanti_zz"] = [p for i, d in enumerate(anti) for p in (d if i % 2 == 0 else d[::-1])]
    for name, order in orders.items():
        inv = [[None] * C for _ in range(R)]
        for ch, (r, c) in zip(s, order): inv[r][c] = ch
        out[name] = "".join("".join(row) for row in inv)
    return out

def main():
    t0 = time.time()
    assert control(); G.jsonl(LOG, {"control": "Bifid CANON + espiral 15x38 TL-cw: alvo plantado recuperado; score inglês > -4.6"})
    seen = {G.FAED, G.FAED[::-1]}
    n_reads = 0
    dims = [(R, 570 // R) for R in range(2, 570) if 570 % R == 0]
    if TASK not in ("all",): dims = [tuple(map(int, TASK.split("x")))] if "x" in TASK else []
    for R, C in dims:
        rd = reads(G.FAED, R, C); rd.update(unreads(G.FAED, R, C))
        for name, s in rd.items():
            if s in seen: continue
            seen.add(s); n_reads += 1
            decode_faed_like(s, f"faed{R}x{C}:{name}")
        print(f"grade {R}x{C} ok  reads={n_reads} tests={N['tests']} t={time.time()-t0:.0f}s", flush=True)
    # ---- dbbi: 7x13, 13x7, triangulos
    dseen = {G.DBBI, G.DBBI[::-1]}; n_dreads = 0
    drd = {}
    if TASK not in ("all", "dbbi"): drd = None
    for R, C in (((7, 13), (13, 7)) if drd is not None else ()):
        drd.update({f"dbbi{R}x{C}:{k}": v for k, v in reads(G.DBBI, R, C).items()})
        drd.update({f"dbbi{R}x{C}:{k}": v for k, v in unreads(G.DBBI, R, C).items()})
    if drd is not None:
        drd.update({"dbbi:" + k: v for k, v in triangle_reads(G.DBBI, 13, False).items()})
        drd.update({"dbbi:" + k: v for k, v in triangle_reads(G.DBBI, 13, True).items()})
    for name, s in (drd or {}).items():
        if s in dseen: continue
        dseen.add(s); n_dreads += 1
        decode_faed_like(s, name)
        # releitura do dbbi como KEYWORD do alfabeto Bifid do faed (CANON = 1a ocorrencia do dbbi)
        alpha = G.keyed_alphabet(s)
        out = G.bifid(G.FAED, alpha, 570)
        check_text(out, name + "|keyed->bifid(faed)")
        if out.startswith("BTCSEED"): G.jsonl(LOG, {"note": "BTCSEED preservado", "read": name, "alpha": alpha})
    summary = {"n_reads_faed": n_reads, "n_reads_dbbi": n_dreads, "n_tests": N["tests"], "aes_decrypts": N["aes"],
               "priv_checks": N["priv"], "hard": len(HARD), "soft": len(SOFT), "best": BEST, "secs": round(time.time() - t0)}
    G.jsonl(LOG, {"summary": summary})
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    top = sorted([s for s in SOFT if "score" in s], key=lambda x: -x["score"])[:10]
    print("TOP soft text:", json.dumps(top, ensure_ascii=False, indent=1))
    pads = [s for s in SOFT if "blob" in s]
    print("soft pads:", len(pads), json.dumps(pads[:10], ensure_ascii=False))
    print("HARD:", json.dumps(HARD, ensure_ascii=False))

if __name__ == "__main__":
    main()
