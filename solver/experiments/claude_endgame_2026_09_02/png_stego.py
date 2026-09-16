# -*- coding: utf-8 -*-
"""png_stego — steganálise completa de follow_the_white_rabbit.png e Puzzle_full.png.
Hipótese: as PNGs carregam canal oculto (alfa / planos LSB / sub-pixel / IDAT / QR) que,
extraído, produz texto, senha (sha256 -> blobs) ou privkey (-> endereço-prêmio).
"""
import sys, os, struct, zlib, hashlib, math, re, json, itertools, collections
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from PIL import Image
import numpy as np

ARCH = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\archive"
LOG = os.path.join(SP, "png_stego.jsonl")
PART2 = len(sys.argv) > 1 and sys.argv[1] in ("part2", "part3")
if not PART2: open(LOG, "w").close()
def log(**kw): G.jsonl(LOG, kw)

log(stage="hypothesis", text="PNGs carregam canal oculto (alfa/LSB/sub-pixel/IDAT/QR) que rende texto, senha sha256 para SMALL/COSMIC/TAIL32 ou privkey do endereço-prêmio.")

N_TESTS = 0
HARD, SOFT = [], []
def oracle_bytes(buf: bytes, how: str):
    """Oráculo duro: privkey em buf, sha256(buf) e buf cru como senha nos 3 blobs."""
    global N_TESTS
    if not buf: return
    # ponytail: privkey escondida estaria no início; 4 KB = 4065 offsets EC por stream
    hits = G.scan_priv(buf[:4096]); N_TESTS += 1
    if hits:
        HARD.append({"how": how + " -> scan_priv", "hit": str(hits)}); log(stage="HARD", how=how, hits=str(hits))
    for pw, tag in ((buf, "raw"), (hashlib.sha256(buf).hexdigest(), "sha256hex")):
        h, s = G.try_password_all(pw); N_TESTS += 1
        if h:
            HARD.append({"how": f"{how} -> {tag} pw", "pw": pw.hex() if isinstance(pw, bytes) else pw, "hits": [(k, b, p.hex()) for k, b, p in h] if isinstance(h[0], tuple) else str(h)})
            log(stage="HARD", how=how, tag=tag)
        if s:
            SOFT.append({"how": f"{how} -> {tag} pw", "soft": str(s)[:200]})

def entropy(bits):
    p = bits.mean() if len(bits) else 0
    if p in (0, 1): return 0.0
    return -(p*math.log2(p) + (1-p)*math.log2(1-p))

def bits_to_bytes(bits, msb_first=True):
    bits = bits[: len(bits) // 8 * 8].reshape(-1, 8)
    if not msb_first: bits = bits[:, ::-1]
    return np.packbits(bits, axis=1).tobytes()

PRINT_RE = re.compile(rb"[\x20-\x7e]{8,}")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
KNOWN = [b"Salted", b"U2Fsd", b"GSMG", b"gsmg", b"matrix", b"prime", b"BTC", b"btc", b"seed", b"key", b"pass", b"http", b"PNG"]

def analyse_stream(buf: bytes, how: str):
    """zsteg-like: strings, base64, tokens conhecidos; depois oráculo."""
    finds = []
    for m in PRINT_RE.finditer(buf): finds.append(("ascii", m.group().decode()[:80]))
    for k in KNOWN:
        if k in buf: finds.append(("token", k.decode()))
    for m in B64_RE.finditer(buf):
        try:
            import base64; d = base64.b64decode(m.group() + b"=" * (-len(m.group()) % 4))
            if G.printable(d) > 0.9 and len(d) >= 8: finds.append(("b64", d.decode("latin-1")[:80]))
        except Exception: pass
    if finds: log(stage="stream_find", how=how, finds=finds[:20])
    oracle_bytes(buf, how)
    # bitstream como a/b -> ASCII (o puzzle faz a=0,b=1 8 bits) já coberto por bits_to_bytes msb; variante lsb-first coberta pelo chamador
    return finds

# ------------------------------------------------------------------ chunks / IDAT
def chunk_report(path):
    d = open(path, "rb").read(); p = 8; rep = []; idat = b""
    while p < len(d):
        L = struct.unpack(">I", d[p:p+4])[0]; t = d[p+4:p+8]; body = d[p+8:p+8+L]
        ok = struct.pack(">I", zlib.crc32(t+body) & 0xffffffff) == d[p+8+L:p+12+L]
        rep.append((t.decode(), L, ok, body.hex() if L <= 16 else ""))
        if t == b"IDAT": idat += body
        p += 12 + L
        if t == b"IEND": break
    trailing = d[p:]
    w, h, bd, ct = struct.unpack(">IIBB", idat[:0] + d[16:26])
    # zlib: decompress e olha o que sobra depois do stream
    do = zlib.decompressobj(); raw = do.decompress(idat); unused = do.unused_data
    bpp = {6: 4, 2: 3, 0: 1, 3: 1}[ct]
    stride = 1 + w * bpp
    filters = bytes(raw[i*stride] for i in range(h)) if len(raw) == stride*h else None
    log(stage="chunks", file=os.path.basename(path), chunks=rep, trailing=len(trailing), md5=hashlib.md5(d).hexdigest(),
        raw_len=len(raw), expected=stride*h, zlib_unused=len(unused),
        filter_hist=dict(collections.Counter(filters)) if filters else None)
    return d, raw, filters, unused, trailing

# ------------------------------------------------------------------ análise por imagem
def analyse_image(path, tag):
    d, raw, filters, unused, trailing = chunk_report(path)
    im = Image.open(path); arr = np.array(im.convert("RGBA")); H, W = arr.shape[:2]
    # alfa
    a_hist = collections.Counter(arr[..., 3].ravel().tolist())
    # cores
    cols = collections.Counter(map(tuple, arr.reshape(-1, 4).tolist()))
    top = cols.most_common(12)
    palette = {(0,0,0,255), (255,255,255,255), (0x3F,0x48,0xCC,255), (0xFF,0xF2,0x00,255)}
    off = {c: n for c, n in cols.items() if c not in palette}
    log(stage="pixels", file=tag, size=[W, H], alpha_hist=dict(a_hist), n_colors=len(cols), top=top, n_offpalette_colors=len(off), offpalette_px=sum(off.values()))
    # planos de bit por canal: entropia
    planes = {}
    for ci, cn in enumerate("RGBA"):
        for b in range(8):
            bits = (arr[..., ci] >> b) & 1
            planes[f"{cn}{b}"] = (int(bits.sum()), round(entropy(bits.ravel().astype(float)), 4))
    log(stage="bitplanes", file=tag, planes=planes)
    # mapa dos pixels fora da paleta (onde estão)
    mask = np.ones((H, W), bool)
    for c in palette: mask &= ~np.all(arr == np.array(c, np.uint8), axis=-1)
    ys, xs = np.nonzero(mask)
    if len(ys):
        log(stage="offpalette_bbox", file=tag, n=int(mask.sum()), y=[int(ys.min()), int(ys.max())], x=[int(xs.min()), int(xs.max())],
            colors=collections.Counter(map(tuple, arr[mask].tolist())).most_common(15))
    # filtros do IDAT como canal
    if filters:
        analyse_stream(filters, f"{tag}:idat_filters")
        analyse_stream(bytes(f & 1 for f in filters), f"{tag}:idat_filters_lsb")
    if unused: analyse_stream(unused, f"{tag}:zlib_unused")
    if trailing: analyse_stream(trailing, f"{tag}:trailing")
    # zsteg-like por pixel: canais × bits(1,2) × ordem(row/col) × msb/lsb
    chans = {"R": [0], "G": [1], "B": [2], "A": [3], "RGB": [0,1,2], "BGR": [2,1,0], "RGBA": [0,1,2,3], "ABGR": [3,2,1,0]}
    n_streams = 0
    for cname, cidx in chans.items():
        for nb in (1, 2):
            for order in ("row", "col"):
                a = arr if order == "row" else arr.transpose(1, 0, 2)
                sub = a[..., cidx].reshape(-1, len(cidx))
                bits = np.concatenate([((sub >> b) & 1).ravel()[:, None] for b in range(nb)], axis=1).ravel() if nb == 1 else \
                       np.stack([(sub >> b) & 1 for b in range(nb-1, -1, -1)], axis=-1).ravel()
                bits = bits.astype(np.uint8)
                for msb in (True, False):
                    buf = bits_to_bytes(bits, msb)
                    n_streams += 1
                    # só primeiros 64 KB para strings (imagem plana repete), oráculo em prefixos 32/64B e no todo
                    analyse_stream(buf[:65536], f"{tag}:zsteg:{cname}:b{nb}:{order}:{'msb' if msb else 'lsb'}")
    log(stage="zsteg_done", file=tag, n_streams=n_streams)
    return arr, mask

# ------------------------------------------------------------------ células 14x14 (ftwr)
def cell_analysis(arr, tag, cell):
    H, W = arr.shape[:2]; n = 14
    uniform, per_cell = 0, []
    grid_colors = []
    for r in range(n):
        row = []
        for c in range(n):
            blk = arr[r*cell:(r+1)*cell, c*cell:(c+1)*cell].reshape(-1, 4)
            cc = collections.Counter(map(tuple, blk.tolist()))
            dom = cc.most_common(1)[0][0]
            row.append(dom); per_cell.append(len(cc))
            uniform += (len(cc) == 1)
        grid_colors.append(row)
    log(stage="cells", file=tag, cell=cell, uniform_cells=uniform, of=n*n, distinct_per_cell=per_cell)
    # matriz binária (preto=1) + alfa/LSB por célula
    M = [[1 if grid_colors[r][c][:3] == (0,0,0) else 0 for c in range(n)] for r in range(n)]
    ones = sum(map(sum, M))
    log(stage="cell_matrix", file=tag, ones=ones, rows=["".join(map(str, r)) for r in M], row_sums=G.row_sums(M), col_sums=G.col_sums(M),
        matches_MATRIX_IMG=(M == G.MATRIX_IMG))
    # bordas entre células: linhas/colunas de fronteira com cor diferente da célula?
    edge_diff = 0
    for r in range(n):
        for c in range(n):
            blk = arr[r*cell:(r+1)*cell, c*cell:(c+1)*cell]
            inner = blk[1:-1, 1:-1].reshape(-1, 4); border = np.concatenate([blk[0], blk[-1], blk[:, 0], blk[:, -1]])
            if len(set(map(tuple, inner.tolist()))) == 1 and set(map(tuple, border.tolist())) != set(map(tuple, inner.tolist())): edge_diff += 1
    log(stage="cell_edges", file=tag, cells_with_border_differing=edge_diff)
    # bitstreams por célula: row-major, col-major, espiral — LSB de cada canal do pixel dominante + matriz
    orders = {"row": [(r, c) for r in range(n) for c in range(n)], "col": [(r, c) for c in range(n) for r in range(n)]}
    sp = G.SPIRAL
    if isinstance(sp, dict): orders["spiral"] = [sp[i] for i in sorted(sp)]
    elif isinstance(sp, (list, tuple)) and len(sp) == n*n and not isinstance(sp[0], (list, tuple)):
        pos = {v: (i//n, i%n) for i, v in enumerate(sp)}; orders["spiral"] = [pos[k] for k in sorted(pos)]
    elif isinstance(sp, (list, tuple)) and len(sp) == n:
        pos = {sp[r][c]: (r, c) for r in range(n) for c in range(n)}; orders["spiral"] = [pos[k] for k in sorted(pos)]
    for oname, od in orders.items():
        for ci, cn in enumerate("RGBA"):
            bits = np.array([grid_colors[r][c][ci] & 1 for r, c in od], np.uint8)
            if bits.sum() in (0, len(bits)): continue  # plano trivial
            for msb in (True, False):
                analyse_stream(bits_to_bytes(bits, msb), f"{tag}:cellLSB:{cn}:{oname}:{'msb' if msb else 'lsb'}")
        bits = np.array([M[r][c] for r, c in od], np.uint8)
        for msb in (True, False):
            analyse_stream(bits_to_bytes(bits, msb), f"{tag}:cellMatrix:{oname}:{'msb' if msb else 'lsb'}")
        # a/b como o puzzle: 0->'a',1->'b' e via z_method (a=1..)
        ab = "".join("ab"[b] for b in bits); oracle_bytes(ab.encode(), f"{tag}:cellMatrix_ab:{oname}")
    return M

# ================================================================== parte 2: filtros Sub, QR, coelho
def part2():
    # (1) posições das linhas com filtro 1 no Puzzle_full (91 = len(dbbi)?)
    d, raw, filters, _, _ = chunk_report(full)
    rows1 = [i for i, f in enumerate(filters) if f == 1]
    # linhas onde a imagem muda em relação à anterior (fronteira de conteúdo)
    change = [i for i in range(1, arr2.shape[0]) if not np.array_equal(arr2[i], arr2[i-1])]
    log(stage="sub_filter_rows", n=len(rows1), rows=rows1, all_are_change_rows=all(r in change or r == 0 for r in rows1),
        n_change_rows=len(change))
    # filtros como bitstream (Sub=1/Up=0) -> oráculo, e as posições como texto
    analyse_stream(bits_to_bytes(np.array([f == 1 for f in filters], np.uint8), True), "full:filters_sub_bits")
    oracle_bytes(bytes(r % 256 for r in rows1), "full:sub_rows_mod256")
    d1, raw1, filters1, _, _ = chunk_report(ftwr)
    log(stage="sub_filter_rows_ftwr", rows=[i for i, f in enumerate(filters1) if f == 1])
    # (2) QR: binarizar, recortar, upscale
    try:
        import cv2
        crop = arr2[1280:1530, 0:250, :3]
        g = cv2.cvtColor(crop, cv2.COLOR_RGB2GRAY); _, th = cv2.threshold(g, 128, 255, cv2.THRESH_BINARY)
        th = cv2.copyMakeBorder(th, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
        det = cv2.QRCodeDetector(); txt = ""
        for fx in (1, 2, 3, 4):
            big = cv2.resize(th, None, fx=fx, fy=fx, interpolation=cv2.INTER_NEAREST)
            txt, pts, _ = det.detectAndDecode(big)
            if txt: break
        log(stage="qr2", text=txt, fx=fx)
        if txt: oracle_bytes(txt.encode(), "full:qr_text")
    except Exception as e: log(stage="qr2", error=repr(e))
    try:
        from pyzbar.pyzbar import decode as zdec
        r = zdec(Image.fromarray(arr2[1280:1530, 0:250]))
        log(stage="qr_pyzbar", res=[x.data.decode() for x in r])
    except Exception as e: log(stage="qr_pyzbar", error=repr(e)[:80])
    # (3) coelho: bitmap binário das células não uniformes (linhas 150-225, colunas 150-250 em ftwr)
    reg = arr1[150:225, 150:250]; blk = np.all(reg[..., :3] == 0, axis=-1).astype(np.uint8)
    art = ["".join("#" if v else "." for v in row) for row in blk]
    log(stage="rabbit_bitmap", rows=art)
    for msb in (True, False):
        analyse_stream(bits_to_bytes(blk.ravel(), msb), f"ftwr:rabbit_rowbits:{'msb' if msb else 'lsb'}")
        analyse_stream(bits_to_bytes(blk.T.ravel(), msb), f"ftwr:rabbit_colbits:{'msb' if msb else 'lsb'}")
    # coelho no Puzzle_full: região equivalente, comparar com upscale NN do ftwr (sub-pixel)
    ys, xs = slice(int(6*74.7857), int(9*74.7857)), slice(int(6*74.857), int(10*74.857))
    regf = np.all(arr2[ys, xs, :3] == 0, axis=-1)
    up = np.array(Image.fromarray(blk*255).resize((regf.shape[1], regf.shape[0]), Image.NEAREST)) > 0
    log(stage="rabbit_full_vs_ftwr", full_black=int(regf.sum()), ftwr_up_black=int(up.sum()), mismatch_px=int((regf != up).sum()), of=int(regf.size))
    # (4) região da matriz no full: fração de cor dominante por célula (sub-pixel)
    fr = []
    for r in range(14):
        for c in range(14):
            blk2 = arr2[int(r*74.7857):int((r+1)*74.7857), int(c*74.857):int((c+1)*74.857)].reshape(-1, 4)
            cc = collections.Counter(map(tuple, blk2.tolist())); fr.append(round(cc.most_common(1)[0][1] / len(blk2), 3))
    log(stage="full_cell_dominant_fraction", min=min(fr), cells_below_0999=[(i//14, i%14, f) for i, f in enumerate(fr) if f < 0.999])
    log(stage="summary2", n_tests=N_TESTS, hard=HARD, n_soft=len(SOFT))
    print(json.dumps({"n_tests": N_TESTS, "hard": HARD, "n_soft": len(SOFT)}))


# ================================================================== parte 3: upscale exato, grade 70x70 de blocos 5px
def part3():
    # (a) Puzzle_full[0:1047, 0:1048] == NN-upscale x3 do ftwr (1050x1050) recortado?
    up = np.array(Image.fromarray(arr1).resize((1050, 1050), Image.NEAREST))
    best = None
    for dy in range(0, 4):
        for dx in range(0, 3):
            sub = up[dy:dy+1047, dx:dx+1048]
            mm = int((~np.all(sub == arr2[:1047], axis=-1)).sum())
            if best is None or mm < best[0]: best = (mm, dy, dx)
    log(stage="full_is_upscale", mismatch_px=best[0], offset=best[1:], of=1047*1048)
    if best[0]:
        sub = up[best[1]:best[1]+1047, best[2]:best[2]+1048]; m = ~np.all(sub == arr2[:1047], axis=-1); ys, xs = np.nonzero(m)
        log(stage="full_upscale_diff", bbox=[[int(ys.min()), int(ys.max())], [int(xs.min()), int(xs.max())]],
            colors_full=collections.Counter(map(tuple, arr2[:1047][m].tolist())).most_common(6),
            colors_up=collections.Counter(map(tuple, sub[m].tolist())).most_common(6))
    # (b) grade 70x70 de blocos 5x5 no ftwr
    B = arr1.reshape(70, 5, 70, 5, 4).transpose(0, 2, 1, 3, 4).reshape(70, 70, 25, 4)
    uniform = np.all(B == B[:, :, :1, :], axis=(2, 3)); log(stage="blocks5", uniform_blocks=int(uniform.sum()), of=4900)
    if uniform.all():
        col = B[:, :, 0, :]
        black = np.all(col[..., :3] == 0, axis=-1).astype(np.uint8)
        blue = np.all(col[..., :3] == (63, 72, 204), axis=-1); yellow = np.all(col[..., :3] == (255, 242, 0), axis=-1)
        log(stage="blocks5_bitmap", black=int(black.sum()), rows=["".join("#" if v else "." for v in r) for r in black])
        for name, bm in (("black", black), ("black_or_blue", (black | blue).astype(np.uint8))):
            for oname, arrb in (("row", bm), ("col", bm.T)):
                for msb in (True, False):
                    analyse_stream(bits_to_bytes(arrb.ravel(), msb), f"ftwr:blocks5:{name}:{oname}:{'msb' if msb else 'lsb'}")
                ab = "".join("ab"[int(v)] for v in arrb.ravel()); oracle_bytes(ab.encode(), f"ftwr:blocks5_ab:{name}:{oname}")
        # coelho em blocos: linhas 30-45, colunas 30-50 (células 6-8 x 6-9)
        rb = black[30:45, 30:50]; log(stage="rabbit_blocks", rows=["".join("#" if v else "." for v in r) for r in rb])
        for msb in (True, False):
            analyse_stream(bits_to_bytes(rb.ravel(), msb), f"ftwr:rabbit_blocks:row:{'msb' if msb else 'lsb'}")
            analyse_stream(bits_to_bytes(rb.T.ravel(), msb), f"ftwr:rabbit_blocks:col:{'msb' if msb else 'lsb'}")
        # bits do coelho dentro das células que ele ocupa (só onde difere da cor de fundo da célula)
    log(stage="summary3", n_tests=N_TESTS, hard=HARD, n_soft=len(SOFT), soft=SOFT)
    print(json.dumps({"n_tests": N_TESTS, "hard": HARD, "n_soft": len(SOFT)}))

# ------------------------------------------------------------------ main
ftwr = os.path.join(ARCH, "follow_the_white_rabbit.png"); full = os.path.join(ARCH, "Puzzle_full.png")
if PART2:
    arr1 = np.array(Image.open(ftwr).convert("RGBA")); arr2 = np.array(Image.open(full).convert("RGBA")); (part3 if sys.argv[1] == "part3" else part2)(); sys.exit()
arr1, mask1 = analyse_image(ftwr, "ftwr")
M1 = cell_analysis(arr1, "ftwr", 25)
arr2, mask2 = analyse_image(full, "full")

# Puzzle_full: região da matriz (1048 px de largura -> célula 1048/14 = 74.857) — localizar a linha vermelha
red = np.all(arr2[..., :3] == np.array([0xED, 0x1C, 0x24]), axis=-1)
ry = np.nonzero(red.any(axis=1))[0]
log(stage="redline", y=[int(ry.min()), int(ry.max())] if len(ry) else None, px=int(red.sum()),
    colors_in_band=collections.Counter(map(tuple, arr2[ry.min():ry.max()+1].reshape(-1,4).tolist())).most_common(6) if len(ry) else None)
# grade: amostrar centro das células na região 0..ry.min()
top = int(ry.min()) if len(ry) else 1048
cellh = top / 14; cellw = 1048 / 14
M2 = [[1 if tuple(arr2[int((r+.5)*cellh), int((c+.5)*cellw)][:3]) == (0,0,0) else 0 for c in range(14)] for r in range(14)]
log(stage="full_matrix", cell=[cellw, cellh], ones=sum(map(sum, M2)), equal_ftwr=(M2 == M1), equal_MATRIX_IMG=(M2 == G.MATRIX_IMG),
    diff=[(r, c) for r in range(14) for c in range(14) if M2[r][c] != M1[r][c]])
# cores por célula no full: pixel central + uniformidade aproximada (miolo 60%)
nonuni = []
for r in range(14):
    for c in range(14):
        y0, y1 = int(r*cellh + .2*cellh), int((r+1)*cellh - .2*cellh); x0, x1 = int(c*cellw + .2*cellw), int((c+1)*cellw - .2*cellw)
        cc = set(map(tuple, arr2[y0:y1, x0:x1].reshape(-1, 4).tolist()))
        if len(cc) > 1: nonuni.append((r, c, len(cc)))
log(stage="full_cells_nonuniform", cells=nonuni)

# FEFEFE e vizinhos (ftwr)
fe = np.all(arr1[..., :3] == 254, axis=-1); ys, xs = np.nonzero(fe)
log(stage="fefefe", n=int(fe.sum()), bbox=[[int(ys.min()), int(ys.max())], [int(xs.min()), int(xs.max())]] if len(ys) else None,
    cells=sorted({(int(y)//25, int(x)//25) for y, x in zip(ys, xs)}))
fe2 = np.all(arr2[..., :3] == 254, axis=-1); ys2, xs2 = np.nonzero(fe2)
log(stage="fefefe_full", n=int(fe2.sum()), bbox=[[int(ys2.min()), int(ys2.max())], [int(xs2.min()), int(xs2.max())]] if len(ys2) else None)

# pixels fora da paleta como canal: seus bytes RGB em ordem raster
for arr, mask, tag in ((arr1, mask1, "ftwr"), (arr2, mask2, "full")):
    off = arr[mask]
    if len(off):
        analyse_stream(off[:, :3].tobytes(), f"{tag}:offpalette_rgb")
        analyse_stream(bytes(int(v) & 1 for v in off[:, :3].ravel()), f"{tag}:offpalette_lsb_bytes")
        bits = (off[:, :3].ravel() & 1).astype(np.uint8)
        for msb in (True, False): analyse_stream(bits_to_bytes(bits, msb), f"{tag}:offpalette_lsbstream:{'msb' if msb else 'lsb'}")

# QR do Puzzle_full
try:
    import cv2
    det = cv2.QRCodeDetector(); bgr = cv2.cvtColor(arr2, cv2.COLOR_RGBA2BGR)
    txt, pts, _ = det.detectAndDecode(bgr)
    if not txt:
        crop = bgr[1280:1520, 0:250]; crop = cv2.resize(crop, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST)
        txt, pts, _ = det.detectAndDecode(crop)
    log(stage="qr", text=txt, found=bool(txt))
    if txt: oracle_bytes(txt.encode(), "full:qr_text")
except Exception as e:
    log(stage="qr", error=repr(e))

# controle positivo do decoder zsteg: embute 'CONTROLE OK' no LSB de R row-major e recupera
ctl = arr1.copy(); msg = b"CONTROLE OK GSMG"; mb = np.unpackbits(np.frombuffer(msg, np.uint8))
flat = ctl[..., 0].ravel(); flat[:len(mb)] = (flat[:len(mb)] & 0xFE) | mb; ctl[..., 0] = flat.reshape(ctl.shape[:2])
rec = bits_to_bytes((ctl[..., 0] & 1).ravel().astype(np.uint8), True)[:len(msg)]
log(stage="control", recovered=rec.decode(), ok=(rec == msg))
assert rec == msg

log(stage="summary", n_tests=N_TESTS, hard=HARD, soft=SOFT[:20], n_soft=len(SOFT))
print(json.dumps({"n_tests": N_TESTS, "hard": HARD, "n_soft": len(SOFT)}, indent=1)[:3000])
