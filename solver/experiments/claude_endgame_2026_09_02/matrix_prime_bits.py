# -*- coding: utf-8 -*-
"""
Família matrix_prime_bits — pistas "zeroed out / prime positions / First or zero / Infrared"
lidas LITERALMENTE sobre o bitmap 14x14 (imagem original) e seus canais RGB.
Parte A: ops em índices primos (zerar/flipar/setar) x matriz(102/101) x base(0/1) x ordem(4) + extração
         de bits primos / não-primos + 163/193 individuais + máscara das 24 coloridas.
Parte B: canais R/G/B/IR/XOR/soma por célula -> mod9 (a-i), mod26, bytes, somas, coloridas; keystream
         mod-9 sobre faed -> Bifid CANON / checkerboard (36 escapes x 2 alfabetos) e sobre dbbi -> z-method.
Parte C: (7,6)/(7,4) e 163/193 como cortes/rotações/remoções em dbbi/faed; sub-bitmap 5px do coelho.
Oráculo duro: G.priv_hit / G.semantic em saída AES. Decoders textuais: G.semantic_text.
"""
import sys, json, os, time, hashlib
SCR = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SCR)
import gsmg_common as G
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

LOG = os.path.join(SCR, "matrix_prime_bits.jsonl")
open(LOG, "w").close()
HYP = ("As pistas 'zeroed out'/'prime positions'/'First or zero'/'Infrared' sao literais sobre o bitmap 14x14: "
       "zerar/flipar/setar bits em indices primos (base 0/1, 4 ordens, matriz 102/101), extrair so bits primos/"
       "nao-primos (152=19 bytes), ou ler canais RGB da imagem; o resultado em forma trivial (ascii/bits/dec/hex/"
       "sha256) e a senha de SMALL/COSMIC/TAIL32 ou a privkey. Espaco finito ~30k testes.")
G.jsonl(LOG, {"family": "matrix_prime_bits", "hypothesis": HYP})

N = 0
CNT = {}
HARD, SOFT = [], []
BEST = {"score": -99.0, "text": "", "how": ""}
BLOBS = ["SMALL", "COSMIC", "TAIL32"]
CAND = 0

def upd_best(t, how):
    if not t: return
    s = G.english_score(t)
    if s > BEST["score"]:
        BEST.update(score=round(s, 3), text=t[:120], how=how)

def test_pw(pw, how):
    global N
    for blob in BLOBS:
        for kdf in ("sha256", "md5"):
            N += 1; CNT["aes"] = CNT.get("aes", 0) + 1
            for k, p in G.aes_try(pw, blob, kdf=kdf):
                rec = {"how": how, "blob": blob, "kdf": kdf, "len": len(p),
                       "printable": round(G.printable(p), 3), "pw_hex": (pw if isinstance(pw, bytes) else pw.encode()).hex()[:200],
                       "head_hex": p[:32].hex()}
                if G.semantic(p):
                    rec["plaintext_hex"] = p.hex(); HARD.append(rec); G.jsonl(LOG, {"HARD": rec})
                else:
                    SOFT.append(rec); G.jsonl(LOG, {"soft": rec})

def test_priv(b32, how):
    global N
    if len(b32) != 32: return
    N += 1; CNT["priv"] = CNT.get("priv", 0) + 1
    r = G.priv_hit(b32)
    if r:
        rec = {"how": how, "priv": b32.hex(), **r}; HARD.append(rec); G.jsonl(LOG, {"HARD": rec})

def test_candidate(name, raw=None, text=None):
    """raw: bytes; text: str. Formas: raw, hex, bits/texto, sha256hex de cada; privkeys sha256/int/pad."""
    global CAND, N
    CAND += 1
    forms = {}
    if raw:
        forms["raw"] = raw; forms["hex"] = raw.hex(); forms["sha_raw"] = G.shahex(raw); forms["sha_hex"] = G.shahex(raw.hex())
        if G.printable(raw) >= 0.85:
            upd_best(raw.decode("latin-1"), name + "/raw")
    if text:
        forms["text"] = text; forms["sha_text"] = G.shahex(text)
        if text.isdigit() and len(text) < 400:
            ai = "".join("oabcdefghi"[int(d)] for d in text)   # digitos -> a-i (o=0), gramatica da pagina
            forms["ai"] = ai; forms["sha_ai"] = G.shahex(ai)
    for f, v in forms.items():
        test_pw(v, f"{name}/{f}")
    # privkeys
    if raw:
        test_priv(G.sha(raw), name + "/priv=sha(raw)")
        test_priv(G.sha(raw.hex()), name + "/priv=sha(hex)")
        test_priv(raw.rjust(32, b"\0")[-32:], name + "/priv=raw_rpad")
        test_priv(raw.ljust(32, b"\0")[:32], name + "/priv=raw_lpad")
        if len(raw) >= 32:
            N += len(raw) - 31; CNT["priv"] = CNT.get("priv", 0) + len(raw) - 31
            for h in G.fast_priv_scan(raw, name):
                HARD.append({"how": h[0] + "/" + h[1], "priv": h[2]}); G.jsonl(LOG, {"HARD": HARD[-1]})
    if text:
        test_priv(G.sha(text), name + "/priv=sha(text)")
        if set(text) <= set("01") and len(text) <= 256:
            test_priv(int(text, 2).to_bytes(32, "big"), name + "/priv=int(bits)")
        elif text.isdigit() and len(text) <= 77:
            n = int(text)
            if 0 < n < 2 ** 256: test_priv(n.to_bytes(32, "big"), name + "/priv=int(dec)")

# ------------------------------------------------------------------ controle positivo
_ctrl_bits = "".join(str(G.MATRIX_IMG[r][c]) for r, c in G.SPIRAL)
_ctrl_raw = bytes(int(_ctrl_bits[i:i + 8], 2) for i in range(0, 192, 8))
assert _ctrl_raw == b"gsmg.io/theseedisplanted", "controle: espiral sem mascara deve dar a URL"
_pw = G.shahex(_ctrl_raw).encode(); _salt = b"ctrlsalt"
_k, _iv = G.evp(_pw, _salt, SHA256)
_pt = b"CONTROLE POSITIVO: plaintext semantico de teste 1234"; _pad = 16 - len(_pt) % 16
G.BLOBS["CTRL"] = (_salt, AES.new(_k, AES.MODE_CBC, _iv).encrypt(_pt + bytes([_pad]) * _pad))
BLOBS.append("CTRL")
test_candidate("CTRL", raw=_ctrl_raw, text=_ctrl_bits)
assert any(h.get("blob") == "CTRL" and h["kdf"] == "sha256" for h in HARD), "controle positivo falhou"
G.jsonl(LOG, {"control": "OK", "n_tests_control": N})
BLOBS.remove("CTRL"); del G.BLOBS["CTRL"]; HARD.clear(); SOFT.clear(); N = 0; CAND = 0; BEST.update(score=-99.0, text="", how=""); CNT.clear()

# ------------------------------------------------------------------ dados
PRIMES = [p for p in range(196) if G.is_prime(p)]       # 44 primos < 196 (2..193)
assert len(PRIMES) == 44
ORDERS = {
    "spiral_ccw": G.SPIRAL,
    "spiral_cw": [(c, r) for r, c in G.SPIRAL],
    "row": [(r, c) for r in range(14) for c in range(14)],
    "col": [(r, c) for c in range(14) for r in range(14)],
}
MATS = {"img102": G.MATRIX_IMG, "readme101": G.MATRIX_README}

def bits_of(M, order): return [M[r][c] for r, c in order]
def to_bytes(bits):
    s = "".join(map(str, bits)); s += "0" * (-len(s) % 8)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))
def apply_op(bits, idxs, op):
    b = bits[:]
    for i in idxs:
        if 0 <= i < len(b):
            b[i] = 0 if op == "zero" else 1 if op == "set1" else 1 - b[i]
    return b

def emit_bits(name, bits):
    """Um vetor de bits -> candidato (bytes de 8 bits + bitstring + decimal)."""
    s = "".join(map(str, bits))
    test_candidate(name, raw=to_bytes(bits), text=s)
    if len(bits) == 196:   # tambem so os 192 (24 bytes) sem a cauda central
        test_candidate(name + "/192", raw=to_bytes(bits[:192]))
    test_candidate(name + "/dec", text=str(int(s, 2)))

t0 = time.time()
# ------------------------------------------------------------------ PARTE A
for mname, M in MATS.items():
    for oname, order in ORDERS.items():
        bits = bits_of(M, order)
        for base in (0, 1):
            pidx = [p - base for p in PRIMES if 0 <= p - base < 196]
            for op in ("zero", "flip", "set1"):
                emit_bits(f"A/{mname}/{oname}/b{base}/{op}/full", apply_op(bits, pidx, op))
            pset = set(pidx)
            prim = [bits[i] for i in pidx]; nonp = [bits[i] for i in range(196) if i not in pset]
            for op in ("none", "flip"):
                pr = prim if op == "none" else [1 - x for x in prim]
                np_ = nonp if op == "none" else [1 - x for x in nonp]
                emit_bits(f"A/{mname}/{oname}/b{base}/{op}/primes_only", pr)
                emit_bits(f"A/{mname}/{oname}/b{base}/{op}/nonprimes_only", np_)
            # primos cujo bit e 1 / 0 -> lista decimal concatenada e como letras mod 26
            for v in (0, 1):
                ps = [p for p in PRIMES if 0 <= p - base < 196 and bits[p - base] == v]
                test_candidate(f"A/{mname}/{oname}/b{base}/primes_with_{v}", text="".join(map(str, ps)))
                test_candidate(f"A/{mname}/{oname}/b{base}/primes_with_{v}/mod26", text="".join(chr(65 + p % 26) for p in ps))
                test_candidate(f"A/{mname}/{oname}/b{base}/primes_with_{v}/spaced", text=" ".join(map(str, ps)))
    # 163 / 193 individuais (indices espirais) em ambas espirais
    for oname in ("spiral_ccw", "spiral_cw"):
        bits = bits_of(M, ORDERS[oname])
        for idxs in ((163,), (193,), (163, 193)):
            for op in ("zero", "flip", "set1"):
                emit_bits(f"A/{mname}/{oname}/only{'_'.join(map(str, idxs))}/{op}", apply_op(bits, list(idxs), op))
G.jsonl(LOG, {"stage": "A done", "n": N, "cand": CAND, "t": round(time.time() - t0, 1)})

# mascara das 24 coloridas (azul=1, amarelo=0) sobre os 24 bytes da URL
bits = bits_of(G.MATRIX_IMG, G.SPIRAL)
col_idx = sorted(i for i in G.COLORED if G.COLORED[i][0] in "BY")
mask = [1 if G.COLORED[i][0] == "B" else 0 for i in col_idx]
test_candidate("A/mask/colors24", text="".join(map(str, mask)), raw=to_bytes(mask))
test_candidate("A/mask/colors24_inv", text="".join(str(1 - m) for m in mask), raw=to_bytes([1 - m for m in mask]))
b = bits[:]
for i, m in zip(col_idx, mask): b[i] ^= m
emit_bits("A/mask/xor_lsb", b)
b = bits[:]
for i in col_idx: b[i] = 1 - b[i]
emit_bits("A/mask/flip_lsb", b)
b = bits[:]
for i in col_idx: b[i] = 1 if G.is_prime(i) else 0
emit_bits("A/mask/lsb=isprime", b)
pm = [1 if G.is_prime(i) else 0 for i in col_idx]
test_candidate("A/mask/colored_isprime24", text="".join(map(str, pm)), raw=to_bytes(pm))
cp = [m for i, m in zip(col_idx, mask) if G.is_prime(i)]
test_candidate("A/mask/color_at_prime_idx", text="".join(map(str, cp)), raw=to_bytes(cp))
cp = [m for i, m in zip(col_idx, mask) if not G.is_prime(i)]
test_candidate("A/mask/color_at_nonprime_idx", text="".join(map(str, cp)), raw=to_bytes(cp))
# coloridas em primos: indices como numeros
pc = [i for i in col_idx if G.is_prime(i)]
test_candidate("A/mask/colored_prime_indices", text="".join(map(str, pc)))
test_candidate("A/mask/colored_prime_indices_sp", text=" ".join(map(str, pc)))
# zerar SO os primos coloridos / so os azuis primos
for lab, idxs in (("colored_primes", pc), ("blue_primes", [i for i in pc if G.COLORED[i][0] == "B"]),
                  ("yellow_primes", [i for i in pc if G.COLORED[i][0] == "Y"]), ("blue", G.BLUE_IDX), ("yellow", G.YELLOW_IDX)):
    for op in ("zero", "flip", "set1"):
        emit_bits(f"A/mask/{lab}/{op}", apply_op(bits, idxs, op))
G.jsonl(LOG, {"stage": "A+mask done", "n": N, "cand": CAND, "t": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ PARTE B: canais da imagem
im = Image.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\archive\follow_the_white_rabbit.png").convert("RGB")
px = im.load()
from collections import Counter
RGB = [[Counter(px[x, y] for y in range(r * 25, r * 25 + 25) for x in range(c * 25, c * 25 + 25)).most_common(1)[0][0]
        for c in range(14)] for r in range(14)]
assert RGB[7][4] == (254, 254, 254)
CH = {
    "R": lambda p: p[0], "G": lambda p: p[1], "B": lambda p: p[2],
    "IR": lambda p: 255 - p[0], "XOR": lambda p: p[0] ^ p[1] ^ p[2], "SUM": lambda p: sum(p),
    "GRAY": lambda p: (p[0] * 299 + p[1] * 587 + p[2] * 114) // 1000,
}
KEYSTREAMS = {}
for ch, f in CH.items():
    grid = [[f(RGB[r][c]) for c in range(14)] for r in range(14)]
    # somas
    rs = [sum(row) for row in grid]; cs = [sum(grid[r][c] for r in range(14)) for c in range(14)]
    for lab, lst in (("rowsums", rs), ("colsums", cs), ("rowcol", rs + cs)):
        test_candidate(f"B/{ch}/{lab}", text="".join(map(str, lst)), raw=bytes(v % 256 for v in lst))
        test_candidate(f"B/{ch}/{lab}/sp", text=" ".join(map(str, lst)))
        test_candidate(f"B/{ch}/{lab}/mod9", text="".join("abcdefghi"[v % 9] for v in lst))
    test_candidate(f"B/{ch}/total", text=str(sum(rs)))
    for oname, order in ORDERS.items():
        seq = [grid[r][c] for r, c in order]
        KEYSTREAMS[f"{ch}/{oname}"] = seq
        raw = bytes(v % 256 for v in seq)
        test_candidate(f"B/{ch}/{oname}/bytes", raw=raw, text="".join(map(str, seq)))
        ai = "".join("abcdefghi"[v % 9] for v in seq)
        test_candidate(f"B/{ch}/{oname}/mod9", text=ai)
        # z-method (pagina): digitos -> decimal -> hex -> ascii
        try:
            z = G.z_method([v % 9 + 1 for v in seq]); test_candidate(f"B/{ch}/{oname}/mod9/zmethod", raw=z)
        except Exception: pass
        # comparacao com dbbi / faed
        m_d = sum(a == b for a, b in zip(ai, G.DBBI)); m_f = sum(a == b for a, b in zip(ai, G.FAED))
        if m_d >= 20 or m_f >= 40:
            G.jsonl(LOG, {"lead": f"B/{ch}/{oname}/mod9 coincide com dbbi={m_d}/91 faed={m_f}/196"})
        l26 = "".join(chr(65 + v % 26) for v in seq)
        test_candidate(f"B/{ch}/{oname}/mod26", text=l26); upd_best(l26, f"B/{ch}/{oname}/mod26")
        if G.semantic_text(l26): G.jsonl(LOG, {"soft_text": f"B/{ch}/{oname}/mod26", "text": l26})
        # so celulas coloridas / so primos
        for lab, sel in (("colored", col_idx if oname == "spiral_ccw" else None), ("primes", PRIMES)):
            if sel is None: continue
            sub = [seq[i] for i in sel]
            test_candidate(f"B/{ch}/{oname}/{lab}/vals", text="".join(map(str, sub)), raw=bytes(v % 256 for v in sub))
            test_candidate(f"B/{ch}/{oname}/{lab}/mod9", text="".join("abcdefghi"[v % 9] for v in sub))
            test_candidate(f"B/{ch}/{oname}/{lab}/hex", text="".join("%02x" % (v % 256) for v in sub))
            test_candidate(f"B/{ch}/{oname}/{lab}/sum", text=str(sum(sub)))
G.jsonl(LOG, {"stage": "B channels done", "n": N, "cand": CAND, "t": round(time.time() - t0, 1)})

# valores das cores e seus digitos hex
for t in ("3F48CC", "FFF200", "3F48CCFFF200", "FFF2003F48CC", "3f48cc", "fff200", "3f48ccfff200", "fff2003f48cc",
          "6372204", "2552420", "63722042552420", "25524206372204", "63 72 204", "255 242 0", "4147404", "16773632",
          "414740416773632", "339", "497", "836", "339497", "497339", "3F48CCFFF200FEFEFE", "FEFEFE", "fefefe",
          "254254254", "16711422", "63722042552420254254254", "192", "63", "13", "0", "255-63",
          "C0B733", "c0b733", "000DFF", "000dff", "C0B733000DFF", "000DFFC0B733",   # infravermelho = 255-x
          "1927251", "01355", "192725101355", "3F", "48", "CC", "FF", "F2", "00", "3F48CC3F48CC", "yellowblue",
          "blueyellow", "YellowBlue", "BlueYellow", "yellowblueprimes", "YellowBluePrimes", "infrared", "Infrared",
          "INFRARED", "red", "Red", "RED", "white", "White", "roses", "Roses", "RosesAreWhite", "rosesarewhite",
          "RosesareWhitebutoftenRed", "rosesarewhitebutoftenred", "Yellowhasanumberandsodoesblue",
          "yellowhasanumberandsodoesblue", "15", "9", "159", "915", "1509", "15+9", "24", "1591", "15910",
          "primes", "Primes", "PRIMES", "163", "193", "163193", "193163", "76", "74", "7674", "7476",
          "1627", "7,6", "7 6", "(7,6)", "(7,4)", "7,4", "7 4", "76+74", "150", "gsmg.io/theseedisplanted",
          "theseedisplanted", "theseedisplanted0100", "0100", "4", "2", "0100gsmg.io/theseedisplanted"):
    test_candidate("B/literal", text=t)
# canais das 24 coloridas em espiral (valores reais 63/72/204 e 255/242/0)
for ch, f in CH.items():
    vals = [f(RGB[G.COLORED[i][1]][G.COLORED[i][2]]) for i in col_idx]
    test_candidate(f"B/colored24/{ch}", text="".join(map(str, vals)), raw=bytes(v % 256 for v in vals))
    test_candidate(f"B/colored24/{ch}/hex", text="".join("%02x" % (v % 256) for v in vals))
    test_candidate(f"B/colored24/{ch}/mod9", text="".join("abcdefghi"[v % 9] for v in vals))
    test_candidate(f"B/colored24/{ch}/sum", text=str(sum(vals)))
G.jsonl(LOG, {"stage": "B literals done", "n": N, "cand": CAND, "t": round(time.time() - t0, 1)})

# keystream mod-9 sobre faed -> Bifid CANON 570 e checkerboard; sobre dbbi -> z-method
ESC = [(a, b) for a in range(1, 10) for b in range(1, 10) if a < b]      # 36 pares
ALPHAS = {"CANON": G.CANON, "P32": "FUBCDORALETHINGKYMVPSJQZXW"}
fd = G.digits(G.FAED); dd = G.digits(G.DBBI)
bif_ctrl = G.bifid(G.FAED, G.CANON, 570); assert bif_ctrl.startswith("BTCSEED")
ks_n = 0
for kname, seq in KEYSTREAMS.items():
    for sign in (1, -1):
        f2 = "".join("abcdefghi"[(d - 1 + sign * seq[i % 196]) % 9] for i, d in enumerate(fd))
        d2 = "".join("abcdefghi"[(d - 1 + sign * seq[i % 196]) % 9] for i, d in enumerate(dd))
        test_candidate(f"B/ks/{kname}/{sign}/faed", text=f2)
        test_candidate(f"B/ks/{kname}/{sign}/dbbi", text=d2)
        try: test_candidate(f"B/ks/{kname}/{sign}/dbbi/zmethod", raw=G.z_method(G.digits(d2)))
        except Exception: pass
        try: test_candidate(f"B/ks/{kname}/{sign}/faed/zmethod", raw=G.z_method(G.digits(f2)))
        except Exception: pass
        for per in (570, 285, None):
            bf = G.bifid(f2, G.CANON, per or len(f2)); N += 1; ks_n += 1
            upd_best(bf, f"B/ks/{kname}/{sign}/bifid{per}")
            if G.semantic_text(bf): G.jsonl(LOG, {"soft_text": f"B/ks/{kname}/{sign}/bifid{per}", "text": bf[:200]})
        dg = G.digits(f2)
        for an, al in ALPHAS.items():
            for e in ESC:
                cb = G.checkerboard_decode(dg, al, e); N += 1; ks_n += 1
                upd_best(cb, f"B/ks/{kname}/{sign}/cb/{an}/{e}")
                if G.semantic_text(cb): G.jsonl(LOG, {"soft_text": f"B/ks/{kname}/{sign}/cb/{an}/{e}", "text": cb[:200]})
G.jsonl(LOG, {"stage": "B keystream done", "n": N, "cand": CAND, "ks_decodes": ks_n, "t": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ PARTE C: (7,6)/(7,4), 163/193 como cortes
CUTS = sorted({11, 72, 163, 193, 102, 104, 76, 74, 42, 28, 7, 6, 4, 30, 356, 163 + 193, 163 * 2, 193 - 163, 91 - 11, 91 - 72,
               570 - 163, 570 - 193, 285 - 163, 285 - 193 + 285})
def variants(S, k):
    L = len(S); k %= L
    return {"rot": S[k:] + S[:k], "head": S[:k], "tail": S[k:], "del": S[:k] + S[k + 1:], "swap": S[k:] + S[:k],
            "zero": S[:k] + "o" + S[k + 1:], "rev_rot": (S[k:] + S[:k])[::-1]}
for sname, S in (("dbbi", G.DBBI), ("faed", G.FAED)):
    for k in CUTS:
        for vn, v in variants(S, k).items():
            if len(v) < 4 or (vn == "swap" and k % len(S) == 0): continue
            nm = f"C/{sname}/{k}/{vn}"
            test_candidate(nm, text=v)
            try: test_candidate(nm + "/zmethod", raw=G.z_method([0 if c == "o" else G.A2I[c] for c in v]))
            except Exception: pass
            if sname == "faed" and "o" not in v:
                bf = G.bifid(v, G.CANON, len(v)); N += 1; upd_best(bf, nm + "/bifid")
                if G.semantic_text(bf): G.jsonl(LOG, {"soft_text": nm + "/bifid", "text": bf[:200]})
                if len(v) % 2 == 0:
                    bf = G.bifid(v, G.CANON, len(v) // 2); N += 1; upd_best(bf, nm + "/bifid_half")
                    if G.semantic_text(bf): G.jsonl(LOG, {"soft_text": nm + "/bifid_half", "text": bf[:200]})
    # caracteres em posicoes 163/193/11/72 etc. e nos primos
    test_candidate(f"C/{sname}/at_primes", text="".join(S[p] for p in PRIMES if p < len(S)))
    test_candidate(f"C/{sname}/at_nonprimes", text="".join(S[i] for i in range(len(S)) if not G.is_prime(i)))
    test_candidate(f"C/{sname}/at_primes_b1", text="".join(S[p - 1] for p in PRIMES if p - 1 < len(S)))
    test_candidate(f"C/{sname}/at_nonprimes_b1", text="".join(S[i - 1] for i in range(1, len(S) + 1) if not G.is_prime(i)))
    test_candidate(f"C/{sname}/at_11_72_163_193", text="".join(S[i % len(S)] for i in (11, 72, 163, 193)))
# sub-bitmap 5px do coelho (regiao central, bbox dos pixels pretos nas celulas 6..8 x 6..9)
sub = [[1 if px[x * 5 + 2, y * 5 + 2] == (0, 0, 0) else 0 for x in range(70)] for y in range(70)]
ys = [y for y in range(30, 45) for x in range(30, 50) if sub[y][x]]; xs = [x for y in range(30, 45) for x in range(30, 50) if sub[y][x]]
y0, y1, x0, x1 = min(ys), max(ys), min(xs), max(xs)
rab = [sub[y][x] for y in range(y0, y1 + 1) for x in range(x0, x1 + 1)]
G.jsonl(LOG, {"rabbit_bbox": [y0, y1, x0, x1], "rabbit_bits": "".join(map(str, rab))})
emit_bits("C/rabbit/rowmajor", rab)
emit_bits("C/rabbit/colmajor", [sub[y][x] for x in range(x0, x1 + 1) for y in range(y0, y1 + 1)])
emit_bits("C/rabbit/region10x21", [sub[y][x] for y in range(30, 40) for x in range(30, 51)])
test_candidate("C/rabbit/count", text=str(sum(rab)))
G.jsonl(LOG, {"stage": "C done", "n": N, "cand": CAND, "t": round(time.time() - t0, 1)})

summary = {"family": "matrix_prime_bits", "n_tests": N, "candidates": CAND, "hard": len(HARD), "soft": len(SOFT),
           "best_readable": BEST, "counts": CNT, "secs": round(time.time() - t0, 1)}
G.jsonl(LOG, {"summary": summary})
print(json.dumps(summary, ensure_ascii=False))
print("SOFT (padding valido, sem semantica):", len(SOFT))
for s in SOFT[:20]: print("  ", s["how"], s["blob"], s["kdf"], s["len"], s["printable"])
print("HARD:", json.dumps(HARD, ensure_ascii=False)[:2000])
