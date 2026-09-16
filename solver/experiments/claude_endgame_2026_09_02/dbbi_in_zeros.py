# -*- coding: utf-8 -*-
"""
Família dbbi_in_zeros — o dbbi (91) preenche as 91 células-zero do trecho URL (espiral 0..191)
da matriz verdadeira (102 uns). Extrai palavras-chave por células primas/amarelas/FEFEFE,
relê a matriz preenchida em outras geometrias, calcula o "matrixsumlist" da matriz preenchida
e faz o "zeroed out" + z-method. Cada string → senha/sha256 nos 3 blobs (KDF SHA256),
z-method, Bifid keyed, checkerboard, keystream mod-9, privkey.
"""
import sys, os, json, base64, hashlib, itertools, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

LOG = os.path.join(SP, "dbbi_in_zeros.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)

N = 14
DBBI = G.DBBI; FAED = G.FAED
FAED_D = G.digits(FAED)                    # 1..9
ALPHA322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
ESCAPES = list(itertools.combinations(range(1, 10), 2))   # 36
PRIMES192 = {i for i in range(192) if G.is_prime(i)}
YELLOW = set(G.YELLOW_IDX); FEFEFE = 163
HYP = ("dbbi (91) preenche as 91 células-zero da espiral 0..191 da matriz verdadeira; a senha sai das letras "
       "em células primas/amarelas/FEFEFE, da matriz relida em outra geometria, das somas de linha/coluna "
       "(matrixsumlist) como senha/keystream, ou do dbbi 'zeroed out' nessas posições + z-method.")
log({"hypothesis": HYP, "family": "dbbi_in_zeros"})

# ---------------------------------------------------------------- geometrias
SPIRAL_CCW = G.SPIRAL                                       # a do puzzle (0..195)
def spiral_cw(n=N):
    seen = set(); order = []; r = c = 0; d = 0
    dirs = [(0, 1), (1, 0), (0, -1), (-1, 0)]              # direita, desce, esquerda, sobe
    for _ in range(n * n):
        order.append((r, c)); seen.add((r, c))
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if not (0 <= nr < n and 0 <= nc < n) or (nr, nc) in seen:
            d = (d + 1) % 4; nr, nc = r + dirs[d][0], c + dirs[d][1]
        r, c = nr, nc
    return order
SPIRAL_CW = spiral_cw()
CENTER = set(SPIRAL_CCW[192:])                              # 2x2 central (fora do trecho URL)
IDX_CCW = {rc: i for i, rc in enumerate(SPIRAL_CCW)}       # célula -> índice espiral do puzzle
ROWMAJ = [(r, c) for r in range(N) for c in range(N)]
COLMAJ = [(r, c) for c in range(N) for r in range(N)]
DIAG = [(r, c) for s in range(2 * N - 1) for r in range(N) for c in range(N) if r + c == s]      # anti-diagonais
DIAG2 = [(r, c) for s in range(-N + 1, N) for r in range(N) for c in range(N) if r - c == s]     # diagonais
RINGS = [(r, c) for k in range(N // 2) for (r, c) in ROWMAJ if min(r, c, N - 1 - r, N - 1 - c) == k]
BOUSTRO = [(r, c) for r in range(N) for c in (range(N) if r % 2 == 0 else range(N - 1, -1, -1))]
def outer(order): return [rc for rc in order if rc not in CENTER]      # 192 células do trecho URL
FILLS = {
    "spiral_ccw": outer(SPIRAL_CCW), "spiral_cw": outer(SPIRAL_CW),
    "spiral_ccw_rev": outer(SPIRAL_CCW)[::-1], "spiral_cw_rev": outer(SPIRAL_CW)[::-1],   # "do centro"
    "rowmajor": outer(ROWMAJ), "colmajor": outer(COLMAJ),
    "rowmajor_rev": outer(ROWMAJ)[::-1], "colmajor_rev": outer(COLMAJ)[::-1],
}
READS = dict(FILLS, **{"diag": outer(DIAG), "diag2": outer(DIAG2), "rings": outer(RINGS), "boustro": outer(BOUSTRO)})
MATS = {"IMG": G.MATRIX_IMG, "README": G.MATRIX_README}

def fill(M, order):
    """Devolve dict célula->letra para as células-zero (fora do centro) na ordem dada."""
    zeros = [rc for rc in order if M[rc[0]][rc[1]] == 0]
    assert len(zeros) in (91, 92), len(zeros)
    return {rc: DBBI[i] for i, rc in enumerate(zeros[:91])}, zeros[91:]   # sobra (README: 1 célula)

# ---------------------------------------------------------------- testes por string
n_tests = 0
hard, soft = [], []
best = {"score": -99, "text": "", "how": ""}
seen_str = set()

def note_text(t, how, min_score=-4.5):
    """Triagem para texto de decoder (nunca G.semantic)."""
    global best
    sc = G.english_score(t) if len(t) >= 8 else -99
    if sc > best["score"]:
        best = {"score": round(sc, 3), "text": t[:120], "how": how}
    if len(t) >= 12 and G.semantic_text(t, min_score=min_score):
        soft.append({"kind": "text", "how": how, "score": round(sc, 3), "text": t[:160]})
        log({"soft_text": how, "score": round(sc, 3), "text": t[:200]})

def aes_pw(pw, how):
    global n_tests
    for blob in ("SMALL", "COSMIC", "TAIL32"):
        n_tests += 1
        for kdf, p in G.aes_try(pw, blob, kdf="sha256"):
            rec = {"blob": blob, "kdf": kdf, "pw": pw if isinstance(pw, str) else pw.hex(), "how": how,
                   "len": len(p), "printable": round(G.printable(p), 3), "head": p[:48].decode("latin-1")}
            if G.semantic(p):
                rec["plaintext_hex"] = p.hex(); hard.append(rec); log({"HARD": rec})
            else:
                soft.append({"kind": "padding", **rec}); log({"soft_pad": rec})

def priv_bytes(b, how):
    global n_tests
    if len(b) == 32:
        n_tests += 1
        r = G.priv_hit(b)
        if r: hard.append({"kind": "priv", "how": how, "priv_hex": b.hex(), "r": str(r)}); log({"HARD": how, "priv": b.hex()})
    elif len(b) > 32:
        n_tests += len(b) - 31
        for h in G.fast_priv_scan(b, how):
            hard.append({"kind": "priv", "how": how, "hit": h}); log({"HARD": how, "hit": h})

def test_string(s, how):
    """s: string de letras a-i (ou mista). Aplica a bateria completa."""
    global n_tests
    if not s or s in seen_str: return
    seen_str.add(s)
    # senhas cruas / sha256hex
    for f, pw in (("raw", s), ("upper", s.upper()), ("sha", G.shahex(s)), ("sha_upper", G.shahex(s.upper()))):
        aes_pw(pw, f"{how}|pw:{f}")
    priv_bytes(G.sha(s), f"{how}|sha256->priv")
    priv_bytes(G.sha(G.sha(s)), f"{how}|sha256d->priv")
    # z-method (a=1..i=9): dígitos → decimal → hex → bytes
    d = G.digits(s)
    if d:
        zb = G.z_method(d); n_tests += 1
        if G.printable(zb) >= 0.85 and len(zb) >= 6:
            note_text(zb.decode("latin-1"), f"{how}|zmethod")
            aes_pw(zb.decode("latin-1"), f"{how}|zmethod-pw")
        priv_bytes(zb, f"{how}|zmethod->priv")
        ds = "".join(map(str, d))
        aes_pw(ds, f"{how}|digits-pw")
        # a1z26 mod 26 (dígitos 1..9 são já letras a-i; pares de dígitos como letras 1..26)
        pairs = [int(ds[i:i + 2]) for i in range(0, len(ds) - 1, 2)]
        t = "".join(chr(64 + p) for p in pairs if 1 <= p <= 26)
        n_tests += 1; note_text(t, f"{how}|digitpairs-a1z26")
    # alfabeto keyed pela string → Bifid 5x5 em faed
    if any(c.isalpha() for c in s):
        ka = G.keyed_alphabet(s)
        for per in (570, 285):
            n_tests += 1
            t = G.bifid(FAED, ka, per); note_text(t, f"{how}|bifid-keyed-{per}")
        # checkerboard em faed com alfabeto keyed, 36 escapes
        for e in ESCAPES:
            n_tests += 1
            t = G.checkerboard_decode(FAED_D, ka, e); note_text(t, f"{how}|cb-keyed-esc{e}")

def test_sums(sums, how):
    """28 números (linhas+colunas): senha, keystream mod-9 sobre faed, ASCII, priv."""
    global n_tests
    key = tuple(sums)
    if key in seen_str: return
    seen_str.add(key)
    for f, pw in (("cat", "".join(map(str, sums))), ("comma", ",".join(map(str, sums))),
                  ("space", " ".join(map(str, sums)))):
        aes_pw(pw, f"{how}|pw:{f}"); aes_pw(G.shahex(pw), f"{how}|pw:sha({f})")
    priv_bytes(G.sha("".join(map(str, sums))), f"{how}|sha->priv")
    # somas como ASCII / mod 26
    n_tests += 2
    note_text("".join(chr(x) for x in sums if 32 <= x < 127), f"{how}|ascii")
    note_text("".join(chr(65 + x % 26) for x in sums), f"{how}|mod26")
    zb = G.z_method([int(c) for c in "".join(map(str, sums))]); n_tests += 1
    if G.printable(zb) >= 0.85: note_text(zb.decode("latin-1"), f"{how}|zmethod")
    priv_bytes(zb, f"{how}|zmethod->priv")
    # keystream mod-9 sobre faed (soma e subtração) → Bifid CANON 570 e checkerboard
    for sign in (1, -1):
        ks = [((FAED_D[i] - 1 + sign * sums[i % len(sums)]) % 9) + 1 for i in range(len(FAED_D))]
        kt = "".join("abcdefghi"[k - 1] for k in ks)
        n_tests += 1; note_text(G.bifid(kt, G.CANON, 570), f"{how}|ks{sign:+d}|bifid-canon")
        for aname, alpha in (("322", ALPHA322), ("canon", G.CANON)):
            for e in ESCAPES:
                n_tests += 1
                note_text(G.checkerboard_decode(ks, alpha, e), f"{how}|ks{sign:+d}|cb-{aname}-esc{e}")

# ---------------------------------------------------------------- controles positivos
def controls():
    global n_tests
    # (1) Bifid keyed reproduz BTCSEED quando a frase é a ordem de 1ª ocorrência do dbbi
    assert G.keyed_alphabet(DBBI) == G.CANON
    assert G.bifid(FAED, G.keyed_alphabet(DBBI), 570).startswith("BTCSEED")
    # (2) pipeline AES detecta blob plantado: senha = sha256hex da 1ª extração (spiral_ccw, primos)
    F, _ = fill(G.MATRIX_IMG, FILLS["spiral_ccw"])
    s = "".join(F[rc] for rc in FILLS["spiral_ccw"] if rc in F and IDX_CCW[rc] in PRIMES192)
    pw = G.shahex(s).encode(); salt = b"\x01" * 8
    k, iv = G.evp(pw, salt, SHA256)
    pt = b"the seed is planted; control plaintext for dbbi_in_zeros pipeline!!"
    pt += bytes([16 - len(pt) % 16]) * (16 - len(pt) % 16)
    G.BLOBS["CTRL"] = (salt, AES.new(k, AES.MODE_CBC, iv).encrypt(pt))
    got = [G.semantic(p) for _, p in G.aes_try(G.shahex(s), "CTRL", kdf="sha256")]
    assert got == [True], got
    del G.BLOBS["CTRL"]
    # (3) 91 zeros no trecho URL; 15 primos; 9 amarelas
    zeros = [rc for rc in FILLS["spiral_ccw"] if G.MATRIX_IMG[rc[0]][rc[1]] == 0]
    assert len(zeros) == 91 and sum(IDX_CCW[rc] in PRIMES192 for rc in zeros) == 15
    assert sum(IDX_CCW[rc] in YELLOW for rc in zeros) == 9 and all(G.MATRIX_IMG[r][c] == 0 for i, (_, r, c) in G.COLORED.items() if i in YELLOW)
    log({"controls": "ok", "ctrl_string_spiral_ccw_primes": s})
    print("controles OK; primos(spiral_ccw) =", s)
controls()

# ---------------------------------------------------------------- (i)+(ii)+(iii)+(iv)
t0 = time.time()
for mname, M in MATS.items():
    for fname, forder in FILLS.items():
        F, leftover = fill(M, forder)
        how0 = f"{mname}/{fname}"
        # (i) extrações por conjunto de células, em 3 ordens de leitura
        sets = {
            "primes": lambda rc: IDX_CCW[rc] in PRIMES192,
            "yellow": lambda rc: IDX_CCW[rc] in YELLOW,
            "fefefe": lambda rc: IDX_CCW[rc] == FEFEFE,
            "yellow+primes": lambda rc: IDX_CCW[rc] in YELLOW or IDX_CCW[rc] in PRIMES192,
            "yellow&primes": lambda rc: IDX_CCW[rc] in YELLOW and IDX_CCW[rc] in PRIMES192,
            "yellow+primes+fefefe": lambda rc: IDX_CCW[rc] in YELLOW or IDX_CCW[rc] in PRIMES192 or IDX_CCW[rc] == FEFEFE,
            "not_primes": lambda rc: IDX_CCW[rc] not in PRIMES192,
            "not_yellow": lambda rc: IDX_CCW[rc] not in YELLOW,
            "not_yellow_primes": lambda rc: not (IDX_CCW[rc] in YELLOW or IDX_CCW[rc] in PRIMES192),
        }
        for sname, pred in sets.items():
            for rname in ("spiral_ccw", "rowmajor", "colmajor"):
                s = "".join(F[rc] for rc in READS[rname] if rc in F and pred(rc))
                if sname == "fefefe":      # 1 letra: só como prefixo/sufixo junto das amarelas
                    continue
                test_string(s, f"{how0}|{sname}|read:{rname}")
                log({"extract": how0, "set": sname, "read": rname, "s": s})
        f1 = next((F[rc] for rc in F if IDX_CCW[rc] == FEFEFE), "")
        ys = "".join(F[rc] for rc in READS["spiral_ccw"] if rc in F and IDX_CCW[rc] in YELLOW)
        test_string(f1 + ys, f"{how0}|fefefe+yellow"); test_string(ys + f1, f"{how0}|yellow+fefefe")
        # (ii) matriz preenchida relida (permutações do dbbi) + variante com uns='1'
        for rname, rorder in READS.items():
            if rname == fname: continue
            s = "".join(F[rc] for rc in rorder if rc in F)
            test_string(s, f"{how0}|reread:{rname}")
            s1 = "".join(F.get(rc, "1" if M[rc[0]][rc[1]] else "0") for rc in rorder)
            for f, pw in (("raw", s1), ("sha", G.shahex(s1))): aes_pw(pw, f"{how0}|reread1:{rname}|pw:{f}")
            priv_bytes(G.sha(s1), f"{how0}|reread1:{rname}|sha->priv")
        # (iii) matrixsumlist da matriz preenchida
        for ones in (1, 0, 9):
            for base1 in (True, False):
                def val(r, c):
                    if (r, c) in F: return ord(F[(r, c)]) - (96 if base1 else 97)
                    return ones if M[r][c] else 0
                rs = [sum(val(r, c) for c in range(N)) for r in range(N)]
                cs = [sum(val(r, c) for r in range(N)) for c in range(N)]
                test_sums(rs + cs, f"{how0}|sums|ones={ones}|a={'1' if base1 else '0'}")
                test_sums(cs + rs, f"{how0}|sums-colsfirst|ones={ones}|a={'1' if base1 else '0'}")
        # (iv) zeroed out: posições do dbbi que caíram em células primas/amarelas → 'o' (=0) → z-method
        pos = {rc: i for i, rc in enumerate([rc for rc in forder if M[rc[0]][rc[1]] == 0][:91])}
        for sname, pred in (("primes", lambda rc: IDX_CCW[rc] in PRIMES192), ("yellow", lambda rc: IDX_CCW[rc] in YELLOW),
                            ("yellow+primes", lambda rc: IDX_CCW[rc] in YELLOW or IDX_CCW[rc] in PRIMES192)):
            idx = {i for rc, i in pos.items() if pred(rc)}
            for mode in ("zero", "delete", "keep"):
                if mode == "zero": ds = [0 if i in idx else G.A2I[c] for i, c in enumerate(DBBI)]
                elif mode == "delete": ds = [G.A2I[c] for i, c in enumerate(DBBI) if i not in idx]
                else: ds = [G.A2I[c] for i, c in enumerate(DBBI) if i in idx]
                zb = G.z_method(ds); n_tests += 1
                how = f"{how0}|zeroed:{sname}:{mode}"
                if G.printable(zb) >= 0.85 and len(zb) >= 6:
                    note_text(zb.decode("latin-1"), how + "|zmethod"); aes_pw(zb.decode("latin-1"), how + "|zmethod-pw")
                priv_bytes(zb, how + "|zmethod->priv")
                dstr = "".join(map(str, ds))
                aes_pw(dstr, how + "|digits-pw"); aes_pw(G.shahex(dstr), how + "|sha(digits)-pw")
                priv_bytes(G.sha(dstr), how + "|sha->priv")
                log({"zeroed": how, "digits": dstr, "z_printable": round(G.printable(zb), 3), "z_head": zb[:40].decode("latin-1")})
    print(f"{mname}: n_tests={n_tests} strings={len(seen_str)} t={time.time()-t0:.0f}s hard={len(hard)} soft={len(soft)}")

summary = {"family": "dbbi_in_zeros", "hypothesis": HYP, "n_tests": n_tests, "n_strings": len(seen_str),
           "hard_hits": hard, "soft_hits": soft[:50], "n_soft": len(soft), "best_readable": best,
           "script": os.path.join(SP, "dbbi_in_zeros.py")}
log({"summary": summary})
json.dump(summary, open(os.path.join(SP, "dbbi_in_zeros_summary.json"), "w"), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in summary.items() if k not in ("soft_hits",)}, ensure_ascii=False)[:3000])
