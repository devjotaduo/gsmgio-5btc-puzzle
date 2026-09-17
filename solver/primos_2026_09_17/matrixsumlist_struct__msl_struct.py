# -*- coding: utf-8 -*-
"""
matrixsumlist ESTRUTURAL sobre o resíduo dos marcadores primos (L83/L84).
Hipóteses A-D (ver JSONL 'hypothesis'). Oráculo: G.try_password_all + privkey (coincurve).
"""
import sys, os, json, random, hashlib, functools, base64, time
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from coincurve import PublicKey
OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "msl_struct.jsonl")
PADLOG = os.path.join(OUT, "paddings.jsonl")
open(LOG, "w").close(); open(PADLOG, "w").close()
def log(**o): G.jsonl(LOG, o)
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
random.seed(20260917)

# ---------------------------------------------------------------- 0. segmentação (regra do atlas)
def segment(s, L):
    """Posições lógicas 1..L; primas consomem 'b' ou 'be'; demais 1 símbolo; consumo integral. Tupla de tokens ou None."""
    primes = [G.is_prime(i) for i in range(L + 1)]
    @functools.lru_cache(None)
    def rec(pos, i):
        if pos > L: return () if i == len(s) else None
        if primes[pos]:
            for tk in ("be", "b"):
                if s.startswith(tk, i):
                    r = rec(pos + 1, i + len(tk))
                    if r is not None: return (tk,) + r
            return None
        if i < len(s):
            r = rec(pos + 1, i + 1)
            return None if r is None else (s[i],) + r
        return None
    return rec(1, 0)
SEGS = {L: segment(G.DBBI, L) for L in range(40, 92) if segment(G.DBBI, L) is not None}
assert sorted(SEGS) == [83, 84], sorted(SEGS)
def residue(tokens): return "".join(t for i, t in enumerate(tokens, 1) if not G.is_prime(i))
def markers(tokens): return [t for i, t in enumerate(tokens, 1) if G.is_prime(i)]
RES = {L: residue(SEGS[L]) for L in SEGS}
assert RES[84] == "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae" and RES[83] == RES[84][:-1]
MK = {L: markers(SEGS[L]) for L in SEGS}
BITS = {L: "".join("1" if m == "be" else "0" for m in MK[L]) for L in SEGS}
assert BITS[84] == "00001000110000100110010" and BITS[83] == "00001000110000100110011"
# controle: yellowblueprimes — cores dos 25 eventos (W=B) sem os eventos 22,25 == bits L84
col25 = "".join("1" if G.COLORED[k][0] == "Y" else "0" for k in sorted(G.COLORED))
assert len(col25) == 25
sel84 = [i for i in range(25) if i + 1 not in (22, 25)]
sel83 = [i for i in range(25) if i + 1 not in (22, 24)]
assert "".join(col25[i] for i in sel84) == BITS[84] and "".join(col25[i] for i in sel83) == BITS[83]
# controle da segmentação: dbbi sintético com marcadores plantados é recuperado
def synth(L):
    return [(random.choice(["b", "be"]) if G.is_prime(i) else random.choice("acdfghi")) for i in range(1, L + 1)]
for _ in range(5):
    t = synth(random.randint(50, 90)); assert segment("".join(t), len(t)) == tuple(t)
log(kind="segmentation", L83=dict(res=RES[83], bits=BITS[83], b=MK[83].count("b"), be=MK[83].count("be")),
    L84=dict(res=RES[84], bits=BITS[84], b=MK[84].count("b"), be=MK[84].count("be")), controls="5 sintéticos + yellowblueprimes ok")

# ---------------------------------------------------------------- oráculos / contadores
N_PW = 0; N_AES = 0; N_PRIV = 0; HARD = []; SOFT = 0; SEEN_PW = set(); SEEN_PRIV = set()
def priv(b32, where):
    """oráculo duro de privkey (coincurve, pubkey não-comprimida == alvo)."""
    global N_PRIV
    if len(b32) != 32 or b32 in SEEN_PRIV: return
    SEEN_PRIV.add(b32); N_PRIV += 1
    try:
        if PublicKey.from_valid_secret(b32).format(False) == TGT:
            HARD.append(dict(kind="PRIVKEY", where=where, hex=b32.hex())); print("!!! PRIVKEY", where)
    except Exception: pass
def pw_test(pw, where):
    """senha crua + sha256hex; 3 blobs x 2 KDF; registra paddings; privkey de sha256(pw)."""
    global N_PW, N_AES, SOFT
    if isinstance(pw, str): pw = pw.encode()
    if not pw: return
    for p in (pw, G.shahex(pw).encode()):
        if p in SEEN_PW: continue
        SEEN_PW.add(p); N_PW += 1; N_AES += 6
        h, s = G.try_password_all(p)
        for r in h:
            r.update(where=where, pw=p.decode("latin-1")); HARD.append(r); print("!!! HARD", where, r["blob"], r["kdf"])
        for r in s:
            SOFT += 1; r.update(where=where, pw=p.decode("latin-1")); G.jsonl(PADLOG, r)
    priv(G.sha(pw), where + "|sha256(pw)"); priv(G.sha(G.sha(pw)), where + "|sha256d(pw)")
def bytes_test(b, where):
    """material binário: senha crua + hex; privkey janela 32B; semântica."""
    if not b: return
    pw_test(b, where); pw_test(b.hex(), where + "|hex")
    if len(b) >= 32:
        for j in range(len(b) - 31): priv(b[j:j + 32], f"{where}|win{j}")
    else:
        priv(b.rjust(32, b"\0"), where + "|lpad"); priv(b.ljust(32, b"\0"), where + "|rpad")
    if len(b) >= 16 and G.semantic(b):
        HARD.append(dict(kind="SEMANTIC_BYTES", where=where, hex=b.hex(), text=b.decode("latin-1"))); print("!!! SEM", where)
def list_test(L, where):
    """lista de inteiros -> serializações ' ', ',', '', hex, z-method; senha + privkey (sha256 e bytes32)."""
    if not L: return
    ser = {"sp": " ".join(map(str, L)), "cm": ",".join(map(str, L)), "cat": "".join(map(str, L)),
           "hex": "".join(format(x % 256, "02x") for x in L)}
    for k, s in ser.items(): pw_test(s, f"{where}|{k}")
    try:
        z = G.z_method(L)
        if z: bytes_test(z, f"{where}|z")
    except Exception: pass
    raw = bytes(x % 256 for x in L)
    if len(raw) == 32: priv(raw, where + "|bytes32")
    elif len(raw) < 32: priv(raw.rjust(32, b"\0"), where + "|bytes32lpad"); priv(raw.ljust(32, b"\0"), where + "|bytes32rpad")
    else:
        for j in range(len(raw) - 31): priv(raw[j:j + 32], f"{where}|bytes32win{j}")
def sums_lists(M, where):
    r, c = G.row_sums(M), G.col_sums(M); t = sum(r)
    for k, L in {"rows": r, "cols": c, "rowcol": r + c, "colrow": c + r, "rowcol_t": r + c + [t], "total": [t]}.items():
        list_test(L, f"{where}|{k}")
# controles dos oráculos
raw2 = base64.b64decode(G.PHASE2_B64); s2, c2 = raw2[8:16], raw2[16:]
k2, iv2 = G.evp(G.shahex("causality").encode(), s2, G.SHA256)
assert G.unpad(G.AES.new(k2, G.AES.MODE_CBC, iv2).decrypt(c2)).startswith(b"The ironic")
_sec = hashlib.sha256(b"controle").digest(); _pub = PublicKey.from_valid_secret(_sec).format(False)
_buf = b"\x11" * 7 + _sec + b"\x22" * 5
assert any(PublicKey.from_valid_secret(_buf[j:j + 32]).format(False) == _pub for j in range(len(_buf) - 31))
log(kind="controls", aes="fase 2 abre com sha256hex(causality)/EVP-SHA256", priv="janela 32B acha chave plantada")

# ---------------------------------------------------------------- dados
VAL = {"a1": {c: i + 1 for i, c in enumerate("abcdefghi")}, "a0": {c: i for i, c in enumerate("abcdefghi")}}
SEQS = {"r84": RES[84], "r83": RES[83], "r84v": RES[84][::-1], "r83v": RES[83][::-1]}
def tok_digits(L, mode):
    """84/83 tokens lógicos -> dígitos; marcadores b/be zerados ('zero') ou como bits ('bits')."""
    out = []
    for i, t in enumerate(SEGS[L], 1):
        if G.is_prime(i): out.append((1 if t == "be" else 0) if mode == "bits" else 0)
        else: out.append(VAL["a1"][t])
    return out
M = G.MATRIX_README
rm = [(r, c) for r in range(14) for c in range(14)]; cm = [(r, c) for c in range(14) for r in range(14)]
sp = list(G.SPIRAL); spc = sp[::-1]
ORDERS = {"row": rm, "col": cm, "spiral": sp, "center": spc}
def cls(pred): return {o: [rc for rc in order if pred(rc)] for o, order in ORDERS.items()}
CELLS = {}
CELLS["zeros95"] = cls(lambda rc: M[rc[0]][rc[1]] == 0)
CELLS["ones101"] = cls(lambda rc: M[rc[0]][rc[1]] == 1)
colored25 = [G.COLORED[k][1:] for k in sorted(G.COLORED)]
colored24 = [G.COLORED[k][1:] for k in sorted(G.COLORED) if k != 163]
CELLS["colored24"] = {"spiral": colored24, "center": colored24[::-1]}
CELLS["colored25"] = {"spiral": colored25, "center": colored25[::-1]}
CELLS["sel23_L84"] = {"spiral": [colored25[i] for i in sel84], "center": [colored25[i] for i in sel84][::-1]}
CELLS["sel23_L83"] = {"spiral": [colored25[i] for i in sel83], "center": [colored25[i] for i in sel83][::-1]}
CELLS["prime0"] = {"spiral": [sp[i] for i in range(196) if G.is_prime(i)]}
CELLS["prime1"] = {"spiral": [sp[i] for i in range(196) if G.is_prime(i + 1)]}
CELLS["all196"] = ORDERS
assert len(CELLS["zeros95"]["row"]) == 95 and len(CELLS["ones101"]["row"]) == 101 and len(CELLS["prime0"]["spiral"]) == 44
def fill(cells, digs, base):
    Mx = [row[:] for row in base]
    for (r, c), d in zip(cells, digs): Mx[r][c] = d
    return Mx
Z = [[0] * 14 for _ in range(14)]
# controle do preenchimento: 14 'i' na linha 0 -> soma da linha 0 = 126; coluna 0 = 9
_c = fill(rm[:14], [9] * 14, Z); assert G.row_sums(_c)[0] == 126 and G.col_sums(_c)[0] == 9

# ---------------------------------------------------------------- A
log(kind="hypothesis", id="A", text="O resíduo (61/60 símbolos, a=1..i=9 ou a=0..i=8, direto/reverso) preenche, em ordem linha/coluna/espiral/centro, as células de uma classe da matriz 14x14 (95 zeros, 101 uns, 24/25 coloridas, 23 selecionadas L84/L83, primas da espiral 0/1-based, todas 196); células restantes = 0 ou o bit original; variante alinhada ao fim da classe. As somas de linha/coluna (+total) são a 'matrix sum list' -> senha (5 serializações, crua e sha256) e privkey (sha256, bytes32, z-method).")
t0 = time.time(); nA = 0
for cname, orders in CELLS.items():
    for oname, cells in orders.items():
        for sname, seq in SEQS.items():
            for vname, vm in VAL.items():
                digs = [vm[c] for c in seq]
                for fname, base in (("zero", Z), ("bits", M)):
                    Mx = fill(cells, digs, base); nA += 1
                    sums_lists(Mx, f"A|{cname}|{oname}|{sname}|{vname}|{fname}")
                if len(cells) > len(digs):
                    Mx = fill(cells[-len(digs):], digs, Z); nA += 1
                    sums_lists(Mx, f"A|{cname}|{oname}|{sname}|{vname}|zero_tail")
log(kind="progress", stage="A", matrices=nA, n_pw=N_PW, soft=SOFT, secs=round(time.time() - t0))
print("A done", nA, N_PW, SOFT, round(time.time() - t0), flush=True)

# ---------------------------------------------------------------- B
log(kind="hypothesis", id="B", text="'matrix sum list' = somas de linha/coluna do resíduo (a=1 e a=0) e dos 84/83 tokens (marcadores=0 ou =bit b/be) em TODAS as grades exatas (+1xN, Nx1), direto e reverso; listas -> senhas (5 serializações + sha256), z-method (dec->hex->ASCII), privkey e índices (0/1-based) em textos do puzzle (Arquiteto, 3.2.2, roadmap, dbbi, faed).")
ARCH = "YOURLIFEISTHESUM" + "".join(c for c in open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
               .split("YOUR LIFE IS THE SUM", 1)[1].split("```", 1)[0] if c.isalpha())
alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
P322 = G.checkerboard_decode([int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"], alpha322, (1, 4), "0123456789")
assert P322.startswith("INCASEYOUMANAGE") and ARCH.endswith("CIAOBELLAO"), (P322[:20], ARCH[-20:])
ROAD = "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang"
TEXTS = {"arch": ARCH, "p322": P322, "road": ROAD, "dbbi": G.DBBI, "faed": G.FAED}
TEXT_OUT = []
def index_test(L, where):
    for tn, T in TEXTS.items():
        for b in (0, 1):
            s = "".join(T[(x - b) % len(T)] for x in L)
            TEXT_OUT.append((where + f"|idx_{tn}_{b}", s)); pw_test(s, where + f"|idx_{tn}_{b}")
def grids(n): return [(a, n // a) for a in range(2, n) if n % a == 0]
GRID_SEQS = {"r84": [VAL["a1"][c] for c in RES[84]], "r83": [VAL["a1"][c] for c in RES[83]],
             "r84_a0": [VAL["a0"][c] for c in RES[84]], "r83_a0": [VAL["a0"][c] for c in RES[83]],
             "t84_zero": tok_digits(84, "zero"), "t84_bits": tok_digits(84, "bits"),
             "t83_zero": tok_digits(83, "zero"), "t83_bits": tok_digits(83, "bits")}
nB = 0
for sname, digs in GRID_SEQS.items():
    for dv in ("", "v"):
        d = digs[::-1] if dv else digs
        for (h, w) in grids(len(d)) + [(1, len(d)), (len(d), 1)]:
            Mx = [d[i * w:(i + 1) * w] for i in range(h)]; nB += 1
            r = [sum(x) for x in Mx]; c = [sum(Mx[i][j] for i in range(h)) for j in range(w)]; t = sum(r)
            for k, L in {"rows": r, "cols": c, "rowcol": r + c, "colrow": c + r, "rowcol_t": r + c + [t]}.items():
                wh = f"B|{sname}{dv}|{h}x{w}|{k}"; list_test(L, wh); index_test(L, wh)
            if r == G.row_sums(M) or c == G.col_sums(M): log(kind="MATCH_MATRIX_SUMS", where=f"B|{sname}{dv}|{h}x{w}")
log(kind="progress", stage="B", grids=nB, n_pw=N_PW, soft=SOFT, secs=round(time.time() - t0))
print("B done", nB, N_PW, SOFT, round(time.time() - t0), flush=True)

# ---------------------------------------------------------------- C
log(kind="hypothesis", id="C", text="As listas de somas da matriz (14 linhas, 14 colunas, 28 nas duas ordens, total 101 = dígitos 1,0,1, e reversas) são a CHAVE de permutação/ordem de leitura do resíduo (61/60) e dos 84/83 tokens (marcador='0' ou 'b'): transposição colunar (cifrar e decifrar), Myszkowski (cifrar/decifrar), permutação por blocos (e inversa) e seleção direta por índice; saída -> letras, a1z26-dígitos, base9-pack -> english_score com nulo casado (100 embaralhamentos que preservam contagens), senha e privkey.")
RS, CS = G.row_sums(M), G.col_sums(M)
KEYS = {"rows14": RS, "cols14": CS, "rowcol28": RS + CS, "colrow28": CS + RS, "total101": [1, 0, 1],
        "rows14v": RS[::-1], "cols14v": CS[::-1]}
def rank(key): return sorted(range(len(key)), key=lambda i: (key[i], i))
def col_encrypt(text, key):
    w = len(key); rows = [text[i:i + w] for i in range(0, len(text), w)]
    return "".join(rows[r][c] for c in rank(key) for r in range(len(rows)) if c < len(rows[r]))
def col_decrypt(ct, key):
    w = len(key); n = len(ct); full = n // w; rem = n % w
    lens = {c: full + (1 if c < rem else 0) for c in range(w)}
    cols = {}; i = 0
    for c in rank(key): cols[c] = ct[i:i + lens[c]]; i += lens[c]
    return "".join(cols[c][r] for r in range(full + 1) for c in range(w) if r < lens[c])
def mysz_encrypt(text, key):
    w = len(key); rows = [text[i:i + w] for i in range(0, len(text), w)]; out = []
    for v in sorted(set(key)):
        cs = [c for c in range(w) if key[c] == v]
        out += [rows[r][c] for r in range(len(rows)) for c in cs if c < len(rows[r])]
    return "".join(out)
def mysz_decrypt(ct, key):
    w = len(key); n = len(ct); full = n // w; rem = n % w
    grid = [[None] * w for _ in range(full + 1)]; i = 0
    for v in sorted(set(key)):
        cs = [c for c in range(w) if key[c] == v]
        for r in range(full + 1):
            for c in cs:
                if r < full or c < rem: grid[r][c] = ct[i]; i += 1
    return "".join(grid[r][c] for r in range(full + 1) for c in range(w) if grid[r][c] is not None)
def block_perm(text, key):
    w = len(key); rk = rank(key); out = []
    for i in range(0, len(text), w):
        blk = text[i:i + w]; out += [blk[j] for j in rk if j < len(blk)]
    return "".join(out)
def block_perm_inv(text, key):
    w = len(key); rk = rank(key); out = []
    for i in range(0, len(text), w):
        blk = text[i:i + w]; m = [j for j in rk if j < len(blk)]; b = [None] * len(blk)
        for pos, j in enumerate(m): b[j] = blk[pos]
        out += b
    return "".join(out)
def key_select(text, key, base): return "".join(text[(k - base) % len(text)] for k in key)
_t = "thequickbrownfoxjumpsoverthelazydogabc"
for k in (RS, CS, [1, 0, 1], [3, 1, 2], RS + CS):
    assert col_decrypt(col_encrypt(_t, k), k) == _t and mysz_decrypt(mysz_encrypt(_t, k), k) == _t and block_perm_inv(block_perm(_t, k), k) == _t
assert col_encrypt("abcdef", [2, 1, 3]) == "bdacecf"[:6] or True  # (não normativo)
METHODS = {"col_enc": col_encrypt, "col_dec": col_decrypt, "mysz_enc": mysz_encrypt, "mysz_dec": mysz_decrypt,
           "blk": block_perm, "blk_inv": block_perm_inv,
           "sel0": lambda t, k: key_select(t, k, 0), "sel1": lambda t, k: key_select(t, k, 1)}
CTEXTS = {"r84": RES[84], "r83": RES[83],
          "t84": "".join(("0" if G.is_prime(i) else t) for i, t in enumerate(SEGS[84], 1)),
          "t84b": "".join(t[0] for t in SEGS[84]),
          "t83": "".join(("0" if G.is_prime(i) else t) for i, t in enumerate(SEGS[83], 1))}
def conv_and_test(s, where, do_oracle=True):
    """string de letras a-i (e '0') -> letras, a1 dígitos, base9 -> senhas/privkey. Devolve english_score."""
    es = G.english_score(s)
    if do_oracle and s:
        pw_test(s, where + "|letters")
        d1 = [0 if c == "0" else VAL["a1"][c] for c in s]; d0 = [0 if c == "0" else VAL["a0"][c] for c in s]
        list_test(d1, where + "|a1")
        n9 = 0
        for x in d0: n9 = n9 * 9 + x
        h = format(n9, "x"); bytes_test(bytes.fromhex(("0" + h) if len(h) % 2 else h), where + "|base9")
    return es
def pipeline_C(ctexts, do_oracle):
    best = (-99, "", "")
    for tn, T in ctexts.items():
        for kn, K in KEYS.items():
            for mn, fn in METHODS.items():
                for rv in ("", "v"):
                    s = fn(T[::-1] if rv else T, K)
                    es = conv_and_test(s, f"C|{tn}{rv}|{kn}|{mn}", do_oracle)
                    if es > best[0]: best = (es, f"C|{tn}{rv}|{kn}|{mn}", s)
    return best
bestC = pipeline_C(CTEXTS, True)
def shuf(s): l = list(s); random.shuffle(l); return "".join(l)
null = [pipeline_C({k: shuf(v) for k, v in CTEXTS.items()}, False)[0] for _ in range(100)]
mu = sum(null) / len(null); sd = (sum((x - mu) ** 2 for x in null) / len(null)) ** 0.5
pC = sum(x >= bestC[0] for x in null) / len(null)
log(kind="null_C", real=bestC[0], where=bestC[1], text=bestC[2], mu=mu, sd=sd, z=(bestC[0] - mu) / (sd or 1), p=pC, n=len(null))
log(kind="progress", stage="C", n_pw=N_PW, soft=SOFT, secs=round(time.time() - t0))
print("C done", N_PW, SOFT, bestC, mu, sd, pC, round(time.time() - t0), flush=True)

# ---------------------------------------------------------------- D
log(kind="hypothesis", id="D", text="61 = 60 + 1: o 'e' final é flag/seletor (e=5: passo 5, corte em 5, rotação 5, posições dos e, remoção dos e) e 61/60 são parâmetros — largura 60/61 na leitura dos 192/196 bits espirais (somas de coluna/linha, bits por coluna), offset/largura/passo 60/61 em faed (somas, fatias -> listas e letras) e índice/corte 60/61 nos textos e no dbbi.")
bits196 = [M[r][c] for r, c in sp]; bits192 = bits196[:192]
fd = [VAL["a1"][c] for c in G.FAED]
for W in (60, 61):
    for name, bl in (("b192", bits192), ("b196", bits196)):
        rows = [bl[i:i + W] for i in range(0, len(bl), W)]
        cs = [sum(r[j] for r in rows if j < len(r)) for j in range(W)]; rs = [sum(r) for r in rows]
        for k, L in {"cols": cs, "rows": rs, "colrow": cs + rs}.items(): list_test(L, f"D|{name}|w{W}|{k}")
        colbits = "".join(str(r[j]) for j in range(W) for r in rows if j < len(r))
        bytes_test(bytes(int(colbits[i:i + 8], 2) for i in range(0, len(colbits) - 7, 8)), f"D|{name}|w{W}|colbits")
    for name, seq in (("faed", fd), ("faed_np", fd[4:])):
        rows = [seq[i:i + W] for i in range(0, len(seq), W)]
        cs = [sum(r[j] for r in rows if j < len(r)) for j in range(W)]; rs = [sum(r) for r in rows]
        for k, L in {"cols": cs, "rows": rs, "colrow": cs + rs, "rowcol": rs + cs}.items(): list_test(L, f"D|{name}|w{W}|{k}")
        for k, L in {"off": seq[W:], "head": seq[:W], "step": seq[::W], "step_off": seq[W::W], "tail": seq[-W:]}.items():
            list_test(L, f"D|{name}|{W}|{k}"); conv_and_test("".join("abcdefghi"[x - 1] for x in L), f"D|{name}|{W}|{k}")
    for tn, T in TEXTS.items():
        for k, s in {"from": T[W:], "to": T[:W], "step": T[::W]}.items(): pw_test(s, f"D|{tn}|{W}|{k}")
for sname, s in {"r84": RES[84], "r83": RES[83], "t84": CTEXTS["t84"]}.items():
    L = [i + 1 for i, c in enumerate(s) if c == "e"]; list_test(L, f"D|{sname}|e_pos"); index_test(L, f"D|{sname}|e_pos")
    for k, out in {"step5": s[::5], "step5_4": s[4::5], "rot5": s[5:] + s[:5], "drop5": s[:-5], "first5": s[:5], "no_e": s.replace("e", "")}.items():
        conv_and_test(out, f"D|{sname}|{k}")
for W in (60, 61):
    for k, out in {"head": G.DBBI[:W], "tail": G.DBBI[W:]}.items(): conv_and_test(out, f"D|dbbi|{W}|{k}")
log(kind="progress", stage="D", n_pw=N_PW, soft=SOFT, secs=round(time.time() - t0))
print("D done", N_PW, SOFT, round(time.time() - t0), flush=True)

# ---------------------------------------------------------------- E (observação nova): somas parciais 61/60
import itertools
PR, PC = list(itertools.accumulate(RS)), list(itertools.accumulate(CS))
assert PR[8] == 61 and PC[7] == 60
log(kind="observation", text="Somas parciais das linhas atingem 61 na linha 9 (6+10+8+7+6+6+5+4+9) e as das colunas 60 na coluna 8: exatamente os comprimentos dos resíduos L84/L83. p≈0,036 em 20.000 matrizes 14x14 aleatórias com 101 uns (post hoc).",
    row_partials=PR, col_partials=PC)
log(kind="hypothesis", id="E", text="O resíduo é ESCRITO nas células-1 da matriz (primeiros 61/60 uns em ordem linha/coluna/espiral/centro; ou nos zeros/todas) e LIDO em outra ordem — transposição pela geometria da matriz; e o resíduo é segmentado pelas somas de linha (9 grupos = 61) / coluna (8 grupos = 60): somas, primeiras/últimas letras, grupos com espaço -> senhas, privkey e english_score com nulo casado.")
def write_read(seq, cells_w, cells_r):
    pos = {rc: ch for rc, ch in zip(cells_w, seq)}
    return "".join(pos[rc] for rc in cells_r if rc in pos)
E_OUT = []
def pipeline_E(seqs, do_oracle):
    best = (-99, "", "")
    for cname in ("ones101", "zeros95", "all196"):
        for ow, cw in CELLS[cname].items():
            for orr, cr in CELLS[cname].items():
                if ow == orr: continue
                for sname, s in seqs.items():
                    t = write_read(s, cw, cr)
                    es = conv_and_test(t, f"E|{cname}|w_{ow}|r_{orr}|{sname}", do_oracle)
                    if es > best[0]: best = (es, f"E|{cname}|w_{ow}|r_{orr}|{sname}", t)
    return best
bestE = pipeline_E({"r84": RES[84], "r83": RES[83]}, True)
nullE = [pipeline_E({"r84": shuf(RES[84]), "r83": shuf(RES[83])}, False)[0] for _ in range(100)]
muE = sum(nullE) / 100; sdE = (sum((x - muE) ** 2 for x in nullE) / 100) ** 0.5
log(kind="null_E", real=bestE[0], where=bestE[1], text=bestE[2], mu=muE, sd=sdE, z=(bestE[0] - muE) / (sdE or 1), p=sum(x >= bestE[0] for x in nullE) / 100, n=100)
# segmentação do resíduo pelas somas
for sname, s, key in (("r84", RES[84], RS[:9]), ("r83", RES[83], CS[:8]), ("r84v", RES[84][::-1], RS[:9][::-1]), ("r83v", RES[83][::-1], CS[:8][::-1])):
    groups = []; i = 0
    for k in key: groups.append(s[i:i + k]); i += k
    assert "".join(groups) == s
    wh = f"E|seg|{sname}"
    pw_test(" ".join(groups), wh + "|spaces"); pw_test(",".join(groups), wh + "|commas")
    list_test([sum(VAL["a1"][c] for c in g) for g in groups], wh + "|gsum")
    list_test([sum(VAL["a0"][c] for c in g) for g in groups], wh + "|gsum0")
    conv_and_test("".join(g[0] for g in groups), wh + "|first"); conv_and_test("".join(g[-1] for g in groups), wh + "|last")
    for g_i, g in enumerate(groups): conv_and_test(g, wh + f"|g{g_i}")
    # grupos como linhas de uma grade irregular: somas de coluna (ragged)
    W = max(len(g) for g in groups)
    list_test([sum(VAL["a1"][g[j]] for g in groups if j < len(g)) for j in range(W)], wh + "|ragged_cols")
log(kind="progress", stage="E", n_pw=N_PW, soft=SOFT, secs=round(time.time() - t0))
print("E done", N_PW, SOFT, bestE, muE, sdE, round(time.time() - t0), flush=True)

# ---------------------------------------------------------------- leituras textuais por índice (B): melhor + nulo casado
best_txt = max(TEXT_OUT, key=lambda x: G.english_score(x[1])) if TEXT_OUT else None
def B_index_best(digs_map):
    best = -99
    for sname, digs in digs_map.items():
        for (h, w) in grids(len(digs)):
            Mx = [digs[i * w:(i + 1) * w] for i in range(h)]
            r = [sum(x) for x in Mx]; c = [sum(Mx[i][j] for i in range(h)) for j in range(w)]
            for L in (r, c, r + c, c + r):
                for tn, T in TEXTS.items():
                    for b in (0, 1):
                        es = G.english_score("".join(T[(x - b) % len(T)] for x in L))
                        if es > best: best = es
    return best
KEYS_B = ("r84", "r83", "t84_zero", "t83_zero")
realB = B_index_best({k: GRID_SEQS[k] for k in KEYS_B})
nullB = []
for _ in range(100):
    dm = {}
    for k in KEYS_B:
        v = GRID_SEQS[k][:]; random.shuffle(v); dm[k] = v
    nullB.append(B_index_best(dm))
muB = sum(nullB) / 100; sdB = (sum((x - muB) ** 2 for x in nullB) / 100) ** 0.5
log(kind="null_B_index", real=realB, mu=muB, sd=sdB, z=(realB - muB) / (sdB or 1), p=sum(x >= realB for x in nullB) / 100,
    best_where=best_txt[0] if best_txt else None, best_text=best_txt[1] if best_txt else None,
    best_score=G.english_score(best_txt[1]) if best_txt else None)

exp_soft = N_AES / 256
log(kind="summary", n_pw=N_PW, n_aes=N_AES, n_priv=N_PRIV, soft=SOFT, soft_expected=round(exp_soft, 1),
    hard=HARD, bestC=dict(score=bestC[0], where=bestC[1], text=bestC[2]), secs=round(time.time() - t0))
print(json.dumps(dict(n_pw=N_PW, n_aes=N_AES, n_priv=N_PRIV, soft=SOFT, soft_expected=round(exp_soft, 1), hard=len(HARD),
                      bestC=bestC, nullC=dict(mu=mu, sd=sd, p=pC), nullB=dict(real=realB, mu=muB, sd=sdB),
                      best_txt=best_txt, secs=round(time.time() - t0))))
