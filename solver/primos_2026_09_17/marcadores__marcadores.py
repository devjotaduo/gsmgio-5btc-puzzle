# -*- coding: utf-8 -*-
"""
Familia MARCADORES: o que os 23 marcadores b/be (L84: 16 b + 7 be) e as duas omissoes
(eventos 22 e 25 = indices espirais 167/191 = bytes 21/24 da URL = 'n'/'d') dizem.
Hipoteses (prosa no JSONL, ver H1..H4 abaixo). Oraculo duro: G.try_password_all + privkey.
"""
import sys, os, json, hashlib, itertools, random, time
KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
import gsmg_common as G
from coincurve import PublicKey

OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "marcadores.jsonl")
if os.path.exists(LOG): os.remove(LOG)
def log(o): G.jsonl(LOG, o)

HYP = {
 "H1": "As duas omissoes (eventos 22/25 -> espiral 167/191 -> celulas (9,6),(5,6) -> bytes 21/24 da URL = 'n','d') apontam a operacao: os proprios indices/letras/celulas e a URL com esses bytes zerados/removidos/flipados sao a senha, ou parametros de offset/largura sobre residuo, faed e espiral.",
 "H2": "A sequencia de 23 tipos (b=0, be=1) e uma CHAVE: bits XOR/soma sobre os 23 primeiros simbolos do residuo; selecao (be=pega) sobre residuo/faed/dbbi/URL/Arquiteto (primeiros 23 e periodica); permutacao dos primos 2..83 pelos tipos; numero em varias larguras.",
 "H3": "16/7/23 como parametros: residuo repartido pelos marcadores (16 b -> 17 pedacos, 7 be -> 8 pedacos, 23 -> 24 pedacos) com concat/entrelacamento/XOR-de-sha256 (receita provada 'intertwined'); faed em grades de largura 7/16/23/24 e selecao de blocos pelos bits; sha256 iterado 1..23 vezes (16 = 'sixteen encryptions') sobre os tokens do roadmap e sobre residuo/dbbi/faed/URL/bits.",
 "H4": "Os 7 primos 'be' (11,23,29,47,61,67,79) e os 16 primos 'b' como INDICES (base 0/1) em faed, dbbi, residuo, URL, Arquiteto, 3.2.2; e como listas decimais.",
}
for k, v in HYP.items(): log({"hypothesis": k, "text": v})

# ------------------------------------------------------------------ segmentacao (regra do atlas)
D = G.DBBI
def segment(L):
    P = [p for p in range(1, L + 1) if G.is_prime(p)]
    res = []
    def rec(pos, i, toks):
        if pos > L:
            if i == len(D): res.append(list(toks))
            return
        if i >= len(D): return
        if G.is_prime(pos):
            if D[i] == 'b':
                rec(pos + 1, i + 1, toks + ['b'])
                if i + 1 < len(D) and D[i + 1] == 'e': rec(pos + 1, i + 2, toks + ['be'])
        else:
            rec(pos + 1, i + 1, toks + [D[i]])
    rec(1, 0, [])
    assert len(res) == 1, (L, len(res))
    toks = res[0]
    marks = [toks[p - 1] for p in P]
    bits = ''.join('1' if m == 'be' else '0' for m in marks)
    resid = ''.join(t for j, t in enumerate(toks, 1) if j not in P)
    return dict(L=L, P=P, toks=toks, marks=marks, bits=bits, resid=resid)
S84, S83 = segment(84), segment(83)
assert S84["bits"] == "00001000110000100110010" and S83["bits"] == "00001000110000100110011"
assert S84["marks"].count('b') == 16 and S84["marks"].count('be') == 7
R84, R83 = S84["resid"], S83["resid"]
assert len(R84) == 61 and len(R83) == 60
B84, B83 = S84["bits"], S83["bits"]
P23 = S84["P"]
P7 = [p for p, m in zip(P23, S84["marks"]) if m == 'be']
P16 = [p for p, m in zip(P23, S84["marks"]) if m == 'b']
assert P7 == [11, 23, 29, 47, 61, 67, 79], P7
# controle: casamento com as cores omitindo 22 e 25 (1-based)
COL25 = ''.join('0' if v[0] in ('B', 'W*') else '1' for k, v in sorted(G.COLORED.items()))
assert ''.join(COL25[j] for j in range(25) if j + 1 not in (22, 25)) == B84
assert ''.join(COL25[j] for j in range(25) if j + 1 not in (22, 24)) == B83
URL = "gsmg.io/theseedisplanted"
assert URL[20] == 'n' and URL[23] == 'd' and URL[22] == 'e'
ARCH = "".join(c for c in open(os.path.join(OUT, "architect.txt"), encoding="utf-8").read().upper() if 'A' <= c <= 'Z')
assert len(ARCH) == 1539, len(ARCH)
alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
_d = [int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"]
P322 = G.checkerboard_decode(_d, alpha322, escapes=(1, 4), universe="0123456789")
assert P322.startswith("INCASEYOUMANAGETOCRACKTHIS")
ROAD = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang", "thispassword",
        "enter", "yourlastcommand", "secondanswer", "theseedisplanted", URL]

# ------------------------------------------------------------------ oraculo
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
N_AES = 0; N_PRIV = 0
HARD, SOFT = [], []
def priv(sec, where):
    global N_PRIV
    if len(sec) != 32: return
    N_PRIV += 1
    try:
        if PublicKey.from_valid_secret(sec).format(False) == TGT:
            HARD.append({"where": where, "privkey": sec.hex()}); log({"HARD": where, "privkey": sec.hex()})
    except Exception:
        pass
def as_bytes(m): return m if isinstance(m, bytes) else m.encode("latin-1")
def test(name, m, fam):
    """senha crua / sha256hex / SHA256HEX x 3 blobs x 2 KDF + privkey (sha256, sha256d, 32B, janelas)."""
    global N_AES
    mb = as_bytes(m)
    if not mb: return
    forms = {"raw": mb, "shahex": G.shahex(mb).encode(), "SHAHEX": G.shahex(mb).upper().encode()}
    for fk, pw in forms.items():
        hard, soft = G.try_password_all(pw); N_AES += 6
        for h in hard:
            h.update(name=name, form=fk, fam=fam); HARD.append(h); log({"HARD": h})
        for s in soft:
            s.update(name=name, form=fk, fam=fam); SOFT.append(s)
            log({"soft": {k: s[k] for k in ("name", "form", "fam", "blob", "kdf", "len", "printable", "hex")}})
    priv(G.sha(mb), f"{fam}/{name}/sha256"); priv(G.sha(G.sha(mb)), f"{fam}/{name}/sha256d")
    priv(G.sha(mb.upper()), f"{fam}/{name}/sha256(upper)")
    if len(mb) == 32: priv(mb, f"{fam}/{name}/raw32")
    if len(mb) > 32:
        for j in range(len(mb) - 31): priv(mb[j:j + 32], f"{fam}/{name}/win{j}")
    t = mb.decode("latin-1")
    if t.isdigit() and int(t) > 0: priv(int(t).to_bytes(32, "big")[-32:] if int(t) < 2**256 else b"", f"{fam}/{name}/int")
    if set(t) <= {"0", "1"} and len(t) >= 8: priv(int(t, 2).to_bytes(32, "big"), f"{fam}/{name}/bin")
    try:
        if len(t) in (64,) and all(c in "0123456789abcdefABCDEF" for c in t): priv(bytes.fromhex(t), f"{fam}/{name}/hex64")
    except ValueError: pass

# ------------------------------------------------------------------ geradores
def sel(src, bits, want='1', periodic=True):
    """selecao: pega src[i] onde bits[i % 23] == want (periodic) ou so sobre os 23 primeiros."""
    n = len(src) if periodic else min(len(src), len(bits))
    return ''.join(src[i] for i in range(n) if bits[i % len(bits)] == want)
def xor_sha(pieces):
    x = bytes(32)
    for p in pieces: x = bytes(a ^ b for a, b in zip(x, G.sha(as_bytes(p))))
    return x
def chain_sha(pieces):
    h = b""
    for p in pieces: h = G.sha(h + as_bytes(p))
    return h
def interleave(pieces):
    out = []
    for tup in itertools.zip_longest(*pieces, fillvalue=''): out.append(''.join(tup))
    return ''.join(out)
def splits(seg, by):
    """pedacos do residuo entre marcadores de tipo `by` ('b','be' ou 'any'); marcadores de outro tipo viram
    seu texto ('b'/'be') ou sao removidos (variante _drop)."""
    keep, drop, cur_k, cur_d = [], [], [], []
    for j, t in enumerate(seg["toks"], 1):
        is_mark = j in seg["P"]
        if is_mark and (by == 'any' or t == by):
            keep.append(''.join(cur_k)); drop.append(''.join(cur_d)); cur_k, cur_d = [], []
        elif is_mark:
            cur_k.append(t)
        else:
            cur_k.append(t); cur_d.append(t)
    keep.append(''.join(cur_k)); drop.append(''.join(cur_d))
    return keep, drop

def spiral_bytes(M):
    bits = ''.join(str(M[r][c]) for r, c in G.SPIRAL)[:192]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, 192, 8))
assert spiral_bytes(G.MATRIX_README) == URL.encode()

def gen_H1():
    out = {}
    for s in ["n", "d", "nd", "dn", "ne", "en", "nde", "21", "24", "2124", "2421", "2123", "22", "25", "2225", "2522", "2224",
              "167", "191", "167191", "191167", "175", "183", "175183", "167175183191", "191183175167",
              "96", "56", "9656", "5696", "107", "67", "10767", "67107", "9,6", "5,6", "(9,6)(5,6)", "r9c6r5c6", "c6",
              "16", "7", "23", "16723", "1672", "sixteen", "seven", "twentythree", "twenty-three", "sixteenseven",
              "twentythreesixteenseven", "23167", "16-7-23"]:
        out["lit:" + s] = s
    u = URL
    out["url:sem_n_d"] = u[:20] + u[21:23]            # remove bytes 21 e 24
    out["url:sem_n"] = u[:20] + u[21:]
    out["url:sem_d"] = u[:23]
    out["url:sem_n_e"] = u[:20] + u[21:22] + u[23:]   # L83: bytes 21 e 23
    out["url:zero_n_d"] = u[:20] + "0" + u[21:23] + "0"
    out["url:nul_n_d"] = u[:20] + "\x00" + u[21:23] + "\x00"
    out["url:zero_n_e"] = u[:20] + "0" + u[21:22] + "0" + u[23:]
    out["url:flip_n_d"] = u[:20] + "o" + u[21:23] + "e"   # bits 167/191 setados
    out["url:sfx_sem_n_d"] = "theseedisplate"; out["url:sfx_sem_n"] = "theseedisplated"; out["url:sfx_sem_d"] = "theseedisplante"
    out["url:sfx_zero_n_d"] = "theseedispla0te0"; out["url:sfx_flip"] = "theseedisplaotee"
    out["url:byte0..22"] = u[:23]
    # matriz: zerar/setar celulas, coluna 6 (col-sum minimo = 3), linhas 5 e 9
    M = [r[:] for r in G.MATRIX_README]
    def mod(fn):
        N = [r[:] for r in M]; fn(N); return spiral_bytes(N)
    out["mat:set167_191"] = mod(lambda N: (N[9].__setitem__(6, 1), N[5].__setitem__(6, 1)))
    out["mat:set_all_yellow"] = mod(lambda N: [N[r].__setitem__(c, 1) for k, (col, r, c) in G.COLORED.items() if col == 'Y'])
    out["mat:set_yellow_sel"] = mod(lambda N: [N[r].__setitem__(c, 1) for k, (col, r, c) in G.COLORED.items() if col == 'Y' and k not in (167, 191)])
    out["mat:zero_col6"] = mod(lambda N: [N[r].__setitem__(6, 0) for r in range(14)])
    out["mat:zero_row5_9"] = mod(lambda N: [N[r].__setitem__(c, 0) for r in (5, 9) for c in range(14)])
    out["mat:zero_blue_events"] = mod(lambda N: [N[r].__setitem__(c, 0) for k, (col, r, c) in G.COLORED.items() if col == 'B'])
    out["mat:col6_bits"] = ''.join(str(M[r][6]) for r in range(14))
    out["mat:row9_bits"] = ''.join(map(str, M[9])); out["mat:row5_bits"] = ''.join(map(str, M[5]))
    out["mat:row9row5"] = ''.join(map(str, M[9])) + ''.join(map(str, M[5]))
    sp = ''.join(str(M[r][c]) for r, c in G.SPIRAL)
    out["spiral:160..195"] = sp[160:]; out["spiral:167..191"] = sp[167:192]; out["spiral:192..195"] = sp[192:]
    # indices como parametros (offset/janela) sobre faed, residuo, dbbi
    F = G.FAED
    for a, b in [(167, 191), (175, 183), (167, 175), (183, 191)]:
        out[f"faed[{a}:{b}]"] = F[a:b]; out[f"faed[{a-1}:{b}]"] = F[a - 1:b]
    for k in (167, 191, 175, 183):
        out[f"faed[{k}:]"] = F[k:]; out[f"faed[:{k}]"] = F[:k]; out[f"faed_rot{k}"] = F[k % 570:] + F[:k % 570]
        out[f"r84_rot{k}"] = R84[k % 61:] + R84[:k % 61]; out[f"r83_rot{k}"] = R83[k % 60:] + R83[:k % 60]
        out[f"dbbi_rot{k}"] = D[k % 91:] + D[:k % 91]
        out[f"faed_stride{k%23 or 23}"] = F[::(k % 23) or 23]
    # largura = 21/24 (bytes), 22/25 (eventos): residuo/faed em grade e leitura por colunas
    for w in (21, 24, 22, 25, 61, 9, 6, 5):
        for nm, s in (("r84", R84), ("faed", F), ("dbbi", D)):
            out[f"{nm}_T{w}"] = ''.join(s[i::w] for i in range(w))
    return out

def gen_bits(bits, tag):
    """familias que dependem da sequencia de 23 bits (recalculadas no nulo)."""
    out = {}
    n = int(bits, 2)
    out[f"{tag}:bits"] = bits; out[f"{tag}:bits_rev"] = bits[::-1]; out[f"{tag}:bits_inv"] = ''.join('1' if c == '0' else '0' for c in bits)
    out[f"{tag}:dec"] = str(n); out[f"{tag}:hex"] = format(n, "x"); out[f"{tag}:hex6"] = format(n, "06x")
    out[f"{tag}:be3"] = n.to_bytes(3, "big"); out[f"{tag}:be4"] = n.to_bytes(4, "big"); out[f"{tag}:le4"] = n.to_bytes(4, "little")
    out[f"{tag}:be32"] = n.to_bytes(32, "big")
    nr = int(bits[::-1], 2); out[f"{tag}:dec_rev"] = str(nr); out[f"{tag}:hex_rev"] = format(nr, "x")
    marks = ''.join('be' if c == '1' else 'b' for c in bits)
    out[f"{tag}:marks"] = marks; out[f"{tag}:marks_sp"] = ' '.join('be' if c == '1' else 'b' for c in bits)
    out[f"{tag}:BY"] = ''.join('Y' if c == '1' else 'B' for c in bits)
    out[f"{tag}:yellowblue"] = ''.join('yellow' if c == '1' else 'blue' for c in bits)
    # primos permutados pelos tipos
    p1 = [p for p, c in zip(P23, bits) if c == '1']; p0 = [p for p, c in zip(P23, bits) if c == '0']
    for sep in ("", " ", ","):
        out[f"{tag}:p1{sep!r}"] = sep.join(map(str, p1)); out[f"{tag}:p0{sep!r}"] = sep.join(map(str, p0))
        out[f"{tag}:p1p0{sep!r}"] = sep.join(map(str, p1 + p0)); out[f"{tag}:p0p1{sep!r}"] = sep.join(map(str, p0 + p1))
    out[f"{tag}:sum_p1"] = str(sum(p1)); out[f"{tag}:sum_p0"] = str(sum(p0)); out[f"{tag}:sum_p1_p0"] = f"{sum(p1)}{sum(p0)}"
    pr = 1
    for p in p1: pr *= p
    out[f"{tag}:prod_p1"] = str(pr)
    # selecao / XOR / soma sobre fontes
    srcs = {"r84": R84, "r83": R83, "faed": G.FAED, "dbbi": D, "url": URL, "url23": URL[:23], "arch": ARCH, "p322": P322,
            "sfx16": "theseedisplanted", "road": ''.join(ROAD[:4])}
    for nm, s in srcs.items():
        for want in '01':
            out[f"{tag}:sel{want}_{nm}_first23"] = sel(s, bits, want, periodic=False)
            out[f"{tag}:sel{want}_{nm}_per"] = sel(s, bits, want, periodic=True)
        if set(s) <= set("abcdefghi"):
            dg = [ord(c) - 96 for c in s]
            for op, fn in (("xor", lambda d, b: d ^ b), ("add", lambda d, b: (d + b - 1) % 9 + 1), ("sub", lambda d, b: (d - b - 1) % 9 + 1)):
                v = [fn(d, int(bits[i % 23])) for i, d in enumerate(dg)]
                out[f"{tag}:{op}_{nm}_dig"] = ''.join(map(str, v))
                out[f"{tag}:{op}_{nm}_let"] = ''.join(chr(96 + x) if 1 <= x <= 26 else '0' for x in v)
    # blocos de faed de largura 24 (23 cheios + resto) e 23 selecionados pelos bits
    F = G.FAED
    for w in (24, 23, 25):
        blocks = [F[i:i + w] for i in range(0, len(F), w)]
        out[f"{tag}:faedblk{w}_1"] = ''.join(b for b, c in zip(blocks, bits) if c == '1')
        out[f"{tag}:faedblk{w}_0"] = ''.join(b for b, c in zip(blocks, bits) if c == '0')
    # posicoes-indice (H4): primos do tipo como indices (base 0/1) nas fontes
    for nm, s in srcs.items():
        for base in (0, 1):
            for lab, plist in (("p1", p1), ("p0", p0), ("p23", P23)):
                out[f"{tag}:idx_{lab}_{nm}_b{base}"] = ''.join(s[(p - base) % len(s)] for p in plist)
    # XOR/cadeia de sha256 dos primos do tipo (receita 'intertwined')
    out[f"{tag}:xorsha_p1"] = xor_sha([str(p) for p in p1]); out[f"{tag}:xorsha_p0"] = xor_sha([str(p) for p in p0])
    out[f"{tag}:xorsha_p23"] = xor_sha([str(p) for p in P23])
    return out

def gen_H3(seg, tag):
    out = {}
    for by in ('b', 'be', 'any'):
        keep, drop = splits(seg, by)
        for lab, pieces in (("keep", keep), ("drop", drop)):
            pz = [p for p in pieces]
            out[f"{tag}:split_{by}_{lab}_concat"] = ''.join(pz)
            out[f"{tag}:split_{by}_{lab}_sp"] = ' '.join(pz)
            out[f"{tag}:split_{by}_{lab}_inter"] = interleave(pz)
            out[f"{tag}:split_{by}_{lab}_rev"] = ''.join(pz[::-1])
            out[f"{tag}:split_{by}_{lab}_xorsha"] = xor_sha(pz)
            out[f"{tag}:split_{by}_{lab}_chain"] = chain_sha(pz)
            nz = [p for p in pz if p]
            out[f"{tag}:split_{by}_{lab}_xorsha_nz"] = xor_sha(nz)
            # pedacos DEPOIS de cada marcador (7 'intertwined' para be)
            after = pz[1:]
            out[f"{tag}:split_{by}_{lab}_after_inter"] = interleave(after)
            out[f"{tag}:split_{by}_{lab}_after_xorsha"] = xor_sha(after)
            out[f"{tag}:split_{by}_{lab}_before_xorsha"] = xor_sha(pz[:-1])
            out[f"{tag}:split_{by}_{lab}_lens"] = ''.join(str(len(p)) for p in pz)
            out[f"{tag}:split_{by}_{lab}_firsts"] = ''.join(p[0] for p in pz if p)
            out[f"{tag}:split_{by}_{lab}_lasts"] = ''.join(p[-1] for p in pz if p)
    # vizinhos dos 'be' e dos 'b' (token anterior/posterior na sequencia logica)
    toks = seg["toks"]
    for lab, plist in (("be", [p for p, m in zip(seg["P"], seg["marks"]) if m == 'be']), ("b", [p for p, m in zip(seg["P"], seg["marks"]) if m == 'b'])):
        nxt = ''.join(toks[p] if p < len(toks) else '' for p in plist)
        prv = ''.join(toks[p - 2] if p >= 2 else '' for p in plist)
        out[f"{tag}:{lab}_next"] = nxt; out[f"{tag}:{lab}_prev"] = prv; out[f"{tag}:{lab}_prevnext"] = prv + nxt
        out[f"{tag}:{lab}_prevnext_inter"] = interleave([prv, nxt])
        out[f"{tag}:{lab}_next_xorsha"] = xor_sha(list(nxt))
        # posicoes fisicas em DBBI (inicio do marcador)
        phys = []; i = 0
        for j, t in enumerate(toks, 1):
            if j in plist: phys.append(i)
            i += len(t)
        out[f"{tag}:{lab}_phys0"] = ''.join(map(str, phys)); out[f"{tag}:{lab}_phys1"] = ''.join(str(x + 1) for x in phys)
        out[f"{tag}:{lab}_phys_sp"] = ' '.join(map(str, phys))
        out[f"{tag}:{lab}_pos_sp"] = ' '.join(map(str, plist)); out[f"{tag}:{lab}_pos"] = ''.join(map(str, plist))
    # dbbi 7x13 / 13x7 e grades 7/16/23/24 de faed, residuo (transposicoes simples)
    for w in (7, 13, 16, 23, 24):
        for nm, s in (("dbbi", D), ("faed", G.FAED), (tag + "res", seg["resid"])):
            out[f"{tag}:T{w}_{nm}"] = ''.join(s[i::w] for i in range(w))
    return out

def gen_iter():
    """sha256 iterado k=1..23 (16 = sixteen encryptions) sobre tokens; cadeia hex e cadeia digest."""
    out = {}
    toks = ROAD + [R84, R83, D, G.FAED, B84, B83, ''.join(ROAD[:4]), "yellowblueprimesmatrixsumlist",
                   S84["marks"] and ''.join(S84["marks"]), "be", "b"]
    for t in toks:
        h = t.encode(); x = t.encode()
        for k in range(1, 24):
            h = G.shahex(h).encode(); x = G.sha(x)
            out[f"iter{k}_hex:{t[:16]}"] = h; out[f"iter{k}_dig:{t[:16]}"] = x
    return out

# ------------------------------------------------------------------ execucao
def run(materials, fam):
    for name, m in materials.items(): test(name, m, fam)

t0 = time.time()
H1 = gen_H1(); run(H1, "H1")
B_real = {**gen_bits(B84, "L84"), **gen_bits(B83, "L83")}; run(B_real, "H2/H4")
H3 = {**gen_H3(S84, "L84"), **gen_H3(S83, "L83")}; run(H3, "H3")
IT = gen_iter(); run(IT, "H3iter")
# 7! ordens dos 7 pedacos apos cada 'be' (L84, sem marcadores) — concat e entrelacamento
keep, drop = splits(S84, 'be'); after7 = drop[1:]; assert len(after7) == 7
perm_n = 0
for perm in itertools.permutations(range(7)):
    pz = [after7[i] for i in perm]
    for m in (''.join(pz), interleave(pz)):
        test(f"perm7:{perm}:{'cat' if m == ''.join(pz) else 'int'}", m, "H3perm"); perm_n += 1
n_real = N_AES
real_soft = len(SOFT); real_maxp = max([s["printable"] for s in SOFT] or [0])

# scores de ingles em saidas textuais (selecoes do Arquiteto / 3.2.2 / URL)
def text_scores(mats):
    sc = {}
    for k, v in mats.items():
        if isinstance(v, bytes): continue
        if ("arch" in k or "p322" in k) and len(v) >= 20:
            sc[k] = G.english_score(v)
    return sc
real_scores = text_scores(B_real)
best_txt = max(real_scores.items(), key=lambda kv: kv[1]) if real_scores else None

# ------------------------------------------------------------------ nulo: 100 embaralhamentos dos 23 bits (16/7 preservados)
rng = random.Random(20260917)
null_soft, null_maxp, null_txt = [], [], []
null_aes0 = N_AES
for it in range(100):
    b = list(B84); rng.shuffle(b); b = ''.join(b)
    mats = gen_bits(b, "N")
    s0 = len(SOFT)
    for name, m in mats.items(): test(f"null{it}:{name}", m, "NULL")
    null_soft.append(len(SOFT) - s0)
    null_maxp.append(max([s["printable"] for s in SOFT[s0:]] or [0]))
    null_txt.append(max(text_scores(mats).values()))
null_aes = N_AES - null_aes0
# comparacao: familias reais dependentes de bits (mesma geracao)
real_bits_soft = sum(1 for s in SOFT if s["fam"] == "H2/H4" and s["name"].startswith("L84"))
real_bits_maxp = max([s["printable"] for s in SOFT if s["fam"] == "H2/H4" and s["name"].startswith("L84")] or [0])

summary = {
    "family": "marcadores_omissoes_16_7_23",
    "n_tests_aes": n_real, "n_null_aes": null_aes, "n_priv": N_PRIV, "n_materials": len(H1) + len(B_real) + len(H3) + len(IT) + perm_n,
    "hard_hits": HARD, "n_soft": real_soft, "real_max_printable": real_maxp,
    "null": {"soft_per_run_mean": sum(null_soft) / 100, "soft_real_L84_bits": real_bits_soft,
             "maxp_null_max": max(null_maxp), "maxp_real_L84_bits": real_bits_maxp,
             "eng_null_max": max(null_txt), "eng_null_mean": sum(null_txt) / 100,
             "eng_real_best": best_txt},
    "top_soft": sorted([{k: s[k] for k in ("name", "form", "blob", "kdf", "printable", "hex")} for s in SOFT if s["fam"] != "NULL"],
                       key=lambda s: -s["printable"])[:5],
    "elapsed_s": round(time.time() - t0, 1),
}
log({"summary": summary})
json.dump(summary, open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps(summary, ensure_ascii=False, indent=1))
