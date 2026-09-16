# -*- coding: utf-8 -*-
"""
FAMILIA residue_autocorr — (A) o residuo de IoC-de-digrafos de faed/dbbi e' estrutura serial real,
e nao cauda do nulo; (B) se ha camada aditiva, ela usa POUCOS residuos (chave binaria/ternaria),
que e' a unica forma de preservar o vies unigrama medido em faed.

Hipotese falsificavel, espaco finito:
(A) Se faed/dbbi carregam periodicidade de chave ou repeticao de blocos, entao existe n-grama
    (n=1..4) e lag L<=60 com autocorrelacao fora do nulo de 500 embaralhados (|z|>4), ou uma taxa
    de repeticao de blocos de comprimento 3..12 fora desse nulo. Nesse caso L e' periodo de chave
    ou largura de transposicao e o decode (checkerboard 3.2.2/CANON x 72 escapes, Bifid CANON) por
    esse periodo produz texto semantico.
(B) Se ha camada aditiva com poucos residuos, existe chave binaria/ternaria k (binario a/b de
    'enter'/'matrixsumlist', a1z26 mod 2/3 dos tokens, bits da matriz README/URL, dbbi mod 2/3,
    indicador de primos, Thue-Morse, Fibonacci mod 2/3, ou qualquer padrao periodico de 2 simbolos
    com periodo <=12) e rotacao tal que faed/dbbi rechaveado (+k, -k, mod 9 e mod 10) recupera
    estrutura serial detectavel SEM conhecer o alfabeto (H_cond ou IoC-de-digrafos com |z|>3 vs 30
    embaralhados) e cujo decode e' texto ingles / cuja sha256 abre SMALL/COSMIC/TAIL32 (EVP-SHA256)
    ou e' a privkey do premio.
Falsificacao: nenhum |z| acima do maximo esperado do nulo (part A |z|>4; part B |z|>3 + controle
positivo recuperado), e nenhum oraculo duro.
"""
import sys, json, time, math, random, collections, itertools
import numpy as np

SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G

LOG = SP + r"\residue_autocorr.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"event": "hypothesis", "family": "residue_autocorr", "text": " ".join(__doc__.split())})

rng = np.random.default_rng(20260902)
T0 = time.time()
N_TESTS = 0          # contador global exato
HARD, SOFT = [], []
BEST = {"score": -99.0, "text": "", "how": ""}

# ---------------------------------------------------------------- oraculos rapidos
from coincurve import PublicKey
TGT_PUB = bytes.fromhex(G.TARGET_PUBKEY_HEX)
def priv_fast(k32):
    """Oraculo duro rapido: privkey 32B -> pubkey do premio?"""
    try:
        return PublicKey.from_valid_secret(k32).format(False) == TGT_PUB
    except Exception:
        return False
assert not priv_fast(G.sha(b"test"))

def oracle_text(pt, how):
    """sha256(pt) e variantes como senha nos 3 blobs (EVP-SHA256) + como privkey."""
    global N_TESTS
    forms = {pt, pt.lower()}
    for f in forms:
        h = G.shahex(f)
        for b in ("SMALL", "COSMIC", "TAIL32"):
            for kdf, p in G.aes_try(h, b, kdf="sha256"):
                N_TESTS += 1
                rec = {"how": how, "pw_sha256hex": h, "blob": b, "kdf": kdf,
                       "printable": round(G.printable(p), 3), "head": p[:40].decode("latin-1")}
                (HARD if G.semantic(p) else SOFT).append(
                    {**rec, **({"plaintext_hex": p.hex()} if G.semantic(p) else {})})
            N_TESTS += 1
        k = G.sha(f.encode())
        N_TESTS += 1
        if priv_fast(k):
            HARD.append({"how": how, "privkey_hex": k.hex(), "src": f[:120], "kind": "sha256(text)"})

# ================================================================= PARTE A
# autocorrelacao de n-gramas (n=1..4, lags 1..60) e taxa de repeticao de blocos (m=3..12)
def as_arr(s):
    return np.array([ord(c) - 97 for c in s], dtype=np.int8)

def ngram_match_rate(a, n, lag):
    """fracao de posicoes i com a[i:i+n] == a[i+lag:i+lag+n]."""
    m = len(a) - lag - n + 1
    if m <= 5: return None
    eq = (a[:len(a) - lag] == a[lag:])
    if n == 1:
        return eq[:m].mean()
    acc = eq[:m].copy()
    for k in range(1, n):
        acc &= eq[k:k + m]
    return acc.mean()

def block_repeats(a, m):
    """numero de pares (i<j) com a[i:i+m]==a[j:j+m] (qualquer distancia)."""
    if len(a) < m + 2: return None
    b = a.astype(np.int64)
    # hash polinomial exato em base 9/10 (valores 0..8) -> inteiro unico por bloco
    pw = 9 ** np.arange(m, dtype=object) if m > 18 else (9 ** np.arange(m)).astype(np.int64)
    win = np.lib.stride_tricks.sliding_window_view(b, m)
    keys = win @ pw
    _, cnt = np.unique(keys, return_counts=True)
    return int((cnt * (cnt - 1) // 2).sum())

SEQS_A = {
    "faed": G.FAED, "dbbi": G.DBBI,
    "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:],
    "faed+dbbi": G.FAED + G.DBBI,
}
NSHUF_A = 500
partA = []
for sname, s in SEQS_A.items():
    a = as_arr(s)
    shuf = [rng.permutation(a) for _ in range(NSHUF_A)]
    # autocorrelacao
    for n in (1, 2, 3, 4):
        for lag in range(1, 61):
            obs = ngram_match_rate(a, n, lag)
            if obs is None: continue
            null = np.array([ngram_match_rate(x, n, lag) for x in shuf], dtype=float)
            N_TESTS += 1
            sd = null.std() or 1e-12
            z = (obs - null.mean()) / sd
            partA.append({"kind": "autocorr", "seq": sname, "n": n, "lag": lag,
                          "obs": float(obs), "z": round(float(z), 2)})
    # repeticao de blocos
    for m in range(3, 13):
        obs = block_repeats(a, m)
        if obs is None: continue
        null = np.array([block_repeats(x, m) for x in shuf], dtype=float)
        N_TESTS += 1
        sd = null.std() or 1e-12
        z = (obs - null.mean()) / sd
        partA.append({"kind": "blockrep", "seq": sname, "m": m,
                      "obs": obs, "null_mean": round(float(null.mean()), 2), "z": round(float(z), 2)})
    print("A:", sname, "ok", round(time.time() - T0), "s", flush=True)

partA.sort(key=lambda d: -abs(d["z"]))
FLAG_A = [d for d in partA if abs(d["z"]) > 4.0]
# quantos |z|>4 seriam esperados por acaso entre len(partA) normais?
n_A = len(partA)
exp_gt4 = n_A * 2 * (1 - 0.5 * (1 + math.erf(4 / math.sqrt(2))))
G.jsonl(LOG, {"event": "partA_summary", "n_stats": n_A, "n_shuffles": NSHUF_A,
              "max_abs_z": partA[0]["z"], "expected_|z|>4_by_chance": round(exp_gt4, 4),
              "n_flagged": len(FLAG_A), "top20": partA[:20]})
print("PARTE A: n_stats", n_A, "max|z|", partA[0]["z"], "flagged", len(FLAG_A), flush=True)

# ---------------------------------------------------------------- decode por lag flagged
AL322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
AL322_25 = AL322.replace(".", "")[:25]
ESC9 = [(x, y) for x in range(1, 10) for y in range(1, 10) if x != y]   # 72 escapes ordenados
PHRASES20 = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "yellowblueprimes",
             "hashthetext", "thematrixhasyou", "salphaseion", "cosmicduality", "yinyang",
             "halfandbetterhalf", "theseedisplanted", "followthewhiterabbit", "salvation",
             "enter", "anstoo", "ourfirsthintisyourlastcommand", "purplepill", "primebasics",
             "fubcdkingoraclequeenthingkymvps", "lifeanddeath"]
ALPHS = {"al322_25": AL322_25, "CANON": G.CANON}
for p in PHRASES20:
    ALPHS[f"kw:{p}"] = G.keyed_alphabet(p)
ALPHS = {k: v for k, v in ALPHS.items() if len(v) == 25}
_seen = {}
for k, v in list(ALPHS.items()):
    if v in _seen: del ALPHS[k]
    else: _seen[v] = k
print("alfabetos:", len(ALPHS), flush=True)

def decode_digits(digs, how, alphs=None, uni="123456789", escs=None):
    """checkerboard todos alfabetos x escapes; triagem semantic_text + oraculo sha256/privkey."""
    global N_TESTS, BEST
    alphs = alphs or ALPHS; escs = escs or ESC9
    for an, al in alphs.items():
        for e in escs:
            pt = G.checkerboard_decode(digs, al, e, uni)
            N_TESTS += 1
            sc = G.english_score(pt)
            if sc > BEST["score"]:
                BEST = {"score": round(sc, 3), "text": pt[:140], "how": f"{how}|{an}|esc{e}"}
            if G.semantic_text(pt):
                G.jsonl(LOG, {"event": "semantic_cand", "how": f"{how}|{an}|esc{e}",
                              "score": round(sc, 3), "head": pt[:120]})
                oracle_text(pt, f"{how}|{an}|esc{e}")

def explore_lag(seq_str, L, tag):
    """L como periodo: Bifid CANON periodo L; transposicao colunar de largura L -> checkerboard."""
    global N_TESTS
    bf = G.bifid(seq_str, G.CANON, L)
    N_TESTS += 1
    if G.semantic_text(bf): oracle_text(bf, f"{tag}|bifid{L}")
    for wid in (L,):
        cols = ["".join(seq_str[i] for i in range(c, len(seq_str), wid)) for c in range(wid)]
        t = "".join(cols)
        decode_digits(G.digits(t), f"{tag}|colread{wid}")

for d in FLAG_A[:8]:
    L = d.get("lag") or d.get("m")
    explore_lag(SEQS_A[d["seq"]], L, f"A|{d['seq']}|z{d['z']}")

# ================================================================= PARTE B
def a1z26(s): return [ord(c) - 96 for c in s.lower() if 'a' <= c <= 'z']
def ascii_bits(s): return [int(b) for ch in s for b in format(ord(ch), "08b")]

# ---- chaves com poucos residuos
KEYS = {}
KEYS["bin(enter)"] = ascii_bits("enter")                       # 40 bits (o binario a/b da pagina)
KEYS["bin(matrixsumlist)"] = ascii_bits("matrixsumlist")       # 104 bits
for w in ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword",
          "yellowblueprimes", "hashthetext", "enter"]:
    v = a1z26(w)
    KEYS[f"{w}:a1z26m2"] = [x % 2 for x in v]
    KEYS[f"{w}:a1z26m3"] = [x % 3 for x in v]
MR = G.MATRIX_README
KEYS["matrixREADME:spiral"] = [MR[r][c] for r, c in G.SPIRAL]           # 196
KEYS["matrixREADME:rowmajor"] = [MR[r][c] for r in range(14) for c in range(14)]
KEYS["url_bits192"] = [MR[r][c] for r, c in G.SPIRAL][:192]
KEYS["dbbi:m2"] = [d % 2 for d in G.digits(G.DBBI)]
KEYS["dbbi:m3"] = [d % 3 for d in G.digits(G.DBBI)]
KEYS["primeind570"] = [1 if G.is_prime(i) else 0 for i in range(570)]
KEYS["primeind570_b1"] = [1 if G.is_prime(i + 1) else 0 for i in range(570)]
# Thue-Morse
KEYS["thuemorse"] = [bin(i).count("1") % 2 for i in range(570)]
# Fibonacci mod 2 / mod 3
fib = [0, 1]
while len(fib) < 570: fib.append(fib[-1] + fib[-2])
KEYS["fib:m2"] = [x % 2 for x in fib[:570]]
KEYS["fib:m3"] = [x % 3 for x in fib[:570]]
# palavra de Fibonacci (substituicao 0->01, 1->0)
fw = "0"
while len(fw) < 570: fw = "".join("01" if c == "0" else "0" for c in fw)
KEYS["fibword"] = [int(c) for c in fw[:570]]
N_NAMED = len(KEYS)

# ---- todas as chaves periodicas de 2 simbolos com periodo <=12 (primitivas; rotacoes ja inclusas)
def primitive(t):
    L = len(t)
    for p in range(1, L):
        if L % p == 0 and all(t[i] == t[i % p] for i in range(L)): return False
    return True
PERIODIC = []
for p in range(1, 13):
    for bits in itertools.product((0, 1), repeat=p):
        if len(set(bits)) == 1: continue          # constante = relabel global, sem informacao serial
        if not primitive(bits): continue
        PERIODIC.append(list(bits))
print("chaves nomeadas:", N_NAMED, "periodicas 2-simb:", len(PERIODIC), flush=True)

# ---- configs
FD = G.digits(G.FAED); DD = G.digits(G.DBBI)
def mkcfg(digs):
    return {
        "m9":     dict(n=9,  c=np.array([d - 1 for d in digs]), uni="123456789",  back=1),
        "m10a1":  dict(n=10, c=np.array(digs),                  uni="0123456789", back=0),
        "m10a0":  dict(n=10, c=np.array([d - 1 for d in digs]), uni="0123456789", back=0),
        "m10i0":  dict(n=10, c=np.array([0 if d == 9 else d for d in digs]), uni="0123456789", back=0),
    }
SEQ_B = {"faed": mkcfg(FD), "dbbi": mkcfg(DD)}

# ---- filtro invariante barato: H_cond e IoC de digrafos vs 30 embaralhados (nulo cacheado por multiset)
NSHUF_B = 30
ZTHR_B = 3.0
def hcond(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).reshape(n, n).astype(float)
    rows = bg.sum(1, keepdims=True); N = bg.sum()
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(bg > 0, bg * np.log2(bg / rows), 0.0)
    return -t.sum() / N
def digraph_ioc(a, n):
    """IoC de digrafos sobrepostos."""
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).astype(float)
    N = bg.sum()
    return (bg * (bg - 1)).sum() / (N * (N - 1))
_NULL = {}
def null_stats(a, n):
    key = (n, tuple(np.bincount(a, minlength=n).tolist()))
    if key not in _NULL:
        h = np.empty(NSHUF_B); d = np.empty(NSHUF_B)
        for i in range(NSHUF_B):
            x = rng.permutation(a); h[i] = hcond(x, n); d[i] = digraph_ioc(x, n)
        _NULL[key] = (h.mean(), h.std() or 1e-12, d.mean(), d.std() or 1e-12)
    return _NULL[key]
def filt(a, n):
    hm, hs, dm, ds = null_stats(a, n)
    z1 = (hcond(a, n) - hm) / hs
    z2 = (digraph_ioc(a, n) - dm) / ds
    return float(z1), float(z2)

# ---------------------------------------------------------------- CONTROLE POSITIVO
def cb_encode(text, alpha, esc, uni):
    top = [d for d in uni if int(d) not in esc]; table = {}; k = 0
    for d in top: table[alpha[k]] = [int(d)]; k += 1
    for e in esc:
        for d in uni: table[alpha[k]] = [e, int(d)]; k += 1
    out = []
    for ch in text.upper():
        if ch in table: out += table[ch]
    return out
CTRL_TXT = ("THE ARCHITECT SAID THAT THE DOOR TO YOUR RIGHT LEADS TO THE SOURCE AND THE SALVATION "
            "OF ZION WHILE THE DOOR TO YOUR LEFT LEADS BACK TO THE MATRIX TO HER AND TO THE END OF "
            "YOUR SPECIES YOU ARE HERE BECAUSE ZION IS ABOUT TO BE DESTROYED ITS EVERY LIVING "
            "INHABITANT TERMINATED ITS ENTIRE EXISTENCE ERADICATED")
ctrl_p = cb_encode(CTRL_TXT, AL322, (1, 4), "0123456789")
assert G.checkerboard_decode(ctrl_p, AL322, (1, 4), "0123456789") == CTRL_TXT.replace(" ", "")
KCTRL = [1, 0, 1, 1, 0, 0, 1]                      # chave BINARIA de periodo 7
ctrl_c = np.array([(p + KCTRL[i % 7]) % 10 for i, p in enumerate(ctrl_p)])
z_cipher = filt(ctrl_c, 10)
ctrl_ok_seq = np.array([(c - KCTRL[i % 7]) % 10 for i, c in enumerate(ctrl_c)])
z_ok = filt(ctrl_ok_seq, 10)
z_rot = filt(np.array([(c - KCTRL[(i + 3) % 7]) % 10 for i, c in enumerate(ctrl_c)]), 10)
z_wrong = filt(np.array([(c - [1, 1, 0, 1, 0, 1, 0][i % 7]) % 10 for i, c in enumerate(ctrl_c)]), 10)
ctrl_pt = G.checkerboard_decode(list(ctrl_ok_seq), AL322, (1, 4), "0123456789")
CTRL_PASS = (max(abs(z_ok[0]), abs(z_ok[1])) > ZTHR_B and ctrl_pt.startswith("THEARCHITECT")
             and G.semantic_text(ctrl_pt))
G.jsonl(LOG, {"event": "control", "len": len(ctrl_c), "key": KCTRL,
              "z_cipher(hcond,digIoC)": [round(x, 2) for x in z_cipher],
              "z_correct_key": [round(x, 2) for x in z_ok],
              "z_rot3": [round(x, 2) for x in z_rot],
              "z_wrong_key": [round(x, 2) for x in z_wrong],
              "decoded_head": ctrl_pt[:40], "control_ok": bool(CTRL_PASS)})
print("CONTROLE:", CTRL_PASS, "z chave certa", [round(x, 2) for x in z_ok],
      "| cifra", [round(x, 2) for x in z_cipher], "| rot3", [round(x, 2) for x in z_rot],
      "| chave errada", [round(x, 2) for x in z_wrong], flush=True)
assert CTRL_PASS, "controle positivo falhou"

# ---------------------------------------------------------------- varredura B
def rekey_np(c, k, n, mode):
    K = np.resize(np.array(k), len(c))
    return (c - K) % n if mode == "add" else (c + K) % n

n_streams = 0; n_pass = 0; PASSERS = []; zmax_seen = 0.0
baseline = {}
for sq, cfgs in SEQ_B.items():
    for cn, cfg in cfgs.items():
        z = filt(cfg["c"], cfg["n"]); n_streams += 1; N_TESTS += 1
        baseline[f"{sq}|{cn}"] = [round(x, 2) for x in z]
G.jsonl(LOG, {"event": "baseline_B", "z_hcond_digIoC": baseline})
print("baseline B:", baseline, flush=True)

ALLKEYS = list(KEYS.items()) + [(f"per{len(b)}:{''.join(map(str,b))}", b) for b in PERIODIC]
for sq, cfgs in SEQ_B.items():
    for cn, cfg in cfgs.items():
        n = cfg["n"]; c = cfg["c"]
        seen = set()
        for kname, kraw in ALLKEYS:
            L = len(kraw)
            rots = range(L) if kname in KEYS else (0,)   # periodicas ja cobrem rotacoes
            for rot in rots:
                k = list(kraw[rot:]) + list(kraw[:rot])
                k = [x % n for x in k]
                if len(set(k)) == 1: continue
                tk = (n, tuple(k[:min(L, len(c))]))
                if tk in seen: continue
                seen.add(tk)
                for mode in ("add", "sub"):
                    a = rekey_np(c, k, n, mode)
                    z1, z2 = filt(a, n); n_streams += 1; N_TESTS += 1
                    zm = max(abs(z1), abs(z2))
                    if zm > zmax_seen: zmax_seen = zm
                    if zm > ZTHR_B:
                        n_pass += 1
                        how = f"B|{sq}|{cn}|{kname}|rot{rot}|{mode}"
                        G.jsonl(LOG, {"event": "filter_pass", "how": how,
                                      "hcond_z": round(z1, 2), "digIoC_z": round(z2, 2)})
                        PASSERS.append((zm, a.copy(), cfg, how, sq))
        print("B:", sq, cn, "streams", n_streams, "pass", n_pass, "zmax", round(zmax_seen, 2),
              round(time.time() - T0), "s", flush=True)

# ---------------------------------------------------------------- decode dos aprovados
PASSERS.sort(key=lambda t: -t[0])
DECODE_CAP = 40
for i, (zm, a, cfg, how, sq) in enumerate(PASSERS[:DECODE_CAP]):
    digs = [int(x) + cfg["back"] for x in a]
    if cfg["n"] == 9:
        decode_digits(digs, how, uni="123456789", escs=ESC9)
    else:
        decode_digits(digs, how, uni="0123456789",
                      escs=[(x, y) for x in range(10) for y in range(10) if x != y][:90])
    # z-method (digitos -> decimal -> hex -> ascii)
    try:
        zb = G.z_method([d % 10 for d in digs]); N_TESTS += 1
        if G.semantic(zb): oracle_text(zb.decode("latin-1"), how + "|zmethod")
    except Exception:
        pass
    # Bifid CANON 570 / 285 sobre o stream rechaveado mapeado de volta p/ a-i
    txt = "".join("abcdefghi"[(int(x)) % 9] for x in a)
    for per in (570, 285):
        bf = G.bifid(txt, G.CANON, per); N_TESTS += 1
        if G.semantic_text(bf): oracle_text(bf, f"{how}|bifid{per}")
    if i % 5 == 0:
        print("decode", i, how, "z", round(zm, 2), "n_tests", N_TESTS,
              "best", BEST["score"], round(time.time() - T0), "s", flush=True)

summary = {
    "event": "summary", "family": "residue_autocorr", "n_tests": N_TESTS,
    "partA": {"n_stats": n_A, "n_shuffles": NSHUF_A, "max_abs_z": partA[0]["z"],
              "expected_|z|>4_by_chance": round(exp_gt4, 4), "n_flagged_z4": len(FLAG_A),
              "flagged": FLAG_A[:10], "top10": partA[:10]},
    "partB": {"n_named_keys": N_NAMED, "n_periodic_keys": len(PERIODIC), "n_streams": n_streams,
              "n_filter_pass": n_pass, "zmax_real": round(zmax_seen, 2),
              "control_z_correct_key": [round(x, 2) for x in z_ok],
              "control_z_cipher": [round(x, 2) for x in z_cipher],
              "control_z_wrongkey": [round(x, 2) for x in z_wrong],
              "n_decoded_streams": min(len(PASSERS), DECODE_CAP)},
    "hard_hits": HARD, "n_soft": len(SOFT), "soft_sample": SOFT[:10], "best_readable": BEST,
    "secs": round(time.time() - T0),
}
G.jsonl(LOG, summary)
print(json.dumps(summary, ensure_ascii=False, indent=1)[:6000])
