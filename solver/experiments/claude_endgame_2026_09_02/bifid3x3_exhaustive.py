"""
FAMILIA bifid3x3_exhaustive — Bifid 3x3 sobre a-i, TODOS os 9! quadrados.

Hipotese: faed (570) / dbbi (91) sao Bifid 3x3 (quadrado desconhecido, periodo divisor do
comprimento, decrypt ou encrypt). O quadrado certo produz saida a-i com dependencia serial forte
(digitos de checkerboard/z-method), detectavel por estatisticas invariantes ao rotulo.

Fato estrutural usado: aplicar a MESMA permutacao pi as linhas e colunas do quadrado da saida
IDENTICA (P'(s)=(pi r, pi c) transforma coordenadas e a inversa consistentemente). Logo ha
9!/3! = 60480 classes; cada classe = 1 saida distinta. Verificado empiricamente abaixo.

Triagem: o Bifid tem artefato proprio — cada posicao da saida toma (linha, coluna) de fontes
{R,C} fixas por posicao (classe de posicao RR/RC/CR/CC). Com unigrama assimetrico (faed), isso
cria dependencia lag-1 espuria em QUALQUER quadrado. Nulo primario = embaralhar a saida DENTRO
das classes de posicao (preserva o artefato, mata a estrutura serial). Nulo secundario (pedido
no briefing) = embaralhar a saida inteira. Etapa 1: G-stat (LLR de dependencia, esperanca sob o
nulo primario) em todas as 60480 classes x (periodo, modo). Etapa 2: z empirico (200 shuffles)
nos top-T. Etapa 3: decodes (z-method, base-9, checkerboard x3 alfabetos x36 escapes,
sha256->AES 3 blobs SHA256 + privkey, Bifid5 CANON) nos top-300 por |z|.
"""
import sys, os, json, time, itertools, hashlib, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import gsmg_common as G

SP = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(SP, "bifid3x3_exhaustive.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)
rng = np.random.default_rng(20260902)
T0 = time.time()
N_BIFID = 0      # saidas Bifid distintas computadas
N_DECODE = 0     # decodes downstream

log({"kind": "hypothesis", "text": __doc__.strip()})

# ------------------------------------------------------------------ classes de quadrados
PERMS = np.array(list(itertools.permutations(range(9))), dtype=np.int8)   # perm[s] = celula de s
assert PERMS.shape == (362880, 9)
def code(P): return (P.astype(np.int64) * (9 ** np.arange(8, -1, -1))).sum(1)
own = code(PERMS); best = own.copy()
for pi in itertools.permutations(range(3)):
    pi = np.array(pi); r, c = PERMS // 3, PERMS % 3
    img = (3 * pi[r] + pi[c]).astype(np.int8)
    best = np.minimum(best, code(img))
CLASSES = PERMS[own == best]
assert len(CLASSES) == 60480, len(CLASSES)
print("classes:", len(CLASSES), round(time.time() - T0, 1), "s")

# ------------------------------------------------------------------ indices de Bifid vetorizado
def bifid_index(n, p, mode):
    """Retorna idx_row, idx_col (n,) em RC=[R|C] (len 2n) e a classe de posicao (0..3)."""
    ir = np.empty(n, np.int64); ic = np.empty(n, np.int64)
    for o in range(0, n, p):
        L = min(p, n - o)
        if mode == "decrypt":
            seq = [(o + k // 2) + (n if k % 2 else 0) for k in range(2 * L)]   # r0,c0,r1,c1...
            for i in range(L): ir[o + i] = seq[i]; ic[o + i] = seq[L + i]
        else:
            seq = [o + k for k in range(L)] + [n + o + k for k in range(L)]      # R-bloco ++ C-bloco
            for i in range(L): ir[o + i] = seq[2 * i]; ic[o + i] = seq[2 * i + 1]
    cls = 2 * (ir >= n) + (ic >= n)
    return ir, ic, cls
def bifid_all(t, P, ir, ic):
    """t: (n,) simbolos 0..8; P: (K,9) perms. Retorna saida (K,n) simbolos 0..8."""
    cell = P[:, t]                              # (K,n) celula de cada simbolo de entrada
    RC = np.concatenate([cell // 3, cell % 3], axis=1)   # (K,2n)
    oc = 3 * RC[:, ir] + RC[:, ic]              # celula de saida
    inv = np.argsort(P, axis=1).astype(np.int8) # celula -> simbolo
    return np.take_along_axis(inv, oc.astype(np.int64), axis=1)
def sym2arr(s): return np.array([ord(c) - 97 for c in s], np.int8)
def arr2sym(a): return "".join(chr(97 + int(x)) for x in a)

# controle de correcao: vetorizado == G.bifid e invariancia diagonal
for _ in range(20):
    P = rng.permutation(9).astype(np.int8); alpha = "".join(chr(97 + int(np.where(P == k)[0][0])) for k in range(9))
    for txt, p in ((G.FAED, 570), (G.FAED, 19), (G.DBBI, 13), (G.DBBI, 7), (G.FAED, 2)):
        for mode in ("decrypt", "encrypt"):
            n = len(txt); ir, ic, _ = bifid_index(n, p, mode)
            v = arr2sym(bifid_all(sym2arr(txt), P[None], ir, ic)[0])
            assert v == G.bifid(txt, alpha, p, 3, mode), (alpha, p, mode)
            pi = rng.permutation(3); P2 = (3 * pi[P // 3] + pi[P % 3]).astype(np.int8)
            assert arr2sym(bifid_all(sym2arr(txt), P2[None], ir, ic)[0]) == v
print("bifid vetorizado == G.bifid; invariancia diagonal OK")

# ------------------------------------------------------------------ estatisticas
LOG2 = np.log2
def digraph_counts(out):
    """out (..., n) -> (..., 81) contagens de digrafos."""
    K = int(np.prod(out.shape[:-1])); o = out.reshape(K, -1).astype(np.int32)
    codes = o[:, :-1] * 9 + o[:, 1:] + (81 * np.arange(K, dtype=np.int32))[:, None]
    del o
    N = np.bincount(codes.ravel(), minlength=81 * K).reshape(*out.shape[:-1], 9, 9).astype(np.float64)
    del codes
    return N
def stats_from_counts(N):
    T = N.sum((-1, -2), keepdims=True)
    def H(x):
        p = x / x.sum(-1, keepdims=True); p = np.where(p > 0, p, 1.0)
        return -(p * LOG2(p)).sum(-1)
    Hxy = H(N.reshape(*N.shape[:-2], 81)); Hx = H(N.sum(-1)); Hy = H(N.sum(-2))
    ioc = (N * (N - 1)).sum((-1, -2)) / (T[..., 0, 0] * (T[..., 0, 0] - 1))
    return Hxy - Hx, Hx + Hy - Hxy, ioc          # H_cond, MI, IoC
def gstat(out, cls):
    """LLR de dependencia lag-1 dado o nulo por classe de posicao. out (K,n)."""
    K, n = out.shape
    N = digraph_counts(out)                                              # (K,9,9)
    codes = out.astype(np.int32) + (9 * cls[None, :]).astype(np.int32) + (36 * np.arange(K, dtype=np.int32))[:, None]
    U = np.bincount(codes.ravel(), minlength=36 * K).reshape(K, 4, 9).astype(np.float64)
    pa = U / np.maximum(U.sum(-1, keepdims=True), 1)                     # (K,4,9)
    M = np.zeros((4, 4)); np.add.at(M, (cls[:-1], cls[1:]), 1)          # pares de classes adjacentes
    E = np.einsum("ab,kai,kbj->kij", M, pa, pa)
    with np.errstate(divide="ignore", invalid="ignore"):
        g = np.where(N > 0, N * np.log(N / np.maximum(E, 1e-300)), 0.0)
    return 2 * g.sum((-1, -2))
def within_class_perms(cls, nsh):
    idx = np.tile(np.arange(len(cls)), (nsh, 1))
    for c in range(4):
        pos = np.where(cls == c)[0]
        if len(pos) > 1:
            for k in range(nsh): idx[k, pos] = pos[rng.permutation(len(pos))]
    return idx
def empirical_z(out, cls, nsh=200):
    """out (K,n). z (K,3) sob nulo por classe e z (K,3) sob shuffle pleno."""
    K, n = out.shape
    obs = np.stack(stats_from_counts(digraph_counts(out)), -1)          # (K,3)
    res = []
    for kind in ("class", "plain"):
        idx = within_class_perms(cls, nsh) if kind == "class" else np.stack([rng.permutation(n) for _ in range(nsh)])
        mu = np.empty((K, 3)); sd = np.empty((K, 3))
        for a in range(0, K, 25):                       # sub-lote: pico ~25*nsh*n bytes
            sh = out[a:a + 25][:, idx]
            st = np.stack(stats_from_counts(digraph_counts(sh)), -1)
            mu[a:a + 25], sd[a:a + 25] = st.mean(1), st.std(1)
            del sh, st
        res.append((obs - mu) / np.maximum(sd, 1e-9))
    return obs, res[0], res[1]

# ------------------------------------------------------------------ pipeline de triagem
PERIODS = {"faed": [570, 285, 190, 114, 95, 57, 38, 30, 19, 15, 10, 6, 5, 3, 2], "dbbi": [91, 13, 7]}
def screen(text, label, periods, top_T=4000, chunk=4032):
    """Etapa 1 (G em todas as classes) + etapa 2 (z empirico nos top_T). Retorna lista de triplas."""
    global N_BIFID
    t = sym2arr(text); n = len(t); rows = []
    for p in periods:
        for mode in ("decrypt", "encrypt"):
            ir, ic, cls = bifid_index(n, p, mode)
            gs = np.empty(len(CLASSES), np.float32)
            for a in range(0, len(CLASSES), chunk):
                out = bifid_all(t, CLASSES[a:a + chunk], ir, ic)
                gs[a:a + chunk] = gstat(out, cls); del out
            N_BIFID += len(CLASSES)
            rows.append((p, mode, gs))
            print(f"  {label} p={p} {mode}: G max={gs.max():.1f} mean={gs.mean():.1f} sd={gs.std():.2f}", round(time.time() - T0), "s", flush=True)
    # top_T global por G
    allg = np.concatenate([r[2] for r in rows]); order = np.argsort(-allg)[:top_T]
    per = len(CLASSES); cand = {}
    for o in order:
        k, ci = divmod(int(o), per); cand.setdefault(k, []).append(ci)
    triples = []
    for k, cis in cand.items():
        p, mode, gs = rows[k]; ir, ic, cls = bifid_index(n, p, mode)
        cis = np.array(cis); out = bifid_all(t, CLASSES[cis], ir, ic)
        for a in range(0, len(cis), 200):
            obs, zc, zp = empirical_z(out[a:a + 200], cls)
            for j in range(len(obs)):
                ci = int(cis[a + j])
                triples.append({"text": label, "period": p, "mode": mode, "class": ci,
                                "square": arr2sym(np.argsort(CLASSES[ci])),  # alfabeto: celula->simbolo
                                "G": float(gs[ci]), "Hcond": float(obs[j, 0]), "MI": float(obs[j, 1]), "IoC": float(obs[j, 2]),
                                "z_class": [float(x) for x in zc[j]], "z_plain": [float(x) for x in zp[j]],
                                "absz": float(np.abs(zc[j]).max()), "absz_plain": float(np.abs(zp[j]).max()),
                                "zH": float(zc[j, 0])})
    triples.sort(key=lambda r: r["zH"])   # mais negativo = mais dependencia serial
    gstats = {f"{p}/{m}": {"max": float(g.max()), "mean": float(g.mean()), "sd": float(g.std())} for p, m, g in rows}
    return triples, gstats, allg

# ------------------------------------------------------------------ CONTROLE positivo
def cb_encode(pt, alphabet, escapes):
    top = [d for d in "123456789" if int(d) not in escapes]
    need = len(top) + 18; alphabet = (alphabet + "." * need)[:need]
    m = {}; k = 0
    for d in top: m[alphabet[k]] = [int(d)]; k += 1
    for e in escapes:
        for d in "123456789": m[alphabet[k]] = [e, int(d)]; k += 1
    out = []
    for c in pt:
        if c in m: out += m[c]
    return out
readme = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
i0 = readme.index("NOW TO RETURN TO THE SOURCE CODES")
ARCH = re.sub("[^A-Z]", "", readme[i0:i0 + 2500].upper().replace("J", "I"))   # ingles real (score -4.08)
CTRL_STRONG = "".join(chr(96 + d) for d in cb_encode(ARCH, G.CANON, (1, 4)))[:570]      # checkerboard real (1-9)
CTRL_WEAK = "".join(chr(97 + (ord(c) - 65) % 9) for c in ARCH)[:570]                     # letra -> (idx mod 9): 26->9
assert len(CTRL_STRONG) == 570 and len(CTRL_WEAK) == 570
def plant(pt, P, p, mode_enc):
    """Cifra pt com quadrado P; o screen deve acha-lo no modo oposto."""
    ir, ic, _ = bifid_index(len(pt), p, mode_enc)
    return arr2sym(bifid_all(sym2arr(pt), P[None], ir, ic)[0])
def class_of(P):
    best = None
    for pi in itertools.permutations(range(3)):
        pi = np.array(pi); img = (3 * pi[P // 3] + pi[P % 3]).astype(np.int8)
        c = int(code(img[None])[0]); best = c if best is None else min(best, c)
    return int(np.where(code(CLASSES) == best)[0][0])

CONTROLS = []
ctrl_specs = [("strong", CTRL_STRONG, 570, "encrypt"), ("strong", CTRL_STRONG, 30, "decrypt"),
              ("weak", CTRL_WEAK, 19, "encrypt")]
for name, pt, p, menc in ctrl_specs:
    P = rng.permutation(9).astype(np.int8); ct = plant(pt, P, p, menc); true_ci = class_of(P)
    want_mode = "decrypt" if menc == "encrypt" else "encrypt"
    # sanidade: decifrar com o quadrado certo devolve pt
    ir, ic, _ = bifid_index(570, p, want_mode)
    assert arr2sym(bifid_all(sym2arr(ct), P[None], ir, ic)[0]) == pt
    tri, gst, allg = screen(ct, f"ctrl_{name}_p{p}", PERIODS["faed"], top_T=4000)
    rank = next((i + 1 for i, r in enumerate(tri) if r["class"] == true_ci and r["period"] == p and r["mode"] == want_mode), None)
    hit = next((r for r in tri if r["class"] == true_ci and r["period"] == p and r["mode"] == want_mode), None)
    rank_zH = rank_absz = None
    if hit:
        rank_zH = 1 + sum(1 for r in tri if r["zH"] < hit["zH"])
        rank_absz = 1 + sum(1 for r in tri if r["absz"] > hit["absz"])
    # rank por G entre TODAS as classes x periodos x modos
    k = [i for i, (pp, mm) in enumerate((pp, mm) for pp in PERIODS["faed"] for mm in ("decrypt", "encrypt")) if pp == p and mm == want_mode][0]
    gtrue = allg[k * len(CLASSES) + true_ci]; rank_G = int((allg > gtrue).sum()) + 1
    rec = {"kind": "control", "name": name, "period": p, "planted_mode": menc, "true_class": true_ci,
           "true_square": arr2sym(np.argsort(P)), "rank_G_all": rank_G, "G_true": float(gtrue),
           "rank_in_funnel_zH": rank_zH, "rank_in_funnel_absz": rank_absz, "pos_sorted": rank,
           "funnel_zH_min": float(min(r["zH"] for r in tri)),
           "true_stats": {kk: hit[kk] for kk in ("z_class", "z_plain", "Hcond", "MI", "IoC")} if hit else None,
           "top1": {kk: tri[0][kk] for kk in ("period", "mode", "class", "absz", "zH", "z_class")},
           "n_classes_ge_G": rank_G - 1}
    print("CONTROLE", json.dumps(rec)[:400], flush=True); log(rec); CONTROLS.append(rec)

# ------------------------------------------------------------------ dados reais
REAL = {}
for label, txt in (("faed", G.FAED), ("dbbi", G.DBBI)):
    tri, gst, allg = screen(txt, label, PERIODS[label], top_T=4000)
    REAL[label] = tri
    log({"kind": "screen", "text": label, "gstats": gst, "n_classes": len(CLASSES),
         "top10": [{k: r[k] for k in ("period", "mode", "square", "G", "zH", "absz", "z_class", "z_plain")} for r in tri[:10]]})
    print(label, "top5 por z_Hcond:", [(r["period"], r["mode"], r["square"], round(r["zH"], 2)) for r in tri[:5]], flush=True)

# ------------------------------------------------------------------ decodes downstream (top-300 por |z|)
CB_ALPHAS = {"FUBCDORA": G.keyed_alphabet("FUBCDORALETHINGKYMVPS"), "CANON": G.CANON, "AZ": "ABCDEFGHIKLMNOPQRSTUVWXYZ"}
ESC = [(a, b) for a in range(1, 10) for b in range(a + 1, 10)]
HARD, SOFT, READ = [], [], []
def judge_bytes(b, how):
    global N_DECODE
    N_DECODE += 1
    hits = G.fast_priv_scan(b, how)
    for h in hits: HARD.append({"how": how, "hit": h, "hex": b.hex()}); log({"kind": "HARD", "how": how, "hit": h, "hex": b.hex()})
    if G.semantic(b):
        pr = G.printable(b)
        SOFT.append({"how": how, "printable": round(pr, 3), "head": b[:60].decode("latin-1")})
def judge_text(t, how):
    global N_DECODE
    N_DECODE += 1
    if G.semantic_text(t):
        sc = G.english_score(t); READ.append({"score": round(sc, 3), "text": t[:120], "how": how, "words": G.word_hits(t, 6)[:8]})
    for w in G.wif_candidates(t):
        try:
            import base58; r = G.priv_hit(base58.b58decode_check(w)[1:33])
            if r: HARD.append({"how": how + "|wif", "wif": w}); log({"kind": "HARD", "how": how, "wif": w})
        except Exception: pass
    for h in G.hex64_candidates(t):
        r = G.priv_hit(bytes.fromhex(h))
        if r: HARD.append({"how": how + "|hex64", "hex": h}); log({"kind": "HARD", "how": how, "hex": h})
def judge_pw(pw, how):
    global N_DECODE
    for blob in ("SMALL", "COSMIC", "TAIL32"):
        N_DECODE += 1
        for kdf, p in G.aes_try(pw, blob, kdf="sha256"):
            rec = {"how": how, "blob": blob, "kdf": kdf, "pw": pw if isinstance(pw, str) else pw.hex(), "len": len(p),
                   "printable": round(G.printable(p), 3), "head": p[:48].decode("latin-1")}
            if G.semantic(p): rec["plaintext_hex"] = p.hex(); HARD.append(rec); log({"kind": "HARD", **rec})
            else: SOFT.append(rec); log({"kind": "soft_pad", **rec})
    N_DECODE += 1
    k = G.sha(pw); r = G.priv_hit(k)
    if r: HARD.append({"how": how + "|sha256->priv", "priv": k.hex()}); log({"kind": "HARD", "how": how, "priv": k.hex()})
def downstream(out, how, full=True):
    digs = G.digits(out)
    try: judge_bytes(G.z_method(digs), how + "|z")
    except Exception as e: log({"kind": "err", "how": how, "err": str(e)})
    n9 = int("".join(str(d - 1) for d in digs), 9); h = format(n9, "x"); h = "0" + h if len(h) % 2 else h
    judge_bytes(bytes.fromhex(h), how + "|base9")
    for pw in (out, out.upper(), G.shahex(out)):
        judge_pw(pw, how + f"|sha256pw({'raw' if pw == out else 'upper' if pw == out.upper() else 'shahex'})")
    if not full: return
    for an, alpha in CB_ALPHAS.items():
        for esc in ESC:
            judge_text(G.checkerboard_decode(digs, alpha, esc), how + f"|cb[{an}]esc{esc[0]}{esc[1]}")
    judge_text(G.bifid(out, G.CANON, None, 5, "decrypt"), how + "|bif5CANON full")
    judge_text(G.bifid(out, G.CANON, None, 5, "encrypt"), how + "|bif5CANON full enc")
# controle do downstream: quadrado + checkerboard reproduzem o texto plantado
_p = rng.permutation(9).astype(np.int8); _ct = plant(CTRL_STRONG, _p, 570, "encrypt")
_ir, _ic, _ = bifid_index(570, 570, "decrypt"); _o = arr2sym(bifid_all(sym2arr(_ct), _p[None], _ir, _ic)[0])
assert G.checkerboard_decode(G.digits(_o), G.CANON, (1, 4)).startswith(ARCH[:30]) and G.semantic_text(G.checkerboard_decode(G.digits(_o), G.CANON, (1, 4)))
print("controle downstream (checkerboard CANON esc14) OK")

for label, txt in (("faed", G.FAED), ("dbbi", G.DBBI)):
    t = sym2arr(txt)
    byzH = sorted(REAL[label], key=lambda x: x["zH"]); byabs = sorted(REAL[label], key=lambda x: -x["absz"])
    full_ids = {id(x) for x in byzH[:300]} | {id(x) for x in byabs[:300]}
    seen = {id(x) for x in byzH[:1500]}
    sel = byzH[:1500] + [x for x in byabs[:1500] if id(x) not in seen]
    for rank, r in enumerate(sel):
        ir, ic, _ = bifid_index(len(t), r["period"], r["mode"])
        out = arr2sym(bifid_all(t, CLASSES[r["class"]][None], ir, ic)[0])
        how = f"bifid3[{r['square']}] p={r['period']} {r['mode']} {label} z={r['absz']:.2f}"
        downstream(out, how, full=id(r) in full_ids)
    print(label, "downstream ok", N_DECODE, round(time.time() - T0), "s", flush=True)

# ------------------------------------------------------------------ resumo
READ.sort(key=lambda r: -r["score"])
summary = {"family": "bifid3x3_exhaustive", "n_bifid_outputs": N_BIFID, "n_decodes": N_DECODE,
           "n_squares_nominal": 362880, "n_classes": len(CLASSES), "controls": CONTROLS,
           "faed_top": [{k: r[k] for k in ("period", "mode", "square", "G", "Hcond", "MI", "IoC", "z_class", "z_plain", "absz")} for r in sorted(REAL["faed"], key=lambda x: x["zH"])[:20]],
           "dbbi_top": [{k: r[k] for k in ("period", "mode", "square", "G", "Hcond", "MI", "IoC", "z_class", "z_plain", "absz")} for r in sorted(REAL["dbbi"], key=lambda x: x["zH"])[:20]],
           "faed_dist": {"zH_min": min(r["zH"] for r in REAL["faed"]), "absz_max": max(r["absz"] for r in REAL["faed"]),
                         "n_zH_le_m6": sum(r["zH"] <= -6 for r in REAL["faed"]), "n_zH_le_m4": sum(r["zH"] <= -4 for r in REAL["faed"])},
           "dbbi_dist": {"zH_min": min(r["zH"] for r in REAL["dbbi"]), "absz_max": max(r["absz"] for r in REAL["dbbi"]),
                         "n_zH_le_m6": sum(r["zH"] <= -6 for r in REAL["dbbi"]), "n_zH_le_m4": sum(r["zH"] <= -4 for r in REAL["dbbi"])},
           "hard": HARD, "soft": SOFT[:40], "n_soft": len(SOFT), "readable": READ[:15], "n_readable": len(READ),
           "elapsed_s": round(time.time() - T0)}
log({"kind": "summary", **summary})
json.dump(summary, open(os.path.join(SP, "bifid3x3_exhaustive_summary.json"), "w"), indent=1)
print(json.dumps({k: summary[k] for k in ("n_bifid_outputs", "n_decodes", "faed_dist", "dbbi_dist", "n_soft", "n_readable", "elapsed_s")}))
print("HARD:", HARD)
