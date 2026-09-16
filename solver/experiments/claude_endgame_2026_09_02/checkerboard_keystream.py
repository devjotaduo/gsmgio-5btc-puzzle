# -*- coding: utf-8 -*-
"""
FAMILIA checkerboard_keystream — faed = checkerboard + camada ADITIVA periodica (Vigenere/Beaufort mod 9/10).

Hipotese (falsificavel, espaco finito): faed tem forma unigrama de checkerboard mas sem memoria
serial; uma camada aditiva periodica ANTES do checkerboard (como a fase 3.2 combinou Beaufort + VIC)
produz exatamente isso. Se verdadeira, existe keystream (token/numero da pagina) x rotacao x direcao
x modo (add/sub/beaufort/autokey) x config (mod 9 a=1..9; mod 10 a=1..i=9; mod 10 i->0) tal que o
faed re-chaveado recupera estrutura serial de checkerboard — detectavel SEM conhecer o alfabeto
(H_cond dos digitos e IoC dos tokens fora do nulo de embaralhados, |z|>3) — e o decode com um dos
alfabetos conhecidos (3.2.2, CANON, 60 frases) x escapes ordenados da ingles, cujo sha256 abre
SMALL/COSMIC/TAIL32 (KDF sha256) ou e' a privkey do premio.
"""
import sys, json, time, math, random, hashlib, collections, itertools
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\checkerboard_keystream.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"event": "hypothesis", "family": "checkerboard_keystream", "text": __doc__.strip()})
rng = np.random.default_rng(1327)
NSHUF = 30          # nulo estagio 1 (H_cond)
NSHUF2 = 60         # nulo estagio 2 (token IoC)
ZTHR = 3.0

# ------------------------------------------------------------------ keystreams (valores brutos; reduzidos mod n por config)
def a1z26(s): return [ord(c) - 96 for c in s.lower() if 'a' <= c <= 'z']
WORDS = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "yellowblueprimes",
         "hashthetext", "thematrixhasyou"]
KS = {}
KS["dbbi:a1..9"] = G.digits(G.DBBI)                                  # 91
for w in WORDS:
    KS[f"{w}:a1z26"] = a1z26(w)
    KS[f"{w}:a1z26m9"] = [x % 9 for x in a1z26(w)]                   # difere so na config mod 10
M = G.MATRIX_IMG
KS["m102:rows"] = G.row_sums(M); KS["m102:cols"] = G.col_sums(M)
KS["m102:black_rows"] = [5, 8, 7, 6, 5, 6, 4, 3, 7, 8, 7, 7, 6, 7]
KS["m102:black_cols"] = [7, 8, 5, 9, 7, 5, 3, 5, 6, 5, 7, 6, 6, 7]
KS["colidx"] = sorted(i for i in G.COLORED if G.COLORED[i][0] != 'W*')   # 24 -> mod 9 / mod 10 por config
KS["blueidx"] = sorted(G.BLUE_IDX); KS["yellowidx"] = sorted(G.YELLOW_IDX)
URLHASH = G.shahex("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
assert URLHASH.startswith("89727c")
for name, tok in list(G.TOKENS.items()) + [("urlhash_src", None)]:
    h = URLHASH if tok is None else G.shahex(tok)
    KS[f"sha256hex({name}):hexdec"] = [int(c, 16) for c in h]        # 64 valores 0..15
KS["primes<570"] = [p for p in range(2, 570) if G.is_prime(p)]        # 104
for n in ["1141", "11110", "101", "102", "163", "193", "140", "42", "1812", "21"]:
    KS[f"num{n}"] = [int(c) for c in n]
print("keystreams brutos:", len(KS))

# ------------------------------------------------------------------ configs (cifra c em 0..n-1; volta p/ digito do universo)
FD = G.digits(G.FAED)   # a=1..i=9
CONFIGS = {
    "m9":    dict(n=9,  c=[d - 1 for d in FD],              uni="123456789",  back=lambda p: p + 1),
    "m10a":  dict(n=10, c=FD[:],                            uni="0123456789", back=lambda p: p),
    "m10i0": dict(n=10, c=[0 if d == 9 else d for d in FD], uni="0123456789", back=lambda p: p),
}
MODES = ["add", "sub", "beau"]
def rekey(c, k, mode, n):
    L = len(k); N = len(c); p = [0] * N
    if mode == "add":
        for i in range(N): p[i] = (c[i] - k[i % L]) % n
    elif mode == "sub":
        for i in range(N): p[i] = (c[i] + k[i % L]) % n
    elif mode == "beau":
        for i in range(N): p[i] = (k[i % L] - c[i]) % n
    elif mode == "autokey_pt":
        for i in range(N): p[i] = (c[i] - (k[i] if i < L else p[i - L])) % n
    elif mode == "autokey_ct":
        for i in range(N): p[i] = (c[i] - (k[i] if i < L else c[i - L])) % n
    return p

# ------------------------------------------------------------------ filtro invariante (estagio 1: H_cond; estagio 2: token-IoC)
def hcond_np(a, n):
    """H(X_{i+1}|X_i) em bits, a = np.array de ints 0..n-1."""
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).reshape(n, n).astype(float)
    rows = bg.sum(1, keepdims=True); N = bg.sum()
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(bg > 0, bg * np.log2(bg / rows), 0.0)
    return -t.sum() / N
def hcond_z(seq, n, nshuf=NSHUF):
    a = np.asarray(seq); obs = hcond_np(a, n)
    null = np.array([hcond_np(rng.permutation(a), n) for _ in range(nshuf)])
    sd = null.std() or 1e-9
    return (obs - null.mean()) / sd, obs
def tokenize(digs, esc):
    out = []; i = 0; N = len(digs)
    while i < N:
        d = digs[i]
        if d in esc and i + 1 < N: out.append((d, digs[i + 1])); i += 2
        else: out.append((d,)); i += 1
    return out
def ioc(toks):
    c = collections.Counter(toks); N = len(toks)
    return sum(v * (v - 1) for v in c.values()) / (N * (N - 1))
def token_ioc_best(seq, uni_vals, nshuf=NSHUF2):
    """Para cada par de escapes (nao ordenado): z do IoC dos tokens vs embaralhados. Devolve (min z, par, obs)."""
    pairs = list(itertools.combinations(uni_vals, 2))
    sh = [list(rng.permutation(seq)) for _ in range(nshuf)]
    best = (0.0, None, 0.0)
    for e in pairs:
        E = set(e); obs = ioc(tokenize(seq, E))
        null = np.array([ioc(tokenize(s, E)) for s in sh]); sd = null.std() or 1e-9
        z = (obs - null.mean()) / sd
        if abs(z) > abs(best[0]): best = (float(z), e, obs)
    return best

# ------------------------------------------------------------------ decode (alfabetos) + oraculos
AL322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
PHRASES = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
 "ourfirsthintisyourlastcommand", "anstoo", "shabef", "shabefanstoo", "yellowblueprimes",
 "rosesarewhitebutoftenred", "yellowhasanumberandsodoesblue", "hushhush", "salphaseion",
 "salvation", "cosmicduality", "yinyang", "yingyang", "followthewhiterabbit", "theseedisplanted",
 "gsmgmeganigma", "gsmgio5btcpuzzlechallenge", "hashthetext", "thematrixhasyou", "causality",
 "theflowerblossomsthroughwhatseemstobeaconcretesurface", "jacquefresco",
 "lastwordsbeforearchichoicethispassword", "halfandbetterhalf", "thewarning", "logic",
 "knockknockneo", "temetnosce", "whiterabbit", "keymaker", "merovingian", "architect", "oracle",
 "zion", "source", "purplepill", "globallysupportingmygeneration", "gsmg", "bitcoin",
 "safenetlunahsm", "heisenbergsuncertaintyprinciple", "giveitjustonesecond",
 "lifeanddeath", "lemiroirdelavieetdelamort", "killprocess", "betterhalf", "primebasics",
 "returntothesourcecodes", "thedoortoyourright", "fubcdkingoraclequeenthingkymvps",
 "dbbi", "faed", "abcdefghijklmnopqrstuvwxyz", "etaoinshrdlcumwfgypbvkjxqz",
 "qwertyuiopasdfghjklzxcvbnm", "zyxwvutsrqponmlkjihgfedcba"]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH9 = {"CANON": G.CANON, "al322_25": AL322.replace(".", "")[:25]}
ALPH10 = {"al322": AL322, "CANON+..": G.CANON + "J.."}
for p in PHRASES:
    ALPH9[f"kw:{p}"] = G.keyed_alphabet(p)                           # 25, I=J
    ALPH10[f"kw26:{p}"] = G.keyed_alphabet(p, base=AZ, merge_j=False) + ".."   # 28
ALPH9 = {k: v for k, v in ALPH9.items() if len(v) == 25}
ALPH10 = {k: v for k, v in ALPH10.items() if len(v) == 28}
# dedupe por valor
for D in (ALPH9, ALPH10):
    seen = {}
    for k, v in list(D.items()):
        if v in seen: del D[k]
        else: seen[v] = k
ESC9 = [(a, b) for a in range(1, 10) for b in range(1, 10) if a != b]
ESC10 = [(a, b) for a in range(10) for b in range(10) if a != b]
print("alfabetos u1-9:", len(ALPH9), "u0-9:", len(ALPH10))

def neighbor(alpha, r):
    a = list(alpha); i, j = r.sample(range(len(a)), 2); a[i], a[j] = a[j], a[i]; return "".join(a)

n_decodes = 0; n_streams = 0; hard = []; soft = []; best = {"score": -99}; PASSERS = []; DECODE_CAP = 400
def oracle(pt, how):
    global best
    rec = {"how": how, "score": round(G.english_score(pt), 3), "head": pt[:80]}
    for pw in (pt, pt.lower(), G.shahex(pt), G.shahex(pt.lower())):
        for b in ("SMALL", "COSMIC", "TAIL32"):
            for kdf, p in G.aes_try(pw, b, kdf="sha256"):
                r = {"pw": pw[:80], "blob": b, "kdf": kdf, "printable": round(G.printable(p), 3), "head": p[:40].decode("latin-1")}
                if G.semantic(p): hard.append({**rec, **r, "plaintext_hex": p.hex()})
                else: soft.append({**rec, **r})
    for k in (G.sha(pt.encode()), G.sha(pt.lower().encode())):
        r = G.priv_hit(k)
        if r: hard.append({**rec, "privkey": k.hex(), "addr": r})
def decode_stream(seq, cfg, how):
    """Todos alfabetos x escapes ordenados; semantic_text + validacao por 2 vizinhos -> oraculo."""
    global n_decodes, best
    n = cfg["n"]; digs = [cfg["back"](p) for p in seq]
    if n == 9: alphs, escs, uni = ALPH9, ESC9, "123456789"
    else: alphs, escs, uni = ALPH10, ESC10, "0123456789"
    r = random.Random(7)
    for an, al in alphs.items():
        for e in escs:
            n_decodes += 1
            pt = G.checkerboard_decode(digs, al, e, uni)
            sc = G.english_score(pt)
            if sc > best["score"]: best = {"score": round(sc, 3), "text": pt[:120], "how": f"{how}|{an}|esc{e}"}
            if G.semantic_text(pt):
                nb = [G.english_score(G.checkerboard_decode(digs, neighbor(al, r), e, uni)) for _ in range(2)]
                ok = all(sc > x for x in nb)
                G.jsonl(LOG, {"event": "semantic_cand", "how": f"{how}|{an}|esc{e}", "score": round(sc, 3),
                              "neighbors": [round(x, 3) for x in nb], "validated": ok, "head": pt[:100]})
                if ok: oracle(pt, f"{how}|{an}|esc{e}")

# ------------------------------------------------------------------ pipeline
def run_stream(seq, cfg, how, decode=True):
    """Estagio 1 (H_cond z) -> estagio 2 (token IoC z) -> decode. Devolve dict com z's e flag passou."""
    global n_streams
    n_streams += 1
    z1, h = hcond_z(seq, cfg["n"])
    rec = {"how": how, "hcond_z": round(float(z1), 2)}; z1 = float(z1)
    passed = False
    if abs(z1) > 2.5:
        z2, e, obs = token_ioc_best(seq, [int(d) for d in cfg["uni"]])
        rec.update({"tok_z": round(z2, 2), "tok_esc": e, "tok_ioc": round(obs, 4)})
        passed = bool(abs(z1) > ZTHR or abs(z2) > ZTHR)
    rec["passed"] = passed
    if passed:
        G.jsonl(LOG, {"event": "filter_pass", **rec})
        if decode: PASSERS.append((max(abs(z1), abs(rec.get("tok_z", 0))), seq, cfg, how))
    return rec

# ------------------------------------------------------------------ CONTROLE POSITIVO
def cb_encode(text, alpha, esc, uni):
    top = [d for d in uni if int(d) not in esc]; table = {}; k = 0
    for d in top: table[alpha[k]] = [int(d)]; k += 1
    for e in esc:
        for d in uni: table[alpha[k]] = [e, int(d)]; k += 1
    out = []
    for ch in text.upper():
        if ch in table: out += table[ch]
    return out
CTRL_TXT = ("THE ARCHITECT SAID THAT THE DOOR TO YOUR RIGHT LEADS TO THE SOURCE AND THE SALVATION OF ZION "
            "WHILE THE DOOR TO YOUR LEFT LEADS BACK TO THE MATRIX TO HER AND TO THE END OF YOUR SPECIES "
            "YOU ARE HERE BECAUSE ZION IS ABOUT TO BE DESTROYED ITS EVERY LIVING INHABITANT TERMINATED "
            "ITS ENTIRE EXISTENCE ERADICATED THE FUNCTION OF THE ONE IS NOW TO RETURN TO THE SOURCE")
ctrl_p = cb_encode(CTRL_TXT, AL322, (1, 4), "0123456789")
assert G.checkerboard_decode(ctrl_p, AL322, (1, 4), "0123456789") == CTRL_TXT.replace(" ", "")
kctrl = [x % 10 for x in a1z26("matrixsumlist")]
ctrl_c = [(p + kctrl[i % 13]) % 10 for i, p in enumerate(ctrl_p)]     # Vigenere add mod 10
cfg_ctrl = dict(n=10, c=ctrl_c, uni="0123456789", back=lambda p: p)
z_raw, _ = hcond_z(ctrl_c, 10)
rec_ok = run_stream(rekey(ctrl_c, kctrl, "add", 10), cfg_ctrl, "CTRL|matrixsumlist|rot0|add", decode=False)
rec_bad = run_stream(rekey(ctrl_c, kctrl[3:] + kctrl[:3], "add", 10), cfg_ctrl, "CTRL|matrixsumlist|rot3|add", decode=False)
ctrl_pt = G.checkerboard_decode(rekey(ctrl_c, kctrl, "add", 10), AL322, (1, 4), "0123456789")
ctrl_ok = rec_ok["passed"] and rec_ok["hcond_z"] < -10 and ctrl_pt.startswith("THEARCHITECTSAID") and G.semantic_text(ctrl_pt)
G.jsonl(LOG, {"event": "control", "len_digits": len(ctrl_c), "hcond_z_cipher": round(float(z_raw), 2),
              "rekeyed_ok": rec_ok, "wrong_rotation": rec_bad, "decoded_head": ctrl_pt[:40], "control_ok": ctrl_ok})
print("CONTROLE:", ctrl_ok, "z cifra:", round(float(z_raw), 2), "z certo:", rec_ok, "z errado:", rec_bad)
assert ctrl_ok
# faed cru por config (baseline)
for cn, cfg in CONFIGS.items():
    r = run_stream(cfg["c"], cfg, f"faed_raw|{cn}", decode=False)
    G.jsonl(LOG, {"event": "baseline", **r})
n_streams = 0

# ------------------------------------------------------------------ varredura
t0 = time.time(); results = []; n_pass = 0; n_pass_streams = []
for cn, cfg in CONFIGS.items():
    n = cfg["n"]; c = cfg["c"]; seen = set()
    for kname, kraw in KS.items():
        k0 = [x % n for x in kraw]
        for dname, kd in (("fwd", k0), ("rev", k0[::-1])):
            L = len(kd)
            for rot in range(L):
                k = kd[rot:] + kd[:rot]
                tk = tuple(k)
                if tk in seen: continue
                seen.add(tk)
                if len(set(k)) == 1: continue          # constante = relabel; filtro invariante (faed cru ja medido)
                for mode in MODES:
                    how = f"{cn}|{kname}|{dname}|rot{rot}|{mode}"
                    r = run_stream(rekey(c, k, mode, n), cfg, how)
                    results.append((r["hcond_z"], r.get("tok_z"), how))
                    if r["passed"]: n_pass += 1; n_pass_streams.append(how)
            if len(set(kd)) > 1:
                for mode in ("autokey_pt", "autokey_ct"):
                    how = f"{cn}|{kname}|{dname}|{mode}"
                    r = run_stream(rekey(c, kd, mode, n), cfg, how)
                    results.append((r["hcond_z"], r.get("tok_z"), how))
                    if r["passed"]: n_pass += 1; n_pass_streams.append(how)
    print(cn, "streams:", n_streams, "passaram:", n_pass, "decodes:", n_decodes, round(time.time() - t0), "s", flush=True)

PASSERS.sort(key=lambda t: -t[0])
for i, (zz, seq, cfg, how) in enumerate(PASSERS[:DECODE_CAP]):
    decode_stream(seq, cfg, how)
    if i % 25 == 0: print("decode", i, how, "z", round(zz, 2), "decodes", n_decodes, "best", best["score"], round(time.time() - t0), "s", flush=True)
results.sort(key=lambda r: -abs(r[0]))
summary = {"event": "summary", "n_streams": n_streams, "n_filter_pass": n_pass, "pass_list": n_pass_streams[:50],
           "n_decoded_streams": min(len(PASSERS), DECODE_CAP), "n_decodes": n_decodes, "n_tests": n_streams + n_decodes, "hard": hard, "soft": soft[:20], "n_soft": len(soft),
           "best": best, "top_hcond": results[:10], "secs": round(time.time() - t0)}
G.jsonl(LOG, summary)
print(json.dumps(summary, ensure_ascii=False, indent=1))
