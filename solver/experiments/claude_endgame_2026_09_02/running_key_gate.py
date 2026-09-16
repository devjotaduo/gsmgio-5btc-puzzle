# -*- coding: utf-8 -*-
"""
FAMILIA running_key_gate (R6 do critico) — faed = checkerboard + running key APERIODICA (>= 570 digitos).

Hipotese (falsificavel, espaco finito): faed (570 digitos base-9) e' um checkerboard/VIC cujo ciphertext
foi mascarado por uma running key aperiodica de alta entropia tirada do corpus do puzzle (monologo do
Arquiteto 3.2.1, plaintexts das fases 2/3/3.2/3.2.2, dbbi x7, digitos das sha256 dos tokens/senhas,
URL 89727c, pi/e/sqrt2, bits da matriz, binarios abba, a propria faed com lag). Se verdadeira, existe
(chave, config mod 9/10, modo add/sub/beaufort, alinhamento <= 30) tal que o stream re-chaveado recupera
memoria serial de checkerboard — detectavel sem alfabeto por H_cond ou IoC de digrafos com |z| >= 10
contra embaralhados (chave certa: z = -24..-42 no controle) — e o decode com alfabetos conhecidos e'
ingles cujo sha256 abre SMALL/COSMIC/TAIL32 (EVP-SHA256) ou e' a privkey do premio.
Chaves binarias/ternarias/periodicas curtas ja' estao refutadas (rodada 2); aqui so' chaves >= 570.
"""
import sys, os, re, json, time, hashlib, collections, itertools
import numpy as np
SP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
from coincurve import PublicKey
import mpmath

LOG = os.path.join(SP, "running_key_gate.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)
log({"event": "hypothesis", "family": "running_key_gate", "text": __doc__.strip()})
rng = np.random.default_rng(89727)
NSHUF = 30
ZGATE = 10.0
MAXALIGN = 30
T0 = time.time()

# ------------------------------------------------------------------ oraculo rapido (copiado de bifid3x3_pass2.try_pw)
BL = {}
for name in ("SMALL", "COSMIC", "TAIL32"):
    salt, ct = G.BLOBS[name]
    BL[name] = (salt, ct, ct[-32:-16], ct[-16:])
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
def evp_key(pw, salt):
    d = b""; prev = b""
    while len(d) < 48:
        prev = hashlib.sha256(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]
def pad_ok(pt):
    p = pt[-1]; return 1 <= p <= 16 and pt.endswith(bytes([p]) * p)
HARD, SOFT = [], []
N = collections.Counter()
def try_pw(pw, how):
    """1 AES-ECB por blob (padding do ultimo bloco CBC); decifra tudo so' se fechar."""
    if isinstance(pw, str): pw = pw.encode("latin-1")
    for name, (salt, ct, cprev, clast) in BL.items():
        N["oracle_pw"] += 1
        k, iv = evp_key(pw, salt)
        last = bytes(a ^ b for a, b in zip(AES.new(k, AES.MODE_ECB).decrypt(clast), cprev))
        if not pad_ok(last): continue
        pt = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        if pt is None: continue
        rec = {"how": how, "blob": name, "kdf": "EVP-SHA256", "pw": pw.decode("latin-1")[:120], "len": len(pt),
               "printable": round(G.printable(pt), 3), "head": pt[:48].decode("latin-1")}
        if G.semantic(pt):
            rec["plaintext_hex"] = pt.hex(); HARD.append(rec); log({"kind": "HARD", **rec})
        else:
            SOFT.append(rec); log({"kind": "soft_pad", **rec})
def try_priv(sec, how):
    N["oracle_priv"] += 1
    try:
        if PublicKey.from_valid_secret(sec).format(False) == TGT:
            HARD.append({"how": how, "priv_hex": sec.hex()}); log({"kind": "HARD", "how": how, "priv_hex": sec.hex()})
    except Exception:
        pass

# ------------------------------------------------------------------ textos do corpus (README, verbatim)
README = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
def between(a, b):
    i = README.index(a); j = README.index(b, i) + len(b); return README[i:j]
TXT = {
    "arch321": between("YOUR LIFE IS THE SUM", "CIAO BELLA O"),
    "p322": between("IN CASE YOU MANAGE", "NEED FUNDS TO LIVE"),
    "p2": between("The ironic 2name", "worst gear."),
    "p3": between("What if the merovingian", "yet again."),
    "p32intro": between("I've been waiting for you", "four for one.") + between("Raising the stakes", "first one seen."),
    "beaufort_ct": re.search(r"^vtkvplmepph\w+", README, re.M).group(),
}
assert len(TXT["beaufort_ct"]) > 1000 and "TWENTY-THREE" in TXT["arch321"]
TXT["allphases"] = TXT["p2"] + TXT["p3"] + TXT["p32intro"] + TXT["arch321"] + TXT["p322"]
P322_DIGITS = re.search(r"^15165943\d+", README, re.M).group()

def letters(s): return [ord(c) - 96 for c in s.lower() if "a" <= c <= "z"]     # a1z26
def ext(k, L=570 + MAXALIGN + 1):
    k = list(k)
    while len(k) < L: k = k + k
    return k

KEYS = {}
for nm, t in TXT.items():
    L = letters(t)
    KEYS[f"{nm}:a1z26"] = ext(L)
    KEYS[f"{nm}:a0z25"] = ext([x - 1 for x in L])
KEYS["arch321:rev:a1z26"] = ext(letters(TXT["arch321"])[::-1])
# dbbi x7: identidade a=1..i=9; mapa CANON (posicao na ordem de 1a ocorrencia d,b,i,f,h,c,e,g,a -> 1..9); a=0..8
DB = G.digits(G.DBBI)
CANON9 = "dbifhcega"
KEYS["dbbi:id"] = ext(DB)
KEYS["dbbi:a0"] = ext([d - 1 for d in DB])
KEYS["dbbi:canon"] = ext([CANON9.index(c) + 1 for c in G.DBBI])
# sha256hex dos 7 tokens + 4 senhas conhecidas -> hex->dec (0..15) / digitos decimais do inteiro / so' digitos 0-9 do hex
PW_KNOWN = ["theflowerblossomsthroughwhatseemstobeaconcretesurface", "causality",
            "causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
            "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"]
HEXES = [G.shahex(t) for t in list(G.TOKENS.values()) + PW_KNOWN]
KEYS["sha_tokens:hexdec"] = ext([int(c, 16) for c in "".join(HEXES)])
KEYS["sha_tokens:decdigits"] = ext([int(c) for c in "".join(str(int(h, 16)) for h in HEXES)])
KEYS["sha_tokens:hexonlydigits"] = ext([int(c) for c in "".join(HEXES) if c.isdigit()])
URL = G.shahex("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
KEYS["url:hexdec"] = ext([int(c, 16) for c in URL])
KEYS["url:onlydigits"] = ext([int(c) for c in URL if c.isdigit()])
KEYS["url:decdigits"] = ext([int(c) for c in str(int(URL, 16))])
# constantes: pi, e, sqrt2 (800 digitos) — cru, 0->9, 0 removido
mpmath.mp.dps = 820
for nm, v in (("pi", mpmath.pi), ("e", mpmath.e), ("sqrt2", mpmath.sqrt(2))):
    ds = [int(c) for c in mpmath.nstr(v, 810).replace(".", "")[:800]]
    KEYS[f"{nm}:raw"] = ds[:601]
    KEYS[f"{nm}:0to9"] = [9 if d == 0 else d for d in ds][:601]
    KEYS[f"{nm}:no0"] = [d for d in ds if d][:601]
# matriz README (101 uns): bits em espiral e row-major, repetidos
M = G.MATRIX_README
sp_bits = [M[r][c] for (r, c) in G.SPIRAL] if isinstance(G.SPIRAL[0], (tuple, list)) else None
if sp_bits is None:
    sp_bits = [M[i // 14][i % 14] for i in G.SPIRAL]
KEYS["matrix:spiral"] = ext(sp_bits)
KEYS["matrix:rowmajor"] = ext([M[r][c] for r in range(14) for c in range(14)])
# binarios abba de matrixsumlist / enter como 0/1
def abba(word): return [int(b) for ch in word for b in format(ord(ch), "08b")]
KEYS["bin:matrixsumlist"] = ext(abba("matrixsumlist"))
KEYS["bin:enter"] = ext(abba("enter"))
KEYS["bin:both"] = ext(abba("matrixsumlist") + abba("enter"))
# digitos da 3.2.2 (151) e do dbbi+faed como decimal
KEYS["p322digits"] = ext([int(c) for c in P322_DIGITS])
# faed com lag (autokey de ciphertext): rotacoes base 0/285/540 (+ alinhamento 0..30 cobre 1..30, 285..315, 540..570)
FD = G.digits(G.FAED)
for L in (0, 285, 540):
    KEYS[f"faedlag{L}"] = ext(FD[L:] + FD[:L])
KEYS["faedrev"] = ext(FD[::-1])
# CT dos blobs e base64 (indices) como running key
B64A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
KEYS["cosmic:ctbytes"] = ext(list(G.BLOBS["COSMIC"][1]))
KEYS["cosmic:b64idx"] = ext([B64A.index(c) for c in G.COSMIC_B64 if c in B64A]) if hasattr(G, "COSMIC_B64") else ext([B64A.index(c) for c in G.SMALL_B64])
KEYS["small+tail:ctbytes"] = ext(list(G.BLOBS["SMALL"][1] + G.BLOBS["TAIL32"][1]))
KEYS["pubkey:hexdec"] = ext([int(c, 16) for c in G.TARGET_PUBKEY_HEX])
KEYS["p2blob:b64idx"] = ext([B64A.index(c) for c in G.PHASE2_B64 if c in B64A])
KEYS["p32blob:b64idx"] = ext([B64A.index(c) for c in G.PHASE32_B64 if c in B64A])
KEYS["arch321+p322:a1z26"] = ext(letters(TXT["arch321"] + TXT["p322"]))
KEYS["p322x6+dbbi"] = ext(letters(TXT["p322"]) * 6 + DB)
for k in KEYS: assert len(KEYS[k]) >= 570 + MAXALIGN + 1, k
print("chaves correntes:", len(KEYS))
log({"event": "keys", "n": len(KEYS), "names": sorted(KEYS)})

# ------------------------------------------------------------------ configs / modos
CONFIGS = {
    "m9":    dict(n=9,  c=np.array([d - 1 for d in FD]),                 uni="123456789",  back=lambda p: p + 1),
    "m10a":  dict(n=10, c=np.array(FD),                                  uni="0123456789", back=lambda p: p),
    "m10i0": dict(n=10, c=np.array([0 if d == 9 else d for d in FD]),    uni="0123456789", back=lambda p: p),
    "m10a0": dict(n=10, c=np.array([d - 1 for d in FD]),                 uni="0123456789", back=lambda p: p),
}
def rekey(c, k, mode, n):
    if mode == "add": return (c - k) % n
    if mode == "sub": return (c + k) % n
    return (k - c) % n            # beaufort

# ------------------------------------------------------------------ gate: H_cond e IoC de digrafos vs embaralhados
def bigram_stats(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).astype(float)
    Mn = bg.sum()
    ioc = (bg * (bg - 1)).sum() / (Mn * (Mn - 1))
    rows = bg.reshape(n, n).sum(1, keepdims=True)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(bg.reshape(n, n) > 0, bg.reshape(n, n) * np.log2(bg.reshape(n, n) / rows), 0.0)
    return -t.sum() / Mn, ioc
def gate_z(a, n, nshuf=NSHUF):
    """Devolve (zH, zIoC, H, ioc). z contra nshuf embaralhados do proprio stream (mesmo unigrama)."""
    if len(np.unique(a)) < 2: return 0.0, 0.0, 0.0, 0.0
    H, I = bigram_stats(a, n)
    nul = np.array([bigram_stats(rng.permutation(a), n) for _ in range(nshuf)])
    sdH = nul[:, 0].std() or 1e-9; sdI = nul[:, 1].std() or 1e-9
    return float((H - nul[:, 0].mean()) / sdH), float((I - nul[:, 1].mean()) / sdI), float(H), float(I)

# ------------------------------------------------------------------ decoders dos aprovados
AL322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PHRASES = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "shabef", "sha256",
           "ourfirsthintisyourlastcommand", "anstoo", "yellowblueprimes", "salphaseion", "cosmicduality",
           "yinyang", "hashthetext", "thematrixhasyou", "followthewhiterabbit", "halfandbetterhalf",
           "causality", "jacquefresco", "theseedisplanted", "gsmg"]
ALPH9 = {"CANON": G.CANON, "al322_25": AL322.replace(".", "")[:25]}
ALPH10 = {"al322": AL322, "CANON+J..": G.CANON + "J.."}
for p in PHRASES:
    ALPH9[f"kw:{p}"] = G.keyed_alphabet(p)
    ALPH10[f"kw26:{p}"] = G.keyed_alphabet(p, base=AZ, merge_j=False) + ".."
ESC9 = [(a, b) for a in range(1, 10) for b in range(1, 10) if a != b]
ESC10 = [(a, b) for a in range(10) for b in range(10) if a != b]
BEST = {"score": -99.0, "text": "", "how": ""}
def oracle_text(pt, how):
    for pw in {pt, pt.lower(), G.shahex(pt), G.shahex(pt.lower())}:
        try_pw(pw, how)
    for k in (G.sha(pt.encode()), G.sha(pt.lower().encode())):
        try_priv(k, how)
def decode_stream(seq, cfg, how):
    n = cfg["n"]; digs = [int(cfg["back"](p)) for p in seq]
    alphs, escs, uni = (ALPH9, ESC9, "123456789") if n == 9 else (ALPH10, ESC10, "0123456789")
    sem = []
    for an, al in alphs.items():
        for e in escs:
            N["decode_cb"] += 1
            pt = G.checkerboard_decode(digs, al, e, uni)
            sc = G.english_score(pt)
            if sc > BEST["score"]: BEST.update(score=round(sc, 3), text=pt[:120], how=f"{how}|{an}|esc{e}")
            if G.semantic_text(pt):
                sem.append((sc, an, e, pt)); oracle_text(pt, f"{how}|{an}|esc{e}")
    # Bifid CANON (so' faz sentido em universo 1-9 -> letras a-i)
    if n == 9:
        s = "".join("abcdefghi"[d - 1] for d in digs)
        for per in (570, 285, None):
            N["decode_bifid"] += 1
            bt = G.bifid(s, G.CANON, per)
            sc = G.english_score(bt)
            if sc > BEST["score"]: BEST.update(score=round(sc, 3), text=bt[:120], how=f"{how}|bifidCANON{per}")
            if G.semantic_text(bt): oracle_text(bt, f"{how}|bifidCANON{per}")
        try_pw(s, how + "|raw"); try_pw(G.shahex(s), how + "|sha")
    # z-method (digitos -> decimal -> hex -> bytes)
    N["decode_z"] += 1
    try:
        zb = G.z_method(digs)
        for h in G.fast_priv_scan(zb, how + "|zmethod"): HARD.append({"how": h[0], "where": h[1], "priv_hex": h[2]}); log({"kind": "HARD", "how": h})
        if G.printable(zb) >= 0.85: log({"kind": "soft_z", "how": how, "head": zb[:60].decode("latin-1")})
    except Exception:
        pass
    for sc, an, e, pt in sorted(sem, reverse=True)[:5]:
        log({"event": "semantic_cand", "how": f"{how}|{an}|esc{e}", "score": round(sc, 3), "head": pt[:100]})

# ------------------------------------------------------------------ varredura (mesma funcao serve ao faed real e ao nulo casado)
def sweep(cbase_by_cfg, tag, decode):
    """cbase_by_cfg: {cfg_name: np.array}. Devolve lista de (absz, zH, zI, how) e contagens."""
    res = []; n_streams = 0; passers = []
    for cn, cfg in CONFIGS.items():
        n = cfg["n"]; c = cbase_by_cfg[cn]
        for kname, kraw in KEYS.items():
            k = np.array(kraw) % n
            for al in range(MAXALIGN + 1):
                kk = k[al:al + 570]
                if len(np.unique(kk)) < 2: continue
                for mode in ("add", "sub", "beau"):
                    n_streams += 1
                    seq = rekey(c, kk, mode, n)
                    zH, zI, H, I = gate_z(seq, n)
                    az = max(abs(zH), abs(zI))
                    how = f"{tag}|{cn}|{kname}|al{al}|{mode}"
                    res.append((az, zH, zI, how))
                    if az >= ZGATE:
                        passers.append((az, seq, cfg, how))
                        log({"event": "gate_pass", "how": how, "zH": round(zH, 2), "zI": round(zI, 2), "H": round(H, 4), "ioc": round(I, 5)})
        print(f"  {tag} {cn}: streams={n_streams} pass={len(passers)} t={round(time.time() - T0)}s", flush=True)
    if decode:
        for az, seq, cfg, how in sorted(passers, key=lambda t: -t[0]):
            decode_stream(seq, cfg, how)
    res.sort(key=lambda t: -t[0])
    return res, n_streams, passers

# ------------------------------------------------------------------ CONTROLE POSITIVO: ingles via checkerboard 3.2.2 + running key = digitos de pi
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
            "ITS ENTIRE EXISTENCE ERADICATED THE FUNCTION OF THE ONE IS NOW TO RETURN TO THE SOURCE "
            "THE MATRIX IS OLDER THAN YOU KNOW I PREFER COUNTING FROM THE EMERGENCE OF ONE INTEGRAL ANOMALY")
ctrl_p = np.array(cb_encode(CTRL_TXT, AL322, (1, 4), "0123456789")[:570])
assert len(ctrl_p) == 570
kpi = np.array(KEYS["pi:raw"][:570]) % 10
ctrl_c = (ctrl_p + kpi) % 10                         # Vigenere add mod 10 com running key = pi
zc = gate_z(ctrl_c, 10)                             # cifra crua: deve ser ~0
zok = gate_z(rekey(ctrl_c, kpi, "add", 10), 10)     # chave certa
zwrong = [gate_z(rekey(ctrl_c, np.array(KEYS["pi:raw"][al:al + 570]) % 10, "add", 10), 10)[:2] for al in (1, 2, 3, 7)]
zwrongkey = [gate_z(rekey(ctrl_c, np.array(KEYS[k][:570]) % 10, "add", 10), 10)[:2] for k in ("e:raw", "arch321:a1z26", "dbbi:id")]
ctrl_pt = G.checkerboard_decode([int(x) for x in rekey(ctrl_c, kpi, "add", 10)], AL322, (1, 4), "0123456789")
ctrl_ok = max(abs(zok[0]), abs(zok[1])) >= ZGATE and ctrl_pt.startswith("THEARCHITECTSAID") and G.semantic_text(ctrl_pt) \
          and all(max(abs(a), abs(b)) < ZGATE for a, b in zwrong + zwrongkey)
ctrl = {"event": "control", "cipher_raw_z": [round(x, 2) for x in zc[:2]], "right_key_z": [round(x, 2) for x in zok[:2]],
        "wrong_align_z": [[round(a, 2), round(b, 2)] for a, b in zwrong], "wrong_key_z": [[round(a, 2), round(b, 2)] for a, b in zwrongkey],
        "decoded_head": ctrl_pt[:40], "control_ok": bool(ctrl_ok)}
log(ctrl); print("CONTROLE:", ctrl)
assert ctrl_ok
# controle 2: a varredura completa recupera a chave certa quando o "faed" e' o controle cifrado (config m10a)
ctrl_cfg = {cn: ctrl_c.copy() for cn in CONFIGS}     # ponytail: mesmo stream em todas as configs; so' m10a e' a certa
# ------------------------------------------------------------------ RUN: faed real
print("== faed real ==", flush=True)
res_real, n_real, pass_real = sweep({cn: cfg["c"] for cn, cfg in CONFIGS.items()}, "faed", decode=True)
top_real = [(round(a, 2), round(zh, 2), round(zi, 2), h) for a, zh, zi, h in res_real[:15]]
log({"event": "real_top", "n_streams": n_real, "n_pass": len(pass_real), "top": top_real})
print("faed: streams", n_real, "passaram", len(pass_real), "top:", top_real[:5], flush=True)

# ------------------------------------------------------------------ nulo casado: mesmo pipeline sobre 2 faed embaralhados (preserva unigrama)
null_max = []
for s in range(2):
    perm = rng.permutation(570)
    res_n, n_n, pass_n = sweep({cn: cfg["c"][perm] for cn, cfg in CONFIGS.items()}, f"null{s}", decode=False)
    null_max.append(round(res_n[0][0], 2))
    log({"event": "null_top", "shuffle": s, "n_streams": n_n, "n_pass": len(pass_n), "top": [(round(a, 2), h) for a, _, _, h in res_n[:5]]})
    print(f"null{s}: max|z|={res_n[0][0]:.2f} pass={len(pass_n)}", flush=True)

# ------------------------------------------------------------------ controle 3: varredura cega recupera pi/al0/add no controle?
res_c, n_c, pass_c = sweep(ctrl_cfg, "ctrl", decode=False)
ctrl_rank = next((i for i, r in enumerate(res_c) if "|m10a|pi:raw|al0|add" in r[3]), None)
log({"event": "control_sweep", "n_streams": n_c, "n_pass": len(pass_c), "rank_of_true_key": ctrl_rank,
     "top": [(round(a, 2), h) for a, _, _, h in res_c[:5]]})
print("controle-varredura: rank da chave certa =", ctrl_rank, "pass =", len(pass_c), "top:", res_c[0][3], round(res_c[0][0], 2))

summary = {"family": "running_key_gate", "n_keys": len(KEYS), "n_streams_real": n_real, "n_pass_real": len(pass_real),
           "max_absz_real": top_real[0][0], "null_max_absz": null_max, "control": ctrl,
           "control_sweep_rank": ctrl_rank, "control_sweep_pass": len(pass_c),
           "counts": dict(N), "n_tests": n_real + sum(N.values()),
           "hard": HARD, "soft": SOFT[:20], "n_soft": len(SOFT), "best_readable": BEST, "top_real": top_real,
           "secs": round(time.time() - T0)}
log({"event": "summary", **summary})
json.dump(summary, open(os.path.join(SP, "running_key_gate_summary.json"), "w"), indent=1)
print(json.dumps({k: v for k, v in summary.items() if k not in ("soft",)}, indent=1)[:3000])
