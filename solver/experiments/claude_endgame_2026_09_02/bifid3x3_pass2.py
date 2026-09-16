# -*- coding: utf-8 -*-
"""
PASSE 2 da familia bifid3x3_exhaustive — oraculo DURO exaustivo, sem porta estatistica.

Motivo: o controle do passe 1 mostrou que a triagem estatistica NAO isola o quadrado certo
(o texto plantado ficou em rank 1834 no funil; decoys chegam a z_Hcond=-19). Logo, em vez de
confiar no ranking, aplico os oraculos BARATOS a TODAS as 60480 classes x (periodo, modo):

  out (string a-i)  ->  (1) senha crua e sha256hex(out) nos 3 blobs (EVP-SHA256, aes-256-cbc)
                        (2) sha256(out) e sha256(out.upper()) como privkey (coincurve)
                        (3) z-method (digitos -> decimal -> hex -> bytes) -> printable/WIF/hex64

Truque de custo: para testar padding PKCS7 basta decifrar o ULTIMO bloco CBC
(P_last = D(C_last) xor C_prev) — 1 AES-ECB em vez de 5/83 blocos. So se o padding fecha e' que
se faz a decifracao completa.
"""
import sys, os, json, time, itertools, hashlib, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from coincurve import PublicKey

SP = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(SP, "bifid3x3_exhaustive.jsonl")
def log(o): G.jsonl(LOG, o)
T0 = time.time()

# ------------------------------------------------------------ blobs: ultimo bloco
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
    p = pt[-1]
    return 1 <= p <= 16 and pt.endswith(bytes([p]) * p)

HARD, SOFT = [], []
N_ORACLE = 0
def try_pw(pw, how):
    """1 AES-ECB por blob (teste de padding); decifra tudo so' se fechar."""
    global N_ORACLE
    for name, (salt, ct, cprev, clast) in BL.items():
        N_ORACLE += 1
        k, iv = evp_key(pw, salt)
        blk = AES.new(k, AES.MODE_ECB).decrypt(clast)
        last = bytes(a ^ b for a, b in zip(blk, cprev))
        if not pad_ok(last): continue
        full = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
        pt = G.unpad(full)
        if pt is None: continue
        rec = {"how": how, "blob": name, "kdf": "EVP-SHA256", "pw": pw.decode("latin-1"),
               "len": len(pt), "printable": round(G.printable(pt), 3),
               "head": pt[:48].decode("latin-1")}
        if G.semantic(pt):
            rec["plaintext_hex"] = pt.hex(); HARD.append(rec); log({"kind": "HARD", **rec})
        else:
            SOFT.append(rec); log({"kind": "soft_pad", **rec})

def try_priv(sec, how):
    global N_ORACLE
    N_ORACLE += 1
    try:
        if PublicKey.from_valid_secret(sec).format(False) == TGT:
            HARD.append({"how": how, "priv_hex": sec.hex()}); log({"kind": "HARD", "how": how, "priv_hex": sec.hex()})
    except Exception:
        pass

HEX64 = G.HEX64_RE
def try_zmethod(out, how):
    global N_ORACLE
    N_ORACLE += 1
    n = int(out.translate(D2))            # a=1..i=9 -> decimal
    h = format(n, "x")
    if len(h) % 2: h = "0" + h
    b = bytes.fromhex(h)
    pr = G.printable(b)
    if pr >= 0.85:
        t = b.decode("latin-1")
        SOFT.append({"how": how + "|z", "printable": round(pr, 3), "head": t[:60]})
        log({"kind": "soft_z", "how": how, "printable": round(pr, 3), "text": t[:200]})
        if G.semantic_text(t):
            HARD.append({"how": how + "|z-semantic", "text": t[:400]}); log({"kind": "HARD_TEXT", "how": how, "text": t[:400]})
    t = b.decode("latin-1")
    for hx in G.hex64_candidates(t):
        try_priv(bytes.fromhex(hx), how + "|z-hex64")
    for w in G.wif_candidates(t):
        try:
            import base58; try_priv(base58.b58decode_check(w)[1:33], how + "|z-wif")
        except Exception: pass

D2 = str.maketrans("abcdefghi", "123456789")

# ------------------------------------------------------------ bifid vetorizado (mesmo do passe 1)
PERMS = np.array(list(itertools.permutations(range(9))), dtype=np.int8)
def code(P): return (P.astype(np.int64) * (9 ** np.arange(8, -1, -1))).sum(1)
own = code(PERMS); best = own.copy()
for pi in itertools.permutations(range(3)):
    pi = np.array(pi); r, c = PERMS // 3, PERMS % 3
    best = np.minimum(best, code((3 * pi[r] + pi[c]).astype(np.int8)))
CLASSES = PERMS[own == best]
assert len(CLASSES) == 60480
del PERMS, own, best

def bifid_index(n, p, mode):
    ir = np.empty(n, np.int64); ic = np.empty(n, np.int64)
    for o in range(0, n, p):
        L = min(p, n - o)
        if mode == "decrypt":
            seq = [(o + k // 2) + (n if k % 2 else 0) for k in range(2 * L)]
            for i in range(L): ir[o + i] = seq[i]; ic[o + i] = seq[L + i]
        else:
            seq = [o + k for k in range(L)] + [n + o + k for k in range(L)]
            for i in range(L): ir[o + i] = seq[2 * i]; ic[o + i] = seq[2 * i + 1]
    return ir, ic
def bifid_all(t, P, ir, ic):
    cell = P[:, t]
    RC = np.concatenate([cell // 3, cell % 3], axis=1)
    oc = (3 * RC[:, ir] + RC[:, ic]).astype(np.int64)
    inv = np.argsort(P, axis=1).astype(np.int8)
    return np.take_along_axis(inv, oc, axis=1)
def sym2arr(s): return np.array([ord(c) - 97 for c in s], np.int8)

# controle positivo: reproduz G.bifid e reencontra uma senha plantada
rng = np.random.default_rng(7)
P = rng.permutation(9).astype(np.int8)
alpha = "".join(chr(97 + int(np.where(P == k)[0][0])) for k in range(9))
ir, ic = bifid_index(570, 30, "decrypt")
v = "".join(chr(97 + int(x)) for x in bifid_all(sym2arr(G.FAED), P[None], ir, ic)[0])
assert v == G.bifid(G.FAED, alpha, 30, 3, "decrypt")
_h = []
def _ctl():
    """Controle do oraculo: cifro um blob com sha256hex(v) e confirmo que try_pw acha."""
    import base64
    pw = G.shahex(v).encode(); salt = os.urandom(8); k, iv = evp_key(pw, salt)
    msg = b"CONTROL PLAINTEXT the private key is deadbeef"
    padn = 16 - len(msg) % 16; msg += bytes([padn]) * padn
    ct = AES.new(k, AES.MODE_CBC, iv).encrypt(msg)
    BL["CTRL"] = (salt, ct, ct[-32:-16], ct[-16:])
    n0 = len(HARD); try_pw(pw, "ctrl"); assert len(HARD) == n0 + 1, HARD[n0:]
    del BL["CTRL"]; HARD.pop()
    # controle do oraculo de privkey
    sec = hashlib.sha256(b"ctrl-seed").digest()
    global TGT
    old = TGT; TGT = PublicKey.from_valid_secret(sec).format(False)
    n0 = len(HARD); try_priv(sec, "ctrl_priv"); assert len(HARD) == n0 + 1
    TGT = old; HARD.pop()
_ctl()
print("controles do oraculo OK", flush=True)

PERIODS = {"faed": [570, 285, 190, 114, 95, 57, 38, 30, 19, 15, 10, 6, 5, 3, 2], "dbbi": [91, 13, 7]}
N_OUT = 0
BENCH = "--bench" in sys.argv
for label, txt in (("dbbi", G.DBBI), ("faed", G.FAED)):
    t = sym2arr(txt); n = len(t)
    for p in PERIODS[label]:
        for mode in ("decrypt", "encrypt"):
            ir, ic = bifid_index(n, p, mode)
            t1 = time.time()
            for a in range(0, len(CLASSES), 4032):
                sub = CLASSES[a:a + 4032]
                out = bifid_all(t, sub, ir, ic)
                arr = (out + 97).astype(np.uint8)
                for j in range(len(sub)):
                    s = arr[j].tobytes().decode("ascii")
                    how = f"{label} p={p} {mode} sq={''.join(chr(97+int(x)) for x in np.argsort(sub[j]))}"
                    N_OUT += 1
                    try_pw(s.encode(), how + "|raw")
                    try_pw(G.shahex(s).encode(), how + "|sha256hex")
                    try_priv(G.sha(s), how + "|sha256->priv")
                    try_priv(G.sha(s.upper()), how + "|sha256(upper)->priv")
                    try_zmethod(s, how)
                del out, arr
                if BENCH: break
            print(f"  {label} p={p} {mode}: {N_OUT} outs, {N_ORACLE} oraculos, {round(time.time()-t1,1)}s (tot {round(time.time()-T0)}s)", flush=True)
            if BENCH: break
        if BENCH: break
    if BENCH: break

summary = {"kind": "summary_pass2", "n_outputs": N_OUT, "n_oracle_calls": N_ORACLE,
           "n_hard": len(HARD), "hard": HARD, "n_soft": len(SOFT), "soft_sample": SOFT[:30],
           "elapsed_s": round(time.time() - T0)}
log(summary)
json.dump(summary, open(os.path.join(SP, "bifid3x3_pass2_summary.json"), "w"), indent=1)
print(json.dumps({k: summary[k] for k in ("n_outputs", "n_oracle_calls", "n_hard", "n_soft", "elapsed_s")}))
print("HARD:", HARD[:5])
