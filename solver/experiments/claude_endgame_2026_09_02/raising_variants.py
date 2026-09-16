# -*- coding: utf-8 -*-
"""Parágrafo 'Raising the stakes…' (antes do TAIL32) em variantes de whitespace, entidades HTML,
quebras de linha, pontuação, caixa e fatias por sentença/segmento, como senha dos 3 blobs
(oráculo rápido de padding, EVP-SHA256) e como privkey via sha256. Lead do tail32_history."""
import sys, os, re, hashlib, itertools
SCR = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, SCR)
import gsmg_common as G
from Crypto.Cipher import AES
from coincurve import PublicKey
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
BL = {n: (s, c, c[-32:-16], c[-16:]) for n, (s, c) in G.BLOBS.items()}
def evp_key(pw, salt):
    d = b""; prev = b""
    while len(d) < 48: prev = hashlib.sha256(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]
N = 0; HARD = []; SOFT = 0; SEEN = set()
def try_pw(pw, how):
    global N, SOFT
    if isinstance(pw, str): pw = pw.encode("utf-8")
    if pw in SEEN: return
    SEEN.add(pw)
    for name, (salt, ct, cprev, clast) in BL.items():
        N += 1; k, iv = evp_key(pw, salt)
        last = bytes(a ^ b for a, b in zip(AES.new(k, AES.MODE_ECB).decrypt(clast), cprev))
        p = last[-1]
        if not (1 <= p <= 16 and last.endswith(bytes([p]) * p)): continue
        pt = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        if pt is None: continue
        if G.semantic(pt): HARD.append({"how": how, "blob": name, "pw": pw.decode("latin-1"), "pt": pt.hex()}); print("### HARD", HARD[-1])
        else: SOFT += 1
    N += 1
    try:
        if PublicKey.from_valid_secret(hashlib.sha256(pw).digest()).format(False) == TGT:
            HARD.append({"how": how, "priv": hashlib.sha256(pw).hexdigest()}); print("### HARD", HARD[-1])
    except Exception as e:
        print("coincurve:", e)

P = "Raising the stakes without extra chances of winning. A fubcd-king & oracle-queen, thingky mvps, on a sad board but as wide as the first one seen."
S1, S2 = P.split(". ")[0] + ".", P.split(". ")[1]
segs = [P, S1, S2, S2.rstrip("."), "A fubcd-king & oracle-queen", "thingky mvps", "on a sad board but as wide as the first one seen",
        "fubcd-king", "oracle-queen", "fubcd-king & oracle-queen, thingky mvps", "as wide as the first one seen", "the first one seen",
        "Raising the stakes without extra chances of winning", "Raising the stakes", "without extra chances of winning", "extra chances of winning"]
def variants(t):
    out = {t, t.strip(), t + "\n", t + "\r\n", t + " ", " " + t, "\n" + t, t.replace("&", "&amp;"), t.replace("&", "and"), t.replace(" & ", " and "),
           t.replace(". ", ".\n"), t.replace(". ", ".\r\n"), t.replace(". ", ".  "), t.replace(", ", ",\n"), t.replace(" ", ""), t.replace(" ", "_"),
           re.sub(r"[^A-Za-z0-9]", "", t), re.sub(r"[^A-Za-z0-9 ]", "", t), re.sub(r"[^A-Za-z]", "", t), t.lower(), t.upper(),
           re.sub(r"[^A-Za-z0-9]", "", t).lower(), re.sub(r"[^A-Za-z0-9]", "", t).upper(), t.replace("-", " "), t.replace("-", ""),
           t.replace("-", "").replace("&", "").replace(",", "").replace(".", ""), re.sub(r"\s+", " ", t), t.replace(" ", "\t"),
           "<p>" + t + "</p>", t + "<br>", t.encode("utf-8").decode("latin-1")}
    return [x for x in out if x]
n_forms = 0
for seg in segs:
    for v in variants(seg):
        h = G.shahex(v)
        for f in (v, h, h.upper(), G.shahex(h), hashlib.sha256(v.encode()).digest(), v.encode("utf-16-le")):
            try_pw(f, seg[:30]); n_forms += 1
# concatenações com a gramática da 3.2 e os tokens do endgame
for a, b in itertools.product(["jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple", "THEMATRIXHASYOU", "giveit", "salphaseion", "cosmicduality", "yinyang", "halfandbetterhalf"],
                              [re.sub(r"[^A-Za-z0-9]", "", S2), re.sub(r"[^A-Za-z0-9]", "", P), re.sub(r"[^A-Za-z]", "", S2).lower()]):
    for f in (a + b, b + a, G.shahex(a + b), G.shahex(b + a)): try_pw(f, "concat"); n_forms += 1
print({"formas": n_forms, "n_oracle": N, "soft_pads": SOFT, "hard": HARD})
