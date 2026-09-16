# -*- coding: utf-8 -*-
"""
FAMILIA polybius_pairs — pares de simbolos a-i como coordenadas num quadrado 9x9 (81 celulas),
triplas/trits num cubo 3x3x3 (27 celulas), T9 multi-tap, e leituras numericas de pares.
Hipotese: alguma leitura direta (sem cifra de chave) de faed/dbbi produz texto/senha/chave.
"""
import sys, os, re, string, hashlib, itertools, json, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = os.path.join(SP, "polybius_pairs.jsonl")
open(LOG, "w").close()
G.jsonl(LOG, {"family": "polybius_pairs", "hypothesis":
    "pares a-i = coordenadas Polybius 9x9 (81 simbolos: ASCII/A-Za-z0-9+punct/base58, keyed por frases); "
    "trits (div3,mod3) em triplas = cubo 3x3x3 (27 = A-Z+espaco); T9 multi-tap; leituras numericas de pares. "
    "Alguma leitura direta de faed/dbbi/metades/pareamento(i,i+285) da ingles, WIF/hex64 ou senha dos blobs."})

# ------------------------------------------------------------------ fontes
FAED, DBBI = G.FAED, G.DBBI
H1, H2 = FAED[:285], FAED[285:]
PAIRED = "".join(FAED[i] + FAED[i + 285] for i in range(285))       # (i, i+285)
PAIRED_R = "".join(FAED[i + 285] + FAED[i] for i in range(285))     # (i+285, i)
SOURCES = {"faed": FAED, "faed_np": FAED[4:], "dbbi": DBBI, "h1": H1, "h2": H2,
           "paired": PAIRED, "paired_r": PAIRED_R, "dbbi_faed": DBBI + FAED}
def d0(s): return [ord(c) - 97 for c in s]

# ------------------------------------------------------------------ alfabetos
PUNCT = ".,;:!?'\"-_ /()[]{}+"           # 19 -> 62+19 = 81
U = {
    "ULD": string.ascii_uppercase + string.ascii_lowercase + string.digits + PUNCT,
    "LUD": string.ascii_lowercase + string.ascii_uppercase + string.digits + PUNCT,
    "DUL": string.digits + string.ascii_uppercase + string.ascii_lowercase + PUNCT,
    "B58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" + PUNCT + "0OIl",
}
for k, v in U.items(): assert len(v) == 81 and len(set(v)) == 81, k
PHRASES = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "sha256", "shabef",
           "ourfirsthintisyourlastcommand", "anstoo", "salphaseion", "cosmicduality", "salvation", "yinyang",
           "yellowblueprimes", "theseedisplanted", "theflowerblossomsthroughwhatseemstobeaconcretesurface",
           "causality", "safenetlunahsm", "thematrixhasyou", "jacquefresco", "giveit", "justonesecond",
           "heisenbergsuncertaintyprinciple", "halfandbetterhalf", "fubcdoralethingkymvpsjqzxw", "gsmg",
           "globallysupportingmygeneration", "purplepill", "lifeanddeath", "lemiroirdelavieetdelamort",
           "killprocess", "primebasics", "returntothesource", "architect", "neo", "morpheus", "trinity", "zion",
           "rabbitsnest", "rosesarewhite", "hushhush", "bingo", "dbbi", "faed", "gsmgio5btcpuzzlechallenge",
           "privatekey", "bitcoin", "genesis", "cypher", "oracle", "keymaker", "wonderland", "alice", "whiterabbit"]
def keyed(phrase, base):
    seen = []
    for c in phrase:
        if c in base and c not in seen: seen.append(c)
    return "".join(seen) + "".join(c for c in base if c not in seen)
ALPHA81 = {}
for nm, base in U.items():
    ALPHA81[nm] = base
    for p in PHRASES:
        for form in {p, p.upper(), p.capitalize()}:
            ALPHA81[f"{nm}|{form}"] = keyed(form, base)
A27 = string.ascii_uppercase + " "
ALPHA27 = {"AZ_": A27, "_AZ": " " + string.ascii_uppercase}
for p in PHRASES:
    ALPHA27["AZ_|" + p] = keyed(p.upper(), A27)
    ALPHA27["_AZ|" + p] = keyed(p.upper(), " " + string.ascii_uppercase)

# ------------------------------------------------------------------ detectores
B58RUN = re.compile(r"[1-9A-HJ-NP-Za-km-z]{50,}")
from coincurve import PrivateKey
TARGET_PUB = bytes.fromhex(G.TARGET_PUBKEY_HEX)
ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def fast_scan(buf, target=TARGET_PUB):
    """Janela deslizante de 32B -> pubkey via coincurve == pubkey do premio (oraculo duro, ~80us/op)."""
    hits = []
    for j in range(0, len(buf) - 31):
        k = buf[j:j + 32]; n = int.from_bytes(k, "big")
        if n == 0 or n >= ORDER_N: continue
        if PrivateKey(k).public_key.format(compressed=False) == target:
            r = G.priv_hit(k); hits.append(("fast", f"priv@{j}", r or k.hex()))
    t = buf.decode("latin-1")
    for m in G.HEX64_RE.finditer(t):
        k = bytes.fromhex(m.group())
        if 0 < int.from_bytes(k, "big") < ORDER_N and PrivateKey(k).public_key.format(compressed=False) == target:
            hits.append(("fast", f"hex@{m.start()}", k.hex()))
    for m in G.WIF_RE.finditer(t):
        try:
            import base58; raw = base58.b58decode_check(m.group()); r = G.priv_hit(raw[1:33])
            if r: hits.append(("fast", f"wif@{m.start()}", r))
        except Exception: pass
    return hits
# controle: chave plantada
import os as _os
_k = _os.urandom(32); _pub = PrivateKey(_k).public_key.format(compressed=False)
assert fast_scan(b"xx" + _k + b"yy", _pub)[0][1] == "priv@2"
assert fast_scan(_os.urandom(200), _pub) == []
N = 0; HARD = []; SOFT = []; BEST = []
def check(name, out, bytes_out=None):
    """out: str. Oraculos duros + triagem. Conta 1 teste."""
    global N
    N += 1
    t = out if isinstance(out, str) else out.decode("latin-1")
    b = bytes_out if bytes_out is not None else t.encode("latin-1", "replace")
    sc = G.english_score(t) if sum(c.isalpha() for c in t) >= 20 else -99.0
    rec = {"name": name, "score": round(sc, 3), "printable": round(G.printable(b), 3), "head": t[:60]}
    # 1) privkey embutida / hash do texto
    hits = fast_scan(b)
    for form in (t.encode("latin-1", "replace"), t.strip().encode("latin-1", "replace")):
        for k in (G.sha(form), G.sha(G.sha(form))):
            r = G.priv_hit(k)
            if r: hits.append((name, "sha256(text)", r, form.hex()))
    if hits:
        rec["priv_hits"] = [str(h) for h in hits]; HARD.append(rec); G.jsonl(LOG, {"HARD": rec}); print("HARD", rec)
    # 2) texto e sha256(texto) como senha nos 3 blobs
    for pw in (t, G.shahex(t), G.shahex(t.strip())):
        hard, soft = G.try_password_all(pw)
        if hard:
            rec2 = dict(rec, pw=pw, aes=hard); HARD.append(rec2); G.jsonl(LOG, {"HARD": rec2}); print("HARD", rec2)
        for s in soft:
            SOFT.append(dict(name=name, pw=pw[:80], **s))
    # 3) WIF / hex64 / base58-run
    for rg, lab in ((G.WIF_RE, "wif"), (G.HEX64_RE, "hex64"), (B58RUN, "b58run")):
        m = rg.search(t)
        if m: rec.setdefault("regex", []).append((lab, m.group()[:70]))
    # 4) legibilidade
    if sc > -6.0:
        rec["words"] = G.word_hits(t)[:8]
    BEST.append((sc, rec))
    if sc > -5.0 or "regex" in rec: G.jsonl(LOG, rec)
    return rec

# ------------------------------------------------------------------ decoders
def pairs_idx(s, order):
    d = d0(s); return [9 * d[i] + d[i + 1] if order == "rm" else d[i] + 9 * d[i + 1] for i in range(0, len(d) - 1, 2)]
def trits(s, mode):
    out = []
    for x in d0(s):
        out += [x // 3, x % 3] if mode == "dm" else [x % 3, x // 3]
    return out
def t9_multitap(digs, sep=None):
    keys = {1: ".,?!'\"-", 2: "ABC", 3: "DEF", 4: "GHI", 5: "JKL", 6: "MNO", 7: "PQRS", 8: "TUV", 9: "WXYZ"}
    out = []; i = 0
    while i < len(digs):
        d = digs[i]
        if d == sep: i += 1; out.append(" "); continue
        j = i
        while j < len(digs) and digs[j] == d and (sep is None or digs[j] != sep): j += 1
        run = j - i; k = keys[d]; out.append(k[(run - 1) % len(k)]); i = j
    return "".join(out)
def a1z26_greedy(digs, offset=0):
    """digitos 1-9 -> parse ganancioso em 1..26 (2 digitos se <=26 senao 1)."""
    out = []; i = 0
    while i < len(digs):
        if i + 1 < len(digs) and 10 <= digs[i] * 10 + digs[i + 1] <= 26:
            out.append(chr(64 + digs[i] * 10 + digs[i + 1])); i += 2
        else:
            out.append(chr(64 + digs[i])); i += 1
    return "".join(out)

# ------------------------------------------------------------------ controle positivo
def _control():
    msg = "IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF"
    alpha = ALPHA81["ULD|thispassword"]
    enc = "".join(chr(97 + alpha.index(c) // 9) + chr(97 + alpha.index(c) % 9) for c in msg)
    dec = "".join(alpha[i] for i in pairs_idx(enc, "rm"))
    assert dec == msg
    assert G.english_score(dec) > -4.0, G.english_score(dec)
    a27 = ALPHA27["AZ_|matrixsumlist"]
    tr = []
    for c in msg:
        i = a27.index(c); tr += [i // 9, (i // 3) % 3, i % 3]
    sym = "".join(chr(97 + 3 * tr[k] + tr[k + 1]) for k in range(0, len(tr), 2))
    tt = trits(sym, "dm"); dec27 = "".join(a27[9 * tt[k] + 3 * tt[k + 1] + tt[k + 2]] for k in range(0, len(tt) - 2, 3))
    assert dec27 == msg, dec27
    assert t9_multitap([4, 4, 3, 3, 5, 5, 5, 5, 5, 5, 6, 6, 6]) == "HELO"
    assert t9_multitap([4, 4, 1, 3, 3, 1, 5, 5, 5, 1, 5, 5, 5, 1, 6, 6, 6], sep=1).replace(" ", "") == "HELLO"
    assert a1z26_greedy([8, 5, 1, 2, 2, 6]) == "HELZ"
    print("controle positivo OK")
_control()

# ------------------------------------------------------------------ 1) pares -> 81 alfabetos
t0 = time.time()
for src, s in SOURCES.items():
    for order in ("rm", "cm"):
        idx = pairs_idx(s, order)
        for an, alpha in ALPHA81.items():
            check(f"p81|{src}|{order}|{an}", "".join(alpha[i] for i in idx))
        # idx mod 16 -> hex -> bytes ("hex expandido")
        hx = "".join("0123456789abcdef"[i % 16] for i in idx)
        if len(hx) % 2: hx = hx[:-1]
        check(f"p81hex16|{src}|{order}", hx); check(f"p81hex16b|{src}|{order}", bytes.fromhex(hx).decode("latin-1"), bytes.fromhex(hx))
        # offsets ASCII completos (a=0: idx+off; a=1 e' off+10)
        for off in range(0, 256 - 80):
            b = bytes(i + off for i in idx)
            check(f"p81off|{src}|{order}|+{off}", b.decode("latin-1"), b)
print("pares-81 feito", N, round(time.time() - t0, 1), "s")

# ------------------------------------------------------------------ 2) leituras numericas de pares
for src, s in SOURCES.items():
    d1 = [x + 1 for x in d0(s)]; dz = d0(s)
    for lab, dd in (("a1", d1), ("a0", dz)):
        for order in ("rm", "cm"):
            dec = [10 * dd[i] + dd[i + 1] if order == "rm" else dd[i] + 10 * dd[i + 1] for i in range(0, len(dd) - 1, 2)]
            check(f"dec26|{src}|{lab}|{order}", "".join(chr(65 + (v - 1) % 26) for v in dec))
            check(f"dec26z|{src}|{lab}|{order}", "".join(chr(65 + v % 26) for v in dec))
            check(f"dec27|{src}|{lab}|{order}", "".join(A27[v % 27] for v in dec))
            for off in range(0, 156):
                b = bytes((v + off) % 256 for v in dec)
                check(f"decoff|{src}|{lab}|{order}|+{off}", b.decode("latin-1"), b)
        # hex direto (a=1 ja em quick_battery; a=0 e' novo)
        hx = "".join(str(x) for x in dd)
        if len(hx) % 2: hx = hx[:-1]
        b = bytes.fromhex(hx); check(f"hexdirect|{src}|{lab}", b.decode("latin-1"), b)
        check(f"hexstr|{src}|{lab}", hx)
    check(f"a1z26greedy|{src}", a1z26_greedy(d1))
    check(f"a1z26greedy_rev|{src}", a1z26_greedy(d1[::-1]))
print("numericas feito", N)

# ------------------------------------------------------------------ 3) trits -> cubo 27
for src, s in SOURCES.items():
    for mode in ("dm", "md"):
        tt = trits(s, mode)
        for order in ("big", "little"):
            idx = [(9 * tt[k] + 3 * tt[k + 1] + tt[k + 2]) if order == "big" else (tt[k] + 3 * tt[k + 1] + 9 * tt[k + 2])
                   for k in range(0, len(tt) - 2, 3)]
            for an, alpha in ALPHA27.items():
                check(f"cube27|{src}|{mode}|{order}|{an}", "".join(alpha[i] for i in idx))
    # triplas de simbolos com mod3 / div3 por simbolo
    for red, f in (("mod3", lambda x: x % 3), ("div3", lambda x: x // 3)):
        r = [f(x) for x in d0(s)]
        for order in ("big", "little"):
            idx = [(9 * r[k] + 3 * r[k + 1] + r[k + 2]) if order == "big" else (r[k] + 3 * r[k + 1] + 9 * r[k + 2])
                   for k in range(0, len(r) - 2, 3)]
            for an in ("AZ_", "_AZ"):
                check(f"tri27|{src}|{red}|{order}|{an}", "".join(ALPHA27[an][i] for i in idx))
print("cubo-27 feito", N)

# ------------------------------------------------------------------ 4) T9
for src, s in SOURCES.items():
    d1 = [x + 1 for x in d0(s)]
    check(f"t9|{src}|nosep", t9_multitap(d1))
    for sep in range(1, 10):
        check(f"t9|{src}|sep{sep}", t9_multitap(d1, sep))
    keys = {1: " ", 2: "A", 3: "D", 4: "G", 5: "J", 6: "M", 7: "P", 8: "T", 9: "W"}
    check(f"t9first|{src}", "".join(keys[d] for d in d1))
print("T9 feito", N)

# ------------------------------------------------------------------ resumo
BEST.sort(key=lambda x: -x[0])
top = [r for _, r in BEST[:15]]
summary = {"n_tests": N, "hard": len(HARD), "soft_pad": len(SOFT), "top": top,
           "soft_sample": SOFT[:20], "soft_by_blob": {b: sum(1 for s in SOFT if s["blob"] == b) for b in ("SMALL", "COSMIC", "TAIL32")}}
G.jsonl(LOG, {"SUMMARY": summary})
print(json.dumps(summary, ensure_ascii=False, indent=1)[:6000])
