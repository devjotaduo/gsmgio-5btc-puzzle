# -*- coding: utf-8 -*-
"""phase2_table_bytes — a tabela da fase 2 "# X 2 S H 4 Y 0 Q B 15 #" lida como MATERIAL BINARIO
(bytes/nibbles/hex/decimal) e como PROGRAMA (larguras/chaves de transposicao), mais a cifra de
teclado sugerida por "the I and W are below" e a 8a parte inserida DENTRO da gramatica da fase 3.

Hipotese (falsificavel, espaco finito): os numeros da tabela nao sao uma senha textual (ja refutado
em phase2_leftovers) mas (a) 7-10 BYTES literais — chave/privkey/senha em hex ou decimal —,
(b) um deslocamento de TECLADO ("I e W estao ABAIXO": I->K, W->S) aplicado as letras X,S,H,Y,Q,B e
aos 7 tokens da pagina do endgame, (c) a "8a parte" que entra numa das 6 juntas INTERNAS das 7
partes da senha da fase 3, (d) alfabetos keyed das frases da fase 2 em variantes fill+kw e dot-style
(convencao 3.2.2) para checkerboard/Bifid, ou (e) larguras/ordens de transposicao colunar de faed/dbbi.
Oraculo duro: G.semantic em saida AES / G.priv_hit-fast_priv_scan. Texto: G.semantic_text (soft).
"""
import sys, os, re, json, time, itertools, random, math
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
import base64

LOG = os.path.join(SP, "phase2_table_bytes.jsonl")
open(LOG, "w").close()
G.jsonl(LOG, {"family": "phase2_table_bytes", "hypothesis": __doc__.strip()})

from coincurve import PublicKey
_TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
def priv_fast(b32):
    """oraculo duro rapido: privkey de 32B -> pubkey on-chain do premio (uncompressed)."""
    if len(b32) != 32: return False
    try:
        return PublicKey.from_valid_secret(b32).format(False) == _TGT
    except Exception:
        return False
assert not priv_fast(G.sha(b"test")) and not priv_fast(bytes(32))

N_AES = 0; N_PRIV = 0; N_DEC = 0   # decrypts AES / checagens de privkey / decodes textuais
N = 0                 # contador exato de testes (1 = 1 decrypt AES OU 1 checagem de privkey OU 1 decode textual)
HARD, SOFT = [], []
BEST = {"score": -99, "text": "", "how": ""}
BLOBS3 = ("SMALL", "COSMIC", "TAIL32")
SEEN_PW = set()

def hard(rec, tag="HARD"):
    HARD.append(rec); G.jsonl(LOG, {tag: rec})

def test_pw(pw, how, blobs=BLOBS3, priv=True):
    """senha -> 3 blobs (EVP-SHA256) [+ sha256(pw) como privkey]."""
    global N
    if isinstance(pw, bytes):
        key = b"B" + pw
    else:
        key = "S" + pw
    if key in SEEN_PW:
        return
    SEEN_PW.add(key)
    for b in blobs:
        N += 1; globals()["N_AES"] += 1
        for kdf, p in G.aes_try(pw, b, kdf="sha256"):
            rec = {"blob": b, "kdf": kdf, "pw": (pw if isinstance(pw, str) else pw.hex())[:160], "how": how,
                   "len": len(p), "printable": round(G.printable(p), 3)}
            if G.semantic(p):
                rec["plaintext_hex"] = p.hex(); hard(rec)
            else:
                rec["head"] = p[:24].decode("latin-1"); SOFT.append(rec)
    if priv:
        N += 1; globals()["N_PRIV"] += 1
        if priv_fast(G.sha(pw)):
            hard({"priv_of_sha256": (pw if isinstance(pw, str) else pw.hex()), "how": how})

def test_key32(k32, how, ivs=(b"\x00" * 16,)):
    """chave crua de 32B (openssl -K). 1 IV basta p/ oraculo de padding (padding so depende de chave+CT)."""
    global N
    for b in BLOBS3:
        for iv in ivs:
            N += 1; globals()["N_AES"] += 1
            p = G.aes_rawkey(k32, b, iv)
            if p is None:
                continue
            rec = {"blob": b, "mode": "-K", "key": k32.hex(), "iv": iv.hex(), "how": how,
                   "len": len(p), "printable": round(G.printable(p), 3)}
            if G.semantic(p):
                rec["plaintext_hex"] = p.hex(); hard(rec)
            else:
                rec["head"] = p[:24].decode("latin-1"); SOFT.append(rec)
    N += 1; globals()["N_PRIV"] += 1
    if priv_fast(k32):
        hard({"privkey_raw": k32.hex(), "how": how})

def note_best(text, how):
    global N, N_DEC
    N += 1; N_DEC += 1
    if len(text) < 20:
        return
    s = G.english_score(text)
    if s > BEST["score"]:
        BEST.update(score=round(s, 3), text=text[:90], how=how)
    if G.semantic_text(text):
        rec = {"how": how, "score": round(s, 3), "text": text[:120], "words": G.word_hits(text, 6)[:8]}
        SOFT.append(rec); G.jsonl(LOG, {"soft_text": rec})

# ------------------------------------------------------------------ CONTROLES POSITIVOS
raw2 = base64.b64decode(G.PHASE2_B64); G.BLOBS["PHASE2"] = (raw2[8:16], raw2[16:])
h0 = len(HARD)
test_pw(G.shahex("causality"), "controle KDF fase2", blobs=("PHASE2",), priv=False)
assert len(HARD) == h0 + 1 and HARD[-1]["blob"] == "PHASE2", "controle de KDF falhou"
CTRL_KDF = HARD.pop()["plaintext_hex"][:40]
ALPHA322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
D322 = [int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"]
assert G.checkerboard_decode(D322, ALPHA322, (1, 4), "0123456789").startswith("INCASEYOUMANAGETOCRACKTHIS")
assert G.bif_full().startswith("BTCSEED")
G.jsonl(LOG, {"controls": {"kdf_fase2_sha256": CTRL_KDF, "checkerboard_322": "OK", "bifid_BTCSEED": "OK"}})
N = 0; N_AES = 0; N_PRIV = 0; N_DEC = 0; SOFT.clear(); SEEN_PW.clear()

# ================================================================== (a) TABELA COMO BYTES/NIBBLES
# tabela: # X 2 S H 4 Y 0 Q B 15 #   com S=32, H=-42, B=-16
def vec(x=None, y=None, q=None, hs=-1, bs=-1, with_xyq=True):
    v = [2, 32, 42 * hs, 4, 0, 16 * bs, 15] if not with_xyq else [x, 2, 32, 42 * hs, 4, y, 0, q, 16 * bs, 15]
    return v

def to_bytes_tc(v):    # complemento de 2 (mod 256)
    return bytes(int(t) % 256 for t in v)

def to_bytes_abs(v):
    return bytes(abs(int(t)) % 256 for t in v)

def dec_concat(v, sep=""):
    return sep.join(str(int(t)) for t in v)

def nibbles(v):
    """cada valor como nibble (se 0..15) senao 2 nibbles; hex string + bytes empacotados."""
    h = "".join((format(abs(int(t)), "x") if abs(int(t)) < 16 else format(abs(int(t)), "02x")) for t in v)
    hh = h if len(h) % 2 == 0 else h + "0"
    return h, bytes.fromhex(hh)

def a1z26(v):
    return "".join(chr(64 + (abs(int(t)) % 26 or 26)) for t in v)

t0 = time.time(); n_a1 = 0
# --- A1: exaustivo sobre os 7 numeros CONHECIDOS (sem X/Y/Q) em todas as representacoes
for hs, bs in ((-1, -1), (1, 1), (-1, 1), (1, -1)):
    v = vec(hs=hs, bs=bs, with_xyq=False)
    ba, bt = to_bytes_abs(v), to_bytes_tc(v)
    nh, nb = nibbles(v)
    reps = {
        "bytes_abs": ba, "bytes_tc": bt, "nib_bytes": nb,
        "bytes_abs_rev": ba[::-1], "bytes_tc_rev": bt[::-1],
    }
    strs = {
        "hex_abs": ba.hex(), "hex_abs_up": ba.hex().upper(), "hex_tc": bt.hex(), "hex_tc_up": bt.hex().upper(),
        "nib_hex": nh, "nib_hex_up": nh.upper(),
        "dec": dec_concat(v), "dec_sp": dec_concat(v, " "), "dec_rev": dec_concat(v[::-1]),
        "dec_abs": dec_concat([abs(t) for t in v]), "dec_abs_rev": dec_concat([abs(t) for t in v][::-1]),
        "a1z26": a1z26(v), "a1z26_low": a1z26(v).lower(),
        "hash_dec": "#" + dec_concat(v, " ") + "#", "hash_dec2": "# " + dec_concat(v, " ") + " #",
    }
    for name, s in strs.items():
        n_a1 += 1
        test_pw(s, f"A1 {name} h={hs} b={bs}")
        test_pw(G.shahex(s), f"A1 sha256({name}) h={hs} b={bs}")
    for name, bb in reps.items():
        n_a1 += 1
        test_pw(bb, f"A1 raw-bytes {name} h={hs} b={bs}")
        for k32, kn in ((bb.rjust(32, b"\x00"), "rjust"), (bb.ljust(32, b"\x00"), "ljust"),
                        (G.sha(bb), "sha256"), ((bb * 32)[:32], "repeat")):
            test_key32(k32, f"A1 -K {name}/{kn} h={hs} b={bs}",
                       ivs=(b"\x00" * 16, bb.rjust(16, b"\x00")))
G.jsonl(LOG, {"stage": "a1_known7", "reps": n_a1, "n": N, "sec": round(time.time() - t0, 1)})

# --- A2: varredura de X,Y (0..99 + valores tematicos) x Q (leituras numericas)
XY_VALS = list(range(0, 100)) + [11110, 1141, 1812, 101, 140, 140 - 100]
Q_NUM = [2, 3, 82, 8, 5, 17]        # twofish->2, threefish->3, 82='R', ...
t0 = time.time(); n_a2 = 0
for q in Q_NUM:
    for hs, bs in ((-1, -1), (1, 1)):
        for x in XY_VALS:
            for y in XY_VALS:
                v = vec(x, y, q, hs, bs)
                n_a2 += 1
                s = dec_concat(v)
                test_pw(G.shahex(s), f"A2 sha256(dec) q={q} x={x} y={y} h={hs} b={bs}", priv=False)
                if max(abs(t) for t in v) < 256:
                    bb = to_bytes_tc(v)
                    N += 2
                    if G.priv_hit(bb.rjust(32, b"\x00")):
                        hard({"privkey_raw": bb.rjust(32, b"\x00").hex(), "how": f"A2 rjust q={q} x={x} y={y}"})
                    if G.priv_hit(bb.ljust(32, b"\x00")):
                        hard({"privkey_raw": bb.ljust(32, b"\x00").hex(), "how": f"A2 ljust q={q} x={x} y={y}"})
G.jsonl(LOG, {"stage": "a2_xy_sweep", "seqs": n_a2, "n": N, "sec": round(time.time() - t0, 1)})

# --- A3: X,Y como strings/Q textual, formas hex/decimal com separadores
Q_STR = ["phishing", "phish", "twofish", "threefish", "blowfish", "fish", "R", "r"]
t0 = time.time(); n_a3 = 0
for q in Q_STR:
    for x, y in [("X", "Y"), ("", ""), (0, 0), (2, 0), (42, 21), (11110, 1141), (1, 2), (24, 25)]:
        for hs, bs in ((-1, -1), (1, 1)):
            v = [x, 2, 32, 42 * hs, 4, y, 0, q, 16 * bs, 15]
            for sep in ("", " ", "-"):
                s = sep.join(str(t) for t in v)
                n_a3 += 1
                test_pw(s, f"A3 raw q={q} x={x} y={y} sep='{sep}'")
                test_pw(G.shahex(s), f"A3 sha256 q={q} x={x} y={y} sep='{sep}'")
G.jsonl(LOG, {"stage": "a3_qstr", "seqs": n_a3, "n": N, "sec": round(time.time() - t0, 1)})

# ================================================================== (b) CIFRA DE TECLADO
LAYOUTS = {
    "qwerty": ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
    "azerty": ["azertyuiop", "qsdfghjklm", "wxcvbn"],
    "qwertz": ["qwertzuiop", "asdfghjkl", "yxcvbnm"],
}
def kb_shift(s, layout, direction):
    rows = LAYOUTS[layout]
    pos = {c: (r, i) for r, row in enumerate(rows) for i, c in enumerate(row)}
    out = []
    for ch in s:
        low = ch.lower()
        if low not in pos:
            out.append(ch); continue
        r, i = pos[low]
        nr, ni = r, i
        if direction == "below":   nr = r + 1
        elif direction == "above": nr = r - 1
        elif direction == "left":  ni = i - 1
        elif direction == "right": ni = i + 1
        elif direction == "bottom":                       # linha inferior (ZXCVBNM) substitui
            nr = len(rows) - 1
        if not (0 <= nr < len(rows)) or not (0 <= ni < len(rows[nr])):
            out.append(ch); continue
        c2 = rows[nr][ni]
        out.append(c2.upper() if ch.isupper() else c2)
    return "".join(out)

KB_TARGETS = {
    "table_letters": "XSHYQB", "table_letters_low": "xshyqb", "table_full": "X2SH4Y0QB15",
    "IW": "IW", "WI": "WI", "iw": "iw",
    "swordfish": "swordfish", "fish": "fish", "phish": "phish", "blowfish": "blowfish", "twofish": "twofish",
}
for k, v in G.TOKENS.items():
    KB_TARGETS["tok_" + k] = v
t0 = time.time(); n_b = 0
for tname, txt in KB_TARGETS.items():
    for lay in LAYOUTS:
        for d in ("below", "above", "left", "right", "bottom"):
            s = kb_shift(txt, lay, d)
            if s == txt:
                continue
            n_b += 1
            for form, val in (("raw", s), ("nospace", s.replace(" ", "")), ("upper", s.upper()),
                              ("lower", s.lower())):
                test_pw(val, f"B kb {tname} {lay} {d} {form}")
                test_pw(G.shahex(val), f"B sha256 kb {tname} {lay} {d} {form}")
            G.jsonl(LOG, {"kb": [tname, lay, d, s[:60]]})
# concatenacoes dos 7 tokens deslocados (ordem da pagina) + tabela
ORDER = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "shabef",
         "line_before_small", "line_after_small"]
for lay in LAYOUTS:
    for d in ("below", "above", "left", "right", "bottom"):
        cat = "".join(kb_shift(G.TOKENS[k], lay, d) for k in ORDER)
        for form, val in (("raw", cat), ("nospace", cat.replace(" ", "")), ("upper", cat.upper().replace(" ", ""))):
            n_b += 1
            test_pw(val, f"B cat7 {lay} {d} {form}")
            test_pw(G.shahex(val), f"B sha256 cat7 {lay} {d} {form}")
G.jsonl(LOG, {"stage": "b_keyboard", "variants": n_b, "n": N, "sec": round(time.time() - t0, 1)})

# ================================================================== (c) 8a PARTE NAS 6 JUNTAS INTERNAS
P7 = ["causality", "Safenet", "Luna", "HSM", "11110",
      "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
      "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"]
assert G.shahex("".join(P7)) == "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
P7_W = P7[:6] + [P7[6].replace("/2R5/", "/6R1/").replace(" b - - 0 1", " w - - 0 1")]   # FEN pre-lance

def seqs2304():
    """re-geracao exata das 2.304 sequencias da tabela (mesma enumeracao de phase2_leftovers)."""
    QN = [2, 3, 82, 17, 8, 7, 5, 0, 1, 16, 64, 128]
    QS = ["phishing", "phish", "Phishing", "twofish", "Twofish", "threefish", "blowfish", "Blowfish",
          "swordfish", "fish", "QWERTYUIOP", "skuytreq"]
    XY = [("X", "Y"), (0, 0), (2, 0), (10, 25), (24, 25), (1, 2)]
    for q in QN + QS:
        for x, y in XY:
            for sgn in (1, -1):
                vals = [x, 2, 32, 42 * sgn, 4, y, 0, q, 16 * sgn, 15]
                for order in ("fwd", "rev"):
                    vv = vals if order == "fwd" else vals[::-1]
                    for sep in ("", " "):
                        s = sep.join(str(t) for t in vv)
                        for hashes in (False, True):
                            yield (f"# {s} #" if hashes else s)

SEQS = list(seqs2304())
assert len(SEQS) == 2304, len(SEQS)
t0 = time.time(); n_c = 0
for parts, pname in ((P7, "FENpost"), (P7_W, "FENpre")):
    for pos in range(1, 7):                    # 6 juntas INTERNAS
        head, tail = "".join(parts[:pos]), "".join(parts[pos:])
        for s in SEQS:
            n_c += 1
            test_pw(G.shahex(head + s + tail), f"C 8a-parte pos={pos} {pname} seq={s[:24]}", priv=False)
G.jsonl(LOG, {"stage": "c_eighth_part", "passwords": n_c, "n": N, "sec": round(time.time() - t0, 1)})

# ================================================================== (d) ALFABETOS fill+kw E dot-style
PHRASES = ["swordfish", "phish", "phishing", "twofish", "threefish", "blowfish", "klingon", "thales", "safenet",
           "luna", "hsm", "safenetlunahsm", "norton", "mcafee", "johnmcafee", "belikin", "belize", "thevenin",
           "overlord", "kennedy", "jfk", "johnson", "truman", "carter", "carrey", "simulacra", "baudrillard",
           "keymaker", "zerg", "hackers", "qwertyuiop", "worstgear", "reverse",
           "extendthenameofahackersswordlessfish", "theiandwarebelow", "chavaghjav",
           "answertoonlythispuzzlebutnothingelse", "okkidonthehighwayletputitintheworstgear",
           "theironicnameofthekeymakers"]
BASE25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
def alpha_fill_kw(phrase):
    """NOVO: filler PRIMEIRO, keyword no fim (inverso da convencao usual kw+fill)."""
    kw = []
    for c in phrase.upper():
        c = "I" if c == "J" else c
        if c in BASE25 and c not in kw: kw.append(c)
    return "".join(c for c in BASE25 if c not in kw) + "".join(kw)
def alpha_dot(phrase):
    """dot-style (convencao 3.2.2 FUBCDORA.LETHINGKYMVPS.JQZXW): 23 letras keyed + 2 '.' nas
    posicoes de grade (inicio da 1a linha de escape, meio da 2a). 7 + 1+8 + 1+8 = 25."""
    kw = []
    for c in phrase.upper():
        c = "I" if c == "J" else c
        if c in BASE25 and c not in kw: kw.append(c)
    L = "".join(kw) + "".join(c for c in BASE25 if c not in kw)
    a = L[:7] + "." + L[7:15] + "." + L[15:23]
    assert len(a) == 25, a
    return a
def to25(a):
    """alfabeto de 25 simbolos distintos (para Bifid), preenchendo o que faltar."""
    out = []
    for c in a + BASE25:
        if c != "." and c not in out: out.append(c)
    return "".join(out[:25])

ALPHAS = {}
for p in PHRASES:
    ALPHAS["fk:" + p] = alpha_fill_kw(p)
    ALPHAS["dot:" + p] = alpha_dot(p)
TEXTS = {"faed": G.FAED, "dbbi": G.DBBI}
t0 = time.time(); n_d = 0
for aname, alpha in ALPHAS.items():
    for tname, txt in TEXTS.items():
        for base1, uni in ((True, "123456789"), (False, "012345678")):
            digs = G.digits(txt, base1)
            for e1, e2 in itertools.permutations([int(c) for c in uni], 2):
                out = G.checkerboard_decode(digs, alpha, (e1, e2), uni)
                n_d += 1
                note_best(out, f"D cb {aname} {tname} a={'1' if base1 else '0'} esc=({e1},{e2})")
# Bifid 5x5 nos periodos da tabela (alfabetos sem ponto)
for aname, alpha in ALPHAS.items():
    a25 = to25(alpha)
    if len(set(a25)) != 25:
        continue
    for tname, txt in TEXTS.items():
        for per in (570, 285, 32, 42, 16, 15, 2, 4):
            if per > len(txt): continue
            for mode in ("decrypt", "encrypt"):
                n_d += 1
                note_best(G.bifid(txt, a25, per, 5, mode), f"D bifid {aname} {tname} per={per} {mode}")
G.jsonl(LOG, {"stage": "d_alphabets", "decodes": n_d, "n": N, "sec": round(time.time() - t0, 1), "best": BEST})

# ================================================================== (e) TRANSPOSICAO COLUNAR + FILTRO INVARIANTE
def columnar(seq, w, order, inverse=False):
    """escreve por linhas em w colunas, le colunas na ordem `order` (inverse = permutacao inversa)."""
    n = len(seq); rows = (n + w - 1) // w
    idx = [r * w + c for c in order for r in range(rows) if r * w + c < n]
    if not inverse:
        return [seq[p] for p in idx]
    out = [None] * n
    for i, p in enumerate(idx): out[p] = seq[i]
    return out

def stats(seq):
    """IoC de digrafos + entropia condicional H(x_{i+1}|x_i) da sequencia de simbolos."""
    n = len(seq)
    dig = {}
    for i in range(n - 1):
        d = (seq[i], seq[i + 1]); dig[d] = dig.get(d, 0) + 1
    m = n - 1
    ioc = sum(v * (v - 1) for v in dig.values()) / max(1, m * (m - 1))
    uni = {}
    for s in seq: uni[s] = uni.get(s, 0) + 1
    H = 0.0
    for (a, b), v in dig.items():
        p_ab = v / m; p_b_a = v / uni[a]
        H -= p_ab * math.log2(p_b_a)
    return ioc, H

def null_dist(seq, k=200):
    rnd = random.Random(1327)
    I, Hs = [], []
    s = list(seq)
    for _ in range(k):
        rnd.shuffle(s)
        i, h = stats(s); I.append(i); Hs.append(h)
    mu_i = sum(I) / k; sd_i = (sum((x - mu_i) ** 2 for x in I) / k) ** .5
    mu_h = sum(Hs) / k; sd_h = (sum((x - mu_h) ** 2 for x in Hs) / k) ** .5
    return (mu_i, sd_i or 1e-9), (mu_h, sd_h or 1e-9)

t0 = time.time(); n_e = 0; ZS = []
KEY7 = [2, 32, 42, 4, 0, 16, 15]
KEY7_S = [2, 32, -42, 4, 0, -16, 15]
def rank_order(key):
    return [i for i, _ in sorted(enumerate(key), key=lambda t: (t[1], t[0]))]
for tname, txt in TEXTS.items():
    seq = list(txt)
    (mi, si), (mh, sh) = null_dist(seq)
    # controle do filtro: sequencia identidade
    i0, h0v = stats(seq)
    G.jsonl(LOG, {"E null": tname, "z_ioc_identity": round((i0 - mi) / si, 2), "z_H_identity": round((h0v - mh) / sh, 2)})
    cands = []
    for w in (15, 32, 42, 16, 4, 2, 7, 10, 38, 5, 3, 6, 19, 30, 57, 95, 114, 190, 285):
        if w >= len(seq): continue
        orders = [list(range(w)), list(range(w))[::-1]]
        if w == 7:
            orders += [rank_order(KEY7), rank_order(KEY7_S), rank_order(KEY7)[::-1]]
        if w <= 10:
            orders.append(rank_order([(KEY7 * 3)[:w]][0]))
        for oi, order in enumerate(orders):
            for inv in (False, True):
                out = columnar(seq, w, order, inv)
                n_e += 1; N += 1
                i1, h1 = stats(out)
                zi, zh = (i1 - mi) / si, (h1 - mh) / sh
                cands.append((max(abs(zi), abs(zh)), tname, w, oi, inv, round(zi, 2), round(zh, 2), "".join(out)))
    cands.sort(reverse=True, key=lambda t: t[0])
    ZS.extend([c[:7] for c in cands[:5]])
    # so decodifica os aprovados pelo filtro (|z| > 3) — ou os 3 melhores, para registro
    for c in cands[:3] if cands[0][0] <= 3 else [c for c in cands if c[0] > 3][:12]:
        s = c[7]
        for alpha in (G.CANON, ALPHAS["dot:theiandwarebelow"].replace(".", "")[:25],
                      G.keyed_alphabet("swordfish")):
            for e1, e2 in ((1, 2), (2, 4), (4, 2), (1, 5), (3, 2), (7, 9), (8, 9), (9, 8)):
                out = G.checkerboard_decode(G.digits(s, True), alpha, (e1, e2), "123456789")
                note_best(out, f"E cb w={c[2]} ord={c[3]} inv={c[4]} esc=({e1},{e2})")
            note_best(G.bifid(s, to25(alpha), len(s), 5, "decrypt"),
                      f"E bifid w={c[2]} ord={c[3]} inv={c[4]}")
        # tambem como senha (digitos -> z-method) e privkey
        try:
            b = G.z_method(G.digits(s, True))
            N += 1
            for hh in G.fast_priv_scan(b, f"E z w={c[2]}"): hard({"how": "E z-method", "priv": str(hh)})
            if G.semantic(b): hard({"how": f"E z-method w={c[2]}", "hex": b.hex()[:200]})
        except Exception:
            pass
G.jsonl(LOG, {"stage": "e_transposition", "perms": n_e, "n": N, "sec": round(time.time() - t0, 1),
              "top_z": [[str(x) for x in z] for z in ZS]})

# ================================================================== (f) TABELA COMO ORDEM / SELECAO
# NOVO: os 7 numeros como (f1) PERMUTACAO das 7 partes da senha da fase 3 e (f2) INDICES que
# SELECIONAM caracteres (selecao != permutacao — lead 1 do briefing) de faed/dbbi/senha da fase 3.
t0 = time.time(); n_f = 0
for parts, pname in ((P7, "FENpost"), (P7_W, "FENpre")):
    for perm in itertools.permutations(range(7)):
        n_f += 1
        test_pw(G.shahex("".join(parts[i] for i in perm)), f"F1 ordem {perm} {pname}", priv=False)
SRC = {"faed": G.FAED, "dbbi": G.DBBI, "pw7": "".join(P7), "genesis": P7[5], "fen": P7[6],
       "dbbi+faed": G.DBBI + G.FAED}
IDX_SETS = {"key7": [2, 32, 42, 4, 0, 16, 15], "key7_rev": [15, 16, 0, 4, 42, 32, 2],
            "key7_sorted": [0, 2, 4, 15, 16, 32, 42],
            "cum": [2, 34, 76, 80, 80, 96, 111], "cum_rev": [15, 31, 31, 35, 77, 109, 111]}
for sname, src in SRC.items():
    for iname, idxs in IDX_SETS.items():
        for base in (0, 1):
            # (i) selecao simples
            sel = "".join(src[i - base] for i in idxs if 0 <= i - base < len(src))
            n_f += 1
            test_pw(sel, f"F2 sel {sname} {iname} base={base}")
            test_pw(G.shahex(sel), f"F2 sha256(sel) {sname} {iname} base={base}")
            # (ii) selecao ciclica ate 32/64 chars (stride = os numeros, somados em ciclo)
            pos = 0 - base; out = []
            for k in range(64):
                pos += idxs[k % len(idxs)] or 1
                q = pos % len(src)
                out.append(src[q])
            for L, tag in ((32, "32"), (64, "64")):
                t = "".join(out[:L]); n_f += 1
                test_pw(t, f"F2 cyc{tag} {sname} {iname} base={base}")
                test_pw(G.shahex(t), f"F2 sha256(cyc{tag}) {sname} {iname} base={base}")
                if L == 32:
                    b = t.encode()[:32]
                    N += 1; globals()["N_PRIV"] += 1
                    if len(b) == 32 and priv_fast(b):
                        hard({"privkey_raw": b.hex(), "how": f"F2 cyc32 {sname} {iname} base={base}"})
G.jsonl(LOG, {"stage": "f_order_selection", "variants": n_f, "n": N, "sec": round(time.time() - t0, 1)})


summary = {"n_tests": N, "n_aes": N_AES, "n_priv": N_PRIV, "n_decode": N_DEC,
           "pad_rate": round(len([x for x in SOFT if "blob" in x]) / max(1, N_AES), 5), "pad_expected": round(1/256, 5), "hard": len(HARD), "soft_total": len(SOFT), "best": BEST,
           "soft_pad": [s for s in SOFT if "blob" in s][:15],
           "soft_text": [s for s in SOFT if "blob" not in s][:15],
           "top_z": [[str(x) for x in z] for z in ZS[:10]]}
G.jsonl(LOG, {"summary": summary})
print(json.dumps(summary, ensure_ascii=False, indent=1)[:8000])
