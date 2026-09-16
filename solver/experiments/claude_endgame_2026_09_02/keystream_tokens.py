# -*- coding: utf-8 -*-
"""
FAMILIA keystream_tokens — faed over-encrypted por keystream derivado de TOKEN/hint.
PRE : keystream mod 9 sobre faed (a=0..8) -> Bifid CANON 570 -> detectores.
POST: keystream mod 26 (A-Z) / mod 25 (CANON25) sobre bif_full / REST(563) / canal impar(285).
Modos: vig_add, vig_sub, beaufort, autokey_pt, autokey_ct, prog_i, prog_blk; rotacoes; direcao reversa.
"""
import sys, json, time, hashlib
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G

LOG = SP + r"\keystream_tokens.jsonl"
HYP = ("faed (ou a saida Bifid CANON) carrega 2a camada aditiva (Vigenere/Beaufort/autokey/progressivo) "
       "com keystream = token/hint da pagina em digitos (a1z26, a1z26 mod 9, a-i), mod 9 antes do Bifid "
       "ou mod 25/26 depois; alguma combinacao da ingles ou chave que abre blob / bate premio.")
G.jsonl(LOG, {"event": "hypothesis", "family": "keystream_tokens", "text": HYP, "t": time.time()})

# ------------------------------------------------------------------ keystreams
WORDS = ["yellowblueprimes", "matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
         "ourfirsthintisyourlastcommand", "anstoo", "hashthetext", "salphaseion", "salvation",
         "cosmicduality", "yinyang", "followthewhiterabbit", "theseedisplanted", "thematrixhasyou",
         "gsmgmeganigma", "purplepill", "halfandbetterhalf", "btcseed"]
NUMS = ["101", "102", "163", "193", "140", "1141", "11110", "227", "7", "28", "31"]
PRIMES = [p for p in range(2, 91) if G.is_prime(p)]
COLIDX = sorted(i for i in G.COLORED if G.COLORED[i][0] != 'W*')   # 24 indices coloridos

def a1z26(s): return [ord(c) - 96 for c in s.lower() if 'a' <= c <= 'z']

KS = {}   # nome -> lista de ints (qualquer faixa; reduzimos mod n na hora)
for w in WORDS:
    v = a1z26(w)
    KS[f"{w}:a1z26"] = v
    KS[f"{w}:a1z26m9"] = [x % 9 for x in v]
    KS[f"{w}:a1z26m9b"] = [(x - 1) % 9 for x in v]          # a=0..h=7,i=8,j=0...
    ai = [ord(c) - 97 for c in w if c in "abcdefghi"]
    if len(ai) >= 2: KS[f"{w}:ai_only"] = ai
for n in NUMS:
    KS[f"num{n}:digits"] = [int(c) for c in n]
KS["dbbi:a0"] = G.digits(G.DBBI, base1=False)
KS["dbbi:a1"] = G.digits(G.DBBI, base1=True)
KS["dbbi_order:429683571"] = [4, 2, 9, 6, 8, 3, 5, 7, 1]
KS["dbbi_order:429683571-1"] = [3, 1, 8, 5, 7, 2, 4, 6, 0]
cs = G.COLOR_SEQ
KS["color:B1Y0"] = [1 if c == 'B' else 0 for c in cs]
KS["color:B15Y9"] = [15 if c == 'B' else 9 for c in cs]
KS["color:B54Y47"] = [54 if c == 'B' else 47 for c in cs]
KS["color:B41Y17"] = [41 if c == 'B' else 17 for c in cs]
KS["colidx:mod9"] = [i % 9 for i in COLIDX]
KS["colidx:raw"] = COLIDX
KS["primes<91"] = PRIMES
KS["primes<91:mod9"] = [p % 9 for p in PRIMES]
KS["primes<91:idx1"] = list(range(1, 25))  # placeholder trivial (progressivo puro)
# dedup por valor
_seen = {}
for k, v in list(KS.items()):
    tv = tuple(v)
    if tv in _seen: del KS[k]
    else: _seen[tv] = k
print("keystreams:", len(KS))

# ------------------------------------------------------------------ decoders
MODES = ["vig_add", "vig_sub", "beaufort", "autokey_pt", "autokey_ct", "prog_i", "prog_blk"]
def decode(c, k, mode, n):
    """c: lista de ints 0..n-1 (cifra); k: keystream; devolve plaintext ints."""
    L = len(k); N = len(c); p = [0] * N
    if mode == "vig_add":      # C = P + K  -> P = C - K
        for i in range(N): p[i] = (c[i] - k[i % L]) % n
    elif mode == "vig_sub":    # C = P - K  -> P = C + K
        for i in range(N): p[i] = (c[i] + k[i % L]) % n
    elif mode == "beaufort":   # C = K - P  -> P = K - C
        for i in range(N): p[i] = (k[i % L] - c[i]) % n
    elif mode == "autokey_pt": # C = P + (K || P)
        for i in range(N): p[i] = (c[i] - (k[i] if i < L else p[i - L])) % n
    elif mode == "autokey_ct": # C = P + (K || C)
        for i in range(N): p[i] = (c[i] - (k[i] if i < L else c[i - L])) % n
    elif mode == "prog_i":     # C = P + K[i] + i
        for i in range(N): p[i] = (c[i] - k[i % L] - i) % n
    elif mode == "prog_blk":   # C = P + K[i] + i//L
        for i in range(N): p[i] = (c[i] - k[i % L] - i // L) % n
    return p

def rotations(k):
    L = len(k)
    return [k[r:] + k[:r] for r in range(L)] if L > 1 else [k]

# ------------------------------------------------------------------ dominios
FAED_D = [ord(c) - 97 for c in G.FAED]                       # 0..8
BIF = G.bif_full(); REST = BIF[7:]; ODD = BIF[1::2]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; C25 = G.CANON
POST = {"full": BIF, "rest": REST, "odd": ODD}
HDR = [0, 1, 2, 3, 285, 286, 287, 288]

# ------------------------------------------------------------------ deteccao
n_tests = 0; hard = []; soft = []; best = {"score": -99}
def check(text, how, extra=None):
    """Detectores sobre texto (letras). Retorna score."""
    global n_tests, best
    n_tests += 1
    sc = G.english_score(text)
    if sc > best["score"]:
        best = {"score": round(sc, 3), "text": text[:80], "how": how}
    hits = []
    h = hashlib.sha256(text.encode()).digest()
    r = G.priv_hit(h)
    if r: hits.append(("sha256->priv", r))
    hd, sf = G.try_password_all(h.hex())
    hd2, sf2 = G.try_password_all(text)
    if hd or hd2: hits.append(("aes", hd + hd2))
    wh = [w for w in G.word_hits(text, 6)]
    flag = sc > -4.6 or len(wh) >= 2 or G.HEX64_RE.search(text) or G.WIF_RE.search(text)
    if hits:
        rec = {"how": how, "text": text, "hits": hits, "score": sc}
        hard.append(rec); G.jsonl(LOG, {"event": "HARD", **rec})
    elif flag or sf or sf2:
        rec = {"how": how, "score": round(sc, 3), "words": wh[:6], "pad_soft": (sf + sf2)[:2], "head": text[:60]}
        if flag: soft.append(rec)
        if flag or (sf + sf2): G.jsonl(LOG, {"event": "soft", **rec})
    return sc

# ------------------------------------------------------------------ controle positivo
def control():
    import random
    rnd = random.Random(7)
    # PRE: cifrar faed com vig_add mod 9 + chave 'purplepill' a1z26m9 rotacao 3; decoder deve devolver BTCSEED
    k = KS["purplepill:a1z26m9"]; k = k[3:] + k[:3]
    ct = [(FAED_D[i] + k[i % len(k)]) % 9 for i in range(570)]
    p = decode(ct, k, "vig_add", 9)
    out = G.bifid("".join(chr(97 + x) for x in p), G.CANON, 570)
    assert out.startswith("BTCSEED") and out == BIF, out[:20]
    # POST: ingles conhecido em A-Z, Vigenere mod 26 chave 'cosmicduality' a1z26, autokey_pt; recuperar
    eng = ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENRETURNSTOTHESOURCEOFALLTHINGSWHILETHEARCHITECT"
           "WATCHESFROMBEHINDTHEDOORTHATLEADSTOSALVATIONOFZION")
    pi = [AZ.index(c) for c in eng]; k = KS["cosmicduality:a1z26"]; L = len(k)
    ct = [];
    for i, x in enumerate(pi): ct.append((x + (k[i] if i < L else pi[i - L])) % 26)
    p = decode(ct, k, "autokey_pt", 26)
    rec = "".join(AZ[x] for x in p)
    assert rec == eng and G.english_score(rec) > -4.6, (rec[:30], G.english_score(rec))
    # ruido: texto aleatorio pontua bem pior
    noise = "".join(rnd.choice(AZ) for _ in range(140))
    assert G.english_score(noise) < -6
    G.jsonl(LOG, {"event": "control", "pre_ok": True, "post_ok": True, "eng_score": round(G.english_score(rec), 3),
                  "noise_score": round(G.english_score(noise), 3)})
    print("controle OK: pre recupera BTCSEED; post recupera ingles", round(G.english_score(rec), 3))
control()

# ------------------------------------------------------------------ varredura
t0 = time.time()
filter_pass = []   # configs de keystream PRE que preservam o header BTCSEED
for name, k0 in KS.items():
    for direction in ("fwd", "rev"):
        for kr, k in enumerate(rotations(k0)):
            L = len(k)
            for mode in MODES:
                how = f"{name}|{mode}|rot{kr}|{direction}"
                # ---- PRE mod 9
                c = FAED_D[::-1] if direction == "rev" else FAED_D
                p = decode(c, k, mode, 9)
                if direction == "rev": p = p[::-1]
                s = "".join(chr(97 + x) for x in p)
                out = G.bifid(s, G.CANON, 570)
                sc = check(out, "PRE9|" + how)
                if out.startswith("BTCSEED") and mode not in ("autokey_pt", "autokey_ct") and all(p[i] == FAED_D[i] for i in HDR) and s != G.FAED:
                    filter_pass.append({"how": how, "score": round(sc, 3), "head": out[:40]})
                # ---- POST mod 26 (A-Z) e mod 25 (CANON25)
                for ch, txt in POST.items():
                    for alph, n in ((AZ, 26), (C25, 25)):
                        ci = [alph.index(ch_) for ch_ in txt]
                        if direction == "rev": ci = ci[::-1]
                        p = decode(ci, k, mode, n)
                        if direction == "rev": p = p[::-1]
                        check("".join(alph[x] for x in p), f"POST{n}|{ch}|" + how)
    print(f"{name:38s} n={n_tests:7d} best={best['score']:.3f} {time.time()-t0:6.0f}s", flush=True)

summary = {"event": "summary", "n_tests": n_tests, "hard": len(hard), "soft": len(soft),
           "best": best, "filter_pass_btcseed": filter_pass[:20], "n_filter_pass": len(filter_pass),
           "elapsed": round(time.time() - t0)}
G.jsonl(LOG, summary)
print(json.dumps(summary, indent=1)[:3000])
soft.sort(key=lambda r: -r["score"])
print("TOP SOFT:", json.dumps(soft[:10], indent=1))
