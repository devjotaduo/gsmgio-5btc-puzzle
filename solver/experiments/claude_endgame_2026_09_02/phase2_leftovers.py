"""phase2_leftovers — a tabela da fase 2 "# X 2 S H 4 Y 0 Q B 15 #" (S=32 Klingon, B=-16, H=-42,
Q/X/Y abertos; criador 2023-06-10: "Can't say anything about this") e os textos da fase 2 nunca
usados (Norton/McAfee/Belikin/JFK/Johnson/Carter/Overlord, Carrey/Truman, Simulacra) sao a
"8a parte" ou a chave da fronteira.

Hipotese (falsificavel, espaco finito): (a) a lista numerica da tabela (com 3 leituras de Q, X, Y,
sinais, ordem direta/inversa = "worst gear" = re) concatenada — sozinha ou como 8a parte das 7 partes
da fase 3 — passa por sha256hex e abre SMALL/COSMIC/TAIL32 (KDF EVP-SHA256) ou e' a privkey;
(b) os numeros sao escapes/periodo/keystream de um checkerboard/Bifid sobre dbbi/faed com alfabeto
keyed pelas palavras da fase 2 (swordfish/phish/twofish/klingon/thales/mcafee/...) e o decode le' em ingles;
(c) as palavras/frases da fase 2 nao usadas sao senha (raw/sha256) ou brainwallet.
Oraculo duro: G.semantic em saida AES / G.priv_hit. Saidas textuais: G.semantic_text (soft).
"""
import sys, itertools, time, json
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
import base64
LOG = SP + r"\phase2_leftovers.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"family": "phase2_leftovers", "hypothesis": __doc__.strip()})

N = 0; HARD = []; SOFT = []; BEST = {"score": -99, "text": "", "how": ""}
PW7 = ("causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"
       "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1")
assert G.shahex(PW7) == "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
PW7_W = PW7.replace("/2R5/", "/6R1/").replace(" b - - 0 1", " w - - 0 1")   # FEN antes do lance

def test_pw(pw, how, blobs=("SMALL", "COSMIC", "TAIL32")):
    """Senha em 3 blobs (KDF sha256) + sha256(pw) como privkey. 4 testes."""
    global N
    N += 4
    for b in blobs:
        for kdf, p in G.aes_try(pw, b, kdf="sha256"):
            rec = {"blob": b, "kdf": kdf, "pw": pw, "how": how, "len": len(p), "printable": round(G.printable(p), 3)}
            if G.semantic(p): rec["plaintext_hex"] = p.hex(); HARD.append(rec); G.jsonl(LOG, {"HARD": rec})
            else: rec["head"] = p[:32].decode("latin-1"); SOFT.append(rec); G.jsonl(LOG, {"soft": rec})
    r = G.priv_hit(G.sha(pw))
    if r: rec = {"priv_of_sha256": pw, "how": how, "r": str(r)}; HARD.append(rec); G.jsonl(LOG, {"HARD": rec})

def note_best(text, how):
    s = G.english_score(text)
    if s > BEST["score"]: BEST.update(score=round(s, 3), text=text[:80], how=how)
    if G.semantic_text(text):
        rec = {"how": how, "score": round(s, 3), "text": text[:120], "words": G.word_hits(text, 6)[:8]}
        SOFT.append(rec); G.jsonl(LOG, {"soft_text": rec})

# ------------------------------------------------------------------ controles positivos
raw2 = base64.b64decode(G.PHASE2_B64); G.BLOBS["PHASE2"] = (raw2[8:16], raw2[16:])
h0 = len(HARD); test_pw(G.shahex("causality"), "controle", blobs=("PHASE2",))
assert len(HARD) == h0 + 1 and HARD[-1]["blob"] == "PHASE2"; HARD.pop(); N -= 4
alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
d322 = [int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"]
assert G.checkerboard_decode(d322, alpha322, (1, 4), "0123456789").startswith("INCASEYOUMANAGE")
assert G.bif_full().startswith("BTCSEED")
G.jsonl(LOG, {"controls": "fase2 abre via test_pw (EVP-SHA256); checkerboard 3.2.2 OK; Bifid BTCSEED OK"})

# ------------------------------------------------------------------ (a) tabela como senha / 8a parte
# Q: 3 leituras principais + variantes numericas/strings
Q_NUM = [2, 3, 82, 17, 8, 7, 5, 0, 1, 16, 64, 128]
Q_STR = ["phishing", "phish", "Phishing", "twofish", "Twofish", "threefish", "blowfish", "Blowfish",
         "swordfish", "fish", "QWERTYUIOP", "skuytreq"]
XY = [("X", "Y"), (0, 0), (2, 0), (10, 25), (24, 25), (1, 2)]
def seqs():
    for q in Q_NUM + Q_STR:
        for x, y in XY:
            for sgn in (1, -1):
                vals = [x, 2, 32, 42 * sgn, 4, y, 0, q, 16 * sgn, 15]
                for order in ("fwd", "rev"):
                    v = vals if order == "fwd" else vals[::-1]
                    for sep in ("", " "):
                        s = sep.join(str(t) for t in v)
                        for hashes in (False, True):
                            yield (f"# {s} #" if hashes else s), dict(q=q, x=x, y=y, sgn=sgn, order=order, sep=sep, hashes=hashes)
t0 = time.time(); na = 0
for s, meta in seqs():
    na += 1
    for pw, how in ((s, "raw"), (G.shahex(s), "sha256"), (G.shahex(PW7 + s), "sha256(PW7+seq)"),
                    (G.shahex(s + PW7), "sha256(seq+PW7)"), (G.shahex(PW7_W + s), "sha256(PW7w+seq)")):
        test_pw(pw, how + " " + json.dumps(meta))
# somas/produtos e os numeros conhecidos sozinhos
for s in ["-5", "5", "37", "27", "2324420-1615", "232-424015", "23242401615", "15-1604-42322", "1516042322",
          "2 32 -42 4 0 -16 15", "2324240Q1615", "X232-424Y0Q-1615"]:
    for pw, how in ((s, "raw"), (G.shahex(s), "sha256"), (G.shahex(PW7 + s), "sha256(PW7+s)")):
        test_pw(pw, how + " extra:" + s)
G.jsonl(LOG, {"stage": "a_password", "sequences": na, "n": N, "sec": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ (c) palavras/frases da fase 2 nao usadas
WORDS = ["Norton", "McAfee", "John McAfee", "JohnMcAfee", "Belikin", "Belikins", "belikins", "Belize", "Thevenin",
         "Thévenin", "Overlord", "overlord", "floating zerg house", "zerg", "Zerg", "StarCraft", "Truman", "The Truman Show",
         "Jimmy Carter", "Carter", "Carrey", "Jim Carrey", "James Gates", "Bill Gates", "Simulacra and Simulation",
         "Simulacra", "Baudrillard", "Kennedy", "JFK", "John F. Kennedy", "Johnson", "Lyndon B. Johnson", "Andrew Johnson",
         "John Adams", "John Quincy Adams", "John Tyler", "Nixon", "Reagan", "Executive Order 11110", "EO11110", "11111",
         "Klingon", "klingon", "cha' vagh jav", "chavaghjav", "Thales", "SafenetLunaHSM", "keymaker", "Keymaker",
         "Swordfish", "swordfish", "phish", "phishing", "Phishing", "Twofish", "twofish", "Blowfish", "blowfish",
         "Threefish", "QWERTYUIOP", "qwertyuiop", "reverse", "Reverse", "R", "worst gear", "highway", "Ok kid",
         "42", "-42", "32", "-16", "16", "15", "the I and W are below", "IW", "WI", "i5", "BV80605001911AP",
         "hackers", "Hackers", "Blowfish Twofish", "phreak", "Phreak", "Gibson", "Zero Cool", "Acid Burn"]
import re
def forms(p):
    alnum = re.sub(r"[^A-Za-z0-9]", "", p)
    f = [p, p.replace(" ", ""), p.lower(), p.upper(), p.lower().replace(" ", ""), p.upper().replace(" ", ""),
         alnum, alnum.lower(), alnum.upper()]
    seen = []; [seen.append(x) for x in f if x and x not in seen]; return seen
t0 = time.time(); nc = 0
for w in WORDS:
    for f in forms(w):
        nc += 1
        test_pw(f, "word raw"); test_pw(G.shahex(f), "word sha256")
        test_pw(G.shahex(PW7 + f), "sha256(PW7+word)")
    r = G.phrase_priv(w); N += 36
    if r: HARD.append({"brainwallet": w, "r": str(r)}); G.jsonl(LOG, {"HARD": {"brainwallet": w, "r": str(r)}})
G.jsonl(LOG, {"stage": "c_words", "forms": nc, "n": N, "sec": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ (b) checkerboard / Bifid / keystream
PHRASES = ["swordfish", "phish", "phishing", "twofish", "threefish", "blowfish", "klingon", "thales", "safenet", "luna",
           "hsm", "safenetlunahsm", "norton", "mcafee", "johnmcafee", "belikin", "belize", "thevenin", "overlord",
           "kennedy", "jfk", "johnson", "truman", "carter", "carrey", "simulacra", "baudrillard", "keymaker", "zerg",
           "hackers", "qwertyuiop", "worstgear", "reverse", "extendthenameofahackersswordlessfish", "theiandwarebelow",
           "chavaghjav", "answertoonlythispuzzlebutnothingelse", "okkidonthehighwayletputitintheworstgear"]
ALPHAS = {}
for p in PHRASES:
    ALPHAS[p] = G.keyed_alphabet(p)
    ALPHAS[p + "@rev"] = G.keyed_alphabet(p)[::-1]
ALPHAS["canon"] = G.CANON; ALPHAS["a322"] = alpha322.replace(".", "")[:25]
TEXTS = {"dbbi": G.DBBI, "dbbi_rev": G.DBBI[::-1], "faed": G.FAED, "faed_rev": G.FAED[::-1],
         "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:]}
t0 = time.time(); nb = 0
# checkerboard: universos a=1..9 e a=0..8; escapes = todos os 72 pares ordenados (inclui (2,4),(4,2),(1,5),(3,2),(1,6)...)
for aname, alpha in ALPHAS.items():
    for tname, txt in TEXTS.items():
        for base1, uni in ((True, "123456789"), (False, "012345678")):
            digs = G.digits(txt, base1)
            for e1, e2 in itertools.permutations([int(c) for c in uni], 2):
                out = G.checkerboard_decode(digs, alpha, (e1, e2), uni); nb += 1; N += 1
                if len(out) > 20: note_best(out, f"cb {aname} {tname} a={'1' if base1 else '0'} esc=({e1},{e2})")
# Bifid: periodos da tabela + todos (alfabetos novos)
PERS = sorted({2, 4, 15, 16, 32, 42, 0} | set(range(1, 571)))
for aname, alpha in ALPHAS.items():
    for tname, txt in TEXTS.items():
        L = len(txt)
        for per in PERS:
            if per > L: break
            for mode in ("decrypt", "encrypt"):
                out = G.bifid(txt, alpha, per or L, 5, mode); nb += 1; N += 1
                note_best(out, f"bifid {aname} {tname} per={per} {mode}")
G.jsonl(LOG, {"stage": "b_cb_bifid", "decodes": nb, "n": N, "sec": round(time.time() - t0, 1), "best": BEST})
# keystream mod 9/10 sobre os digitos (a=1..9), leitura z-method (bytes) + priv scan + a-i re-letras
t0 = time.time(); nk = 0
def readouts(digs, how):
    global N
    try:
        b = G.z_method(digs)
    except Exception:
        return
    N += 1; nk_ = 1
    if G.semantic(b):
        rec = {"how": how, "hex": b.hex()[:200], "printable": round(G.printable(b), 3)}; HARD.append(rec); G.jsonl(LOG, {"HARD_z": rec})
    for h in G.fast_priv_scan(b, how): HARD.append({"how": how, "priv": h}); G.jsonl(LOG, {"HARD_priv": [how, str(h)]})
    N += 1
    # pares de digitos -> a1z26
    t = "".join(chr(64 + v) for v in (int(str(digs[i]) + str(digs[i + 1])) for i in range(0, len(digs) - 1, 2)) if 1 <= v <= 26)
    if len(t) > 20: note_best(t, how + " pairs-a1z26")
for q in Q_NUM:
    for x, y in XY[1:]:
        for sgn in (1, -1):
            vals = [x, 2, 32, 42 * sgn, 4, y, 0, q, 16 * sgn, 15]
            for order in ("fwd", "rev"):
                ks = vals if order == "fwd" else vals[::-1]
                for m in (9, 10):
                    for tname in ("dbbi", "faed"):
                        d = G.digits(TEXTS[tname], True)
                        for op in ("+", "-"):
                            out = [((v + k) if op == "+" else (v - k)) % m for v, k in zip(d, itertools.cycle(ks))]
                            nk += 1
                            readouts(out, f"ks q={q} xy={x},{y} sgn={sgn} {order} mod{m} {tname} {op}")
G.jsonl(LOG, {"stage": "keystream", "streams": nk, "n": N, "sec": round(time.time() - t0, 1)})

summary = {"n_tests": N, "hard": len(HARD), "soft": len(SOFT), "best": BEST,
           "soft_pad": [s for s in SOFT if "blob" in s][:20], "soft_text": [s for s in SOFT if "blob" not in s][:20]}
G.jsonl(LOG, {"summary": summary})
print(json.dumps(summary, ensure_ascii=False, indent=1)[:6000])
