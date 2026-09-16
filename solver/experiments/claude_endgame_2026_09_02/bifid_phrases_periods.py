# -*- coding: utf-8 -*-
"""
FAMILIA bifid_phrases_periods.
A: Bifid 5x5 keyed por frases do puzzle x periodos 1..570 x {decrypt,encrypt} sobre faed.
B: Bifid 3x3 sobre a-i (quadrados dbbi/faed/natural/reverso/frequencia) x periodos x modos,
   saida -> digitos -> z-method / checkerboard (3 alfabetos x 36 escapes) / Bifid 5x5 CANON.
C: dbbi sob os mesmos Bifids (5x5 keyed e 3x3).
Oraculo duro: privkey -> endereco-premio (coincurve rapido, confirmado por G.priv_hit) ou blob
AES aberto com semantica (G.try_password_all). Resto e triagem (quadgramas / header-palavra).
"""
import sys, os, json, time, heapq, hashlib, re
from collections import Counter
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
import coincurve
LOG = os.path.join(SP, "bifid_phrases_periods.jsonl")
if os.path.exists(LOG): os.remove(LOG)
log = lambda o: G.jsonl(LOG, o)

HYP = ("O quadrado do Bifid nao e (so) o do dbbi: (A) 5x5 keyed por frase do puzzle x periodo 1..570; "
       "(B) 3x3 sobre a-i (9=3^2) com saida a-i -> digitos -> z-method/checkerboard/Bifid5 CANON; "
       "(C) idem sobre o dbbi. Negativo se nada der ingles > -4.6, header-palavra != BTCSEED, privkey ou blob aberto.")
log({"family": "bifid_phrases_periods", "hypothesis": HYP})

# ------------------------------------------------------------------ oraculo rapido de privkey
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_TH = G.TARGET_H160
TH = bytes.fromhex(_TH) if isinstance(_TH, str) else _TH
def _h160(b): return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
def fast_scan(buf):
    """Todo offset de 32B -> h160 comp/uncomp == alvo? Retorna lista de (offset, hex)."""
    hits = []
    for j in range(0, len(buf) - 31):
        k = buf[j:j + 32]; n = int.from_bytes(k, "big")
        if n == 0 or n >= ORDER: continue
        pk = coincurve.PrivateKey(k).public_key
        if _h160(pk.format(True)) == TH or _h160(pk.format(False)) == TH:
            assert G.priv_hit(k); hits.append((j, k.hex()))
    return hits
# controle do oraculo rapido: chave conhecida -> endereco e coerente com o kit
_k = hashlib.sha256(b"ctrl").digest()
assert G.priv_hit(_k) is None and fast_scan(_k) == []

# ------------------------------------------------------------------ detector nao-BTCSEED
THEME = """private privkey privatekey bitcoin address wallet seed btcseed secret password passphrase
answer congrats congratulations welcome hello matrix salvation cosmic duality yinyang yingyang
halfand betterhalf better half architect oracle source zion trinity morpheus rabbit follow
white roses yellow blue prime primes number bingo salphaseion thispassword lastwords enter sha
hash text hashthetext keynote intertwined ciphers encryptions brute force satoshi genesis
flower planted seedis theseed thekey key keys yours youare thisis theprize prize reward winner
found finally message mirror life death mrrobot eps kill process hush rabbits nest door
knock wake wakeup neo rose dark army fsociety elliot whiterose purple pill red pill
first hint last command ans too shabef matrixsum sumlist list before archi choice""".split()
WORDS_ALL = {w.upper() for w in G.BIP39_WORDS if len(w) >= 5} | {w.upper() for w in THEME if len(w) >= 5}
WORDS_BY_LEN = {}
for w in WORDS_ALL: WORDS_BY_LEN.setdefault(len(w), set()).add(w)
def header_word(t, minlen=5):
    """Maior prefixo de t (>=minlen) que e palavra da lista; '' se nenhum."""
    T = t.upper()
    for L in range(min(12, len(T)), minlen - 1, -1):
        if T[:L] in WORDS_BY_LEN.get(L, ()): return T[:L]
    return ""
def word6(t):
    return [w for w in G.word_hits(t, 6)]
HEXRE, WIFRE = G.HEX64_RE, G.WIF_RE

class Top:
    def __init__(self, k=20): self.k = k; self.h = []; self.n = 0
    def push(self, score, rec):
        self.n += 1; item = (score, self.n, rec)
        if len(self.h) < self.k: heapq.heappush(self.h, item)
        elif score > self.h[0][0]: heapq.heapreplace(self.h, item)
    def items(self): return [r for _, _, r in sorted(self.h, key=lambda x: -x[0])]
TOP = Top(20); HEADERS = []; HARD = []; SOFT = []
N = 0; T0 = time.time()

def judge(text, how, part):
    """Triagem de uma saida em letras. Retorna True se registrou algo."""
    global N
    N += 1
    sc = G.english_score(text)
    TOP.push(sc, {"score": round(sc, 3), "text": text[:120], "how": how, "part": part})
    hw = header_word(text)
    flag = False
    if hw and hw != "BTCSE" and not text.upper().startswith("BTCSEED"):
        HEADERS.append({"header": hw, "how": how, "part": part, "score": round(sc, 3), "text": text[:80]})
        flag = True
    if sc > -4.6:
        w6 = word6(text)
        log({"kind": "readable", "part": part, "how": how, "score": round(sc, 3), "words6": w6, "text": text[:200]})
        flag = True
    else:
        w6 = word6(text) if sc > -5.2 else []
        if len(w6) >= 2:
            log({"kind": "words6", "part": part, "how": how, "score": round(sc, 3), "words6": w6, "text": text[:200]}); flag = True
    # ponytail: saida so-letras nunca e hex64/WIF real; WIF_RE casaria runs de letras sem I/O e dispararia scan lento
    if any(c.isdigit() for c in text) and (HEXRE.search(text) or WIFRE.search(text)):
        for h in G.scan_priv(text.encode("latin-1"), how):
            HARD.append({"part": part, "how": how, "hit": h}); log({"kind": "HARD", "part": part, "how": how, "hit": str(h)})
    return flag

def judge_bytes(b, how, part):
    """Triagem de bytes: privkey em qualquer offset, semantica, senha nos blobs."""
    global N
    N += 1
    for j, k in fast_scan(b):
        r = G.priv_hit(bytes.fromhex(k))
        HARD.append({"part": part, "how": how, "privkey": k, "offset": j, "addr": r}); log({"kind": "HARD", "how": how, "priv": k, "addr": r})
    pr = G.printable(b)
    if pr >= 0.85 and len(b) >= 8:
        log({"kind": "printable", "part": part, "how": how, "printable": round(pr, 3), "head": b[:64].decode("latin-1")})
    hard, soft = G.try_password_all(b)
    if pr >= 0.85:
        h2, s2 = G.try_password_all(b.decode("latin-1"));  hard += h2; soft += s2
    hard2, soft2 = G.try_password_all(hashlib.sha256(b).hexdigest())
    hard += hard2; soft += soft2
    for h in hard:
        HARD.append({"part": part, "how": how, "pw_hex": b.hex(), **h}); log({"kind": "HARD_AES", "how": how, "pw_hex": b.hex(), **h})
    for s in soft:
        SOFT.append({"part": part, "how": how, "pw_hex": b.hex()[:80], **s}); log({"kind": "soft_pad", "how": how, **s})
    if len(b) == 32:
        r = G.priv_hit(b)
        if r: HARD.append({"part": part, "how": how + "|raw32", "privkey": b.hex(), "addr": r})
    r = G.priv_hit(hashlib.sha256(b).digest())
    if r: HARD.append({"part": part, "how": how + "|sha256", "privkey": hashlib.sha256(b).hexdigest(), "addr": r}); log({"kind": "HARD", "how": how + "|sha256", "priv": hashlib.sha256(b).hexdigest()})

# ------------------------------------------------------------------ frases -> alfabetos 5x5
PHRASES = """matrixsumlist lastwordsbeforearchichoice thispassword shabef ourfirsthintisyourlastcommand
anstoo enter salphaseion cosmicduality salvation yellowblueprimes yinyang yingyang theseedisplanted
theflowerblossomsthroughwhatseemstobeaconcretesurface causality safenet lunahsm safenetlunahsm
jacquefresco giveit justonesecond heisenbergsuncertaintyprinciple thematrixhasyou fubcdoralethingkymvps
halfandbetterhalf betterhalf purplepill redpill bluepill gsmg gsmgio globallysupportingmygeneration
hashthetext architect zion neo trinity morpheus oracle keymaker returntothesourcecodes primebasics
thesource lifeanddeath lemiroirdelavieetdelamort mirror mrrobot killprocess elliotalderson fsociety
whiterose darkarmy rosesarewhitebutoftenred rabbitsnest hushhush followthewhiterabbit wakeupneo bitcoin
satoshinakamoto genesisblock chancellor privatekey privatekeynote regularbitcoinprivatekey raisingthestakes
fubcdking oraclequeen thingkymvps sadboard matrix cosmic duality firstorzero bifid polybius blue yellow
primes twentythreeciphers sixteenencryptions sevenintertwinedpasswords hundredfourty keynote gsmgpuzzle
salphaseioncosmicduality wallet password thepassword bingo infrontofyoureyes thedoortoyourright venusproject
resourcebasedeconomy deusexmachina agentsmith cypher nebuchadnezzar knockknock theonebitcoin
sha256answertoo shabefanstoo sha256 yellowhasanumberandsodoesblue gobacktothefirstpuzzlepiece
gsmgmeganigma gsmgio5btcpuzzlechallenge lastwordsbeforearchichoicethispassword thewarning logic knockknockneo
temetnosce merovingian source giveitjustonesecond fubcdkingoraclequeenthingkymvps abcdefghijklmnopqrstuvwxyz
etaoinshrdlcumwfgypbvkjxqz qwertyuiopasdfghjklzxcvbnm zyxwvutsrqponmlkjihgfedcba
dbbibfbhccbegbihabebeihbeggegebebbgehhebhhfbabfdhbeffcdbbfcccgbfbeeggecbedcibfbffgigbeeeabe
""".split()
ALPHAS = {}
for p in PHRASES:
    a = G.keyed_alphabet(p)
    if a == G.CANON: continue           # canonico ja fechado
    if a not in ALPHAS.values(): ALPHAS[p] = a
print("alfabetos 5x5 distintos:", len(ALPHAS))

# ------------------------------------------------------------------ controles positivos
assert G.bifid(G.FAED, G.CANON, 570).startswith("BTCSEED")
# roundtrip 5x5 e 3x3 com periodo que nao divide o comprimento
_a = G.keyed_alphabet("matrixsumlist")
_pt = "THEPRIVATEKEYISHIDDENINSIDETHEMATRIXFOLLOWTHEWHITERABBIT" * 4
assert G.bifid(G.bifid(_pt, _a, 37, 5, "encrypt"), _a, 37, 5, "decrypt") == _pt
assert G.bifid(G.bifid(G.FAED, "dbifhcega", 41, 3, "encrypt"), "dbifhcega", 41, 3, "decrypt") == G.FAED
# alvo plantado: detector deve pegar ingles decifrado
_ct = G.bifid(_pt, _a, 37, 5, "encrypt")
_dec = G.bifid(_ct, _a, 37, 5, "decrypt")
assert G.english_score(_dec) > -4.6
assert judge(_dec, "controle_plantado", "ctrl")
N = 0; TOP = Top(20); HEADERS.clear()
log({"kind": "control", "ok": True, "planted_score": round(G.english_score(_dec), 3), "btcseed": True})

# ------------------------------------------------------------------ Parte A: 5x5 keyed x periodos x modos (faed)
t0 = time.time()
def part_5x5(text, label, periods):
    for name, alpha in ALPHAS.items():
        print("5x5", label, name, N, round(time.time() - T0), file=sys.stderr, flush=True)
        for per in periods:
            for mode in ("decrypt", "encrypt"):
                out = G.bifid(text, alpha, per, 5, mode)
                judge(out, f"bifid5[{name}] p={per} {mode} {label}", "A" if label == "faed" else "C5")
part_5x5(G.FAED, "faed", range(2, 571))
print("Parte A ok", N, "tests", round(time.time() - t0), "s")
nA = N

# ------------------------------------------------------------------ Parte B: 3x3 sobre a-i
def first_occ(s): return "".join(dict.fromkeys(c for c in s if c in "abcdefghi"))
def freq_order(s):
    c = Counter(ch for ch in s if ch in "abcdefghi")
    return "".join(sorted("abcdefghi", key=lambda x: (-c[x], x)))
SQ3 = {"dbbi_1st": (first_occ(G.DBBI) + "abcdefghi")[:9], "faed_1st": first_occ(G.FAED),
       "natural": "abcdefghi", "reverse": "ihgfedcba",
       "freq_faed": freq_order(G.FAED), "freq_dbbi": freq_order(G.DBBI)}
SQ3["faed_1st"] = "".join(dict.fromkeys(SQ3["faed_1st"] + "abcdefghi"))
SQ3 = {k: v for k, v in SQ3.items() if len(v) == 9 and len(set(v)) == 9}
# dedupe
_seen = set(); SQ3 = {k: v for k, v in SQ3.items() if v not in _seen and not _seen.add(v)}
assert len(SQ3) >= 4, SQ3
print("quadrados 3x3:", SQ3)
CB_ALPHAS = {"FUBCDORA": G.keyed_alphabet("FUBCDORALETHINGKYMVPS"), "CANON": G.CANON,
             "AZ": "ABCDEFGHIKLMNOPQRSTUVWXYZ"}
ESC = [(a, b) for a in range(1, 10) for b in range(a + 1, 10)]   # 36
assert len(ESC) == 36
# controle checkerboard universo 1-9: codifica e decodifica
def cb_encode(pt, alphabet, escapes):
    top = [d for d in "123456789" if int(d) not in escapes]
    need = len(top) + 18; alphabet = (alphabet + "." * need)[:need]
    m = {}; k = 0
    for d in top: m[alphabet[k]] = [int(d)]; k += 1
    for e in escapes:
        for d in "123456789": m[alphabet[k]] = [e, int(d)]; k += 1
    out = []
    for c in pt: out += m[c]
    return out
_cbpt = "THEPRIVATEKEYISHERE"
assert G.checkerboard_decode(cb_encode(_cbpt, CB_ALPHAS["CANON"], (1, 4)), CB_ALPHAS["CANON"], (1, 4)) == _cbpt

def post_ai(out, how, part):
    """Saida a-i -> digitos -> z-method / checkerboard / Bifid5 CANON."""
    digs = G.digits(out)
    try:
        judge_bytes(G.z_method(digs), how + "|z", part)
    except Exception as e:
        log({"kind": "err", "how": how, "err": str(e)})
    for an, alpha in CB_ALPHAS.items():
        for esc in ESC:
            judge(G.checkerboard_decode(digs, alpha, esc), how + f"|cb[{an}]esc{esc[0]}{esc[1]}", part)
    judge(G.bifid(out, G.CANON, None, 5, "decrypt"), how + "|bif5CANON full", part)

def part_3x3(text, label, periods, part):
    for sq, alpha in SQ3.items():
        print("3x3", label, sq, N, round(time.time() - T0), file=sys.stderr, flush=True)
        for per in periods:
            for mode in ("decrypt", "encrypt"):
                out = G.bifid(text, alpha, per, 3, mode)
                how = f"bifid3[{sq}={alpha}] p={per} {mode} {label}"
                post_ai(out, how, part)
                # bif5 CANON com o MESMO periodo
                judge(G.bifid(out, G.CANON, per, 5, "decrypt"), how + "|bif5CANON same-p", part)
t0 = time.time()
part_3x3(G.FAED, "faed", range(2, 571), "B")
print("Parte B ok", N - nA, "tests", round(time.time() - t0), "s")
nB = N

# ------------------------------------------------------------------ Parte C: dbbi
t0 = time.time()
part_5x5(G.DBBI, "dbbi", range(2, 92))
part_3x3(G.DBBI, "dbbi", range(2, 92), "C3")
print("Parte C ok", N - nB, "tests", round(time.time() - t0), "s")

# ------------------------------------------------------------------ resumo
HEADERS.sort(key=lambda h: (-len(h["header"]), h["score"]))
summary = {"n_tests": N, "nA": nA, "nB": nB - nA, "nC": N - nB, "hard": HARD, "soft": SOFT[:50],
           "n_soft": len(SOFT), "top20": TOP.items(), "headers": HEADERS[:200], "n_headers": len(HEADERS),
           "alphas5": len(ALPHAS), "sq3": SQ3}
log({"kind": "summary", **summary})
json.dump(summary, open(os.path.join(SP, "bifid_phrases_periods_summary.json"), "w"), indent=1)
print(json.dumps({k: v for k, v in summary.items() if k not in ("top20", "headers", "soft")}, indent=1))
print("TOP5:", json.dumps(summary["top20"][:5], indent=1))
print("HEADERS (>=6):", [h for h in HEADERS if len(h["header"]) >= 6][:30])
print("n_headers", len(HEADERS), "n_soft", len(SOFT), "n_hard", len(HARD))
