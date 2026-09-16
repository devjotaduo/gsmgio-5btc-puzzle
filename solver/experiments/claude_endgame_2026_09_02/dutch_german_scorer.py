# -*- coding: utf-8 -*-
"""dutch_german_scorer — re-pontuar decodificações de faed/dbbi com quadgramas de HOLANDÊS e ALEMÃO.

Hipótese (falsificável, espaço finito): o criador é holandês/flamengo (GSMG.io holandesa; "the Dutch
turned carrots orange"; Jrk Bgrt). Toda a triagem anterior usou quadgramas de INGLÊS, então um plaintext
em holandês (ou alemão) em qualquer decodificação de faed/dbbi — Bifid CANON (BTCSEED, REST, canal ímpar),
checkerboard com alfabetos 3.2.2/CANON/A-Z/keyed, hill-climb do alfabeto do checkerboard, substituição
mono sobre REST/canal ímpar — teria sido descartada como ruído. Se verdadeiro: alguma saída supera o
limiar nulo nl/de (hill-climb sobre texto embaralhado) e vira senha/privkey; e traduções nl/de dos
tokens abrem SMALL/COSMIC/TAIL32 (KDF SHA256) ou geram a privkey (brainwallet).
"""
import sys, os, re, json, math, time, random, pickle, unicodedata, hashlib
from collections import Counter
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = os.path.join(SP, "dutch_german_scorer.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)
log({"hypothesis": __doc__.strip()})
t0 = time.time()
n_tests = 0; hard = []; soft = []; best = {"score": -99}

# ---------------------------------------------------------------- modelos de quadgramas nl / de
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; IDX = {c: i for i, c in enumerate(A)}
def fold(t):
    """Remove diacríticos (ë→E, ü→U, ß→SS), mantém só A-Z."""
    t = t.replace("ß", "ss").replace("ẞ", "SS")
    t = unicodedata.normalize("NFKD", t)
    return re.sub(r"[^A-Z]", "", t.upper())
def build_model(lang):
    cache = os.path.join(SP, f"quad_{lang}.pkl")
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    raw = open(os.path.join(SP, "corpus", f"{lang}.txt"), encoding="utf-8").read()
    t = fold(raw)
    cut = int(len(t) * 0.9)            # 10% final = held-out para calibração
    train, held = t[:cut], t[cut:]
    counts = Counter(train[i:i + 4] for i in range(len(train) - 3))
    total = sum(counts.values())
    floor = math.log10(0.01 / total)
    tab = [floor] * (26 ** 4)
    for q, c in counts.items():
        tab[((IDX[q[0]] * 26 + IDX[q[1]]) * 26 + IDX[q[2]]) * 26 + IDX[q[3]]] = math.log10(c / total)
    pickle.dump((tab, floor, held), open(cache, "wb"))
    return tab, floor, held
MODELS = {}
for lang in ("nl", "de"):
    tab, floor, held = build_model(lang)
    MODELS[lang] = (tab, floor, held)
    print(lang, "modelo ok; held-out", len(held), "letras", flush=True)
import numpy as np
NPTAB = {lang: np.asarray(MODELS[lang][0], dtype=np.float32) for lang in ("nl", "de")}
NPW = np.array([17576, 676, 26, 1], dtype=np.int64)
# lexico nl/de a partir do corpus (palavras >=6 letras, freq >=4) -> 2o oraculo de legibilidade
def build_lex(lang):
    raw = open(os.path.join(SP, "corpus", f"{lang}.txt"), encoding="utf-8").read()
    c = Counter()
    for w in re.findall(r"[A-Za-zÀ-ɏ]+", raw):
        w = fold(w)
        if 6 <= len(w) <= 12: c[w] += 1
    return {w for w, k in c.items() if k >= 4}
LEX = {lang: build_lex(lang) for lang in ("nl", "de")}
def lex_hits(lang, text, minlen=6):
    t = fold(text); S = LEX[lang]; out = []
    for L in range(minlen, 13):
        for i in range(len(t) - L + 1):
            w = t[i:i + L]
            if w in S: out.append(w)
    return out
def score_tab(tab, floor, idxs):
    n = len(idxs)
    if n < 4: return floor
    s = 0.0
    for i in range(n - 3):
        s += tab[((idxs[i] * 26 + idxs[i + 1]) * 26 + idxs[i + 2]) * 26 + idxs[i + 3]]
    return s / (n - 3)
def sc(lang, text):
    tab, floor, _ = MODELS[lang]
    return score_tab(tab, floor, [IDX[c] for c in fold(text) if c in IDX])
def sc_en(text): return G.english_score(fold(text))
def scores(text): return {"nl": round(sc("nl", text), 3), "de": round(sc("de", text), 3), "en": round(sc_en(text), 3)}

# ---------------------------------------------------------------- calibração
EN_SAMPLE = ("The Netherlands is a country located in northwestern Europe with overseas territories in the "
             "Caribbean. It is the largest of the four constituent countries of the Kingdom of the Netherlands. "
             "The Netherlands consists of twelve provinces; it borders Germany to the east and Belgium to the south, "
             "with a North Sea coastline to the north and west. The country's official language is Dutch, with West "
             "Frisian as a secondary official language in the province of Friesland. Dutch, English, and Papiamento "
             "are official in the Caribbean territories. Netherlands literally means lower countries in reference to "
             "its low elevation and flat topography, with nearly a quarter of the land below sea level. Most of the "
             "areas below sea level are the result of land reclamation that began in the 14th century. In the "
             "Republican period, which began in 1588, the Netherlands entered a unique era of political, economic, "
             "and cultural greatness, ranked among the most powerful and influential in Europe and the world; this "
             "period is known as the Dutch Golden Age. During this time, its trading companies, the Dutch East India "
             "Company and the Dutch West India Company, established colonies and trading posts all over the world.")
rng = random.Random(42)
def chunks(t, L=300, k=20):
    t = fold(t); step = max(1, (len(t) - L) // k)
    return [t[i:i + L] for i in range(0, len(t) - L, step)][:k]
def stats(xs): return {"mean": round(sum(xs) / len(xs), 3), "min": round(min(xs), 3), "max": round(max(xs), 3)}
calib = {}
held_nl = MODELS["nl"][2]; held_de = MODELS["de"][2]
for lang in ("nl", "de"):
    calib[lang] = {
        "nl_text": stats([sc(lang, c) for c in chunks(held_nl)]),
        "de_text": stats([sc(lang, c) for c in chunks(held_de)]),
        "en_text": stats([sc(lang, c) for c in chunks(EN_SAMPLE, 300, 5)]),
        "random_uniform": stats([sc(lang, "".join(rng.choice(A) for _ in range(300))) for _ in range(20)]),
        "shuffled_nl": stats([sc(lang, "".join(rng.sample(c, len(c)))) for c in chunks(held_nl, 300, 20)]),
        "BIF_canon": round(sc(lang, G.bif_full()), 3),
    }
calib["en_scorer"] = {"nl_text": stats([sc_en(c) for c in chunks(held_nl)]),
                      "de_text": stats([sc_en(c) for c in chunks(held_de)]),
                      "en_text": stats([sc_en(c) for c in chunks(EN_SAMPLE, 300, 5)]),
                      "random_uniform": stats([sc_en("".join(rng.choice(A) for _ in range(300))) for _ in range(20)]),
                      "shuffled_nl": stats([sc_en("".join(rng.sample(c, len(c)))) for c in chunks(held_nl, 300, 20)])}
log({"calibration": calib})
print(json.dumps(calib, indent=1), flush=True)
# limiar para saídas NÃO otimizadas: texto real nl fica ≥ ~-3.6; ruído/aleatório ≤ ~-6.
THR_FIXED = {lang: calib[lang]["nl_text" if lang == "nl" else "de_text"]["min"] - 0.6 for lang in ("nl", "de")}

# ---------------------------------------------------------------- oráculo duro sobre candidatos
def oracle(pt, how, scs):
    """Candidato legível -> senha AES (KDF sha256) nos 3 blobs + brainwallet."""
    global n_tests
    rec = {"cand": how, "scores": scs, "head": pt[:100]}
    for pw in (pt, pt.lower(), G.shahex(pt), G.shahex(pt.lower())):
        for b in ("SMALL", "COSMIC", "TAIL32"):
            n_tests += 1
            for kdf, p in G.aes_try(pw, b, kdf="sha256"):
                item = {"pw": pw[:80], "blob": b, "kdf": "sha256", "pt_hex": p.hex(), **rec}
                (hard if G.semantic(p) else soft).append(item)
    for k in (G.sha(pt.encode()), G.sha(pt.lower().encode())):
        n_tests += 1
        r = G.priv_hit(k)
        if r: hard.append({"privkey": k.hex(), "addr": r, **rec})
    log(rec)
def consider(pt, how, thr_extra=0.0):
    """Registra melhor e dispara oráculo se nl/de acima do limiar de saída fixa."""
    global best
    s = scores(pt)
    m = max(s["nl"], s["de"])
    if m > best["score"]: best = {"score": m, "scores": s, "text": pt[:160], "how": how}
    if s["nl"] > THR_FIXED["nl"] + thr_extra or s["de"] > THR_FIXED["de"] + thr_extra:
        oracle(pt, how, s)
        return True
    return False

# ---------------------------------------------------------------- (2a) Bifid CANON re-pontuado
BIF = G.bif_full(); REST = BIF[7:]; ODD = BIF[1::2]; EVEN = BIF[0::2]
bif_rescore = {}
for name, t in (("BIF_full", BIF), ("REST563", REST), ("ODD285", ODD), ("EVEN285", EVEN), ("ODD_REST", REST[1::2]), ("EVEN_REST", REST[0::2])):
    n_tests += 1
    bif_rescore[name] = scores(t); consider(t, f"bifid_canon|{name}")
log({"bifid_canon_rescore": bif_rescore, "thr_fixed": THR_FIXED})
print("bifid rescore", bif_rescore, flush=True)

# ---------------------------------------------------------------- (2b) checkerboard com alfabetos fixos
alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
AZ25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
KEYS = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "sha256", "ourfirsthintisyourlastcommand",
        "anstoo", "shabef", "salphaseion", "cosmicduality", "yinyang", "yellowblueprimes", "hashthetext", "halfandbetterhalf",
        # chaves em holandês (criador holandês poderia keyar em nl)
        "matrixsomlijst", "laatstewoordenvoordekeuzevandearchitect", "ditwachtwoord", "verlossing", "kosmischedualiteit",
        "wederhelft", "hetzaadisgeplant", "volghetwittekonijn", "wachtwoord", "sleutel", "priemgetallen", "geelblauw",
        "nederland", "gsmg", "bitcoin", "jrkbgrt", "erlosung", "schlussel", "kosmischedualitat"]
def keyed25(k): return G.keyed_alphabet(k, AZ25, merge_j=True)
FIXED_ALPHAS = {"alpha322_25": alpha322.replace(".", "")[:25], "CANON": G.CANON, "AZ25": AZ25}
for k in KEYS: FIXED_ALPHAS[f"key:{k}"] = keyed25(k)
TEXTS = {"faed": G.FAED, "faed_noprefix": G.FAED[4:], "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:], "dbbi": G.DBBI}
D1 = {k: G.digits(v) for k, v in TEXTS.items()}
ESC72 = [(a, b) for a in range(1, 10) for b in range(1, 10) if a != b]
n_cb = 0; best_cb = {"nl": (-99, ""), "de": (-99, "")}
for an, alpha in FIXED_ALPHAS.items():
    assert len(alpha) == 25 and len(set(alpha)) == 25, (an, alpha)
    for tn, digs in D1.items():
        for e in ESC72:
            n_tests += 1; n_cb += 1
            pt = G.checkerboard_decode(digs, alpha, e, "123456789")
            hit = consider(pt, f"cb|{an}|{tn}|esc{e}")
            for lang in ("nl", "de"):
                s = sc(lang, pt)
                if s > best_cb[lang][0]: best_cb[lang] = (round(s, 3), f"{an}|{tn}|esc{e}|{pt[:60]}")
# layout 3.2.2 (universo 0-9, i->0, 28 células, escapes ordenados)
D0 = {k: [0 if d == 9 else d for d in v] for k, v in D1.items()}
ESC90 = [(a, b) for a in range(10) for b in range(10) if a != b]
for tn, digs in D0.items():
    for e in ESC90:
        n_tests += 1; n_cb += 1
        pt = G.checkerboard_decode(digs, alpha322, e, "0123456789")
        consider(pt, f"cb322|{tn}|esc{e}|u0-9")
log({"checkerboard_fixed": {"n": n_cb, "best": best_cb,
     "lex_best": {l: lex_hits(l, best_cb[l][1].split("|")[-1])[:8] for l in ("nl", "de")}}})
print("checkerboard fixo", n_cb, best_cb, flush=True)

# ---------------------------------------------------------------- hill-climb genérico (mono-sub em sequência de índices)
def hill_climb(seq, nsym, lang, restarts=10, iters=6000, patience=600, seed=0):
    """seq: lista de indices 0..nsym-1. Chave key[sym] = letra A-Z (swap tambem com letras fora do pool,
    logo o subconjunto de 25 letras usadas tambem e otimizado). Score = quadgrama nl/de por letra."""
    T = NPTAB[lang]; floor = MODELS[lang][1]
    n = len(seq)
    if n < 4: return floor, "", list(range(26))
    S = np.asarray(seq, dtype=np.int64)
    Q = np.stack([S[0:n - 3], S[1:n - 2], S[2:n - 1], S[3:n]], axis=1)
    inv = 1.0 / (n - 3)
    rng = random.Random(seed)
    best_s, best_key = -1e9, None
    for r in range(restarts):
        key = list(range(26)); rng.shuffle(key)
        ka = np.asarray(key, dtype=np.int64)
        cur = float(T[(ka[Q] * NPW).sum(1)].sum()) * inv
        since = 0
        for it in range(iters):
            a = rng.randrange(nsym); b = rng.randrange(26)
            if a == b: continue
            ka[a], ka[b] = ka[b], ka[a]
            s = float(T[(ka[Q] * NPW).sum(1)].sum()) * inv
            if s > cur: cur = s; since = 0
            else:
                ka[a], ka[b] = ka[b], ka[a]; since += 1
                if since >= patience: break
        if cur > best_s: best_s, best_key = cur, ka.tolist()
    return best_s, "".join(A[best_key[s]] for s in seq), best_key

def cb_cells(digs, escapes, universe="123456789"):
    """Sequência de índices de célula (0..24) do checkerboard — independente do alfabeto."""
    top = [int(d) for d in universe if int(d) not in escapes]
    cell = {}
    k = 0
    for d in top: cell[(d,)] = k; k += 1
    for e in escapes:
        for d in universe: cell[(e, int(d))] = k; k += 1
    out = []; i = 0
    while i < len(digs):
        d = digs[i]
        if d in escapes:
            if i + 1 < len(digs): out.append(cell[(d, digs[i + 1])]); i += 2
            else: break
        else: out.append(cell[(d,)]); i += 1
    return out
def cb_encode(text, alphabet, escapes, universe="123456789", rng=None):
    """Codifica texto (25 letras) em dígitos do checkerboard — para o controle positivo."""
    top = [int(d) for d in universe if int(d) not in escapes]
    enc = {}; k = 0
    for d in top: enc[alphabet[k]] = [d]; k += 1
    for e in escapes:
        for d in universe: enc[alphabet[k]] = [e, int(d)]; k += 1
    out = []
    for c in text:
        if c in enc: out += enc[c]
    return out

# ---------------------------------------------------------------- (2c) controles do hill-climb (nl)
NL_CTRL = fold("De Nederlanden zijn een land in het noordwesten van Europa met overzeese gebieden in het Caribisch gebied. "
               "Het is het grootste van de vier landen van het Koninkrijk der Nederlanden. Nederland bestaat uit twaalf "
               "provincies en grenst aan Duitsland in het oosten en aan Belgie in het zuiden, met een kustlijn aan de "
               "Noordzee in het noorden en westen. De officiele taal van het land is het Nederlands. Nederland betekent "
               "letterlijk lage landen, verwijzend naar de lage ligging en het vlakke landschap, waarbij bijna een kwart "
               "van het land onder de zeespiegel ligt. In de zeventiende eeuw beleefde de Republiek een periode van grote "
               "politieke economische en culturele bloei die bekend staat als de Gouden Eeuw.").replace("J", "I")
NL_CTRL = "".join(c for c in NL_CTRL if c in AZ25)
ctrl = {}
# controle 1: checkerboard — cifra texto nl com alfabeto keyed e escapes (3,7), recupera via hill-climb
alpha_c = keyed25("wederhelft"); esc_c = (3, 7)
digs_c = cb_encode(NL_CTRL[:400], alpha_c, esc_c)
seq_c = cb_cells(digs_c, esc_c)
s_c, pt_c, _ = hill_climb(seq_c, 25, "nl", restarts=6, iters=6000, seed=1)
match_c = sum(a == b for a, b in zip(pt_c, NL_CTRL)) / len(pt_c)
ctrl["cb_nl"] = {"digits": len(digs_c), "score": round(s_c, 3), "match": round(match_c, 3), "head": pt_c[:60]}
# controle 2: substituição mono sobre 285 letras de nl
perm = list(AZ25); rng.shuffle(perm); tbl = {AZ25[i]: perm[i] for i in range(25)}
ct_m = "".join(tbl[c] for c in NL_CTRL[:285]); seq_m = [AZ25.index(c) for c in ct_m]
s_m, pt_m, _ = hill_climb(seq_m, 25, "nl", restarts=6, iters=6000, seed=2)
ctrl["mono_nl_285"] = {"score": round(s_m, 3), "match": round(sum(a == b for a, b in zip(pt_m, NL_CTRL)) / len(pt_m), 3), "head": pt_m[:60]}
# nulo: hill-climb sobre sequências ALEATÓRIAS (i.i.d. 25 símbolos) de 285 e 400 (teto de sobre-ajuste)
null = {}
for L in (91, 285, 400, 563):
    vals = []
    for r in range(3):
        seqr = [rng.randrange(25) for _ in range(L)]
        for lang in ("nl", "de"):
            s_r, _, _ = hill_climb(seqr, 25, lang, restarts=4, iters=6000, seed=10 + r)
            vals.append((lang, round(s_r, 3)))
    null[L] = {"nl": max(v for l, v in vals if l == "nl"), "de": max(v for l, v in vals if l == "de")}
# nulo específico: hill-climb sobre faed EMBARALHADO (mantém unigrama), escapes (3,7)
faed_sh = G.digits(G.FAED); rng.shuffle(faed_sh)
seq_sh = cb_cells(faed_sh, (3, 7))
null["faed_shuffled_cb"] = {lang: round(hill_climb(seq_sh, 25, lang, restarts=4, iters=6000, seed=99)[0], 3) for lang in ("nl", "de")}
ctrl["null_hillclimb_max"] = null
log({"controls": ctrl})
print("controles", json.dumps(ctrl), flush=True)
def thr_hc(L, lang):
    # limiar = maior nulo de tamanho <= L (mais curto sobre-ajusta mais) + margem 0.15
    ks = [k for k in null if isinstance(k, int)]
    k = max([k for k in ks if k <= L] or [min(ks)])
    return max(null[k][lang], null["faed_shuffled_cb"][lang]) + 0.15

# ---------------------------------------------------------------- (2d) hill-climb do alfabeto do checkerboard (faed, dbbi)
ESC36 = [(a, b) for a in range(1, 10) for b in range(a + 1, 10)]
hc_res = []
for tn in ("faed", "dbbi"):
    digs = D1[tn]
    for e in ESC36:
        seq = cb_cells(digs, e)
        for lang in ("nl", "de"):
            n_tests += 1
            s, pt, key = hill_climb(seq, 25, lang, restarts=10, iters=6000, seed=hash((tn, e, lang)) & 0xffff)
            rec = {"how": f"cb_hc|{tn}|esc{e}|{lang}", "L": len(seq), "score": round(s, 3), "thr": round(thr_hc(len(seq), lang), 3), "head": pt[:60], "lex": lex_hits(lang, pt)[:8]}
            hc_res.append(rec)
            if s > best["score"]: best = {"score": round(s, 3), "scores": scores(pt), "text": pt[:160], "how": rec["how"]}
            if s > rec["thr"]:
                rec["ABOVE_NULL"] = True; oracle(pt, rec["how"], scores(pt))
            log(rec)
    print("hc", tn, "feito", round(time.time() - t0), "s", flush=True)
top_hc = sorted(hc_res, key=lambda r: r["score"] - r["thr"], reverse=True)[:6]
log({"cb_hillclimb_top": top_hc})

# ---------------------------------------------------------------- (2e) substituição mono sobre REST (563) e canal ímpar (285)
mono_res = []
for name, t in (("REST563", REST), ("ODD285", ODD), ("ODD_REST", REST[1::2])):
    syms = sorted(set(t)); seq = [syms.index(c) for c in t]
    for lang in ("nl", "de"):
        n_tests += 1
        s, pt, _ = hill_climb(seq, len(syms), lang, restarts=10, iters=6000, seed=7)
        rec = {"how": f"mono_hc|{name}|{lang}", "L": len(seq), "nsym": len(syms), "score": round(s, 3), "thr": round(thr_hc(len(seq), lang), 3), "head": pt[:60], "lex": lex_hits(lang, pt)[:8]}
        mono_res.append(rec)
        if s > best["score"]: best = {"score": round(s, 3), "scores": scores(pt), "text": pt[:160], "how": rec["how"]}
        if s > rec["thr"]:
            rec["ABOVE_NULL"] = True; oracle(pt, rec["how"], scores(pt))
        log(rec)
log({"mono_hillclimb": mono_res})
print("mono hc", json.dumps(mono_res), flush=True)

# ---------------------------------------------------------------- (3) senhas em holandês / alemão
NL_PHRASES = [
 "laatste woorden voor de keuze van de architect", "laatste woorden voor de architectkeuze", "laatste woorden voor architect keuze",
 "laatste woorden voor de keuze", "laatstewoordenvoorarchikeuze", "dit wachtwoord", "dit is het wachtwoord", "de toekomst is van ons",
 "de toekomst behoort ons toe", "het zaad is geplant", "het zaadje is geplant", "volg het witte konijn", "verlossing", "redding",
 "zaligheid", "kosmische dualiteit", "yin yang", "yin en yang", "hash de tekst", "onze eerste hint is je laatste commando",
 "onze eerste hint is jouw laatste commando", "onze eerste aanwijzing is je laatste opdracht", "onze eerste hint is je laatste opdracht",
 "antwoord ook", "sha256 antwoord ook", "matrix som lijst", "matrix somlijst", "matrixsomlijst", "keuze", "deur", "bron", "de bron",
 "de deur", "de keuze", "de deur aan je rechterkant leidt naar de bron", "de bron en de verlossing van zion", "halve en betere helft",
 "helft en betere helft", "de helft en de wederhelft", "wederhelft", "mijn wederhelft", "betere helft", "sleutel", "privesleutel",
 "prive sleutel", "geheime sleutel", "de sleutel", "wachtwoord", "geel blauw priemgetallen", "geelblauwpriemgetallen", "priemgetal",
 "priemgetallen", "rozen zijn wit maar vaak rood", "geel heeft een nummer en blauw ook", "het is voor je ogen maar je ziet het niet",
 "het staat voor je neus", "voor je ogen", "de matrix heeft je", "leven en dood", "de spiegel van leven en dood", "paarse pil",
 "rode pil", "blauwe pil", "wereldwijd mijn generatie ondersteunen", "oorzakelijkheid", "causaliteit", "de bloem bloeit door wat een betonnen oppervlak lijkt",
 "voer in", "enter", "ken uzelf", "ken jezelf", "wortels", "de nederlanders maakten wortels oranje", "oranje", "oranje boven",
 "ik ben de architect", "de architect", "het orakel", "de bron code", "terug naar de bron", "eerste of nul", "hallo wereld",
 "de laatste stap is een cadeau", "geef het weg", "het antwoord", "salphaseion", "sal fase ion", "zout fase ion", "ons eerste hint",
 "laatste commando", "jouw laatste commando", "je laatste commando", "priem", "primer", "nul", "een", "twee", "honderdveertig",
 "de matrix heeft jou", "wakker worden neo", "klop klop neo", "volg het witte konijn neo",
]
DE_PHRASES = [
 "letzte worte vor der wahl des architekten", "letzte worte vor der architektenwahl", "dieses passwort", "die zukunft gehoert uns",
 "die zukunft gehört uns", "der samen ist gepflanzt", "die saat ist gesaet", "folge dem weissen kaninchen", "folge dem weißen kaninchen",
 "erloesung", "erlösung", "kosmische dualitaet", "kosmische dualität", "unser erster hinweis ist dein letzter befehl", "antwort auch",
 "schluessel", "schlüssel", "privater schluessel", "haelfte und bessere haelfte", "bessere haelfte", "bessere hälfte", "tuer", "tür",
 "quelle", "wahl", "primzahl", "primzahlen", "gelb blau primzahlen", "matrix summen liste", "matrixsummenliste", "passwort",
 "leben und tod", "erkenne dich selbst", "die matrix hat dich", "wach auf neo",
]
def forms(p):
    out = {p, p.replace(" ", ""), p.lower().replace(" ", ""), p.upper().replace(" ", "")}
    f = unicodedata.normalize("NFKD", p.replace("ß", "ss")).encode("ascii", "ignore").decode()
    out |= {f, f.replace(" ", "")}
    out |= {G.shahex(x) for x in list(out)}
    return out
n_pw = 0; n_bw = 0
for p in NL_PHRASES + DE_PHRASES:
    for pw in forms(p):
        for b in ("SMALL", "COSMIC", "TAIL32"):
            n_tests += 1; n_pw += 1
            for kdf, pt in G.aes_try(pw, b, kdf="sha256"):
                item = {"pw": pw, "blob": b, "kdf": "sha256", "pt_hex": pt.hex(), "src": "nl_de_password", "printable": round(G.printable(pt), 3)}
                (hard if G.semantic(pt) else soft).append(item)
    n_tests += 36; n_bw += 36            # phrase_priv: 6 formas x 2 (\n) x 3 hashes
    for r in G.phrase_priv(p): hard.append({"brainwallet": p, "hit": r})
    for fp in forms(p):                  # sha256 das formas dobradas (ASCII) como privkey
        n_tests += 1
        r = G.priv_hit(G.sha(fp.encode()))
        if r: hard.append({"brainwallet_form": fp, "hit": r})
log({"passwords": {"phrases": len(NL_PHRASES) + len(DE_PHRASES), "aes_tests": n_pw, "brainwallet_tests": n_bw}})

summary = {"n_tests": n_tests, "hard": hard, "soft": soft, "best": best, "calibration": calib, "controls": ctrl,
           "cb_hillclimb_top": top_hc, "mono_hillclimb": mono_res, "bifid_canon_rescore": bif_rescore, "secs": round(time.time() - t0)}
log({"summary": summary})
json.dump(summary, open(os.path.join(SP, "dutch_german_scorer_summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in summary.items() if k not in ("calibration",)}, ensure_ascii=False, indent=1), flush=True)
