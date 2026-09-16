# -*- coding: utf-8 -*-
"""
Cosmic Book Attack — candidatos derivados do livro "Cosmic Duality"
(Time-Life, Mysteries of the Unknown, 1991), a pista "scary specific"
(foto de pagina do livro, pagina sobre "Life and Death").

F1 — ANSWER candidates do livro -> senhas AES / privkey:
  (a) titulos de capitulos/essays verbatim e normalizados
  (b) frases das passagens "life and death" (contexto +-2 frases)
  (c) essay "The Unity of Opposites": cada frase, n-gramas 2-8 palavras
      (frases <=12 palavras) e o essay inteiro concatenado
  (d) frases da caption yin-yang ("yin and yang", "dragons", "pinwheel")
  (e) cruzamento com tokens classicos do puzzle (yinyang, salphaseion, ...)
  Normalizacoes: verbatim / lower / lower-sem-espacos-pontuacao / TitleCase-sem-espacos.
  Por variante: aes_open(cand), aes_open(sha256hex(cand)), check_privkey(sha256(cand)).

F2 — Keystream do livro sobre faed -> straddling checkerboard:
  passagens fortes -> letras a-z -> (1-26 | 0-25) -> mod 9 -> +- keystream
  ciclica sobre faed (a=1..i=9 | a=0..8) -> decode checkerboard com os
  36 pares de escape x alfabetos-chave -> score quadgramas; >= -5.0 => oraculos.

F3 — Pagina exata (foto do barrystyle = 1 pagina): paginas do essay Unity of
  Opposites e as que contem "life and death"/"yin and yang"; texto da pagina
  (com/sem whitespace) -> sha256 -> aes_open; palavras da pagina -> F1.

Log: _work/cosmic_book_attack.jsonl. Solve -> solver/out/SOLVED.json.
"""
import os, re, sys, json, time, hashlib, itertools

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import oracles as O
from scorer import Scorer
from checkerboard import decode as cb_decode, ALPHA25

TXT = os.path.join(ROOT, "_work", "cosmic_duality.txt")
LOG = os.path.join(ROOT, "_work", "cosmic_book_attack.jsonl")
OUTDIR = os.path.join(HERE, "out")
os.makedirs(OUTDIR, exist_ok=True)

SC = Scorer()
LOGF = open(LOG, "a", encoding="utf-8")

def log(rec):
    rec["ts"] = time.strftime("%H:%M:%S")
    LOGF.write(json.dumps(rec, ensure_ascii=False) + "\n")
    LOGF.flush()

SOLVED = None
def solved(payload):
    global SOLVED
    SOLVED = payload
    json.dump(payload, open(os.path.join(OUTDIR, "SOLVED.json"), "w"),
              indent=2, ensure_ascii=False)
    log({"kind": "SOLVED", **{k: str(v)[:200] for k, v in payload.items()}})
    print("\n!!! SOLVED -> solver/out/SOLVED.json")

# ---------------- texto do livro ----------------
RAW = open(TXT, encoding="utf-8", errors="replace").read()
PAGES = RAW.split("\f")

def clean(t):
    """Colapsa whitespace; OCR tem hifens de quebra, mantemos verbatim tambem."""
    return re.sub(r"\s+", " ", t).strip()

def sentences(t):
    t = clean(t)
    # split simples em frases
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z\"'])", t)
    return [p.strip() for p in parts if len(p.strip()) >= 3]

# essay "The Unity of Opposites" = inicio ate o capitulo 1
m_ch1 = re.search(r"(?i)lUies As Old As Time|Dualities As Old As Time", RAW)
ESSAY = RAW[:m_ch1.start()] if m_ch1 else RAW[:11000]
# remove front matter (capa/TOC): essay comeca perto do primeiro "life and death"
m_start = re.search(r"(?i)unity of opposites", ESSAY)
ESSAY_BODY = ESSAY[m_start.start():] if m_start else ESSAY[800:]

TITLES = [
    "Cosmic Duality", "The Unity of Opposites", "Dualities As Old As Time",
    "The Battle of the Sexes", "In the Grasp of Ageless Evil",
    "The Triumph of Good", "Life and Death", "Mysteries of the Unknown",
    "Yin and Yang", "The Yin and the Yang",
]

TOKENS = ["yinyang", "salphaseion", "cosmicduality", "hashthetext",
          "matrixsumlist", "shabefanstoo"]

def norms(cand):
    out = {cand, cand.lower()}
    out.add(re.sub(r"[^a-z0-9]", "", cand.lower()))
    out.add(re.sub(r"[^A-Za-z0-9]", "", cand.title()))
    return {x for x in out if x}

# ---------------- F1 ----------------
def oracle_pw(pw, tag, stats):
    """Testa uma senha em todos os oraculos. Retorna True se solve."""
    stats["pw_tested"] += 1
    h = O.aes_open(pw)
    if h:
        solved({"kind": "aes_open", "pw": pw, "tag": tag, "hits": h}); return True
    hh = hashlib.sha256(pw.encode()).hexdigest()
    h = O.aes_open(hh)
    if h:
        solved({"kind": "aes_open_sha256hex", "pw": pw, "tag": tag, "hits": h}); return True
    r = O.check_privkey(hashlib.sha256(pw.encode()).digest())
    if r:
        solved({"kind": "privkey_sha256", "pw": pw, "tag": tag, "hit": r}); return True
    return False

def f1_candidates():
    """Gera (candidato_base, tag) sem normalizacao nem cruzamento."""
    seen = set()
    def emit(c, tag):
        c = clean(c) if " " in c or "\n" in c else c
        if not c or len(c) < 3 or c in seen:
            return
        seen.add(c)
        yield (c, tag)
    # (a) titulos
    for t in TITLES:
        yield from emit(t, "title")
    # (b) passagens life and death (+-2 frases)
    low = RAW.lower()
    for m in re.finditer(r"life and death", low):
        ctx = RAW[max(0, m.start() - 1200):m.start() + 1200]
        sents = sentences(ctx)
        # acha a frase que contem a mencao
        for i, s in enumerate(sents):
            if "life and death" in s.lower():
                for j in range(max(0, i - 2), min(len(sents), i + 3)):
                    yield from emit(sents[j], "life_death_sent")
                yield from emit(" ".join(sents[max(0, i - 2):i + 3]), "life_death_ctx")
    # (c) essay Unity of Opposites
    esents = sentences(ESSAY_BODY)
    for s in esents:
        yield from emit(s, "essay_sent")
        words = re.findall(r"[A-Za-z']+", s)
        if len(words) <= 12:
            for n in range(2, 9):
                for k in range(0, len(words) - n + 1):
                    yield from emit(" ".join(words[k:k + n]), f"essay_ngram{n}")
    yield from emit(clean(ESSAY_BODY), "essay_full")
    yield from emit(re.sub(r"[^A-Za-z]", "", ESSAY_BODY), "essay_full_alpha")
    # (d) caption yin-yang
    for m in re.finditer(r"(?i)dragons|pinwheel|yin and yang", RAW):
        ctx = RAW[max(0, m.start() - 600):m.start() + 600]
        for s in sentences(ctx):
            if re.search(r"(?i)yin|yang|dragon|pinwheel", s):
                yield from emit(s, "yinyang_caption")

def crossed(base_iter):
    """(e) cruzamento com tokens classicos."""
    for cand, tag in base_iter:
        yield cand, tag
        base_compact = re.sub(r"[^a-z0-9]", "", cand.lower())
        if len(base_compact) > 60:
            continue  # cruzamento so para candidatos curtos
        for tok in TOKENS:
            yield cand + tok, f"{tag}+{tok}"
            yield base_compact + tok, f"{tag}compact+{tok}"
        yield "shabef" + base_compact + "anstoo", f"shabef+{tag}+anstoo"

def run_f1(extra_candidates=()):
    stats = {"pw_tested": 0}
    nbase = 0
    best = []
    gen = itertools.chain(f1_candidates(), extra_candidates)
    for cand, tag in crossed(gen):
        for pw in norms(cand):
            nbase += 1
            if SOLVED:
                return stats, nbase
            if oracle_pw(pw, tag, stats):
                return stats, nbase
    log({"kind": "F1_done", "variants": nbase, **stats})
    print(f"[F1] {nbase} variantes de senha testadas ({stats['pw_tested']} oracles)")
    return stats, nbase

# ---------------- F2 ----------------
KEYED_ALPHABETS = []
def _keyed25(key):
    seen = []
    for ch in (key + "ABCDEFGHIKLMNOPQRSTUVWXYZ"):  # sem J
        ch = ch.upper()
        if ch == "J":
            ch = "I"
        if ch in ALPHA25 and ch not in seen:
            seen.append(ch)
    return "".join(seen[:25])

KEYED_ALPHABETS.append(_keyed25("DBIFHCEGA"))
KEYED_ALPHABETS.append(_keyed25("FUBCDORA.LETHINGKYMVPS.JQZXW".replace(".", "")))

def f2_passages():
    yield "essay_full", clean(ESSAY_BODY)
    for m in re.finditer(r"(?i)life and death", RAW):
        yield "life_death", clean(RAW[max(0, m.start() - 800):m.start() + 800])
    for m in re.finditer(r"(?i)dragons guard the pinwheel", RAW):
        yield "yinyang_caption", clean(RAW[max(0, m.start() - 200):m.start() + 600])

def keystream_digits(text, base):
    """letras a-z -> 1-26 (base=1) ou 0-25 (base=0), mod 9 -> dominio 0..8."""
    ds = []
    for ch in text.lower():
        if "a" <= ch <= "z":
            v = (ord(ch) - 96) if base == 1 else (ord(ch) - 97)
            ds.append(v % 9)
    return ds

def apply_keystream(faed_ds, ks, sign):
    """Aritmetica no dominio 0..8 (faed ja convertido)."""
    if not ks:
        return faed_ds
    return [(d + sign * ks[i % len(ks)]) % 9 for i, d in enumerate(faed_ds)]

def hard_oracles_pt(pt, tag):
    for s in {pt, pt.lower()}:
        for f in (s, hashlib.sha256(s.encode()).hexdigest()):
            h = O.aes_open(f)
            if h:
                solved({"kind": "aes_open", "via": "F2", "tag": tag, "pw": f[:64], "hits": h}); return True
        r = O.check_privkey(hashlib.sha256(s.encode()).digest())
        if r:
            solved({"kind": "privkey", "via": "F2", "tag": tag, "hit": r}); return True
    return False

def run_f2():
    faed = O.sources()["faed"]
    faed_variants = {
        "a1": [ord(c) - 97 for c in faed],        # a=1..i=9 -> dominio 0..8
        "a0": [ord(c) - 97 for c in faed],        # a=0..i=8 -> dominio 0..8 (mesmo shape; diff no ks base)
    }
    # decode checkerboard espera 1..9: somamos 1 na saida do keystream
    pairs = [(e1, e2) for e1 in range(1, 10) for e2 in range(e1 + 1, 10)]
    best = []
    n = 0
    for ptag, ptext in f2_passages():
        for base in (0, 1):
            ks = keystream_digits(ptext, base)
            for ftag, fds in faed_variants.items():
                for sign in (1, -1):
                    ds = [d + 1 for d in apply_keystream(fds, ks, sign)]
                    for perm in KEYED_ALPHABETS:
                        for e1, e2 in pairs:
                            pt = cb_decode(ds, perm, e1, e2)
                            sc = SC(pt)
                            n += 1
                            best.append((sc, ptag, base, ftag, sign, e1, e2, perm[:6], pt))
                            if sc >= -5.0:
                                log({"kind": "F2_candidate", "score": round(sc, 3),
                                     "passage": ptag, "base": base, "faed": ftag,
                                     "sign": sign, "esc": [e1, e2], "alpha": perm,
                                     "plaintext": pt})
                                if hard_oracles_pt(pt, f"F2/{ptag}/{ftag}"):
                                    return n, best
    best.sort(key=lambda x: -x[0])
    log({"kind": "F2_done", "decodes": n,
         "top": [{"score": round(b[0], 3), "passage": b[1], "faed": b[3],
                  "sign": b[4], "esc": [b[5], b[6]], "head": b[8][:60]} for b in best[:10]]})
    print(f"[F2] {n} decodes | melhor score {best[0][0]:.3f}" if best else "[F2] vazio")
    return n, best

# ---------------- F3 ----------------
def run_f3():
    hits_pages = []
    for i, pg in enumerate(PAGES):
        low = pg.lower()
        if i < 8 or "life and death" in low or "yin and yang" in low or "pinwheel" in low:
            hits_pages.append((i, pg))
    extra = []
    npw = 0
    for i, pg in hits_pages:
        full = clean(pg)
        nospace = re.sub(r"\s+", "", pg)
        alpha = re.sub(r"[^A-Za-z]", "", pg)
        for label, text in (("page_raw", pg), ("page_clean", full),
                            ("page_nospace", nospace), ("page_alpha", alpha)):
            if len(text) < 10:
                continue
            for payload in (text, text.lower()):
                hh = hashlib.sha256(payload.encode()).hexdigest()
                h = O.aes_open(hh)
                npw += 1
                if h:
                    solved({"kind": "aes_open_page_sha256hex", "page": i,
                            "form": label, "hits": h}); return npw, len(extra)
        # palavras da pagina como candidatos F1
        for w in re.findall(r"[A-Za-z]{4,}", pg):
            extra.append((w, f"page{i}_word"))
    log({"kind": "F3_pages", "pages": [i for i, _ in hits_pages], "pw_tested": npw})
    print(f"[F3] {len(hits_pages)} paginas, {npw} sha256->AES, {len(extra)} palavras p/ F1")
    return npw, extra

if __name__ == "__main__":
    t0 = time.time()
    log({"kind": "start", "essay_len": len(ESSAY_BODY), "pages": len(PAGES)})
    print(f"[init] essay {len(ESSAY_BODY)} chars, {len(PAGES)} paginas")
    npw3, extra_words = run_f3()
    if not SOLVED:
        run_f1(extra_candidates=extra_words)
    if not SOLVED:
        run_f2()
    log({"kind": "done", "elapsed_s": round(time.time() - t0, 1), "solved": bool(SOLVED)})
    print(f"[fim] {time.time() - t0:.0f}s solved={bool(SOLVED)}")
