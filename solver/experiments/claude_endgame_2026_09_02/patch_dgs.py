# -*- coding: utf-8 -*-
import io, re, os
SP = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(SP, "dutch_german_scorer.py")
src = io.open(p, encoding="utf-8").read()

# 1) numpy + tabelas np + dicionario nl/de logo depois da construcao dos MODELS
anchor = 'def score_tab(tab, floor, idxs):'
assert anchor in src
add = '''import numpy as np
NPTAB = {lang: np.asarray(MODELS[lang][0], dtype=np.float32) for lang in ("nl", "de")}
NPW = np.array([17576, 676, 26, 1], dtype=np.int64)
# lexico nl/de a partir do corpus (palavras >=6 letras, freq >=4) -> 2o oraculo de legibilidade
def build_lex(lang):
    raw = open(os.path.join(SP, "corpus", f"{lang}.txt"), encoding="utf-8").read()
    c = Counter()
    for w in re.findall(r"[A-Za-z\u00c0-\u024f]+", raw):
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
'''
src = src.replace(anchor, add + anchor, 1)

# 2) hill_climb -> numpy
old_start = src.index('def hill_climb(seq, nsym, lang, restarts=10')
old_end = src.index('def cb_cells(digs, escapes')
new_hc = '''def hill_climb(seq, nsym, lang, restarts=10, iters=6000, patience=600, seed=0):
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

'''
src = src[:old_start] + new_hc + src[old_end:]

# 3) calibracao extra do scorer INGLES sobre ruido (prova de que nl passaria pelo filtro ingles)
src = src.replace(
 'calib["en_scorer"] = {"nl_text": stats([sc_en(c) for c in chunks(held_nl)]), "en_text": stats([sc_en(c) for c in chunks(EN_SAMPLE, 300, 5)])}',
 'calib["en_scorer"] = {"nl_text": stats([sc_en(c) for c in chunks(held_nl)]),\n'
 '                      "de_text": stats([sc_en(c) for c in chunks(held_de)]),\n'
 '                      "en_text": stats([sc_en(c) for c in chunks(EN_SAMPLE, 300, 5)]),\n'
 '                      "random_uniform": stats([sc_en("".join(rng.choice(A) for _ in range(300))) for _ in range(20)]),\n'
 '                      "shuffled_nl": stats([sc_en("".join(rng.sample(c, len(c)))) for c in chunks(held_nl, 300, 20)])}', 1)

# 4) registrar lex_hits nos records de hill-climb
src = src.replace('rec = {"how": f"cb_hc|{tn}|esc{e}|{lang}", "L": len(seq), "score": round(s, 3), "thr": round(thr_hc(len(seq), lang), 3), "head": pt[:60]}',
                  'rec = {"how": f"cb_hc|{tn}|esc{e}|{lang}", "L": len(seq), "score": round(s, 3), "thr": round(thr_hc(len(seq), lang), 3), "head": pt[:60], "lex": lex_hits(lang, pt)[:8]}', 1)
src = src.replace('rec = {"how": f"mono_hc|{name}|{lang}", "L": len(seq), "nsym": len(syms), "score": round(s, 3), "thr": round(thr_hc(len(seq), lang), 3), "head": pt[:60]}',
                  'rec = {"how": f"mono_hc|{name}|{lang}", "L": len(seq), "nsym": len(syms), "score": round(s, 3), "thr": round(thr_hc(len(seq), lang), 3), "head": pt[:60], "lex": lex_hits(lang, pt)[:8]}', 1)

# 5) lex nos melhores do checkerboard fixo
src = src.replace('log({"checkerboard_fixed": {"n": n_cb, "best": best_cb}})',
                  'log({"checkerboard_fixed": {"n": n_cb, "best": best_cb,\n'
                  '     "lex_best": {l: lex_hits(l, best_cb[l][1].split("|")[-1])[:8] for l in ("nl", "de")}}})', 1)
io.open(p, "w", encoding="utf-8").write(src)
print("patch ok", len(src))
