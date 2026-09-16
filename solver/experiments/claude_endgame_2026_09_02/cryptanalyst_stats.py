# -*- coding: utf-8 -*-
"""
FAMILIA cryptanalyst_stats — inferencia estatistica do tipo de cifra de dbbi (91) e faed (570).

HIPOTESE (prosa, falsificavel): dbbi e faed sao textos de 9 simbolos (a-i) produzidos por UMA das
familias classicas (checkerboard straddling 1-9, Bifid/Polybius 3x3 pareado, transposicao de digitos,
digitos de um numero, homofonico/OTP). Cada familia deixa uma assinatura invariante a relabeling:
- checkerboard: um par de simbolos "escape" cuja distribuicao condicional do sucessor difere do global,
  e a tokenizacao (e,x) eleva o IoC dos tokens a niveis de linguagem (~0.066);
- Bifid periodo p: informacao mutua elevada entre posicoes i e i+p/2 (para p=570 -> lag 285);
- Polybius/pares: chi2 forte em posicoes mod 2 (linha vs coluna);
- numero decimal/base-9: frequencias uniformes, sem estrutura serial (H(X|X_prev) ~ log2 9);
- transposicao: frequencias identicas ao "plaintext-tipo" (comparar dbbi x faed) mas digramas destruidos.
Se nenhuma assinatura for significativa (z<3 vs 300 embaralhamentos), o modelo mais provavel e "sem
estrutura serial" (numero/keystream/OTP), o que refuta Bifid-570 real e checkerboard direto.
"""
import sys, math, random, json, collections, itertools
SCR = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SCR)
import gsmg_common as G
LOG = SCR + r"\cryptanalyst_stats.jsonl"
random.seed(1327)
N_TESTS = 0

Z1 = "agdafaoaheiecggchgicbbhcgbehcfcoabicfdhhcdbbcagbdaiobbgbeadedde"
Z2 = "cfobfdhgdobdgooiigdocdaoofidh"
SYM = "abcdefghi"

def log(o): G.jsonl(LOG, o)

# ------------------------------------------------------------ estatisticas basicas
def freqs(s):
    c = collections.Counter(s); n = len(s)
    return {k: c[k] for k in sorted(c)}, n
def ioc(s):
    c = collections.Counter(s); n = len(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1)) if n > 1 else 0
def entropy(s):
    c = collections.Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())
def cond_entropy(s):
    """H(X_{i+1} | X_i) em bits."""
    pairs = collections.Counter(zip(s, s[1:])); first = collections.Counter(s[:-1]); n = len(s) - 1
    return -sum(v / n * math.log2(v / first[a]) for (a, b), v in pairs.items())
def mi_lag(s, d):
    """Informacao mutua I(X_i; X_{i+d}) em bits."""
    n = len(s) - d
    if n < 10: return 0.0
    pa = collections.Counter(s[:n]); pb = collections.Counter(s[d:]); pab = collections.Counter(zip(s[:n], s[d:]))
    return sum(v / n * math.log2(v * n / (pa[a] * pb[b])) for (a, b), v in pab.items())
def match_lag(s, d):
    n = len(s) - d
    return sum(s[i] == s[i + d] for i in range(n)) / n
def chi2_uniform(s):
    c = collections.Counter(s); n = len(s); e = n / 9
    return sum((c.get(k, 0) - e) ** 2 / e for k in SYM)
def chi2_vs_global(sub, glob_p):
    n = len(sub); c = collections.Counter(sub)
    return sum((c.get(k, 0) - n * glob_p[k]) ** 2 / (n * glob_p[k]) for k in SYM if glob_p[k] > 0)
def periodic_ioc(s, k):
    cols = [s[i::k] for i in range(k)]
    return sum(ioc(c) for c in cols) / k
def chi2_mod_k(s, k, glob_p):
    """Soma do chi2 de cada residuo mod k contra a distribuicao global; df = k*8."""
    return sum(chi2_vs_global(s[i::k], glob_p) for i in range(k)), k * 8
def zscore(obs, samples):
    m = sum(samples) / len(samples); sd = (sum((x - m) ** 2 for x in samples) / len(samples)) ** 0.5
    return (obs - m) / sd if sd > 0 else 0.0
def shuffles(s, n=300):
    l = list(s)
    for _ in range(n):
        random.shuffle(l); yield "".join(l)

# ------------------------------------------------------------ Kasiski
def kasiski(s, L=3):
    pos = collections.defaultdict(list)
    for i in range(len(s) - L + 1): pos[s[i:i + L]].append(i)
    dists = collections.Counter()
    reps = {g: p for g, p in pos.items() if len(p) > 1}
    for g, p in reps.items():
        for a, b in itertools.combinations(p, 2): dists[b - a] += 1
    fac = collections.Counter()
    for d, c in dists.items():
        for f in range(2, 61):
            if d % f == 0: fac[f] += c
    return len(reps), fac.most_common(8)

# ------------------------------------------------------------ checkerboard: IoC dos tokens (invariante ao mapeamento)
def tokenize(digs, escapes):
    out = []; i = 0
    while i < len(digs):
        d = digs[i]
        if d in escapes and i + 1 < len(digs): out.append((d, digs[i + 1])); i += 2
        else: out.append((d,)); i += 1
    return out
def checker_scan(s):
    digs = G.digits(s)
    res = []
    for k in (1, 2, 3):
        for esc in itertools.combinations(range(1, 10), k):
            toks = tokenize(digs, set(esc))
            res.append((ioc(toks), esc, len(toks), len(set(toks))))
    res.sort(reverse=True)
    return res

# ------------------------------------------------------------ Benford / numero
def benford(s):
    """Blocos de 3 digitos (a=1..i=9): distribuicao do 1o digito vs Benford."""
    d = G.digits(s); c = collections.Counter(d[i] for i in range(0, len(d) - 2, 3)); n = sum(c.values())
    chi = sum((c.get(k, 0) - n * math.log10(1 + 1 / k)) ** 2 / (n * math.log10(1 + 1 / k)) for k in range(1, 10))
    return chi, n

def analyse(name, s):
    global N_TESTS
    f, n = freqs(s); glob_p = {k: f.get(k, 0) / n for k in SYM}
    rep = {"name": name, "n": n, "freqs": f, "ioc": round(ioc(s), 4), "ioc_uniform": round(1 / 9, 4),
           "H1": round(entropy(s), 3), "H_cond": round(cond_entropy(s), 3), "log2_9": round(math.log2(9), 3),
           "chi2_uniform_df8": round(chi2_uniform(s), 2)}
    sh = list(shuffles(s, 300))
    # entropia condicional vs embaralhado
    rep["H_cond_z"] = round(zscore(cond_entropy(s), [cond_entropy(x) for x in sh]), 2)
    # IoC periodico e MI por lag
    per = {}
    for k in list(range(2, 61)) + [95, 285]:
        if k >= n // 3: continue
        obs = periodic_ioc(s, k); z = zscore(obs, [periodic_ioc(x, k) for x in sh[:120]])
        per[k] = (round(obs, 4), round(z, 2))
    rep["periodic_ioc_top"] = sorted(per.items(), key=lambda kv: -kv[1][1])[:6]
    mi = {}
    lags = [d for d in list(range(1, 61)) + ([95, 114, 190, 285] if n > 300 else []) if d < n - 10]
    for d in lags:
        obs = mi_lag(s, d); z = zscore(obs, [mi_lag(x, d) for x in sh[:120]])
        mi[d] = (round(obs, 4), round(z, 2))
    rep["mi_lag_top"] = sorted(mi.items(), key=lambda kv: -kv[1][1])[:6]
    rep["mi_lag_1"] = mi[1]
    if 285 in mi: rep["mi_lag_285_bifid570"] = mi[285]
    rep["match_lag_top"] = sorted(((d, round(match_lag(s, d), 3)) for d in lags), key=lambda x: -x[1])[:5]
    # chi2 mod k
    ch = {}
    for k in list(range(2, 16)) + [19, 38, 57, 95]:
        if k * 8 >= n: continue
        chi, df = chi2_mod_k(s, k, glob_p)
        # z vs embaralhado
        z = zscore(chi, [chi2_mod_k(x, k, glob_p)[0] for x in sh[:120]])
        ch[k] = (round(chi, 1), df, round(z, 2))
    rep["chi2_mod_k"] = ch
    rep["chi2_mod_k_top"] = sorted(ch.items(), key=lambda kv: -kv[1][2])[:4]
    # Kasiski + z do numero de n-gramas repetidos vs embaralhado (keystream/repeticao?)
    for L in (2, 3, 4):
        nrep, fac = kasiski(s, L); z = zscore(nrep, [kasiski(x, L)[0] for x in sh[:100]])
        rep[f"kasiski_L{L}"] = {"n_repeated": nrep, "z_vs_shuffle": round(z, 2), "top_factors": fac}
    # escape test: chi2 do sucessor condicionado a cada simbolo
    esc = {}
    for a in SYM:
        nxt = [s[i + 1] for i in range(n - 1) if s[i] == a]
        if len(nxt) >= 8: esc[a] = round(chi2_vs_global(nxt, glob_p), 1)
    rep["succ_chi2_df8_by_symbol"] = esc
    # checkerboard token-IoC
    cs = checker_scan(s)
    csh = [checker_scan(x)[0][0] for x in sh[:40]]
    rep["checker_best"] = [(round(i, 4), e, nt, nu) for i, e, nt, nu in cs[:5]]
    rep["checker_best_z_vs_shuffle_best"] = round(zscore(cs[0][0], csh), 2)
    rep["checker_english_ref"] = 0.066
    # numero: Benford
    chi, nb = benford(s); rep["benford_chi2_df8"] = (round(chi, 1), nb)
    # paridade (Polybius pares)
    if n % 2 == 0:
        ev, od = s[0::2], s[1::2]
        rep["even_odd_freqs"] = (freqs(ev)[0], freqs(od)[0])
    N_TESTS += 1
    log(rep)
    return rep

def main():
    global N_TESTS
    log({"hypothesis": __doc__.strip()})
    reports = {}
    for name, s in (("dbbi", G.DBBI), ("faed", G.FAED), ("faed_no_prefix", G.FAED[4:]),
                    ("z1", Z1.replace("o", "")), ("z2", Z2.replace("o", ""))):
        reports[name] = analyse(name, s)
        r = reports[name]
        print(f"== {name} n={r['n']} IoC={r['ioc']} H1={r['H1']} Hcond={r['H_cond']} (z={r['H_cond_z']}) chi2u={r['chi2_uniform_df8']}")
        print("  freqs", r["freqs"])
        print("  perIoC top", r["periodic_ioc_top"])
        print("  MI top", r["mi_lag_top"], "MI1", r["mi_lag_1"], "MI285", r.get("mi_lag_285_bifid570"))
        print("  chi2 mod k top", r["chi2_mod_k_top"])
        print("  kasiski3", r["kasiski_L3"], "kasiski4", r["kasiski_L4"])
        print("  succ chi2", r["succ_chi2_df8_by_symbol"])
        print("  checker best", r["checker_best"][:3], "z", r["checker_best_z_vs_shuffle_best"])
        print("  benford", r["benford_chi2_df8"])
        if "even_odd_freqs" in r: print("  even/odd", r["even_odd_freqs"])
    # homogeneidade dbbi x faed (mesma fonte?)
    fd, nd = freqs(G.DBBI); ff, nf = freqs(G.FAED)
    chi = 0
    for k in SYM:
        tot = fd.get(k, 0) + ff.get(k, 0)
        for c, n in ((fd, nd), (ff, nf)):
            e = tot * n / (nd + nf); chi += (c.get(k, 0) - e) ** 2 / e
    print("homogeneidade dbbi x faed chi2 df8 =", round(chi, 2))
    log({"homog_dbbi_faed_chi2_df8": round(chi, 2)})
    # faed grade 15x38: somas de linha/coluna e IoC por coluna
    rows = [G.FAED[i * 38:(i + 1) * 38] for i in range(15)]
    cols = ["".join(r[j] for r in rows) for j in range(38)]
    print("grade 15x38: IoC medio linhas", round(sum(ioc(r) for r in rows) / 15, 4), "colunas", round(sum(ioc(c) for c in cols) / 38, 4))
    rows2 = [G.FAED[i * 15:(i + 1) * 15] for i in range(38)]
    cols2 = ["".join(r[j] for r in rows2) for j in range(15)]
    print("grade 38x15: IoC medio linhas", round(sum(ioc(r) for r in rows2) / 38, 4), "colunas", round(sum(ioc(c) for c in cols2) / 15, 4))
    print("N_TESTS(stats)", N_TESTS)
    json.dump(reports, open(SCR + r"\cryptanalyst_stats_reports.json", "w"), indent=1)

if __name__ == "__main__" and len(sys.argv) == 1:
    main()

# ============================================================ FASE 2: controle positivo + testes decisivos
DIG322 = "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"

def token_ioc_scan_digits(digs, universe):
    res = []
    for k in (1, 2):
        for esc in itertools.combinations(universe, k):
            toks = tokenize(digs, set(esc)); res.append((round(ioc(toks), 4), esc, len(set(toks))))
    return sorted(res)

def control_322():
    """Controle positivo do detector token-IoC: fase 3.2.2 (escapes reais 1,4, universo 0-9)."""
    digs = [int(c) for c in DIG322]
    res = token_ioc_scan_digits(digs, range(10))
    rank = [i for i, r in enumerate(res) if r[1] == (1, 4)][0]
    print("CONTROLE 3.2.2: n=%d IoC digitos=%.4f freqs=%s" % (len(digs), ioc(digs), sorted(collections.Counter(digs).items())))
    print("  token-IoC ordenado (menor=mais ingles): top5", res[:5], "| rank de (1,4) =", rank, "/", len(res))
    log({"control_322": {"rank_true_escapes": rank, "n_pairs": len(res), "top": res[:5]}})
    return rank

def readings(s):
    """Leituras transpostas plausiveis (grades cujas dimensoes dividem n) + reverso."""
    n = len(s); out = {"id": s, "rev": s[::-1]}
    for r in range(2, n):
        if n % r == 0 and r <= n // 2:
            c = n // r
            out[f"cols_{r}x{c}"] = "".join(s[i * c + j] for j in range(c) for i in range(r))
            out[f"cols_{c}x{r}"] = "".join(s[i * r + j] for j in range(r) for i in range(c))
    return out

def transposition_scan(name, s):
    """Para cada leitura: estrutura serial (H_cond z, MI1 z) e melhor token-IoC (menor) — invariante ao mapeamento."""
    sh = list(shuffles(s, 150))
    base_hc = [cond_entropy(x) for x in sh]; base_mi = [mi_lag(x, 1) for x in sh]
    base_tok = [token_ioc_scan_digits(G.digits(x), range(1, 10))[0][0] for x in sh[:60]]
    rows = []
    for k, t in readings(s).items():
        hc = zscore(cond_entropy(t), base_hc); mi = zscore(mi_lag(t, 1), base_mi)
        tok = token_ioc_scan_digits(G.digits(t), range(1, 10))[0]
        tz = zscore(tok[0], base_tok)
        rows.append((k, round(hc, 2), round(mi, 2), tok, round(tz, 2)))
    rows.sort(key=lambda r: r[1])
    print(f"TRANSPOSICAO {name}: {len(rows)} leituras; mais estruturadas (H_cond z menor):")
    for r in rows[:6]: print("  ", r)
    best_tok = min(rows, key=lambda r: r[4]); print("  melhor token-IoC:", best_tok)
    log({"transposition_scan": name, "n_readings": len(rows), "top_struct": rows[:6], "best_token_ioc": best_tok})
    return rows

def number_tests():
    """Teste decisivo 1 do modelo 'numero como os z-segmentos': z-method em dbbi/faed -> ASCII? privkey? senha?"""
    global N_TESTS
    hard, soft = [], []
    srcs = {"dbbi": G.DBBI, "faed": G.FAED, "faed_np": G.FAED[4:], "dbbi_rev": G.DBBI[::-1], "faed_rev": G.FAED[::-1],
            "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:], "dbbi+faed": G.DBBI + G.FAED}
    for nm, s in srcs.items():
        for enc in ("dec1", "base9"):
            d = G.digits(s) if enc == "dec1" else G.digits(s, base1=False)
            if enc == "dec1": b = G.z_method(d)
            else:
                v = 0
                for x in d: v = v * 9 + x
                h = format(v, "x"); b = bytes.fromhex(("0" if len(h) % 2 else "") + h)
            sem = G.semantic(b); pr = round(G.printable(b), 3)
            hits = G.scan_priv(b, f"{nm}/{enc}") + G.scan_priv(G.sha(b), f"{nm}/{enc}/sha")
            N_TESTS += 2
            for pw in (b, b.hex(), G.shahex(b), G.shahex(b.hex())):
                h, so = G.try_password_all(pw); N_TESTS += 6
                hard += [dict(x, src=f"{nm}/{enc}", pw=str(pw)[:80]) for x in h]; soft += [dict(x, src=f"{nm}/{enc}") for x in so]
            if hits: hard.append({"src": f"{nm}/{enc}", "priv": [str(x) for x in hits], "bytes": b.hex()})
            log({"number_test": f"{nm}/{enc}", "nbytes": len(b), "printable": pr, "semantic": sem, "head": b[:24].decode("latin-1"), "priv_hits": len(hits)})
            print(f"  numero {nm}/{enc}: {len(b)} B printable={pr} semantic={sem} priv={len(hits)}")
    return hard, soft

def anneal_checkerboard(s, escapes, iters=6000):
    """Hill-climb curto de mapeamento token->letra (25 letras) por quadgramas; devolve (score, texto)."""
    toks = tokenize(G.digits(s), set(escapes))
    types = sorted(set(toks)); L = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    if len(types) > 25: return None
    cur = {t: L[i] for i, t in enumerate(types)}
    def txt(m): return "".join(m[t] for t in toks)
    cur_s = G.english_score(txt(cur)); best_s, best_t = cur_s, txt(cur)
    for it in range(iters):
        m = cur.copy()
        if random.random() < 0.5 and len(types) > 1:
            a, b = random.sample(types, 2); m[a], m[b] = m[b], m[a]
        else:
            free = [c for c in L if c not in m.values()]
            if not free: continue
            m[random.choice(types)] = random.choice(free)
        sc = G.english_score(txt(m))
        T = 1.0 * (1 - it / iters) + 0.05
        if sc > cur_s or random.random() < math.exp((sc - cur_s) * len(toks) / (20 * T)):
            cur, cur_s = m, sc
            if sc > best_s: best_s, best_t = sc, txt(m)
    return best_s, best_t

def decisive_checkerboard(name, s, cands):
    """Teste decisivo 2: para as leituras/escapes mais promissores, hill-climb + oraculo duro."""
    global N_TESTS
    hard, soft, best = [], [], (-99, "", "")
    for rd, esc in cands:
        t = readings(s)[rd]
        r = anneal_checkerboard(t, esc); N_TESTS += 1
        if r is None: continue
        sc, txt = r
        if sc > best[0]: best = (sc, txt, f"{name}/{rd}/esc{esc}")
        for pw in (txt, txt.lower(), G.shahex(txt), G.shahex(txt.lower())):
            h, so = G.try_password_all(pw); N_TESTS += 6
            hard += [dict(x, src=f"{name}/{rd}/{esc}", pw=pw[:80]) for x in h]; soft += [dict(x, src=f"{name}/{rd}/{esc}") for x in so]
        for ph in (txt, txt.lower()):
            hp = G.phrase_priv(ph); N_TESTS += 1
            if hp: hard.append({"src": f"{name}/{rd}/{esc}", "phrase_priv": str(hp)})
        log({"decisive_checkerboard": f"{name}/{rd}/{esc}", "score": round(sc, 3), "text": txt[:120]})
        print(f"  {name}/{rd}/esc{esc}: score={sc:.3f} {txt[:60]}")
    return hard, soft, best

def phase2():
    global N_TESTS
    rank = control_322()
    scans = {nm: transposition_scan(nm, s) for nm, s in (("dbbi", G.DBBI), ("faed", G.FAED))}
    print("TESTE DECISIVO 1 (modelo numero):")
    h1, s1 = number_tests()
    print("TESTE DECISIVO 2 (transposicao+checkerboard, leituras com menor token-IoC / maior estrutura):")
    hard, soft, best = list(h1), list(s1), (-99, "", "")
    for nm, s in (("dbbi", G.DBBI), ("faed", G.FAED)):
        rows = scans[nm]
        cands = [(r[0], r[3][1]) for r in sorted(rows, key=lambda r: r[4])[:3]] + [(r[0], r[3][1]) for r in rows[:2]]
        cands = list(dict.fromkeys(cands))
        h, so, b = decisive_checkerboard(nm, s, cands)
        hard += h; soft += so
        if b[0] > best[0]: best = b
    out = {"n_tests": N_TESTS, "hard": hard, "soft": soft, "best": {"score": round(best[0], 3), "text": best[1][:200], "how": best[2]}, "control_rank": rank}
    log({"phase2_summary": out}); print(json.dumps(out, indent=1)[:3000])

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "phase2":
    phase2()

# ============================================================ FASE 3: calibracao do controle + hill-climb com reinicios
def anneal_digits(digs, escapes, iters=15000, restarts=6, L="ABCDEFGHIKLMNOPQRSTUVWXYZ"):
    toks = tokenize(digs, set(escapes)); types = sorted(set(toks))
    if len(types) > len(L): return None
    def txt(m): return "".join(m[t] for t in toks)
    best_s, best_t = -99, ""
    for r in range(restarts):
        letters = list(L); random.shuffle(letters)
        cur = {t: letters[i] for i, t in enumerate(types)}; cur_s = G.english_score(txt(cur))
        for it in range(iters):
            m = cur.copy()
            if random.random() < 0.6 and len(types) > 1:
                a, b = random.sample(types, 2); m[a], m[b] = m[b], m[a]
            else:
                free = [c for c in L if c not in m.values()]
                if not free: continue
                m[random.choice(types)] = random.choice(free)
            sc = G.english_score(txt(m)); T = 0.6 * (1 - it / iters) + 0.02
            if sc > cur_s or random.random() < math.exp((sc - cur_s) * len(toks) / (25 * T)):
                cur, cur_s = m, sc
                if sc > best_s: best_s, best_t = sc, txt(m)
    return best_s, best_t

def phase3():
    global N_TESTS
    # calibracao: o que um checkerboard REAL de ingles mostra (fase 3.2.2, n=149)
    digs = [int(c) for c in DIG322]; s322 = "".join(chr(97 + d) for d in digs)
    sh = list(shuffles(s322, 200))
    hz = zscore(cond_entropy(s322), [cond_entropy(x) for x in sh]); mz = zscore(mi_lag(s322, 1), [mi_lag(x, 1) for x in sh])
    print(f"CONTROLE 3.2.2 estrutura serial: H_cond z={hz:.2f}  MI1 z={mz:.2f}  (faed direto: -0.75/0.65; dbbi: -1.83/1.62)")
    sc, t = anneal_digits(digs, (1, 4), iters=8000, restarts=3, L="ABCDEFGHIJKLMNOPQRSTUVWXYZ.."); N_TESTS += 1
    print(f"CONTROLE hill-climb 3.2.2 esc(1,4): score={sc:.3f} {t[:70]}")
    log({"control_serial": {"H_cond_z": round(hz, 2), "MI1_z": round(mz, 2)}, "control_anneal": {"score": round(sc, 3), "text": t[:80]}})
    # forma unigrama: checkerboard simulado de ingles (7 singles = ETAOINS) vs faed/dbbi
    eng = dict(zip("ETAOINSHRDLCUMWFGYPBVKJXQZ", [12.7,9.1,8.2,7.5,7.0,6.7,6.3,6.1,6.0,4.3,4.0,2.8,2.8,2.4,2.4,2.2,2.0,2.0,1.9,1.5,1.0,0.8,0.15,0.15,0.1,0.07]))
    singles = "ETAOINS"; rest = [c for c in eng if c not in singles]
    esc_p = sum(eng[c] for c in rest) / 100; tot = 1 + esc_p  # digitos por letra
    shape = sorted([sum(eng[c] for c in singles) / 100 / 7 + esc_p / 9] * 7 + [esc_p / 2 + esc_p / 9] * 2, reverse=True)
    shape = [x / tot for x in shape]
    for nm, s in (("faed", G.FAED), ("dbbi", G.DBBI)):
        f = sorted(collections.Counter(s).values(), reverse=True); n = len(s)
        chi = sum((o - n * e) ** 2 / (n * e) for o, e in zip(f, shape))
        print(f"forma unigrama {nm}: obs={[round(x/n,3) for x in f]} esperado(checkerboard ETAOINS)={[round(x,3) for x in shape]} chi2={chi:.1f} (df8)")
        log({"unigram_shape": nm, "obs": f, "expected_checkerboard": shape, "chi2": round(chi, 1)})
    # hill-climb com reinicios nos melhores candidatos (leitura, escapes)
    hard, soft, best = [], [], (-99, "", "")
    cands = [("faed", "cols_15x38", (7, 9)), ("faed", "cols_6x95", (7, 9)), ("faed", "id", (7, 9)), ("faed", "cols_38x15", (7, 9)),
             ("dbbi", "id", (2, 5)), ("dbbi", "rev", (2, 5)), ("dbbi", "cols_7x13", (2, 5)), ("dbbi", "cols_13x7", (2, 5))]
    for nm, rd, esc in cands:
        s = G.DBBI if nm == "dbbi" else G.FAED
        r = anneal_digits(G.digits(readings(s)[rd]), esc, iters=12000, restarts=5); N_TESTS += 1
        sc, txt = r
        if sc > best[0]: best = (sc, txt, f"{nm}/{rd}/esc{esc}")
        for pw in (txt, txt.lower(), G.shahex(txt), G.shahex(txt.lower())):
            h, so = G.try_password_all(pw); N_TESTS += 6
            hard += [dict(x, src=f"{nm}/{rd}/{esc}", pw=pw[:80]) for x in h]; soft += [dict(x, src=f"{nm}/{rd}/{esc}") for x in so]
        hp = G.phrase_priv(txt); N_TESTS += 1
        if hp: hard.append({"src": f"{nm}/{rd}/{esc}", "phrase_priv": str(hp)})
        log({"phase3_anneal": f"{nm}/{rd}/{esc}", "score": round(sc, 3), "text": txt[:120]})
        print(f"  {nm}/{rd}/esc{esc}: score={sc:.3f} {txt[:70]}")
    out = {"n_tests": N_TESTS, "hard": hard, "soft": soft, "best": {"score": round(best[0], 3), "text": best[1][:200], "how": best[2]}}
    log({"phase3_summary": out}); print(json.dumps(out, indent=1)[:2500])

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "phase3":
    phase3()

# ============================================================ FASE 4: transposicao colunar keyed — hill-climb da chave com fitness invariante ao mapeamento (H_cond)
def untranspose(s, key):
    """Transposicao colunar completa: ct foi lido por colunas na ordem key. Reconstroi linhas."""
    w = len(key); n = len(s); rows = n // w; extra = n % w
    lens = [rows + (1 if i < extra else 0) for i in range(w)]  # coluna i (posicao original) tem lens[i]
    cols = {}; p = 0
    for k in key:
        cols[k] = s[p:p + lens[k]]; p += lens[k]
    out = []
    for r in range(rows + (1 if extra else 0)):
        for c in range(w):
            if r < lens[c]: out.append(cols[c][r])
    return "".join(out)

def phase4():
    global N_TESTS
    res = []
    for nm, s in (("faed", G.FAED), ("dbbi", G.DBBI)):
        sh = list(shuffles(s, 200)); base = [cond_entropy(x) for x in sh]
        mu = sum(base) / len(base); sd = (sum((x - mu) ** 2 for x in base) / len(base)) ** 0.5
        # ceiling: melhor H_cond alcancavel por hill-climb em texto EMBARALHADO (overfit da busca)
        for w in range(3, 21):
            best = (9, None)
            for restart in range(4):
                key = list(range(w)); random.shuffle(key); cur = cond_entropy(untranspose(s, key))
                for it in range(600):
                    i, j = random.sample(range(w), 2); k2 = key[:]; k2[i], k2[j] = k2[j], k2[i]
                    h = cond_entropy(untranspose(s, k2))
                    if h < cur or random.random() < 0.02: key, cur = k2, h
                    if cur < best[0]: best = (cur, key[:])
            N_TESTS += 1
            # controle de overfit: mesma busca (1 reinicio) num embaralhado
            key = list(range(w)); random.shuffle(key); x = sh[w]; cur = cond_entropy(untranspose(x, key)); ov = cur
            for it in range(600):
                i, j = random.sample(range(w), 2); k2 = key[:]; k2[i], k2[j] = k2[j], k2[i]
                h = cond_entropy(untranspose(x, k2))
                if h < cur: key, cur = k2, h
                ov = min(ov, cur)
            z = (best[0] - mu) / sd; zo = (ov - mu) / sd
            res.append((nm, w, round(z, 2), round(zo, 2), best[1]))
        top = sorted([r for r in res if r[0] == nm], key=lambda r: r[2])[:5]
        print(f"TRANSPOSICAO KEYED {nm}: top (w, z_real, z_overfit_embaralhado):", [(r[1], r[2], r[3]) for r in top])
        log({"keyed_transposition": nm, "top": top, "all": [(r[1], r[2], r[3]) for r in res if r[0] == nm]})
    print("N_TESTS fase4", N_TESTS)

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "phase4":
    phase4()

# ============================================================ FASE 5: teste justo do overfit (w=19/15 faed, w=19/11 dbbi): mesma busca em 12 embaralhados
def climb(s, w, restarts=4, iters=600):
    best = (9, None)
    for _ in range(restarts):
        key = list(range(w)); random.shuffle(key); cur = cond_entropy(untranspose(s, key))
        for it in range(iters):
            i, j = random.sample(range(w), 2); k2 = key[:]; k2[i], k2[j] = k2[j], k2[i]
            h = cond_entropy(untranspose(s, k2))
            if h < cur or random.random() < 0.02: key, cur = k2, h
            if cur < best[0]: best = (cur, key[:])
    return best

def phase5():
    global N_TESTS
    for nm, s, ws in (("faed", G.FAED, (19, 15)), ("dbbi", G.DBBI, (19, 11))):
        sh = list(shuffles(s, 200)); base = [cond_entropy(x) for x in sh]
        mu = sum(base) / len(base); sd = (sum((x - mu) ** 2 for x in base) / len(base)) ** 0.5
        for w in ws:
            real = climb(s, w); null = sorted((climb(x, w)[0] - mu) / sd for x in sh[:12]); N_TESTS += 13
            zr = (real[0] - mu) / sd
            print(f"{nm} w={w}: z_real={zr:.2f}  nulo(12 embaralhados, mesma busca)= min {null[0]:.2f} med {null[6]:.2f} max {null[-1]:.2f}  -> {'ACIMA do nulo' if zr < null[0] else 'dentro do nulo'}")
            t = untranspose(s, real[1])
            log({"fair_overfit": f"{nm}/w{w}", "z_real": round(zr, 2), "null": [round(x, 2) for x in null], "key": real[1], "text": t})
            if zr < null[0] - 1:
                # segue: token-IoC e hill-climb checkerboard no texto destransposto
                tok = token_ioc_scan_digits(G.digits(t), range(1, 10))[:3]; print("   token-IoC:", tok)
                sc, txt = anneal_digits(G.digits(t), tok[0][1], iters=10000, restarts=4); N_TESTS += 1
                print(f"   anneal esc{tok[0][1]}: {sc:.3f} {txt[:80]}")
                for pw in (txt, txt.lower(), G.shahex(txt), G.shahex(txt.lower())):
                    h, so = G.try_password_all(pw); N_TESTS += 6
                    if h: print("HARD", h)
                    if so: print("soft", so)
                log({"fair_overfit_followup": f"{nm}/w{w}", "score": round(sc, 3), "text": txt[:160]})
    print("N_TESTS fase5", N_TESTS)

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "phase5":
    phase5()
