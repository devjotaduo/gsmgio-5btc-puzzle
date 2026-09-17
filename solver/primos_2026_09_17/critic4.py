# -*- coding: utf-8 -*-
"""Critico adversarial do lead 'marcadores b/be nos primos logicos de dbbi'.
(1) reproducao da segmentacao + nulo >=5000 + look-elsewhere sobre regras;
(2) look-elsewhere EXATO do casamento 23 bits <-> cores dos 25 eventos;
(3) scorer contaminado vs limpo na identidade do residuo;
(4) bateria de aleatoriedade do residuo (chi2, serial, bigramas) vs embaralhamentos."""
import sys, os, json, random, math, itertools
from collections import Counter
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "critic4.jsonl")
S = G.DBBI; N = len(S); L9 = "abcdefghi"
PR = {k for k in range(1, 200) if G.is_prime(k)}
SQ = {k*k for k in range(1, 15)}; TRI = {k*(k+1)//2 for k in range(1, 20)}
FIB = set(); a, b = 1, 2
while a < 200: FIB.add(a); a, b = b, a+b
SCHEMES = {  # predicado sobre a posicao k (1-based no contador)
    "prime1": lambda k: k in PR, "prime0": lambda k: (k-1) in PR,
    "comp1": lambda k: k > 1 and k not in PR, "comp0": lambda k: (k-1) > 1 and (k-1) not in PR,
    "square": lambda k: k in SQ, "tri": lambda k: k in TRI, "fib": lambda k: k in FIB,
    "odd": lambda k: k % 2 == 1, "even": lambda k: k % 2 == 0, "mult3": lambda k: k % 3 == 0,
    "prime2": lambda k: (k+1) in PR,  # numerar a partir de 2
}

def segment(s, x, suf, pred, want_paths=False):
    """DP logica: no token k (1-based) se pred(k) consome x ou x+y (y in suf); senao 1 simbolo qualquer.
    Devolve (n_segmentacoes completas, caminhos) - caminho = lista de tokens."""
    n = len(s); reach = {0: 1}; paths = {0: [[]]} if want_paths else None; total = 0; done = []
    k = 1
    while reach and k <= n + 1:
        new = {}; newp = {} if want_paths else None
        for i, cnt in reach.items():
            if i == n: continue
            opts = []
            if pred(k):
                if s[i] == x:
                    opts.append(1)
                    if i + 1 < n and s[i+1] in suf: opts.append(2)
            else:
                opts.append(1)
            for ln in opts:
                j = i + ln; new[j] = new.get(j, 0) + cnt
                if want_paths: newp.setdefault(j, []).extend(p + [s[i:j]] for p in paths[i])
        reach = new
        if want_paths: paths = newp
        if n in reach:
            total += reach[n]
            if want_paths: done.extend(paths[n])
        k += 1
    return total, done

def segment_phys(s, x, suf, pred):
    """Modo fisico: contador = indice fisico 1-based; em posicao marcada exige x (opcional x+y)."""
    n = len(s); reach = {0: 1}; total = 0
    while reach:
        new = {}
        for i, cnt in reach.items():
            if i == n: total += cnt; continue
            if pred(i + 1):
                if s[i] == x:
                    new[i+1] = new.get(i+1, 0) + cnt
                    if i + 1 < n and s[i+1] in suf: new[i+2] = new.get(i+2, 0) + cnt
            else:
                new[i+1] = new.get(i+1, 0) + cnt
        reach = new
    return total

def seg_from_end(s, x, suf, L):
    """Primos contados do fim: token k (1..L) e marcador se L-k+1 primo; exige exatamente L tokens."""
    n = len(s); reach = {0: 1}
    for k in range(1, L + 1):
        new = {}
        for i, cnt in reach.items():
            if i >= n: continue
            if (L - k + 1) in PR:
                if s[i] == x:
                    new[i+1] = new.get(i+1, 0) + cnt
                    if i + 1 < n and s[i+1] in suf: new[i+2] = new.get(i+2, 0) + cnt
            else: new[i+1] = new.get(i+1, 0) + cnt
        reach = new
        if not reach: return 0
    return reach.get(n, 0)

def rules():
    sufs = {"none": "", "any": L9}; sufs.update({y: y for y in L9})
    for x in L9:
        for sn, suf in sufs.items():
            for scn in SCHEMES:
                yield (x, sn, suf, scn, "logical")
                yield (x, sn, suf, scn, "physical")
            yield (x, sn, suf, "prime_end", "logical")
        for y, z in itertools.combinations(L9, 2):  # x / xy / xz
            for scn in ("prime1", "prime0"):
                yield (x, y+z, y+z, scn, "logical")

def run_rule(s, r):
    x, sn, suf, scn, mode = r
    if scn == "prime_end": return sum(seg_from_end(s, x, suf, L) for L in range(50, len(s)+1))
    if mode == "physical": return segment_phys(s, x, suf, SCHEMES[scn])
    return segment(s, x, suf, SCHEMES[scn])[0]

def main():
    out = {}
    # ---------- (1a) reproducao
    tot, paths = segment(S, "b", "e", SCHEMES["prime1"], want_paths=True)
    segs = []
    for p in paths:
        L = len(p); marks = [t for k, t in enumerate(p, 1) if k in PR]; resid = "".join(t for k, t in enumerate(p, 1) if k not in PR)
        bits = "".join("1" if t == "be" else "0" for t in marks)
        segs.append({"L": L, "nb": marks.count("b"), "nbe": marks.count("be"), "bits": bits, "resid": resid, "len_resid": len(resid)})
    out["segmentacoes_dbbi"] = segs
    assert tot == 2 and {s_["L"] for s_ in segs} == {83, 84}, segs
    print("(1a) segmentacoes:", json.dumps(segs))
    rng = random.Random(7); ok = 0
    for _ in range(5):
        L = rng.randint(70, 90); toks = []
        for k in range(1, L+1):
            toks.append(("b" + ("e" if rng.random() < .3 else "")) if k in PR else rng.choice(L9))
        t, _ = segment("".join(toks), "b", "e", SCHEMES["prime1"]); ok += t >= 1
    assert ok == 5; print("(1a) controle positivo 5/5")
    # ---------- (1b) look-elsewhere: familia de regras em dbbi
    R = list(rules()); hits = []
    for r in R:
        c = run_rule(S, r)
        if c: hits.append((r, c))
    out["familia_n_regras"] = len(R); out["familia_hits_dbbi"] = [(list(r), c) for r, c in hits]
    print(f"(1b) {len(R)} regras; hits em dbbi: {len(hits)}")
    for r, c in hits: print("   ", r, c)
    # ---------- (1c) nulo: regra principal 5000; familia 1000
    rng = random.Random(20260917); chars = list(S); n_main = 0; NS = 5000
    for _ in range(NS):
        rng.shuffle(chars); n_main += segment("".join(chars), "b", "e", SCHEMES["prime1"])[0] > 0
    out["nulo_regra_principal"] = {"n": NS, "hits": n_main}
    print(f"(1c) nulo regra principal: {n_main}/{NS}")
    NF = 1000; fam_hits = 0; per_rule = Counter()
    for _ in range(NF):
        rng.shuffle(chars); t = "".join(chars); any_hit = False
        for r in R:
            if run_rule(t, r): per_rule[r] += 1; any_hit = True
        fam_hits += any_hit
    out["nulo_familia"] = {"n": NF, "n_regras": len(R), "embaralhamentos_com_algum_hit": fam_hits,
                           "regras_que_bateram": [(list(r), c) for r, c in per_rule.most_common(20)]}
    print(f"(1c) nulo familia: {fam_hits}/{NF} embaralhamentos batem em alguma das {len(R)} regras; regras:", per_rule.most_common(10))
    # ---------- (2) look-elsewhere exato bits <-> cores
    ev = sorted(G.COLORED.items()); cols = [v[0] for _, v in ev]  # 25, com 'W*'
    bits84 = next(s_["bits"] for s_ in segs if s_["L"] == 84); bits83 = next(s_["bits"] for s_ in segs if s_["L"] == 83)
    reach = {}
    for W in "BY":
        cs = [W if c == "W*" else c for c in cols]
        for om in itertools.combinations(range(25), 2):
            s23 = "".join("1" if cs[i] == "Y" else "0" for i in range(25) if i not in om)
            reach.setdefault(s23, []).append((W, tuple(o+1 for o in om)))
    matches = {}
    for name, bts in (("L84", bits84), ("L83", bits83)):
        for pol, tgt in (("be=1", bts), ("be=0", "".join("1" if c == "0" else "0" for c in bts))):
            if tgt in reach: matches[f"{name}/{pol}"] = reach[tgt]
    n_conf = 2 * 300 * 2 * 2
    def cnt_ones(k): return sum(1 for s23 in reach if s23.count("1") == k)
    p84 = (cnt_ones(7) + cnt_ones(16)) / math.comb(23, 7); p83 = (cnt_ones(8) + cnt_ones(15)) / math.comb(23, 8)
    out["bits_cores"] = {"bits84": bits84, "bits83": bits83, "n_configs": n_conf, "distintas_alcancaveis": len(reach),
                         "matches": matches, "p_nulo_L84_ambas_polaridades": p84, "p_nulo_L83": p83, "p_familia_uniao": p84 + p83,
                         "alcancaveis_por_num_uns": {k: cnt_ones(k) for k in range(6, 11)}}
    print("(2) matches:", matches); print(f"(2) p_nulo L84={p84:.2e} L83={p83:.2e} familia={p84+p83:.2e}; alcancaveis={len(reach)} de {n_conf} configs")
    # ---------- (3) scorer contaminado vs limpo: identidade do residuo
    resid84 = next(s_["resid"] for s_ in segs if s_["L"] == 84)
    sys.path.insert(0, os.path.join(HERE, "..", "resid_decoders"))
    clean = None
    try:
        import clean_scorer as CS
        for nm in ("score", "english_score", "clean_score"):
            if hasattr(CS, nm): clean = getattr(CS, nm); break
        if clean is None and hasattr(CS, "Scorer"): clean = CS.Scorer()
    except Exception as e:
        print("clean_scorer indisponivel:", e)
    def zscore(fn, text, ns=2000, seed=1):
        r = random.Random(seed); ch = list(text); real = fn(text); vals = []
        for _ in range(ns): r.shuffle(ch); vals.append(fn("".join(ch)))
        mu = sum(vals)/ns; sd = (sum((v-mu)**2 for v in vals)/ns) ** .5
        return {"real": round(real, 3), "mu": round(mu, 3), "sd": round(sd, 3), "z": round((real-mu)/sd, 2) if sd else None,
                "p": sum(v >= real for v in vals)/ns}
    out["scorer_identidade"] = {"contaminado": zscore(G.english_score, resid84)}
    if clean: out["scorer_identidade"]["limpo"] = zscore(lambda t: clean(t.upper()), resid84)
    out["scorer_identidade"]["quadgramas"] = {q: round(G.scorer()(q), 2) for q in ("DIFH", "GEHH", "BBGE", "THEQ", "QXZJ")}
    print("(3)", json.dumps(out["scorer_identidade"]))
    # ---------- (4) aleatoriedade do residuo
    def stats(t):
        c = Counter(t); n = len(t); exp = n / 9
        chi = sum((c.get(ch, 0) - exp) ** 2 / exp for ch in L9)
        d = [ord(ch) - 97 for ch in t]; mu = sum(d)/n
        num = sum((d[i]-mu)*(d[i+1]-mu) for i in range(n-1)); den = sum((x-mu)**2 for x in d) or 1
        big = Counter(t[i:i+2] for i in range(n-1)); rep_big = sum(v-1 for v in big.values() if v > 1)
        runs = sum(1 for i in range(n-1) if t[i] == t[i+1])
        return {"chi2_uniforme": chi, "serial_lag1": num/den, "bigramas_repetidos": rep_big, "pares_iguais_adjacentes": runs}
    real = stats(resid84); r = random.Random(3); ch = list(resid84); null = []
    for _ in range(5000): r.shuffle(ch); null.append(stats("".join(ch)))
    rnd = {}
    for key in real:
        vals = [v[key] for v in null]; mu = sum(vals)/len(vals); sd = (sum((v-mu)**2 for v in vals)/len(vals))**.5
        lo = sum(v <= real[key] for v in vals)/len(vals); hi = sum(v >= real[key] for v in vals)/len(vals)
        rnd[key] = {"real": round(real[key], 3), "mu": round(mu, 3), "sd": round(sd, 3), "p_two": round(min(1, 2*min(lo, hi)), 3)}
    rnd["chi2_uniforme"]["nota"] = f"gl=8, invariante ao embaralhamento; faed chi2={stats(G.FAED)['chi2_uniforme']:.1f} (n=570); dbbi chi2={stats(S)['chi2_uniforme']:.1f}"
    rnd["freq_residuo"] = dict(sorted(Counter(resid84).items())); rnd["freq_faed_escalada_61"] = {k: round(v/570*61, 1) for k, v in sorted(Counter(G.FAED).items())}
    out["aleatoriedade_residuo"] = rnd; print("(4)", json.dumps(rnd))
    json.dump(out, open(os.path.join(HERE, "summary.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    G.jsonl(LOG, {"hipotese": "critico: reproducao + look-elsewhere (regras e bits/cores) + scorer + aleatoriedade", "resultado": out})

if __name__ == "__main__": main()
