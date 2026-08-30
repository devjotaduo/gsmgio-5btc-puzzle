# -*- coding: utf-8 -*-
"""
VIC FULL ATTACK — cobre as lacunas NUNCA testadas do endgame SalPhaseIon:

  F1  dbbi: sweep exaustivo 9! mapeamentos a-i -> digitos (universos 0-8 e 1-9)
      x straddling checkerboard (36 pares de escape x 4 alfabetos), score por
      quadgramas (numpy vetorizado; decode exato em Python so p/ top candidatos).
  F2  dbbi: transposicao colunar keyed "matrixsumlist" (grades 7x13 e 13x7,
      4 combos in/out x ordem normal/reversa) -> F1 reduzido (3 mapeamentos
      fixos) + keystream mod-9 sobre faed -> Bifid(CANON).
  F3  VIC chain-addition (lagged Fibonacci mod-10 e mod-9) com sementes
      tematicas -> keystream +/- sobre faed -> checkerboard.
  F4  faed: transposicao colunar keyed "lastwordsbeforearchichoicethispassword"
      (grade 15x38) + boustrophedon + espiral -> checkerboard.
  F5  melhor plaintext de F1 como senha AES / sha256 / keyword Bifid / chave
      de transposicao colunar sobre faed.

Oraculos DUROS (solver/oracles.py): aes_open / check_privkey / check_mnemonic.
Qualquer hit -> solver/out/SOLVED.json e PARA.

Log: _work/vic_full_attack.jsonl (1 registro por familia).
Decisoes de modelagem (registradas p/ reproducao):
  - pares de escape = 36 pares NAO ordenados (e1<e2) dentro do universo;
    e1 define a 1a linha do board, e2 a 2a (checkerboard.py build_layout).
  - checkerboard 25 slots: topo = universo menos escapes (7), linha e1 = 9
    slots indexados pelo digito seguinte, linha e2 = idem.
  - alfabetos: (1) 1a ocorrencia do dbbi (DBIFHCEGA+filler), (2) fase 3.2.2
    "FUBCDORA.LETHINGKYMVPS.JQZXW" sem pontos e sem J (25 letras),
    (3) canonico A-Z sem J, (4) ETAOIN SHRDLU primeiro.
  - score vetorizado difere levemente do Scorer (janelas invalidas -> floor
    em vez de filtrar o char); top candidatos sao RE-PONTUADOS com o Scorer
    exato antes de oraculos/log.
"""
import os, sys, json, time, math, hashlib, itertools

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "out"); os.makedirs(OUT, exist_ok=True)
WORK = os.path.join(ROOT, "_work"); os.makedirs(WORK, exist_ok=True)
LOG = os.path.join(WORK, "vic_full_attack.jsonl")

import numpy as np
import oracles as O
from scorer import Scorer
from prime_attack import CANON, bifid_decrypt, kw_square

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"          # A-Z sem J
AIDX = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}

# ---------------- alfabetos candidatos (25 slots) ----------------
def _firstocc_fill(seed):
    seen = []
    for c in seed.upper() + ALPHA25:
        if c in ALPHA25 and c not in seen:
            seen.append(c)
    return "".join(seen)

def build_alphabets(dbbi):
    vic322 = "FUBCDORALETHINGKYMVPSJQZXW".replace("J", "")  # 25 letras, sem pontos/J
    etaoin = _firstocc_fill("ETAOINSHRDLU")
    return {
        "dbbi_firstocc": _firstocc_fill(dbbi),       # DBIFHCEGA + filler
        "vic322": vic322,                            # fase 3.2.2
        "canon25": ALPHA25,                          # A-Z sem J
        "etaoin": etaoin,                            # ETAOIN SHRDLU primeiro
    }

# ---------------- scorer vetorizado ----------------
_sc = None
TAB = None
FLOOR = None
def init_scorer():
    global _sc, TAB, FLOOR
    _sc = Scorer()
    TAB = np.array(_sc.tab, dtype=np.float64)
    FLOOR = float(_sc.floor)

def alpha_to_idx(alpha25):
    return np.array([AIDX[c] for c in alpha25], dtype=np.int16)

def score_block(D, U, pairs, alphas):
    """
    D: (N, L) int array de VALORES de digito. U: lista dos 9 digitos do universo.
    pairs: lista de (e1,e2) nao ordenados. alphas: {nome: idx_array[25]}.
    Yield (e1, e2, alpha_nome, scores[N]).
    """
    N, L = D.shape
    pos = np.arange(L)
    Uidx = np.full(10, -1, np.int16)
    for k, d in enumerate(U):
        Uidx[d] = k
    for (e1, e2) in pairs:
        esc = (D == e1) | (D == e2)
        second = np.zeros((N, L), dtype=bool)
        prev_esc = esc[:, 0].copy()
        prev_sec = np.zeros(N, dtype=bool)
        for i in range(1, L):
            sec = prev_esc & ~prev_sec
            second[:, i] = sec
            prev_sec = sec
            prev_esc = esc[:, i]
        primary = ~second
        top_digits = [d for d in U if d != e1 and d != e2]
        tarr = np.full(10, -1, np.int16)
        for k, d in enumerate(top_digits):
            tarr[d] = k
        S = np.where(primary & ~esc, tarr[D], np.int16(-1)).astype(np.int16)
        Dnext = np.zeros_like(D)
        Dnext[:, :-1] = D[:, 1:]
        colok = Uidx[Dnext] >= 0
        colok[:, -1] = False
        rowbase = np.where(D == e1, np.int16(7), np.int16(16))
        S = np.where(primary & esc & colok, rowbase + Uidx[Dnext], S)
        order = np.argsort(np.where(primary, pos[None, :], L), axis=1, kind="stable")
        Sg = np.take_along_axis(S, order, 1)
        out_len = primary.sum(1)
        denom = np.maximum(out_len - 3, 1)
        for aname, aidx in alphas.items():
            Lval = np.where(Sg >= 0, aidx[np.clip(Sg, 0, 24)], np.int16(-1))
            Ls = np.clip(Lval, 0, 25).astype(np.int32)
            q = ((Ls[:, :-3] * 26 + Ls[:, 1:-2]) * 26 + Ls[:, 2:-1]) * 26 + Ls[:, 3:]
            valid = (Lval[:, :-3] >= 0) & (Lval[:, 1:-2] >= 0) & \
                    (Lval[:, 2:-1] >= 0) & (Lval[:, 3:] >= 0)
            # janelas alem de out_len-3 sao padding da compactacao: excluir
            widx = np.arange(L - 3)
            valid &= widx[None, :] < (out_len - 3)[:, None]
            contrib = np.where(valid, TAB[q], 0.0)
            yield e1, e2, aname, contrib.sum(1) / denom

# ---------------- decode exato (Python, 1 stream) ----------------
def decode_py(digits, U, e1, e2, alpha):
    """digits: lista de valores. Retorna plaintext A-Z ('?' p/ invalido)."""
    top = {}
    k = 0
    for d in U:
        if d == e1 or d == e2:
            continue
        top[d] = alpha[k]; k += 1
    Uidx = {d: i for i, d in enumerate(U)}
    row1 = {d: alpha[7 + i] for d, i in Uidx.items()}
    row2 = {d: alpha[16 + i] for d, i in Uidx.items()}
    out = []
    i = 0
    n = len(digits)
    while i < n:
        d = digits[i]
        if d == e1 and i + 1 < n:
            out.append(row1.get(digits[i + 1], "?")); i += 2
        elif d == e2 and i + 1 < n:
            out.append(row2.get(digits[i + 1], "?")); i += 2
        elif d in top:
            out.append(top[d]); i += 1
        else:
            out.append("?"); i += 1
    return "".join(out)

# ---------------- oraculos duros ----------------
SOLVED = None
def hard_oracles(pt, tag):
    """Retorna hit dict ou None. Usado em TODO plaintext acima do corte."""
    forms = {pt, pt.lower(), pt.replace(" ", ""), pt.lower().replace(" ", "")}
    if len(pt) > 7:
        forms |= {pt[7:], pt[7:].lower()}
    for s in forms:
        for pw in {s, hashlib.sha256(s.encode()).hexdigest()}:
            h = O.aes_open(pw)
            if h:
                return {"kind": "aes_open", "pw": pw[:60], "hits": h, "tag": tag, "pt": pt[:80]}
        for c in (hashlib.sha256(s.encode()).digest(),
                  hashlib.sha256(s.lower().encode()).digest()):
            r = O.check_privkey(c)
            if r:
                return {"kind": "privkey", "hit": r, "tag": tag, "pt": pt[:80]}
    return None

def maybe_solve(hit, family):
    global SOLVED
    if hit and not SOLVED:
        SOLVED = {"family": family, **hit}
        json.dump(SOLVED, open(os.path.join(OUT, "SOLVED.json"), "w"), indent=2)
        print(f"\n!!! SOLVE ({family}) — solver/out/SOLVED.json")
        print(json.dumps(SOLVED, indent=2)[:2000])
    return SOLVED is not None

def log_family(rec):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def pairs_of(U):
    return [(U[i], U[j]) for i in range(9) for j in range(i + 1, 9)]

# ---------------- helpers de mapeamento / grade ----------------
MAPPINGS = {
    "a0": tuple(range(9)),                          # a->0 .. i->8
    "a1": tuple(range(1, 10)),                      # a->1 .. i->9
    "hint256134789": tuple(int(c) for c in "256134789"),
}

def sym_to_digits(sym, mapping):
    return [mapping[ord(c) - 97] for c in sym]

def col_order(key, reverse=False):
    idx = sorted(range(len(key)), key=lambda i: (key[i], i))
    return idx[::-1] if reverse else idx

def read_cols_by_order(s, nrows, ncols, order):
    rows = [s[r * ncols:(r + 1) * ncols] for r in range(nrows)]
    return "".join(rows[r][c] for c in order for r in range(nrows))

def write_cols_by_order(s, nrows, ncols, order):
    grid = [[""] * ncols for _ in range(nrows)]
    it = iter(s)
    for c in order:
        for r in range(nrows):
            grid[r][c] = next(it)
    return "".join(ch for row in grid for ch in row)

def boustrophedon(s, nrows, ncols):
    rows = [s[r * ncols:(r + 1) * ncols] for r in range(nrows)]
    return "".join(row if r % 2 == 0 else row[::-1] for r, row in enumerate(rows))

def spiral(s, nrows, ncols):
    grid = [list(s[r * ncols:(r + 1) * ncols]) for r in range(nrows)]
    out = []
    r0, r1, c0, c1 = 0, nrows - 1, 0, ncols - 1
    while r0 <= r1 and c0 <= c1:
        out += grid[r0][c0:c1 + 1]
        out += [grid[r][c1] for r in range(r0 + 1, r1 + 1)]
        if r0 < r1:
            out += grid[r1][c0:c1][::-1]
        if c0 < c1:
            out += [grid[r][c0] for r in range(r0 + 1, r1)][::-1]
        r0 += 1; r1 -= 1; c0 += 1; c1 -= 1
    return "".join(out)

# ---------------- runner generico de checkerboard p/ streams pequenos ----------------
def run_streams(name2digits, alphas, cutoff, family, tag):
    """name2digits: {label: (digit_list, U)}. Retorna (n_tested, [(score,label,pt)])."""
    best = []
    n = 0
    # agrupa por universo
    byU = {}
    for label, (digits, U) in name2digits.items():
        byU.setdefault(tuple(U), []).append((label, digits))
    for Ut, items in byU.items():
        U = list(Ut)
        D = np.array([d for _, d in items], dtype=np.int16)
        labels = [l for l, _ in items]
        aidxs = {an: alpha_to_idx(a) for an, a in alphas.items()}
        for e1, e2, aname, scores in score_block(D, U, pairs_of(U), aidxs):
            n += len(labels)
            for i in np.argsort(-scores)[:3]:
                pt = decode_py(items[int(i)][1], U, e1, e2, alphas[aname])
                exact = _sc(pt)
                best.append((exact, f"{labels[int(i)]}|e={e1},{e2}|{aname}", pt))
    best.sort(key=lambda r: -r[0])
    for sc, label, pt in best[:10]:
        if sc >= cutoff:
            hit = hard_oracles(pt, f"{family}:{label}")
            if hit:
                maybe_solve(hit, family)
                break
    return n, best

# =====================================================================
def F1(dbbi, alphas):
    t0 = time.time()
    print(f"\n=== F1: sweep exaustivo dbbi 9! x checkerboard ===", flush=True)
    dbbi_idx = np.array([ord(c) - 97 for c in dbbi])
    base_perms = np.array(list(itertools.permutations(range(9))), dtype=np.int16)  # 362880x9
    P1 = base_perms + 1  # universo 1-9
    aidxs = {an: alpha_to_idx(a) for an, a in alphas.items()}
    cands = []   # (score_vec, uni_base, perm_idx, e1, e2, alpha_nome)
    n_tested = 0
    for base, P in ((0, base_perms), (1, P1)):
        U = list(range(base, base + 9))
        D = P[:, dbbi_idx]  # (362880, 91)
        prs = pairs_of(U)
        for bi, (e1, e2, aname, scores) in enumerate(score_block(D, U, prs, aidxs)):
            n_tested += len(scores)
            top = np.argpartition(-scores, 6)[:6]
            for i in top:
                cands.append((float(scores[i]), base, int(i), e1, e2, aname))
            if bi % 36 == 0:
                print(f"  [F1] U={base}-{base+8} bloco {bi+1}/{len(prs)*len(aidxs)} "
                      f"({time.time()-t0:.0f}s)", flush=True)
        del D
    cands.sort(key=lambda r: -r[0])
    print(f"  [F1] decodes={n_tested:,}  re-scorando top candidatos...", flush=True)
    # re-score exato + decode exato (dedup por config)
    seen = set()
    exact = []
    for sc_vec, base, pi, e1, e2, aname in cands[:400]:
        key = (base, pi, e1, e2, aname)
        if key in seen:
            continue
        seen.add(key)
        perm = tuple(int(v) for v in (base_perms[pi] + base))
        digits = sym_to_digits(dbbi, perm)
        U = list(range(base, base + 9))
        pt = decode_py(digits, U, e1, e2, alphas[aname])
        exact.append((_sc(pt), base, perm, e1, e2, aname, pt))
        if len(exact) >= 120:
            break
    exact.sort(key=lambda r: -r[0])
    top50 = exact[:50]
    oracle_hits = []
    for sc, base, perm, e1, e2, aname, pt in top50:
        if sc >= -4.8:
            hit = hard_oracles(pt, f"F1:U{base}|perm={perm}|e={e1},{e2}|{aname}")
            if hit:
                oracle_hits.append(hit)
                maybe_solve(hit, "F1")
                break
    rec = {
        "family": "F1", "params": {"universes": ["0-8", "1-9"], "mappings": "9! cada",
        "escape_pairs": "36 nao-ordenados", "alphabets": list(alphas)},
        "n_tested": n_tested, "best_score": round(top50[0][0], 4),
        "best_plaintext": top50[0][6],
        "best_config": {"universe_base": top50[0][1], "perm": top50[0][2],
                        "e1": top50[0][3], "e2": top50[0][4], "alpha": top50[0][5]},
        "top50": [{"score": round(s, 4), "U": b, "e": [e1, e2], "alpha": a, "pt": p[:60]}
                  for s, b, _, e1, e2, a, p in top50],
        "oracle_hits": oracle_hits, "seconds": round(time.time() - t0, 1),
    }
    log_family(rec)
    print(f"  [F1] fim: best={top50[0][0]:.3f} pt={top50[0][6][:50]} "
          f"({rec['seconds']}s)", flush=True)
    return rec

def F2(dbbi, faed, alphas):
    t0 = time.time()
    print(f"\n=== F2: transposicao colunar 'matrixsumlist' no dbbi ===", flush=True)
    key = "matrixsumlist"
    assert len(key) == 13
    streams = {}
    for (nr, nc) in ((7, 13), (13, 7)):
        for rev in (False, True):
            order = col_order(key, rev)
            sfx = '_rev' if rev else ''
            if nc == len(order):
                streams[f"read_{nr}x{nc}{sfx}"] = read_cols_by_order(dbbi, nr, nc, order)
                streams[f"write_{nr}x{nc}{sfx}"] = write_cols_by_order(dbbi, nr, nc, order)
            else:  # nr == len(order): chave de 13 letras ordena as 13 LINHAS
                rows = [dbbi[r * nc:(r + 1) * nc] for r in range(nr)]
                streams[f"readrows_{nr}x{nc}{sfx}"] = "".join(rows[o] for o in order)
                wr = [""] * nr
                for i, o in enumerate(order):
                    wr[o] = rows[i]
                streams[f"writerows_{nr}x{nc}{sfx}"] = "".join(wr)
    # 2a: F1 reduzido (3 mapeamentos fixos)
    name2digits = {}
    for sname, s in streams.items():
        for mname, m in MAPPINGS.items():
            U = list(range(0, 9)) if mname == "a0" else list(range(1, 10))
            name2digits[f"{sname}|{mname}"] = (sym_to_digits(s, m), U)
    n1, best = run_streams(name2digits, alphas, -4.8, "F2", "checker")
    # 2b: resultado como keystream mod-9 sobre faed -> Bifid(CANON)
    n2 = 0
    bif_best = []
    fd = [ord(c) - 97 for c in faed]
    for sname, s in streams.items():
        for mname, m in MAPPINGS.items():
            kd = sym_to_digits(s, m)
            kd0 = [d - min(m) for d in kd]  # normaliza p/ 0-8
            for direction in (1, -1):
                comb = "".join("abcdefghi"[(fd[i] + direction * kd0[i % len(kd0)]) % 9]
                               for i in range(len(fd)))
                for period in (570, 285, 190, 114, 57, 38, 19, 15):
                    pt = bifid_decrypt(comb.upper(), CANON, period)
                    sc = _sc(pt)
                    n2 += 1
                    bif_best.append((sc, f"{sname}|{mname}|{'+-'[direction<0]}|p{period}", pt))
    bif_best.sort(key=lambda r: -r[0])
    for sc, label, pt in bif_best[:5]:
        if sc >= -5.0:
            hit = hard_oracles(pt, f"F2-bifid:{label}")
            if hit:
                maybe_solve(hit, "F2")
                break
    rec = {"family": "F2", "params": {"key": key, "streams": len(streams),
            "fixed_mappings": list(MAPPINGS)},
           "n_tested": n1 + n2,
           "best_score": round(best[0][0], 4) if best else None,
           "best_plaintext": best[0][2] if best else None,
           "top10": [{"score": round(s, 4), "cfg": l, "pt": p[:60]} for s, l, p in best[:10]],
           "bifid_top5": [{"score": round(s, 4), "cfg": l, "pt": p[:60]} for s, l, p in bif_best[:5]],
           "oracle_hits": [], "seconds": round(time.time() - t0, 1)}
    log_family(rec)
    print(f"  [F2] fim: n={n1+n2} best_cb={rec['best_score']} "
          f"best_bifid={bif_best[0][0]:.3f} ({rec['seconds']}s)", flush=True)
    return rec

def F3(faed, alphas):
    t0 = time.time()
    print(f"\n=== F3: VIC chain-addition keystreams ===", flush=True)
    dbbi_digits_a1 = sym_to_digits(O.sources()["dbbi"], MAPPINGS["a1"])
    sha = hashlib.sha256(b"GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe").hexdigest()
    sha_dec = str(int(sha, 16))
    seeds = {
        "101": [1, 0, 1], "163": [1, 6, 3], "140": [1, 4, 0], "1141": [1, 1, 4, 1],
        "7": [7], "28": [2, 8], "35": [3, 5], "256134789": [2, 5, 6, 1, 3, 4, 7, 8, 9],
        "dbbi_a1": dbbi_digits_a1, "sha_dec10": [int(c) for c in sha_dec[:10]],
        "sha_dec20": [int(c) for c in sha_dec[:20]],
        "89727": [8, 9, 7, 2, 7], "54": [5, 4], "47": [4, 7],
    }
    def chain(seed, m, n):
        s = list(seed)
        L = len(s)
        while len(s) < n:
            s.append((s[-L] + s[-L + 1]) % m)
        return s[:n]
    name2digits = {}
    fd = {0: [ord(c) - 97 for c in faed], 1: [ord(c) - 96 for c in faed]}
    for sname, seed in seeds.items():
        if len(seed) < 2:
            continue  # chain-addition precisa de >=2 digitos
        for m in (10, 9):
            ks = chain(seed, m, 570)
            for base in (0, 1):
                for direction in (1, -1):
                    r = [(fd[base][i] - base + direction * ks[i]) % 9 for i in range(570)]
                    lbl = f"{sname}|m{m}|a{base}|{'+' if direction > 0 else '-'}"
                    name2digits[lbl + "|U0"] = (r, list(range(9)))
                    name2digits[lbl + "|U1"] = ([d + 1 for d in r], list(range(1, 10)))
    n, best = run_streams(name2digits, alphas, -5.0, "F3", "chain")
    rec = {"family": "F3", "params": {"seeds": list(seeds), "mods": [10, 9],
            "mappings": ["a0", "a1"], "dirs": ["+", "-"], "U": ["0-8", "1-9"]},
           "n_tested": n, "best_score": round(best[0][0], 4) if best else None,
           "best_plaintext": best[0][2] if best else None,
           "top10": [{"score": round(s, 4), "cfg": l, "pt": p[:60]} for s, l, p in best[:10]],
           "oracle_hits": [], "seconds": round(time.time() - t0, 1)}
    log_family(rec)
    print(f"  [F3] fim: n={n} best={rec['best_score']} ({rec['seconds']}s)", flush=True)
    return rec

def F4(faed, alphas):
    t0 = time.time()
    print(f"\n=== F4: transposicoes do faed 15x38 ===", flush=True)
    key = "lastwordsbeforearchichoicethispassword"
    streams = {}
    for rev in (False, True):
        order = col_order(key, rev)
        streams[f"read15x38{'_rev' if rev else ''}"] = read_cols_by_order(faed, 15, 38, order)
        streams[f"write15x38{'_rev' if rev else ''}"] = write_cols_by_order(faed, 15, 38, order)
    streams["boustrophedon"] = boustrophedon(faed, 15, 38)
    streams["spiral"] = spiral(faed, 15, 38)
    name2digits = {}
    for sname, s in streams.items():
        for mname, m in MAPPINGS.items():
            U = list(range(0, 9)) if mname == "a0" else list(range(1, 10))
            name2digits[f"{sname}|{mname}"] = (sym_to_digits(s, m), U)
    n, best = run_streams(name2digits, alphas, -5.0, "F4", "transpose")
    rec = {"family": "F4", "params": {"key": key, "streams": list(streams)},
           "n_tested": n, "best_score": round(best[0][0], 4) if best else None,
           "best_plaintext": best[0][2] if best else None,
           "top10": [{"score": round(s, 4), "cfg": l, "pt": p[:60]} for s, l, p in best[:10]],
           "oracle_hits": [], "seconds": round(time.time() - t0, 1)}
    log_family(rec)
    print(f"  [F4] fim: n={n} best={rec['best_score']} ({rec['seconds']}s)", flush=True)
    return rec

def F5(f1_rec, faed, alphas):
    t0 = time.time()
    print(f"\n=== F5: melhor plaintext de F1 como chave ===", flush=True)
    pt = f1_rec["best_plaintext"]
    hits = []
    n = 0
    # 5a: senha AES direta / sha256 / variantes
    hit = hard_oracles(pt, "F5:best_f1")
    n += 1
    if hit:
        hits.append(hit); maybe_solve(hit, "F5")
    # 5b: keyword de Bifid sobre faed
    sq = kw_square(pt)
    bif_best = []
    if sq:
        for period in (570, 285, 190, 114, 57, 38, 19, 15):
            out = bifid_decrypt(faed.upper(), sq, period)
            bif_best.append((_sc(out), f"kwbifid|p{period}", out))
            n += 1
    # 5c: chave de transposicao colunar sobre faed (15x38 e 38x15)
    keylets = "".join(c for c in pt.upper() if c.isalpha())
    trans_top = []
    name2digits = {}
    for (nr, nc) in ((15, 38), (38, 15)):
        if len(keylets) != nc:
            continue
        for rev in (False, True):
            order = col_order(keylets.lower(), rev)
            s1 = read_cols_by_order(faed, nr, nc, order)
            s2 = write_cols_by_order(faed, nr, nc, order)
            for nm, s in ((f"read{nr}x{nc}{'_rev' if rev else ''}", s1),
                          (f"write{nr}x{nc}{'_rev' if rev else ''}", s2)):
                for mname, m in MAPPINGS.items():
                    U = list(range(0, 9)) if mname == "a0" else list(range(1, 10))
                    name2digits[f"{nm}|{mname}"] = (sym_to_digits(s, m), U)
    skipped = len(keylets) not in (15, 38)
    if name2digits:
        n2, trans_top = run_streams(name2digits, alphas, -5.0, "F5", "coltrans")
        n += n2
    for sc, label, out in bif_best:
        if sc >= -5.0:
            hit = hard_oracles(out, f"F5:{label}")
            if hit:
                hits.append(hit); maybe_solve(hit, "F5")
                break
    rec = {"family": "F5", "params": {"source": "F1 best", "pt": pt,
            "bifid_kw": sq, "coltrans_skipped_keylen": skipped and len(keylets)},
           "n_tested": n,
           "bifid_scores": [{"score": round(s, 4), "cfg": l, "pt": p[:60]} for s, l, p in bif_best[:5]],
           "coltrans_top5": [{"score": round(s, 4), "cfg": l, "pt": p[:60]} for s, l, p in trans_top[:5]],
           "oracle_hits": hits, "seconds": round(time.time() - t0, 1)}
    log_family(rec)
    print(f"  [F5] fim: n={n} ({rec['seconds']}s)", flush=True)
    return rec

def main():
    init_scorer()
    src = O.sources()
    dbbi, faed = src["dbbi"], src["faed"]
    alphas = build_alphabets(dbbi)
    print(f"[vic_full_attack] dbbi={len(dbbi)} faed={len(faed)} "
          f"alfabetos={list(alphas)}", flush=True)
    for an, a in alphas.items():
        assert len(a) == 25 and len(set(a)) == 25, (an, a)
    t0 = time.time()
    if "--skip-f1" in sys.argv:
        # reutiliza o ultimo registro F1 do log (ja executado nesta maquina)
        f1 = None
        with open(LOG, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r.get("family") == "F1":
                    f1 = r
        assert f1, "nenhum registro F1 no log"
        print(f"[skip-f1] reuso: best={f1['best_score']} pt={f1['best_plaintext'][:40]}",
              flush=True)
    else:
        f1 = F1(dbbi, alphas)
    if SOLVED: return
    f2 = F2(dbbi, faed, alphas)
    if SOLVED: return
    f3 = F3(faed, alphas)
    if SOLVED: return
    f4 = F4(faed, alphas)
    if SOLVED: return
    f5 = F5(f1, faed, alphas)
    print(f"\n=== FIM ({time.time()-t0:.0f}s) ===", flush=True)
    for r in (f1, f2, f3, f4, f5):
        print(f"  {r['family']}: n={r['n_tested']:,} best={r.get('best_score')}", flush=True)

if __name__ == "__main__":
    main()
