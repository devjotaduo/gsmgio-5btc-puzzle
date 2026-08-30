# -*- coding: utf-8 -*-
"""
COMPOSITION ATTACK — ultimas duas/tres lacunas de COMPOSICAO do endgame:

  G1  Checkerboard PRIMEIRO, Bifid DEPOIS (sobre faed):
      faed (a=0 e a=1) -> straddling checkerboard (36 pares de escape x
      5 alfabetos: dbbi_firstocc, vic322, canon25, etaoin, matrixsumlist+filler)
      -> texto 25 letras -> Bifid decode com o MESMO alfabeto como quadrado
      x periodos {5,6,10,15,19,30,38,57,95,114,190,285,570,sem-seriacao}.
      Direcao inversa: Bifid(faed, sq, per) -> re-encode checkerboard (36 pares)
      -> decode checkerboard (alfabetos) -> score.
  G2  dbbi como keystream sobre a SAIDA do checkerboard (nao sobre faed cru):
      faed -> checkerboard (grade de G1), top-200 por score intermediario ->
      aplica dbbi (91 simbolos; mapeamentos a=0/a=1/256134789, repetido
      ciclicamente, +/- mod 25 e mod 26) -> score + oraculos.
  G3  dbbi como chave de transposicao colunar de comprimento arbitrario
      sobre faed: dbbi como letras (rank alfabetico estavel) e como digitos
      (a=0/a=1, rank estavel) -> read-in/read-out colunar (larguras 91, 13, 7
      em stream continuo; 15x38 com chave = primeiros 38 simbolos do dbbi)
      -> checkerboard (3 mapeamentos x 36 pares x 2 alfabetos) -> score.

Oraculos DUROS p/ score >= -5.0: aes_open(pt), aes_open(sha256hex),
aes_open(lower-sem-espacos), e pt como keyword de Bifid sobre faed
(periodos tematicos) -> oraculo de novo se >= -5.0.
Qualquer hit -> solver/out/SOLVED.json e PARA.

Validacao: bifid_decrypt(faed, CANON, 570) == 'BTCSEED...' score -5.577.
Log: _work/composition_attack.jsonl (1 registro por familia).
"""
import os, sys, json, time, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "out"); os.makedirs(OUT, exist_ok=True)
WORK = os.path.join(ROOT, "_work"); os.makedirs(WORK, exist_ok=True)
LOG = os.path.join(WORK, "composition_attack.jsonl")

import oracles as O
from scorer import Scorer
from prime_attack import CANON, bifid_decrypt, kw_square

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
PERIODS = [5, 6, 10, 15, 19, 30, 38, 57, 95, 114, 190, 285, 570]  # + "sem seriacao" = len(texto)
CUTOFF = -5.0

_sc = Scorer()

# ---------------- alfabetos (25 slots) ----------------
def _firstocc_fill(seed):
    seen = []
    for c in seed.upper() + ALPHA25:
        if c in ALPHA25 and c not in seen:
            seen.append(c)
    return "".join(seen)

def build_alphabets(dbbi):
    vic322 = "FUBCDORALETHINGKYMVPSJQZXW".replace("J", "")
    return {
        "dbbi_firstocc": _firstocc_fill(dbbi),
        "vic322": vic322,
        "canon25": ALPHA25,
        "etaoin": _firstocc_fill("ETAOINSHRDLU"),
        "matrixsumlist": _firstocc_fill("matrixsumlist"),
    }

# ---------------- checkerboard ----------------
MAPPINGS = {
    "a0": tuple(range(9)),
    "a1": tuple(range(1, 10)),
    "hint256134789": tuple(int(c) for c in "256134789"),
}

def sym_to_digits(sym, mapping):
    return [mapping[ord(c) - 97] for c in sym]

def pairs_of(U):
    return [(U[i], U[j]) for i in range(9) for j in range(i + 1, 9)]

def cb_decode(digits, U, e1, e2, alpha):
    """decode exato (de vic_full_attack.decode_py)."""
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
    i, n = 0, len(digits)
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

def cb_encode(text, U, e1, e2, alpha):
    """inverso de cb_decode: letras -> digitos (board de 25 slots)."""
    slot = {c: i for i, c in enumerate(alpha)}
    top_digits = [d for d in U if d != e1 and d != e2]
    Uidx = {d: i for i, d in enumerate(U)}
    out = []
    for c in text:
        s = slot.get(c)
        if s is None:
            continue
        if s < 7:
            out.append(top_digits[s])
        elif s < 16:
            out += [e1, U[s - 7]]
        else:
            out += [e2, U[s - 16]]
    return out

# ---------------- transposicao colunar ----------------
def col_order(key, reverse=False):
    """rank estavel da chave (letras ou digitos)."""
    idx = sorted(range(len(key)), key=lambda i: (key[i], i))
    return idx[::-1] if reverse else idx

def coltrans_out(s, ncols, order):
    """escreve s row-major (linhas de ncols), le colunas na ordem dada."""
    nrows = (len(s) + ncols - 1) // ncols
    return "".join(s[r * ncols + c] for c in order for r in range(nrows)
                   if r * ncols + c < len(s))

def coltrans_in(s, ncols, order):
    """inverso: s sao as colunas lidas na ordem; reconstroi o row-major."""
    nrows = (len(s) + ncols - 1) // ncols
    lens = {c: sum(1 for r in range(nrows) if r * ncols + c < len(s)) for c in range(ncols)}
    cols = {}
    p = 0
    for c in order:
        cols[c] = s[p:p + lens[c]]; p += lens[c]
    return "".join(cols[c][r] for r in range(nrows) for c in range(ncols)
                   if r < len(cols[c]))

# ---------------- oraculos ----------------
SOLVED = None

def maybe_solve(hit, family):
    global SOLVED
    if hit and not SOLVED:
        SOLVED = {"family": family, **hit}
        json.dump(SOLVED, open(os.path.join(OUT, "SOLVED.json"), "w"), indent=2)
        print(f"\n!!! SOLVE ({family}) — solver/out/SOLVED.json")
        print(json.dumps(SOLVED, indent=2)[:2000])
    return SOLVED is not None

def hard_oracles(pt, tag, faed):
    """aes_open(pt / sha256hex / lower-sem-espacos) + pt como keyword Bifid."""
    if not pt:
        return None
    forms = {pt, pt.lower(), pt.replace(" ", ""), pt.lower().replace(" ", "")}
    if len(pt) > 7:
        forms |= {pt[7:], pt[7:].lower()}
    for s in forms:
        for pw in {s, hashlib.sha256(s.encode()).hexdigest()}:
            h = O.aes_open(pw)
            if h:
                return {"kind": "aes_open", "pw": pw[:60], "hits": h, "tag": tag, "pt": pt[:80]}
    # keyword Bifid final sobre faed (periodos tematicos)
    sq = kw_square(pt)
    if sq:
        for period in (570, 285, 190, 114, 95, 57, 38, 30, 19, 15):
            out = bifid_decrypt(faed.upper(), sq, period)
            if _sc(out) >= CUTOFF:
                h = O.aes_open(out) or O.aes_open(out.lower())
                if h:
                    return {"kind": "kw_bifid_aes", "period": period, "hits": h,
                            "tag": tag, "pt": out[:80]}
                hh = O.check_privkey(hashlib.sha256(out.encode()).digest())
                if hh:
                    return {"kind": "kw_bifid_privkey", "period": period, "hit": hh,
                            "tag": tag, "pt": out[:80]}
    return None

def log_family(rec):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# =====================================================================
def G1(faed, alphas):
    """Checkerboard -> Bifid (e inversa)."""
    t0 = time.time()
    print(f"\n=== G1: checkerboard -> Bifid (e inversa) ===", flush=True)
    n = 0
    best = []  # (score, cfg, pt)
    boards = []  # guarda intermediarios p/ G2: (score_cb, cfg, pt_cb)
    for mname in ("a0", "a1"):
        m = MAPPINGS[mname]
        U = list(range(0, 9)) if mname == "a0" else list(range(1, 10))
        digits = sym_to_digits(faed, m)
        for (e1, e2) in pairs_of(U):
            for aname, alpha in alphas.items():
                cb = cb_decode(digits, U, e1, e2, alpha)
                n += 1
                sc_cb = _sc(cb)
                boards.append((sc_cb, f"{mname}|e={e1},{e2}|{aname}", cb))
                cb_clean = cb.replace("?", "")
                if len(cb_clean) < 20:
                    continue
                # Bifid DEPOIS com o MESMO alfabeto como quadrado
                for period in PERIODS + [len(cb_clean)]:
                    pt = bifid_decrypt(cb_clean, alpha, period)
                    n += 1
                    sc = _sc(pt)
                    best.append((sc, f"cb2bifid|{mname}|e={e1},{e2}|{aname}|p{period}", pt))
    # direcao inversa: Bifid PRIMEIRO -> checkerboard
    faedU = faed.upper().replace("J", "I")
    for aname, sq in alphas.items():
        for period in PERIODS + [570]:
            mid = bifid_decrypt(faedU, sq, period)
            U = list(range(9))
            for (e1, e2) in pairs_of(U):
                digs = cb_encode(mid, U, e1, e2, sq)
                for aname2, alpha2 in alphas.items():
                    pt = cb_decode(digs, U, e1, e2, alpha2)
                    n += 1
                    best.append((_sc(pt),
                                 f"bifid2cb|{aname}|p{period}|e={e1},{e2}|{aname2}", pt))
    best.sort(key=lambda r: -r[0])
    boards.sort(key=lambda r: -r[0])
    hits = []
    seen = set()
    for sc, cfg, pt in best:
        if sc < CUTOFF:
            break
        if pt[:60] in seen:
            continue
        seen.add(pt[:60])
        hit = hard_oracles(pt, f"G1:{cfg}", faed)
        if hit:
            hits.append(hit); maybe_solve(hit, "G1"); break
    rec = {"family": "G1", "params": {"mappings": ["a0", "a1"], "pairs": 36,
            "alphabets": list(alphas), "periods": PERIODS + ["full"]},
           "n_tested": n, "best_score": round(best[0][0], 4),
           "best_plaintext": best[0][2][:80], "best_config": best[0][1],
           "top10": [{"score": round(s, 4), "cfg": c, "pt": p[:60]} for s, c, p in best[:10]],
           "oracle_hits": hits, "seconds": round(time.time() - t0, 1)}
    log_family(rec)
    print(f"  [G1] n={n:,} best={best[0][0]:.3f} ({rec['seconds']}s)", flush=True)
    return rec, boards

def G2(dbbi, faed, boards):
    """dbbi como keystream sobre a SAIDA do checkerboard (top-200)."""
    t0 = time.time()
    print(f"\n=== G2: dbbi keystream sobre saida do checkerboard (top-200) ===", flush=True)
    n = 0
    best = []
    keys = {}
    for mname, m in MAPPINGS.items():
        keys[mname] = [d - min(m) for d in sym_to_digits(dbbi, m)]  # normaliza 0-8
    for sc_cb, cb_cfg, cb in boards[:200]:
        base = cb.replace("?", "")
        if len(base) < 20:
            continue
        idx25 = [ALPHA25.index(c) for c in base]
        idx26 = [ord(c) - 65 for c in base]  # A-Z com J (J nao ocorre)
        for kname, kd in keys.items():
            L = len(kd)
            for mod, idx, alpha in ((25, idx25, ALPHA25), (26, idx26, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")):
                for direction in (1, -1):
                    pt = "".join(alpha[(idx[i] + direction * kd[i % L]) % mod]
                                 for i in range(len(idx)))
                    n += 1
                    sc = _sc(pt)
                    best.append((sc, f"G2|{cb_cfg}|{kname}|mod{mod}|{'+' if direction > 0 else '-'}", pt))
    best.sort(key=lambda r: -r[0])
    hits = []
    seen = set()
    for sc, cfg, pt in best:
        if sc < CUTOFF:
            break
        if pt[:60] in seen:
            continue
        seen.add(pt[:60])
        hit = hard_oracles(pt, cfg, faed)
        if hit:
            hits.append(hit); maybe_solve(hit, "G2"); break
    rec = {"family": "G2", "params": {"top_boards": 200, "dbbi_mappings": list(MAPPINGS),
            "mods": [25, 26], "dirs": ["+", "-"]},
           "n_tested": n, "best_score": round(best[0][0], 4),
           "best_plaintext": best[0][2][:80], "best_config": best[0][1],
           "top10": [{"score": round(s, 4), "cfg": c, "pt": p[:60]} for s, c, p in best[:10]],
           "oracle_hits": hits, "seconds": round(time.time() - t0, 1)}
    log_family(rec)
    print(f"  [G2] n={n:,} best={best[0][0]:.3f} ({rec['seconds']}s)", flush=True)
    return rec

def G3(dbbi, faed, alphas):
    """dbbi como chave de transposicao colunar sobre faed -> checkerboard."""
    t0 = time.time()
    print(f"\n=== G3: dbbi como chave de transposicao colunar sobre faed ===", flush=True)
    n = 0
    best = []
    # chaves: letras (rank alfabetico estavel) e digitos a0/a1 (rank estavel)
    keys = {"letters": dbbi,
            "digits_a0": sym_to_digits(dbbi, MAPPINGS["a0"]),
            "digits_a1": sym_to_digits(dbbi, MAPPINGS["a1"])}
    streams = {}
    for kname, key in keys.items():
        for w in (91, 13, 7):
            order = col_order(key[:w])  # rank estavel dentro dos primeiros w simbolos
            streams[f"{kname}|w{w}|out"] = coltrans_out(faed, w, order)
            streams[f"{kname}|w{w}|in"] = coltrans_in(faed, w, order)
        # 15x38 row-major: chave = primeiros 38 simbolos do dbbi
        order38 = col_order(key[:38])
        streams[f"{kname}|15x38|out"] = coltrans_out(faed, 38, order38)
        streams[f"{kname}|15x38|in"] = coltrans_in(faed, 38, order38)
    alph2 = {k: alphas[k] for k in ("dbbi_firstocc", "canon25")}
    for sname, s in streams.items():
        for mname, m in MAPPINGS.items():
            U = list(range(0, 9)) if mname == "a0" else list(range(1, 10))
            digits = sym_to_digits(s, m)
            for (e1, e2) in pairs_of(U):
                for aname, alpha in alph2.items():
                    pt = cb_decode(digits, U, e1, e2, alpha)
                    n += 1
                    best.append((_sc(pt), f"{sname}|{mname}|e={e1},{e2}|{aname}", pt))
    best.sort(key=lambda r: -r[0])
    hits = []
    seen = set()
    for sc, cfg, pt in best:
        if sc < CUTOFF:
            break
        if pt[:60] in seen:
            continue
        seen.add(pt[:60])
        hit = hard_oracles(pt, f"G3:{cfg}", faed)
        if hit:
            hits.append(hit); maybe_solve(hit, "G3"); break
    rec = {"family": "G3", "params": {"keys": list(keys), "widths": [91, 13, 7, "15x38"],
            "io": ["out", "in"], "mappings": list(MAPPINGS), "pairs": 36,
            "alphabets": list(alph2)},
           "n_tested": n, "best_score": round(best[0][0], 4),
           "best_plaintext": best[0][2][:80], "best_config": best[0][1],
           "top10": [{"score": round(s, 4), "cfg": c, "pt": p[:60]} for s, c, p in best[:10]],
           "oracle_hits": hits, "seconds": round(time.time() - t0, 1)}
    log_family(rec)
    print(f"  [G3] n={n:,} best={best[0][0]:.3f} ({rec['seconds']}s)", flush=True)
    return rec

def main():
    src = O.sources()
    dbbi, faed = src["dbbi"], src["faed"]
    alphas = build_alphabets(dbbi)
    for an, a in alphas.items():
        assert len(a) == 25 and len(set(a)) == 25, (an, a)
    # validacao do Bifid contra o decode conhecido
    canon_pt = bifid_decrypt(faed.upper(), CANON, 570)
    assert canon_pt.startswith("BTCSEED"), canon_pt[:20]
    print(f"[composition_attack] Bifid ok (BTCSEED, score {_sc(canon_pt):.3f}); "
          f"alfabetos={list(alphas)}", flush=True)
    t0 = time.time()
    g1, boards = G1(faed, alphas)
    if SOLVED: return
    g2 = G2(dbbi, faed, boards)
    if SOLVED: return
    g3 = G3(dbbi, faed, alphas)
    print(f"\n=== FIM ({time.time()-t0:.0f}s) ===", flush=True)
    for r in (g1, g2, g3):
        print(f"  {r['family']}: n={r['n_tested']:,} best={r['best_score']}", flush=True)

if __name__ == "__main__":
    main()
