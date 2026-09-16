# -*- coding: utf-8 -*-
"""permutation_search2 — SEGUNDA passada da familia permutation_search.

A rodada 2 ja fechou: permutacoes de indice (primos/coloridos/mod k), leituras de grade de UM lado
(escrita row-major, leitura por rota), colunar keyed simples, hill-climb estruturado. Aqui cubro APENAS
o que sobrou dentro do mesmo frame:

  (A) ROTA DUPLA (route cipher de dois lados): escrever o stream na grade por uma rota A e ler por uma rota B.
      A rodada anterior so fez A = row-major. 32 rotas x 32 rotas x todas as grades de 570 e de 91.
  (B) COLUNAR DUPLA (duas transposicoes colunares keyed encadeadas) — o Arquiteto fala em "SIXTEEN
      ENCRYPTIONS AND OR SEVEN INTERTWINED PASSWORDS"; transposicao dupla e o classico de campo.
  (C) METADES COM ROTAS DIFERENTES ("half and better half"): rota P na 1a metade, rota Q na 2a,
      concatenadas ou intercaladas — antes as duas metades usavam a MESMA rota.

Hipotese (falsificavel, espaco finito): se faed/dbbi sao um stream serial (checkerboard/VIC ou digitos de
um numero) embaralhado por uma rota de dois lados / transposicao dupla / rotas por metade, entao a inversa
dessa permutacao devolve a dependencia lag-1 do original, com |z| >= 8 em n=570 (calibracao: checkerboard
real da 3.2.2 da z ~ +6 com n=149). O maximo esperado do nulo com ~50 mil permutacoes e |z| ~ 4,8.

Fitness reusado de permutation_search (mi1 lag-1 e IoC de digrafos vs nulo de embaralhados).
"""
import sys, time, json
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
import permutation_search as PS   # reuso: mi1/ioc2/Null/inv/apply/grid_reads/columnar/decode_seq

LOG = SP + r"\permutation_search2.jsonl"
PS.LOG = LOG                       # os decodes/AES da PS logam no meu arquivo
np.random.seed(1327)
T0 = time.time()
HYP = ("faed/dbbi = stream serial embaralhado por rota de DOIS lados (escrita rota A, leitura rota B), "
       "transposicao colunar DUPLA, ou rotas diferentes por metade; a inversa restaura MI lag-1 com |z|>=8.")
G.jsonl(LOG, {"family": "permutation_search2", "hypothesis": HYP})

# ---------------------------------------------------------------- familias NOVAS
def routes(r, c):
    """dict nome -> lista de indices flat na ordem da rota (32 rotas: 8 bases x 4 flips)."""
    return PS.grid_reads(r, c)

def divisors(n, lo=2):
    return [r for r in range(lo, n + 1) if n % r == 0 and n // r >= 2]

def fam_route2(n, max_perms=None):
    """(A) escrever por rota A, ler por rota B: p[u] = posA[B[u]]."""
    out = {}
    for r in divisors(n):
        rts = routes(r, n // r)
        items = list(rts.items())
        for na, A in items:
            posA = np.empty(n, dtype=np.int32); posA[np.array(A)] = np.arange(n)
            for nb, B in items:
                if na == nb: continue
                out[f"r2:{na}>{nb}"] = posA[np.array(B)].tolist()
        if max_perms and len(out) > max_perms: break
    return out

COLKEYS = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "yellowblueprimes",
           "salphaseion", "cosmicduality", "yinyang", "hashthetext", "halfandbetterhalf", "anstoo",
           "theseedisplanted", "ourfirsthintisyourlastcommand", "sha256"]
def col_base(n):
    """perms colunares base (chave-token x largura), deduplicadas."""
    out = {}
    for k in COLKEYS + [G.DBBI[:17], G.DBBI[:24]]:
        for w in sorted({len(k), 7, 11, 13, 15, 19, 30, 38}):
            kw = (k * (w // len(k) + 1))[:w]
            out[f"c:{k[:12]}_w{w}"] = PS.columnar_encrypt_perm(n, kw)
    return out

def fam_dblcol(n):
    """(B) composicao de duas colunares: p = p1 o p2 (aplica p2 depois p1) e a ordem trocada."""
    base = col_base(n); items = list(base.items()); out = {}
    arrs = {k: np.array(v) for k, v in items}
    for na, A in items:
        a = arrs[na]
        for nb, B in items:
            if na == nb: continue
            out[f"d2:{na}>{nb}"] = a[np.array(B)].tolist()
    return out

def fam_halves_mixed(n):
    """(C) rota P na 1a metade, rota Q na 2a; concatena ou intercala."""
    if n % 2: return {}
    h = n // 2; base = {}
    for r in divisors(h):
        for nm, p in routes(r, h // r).items():
            if nm.endswith("_id") or "spiral" in nm or "diagzig" in nm:
                base[nm] = p
    items = list(base.items()); out = {}
    for na, P in items:
        for nb, Q in items:
            out[f"hm:{na}|{nb}"] = P + [i + h for i in Q]                      # concatenadas
            out[f"hi:{na}|{nb}"] = [x for i in range(h) for x in (P[i], Q[i] + h)]  # intercaladas
    return out

# ---------------------------------------------------------------- varredura
def scan(a, null, fams, tag, keep=40):
    """avalia cada permutacao e sua inversa; devolve top por |z| e estatistica por familia."""
    res = []; seen = set(); stats = {}
    for fam, d in fams.items():
        zs = []
        for name, p in d.items():
            pa = np.array(p, dtype=np.int32)
            for side, q in (("perm", pa), ("inv", np.argsort(pa))):
                key = q.astype(np.int16).tobytes()
                if key in seen: continue
                seen.add(key)
                b = a[q]; z = null.z(b); zi = null.zio(b)
                zs.append(z); res.append((z, zi, fam, f"{name}/{side}", q))
        zs = np.array(zs) if len(zs) else np.zeros(1)
        stats[fam] = {"n_perms": int(len(zs)), "z_mean": round(float(zs.mean()), 3), "z_sd": round(float(zs.std()), 3),
                      "z_max": round(float(zs.max()), 3), "z_min": round(float(zs.min()), 3),
                      "n_abs_ge5": int((np.abs(zs) >= 5).sum()), "n_abs_ge8": int((np.abs(zs) >= 8).sum())}
        G.jsonl(LOG, {"tag": tag, "family": fam, **stats[fam]})
    res.sort(key=lambda t: -abs(t[0]))
    return res[:keep], stats, len(seen)

def main():
    N_EVAL = 0
    # ---------------- CONTROLE POSITIVO ----------------
    D322 = np.array([int(ch) for ch in
        "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"])
    ctrl = {}
    d144 = D322[:144]                              # 144 = 12x12, permite rota de dois lados
    null144 = PS.Null(d144, 10)
    ctrl["z_real_144"] = round(null144.z(d144), 2)
    A = routes(12, 12)["g12x12_spiral_in_id"]; B = routes(12, 12)["g12x12_diagzig_rot"]
    posA = np.empty(144, dtype=np.int32); posA[np.array(A)] = np.arange(144)
    pmix = posA[np.array(B)]
    scr = d144[pmix]
    ctrl["z_scrambled_route2"] = round(null144.z(scr), 2)
    top, st, nse = scan(scr, null144, {"route2": fam_route2(144)}, "ctrl_route2", keep=5)
    N_EVAL += nse
    ctrl["route2_top"] = [(round(float(z), 2), nm) for z, _, _, nm, _ in top]
    ctrl["route2_recovered"] = bool(np.array_equal(scr[top[0][4]], d144))
    # controle da colunar dupla (n=149 inteiro)
    null149 = PS.Null(D322, 10); ctrl["z_real_149"] = round(null149.z(D322), 2)
    cb = col_base(149)
    k1 = next(k for k in cb if k.startswith("c:matrixsumli") and k.endswith("_w13"))
    k2 = next(k for k in cb if k.startswith("c:yinyang") and k.endswith("_w19"))
    p1 = np.array(cb[k1]); p2 = np.array(cb[k2])
    pd = p1[p2]; scr2 = D322[pd]
    ctrl["z_scrambled_dblcol"] = round(null149.z(scr2), 2)
    top2, st2, nse2 = scan(scr2, null149, {"dblcol": fam_dblcol(149)}, "ctrl_dblcol", keep=5)
    N_EVAL += nse2
    ctrl["dblcol_top"] = [(round(float(z), 2), nm) for z, _, _, nm, _ in top2]
    ctrl["dblcol_recovered"] = bool(np.array_equal(scr2[top2[0][4]], D322))
    G.jsonl(LOG, {"control": ctrl}); print(json.dumps(ctrl, indent=1), flush=True)

    # ---------------- FAED (n=570) ----------------
    faed = np.array(G.digits(G.FAED)) - 1          # 0..8
    nullF = PS.Null(faed, 9)
    baseF = {"z_mi1": round(nullF.z(faed), 2), "z_ioc2": round(nullF.zio(faed), 2)}
    famsF = {"route2": fam_route2(570), "dblcol": fam_dblcol(570), "halves_mixed": fam_halves_mixed(570)}
    print("faed fams:", {k: len(v) for k, v in famsF.items()}, flush=True)
    topF, stF, nseF = scan(faed, nullF, famsF, "faed", keep=40)
    N_EVAL += nseF
    print("faed base", baseF, "n_perm", nseF, "top5", [(round(float(z), 2), nm) for z, _, _, nm, _ in topF[:5]],
          "t", int(time.time() - T0), flush=True)

    # ---------------- DBBI (n=91) ----------------
    dbbi = np.array(G.digits(G.DBBI)) - 1
    nullD = PS.Null(dbbi, 9)
    baseD = {"z_mi1": round(nullD.z(dbbi), 2), "z_ioc2": round(nullD.zio(dbbi), 2)}
    famsD = {"route2": fam_route2(91), "dblcol": fam_dblcol(91)}
    print("dbbi fams:", {k: len(v) for k, v in famsD.items()}, flush=True)
    topD, stD, nseD = scan(dbbi, nullD, famsD, "dbbi", keep=40)
    N_EVAL += nseD
    print("dbbi base", baseD, "n_perm", nseD, "top5", [(round(float(z), 2), nm) for z, _, _, nm, _ in topD[:5]],
          "t", int(time.time() - T0), flush=True)

    # ---------------- DECODE dos top-K (oraculo duro) ----------------
    K = 20
    for tag, a, top in (("faed", faed, topF), ("dbbi", dbbi, topD)):
        for z, zi, fam, nm, q in top[:K]:
            sym = "".join(chr(97 + int(x)) for x in a[q])
            PS.decode_seq(sym, f"{tag}:{nm}_z{round(float(z),2)}")
        print(tag, "decode ok", PS.best, "t", int(time.time() - T0), flush=True)

    out = {"n_tests": {"perm_eval": N_EVAL, **PS.N}, "hard": PS.hard, "soft": PS.soft, "best": PS.best,
           "control": ctrl, "faed_base": baseF, "faed_stats": stF,
           "faed_top": [(round(float(z), 2), nm) for z, _, _, nm, _ in topF[:12]],
           "dbbi_base": baseD, "dbbi_stats": stD,
           "dbbi_top": [(round(float(z), 2), nm) for z, _, _, nm, _ in topD[:12]],
           "secs": int(time.time() - T0)}
    out["n_tests_total"] = N_EVAL + PS.N["decode"] + PS.N["aes"] + PS.N["priv"]
    G.jsonl(LOG, {"SUMMARY": out})
    json.dump(out, open(SP + r"\permutation_search2_summary.json", "w"), indent=1, default=str)
    print(json.dumps(out, indent=1, default=str)[:4000], flush=True)

if __name__ == "__main__":
    main()
