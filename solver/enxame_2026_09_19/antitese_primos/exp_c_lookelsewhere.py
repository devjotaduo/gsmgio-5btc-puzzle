"""F8 / Experimento C — efeito look-elsewhere honesto.

O argumento do lead diz: "unica familia em 2.925 regras testadas". Isso mede o numerador
(so uma regra funciona em dbbi). Falta o denominador correto do teste de significancia:
com que frequencia um texto ALEATORIO admite ALGUMA regra da mesma familia a priori?

Familia a priori (1.170 regras): letra X em a..i (9) x sufixo Y em {nenhum} U a..i (10)
x 13 familias de posicoes marcadas (primos 1-based, primos 0-based, compostos, quadrados,
Fibonacci, triangulares, impares, pares, multiplos de 3..7).

Mede-se:
  C1 - quantas das 1.170 regras dbbi admite;
  C2 - fracao de embaralhamentos (preservando contagens) que admitem >= 1 regra qualquer;
  C3 - fracao que admitem >= 1 regra com posicoes PRIMAS (o rotulo `yellowblueprimes`
       fixa "primos", entao este e o look-elsewhere restrito e honesto).

Semente mestra: 20260919.
"""
from __future__ import annotations
import sys, json, time
import numpy as np

sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
import gsmg_common as G
from fast_seg import admits, encode
from seg_core import MARK_FAMILIES

ALPHA = "abcdefghi"
IDX = {c: i for i, c in enumerate(ALPHA)}
SEED = 20260919
n = len(G.DBBI)

RULES = []
for fam, fn in MARK_FAMILIES.items():
    marks = fn(n + 2)
    for xi, x in enumerate(ALPHA):
        for y in [None] + list(ALPHA):
            RULES.append((fam, marks, xi, (IDX[y] if y else None), x, y))


def shuffles(rng, N):
    a = np.array([IDX[c] for c in G.DBBI], dtype=np.uint8)
    out = np.empty((N, n), dtype=np.uint8)
    for r in range(N):
        out[r] = rng.permutation(a)
    return out


def sweep(arr, rules, label):
    any_hit = np.zeros(len(arr), dtype=bool)
    any_prime = np.zeros(len(arr), dtype=bool)
    per_rule = {}
    t0 = time.time()
    for fam, marks, xi, yi, x, y in rules:
        ok = admits(arr, xi, yi, marks)
        c = int(ok.sum())
        if c:
            per_rule[f"{fam}|{x}|{y or '-'}"] = c
            any_hit |= ok
            if fam.startswith("primos"):
                any_prime |= ok
    print(f"  [{label}] {len(rules)} regras, {len(arr)} strings, {time.time()-t0:.0f}s")
    return any_hit, any_prime, per_rule


def main():
    rng = np.random.default_rng(np.random.SeedSequence(SEED + 2))
    out = {"n_regras": len(RULES)}

    print("== C1: dbbi sob as", len(RULES), "regras ==")
    db = encode([G.DBBI])
    _, _, pr = sweep(db, RULES, "dbbi")
    out["C1_dbbi_regras_que_funcionam"] = pr
    for k, v in pr.items():
        print("   ", k)

    print("\n== C2/C3: triagem em 2.000 embaralhamentos ==")
    arr = shuffles(rng, 2000)
    ah, ap, pr2 = sweep(arr, RULES, "triagem")
    print(f"   admitem >=1 regra qualquer: {int(ah.sum())}/2000 = {ah.mean():.4f}")
    print(f"   admitem >=1 regra PRIMA:    {int(ap.sum())}/2000 = {ap.mean():.4f}")
    print("   regras vivas na triagem:", json.dumps(pr2, ensure_ascii=False))
    out["C2_triagem"] = {"N": 2000, "any_hits": int(ah.sum()), "prime_hits": int(ap.sum()),
                         "por_regra": pr2}

    vivas = [r for r in RULES if f"{r[0]}|{r[4]}|{r[5] or '-'}" in pr2] or []
    if vivas:
        print(f"\n== C2b: {len(vivas)} regras vivas em 20.000 embaralhamentos ==")
        arr2 = shuffles(rng, 20000)
        ah2, ap2, pr3 = sweep(arr2, vivas, "confirmacao")
        print(f"   admitem >=1 regra: {int(ah2.sum())}/20000 = {ah2.mean():.5f}")
        print(f"   PRIMA:             {int(ap2.sum())}/20000 = {ap2.mean():.5f}")
        out["C2b_confirmacao"] = {"N": 20000, "any_hits": int(ah2.sum()),
                                  "prime_hits": int(ap2.sum()), "por_regra": pr3}
    else:
        out["C2b_confirmacao"] = "nenhuma regra sobreviveu a triagem"

    json.dump(out, open("/home/user/gsmgio-5btc-puzzle/_work/enxame_2026-09-19/antitese_primos/exp_c.json", "w"),
              indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
