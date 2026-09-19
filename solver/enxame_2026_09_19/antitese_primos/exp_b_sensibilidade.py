"""F8 / Experimento B — sensibilidade a composicao e comprimento.

B1: quantos 'b' um texto ALEATORIO de 91 simbolos precisa para admitir a segmentacao?
    (dbbi tem 25; o minimo aritmetico e 23 marcadores). Se a propriedade so aparece com
    muito mais 'b' do que dbbi tem, a folga do alvo e estreita -> assinatura de desenho.
    Se aparece com pouco mais, a propriedade e quase inevitavel -> assinatura de artefato.

B2: varredura de comprimento n mantendo a fracao de 'b' de dbbi (25/91).
    A unicidade das DUAS segmentacoes depende de n=91? Ou e generica?

B3: numero MEDIO de segmentacoes condicionado a existir pelo menos uma.

Semente mestra: 20260919.
"""
from __future__ import annotations
import sys, json
import numpy as np

sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
import gsmg_common as G
from fast_seg import admits
from seg_core import sieve_primes, count_segmentations

ALPHA = "abcdefghi"
IDX = {c: i for i, c in enumerate(ALPHA)}
SEED = 20260919
B, E = 1, 4


def build(rng, N, n, m):
    """N strings de comprimento n com exatamente m 'b' em posicoes uniformes;
    resto iid pela distribuicao dos nao-b de dbbi."""
    nonb = np.array([IDX[c] for c in G.DBBI if c != "b"])
    pn = np.bincount(nonb, minlength=9).astype(float)
    pn[B] = 0.0
    pn /= pn.sum()
    out = rng.choice(9, size=(N, n), p=pn).astype(np.uint8)
    for r in range(N):
        pos = rng.choice(n, size=m, replace=False)
        out[r, pos] = B
    return out


def run(arr, chunk=50000):
    marks = sieve_primes(arr.shape[1] + 2)
    hits = 0
    for i in range(0, len(arr), chunk):
        hits += int(admits(arr[i:i + chunk], B, E, marks).sum())
    return hits


def main():
    ss = np.random.SeedSequence(SEED + 1)
    rng = np.random.default_rng(ss)
    out = {"B1_composicao": [], "B2_comprimento": [], "B3_contagem_dbbi": None}

    N = 20000
    print("== B1: comprimento fixo n=91, varrendo o numero de 'b' (dbbi tem 25) ==")
    for m in list(range(23, 46)) + [50, 55, 60, 65]:
        arr = build(rng, N, 91, m)
        h = run(arr)
        out["B1_composicao"].append({"n": 91, "m_b": m, "N": N, "hits": h, "freq": h / N})
        print(f"  m_b={m:3d}  hits={h:6d}/{N}  freq={h/N:.5f}" + ("   <- dbbi" if m == 25 else ""))

    print("\n== B2: fracao de 'b' fixa em 25/91, varrendo o comprimento n ==")
    for n in range(60, 141, 5):
        m = max(1, round(n * 25 / 91))
        arr = build(rng, N, n, m)
        h = run(arr)
        out["B2_comprimento"].append({"n": n, "m_b": m, "N": N, "hits": h, "freq": h / N})
        print(f"  n={n:4d} m_b={m:3d}  hits={h:6d}/{N}  freq={h/N:.5f}" + ("   <- dbbi" if n == 90 else ""))

    print("\n== B3: dbbi exato ==")
    tot, Ls = count_segmentations(G.DBBI)
    out["B3_contagem_dbbi"] = {"segmentacoes": tot, "L": [list(x) for x in Ls]}
    print("  ", tot, Ls)

    json.dump(out, open("/home/user/gsmgio-5btc-puzzle/_work/enxame_2026-09-19/antitese_primos/exp_b.json", "w"),
              indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
