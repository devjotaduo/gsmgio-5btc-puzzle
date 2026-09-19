"""DP vetorizado (numpy) do contador de segmentacoes, sobre MUITAS strings de uma vez.

Devolve, para cada string, se admite >= 1 segmentacao sob a regra (x, xy) nas posicoes marcadas.
Verificado contra seg_core.count_segmentations (implementacao independente, escalar).
"""
from __future__ import annotations
import numpy as np

from seg_core import sieve_primes


def encode(strings, alpha="abcdefghi"):
    """lista de strings de mesmo tamanho -> array uint8 (N, n) com indices do alfabeto."""
    idx = {c: i for i, c in enumerate(alpha)}
    n = len(strings[0])
    out = np.empty((len(strings), n), dtype=np.uint8)
    for r, s in enumerate(strings):
        out[r] = [idx[c] for c in s]
    return out


def admits(arr: np.ndarray, x: int, y: int | None, marks: set, Lmax: int | None = None):
    """arr: (N, n) uint8. x,y: indices do alfabeto (y=None => token so de 1 char).
    Devolve bool (N,): admite pelo menos uma segmentacao completa."""
    N, n = arr.shape
    if Lmax is None:
        Lmax = n
    W = Lmax + 3
    mark = np.zeros(W, dtype=bool)
    for i in marks:
        if i < W:
            mark[i] = True
    A = np.zeros((N, W), dtype=bool)
    B1 = np.zeros((N, W), dtype=bool)
    B2 = np.zeros((N, W), dtype=bool)
    A[:, 1] = True
    bufs = [A, B1, B2]
    for p in range(n):
        cur = bufs[p % 3]
        r1 = bufs[(p + 1) % 3]
        r2 = bufs[(p + 2) % 3]
        chX = (arr[:, p] == x)
        free = cur & ~mark[None, :]
        mk = cur & mark[None, :]
        # shift logico +1
        r1[:, 1:] |= free[:, :-1]
        r1[:, 1:] |= mk[:, :-1] & chX[:, None]
        if y is not None and p + 1 < n:
            chXY = chX & (arr[:, p + 1] == y)
            r2[:, 1:] |= mk[:, :-1] & chXY[:, None]
        cur[:] = False
    final = bufs[n % 3]
    return final.any(axis=1)


def admits_primes_be(arr: np.ndarray):
    return admits(arr, 1, 4, sieve_primes(arr.shape[1] + 2))  # b=1, e=4


if __name__ == "__main__":
    import sys
    sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
    import gsmg_common as G
    from seg_core import count_segmentations
    import random
    rnd = random.Random(20260919)
    strs = [G.DBBI] + ["".join(rnd.sample(G.DBBI, len(G.DBBI))) for _ in range(300)]
    fast = admits_primes_be(encode(strs))
    slow = np.array([count_segmentations(s)[0] > 0 for s in strs])
    print("concordancia rapida x lenta:", int((fast == slow).all()), "| positivos:", int(fast.sum()), int(slow.sum()))
