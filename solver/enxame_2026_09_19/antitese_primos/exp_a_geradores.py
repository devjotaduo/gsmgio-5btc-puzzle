"""F8 / Experimento A — processos geradores alternativos.

Pergunta: o nulo existente (embaralhamento preservando contagens, 0/20.000) e UM nulo.
Com que frequencia OUTROS processos geradores plausiveis de texto a-i produzem uma string
de 91 simbolos que admite a segmentacao b/be em posicoes primas?

Semente mestra: 20260919 (declarada; cada gerador usa um numpy Generator derivado dela).
"""
from __future__ import annotations
import sys, json, time
import numpy as np

sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
import gsmg_common as G
from fast_seg import encode, admits_primes_be
from seg_core import count_segmentations

ALPHA = "abcdefghi"
IDX = {c: i for i, c in enumerate(ALPHA)}
SEED = 20260919
N = 20000
n = len(G.DBBI)  # 91


def arr_of(s):
    return np.array([IDX[c] for c in s], dtype=np.uint8)


DB = arr_of(G.DBBI)
FA = arr_of(G.FAED)


def freqs(a, k=9):
    c = np.bincount(a, minlength=k).astype(float)
    return c / c.sum()


def trans1(a, k=9, alpha=0.0):
    T = np.full((k, k), alpha)
    for i in range(len(a) - 1):
        T[a[i], a[i + 1]] += 1
    rs = T.sum(axis=1, keepdims=True)
    rs[rs == 0] = 1.0
    return T / rs


def trans2(a, k=9, alpha=0.0):
    T = np.full((k, k, k), alpha)
    for i in range(len(a) - 2):
        T[a[i], a[i + 1], a[i + 2]] += 1
    rs = T.sum(axis=2, keepdims=True)
    rs[rs == 0] = 1.0
    return T / rs


def gen_iid(rng, p, N, n):
    return rng.choice(9, size=(N, n), p=p).astype(np.uint8)


def gen_markov1(rng, p0, T, N, n):
    out = np.empty((N, n), dtype=np.uint8)
    out[:, 0] = rng.choice(9, size=N, p=p0)
    cum = np.cumsum(T, axis=1)
    for j in range(1, n):
        u = rng.random(N)
        prev = out[:, j - 1]
        out[:, j] = (cum[prev] < u[:, None]).sum(axis=1).clip(0, 8)
    return out


def gen_markov2(rng, p0, T1, T2, N, n):
    out = np.empty((N, n), dtype=np.uint8)
    out[:, 0] = rng.choice(9, size=N, p=p0)
    c1 = np.cumsum(T1, axis=1)
    u = rng.random(N)
    out[:, 1] = (c1[out[:, 0]] < u[:, None]).sum(axis=1).clip(0, 8)
    c2 = np.cumsum(T2, axis=2)
    for j in range(2, n):
        u = rng.random(N)
        ctx = c2[out[:, j - 2], out[:, j - 1]]
        out[:, j] = (ctx < u[:, None]).sum(axis=1).clip(0, 8)
    return out


def gen_renovacao_b(rng, N, n):
    """Processo de renovacao: lacunas entre 'b' amostradas iid da distribuicao empirica
    de lacunas de dbbi; posicoes nao-b preenchidas iid pela distribuicao dos nao-b de dbbi."""
    bpos = [i for i, c in enumerate(G.DBBI) if c == "b"]
    gaps = np.diff([-1] + bpos)  # >=1
    nonb = np.array([IDX[c] for c in G.DBBI if c != "b"], dtype=np.uint8)
    pn = np.bincount(nonb, minlength=9).astype(float)
    pn /= pn.sum()
    out = rng.choice(9, size=(N, n), p=pn).astype(np.uint8)
    for r in range(N):
        pos = -1
        while True:
            pos += int(rng.choice(gaps))
            if pos >= n:
                break
            out[r, pos] = 1  # 'b'
    return out


def gen_blocos(rng, N, n):
    """Embaralhamento por blocos de 2 (preserva metade dos bigramas 'be' intactos)."""
    a = DB.copy()
    pad = a if n % 2 == 0 else np.concatenate([a, a[:1]])
    pairs = pad.reshape(-1, 2)
    out = np.empty((N, n), dtype=np.uint8)
    for r in range(N):
        perm = rng.permutation(len(pairs))
        out[r] = pairs[perm].reshape(-1)[:n]
    return out


def gen_shuffle(rng, N, n):
    out = np.empty((N, n), dtype=np.uint8)
    for r in range(N):
        out[r] = rng.permutation(DB)
    return out


def main():
    ss = np.random.SeedSequence(SEED)
    children = ss.spawn(10)
    R = [np.random.default_rng(c) for c in children]

    pdb = freqs(DB)
    pfa = freqs(FA)
    T1db = trans1(DB)
    T1fa = trans1(FA)
    T2db = trans2(DB)
    # suavizacao de Laplace para o de ordem 2 (senao reproduz dbbi quase literalmente)
    T2db_s = trans2(DB, alpha=0.25)
    T1db_s = trans1(DB, alpha=0.25)

    gens = {
        "embaralhamento_contagens (nulo existente)": lambda: gen_shuffle(R[0], N, n),
        "iid_freq_dbbi": lambda: gen_iid(R[1], pdb, N, n),
        "iid_freq_faed": lambda: gen_iid(R[2], pfa, N, n),
        "markov1_dbbi": lambda: gen_markov1(R[3], pdb, T1db, N, n),
        "markov1_dbbi_laplace0.25": lambda: gen_markov1(R[4], pdb, T1db_s, N, n),
        "markov1_faed": lambda: gen_markov1(R[5], pfa, T1fa, N, n),
        "markov2_dbbi_laplace0.25": lambda: gen_markov2(R[6], pdb, T1db_s, T2db_s, N, n),
        "renovacao_lacunas_b": lambda: gen_renovacao_b(R[7], N, n),
        "embaralhamento_blocos2": lambda: gen_blocos(R[8], N, n),
    }

    res = {}
    for name, fn in gens.items():
        t0 = time.time()
        arr = fn()
        ok = admits_primes_be(arr)
        k = int(ok.sum())
        nb = (arr == 1).sum(axis=1)
        res[name] = {
            "N": N,
            "hits": k,
            "freq": k / N,
            "media_b": float(nb.mean()),
            "frac_com_b>=23": float((nb >= 23).mean()),
            "segundos": round(time.time() - t0, 1),
        }
        print(f"{name:42s} hits={k:6d}/{N}  freq={k/N:.6f}  media_b={nb.mean():.2f} "
              f"P(b>=23)={float((nb>=23).mean()):.4f}  [{res[name]['segundos']}s]")
        # verificacao escalar de um punhado de hits
        if 0 < k <= 5:
            for r in np.where(ok)[0][:5]:
                s = "".join(ALPHA[v] for v in arr[r])
                tot, Ls = count_segmentations(s)
                print("   conferido escalar:", tot, Ls)

    print("\ndbbi:", admits_primes_be(encode([G.DBBI]))[0], count_segmentations(G.DBBI))
    json.dump(res, open("/home/user/gsmgio-5btc-puzzle/_work/enxame_2026-09-19/antitese_primos/exp_a.json", "w"),
              indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
