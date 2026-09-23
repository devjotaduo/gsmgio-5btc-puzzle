"""Nucleo da frente F8 (antitese_primos): contador exato de segmentacoes b/be em posicoes primas.

Regra generalizada (familia do lead `yellowblueprimes`, ENDGAME.md §6):
  - numeram-se as posicoes LOGICAS 1..L;
  - em posicao MARCADA (por padrao: prima, 1-based) consome-se o token de 1 char `X`
    ou o token de 2 chars `XY` do texto fisico;
  - nas demais posicoes consome-se exatamente 1 simbolo qualquer;
  - exige-se consumo INTEGRAL dos n simbolos do texto fisico.
L nao e fixado: emerge da segmentacao.

`count_segmentations` devolve o numero exato de segmentacoes e a lista de L viaveis.
Implementacao por DP O(n * Lmax); verificada contra dbbi (2 segmentacoes: L83 e L84).
"""
from __future__ import annotations

ALPHA = "abcdefghi"


def sieve_primes(limit: int) -> set:
    if limit < 2:
        return set()
    bs = bytearray([1]) * (limit + 1)
    bs[0] = bs[1] = 0
    i = 2
    while i * i <= limit:
        if bs[i]:
            bs[i * i:: i] = bytearray(len(bs[i * i:: i]))
        i += 1
    return {i for i in range(limit + 1) if bs[i]}


def marks_primes_1based(Lmax: int) -> set:
    return sieve_primes(Lmax)


def marks_primes_0based(Lmax: int) -> set:
    """posicao logica i (1-based) marcada se (i-1) e primo."""
    P = sieve_primes(Lmax)
    return {i for i in range(1, Lmax + 1) if (i - 1) in P}


def marks_composites(Lmax: int) -> set:
    P = sieve_primes(Lmax)
    return {i for i in range(2, Lmax + 1) if i not in P}


def marks_squares(Lmax: int) -> set:
    s, out = 1, set()
    while s * s <= Lmax:
        out.add(s * s)
        s += 1
    return out


def marks_fib(Lmax: int) -> set:
    a, b, out = 1, 2, {1}
    while a <= Lmax:
        out.add(a)
        a, b = b, a + b
    return out


def marks_triangular(Lmax: int) -> set:
    out, k = set(), 1
    while k * (k + 1) // 2 <= Lmax:
        out.add(k * (k + 1) // 2)
        k += 1
    return out


def marks_multiples(k: int):
    return lambda Lmax: {i for i in range(k, Lmax + 1, k)}


def marks_odd(Lmax: int) -> set:
    return set(range(1, Lmax + 1, 2))


def marks_even(Lmax: int) -> set:
    return set(range(2, Lmax + 1, 2))


MARK_FAMILIES = {
    "primos_1based": marks_primes_1based,
    "primos_0based": marks_primes_0based,
    "compostos": marks_composites,
    "quadrados": marks_squares,
    "fibonacci": marks_fib,
    "triangulares": marks_triangular,
    "impares": marks_odd,
    "pares": marks_even,
    "mult3": marks_multiples(3),
    "mult4": marks_multiples(4),
    "mult5": marks_multiples(5),
    "mult6": marks_multiples(6),
    "mult7": marks_multiples(7),
}


def count_segmentations(s: str, x: str = "b", y: str = "e",
                        marks: set | None = None, Lmax: int | None = None):
    """Devolve (n_segmentacoes, [L viaveis]) para a regra (x, x+y) nas posicoes marcadas."""
    n = len(s)
    if Lmax is None:
        Lmax = n
    if marks is None:
        marks = sieve_primes(Lmax + 1)
    two = (x + y) if y else None
    # dp[p][i] = numero de caminhos que consumiram p chars e vao preencher a posicao logica i
    # representado como lista de dicts esparsos por p
    cur = [0] * (Lmax + 3)
    nxt1 = [0] * (Lmax + 3)
    nxt2 = [0] * (Lmax + 3)
    cur[1] = 1
    buf = [cur, nxt1, nxt2]
    out_counts = {}
    for p in range(n + 1):
        row = buf[p % 3]
        if p == n:
            for i in range(1, Lmax + 3):
                if row[i]:
                    out_counts[i - 1] = out_counts.get(i - 1, 0) + row[i]
            break
        r1 = buf[(p + 1) % 3]
        r2 = buf[(p + 2) % 3]
        ch = s[p]
        ch2 = s[p:p + 2]
        for i in range(1, Lmax + 2):
            v = row[i]
            if not v:
                continue
            if i in marks:
                if ch == x:
                    r1[i + 1] += v
                if two is not None and ch2 == two:
                    r2[i + 1] += v
            else:
                r1[i + 1] += v
        for i in range(len(row)):
            row[i] = 0
    total = sum(out_counts.values())
    return total, sorted(out_counts.items())


def marker_profile(s: str, L: int, x: str = "b", y: str = "e", marks=None):
    """Para um L fixo, devolve (n_x, n_xy) da unica/primeira segmentacao, ou None."""
    if marks is None:
        marks = sieve_primes(L)
    n = len(s)
    res = []

    def rec(i, p, prof):
        if i > L:
            if p == n:
                res.append(tuple(prof))
            return
        if p >= n:
            return
        if i in marks:
            if s[p] == x:
                rec(i + 1, p + 1, prof + ["b"])
            if s[p:p + 2] == x + y:
                rec(i + 1, p + 2, prof + ["be"])
        else:
            rec(i + 1, p + 1, prof)

    rec(1, 0, [])
    return res


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
    import gsmg_common as G
    tot, Ls = count_segmentations(G.DBBI)
    print("dbbi:", len(G.DBBI), "simbolos ->", tot, "segmentacoes, L viaveis:", Ls)
    for L, _ in Ls:
        profs = marker_profile(G.DBBI, L)
        for pr in profs:
            print(f"  L={L}: marcadores={len(pr)} b={pr.count('b')} be={pr.count('be')}")
    tot_f, Ls_f = count_segmentations(G.FAED)
    print("faed:", len(G.FAED), "->", tot_f, "segmentacoes", Ls_f)
