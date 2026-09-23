"""F8 / Experimento D — cota EXATA (sem amostragem) para a probabilidade do encaixe.

O nulo por embaralhamento so consegue dizer "0 em 20.000" => p < 1,5e-4 (95 %).
Aqui a cota e analitica e exata, por desigualdade de Markov:

    P(admite >= 1 segmentacao) <= E[numero de segmentacoes].

E[#seg] e somavel em forma fechada. Uma segmentacao e determinada por L (comprimento logico)
e por quais dos m = pi(L) primos usam o token de 2 chars `be`; ha k = n - L deles.
As posicoes fisicas exigidas sao: m posicoes iguais a 'b' e k posicoes iguais a 'e'.
Logo

    E[#seg] = SOMA_L  C(pi(L), n-L) * P(m posicoes dadas = 'b' E k posicoes dadas = 'e')

sob dois modelos de texto:
  (i)  i.i.d. com as frequencias de dbbi  -> P = pb^m * pe^k
  (ii) multiconjunto fixo (o nulo do embaralhamento, exato) ->
       P = [25!/(25-m)!] * [18!/(18-k)!] / [91!/(91-m-k)!]

Tambem se calcula a mesma cota para faed (n=570) e a sensibilidade em n.
"""
from __future__ import annotations
import sys
from math import comb, log, exp
from fractions import Fraction

sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
import gsmg_common as G
sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/enxame_2026_09_19/antitese_primos")
from seg_core import sieve_primes


def pi_table(N):
    P = sieve_primes(N)
    out = [0] * (N + 1)
    c = 0
    for i in range(N + 1):
        if i in P:
            c += 1
        out[i] = c
    return out


def E_iid(n, pb, pe, PI):
    tot = 0.0
    parts = []
    for L in range(1, n + 1):
        k = n - L
        m = PI[L]
        if k > m:
            continue
        v = comb(m, k) * (pb ** m) * (pe ** k)
        tot += v
        parts.append((L, m, k, v))
    return tot, parts


def falling(a, b):
    """a!/(a-b)! como Fraction exata; 0 se b > a."""
    if b > a:
        return Fraction(0)
    r = Fraction(1)
    for i in range(b):
        r *= (a - i)
    return r


def E_multiset(n, nb, ne, PI):
    tot = Fraction(0)
    parts = []
    for L in range(1, n + 1):
        k = n - L
        m = PI[L]
        if k > m:
            continue
        num = falling(nb, m) * falling(ne, k)
        den = falling(n, m + k)
        if den == 0 or num == 0:
            continue
        v = Fraction(comb(m, k)) * num / den
        tot += v
        parts.append((L, m, k, float(v)))
    return tot, parts


def main():
    n = len(G.DBBI)
    PI = pi_table(max(n, len(G.FAED)) + 2)
    nb, ne = G.DBBI.count("b"), G.DBBI.count("e")
    pb, pe = nb / n, ne / n

    print(f"dbbi: n={n}  #b={nb}  #e={ne}   (pb={pb:.4f}, pe={pe:.4f})")
    ei, pi_parts = E_iid(n, pb, pe, PI)
    em, pm_parts = E_multiset(n, nb, ne, PI)
    print(f"\n(i)  i.i.d. freq dbbi   E[#seg] = {ei:.4e}   => P(>=1) <= {ei:.4e}")
    print(f"(ii) multiconjunto fixo E[#seg] = {float(em):.4e}   => P(>=1) <= {float(em):.4e}")
    print("     (o nulo de 20.000 embaralhamentos so alcanca p < 1,5e-4; a cota exata e "
          f"{1.5e-4/float(em):.0f}x mais forte)")
    print("\n  decomposicao por L (multiconjunto), termos >= 1e-12:")
    for L, m, k, v in sorted(pm_parts, key=lambda t: -t[3])[:8]:
        print(f"    L={L:3d} pi(L)={m:3d} k(be)={k:3d}  C={comb(m,k):>18d}  E_L={v:.3e}")

    # faed
    nf = len(G.FAED)
    fb, fe = G.FAED.count("b"), G.FAED.count("e")
    ef, _ = E_multiset(nf, fb, fe, PI)
    print(f"\nfaed: n={nf} #b={fb} #e={fe}  E[#seg] = {float(ef):.4e} => P(>=1) <= {float(ef):.4e}")
    print("  (o negativo de faed e esperado sob o nulo: nao e evidencia adicional de desenho)")

    # sensibilidade: quantos 'b' seriam precisos para E[#seg] ~ 1
    print("\n  sensibilidade: E[#seg] (multiconjunto, n=91, #e=18) vs #b")
    for m_b in [23, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70]:
        e, _ = E_multiset(91, m_b, 18, PI)
        print(f"    #b={m_b:3d}  E[#seg]={float(e):.3e}")

    print("\n  sensibilidade em comprimento (fracao de b = 25/91, #e/n = 18/91):")
    for nn in range(60, 145, 5):
        e, _ = E_multiset(nn, round(nn * 25 / 91), round(nn * 18 / 91), PI)
        print(f"    n={nn:4d}  E[#seg]={float(e):.3e}")


if __name__ == "__main__":
    main()
