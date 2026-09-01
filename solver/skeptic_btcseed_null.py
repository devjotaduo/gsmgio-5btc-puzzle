# -*- coding: utf-8 -*-
"""NULL-MODEL de BTCSEED (o unico sinal positivo do relatorio INV1).

CANON = "DBIFHCEGA" + "KLMNOPQRSTUVWXYZ". Os 9 primeiros sao permutacao de
{A..I}; o resto e alfabetico fixo (J removido). Espaco livre = 9! = 362880.

Pergunta: o prefixo "BTCSEED" e raro nesse espaco (sinal real) ou trivial de
achar (apofenia por alfabeto fitado)? Amostro N permutacoes aleatorias, decifro
faed por Bifid e conto: (a) prefixo == BTCSEED, (b) prefixo e 7-gram de palavra
comum de cripto/ingles. Tambem faco a busca EXAUSTIVA restrita ao alvo BTCSEED.
"""
import itertools, random, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O
from dsl import _bifid

FAED = O.sources()["faed"]
TAIL = "KLMNOPQRSTUVWXYZ"  # fixo em CANON
NINE = "ABCDEFGHI"

def prefix7(perm9):
    alpha = perm9 + TAIL
    return _bifid(FAED, alpha, len(FAED), "decrypt")[:7]

# 1. amostra aleatoria: quantas dao exatamente BTCSEED?
rng = random.Random(0)
N = 200000
exact = 0
starts_BTC = 0
for _ in range(N):
    p = list(NINE); rng.shuffle(p)
    pre = prefix7("".join(p))
    if pre == "BTCSEED":
        exact += 1
    if pre.startswith("BTC"):
        starts_BTC += 1
print(f"[null] {N} permutacoes aleatorias de A-I:")
print(f"  prefixo == 'BTCSEED' : {exact}  ({exact/N:.2e})")
print(f"  prefixo comeca 'BTC' : {starts_BTC}  ({starts_BTC/N:.2e})")

# 2. quantas permutacoes no espaco TODO (9!) dao BTCSEED? (exaustivo, 362880)
total_exact = 0
btc_prefixes = {}
for perm in itertools.permutations(NINE):
    pre = prefix7("".join(perm))
    if pre == "BTCSEED":
        total_exact += 1
    if pre.startswith("BTC"):
        btc_prefixes[pre] = btc_prefixes.get(pre, 0) + 1
print(f"[exaustivo 9!] permutacoes que dao 'BTCSEED': {total_exact} de 362880 "
      f"({total_exact/362880:.2e})")
print(f"[exaustivo 9!] prefixos que comecam 'BTC' (amostra): "
      f"{dict(list(sorted(btc_prefixes.items(), key=lambda kv:-kv[1]))[:8])}")
print(f"\nVEREDITO: se 'BTCSEED' e raro (poucas permutacoes o produzem), o alfabeto"
      f" CANON carrega informacao real, nao fit arbitrario.")
