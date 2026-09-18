# -*- coding: utf-8 -*-
"""Bijeção arbitrária símbolo→dígito: a família que reabriria a1z26 e ASCII decimal (2026-09-18).

Os fechamentos dos PRs #13 e #14 usaram um teto algébrico forte — "o resíduo não tem `o`, logo sua
string de dígitos não tem zero" — mas esse teto depende da convenção `a=1…i=9` da página. Se o autor
tivesse usado outra atribuição, os zeros voltariam e as duas famílias reabririam. Esta é a honestidade
que faltava fechar: **varrer todas as bijeções**.

Espaço: os 9 símbolos `a..i` recebem 9 dígitos distintos escolhidos entre os 10 -> C(10,9) × 9! =
3.628.800 atribuições, aplicadas aos quatro alvos (L84 e L83, cada um nos dois sentidos).

Para cada atribuição, conta-se por programação dinâmica quantas segmentações válidas existem em duas
gramáticas, e só as viáveis passam à medida de legibilidade:
  - **a1z26**: números de 1 ou 2 dígitos com valor 1..26 (0 não é letra e não inicia número);
  - **ASCII decimal**: códigos de 2 ou 3 dígitos com valor 32..126.
Para as viáveis, mede-se o **máximo exato** de fração de letras+espaço sobre TODOS os caminhos
(Dinkelbach no DAG), não uma amostra.
Uso: python residuo_bijecao.py [--workers 10]
"""
import argparse, hashlib, json, string, sys
from fractions import Fraction
from itertools import permutations
from multiprocessing import Pool
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
OUT = REPO / "_work" / "residuo_como_somas_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
ALFA = "abcdefghi"
ALVOS = {"L84": R84, "L84_rev": R84[::-1], "L83": R83, "L83_rev": R83[::-1]}
SEQS = {k: [ALFA.index(c) for c in v] for k, v in ALVOS.items()}
BONS_A1Z26 = set(string.ascii_uppercase)                      # a1z26 só produz letras
BONS_ASCII = set(string.ascii_letters + " ")


def conta_a1z26(seq, sig):
    """Nº de segmentações em números 1..26. 0 não é letra nem inicia número de 2 dígitos."""
    n = len(seq)
    c = [0] * (n + 1)
    c[n] = 1
    for i in range(n - 1, -1, -1):
        d = sig[seq[i]]
        t = c[i + 1] if 1 <= d <= 9 else 0
        if i + 1 < n and d in (1, 2):
            v = d * 10 + sig[seq[i + 1]]
            if 10 <= v <= 26:
                t += c[i + 2]
        c[i] = t
    return c


def conta_ascii(seq, sig):
    """Nº de segmentações em códigos 32..126 (2 ou 3 dígitos), sem zero à esquerda."""
    n = len(seq)
    c = [0] * (n + 1)
    c[n] = 1
    for i in range(n - 1, -1, -1):
        d = sig[seq[i]]
        t = 0
        if d != 0:
            if i + 2 <= n:
                v = d * 10 + sig[seq[i + 1]]
                if 32 <= v <= 99:
                    t += c[i + 2]
            if i + 3 <= n:
                v = (d * 10 + sig[seq[i + 1]]) * 10 + sig[seq[i + 2]]
                if 100 <= v <= 126:
                    t += c[i + 3]
        c[i] = t
    return c


def arestas_a1z26(seq, sig):
    n = len(seq)
    ar = [[] for _ in range(n)]
    for i in range(n):
        d = sig[seq[i]]
        if 1 <= d <= 9:
            ar[i].append((i + 1, chr(64 + d)))
        if i + 1 < n and d in (1, 2):
            v = d * 10 + sig[seq[i + 1]]
            if 10 <= v <= 26:
                ar[i].append((i + 2, chr(64 + v)))
    return ar


def arestas_ascii(seq, sig):
    n = len(seq)
    ar = [[] for _ in range(n)]
    for i in range(n):
        d = sig[seq[i]]
        if d == 0:
            continue
        if i + 2 <= n:
            v = d * 10 + sig[seq[i + 1]]
            if 32 <= v <= 99:
                ar[i].append((i + 2, chr(v)))
        if i + 3 <= n:
            v = (d * 10 + sig[seq[i + 1]]) * 10 + sig[seq[i + 2]]
            if 100 <= v <= 126:
                ar[i].append((i + 3, chr(v)))
    return ar


def fracao_maxima(ar, n, vivos, bons):
    """Dinkelbach: máximo exato de (#bons / #caracteres) sobre todos os caminhos completos."""
    lam = Fraction(0)
    while True:
        v = [None] * (n + 1)
        v[n] = (Fraction(0), "")
        for i in range(n - 1, -1, -1):
            for j, ch in ar[i]:
                if vivos[j] and v[j] is not None:
                    cand = ((1 if ch in bons else 0) - lam + v[j][0], ch + v[j][1])
                    if v[i] is None or cand[0] > v[i][0]:
                        v[i] = cand
        if v[0] is None or not v[0][1]:
            return None, ""
        s = v[0][1]
        f = Fraction(sum(ch in bons for ch in s), len(s))
        if f <= lam:
            return lam, s
        lam = f


def bloco(args):
    """Varre as bijeções cujo dígito excluído e primeiro valor estão fixados."""
    fora, primeiro = args
    digitos = [d for d in range(10) if d != fora]
    resto = [d for d in digitos if d != primeiro]
    achados = {"a1z26": [], "ascii": []}
    n_bij = n_via_a = n_via_s = 0
    for perm in permutations(resto):
        sig = (primeiro,) + perm
        n_bij += 1
        for nome, seq in SEQS.items():
            ca = conta_a1z26(seq, sig)
            if ca[0]:
                n_via_a += 1
                ar = arestas_a1z26(seq, sig)
                f, s = fracao_maxima(ar, len(seq), [x > 0 for x in ca], BONS_A1Z26)
                if f is not None and f >= Fraction(95, 100):
                    achados["a1z26"].append({"alvo": nome, "sigma": list(sig),
                                             "fracao": float(f), "texto": s})
            cs = conta_ascii(seq, sig)
            if cs[0]:
                n_via_s += 1
                ar = arestas_ascii(seq, sig)
                f, s = fracao_maxima(ar, len(seq), [x > 0 for x in cs], BONS_ASCII)
                if f is not None and f >= Fraction(95, 100):
                    achados["ascii"].append({"alvo": nome, "sigma": list(sig),
                                             "fracao": float(f), "texto": s})
    return n_bij, n_via_a, n_via_s, achados


def controle():
    """Um texto plantado é recuperado sob a bijeção identidade da página (a=1..i=9)."""
    sig = tuple(range(1, 10))                     # a=1 ... i=9
    seq = [ALFA.index(c) for c in "abc"]          # 1,2,3 -> A,B,C ou 12,3 -> L,C ...
    c = conta_a1z26(seq, sig)
    assert c[0] >= 1
    ar = arestas_a1z26(seq, sig)
    f, s = fracao_maxima(ar, len(seq), [x > 0 for x in c], BONS_A1Z26)
    assert f == 1 and s, (f, s)
    return {"identidade_a1z26_viavel": True, "caminhos_em_abc": c[0], "texto": s}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workers", type=int, default=10)
    a = ap.parse_args()
    ctl = controle()
    tarefas = [(fora, primeiro) for fora in range(10)
               for primeiro in [d for d in range(10) if d != fora]]
    tot_b = tot_a = tot_s = 0
    achados = {"a1z26": [], "ascii": []}
    with Pool(a.workers) as pool:
        for nb, na, ns, ach in pool.imap_unordered(bloco, tarefas):
            tot_b += nb
            tot_a += na
            tot_s += ns
            for k in achados:
                achados[k] += ach[k]
    res = {"familia": "bijeção arbitrária símbolo→dígito (a família que reabriria os PRs #13 e #14)",
           "motivo": "o teto do zero dependia da convenção a=1..i=9; com outra atribuição os zeros voltam",
           "controle": ctl,
           "bijecoes": tot_b,
           "espaco_esperado": 10 * 362880,
           "alvos": list(ALVOS),
           "pares_bijecao_alvo_viaveis": {"a1z26": tot_a, "ascii_decimal": tot_s},
           "de_um_total_de": tot_b * len(ALVOS),
           "com_fracao_legivel_ge_0_95": {k: len(v) for k, v in achados.items()},
           "achados": {k: v[:20] for k, v in achados.items()},
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    OUT.mkdir(parents=True, exist_ok=True)
    json.dump(res, open(OUT / "residuo_bijecao.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "achados"}, ensure_ascii=False, indent=1))
    for k, v in achados.items():
        print(f"{k}: {len(v)} com fração >= 0,95")
        for x in v[:5]:
            print("   ", x["alvo"], x["sigma"], round(x["fracao"], 3), repr(x["texto"][:60]))


if __name__ == "__main__":
    main()
