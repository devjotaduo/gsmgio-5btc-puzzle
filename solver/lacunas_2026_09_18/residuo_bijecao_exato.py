# -*- coding: utf-8 -*-
"""Fecha por exaustão os caminhos a1z26 COM PARES, sobre todas as bijeções (2026-09-18).

Dívida declarada no PR #15: o caminho canônico (substituição monoalfabética) foi coberto por exaustão,
mas os caminhos que usam pares 10..26 foram apenas **amostrados**. Aqui eles são fechados.

O truque que torna isso barato: não é preciso maximizar a média de quadgramas (que exigiria Dinkelbach
por bijeção, porque o comprimento varia com o número de pares). Basta um **teste de limiar exato**.
O `clean_scorer` devolve `soma_de_quadgramas / (len - 3)`; logo

    existe caminho com média ≥ L   ⇔   max( soma − L · n_quadgramas ) ≥ 0

e isso é uma única passada de programação dinâmica, com estado `(posição, últimos 3 caracteres)`.
Roda-se o teste para um limiar **generoso**: L = −4,5, bem abaixo do inglês real (−3,766) e bem acima do
melhor caminho canônico (−5,739). Se nenhuma das 3.628.800 bijeções × 4 alvos produz caminho que atinja
−4,5, a família está fechada com folga.
Uso: python residuo_bijecao_exato.py [--workers 10] [--limiar -4.5]
"""
import argparse, hashlib, json, sys
from itertools import permutations
from multiprocessing import Pool
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "primos_2026_09_17"))
import clean_scorer  # noqa: E402
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver")
import scorer as S0  # noqa: E402

OUT = REPO / "_work" / "residuo_como_somas_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
ALFA = "abcdefghi"
SEQS = {"L84": [ALFA.index(c) for c in R84], "L84_rev": [ALFA.index(c) for c in R84[::-1]],
        "L83": [ALFA.index(c) for c in R83], "L83_rev": [ALFA.index(c) for c in R83[::-1]]}
_TAB = _FLOOR = None


def tabela():
    global _TAB, _FLOOR
    if _TAB is None:
        sc = clean_scorer.Scorer()
        _TAB, _FLOOR = sc.tab, sc.floor
    return _TAB, _FLOOR


def atinge(seq, sig, L, tab):
    """max(soma_quadgramas − L·n_quadgramas) sobre todos os caminhos completos. ≥ 0 ⇒ média ≥ L."""
    n = len(seq)
    I = S0.IDX
    est = {(0, ""): 0.0}
    melhor_final = None
    for i in range(n):
        atuais = [(k, v) for k, v in est.items() if k[0] == i]
        if not atuais:
            continue
        d = sig[seq[i]]
        opts = []
        if 1 <= d <= 9:
            opts.append((1, chr(64 + d)))
        if i + 1 < n and d in (1, 2):
            v2 = d * 10 + sig[seq[i + 1]]
            if 10 <= v2 <= 26:
                opts.append((2, chr(64 + v2)))
        for (pos, ctx), val in atuais:
            for k, ch in opts:
                add = 0.0
                if len(ctx) == 3:
                    q = ctx + ch
                    add = tab[((I[q[0]] * 26 + I[q[1]]) * 26 + I[q[2]]) * 26 + I[q[3]]] - L
                key = (i + k, (ctx + ch)[-3:])
                nv = val + add
                if key not in est or est[key] < nv:
                    est[key] = nv
    for (pos, ctx), val in est.items():
        if pos == n and (melhor_final is None or val > melhor_final):
            melhor_final = val
    return melhor_final


def bloco(args):
    fora, primeiro, L = args
    tab, _ = tabela()
    digitos = [d for d in range(10) if d != fora]
    resto = [d for d in digitos if d != primeiro]
    n_av = 0
    n_atingem = 0
    melhor = {"valor": -1e18}
    for perm in permutations(resto):
        sig = (primeiro,) + perm
        for nome, seq in SEQS.items():
            v = atinge(seq, sig, L, tab)
            if v is None:
                continue
            n_av += 1
            if v > melhor["valor"]:
                melhor = {"valor": v, "alvo": nome, "sigma": list(sig)}
            if v >= 0:
                n_atingem += 1
    return n_av, n_atingem, melhor


def controle(L):
    """Um texto em inglês de verdade atinge o limiar; o resíduo sob a identidade não."""
    tab, _ = tabela()
    sc = clean_scorer.Scorer()
    alvo = "INCASEYOUMANAGETOCRACKTHIS"
    assert sc(alvo) >= L, sc(alvo)
    assert sc(R84.upper()) < L, sc(R84.upper())
    return {"ingles_atinge": round(sc(alvo), 3), "identidade_nao_atinge": round(sc(R84.upper()), 3),
            "limiar": L}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--limiar", type=float, default=-4.5)
    a = ap.parse_args()
    L = a.limiar
    ctl = controle(L)
    tarefas = [(fora, primeiro, L) for fora in range(10)
               for primeiro in [d for d in range(10) if d != fora]]
    tot = ating = 0
    melhor = {"valor": -1e18}
    with Pool(a.workers) as pool:
        for n_av, n_at, m in pool.imap_unordered(bloco, tarefas):
            tot += n_av
            ating += n_at
            if m["valor"] > melhor["valor"]:
                melhor = m
    melhor["valor"] = round(melhor["valor"], 2)
    res = {"divida_fechada": "caminhos a1z26 COM PARES, antes só amostrados (PR #15)",
           "metodo": "teste de limiar exato: existe caminho com média ≥ L  ⇔  max(soma − L·n_quadgramas) ≥ 0; "
                     "uma passada de DP com estado (posição, últimos 3 caracteres)",
           "limiar": L, "controle": ctl,
           "bijecoes": 3628800, "pares_bijecao_alvo_avaliados": tot,
           "caminhos_que_atingem_o_limiar": ating,
           "melhor_margem_sobre_o_limiar": melhor,
           "leitura": "margem negativa = nenhum caminho, em nenhuma bijeção, chega ao limiar",
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    OUT.mkdir(parents=True, exist_ok=True)
    json.dump(res, open(OUT / "residuo_bijecao_exato.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
