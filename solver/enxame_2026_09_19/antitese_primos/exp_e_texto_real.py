"""F8 / Experimento E — geradores 'do mundo real': strings a-i vindas de TEXTO, nao de urna.

Se dbbi e o produto de alguma codificacao natural (texto -> digitos 1..9 -> a..i), entao
janelas de 91 simbolos extraidas dessas codificacoes sao o processo gerador mais realista
que se pode montar sem supor intencao. Mede-se a frequencia de encaixe nelas.

Fontes: README.md, ENDGAME.md, G.MATRIX_README, G.FAED, G.DBBI (controle).
Codificacoes: a1z26 dos digitos da letra; (ord % 9)+1; base-9 dos bytes; digitos de pi/e.
"""
from __future__ import annotations
import sys, json
import numpy as np

sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
import gsmg_common as G
sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/enxame_2026_09_19/antitese_primos")
from fast_seg import admits
from seg_core import sieve_primes

ALPHA = "abcdefghi"
B, E = 1, 4
N = 91


def only_letters(t):
    return "".join(c for c in t.lower() if "a" <= c <= "z")


def enc_a1z26(t):
    """letra -> seu numero 1..26 em digitos; digito 0 descartado; digito d -> ALPHA[d-1]."""
    out = []
    for c in only_letters(t):
        for d in str(ord(c) - 96):
            if d != "0":
                out.append(int(d) - 1)
    return np.array(out, dtype=np.uint8)


def enc_mod9(t):
    return np.array([(ord(c) - 97) % 9 for c in only_letters(t)], dtype=np.uint8)


def enc_base9(t):
    out = []
    for c in t.encode("utf-8", "ignore"):
        v = c
        while v:
            d = v % 9
            v //= 9
            out.append(d)
    return np.array(out, dtype=np.uint8)


def enc_digits(seq):
    return np.array([int(d) - 1 for d in seq if d in "123456789"], dtype=np.uint8)


def windows(a, n=N, step=1, cap=200000):
    if len(a) < n:
        return np.zeros((0, n), dtype=np.uint8)
    idx = np.arange(0, len(a) - n + 1, step)[:cap]
    return np.stack([a[i:i + n] for i in idx]) if len(idx) else np.zeros((0, n), np.uint8)


def main():
    marks = sieve_primes(N + 2)
    textos = {}
    for p in ["README.md", "ENDGAME.md", "AGENTS.md", "docs/RESEARCH-INDEX.md"]:
        try:
            textos[p] = open("/home/user/gsmgio-5btc-puzzle/" + p, encoding="utf-8").read()
        except Exception:
            pass
    textos["MATRIX_README"] = G.MATRIX_README if isinstance(G.MATRIX_README, str) else str(G.MATRIX_README)

    fontes = {}
    for nome, t in textos.items():
        fontes[f"{nome}|a1z26"] = enc_a1z26(t)
        fontes[f"{nome}|mod9"] = enc_mod9(t)
        fontes[f"{nome}|base9"] = enc_base9(t)
    fontes["faed|literal"] = np.array([ALPHA.index(c) for c in G.FAED], dtype=np.uint8)
    fontes["dbbi|literal (controle)"] = np.array([ALPHA.index(c) for c in G.DBBI], dtype=np.uint8)

    res, tot_w, tot_h = {}, 0, 0
    for nome, a in sorted(fontes.items()):
        W = windows(a)
        if len(W) == 0:
            continue
        hits = 0
        for i in range(0, len(W), 50000):
            hits += int(admits(W[i:i + 50000], B, E, marks).sum())
        nb = (W == B).sum(axis=1)
        res[nome] = {"janelas": int(len(W)), "hits": hits,
                     "media_b": float(nb.mean()), "max_b": int(nb.max())}
        tot_w += len(W); tot_h += hits
        print(f"  {nome:38s} janelas={len(W):7d} hits={hits:4d} media_b={nb.mean():5.2f} max_b={int(nb.max()):3d}")
    print(f"\n  TOTAL: {tot_h} encaixes em {tot_w} janelas de texto real")
    json.dump({"por_fonte": res, "total_janelas": tot_w, "total_hits": tot_h},
              open("/home/user/gsmgio-5btc-puzzle/_work/enxame_2026-09-19/antitese_primos/exp_e.json", "w"),
              indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
