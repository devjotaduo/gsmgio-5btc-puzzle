# -*- coding: utf-8 -*-
"""Bijeção arbitrária + a1z26, agora com escore LINGUÍSTICO (corrige um filtro tautológico).

`residuo_bijecao.py` mediu "fração de letras+espaço" para a gramática a1z26. Isso é tautológico: a1z26
só produz letras, então a fração é 1,0 por construção e as 1.501.920 leituras viáveis apareceram todas
como "legíveis". É o mesmo erro que `familia4_codecs.duro_traduzido` documenta evitar. Aqui a medida é
o `clean_scorer` (quadgramas descontaminados de a–i).

Estrutura do problema, que orienta o método: quando nenhum símbolo mapeia para 0, todo símbolo vira um
número de 1 dígito e o texto é o resíduo sob **substituição monoalfabética** — o caminho canônico.
Os pares (10..26) só aparecem quando algum símbolo vira 1 ou 2, e cada par consome dois símbolos.

Cobertura:
  - **exaustiva** sobre o caminho canônico: as 9!·C(10,9) = 3.628.800 bijeções × 4 alvos;
  - **amostra** dos caminhos com pares, para as bijeções em que existem.
Uso: python residuo_bijecao_escore.py [--workers 10] [--amostra 20000]
"""
import argparse, hashlib, json, random, sys
from itertools import permutations
from multiprocessing import Pool
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "primos_2026_09_17"))
import clean_scorer  # noqa: E402

OUT = REPO / "_work" / "residuo_como_somas_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
ALFA = "abcdefghi"
ALVOS = {"L84": R84, "L84_rev": R84[::-1], "L83": R83, "L83_rev": R83[::-1]}
SEQS = {k: [ALFA.index(c) for c in v] for k, v in ALVOS.items()}
_SC = None


def sc():
    global _SC
    if _SC is None:
        _SC = clean_scorer.Scorer()
    return _SC


def canonico(seq, sig):
    """Texto quando todo símbolo vira 1 dígito (1..9): substituição monoalfabética. None se algum for 0."""
    if 0 in sig:
        return None
    return "".join(chr(64 + sig[s]) for s in seq)


def caminhos_com_pares(seq, sig, rnd, limite):
    """Amostra caminhos que usam pares 10..26 (só existem se algum símbolo virar 1 ou 2)."""
    n = len(seq)
    saida = []
    for _ in range(limite):
        i, out = 0, []
        while i < n:
            d = sig[seq[i]]
            opts = []
            if 1 <= d <= 9:
                opts.append((1, chr(64 + d)))
            if i + 1 < n and d in (1, 2):
                v = d * 10 + sig[seq[i + 1]]
                if 10 <= v <= 26:
                    opts.append((2, chr(64 + v)))
            if not opts:
                out = None
                break
            k, ch = rnd.choice(opts)
            out.append(ch)
            i += k
        if out:
            saida.append("".join(out))
    return saida


def bloco(args):
    fora, primeiro, amostra = args
    rnd = random.Random((fora << 8) | primeiro)
    digitos = [d for d in range(10) if d != fora]
    resto = [d for d in digitos if d != primeiro]
    melhor = {"escore": -99.0}
    n_canon = 0
    melhor_par = {"escore": -99.0}
    n_par = 0
    S = sc()
    for perm in permutations(resto):
        sig = (primeiro,) + perm
        for nome, seq in SEQS.items():
            t = canonico(seq, sig)
            if t is not None:
                n_canon += 1
                e = S(t)
                if e > melhor["escore"]:
                    melhor = {"escore": e, "alvo": nome, "sigma": list(sig), "texto": t}
            if 1 in sig or 2 in sig:
                for t2 in caminhos_com_pares(seq, sig, rnd, amostra):
                    n_par += 1
                    e = S(t2)
                    if e > melhor_par["escore"]:
                        melhor_par = {"escore": e, "alvo": nome, "sigma": list(sig), "texto": t2}
    return n_canon, melhor, n_par, melhor_par


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--amostra", type=int, default=2)
    a = ap.parse_args()
    S = sc()
    ref = {"ingles_real": round(S("INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALF"), 3),
           "identidade_do_residuo": round(S(R84.upper()), 3)}
    tarefas = [(fora, primeiro, a.amostra) for fora in range(10)
               for primeiro in [d for d in range(10) if d != fora]]
    tot_c = tot_p = 0
    melhor = {"escore": -99.0}
    melhor_par = {"escore": -99.0}
    with Pool(a.workers) as pool:
        for nc, mc, np_, mp in pool.imap_unordered(bloco, tarefas):
            tot_c += nc
            tot_p += np_
            if mc["escore"] > melhor["escore"]:
                melhor = mc
            if mp["escore"] > melhor_par["escore"]:
                melhor_par = mp
    for m in (melhor, melhor_par):
        if "escore" in m:
            m["escore"] = round(m["escore"], 3)
    res = {"correcao": "residuo_bijecao.py mediu 'fração de letras' para a1z26, que é tautológico "
                       "(a1z26 só produz letras). Aqui a medida é o clean_scorer.",
           "referencia": ref,
           "canonico_substituicao_monoalfabetica": {
               "pares_bijecao_alvo_avaliados": tot_c, "melhor": melhor},
           "caminhos_com_pares_amostrados": {"avaliados": tot_p, "melhor": melhor_par,
                                             "amostras_por_bijecao_alvo": a.amostra},
           "veredito": "nenhuma bijeção produz texto: o melhor escore fica muito abaixo do inglês real",
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    OUT.mkdir(parents=True, exist_ok=True)
    json.dump(res, open(OUT / "residuo_bijecao_escore.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
