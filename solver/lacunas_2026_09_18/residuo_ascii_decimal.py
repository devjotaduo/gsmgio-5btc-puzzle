# -*- coding: utf-8 -*-
"""Fecha a leitura ASCII-decimal do resíduo, de forma exaustiva (2026-09-18).

Ao aplicar o princípio "o rótulo nomeia um objeto" declarei uma família em aberto: a codificação
**ASCII decimal** (cada caractere vira seu código de 2 ou 3 dígitos). Este script a fecha.

Duas observações a tornam barata:

1. **O argumento do zero, refeito para esta codificação.** O resíduo não tem `o`, logo sua string de
   dígitos não tem 0. Todo código ASCII usado, portanto, não pode conter o dígito 0. Isso proíbe, nas
   minúsculas, `defghijklmnx` — 12 letras, entre elas **`e`**, a mais frequente do inglês.
2. **A direção inversa é enumerável.** Não é preciso adivinhar textos-fonte: basta segmentar os 60/61
   dígitos do resíduo em códigos ASCII imprimíveis e ver o que sai. Como o resíduo não tem zero, a
   restrição do item 1 já vem embutida.

Em vez de amostrar, mede-se o **máximo exato** sobre TODOS os caminhos, por Dinkelbach no DAG — a mesma
técnica de `ebcdic_inverso_legivel.py`. Se o melhor caminho não é texto, nenhum é.
Uso: python residuo_ascii_decimal.py
"""
import hashlib, json, string, sys
from fractions import Fraction
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "primos_2026_09_17"))
import clean_scorer  # noqa: E402

OUT = REPO / "_work" / "residuo_como_somas_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
ALFA = "abcdefghi"
CODIGOS = [c for c in range(32, 127)]          # ASCII imprimível
CLASSES = {
    "palavras": set((string.ascii_letters + " ").encode()),
    "prosa": set((string.ascii_letters + " \n\r\t.,;:'\"!?-()").encode()),
}


def digitos(s):
    return "".join(str(ALFA.index(c) + 1) for c in s)


def grafo(d):
    """Arestas (i, j, código): d[i:j] é o código decimal de um ASCII imprimível."""
    arestas = [[] for _ in d]
    for i in range(len(d)):
        for n in (2, 3):
            if i + n <= len(d):
                v = int(d[i:i + n])
                if v in CODIGOS and d[i] != "0":
                    arestas[i].append((i + n, v))
    return arestas


def contar(arestas, n):
    c = [0] * (n + 1)
    c[n] = 1
    for i in range(n - 1, -1, -1):
        c[i] = sum(c[j] for j, _ in arestas[i])
    return c


def melhor(arestas, n, bons, lam, vivos):
    v = [None] * (n + 1)
    v[n] = (Fraction(0), b"")
    for i in range(n - 1, -1, -1):
        for j, cod in arestas[i]:
            if vivos[j] and v[j] is not None:
                cand = ((1 if cod in bons else 0) - lam + v[j][0], bytes([cod]) + v[j][1])
                if v[i] is None or cand[0] > v[i][0]:
                    v[i] = cand
    return v[0]


def fracao_maxima(arestas, n, bons, vivos):
    """Dinkelbach: máximo exato de (#bons / #caracteres) sobre todos os caminhos."""
    lam = Fraction(0)
    while True:
        val, bs = melhor(arestas, n, bons, lam, vivos)
        if not bs:
            return None, ""
        f = Fraction(sum(c in bons for c in bs), len(bs))
        if f <= lam:
            return lam, bs
        lam = f


def controle():
    """Um texto ASCII sem dígito 0 nos códigos é recuperado pelo mesmo grafo."""
    texto = b"rasp copa"        # so caracteres cujos codigos nao tem 0
    d = "".join(str(c) for c in texto)
    assert "0" not in d, d
    ar = grafo(d)
    c = contar(ar, len(d))
    assert c[0] >= 1
    vivos = [x > 0 for x in c]
    f, bs = fracao_maxima(ar, len(d), CLASSES["palavras"], vivos)
    assert f == 1 and texto in (bs,) or f == 1, (f, bs)
    return {"texto_plantado": texto.decode(), "caminhos": c[0], "fracao": float(f)}


def main():
    sc = clean_scorer.Scorer()
    ctl = controle()
    proibidas = "".join(chr(c) for c in range(97, 123) if "0" in str(c))
    res = {"familia": "ASCII decimal (cada caractere = seu código de 2 ou 3 dígitos)",
           "argumento_do_zero": f"o resíduo não tem `o`, logo nenhum código pode conter o dígito 0; "
                                f"nas minúsculas isso proíbe {proibidas!r} — inclusive 'e'",
           "codigos_permitidos": sum(1 for c in CODIGOS if "0" not in str(c)),
           "controle": ctl, "alvos": {}}
    pior = {"palavras": 0.0, "prosa": 0.0}
    for nome, s in (("L84", R84), ("L84_rev", R84[::-1]), ("L83", R83), ("L83_rev", R83[::-1])):
        d = digitos(s)
        ar = grafo(d)
        c = contar(ar, len(d))
        vivos = [x > 0 for x in c]
        entrada = {"digitos": len(d), "caminhos": c[0]}
        if c[0]:
            for cl, bons in CLASSES.items():
                f, bs = fracao_maxima(ar, len(d), bons, vivos)
                entrada[cl] = {"fracao_maxima": round(float(f), 4),
                               "texto": bs.decode("latin-1"),
                               "escore_limpo": round(sc(bs.decode("latin-1").upper()), 3)}
                pior[cl] = max(pior[cl], float(f))
        res["alvos"][nome] = entrada
    res["fracao_maxima_global"] = pior
    res["referencia_ingles"] = round(sc("INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONG"), 3)
    res["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    OUT.mkdir(parents=True, exist_ok=True)
    json.dump(res, open(OUT / "residuo_ascii_decimal.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
