# -*- coding: utf-8 -*-
"""Item 6 (lacunas 2026-09-18): limite de legibilidade sobre TODOS os caminhos da leitura EBCDIC por
códigos decimais concatenados, na direção autêntica da fase 3.2.

A busca de solver/ebcdic_codepoints.cjs (rodada com ebcdic_inverso_patch.cjs) aceita 45 casos, todos com
códigos mínimos em dbbi, somando dezenas de milhões de caminhos; seis passam do limite de 100 mil textos
enumerados. Aceitar só quer dizer que a sequência de dígitos se parte em códigos do repertório. Aqui, com
implementação independente do Node (repertório pelo codec cp273 do Python, grafo reconstruído do zero):
  1. conta os caminhos de cada caso por DP e confere com o `count` do buscador;
  2. acha, por Dinkelbach sobre o DAG, a fração MÁXIMA exata de caracteres 'bons' entre todos os caminhos,
     para duas classes: prosa (letras, espaço, quebra de linha e pontuação comum) e senha (letras e dígitos,
     que cobre hex64, WIF, base58 e base64 sem sinais);
  3. controle: um texto plantado na mesma codificação é achado com fração 1 e contado.
Uso: python ebcdic_inverso_legivel.py
"""
import hashlib, json, string
from fractions import Fraction
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "_work" / "lacunas_2026-09-18" / "ebcdic_codepoints_inverso"
ASCII_OK = set(range(32, 127)) | {9, 10, 13}


def imagem(b):
    """ASCII que o byte guardado b vira na direção da fase 3.2 (latin-1 → cp273), ou None."""
    try:
        e = bytes([b]).decode("latin-1").encode("cp273")[0]
    except UnicodeEncodeError:
        return None
    return e if e in ASCII_OK else None


REP = {b: imagem(b) for b in range(256) if imagem(b) is not None}
CLASSES = {
    "palavras": set((string.ascii_letters + " ").encode()),   # prosa em inglês passa de ~0,95
    "prosa": set((string.ascii_letters + " \n\r\t.,;:'\"!?-()").encode()),
    "senha": set((string.ascii_letters + string.digits).encode()),
}


def grafo(src, mapa, aliases):
    """Arestas (i, j, byte): o código decimal mínimo de `byte` casa com os dígitos de src[i:j]."""
    arestas = [[] for _ in src]
    for i in range(len(src)):
        for b in REP:
            w = str(b)
            if i + len(w) <= len(src) and all(
                    int(d) == mapa[src[i + k]] or (d == "0" and src[i + k] in aliases) for k, d in enumerate(w)):
                arestas[i].append((i + len(w), b))
    return arestas


def contar(arestas, n):
    c = [0] * (n + 1)
    c[n] = 1
    for i in range(n - 1, -1, -1):
        c[i] = sum(c[j] for j, _ in arestas[i])
    return c


def melhor(arestas, n, bons, lam, vivos):
    """Caminho completo que maximiza Σ(bom(b) − λ); devolve (valor, bytes)."""
    v = [None] * (n + 1)
    v[n] = (Fraction(0), b"")
    for i in range(n - 1, -1, -1):
        for j, b in arestas[i]:
            if vivos[j] and v[j] is not None:
                cand = ((1 if REP[b] in bons else 0) - lam + v[j][0], bytes([b]) + v[j][1])
                if v[i] is None or cand[0] > v[i][0]:
                    v[i] = cand
    return v[0]


def fracao_maxima(arestas, n, bons, vivos):
    """Dinkelbach: max sobre caminhos de (#bons / #bytes), exato em frações."""
    lam = Fraction(0)
    while True:
        val, bs = melhor(arestas, n, bons, lam, vivos)
        f = Fraction(sum(REP[b] in bons for b in bs), len(bs))
        if f <= lam:
            return lam, bs
        lam = f


def caso(src, mapa, aliases):
    arestas = grafo(src, mapa, aliases)
    c = contar(arestas, len(src))
    vivos = [x > 0 for x in c]
    out = {"caminhos": c[0]}
    for nome, bons in CLASSES.items():
        f, bs = fracao_maxima(arestas, len(src), bons, vivos) if c[0] else (None, b"")
        out[nome] = {"fracao_maxima": None if f is None else round(float(f), 4),
                     "texto_ascii": bytes(REP[b] for b in bs).decode("ascii")}
    return out


def controle():
    """Textos plantados: codifica na direção autêntica, vira dígitos mínimos e letras por um mapa e um alias;
    cada um tem de sair com fração 1 na sua classe."""
    inv = {e: b for b, e in REP.items()}
    mapa = [8, 5, 2, 1, 6, 7, 3, 4, 9]            # letra i -> dígito
    alias = 4                                       # letra e também vale 0
    letra = {d: i for i, d in enumerate(mapa)} | {0: alias}
    out = {}
    for classe, texto in (("palavras", "Follow the white rabbit Neo"), ("prosa", "Follow the white rabbit, Neo."),
                          ("senha", "0f3a9c52e1d8b7a6")):
        digitos = "".join(str(inv[ord(c)]) for c in texto)
        r = caso([letra[int(d)] for d in digitos], mapa, {alias})
        assert r["caminhos"] >= 1 and r[classe]["fracao_maxima"] == 1.0, (classe, r)
        out[classe] = {"texto": texto, "digitos": len(digitos), "caminhos": r["caminhos"],
                       "achado": r[classe]["texto_ascii"]}
    return out


def main():
    assert len(REP) == 98, len(REP)
    rep = json.load(open(OUT / "repertorio.json", encoding="utf-8"))
    assert rep["allowed"] == sorted(REP), "repertório do Node diverge do cp273 do Python"
    ctl = controle()
    entrada = json.load(open(REPO / "_work" / "prime_geometry_2026-09-11" / "inputs.json", encoding="utf-8"))
    saved = json.load(open(OUT / "summary_completo.json", encoding="utf-8"))
    casos, maximo = [], {k: 0.0 for k in CLASSES}
    for a in saved["accepted"]:
        campo = entrada[a["field"]][::-1] if a["reverse"] else entrada[a["field"]]
        assert not a["padded"], "só há aceitos com códigos mínimos"
        src = [ord(ch) - 97 for ch in campo]
        r = caso(src, [int(d) for d in a["mapping"]], {ord(ch) - 97 for ch in a["aliases"]})
        assert r["caminhos"] == int(a["count"]), (a["mapping"], r["caminhos"], a["count"])
        for k in CLASSES:
            maximo[k] = max(maximo[k], r[k]["fracao_maxima"])
        casos.append({k: a[k] for k in ("field", "reverse", "aliases", "mapping", "count")} | r)
    res = {"controle_plantado": ctl, "casos_aceitos": len(casos),
           "caminhos_total": sum(c["caminhos"] for c in casos),
           "caminhos_conferidos_com_o_buscador": True, "fracao_maxima_global": maximo,
           "classes": {k: "".join(sorted(map(chr, v))) for k, v in CLASSES.items()},
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "casos": casos}
    json.dump(res, open(OUT / "legibilidade.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    # summary.json versionável: o completo (textos enumerados, ~120 MB) fica só local
    compacto = {k: v for k, v in saved.items() if k not in ("accepted", "partial")} | {
        "accepted": [{k: v for k, v in a.items() if k != "texts"} | {"savedTexts": len(a["texts"])}
                     for a in saved["accepted"]], "partial_count": len(saved["partial"]),
        "summary_completo_sha256": hashlib.sha256((OUT / "summary_completo.json").read_bytes()).hexdigest()}
    json.dump(compacto, open(OUT / "summary.json", "w", encoding="utf-8"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "casos"}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
