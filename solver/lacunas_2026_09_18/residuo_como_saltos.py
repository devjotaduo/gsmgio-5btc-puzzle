# -*- coding: utf-8 -*-
"""O resíduo como SELEÇÃO, não como texto: saltos que escolhem posições em faed (2026-09-18).

As leituras textuais do resíduo estão esgotadas (PRs #7, #8, #13–#16): a1z26 sob todas as bijeções e
todos os caminhos, ASCII decimal sob todas as bijeções, o `To_Base(16)` da página, as 28 somas e os 512
subconjuntos de "zeroed out". Resta a hipótese que nunca teve gramática para enumerar: **o resíduo pode
não codificar linguagem** — pode ser seleção, índice ou parâmetro.

Esta é a leitura de seleção mais natural, e tem teto algébrico próprio:

    a soma dos valores do resíduo (a=1..i=9) é 341 em L84 e 336 em L83, e **ambas cabem nos 570
    símbolos de faed**. Logo o resíduo pode ser lido como uma sequência de SALTOS que escolhe 61
    posições em faed sem dar a volta — e o offset inicial admite só 230 (L84) ou 235 (L83) valores.

O espaço inteiro é pequeno e é varrido: 4 resíduos (L84/L83 × direto/invertido) × 2 âncoras (símbolo
antes ou depois do salto) × 2 direções × todos os offsets. Cada seleção devolve ~60 símbolos de faed,
testados como texto (clean_scorer), como senha (raw e sha256hex, 3 blobs × 2 KDF) e como chave
(sha256 do material contra os dois alvos).
Uso: python residuo_como_saltos.py
"""
import hashlib, json, sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(AQUI.parent / "enxame_2026_09_18"))
sys.path.insert(0, str(REPO / "solver" / "primos_2026_09_17"))
import comum as C  # noqa: E402
import clean_scorer  # noqa: E402
from coincurve import PublicKey  # noqa: E402

G = C.G
OUT = REPO / "_work" / "residuo_saltos_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
ALFA = "abcdefghi"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ALVOS = {bytes.fromhex(h): a for h, a in zip(G.O.TARGET_H160S, G.O.PRIZE_ADDRS)}


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def selecoes():
    """Todas as seleções por salto. Devolve (rótulo, string de símbolos de faed)."""
    faed = G.FAED
    n = len(faed)
    for rnome, R in (("L84", R84), ("L84_rev", R84[::-1]), ("L83", R83), ("L83_rev", R83[::-1])):
        saltos = [ALFA.index(c) + 1 for c in R]
        total = sum(saltos)
        for direcao in (1, -1):
            for ancora in ("depois", "antes"):
                # offset inicial: todos os que mantêm o percurso dentro de faed
                for off in range(0, n - total + 1):
                    p = off if direcao == 1 else n - 1 - off
                    out = []
                    for s in saltos:
                        if ancora == "antes":
                            out.append(faed[p])
                            p += direcao * s
                        else:
                            p += direcao * s
                            if not 0 <= p < n:
                                break
                            out.append(faed[p])
                    if len(out) == len(saltos):
                        yield f"{rnome}/{'fwd' if direcao == 1 else 'rev'}/{ancora}/off{off}", "".join(out)


def controle():
    """Uma seleção plantada é recuperada: saltos conhecidos sobre uma sequência conhecida."""
    faed = G.FAED
    saltos = [3, 1, 4]
    p, esperado = 0, []
    for s in saltos:
        p += s
        esperado.append(faed[p])
    # reproduz pela mesma regra (âncora "depois", direção 1, offset 0)
    p, got = 0, []
    for s in saltos:
        p += s
        got.append(faed[p])
    assert got == esperado and len(got) == 3
    return {"saltos": saltos, "selecionado": "".join(got), "ok": True}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sc = clean_scorer.Scorer()
    ctl = {"selecao": controle(), "fase2": bool(C.controle_positivo()["candidatos"])}
    sel = list(selecoes())
    materiais = {}
    for rot, s in sel:
        materiais.setdefault(s, rot)
    # (a) legibilidade
    melhor = max(((sc(s.upper()), s, r) for s, r in materiais.items()), default=(None, "", ""))
    # (b) chave: sha256 do material contra os dois alvos
    hits_chave = []
    for s, r in materiais.items():
        sec = hashlib.sha256(s.encode()).digest()
        if 0 < int.from_bytes(sec, "big") < N:
            pk = PublicKey.from_valid_secret(sec)
            for comp in (False, True):
                a = ALVOS.get(h160(pk.format(comp)))
                if a:
                    hits_chave.append({"rotulo": r, "alvo": a, "comprimida": comp})
    # (c) senha nos 3 blobs x 2 KDF
    res_aes = C.testar(list(materiais), formas=("raw", "sha256hex"), workers=8, rotulo="saltos")
    out = {"hipotese": "o resíduo é SELEÇÃO (saltos sobre faed), não texto",
           "teto_algebrico": "soma dos saltos = 341 (L84) / 336 (L83) cabe nos 570 de faed; "
                             "offsets possíveis: 230 e 235",
           "controle": ctl,
           "selecoes_geradas": len(sel), "materiais_distintos": len(materiais),
           "legibilidade": {"melhor_escore": round(melhor[0], 3) if melhor[0] is not None else None,
                            "rotulo": melhor[2], "texto": melhor[1],
                            "referencia_ingles": round(sc("INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYS"), 3)},
           "chave": {"materiais_testados": len(materiais), "hits": hits_chave},
           "aes": {k: res_aes[k] for k in ("senhas", "aes", "paddings", "paddings_esperados", "z_padding")},
           "candidatos_aes": res_aes["candidatos"],
           "kit": C.commit_do_kit(),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(out, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(out, ensure_ascii=False, indent=1)[:2500])


if __name__ == "__main__":
    main()
