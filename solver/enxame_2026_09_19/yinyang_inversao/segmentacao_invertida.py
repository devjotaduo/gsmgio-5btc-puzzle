# -*- coding: utf-8 -*-
"""F6 — o eixo de COMPOSIÇÃO da inversão yin-yang, resolvido por teorema em vez de busca.

Pergunta: a inversão pode agir ANTES do passo provado `yellowblueprimes` (a segmentação de
`dbbi` por marcadores `b`/`be` nas posições lógicas primas, ENDGAME §6)?

Duas leituras possíveis da composição:
  (a) regra LITERAL (marcador continua sendo o símbolo físico `b`/`be`) aplicada ao objeto
      invertido — enumerável por DFS: existe segmentação válida de C(dbbi) / R(dbbi) / CR(dbbi)?
  (b) regra RELABELADA (marcador = imagem do `b` pela involução) — então C é uma bijeção
      pontual e comuta com a segmentação: residuo(C(dbbi)) = C(residuo(dbbi)). Verificado aqui.

Se (a) der 0 segmentações, a ordem "inverter e depois segmentar" está fechada por
impossibilidade (determinística), e (b) mostra que a outra ordem não acrescenta objeto novo
além dos já cobertos por `fecha_inversao.py`. O eixo de composição some para C e R.
"""
from __future__ import annotations
import json, os, sys

KIT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                   "experiments", "claude_endgame_2026_09_02"))
sys.path.insert(0, KIT)
import gsmg_common as G  # noqa: E402

OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                   "_work", "enxame_2026-09-19", "yinyang_inversao"))
COMP = {c: chr(ord('a') + (8 - (ord(c) - ord('a')))) for c in "abcdefghi"}
C = lambda s: "".join(COMP[c] for c in s)          # noqa: E731
R = lambda s: s[::-1]                               # noqa: E731


def segmenta(txt, mark="b", ext="e"):
    """Todas as segmentações: em posição lógica prima (base 1) consome `mark` ou `mark+ext`;
    nas demais, um símbolo. Consumo integral. Devolve lista de (tipos, residuo)."""
    n = len(txt)
    res = []

    def dfs(i, pos, tipos, resid):
        if i == n:
            res.append(("".join(tipos), "".join(resid)))
            return
        if len(res) > 50:
            return
        if G.is_prime(pos):
            if txt[i] == mark:
                if i + 1 < n and txt[i + 1] == ext:
                    dfs(i + 2, pos + 1, tipos + ["1"], resid)
                dfs(i + 1, pos + 1, tipos + ["0"], resid)
        else:
            dfs(i + 1, pos + 1, tipos, resid + [txt[i]])

    dfs(0, 1, [], [])
    return res


def main():
    os.makedirs(OUT, exist_ok=True)
    base = segmenta(G.DBBI)
    out = {"controle_dbbi_original": {"n_segmentacoes": len(base),
                                      "residuos": [r for _, r in base],
                                      "tipos": [t for t, _ in base]}}
    for nome, s in (("C_dbbi", C(G.DBBI)), ("R_dbbi", R(G.DBBI)),
                    ("CR_dbbi", C(R(G.DBBI))), ("C_faed", C(G.FAED)), ("R_faed", R(G.FAED))):
        segs = segmenta(s)
        out[nome] = {"n_segmentacoes_regra_literal": len(segs),
                     "residuos": [r for _, r in segs][:4]}
    # (b) regra relabelada: C comuta com a segmentação
    relab = segmenta(C(G.DBBI), mark=COMP["b"], ext=COMP["e"])
    out["C_dbbi_regra_relabelada"] = {
        "n_segmentacoes": len(relab),
        "residuos_iguais_a_C_do_residuo_original":
            [r for _, r in relab] == [C(r) for _, r in base],
        "residuos": [r for _, r in relab],
    }
    json.dump(out, open(os.path.join(OUT, "segmentacao_invertida.json"), "w"),
              indent=2, ensure_ascii=False)
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
