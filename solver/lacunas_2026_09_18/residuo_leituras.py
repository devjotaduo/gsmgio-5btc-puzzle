# -*- coding: utf-8 -*-
"""A "transformação não identificada" do resíduo de dbbi (§6), atacada de frente (2026-09-18).

Fluxo: dbbi -> yellowblueprimes (primos b/be) -> resíduo L84 (61) ou L83 (60) -> ??? . Este script
ataca o ??? com as leituras que o PRÓPRIO criador ensinou e apontou, com controle validado e escore
pelo scorer limpo (o original inflaria a leitura identidade, que é rica em a-i):

  (1) a1z26 com segmentação ambígua — a dica literal "could also be 21 or 1812" (R=18/A=1/B=2):
      dígitos 1-9 lidos como números 1-26, enumerando todas as fronteiras (single ou par 10-26);
  (2) método literal da página (Substitute a-i,o->1-9,0; To_Base(16); From_Hex) — o que decodificou
      lastwordsbeforearchichoice e thispassword; controle reproduz os dois verbatim.

Conclusão registrada: ambas dão lixo. Não é operação faltando — é que o resíduo, sob o que o criador
ensinou, não vira texto. O muro é interpretativo (qual segmentação, o que "zeroed out" zera).
Uso: python residuo_leituras.py
"""
import json, sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "primos_2026_09_17"))
import clean_scorer  # noqa: E402
OUT = REPO / "_work" / "half_betterhalf_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
NUM = {c: i + 1 for i, c in enumerate("abcdefghi")}


def segmentacoes(nums):
    """dígitos 1-9 -> números a1z26 (single 1-9 ou par 10-26); todas as fronteiras."""
    saidas = []

    def rec(i, acc):
        if i == len(nums):
            saidas.append(acc[:])
            return
        rec(i + 1, acc + [nums[i]])
        if i + 1 < len(nums) and 10 <= nums[i] * 10 + nums[i + 1] <= 26:
            rec(i + 2, acc + [nums[i] * 10 + nums[i + 1]])
    rec(0, [])
    return saidas


def metodo_pagina(R):
    """a-i -> 1-9, concatena, decimal -> hex -> bytes (o método de lastwords/thispassword)."""
    dec = "".join(str(NUM[c]) for c in R)
    h = format(int(dec), "x")
    b = bytes.fromhex(("0" + h) if len(h) % 2 else h)
    return b, sum(32 <= x < 127 for x in b) / len(b)


def controle():
    for n, esperado in ((174161018595377387932283725836301293648834223172419022725145445, "lastwordsbeforearchichoice"),
                        (36026487402470099740341006948, "thispassword")):
        h = format(n, "x")
        assert bytes.fromhex(("0" + h) if len(h) % 2 else h).decode("latin-1") == esperado
    return {"metodo_pagina_reproduz": ["lastwordsbeforearchichoice", "thispassword"]}


def main():
    sc = clean_scorer.Scorer()
    res = {"controle": controle(), "a1z26_ambiguo": {}, "metodo_pagina": {}}
    for nome, R in (("L84", R84), ("L83", R83)):
        segs = segmentacoes([NUM[c] for c in R])
        textos = ["".join(chr(64 + v) for v in s) for s in segs]
        ranked = sorted(textos, key=sc, reverse=True)
        res["a1z26_ambiguo"][nome] = {"segmentacoes": len(segs), "melhor_escore_limpo": round(sc(ranked[0]), 3),
                                      "melhor_texto": ranked[0]}
        b, pr = metodo_pagina(R)
        res["metodo_pagina"][nome] = {"bytes": len(b), "printable": round(pr, 2), "latin1": b.decode("latin-1")}
    # referência: um inglês real e a leitura identidade, no mesmo scorer
    res["referencia_escore_limpo"] = {
        "ingles": round(sc("INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALF"), 3),
        "identidade_L84": round(sc(R84.upper()), 3)}
    json.dump(res, open(OUT / "residuo_leituras.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
