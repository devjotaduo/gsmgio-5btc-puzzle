# -*- coding: utf-8 -*-
"""A coincidência 83 = L83 = blocos do COSMIC, testada como partição (2026-09-18).

O `ENDGAME.md` registra que o COSMIC tem **83 blocos AES** e que uma das duas segmentações de `dbbi` tem
**83 tokens** — mas trata isso como coincidência numérica e nunca testou a correspondência. Ela importa
porque o gargalo declarado da §6 é justamente **qual segmentação é a pretendida, L83 ou L84**: L83 teria
um campo correspondente de 83 unidades, L84 não teria campo de 84.

Se o autor construiu o COSMIC com a estrutura de L83, os 23 blocos em posições **primas** (os
marcadores) deveriam diferir dos outros 60 de alguma forma mensurável. Se o ciphertext é AES puro, não
há diferença — e a coincidência cai de "pista" para "número".

Método: segmentação reconstruída do zero (regra da §6: posição lógica prima consome `b` ou `be`, as
demais um símbolo, consumo integral dos 91), validada contra o resíduo publicado no ENDGAME. Depois,
partição dos 83 blocos e **nulo casado** com 20.000 partições aleatórias do mesmo tamanho, em quatro
estatísticas, com correção para comparações múltiplas.
Uso: python l83_blocos_cosmic.py
"""
import hashlib, json, math, random, sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "experiments" / "claude_endgame_2026_09_02"))
import gsmg_common as G  # noqa: E402

OUT = REPO / "_work" / "l83_cosmic_2026-09-18"
RESIDUO_ENDGAME_L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"


def eh_primo(n):
    return n > 1 and all(n % d for d in range(2, int(n ** .5) + 1))


def segmentar(D):
    """Regra da §6. Marcador = token em posição lógica PRIMA (não é o conteúdo 'b')."""
    sols = []

    def rec(i, pos, toks):
        if i == len(D):
            sols.append(list(toks))
            return
        if i > len(D):
            return
        if eh_primo(pos):
            if D[i] == 'b':
                if i + 1 < len(D) and D[i + 1] == 'e':
                    toks.append(('be', pos, True)); rec(i + 2, pos + 1, toks); toks.pop()
                toks.append(('b', pos, True)); rec(i + 1, pos + 1, toks); toks.pop()
        else:
            toks.append((D[i], pos, False)); rec(i + 1, pos + 1, toks); toks.pop()

    rec(0, 1, [])
    return sols


def estatisticas(blocos, idx):
    """Quatro medidas sobre um subconjunto de blocos de 16 B."""
    sub = [blocos[i] for i in idx]
    todos = b"".join(sub)
    n = len(todos)
    media = sum(todos) / n
    var = sum((x - media) ** 2 for x in todos) / n
    popcount = sum(bin(x).count("1") for x in todos) / n
    freq = [0] * 256
    for x in todos:
        freq[x] += 1
    ent = -sum((c / n) * math.log2(c / n) for c in freq if c)
    return {"media": media, "variancia": var, "bits_por_byte": popcount, "entropia": ent}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    D = G.DBBI
    sols = segmentar(D)
    info = {}
    for s in sols:
        L = len(s)
        marc = [(t, p) for t, p, m in s if m]
        resid = "".join(t for t, p, m in s if not m)
        info[f"L{L}"] = {
            "tokens": L, "marcadores": len(marc),
            "b": sum(1 for t, _ in marc if t == 'b'), "be": sum(1 for t, _ in marc if t == 'be'),
            "residuo_len": len(resid), "residuo": resid,
            "posicoes_primas": [p for _, p in marc],
            "bits_dos_tipos": "".join('0' if t == 'b' else '1' for t, _ in marc)}
    assert len(sols) == 2, len(sols)
    assert info["L84"]["residuo"] == RESIDUO_ENDGAME_L84, "resíduo não confere com o ENDGAME"

    salt, ct = G.BLOBS["COSMIC"]
    blocos = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    assert len(blocos) == 83, len(blocos)

    # a correspondência só existe para L83: 83 tokens <-> 83 blocos
    primas = info["L83"]["posicoes_primas"]            # 1-based, 23 posições
    marcados = [p - 1 for p in primas]
    outros = [i for i in range(83) if i not in set(marcados)]
    obs_m = estatisticas(blocos, marcados)
    obs_o = estatisticas(blocos, outros)
    dif = {k: obs_m[k] - obs_o[k] for k in obs_m}

    rnd = random.Random(20260918)
    N = 20000
    extremos = {k: 0 for k in dif}
    for _ in range(N):
        amo = rnd.sample(range(83), len(marcados))
        rest = [i for i in range(83) if i not in set(amo)]
        a, b = estatisticas(blocos, amo), estatisticas(blocos, rest)
        for k in dif:
            if abs(a[k] - b[k]) >= abs(dif[k]):
                extremos[k] += 1
    p = {k: (extremos[k] + 1) / (N + 1) for k in dif}
    menor = min(p.values())
    res = {"pergunta": "a coincidência 83 = L83 = blocos do COSMIC tem lastro no ciphertext?",
           "por_que_importa": "o gargalo da §6 é qual segmentação é a pretendida; L83 teria campo "
                              "correspondente de 83 unidades, L84 não teria campo de 84",
           "segmentacao_reconstruida_do_zero": {k: {kk: vv for kk, vv in v.items()
                                                    if kk != "posicoes_primas"} for k, v in info.items()},
           "validacao": "o resíduo de L84 confere byte a byte com o publicado no ENDGAME §6",
           "particao": {"blocos": 83, "marcados_posicao_prima": len(marcados), "outros": len(outros)},
           "diferencas_observadas": {k: round(v, 5) for k, v in dif.items()},
           "p_bicaudal_nulo_casado": {k: round(v, 4) for k, v in p.items()},
           "nulo": f"{N} partições aleatórias do mesmo tamanho",
           "menor_p": round(menor, 4),
           "bonferroni_4_estatisticas": round(min(1.0, menor * 4), 4),
           "veredito": ("sem sinal: a coincidência 83=83 não tem lastro detectável no ciphertext"
                        if menor * 4 > 0.05 else "ATENÇÃO: diferença significativa, exige revisão"),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(res, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
