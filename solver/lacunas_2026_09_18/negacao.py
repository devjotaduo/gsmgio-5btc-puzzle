# -*- coding: utf-8 -*-
"""Item 8 (lacunas 2026-09-18): negação N−k contra os dois alvos nas 17 fontes da frente retro_17ucy.

As famílias .cjs e o prime_host comparavam só a coordenada x com 1GSMG, o que cobria k e N−k; a frente
retro_17ucy testou só k contra 17ucy. Aqui cada escalar k das 17 fontes (regeneradas pelo próprio
retro.py, com as mesmas reconciliações) é conferido como k e como N−k, nas duas formas de pubkey, contra
os dois alvos. A pubkey de N−k é o ponto negado (x, p−y): prefixo comprimido trocado e y → p−y, sem
segunda multiplicação na curva.

retro.py não é editado: este script troca só retro.varrer (no pai e em cada filho spawn, porque o
patch roda na importação). Controles: fórmula da negação conferida contra coincurve(N−k) em escalares
aleatórios; em cada fonte, o h160 de N−k de um escalar do próprio fluxo é plantado e tem de ser achado
pelo lado N−k (senão a fonte aborta), além dos dois controles plantados de k que o retro.py já faz.
Uso: python negacao.py [FONTE ...]   (sem argumentos: as 17 fontes, Pool de 4)
"""
import hashlib, json, os, random, sys, time
from multiprocessing import Pool
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "enxame_2026_09_18" / "retro_17ucy"))
import retro as R  # noqa: E402
from coincurve import PublicKey  # noqa: E402

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
OUT = REPO / "_work" / "lacunas_2026-09-18" / "negacao"
WORKERS = 4


def formas(k):
    """{(lado, comprimida): pubkey serializada} para k e N−k."""
    pk = PublicKey.from_valid_secret(k)
    u = pk.format(False)
    x, yn = u[1:33], P - int.from_bytes(u[33:], "big")
    return {("k", False): u, ("k", True): pk.format(True),
            ("N-k", False): b"\x04" + x + yn.to_bytes(32, "big"), ("N-k", True): bytes([2 + (yn & 1)]) + x}


def varrer(arr, plantados):
    """Mesma assinatura e retorno de retro.varrer, conferindo k e N−k."""
    alvos = {**{h: ("REAL", a) for h, a in R.REAIS.items()}, **plantados}
    neg = None
    for v in arr:                                   # controle do lado N−k: primeiro escalar válido do fluxo
        k = v.tobytes()
        if k != R.ZERO and k < R.NB:
            kn = PublicKey.from_valid_secret((R.N - int.from_bytes(k, "big")).to_bytes(32, "big"))
            neg = (k.hex(), {R.h160(kn.format(c)): ("PLANTADO_NEG", c) for c in (False, True)})
            alvos.update(neg[1])
            break
    fluxo = hashlib.sha256()
    validos = invalidos = 0
    acertos = []
    for v in arr:
        k = v.tobytes()
        if k == R.ZERO or k >= R.NB:
            invalidos += 1
            continue
        validos += 1
        fluxo.update(k)
        for (lado, comp), blob in formas(k).items():
            h = R.h160(blob)
            # os plantados de k (do retro.py) só valem pelo lado k: fontes com espelho (brainwallet_inline
            # guarda k e N−k) casariam o plantado também pelo N−k do espelho
            if h in alvos and not (alvos[h][0] == "PLANTADO" and lado == "N-k"):
                acertos.append({"k": k.hex(), "lado": lado, "comprimida": comp, "h160": h.hex(), "alvo": alvos[h]})
    if neg:
        achados = {a["comprimida"] for a in acertos if a["alvo"][0] == "PLANTADO_NEG" and a["k"] == neg[0] and a["lado"] == "N-k"}
        assert achados == {False, True}, ("controle N−k falhou", neg[0], achados)
        NEG_CTL.append({"k0_prefixo": neg[0][:16], "achado_nas_duas_formas": True})
    return validos, invalidos, fluxo.hexdigest(), [a for a in acertos if a["alvo"][0] != "PLANTADO_NEG"]


NEG_CTL = []
R.varrer = varrer  # ponytail: troca só o oráculo; geração, reconciliação e controles de k seguem os do retro.py


def processar(nome):
    """retro.processar + prova, vinda do próprio filho, de que o varrer com N−k rodou."""
    NEG_CTL.clear()
    r, pref = R.processar(nome)
    r["negacao"] = {"patch_ativo_no_filho": R.varrer is varrer, "controle_N-k": list(NEG_CTL)}
    return r, pref


def controle_formula(n=2000):
    rnd = random.Random(20260918)
    for _ in range(n):
        k = rnd.randrange(1, R.N).to_bytes(32, "big")
        kn = PublicKey.from_valid_secret((R.N - int.from_bytes(k, "big")).to_bytes(32, "big"))
        f = formas(k)
        assert (f[("N-k", False)], f[("N-k", True)]) == (kn.format(False), kn.format(True))
    return {"escalares_aleatorios": n, "negacao_igual_a_coincurve": True}


def main(nomes):
    teste = bool(nomes)
    nomes = nomes or list(R.FONTES)
    t0 = time.time()
    ctl = {"formula": controle_formula()}
    res = []
    with Pool(WORKERS, maxtasksperchild=1) as pool:
        for r, _pref in pool.imap_unordered(processar, nomes):
            res.append(r)
            print("[fonte] %-22s validos=%9d reais=%d plantado_k=%s negacao=%s %.0fs" % (
                r["fonte"], r["validos"], len(r["hits_reais"]), r["controle_plantado_ok"], r["negacao"], r["seg_total"]),
                flush=True)
    assert all(r["controle_plantado_ok"] and r["ecdsa_divergencias"] == 0 for r in res), "controle de k falhou"
    assert all(r["negacao"]["patch_ativo_no_filho"] and len(r["negacao"]["controle_N-k"]) == 1 for r in res), \
        "o varrer com N−k não rodou em algum filho"
    ordem = {n: i for i, n in enumerate(R.FONTES)}
    res.sort(key=lambda r: ordem[r["fonte"]])
    resumo = {"item": 8, "alvos": dict(zip(R.O.PRIZE_ADDRS, R.O.TARGET_H160S)), "fontes": len(res),
              "validos": sum(r["validos"] for r in res),
              "verificacoes_h160": 4 * sum(r["validos"] for r in res),   # k e N−k, comprimida e não
              "hits_reais": [h for r in res for h in r["hits_reais"]],
              "controle_N-k_por_fonte": "assert dentro de varrer(): h160 de N−k plantado achado pelo lado N−k",
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "retro_sha256": R.sha_arquivo(R.__file__), "kit": R.C.commit_do_kit(),
              "seg_parede": round(time.time() - t0, 1)}
    print(json.dumps(resumo, ensure_ascii=False, indent=1), flush=True)
    if teste:
        return
    OUT.mkdir(parents=True, exist_ok=True)
    por_fonte = [{k: r[k] for k in ("fonte", "unicos", "validos", "sha256_fluxo_ordenado", "hits_reais",
                                    "controle_plantado_ok", "ecdsa_divergencias", "negacao", "seg_total")} for r in res]
    json.dump({**resumo, "por_fonte": por_fonte}, open(OUT / "summary.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    json.dump(ctl | {"k_plantado_por_fonte": {r["fonte"]: r["controle_plantado_ok"] for r in res}},
              open(OUT / "controls.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main(sys.argv[1:])
