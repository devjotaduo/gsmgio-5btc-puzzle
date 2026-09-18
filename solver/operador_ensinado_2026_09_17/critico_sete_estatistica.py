# -*- coding: utf-8 -*-
r"""Auditoria fechada do "sinal" z=+2,71 da familia sete_entrelacados, sem rodar AES nenhuma.

 1. Expectativa EXATA de padding valido sob a regra de `G.unpad` (aceita 1..16):
    p = Sigma_{j=1..16} 256^-j = (1 - 256^-16)/255 = 1/255 a menos de 2^-128.
 2. O histograma de COMPRIMENTOS de padding do log do atacante decide a questao sozinho:
    se o excesso fosse sinal, estaria espalhado; se for o denominador, esta todo em pad >= 2.
 3. Duplicatas de material entre tarefas: o mesmo material decifrado m vezes correlaciona as
    celulas. Var[X] = 12 p(1-p) Sigma m_i^2 (e nao n p (1-p)). Corrige o z.
 4. Independencia entre celulas: qui-quadrado sobre as 12 celulas (blob x KDF x forma).
 5. Teto de `printable` por celula: cauda binomial exata + maximo esperado em N amostras.
"""
from __future__ import annotations
import gzip, json, math, os, collections
from math import comb

W = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17"
AG, OUT = os.path.join(W, "familia3_entrelacamento"), os.path.join(W, "critico_sete_final")
N_AES, PADS = 109_296_000, 428_706
P = sum(256.0 ** -j for j in range(1, 17))


def z(k, n, p=P):
    return (k - n * p) / math.sqrt(n * p * (1 - p))


def cauda(n, p, kmin):
    return sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(kmin, n + 1))


def main():
    pad_hist = collections.Counter()
    cel = collections.Counter()
    pr = {"SMALL": [], "COSMIC": [], "TAIL32": []}
    LEN = {"SMALL": 80, "COSMIC": 1328, "TAIL32": 80}
    with gzip.open(os.path.join(AG, "paddings.jsonl.gz"), "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            pad_hist[LEN[r["blob"]] - r["len"]] += 1
            cel[(r["blob"], r["kdf"].split(".")[-1], r["form"])] += 1
            pr[r["blob"]].append(r["printable"])

    # 1-2: denominador
    esp = {j: N_AES * 256.0 ** -j for j in range(1, 5)}
    qui_pad = sum((pad_hist[j] - esp[j]) ** 2 / esp[j] for j in (1, 2, 3))
    # 3: duplicatas (histograma vindo do stage dedup)
    dd = json.load(open(os.path.join(OUT, "resumo_dedup.json"), encoding="utf-8"))["dedup"]
    hm = {int(k): v for k, v in dd["histograma_multiplicidade"].items()}
    sm2 = sum(m * m * c for m, c in hm.items())
    sm1 = sum(m * c for m, c in hm.items())
    # 4: qui-quadrado das 12 celulas
    e_cel = N_AES / 12 * P
    qui_cel = sum((v - e_cel) ** 2 / e_cel for v in cel.values())
    # 5: teto de printable (p = 95/256 por byte de ruido)
    pb = 95 / 256
    teto = {}
    for bn, vals in pr.items():
        n_b = 79 if bn != "COSMIC" else 64          # COSMIC no log vem truncado em 64 B
        N = len(vals)
        obs = max(vals)
        kobs = round(obs * n_b)
        teto[bn] = {"amostras": N, "printable_max_obs": obs, "bytes_no_log": n_b,
                    "p_um_registro(>=obs)": cauda(n_b, pb, kobs),
                    "esperado_em_N": N * cauda(n_b, pb, kobs),
                    "maior_k_com_esperado<1": next(k for k in range(n_b, 0, -1)
                                                   if N * cauda(n_b, pb, k) >= 1) + 1}
    R = {
        "expectativa": {"p_exato_regra_1_a_16": P, "1/255": 1 / 255, "1/256": 1 / 256,
                        "esperado_1_255": round(N_AES * P, 1), "esperado_1_256": N_AES / 256,
                        "observado": PADS, "desvio_vs_1_255": round(PADS - N_AES * P, 1),
                        "sigma": round(math.sqrt(N_AES * P * (1 - P)), 1),
                        "z_1_255": round(z(PADS, N_AES), 3), "z_1_256": round(z(PADS, N_AES, 1 / 256), 3),
                        "vies_do_denominador_em_z": round(z(PADS, N_AES, 1 / 256) - z(PADS, N_AES), 3)},
        "histograma_padding": {"observado": dict(sorted(pad_hist.items())),
                               "esperado_geometrico": {j: round(v, 1) for j, v in esp.items()},
                               "qui2_3gl": round(qui_pad, 2),
                               "excesso_sobre_n/256": round(PADS - N_AES / 256, 1),
                               "explicado_pela_cauda_j>=2": round(N_AES * (P - 1 / 256), 1)},
        "duplicatas": {"materiais_por_tarefa": sm1, "distintos": sum(hm.values()),
                       "multiplicidades": hm, "soma_m2": sm2,
                       "inflacao_de_variancia": round(12 * sm2 / N_AES, 4),
                       "z_corrigido": round((PADS - N_AES * P) / math.sqrt(12 * P * (1 - P) * sm2), 3)},
        "celulas": {"observado": {"/".join(k): v for k, v in sorted(cel.items())},
                    "esperado_por_celula": round(e_cel, 1), "qui2_11gl": round(qui_cel, 2),
                    "p_aprox": round(math.exp(-qui_cel / 2) * sum((qui_cel / 2) ** i / math.factorial(i)
                                                                  for i in range(6)), 3)},
        "teto_printable": teto,
    }
    print(json.dumps(R, indent=1, ensure_ascii=False))
    json.dump(R, open(os.path.join(OUT, "estatistica.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
