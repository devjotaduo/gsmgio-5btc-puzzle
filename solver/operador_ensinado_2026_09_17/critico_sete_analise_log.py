# -*- coding: utf-8 -*-
"""Analise fechada do paddings.jsonl.gz do atacante (familia sete_entrelacados):
distribuicao dos comprimentos de padding (prova do denominador 1/255), contagem por celula
(blob x KDF x forma) e pt_sha distintos (mede duplicatas de material entre tarefas)."""
import gzip, json, math, collections, os
DIR = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17"
LEN = {"SMALL": 80, "COSMIC": 1328, "TAIL32": 80}
pad_hist = collections.Counter(); cel = collections.Counter(); sha = set(); n = 0
trunc = collections.Counter(); pr_hi = 0; tarefas = set(); tam_mat = collections.Counter()
with gzip.open(os.path.join(DIR, "familia3_entrelacamento", "paddings.jsonl.gz"), "rt", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line); n += 1
        pad_hist[LEN[r["blob"]] - r["len"]] += 1
        cel[(r["blob"], r["kdf"].split(".")[-1], r["form"])] += 1
        sha.add((r["blob"], r["kdf"], r["pt_sha"]))
        trunc[(r["blob"], r["trunc"])] += 1
        if r["printable"] >= 0.6: pr_hi += 1
        tarefas.add(r["tarefa"])
        tam_mat[len(r["material"]) >= 120] += 1
N_AES = 109_296_000
p_ok = sum(256.0 ** -j for j in range(1, 17))
esp = {j: N_AES * 256.0 ** -j for j in range(1, 6)}
out = {
    "registros": n, "tarefas_distintas": len(tarefas),
    "pad_hist_obs": dict(sorted(pad_hist.items())),
    "pad_hist_esperado": {j: round(v, 1) for j, v in esp.items()},
    "excesso_obs_sobre_n_256": n - N_AES / 256, "excesso_esperado_cauda_j>=2": round(N_AES * (p_ok - 1 / 256), 1),
    "z_1_256": round((n - N_AES / 256) / math.sqrt(N_AES / 256 * 255 / 256), 3),
    "z_1_255": round((n - N_AES * p_ok) / math.sqrt(N_AES * p_ok * (1 - p_ok)), 3),
    "por_celula": {"/".join(k): v for k, v in sorted(cel.items())},
    "esperado_por_celula": round(N_AES / 12 * p_ok, 1),
    "pt_sha_distintos(blob,kdf,sha)": len(sha), "duplicatas_no_log": n - len(sha),
    "trunc": {f"{k[0]}/trunc={k[1]}": v for k, v in sorted(trunc.items())},
    "printable>=0.6": pr_hi, "material_truncado_a_120": tam_mat[True],
}
print(json.dumps(out, indent=1))
json.dump(out, open(os.path.join(DIR, "critico_sete_final", "analise_log_atacante.json"), "w"), indent=1)
