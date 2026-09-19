# -*- coding: utf-8 -*-
"""F2: sobreposicao exata entre os conjuntos de senha de F1 e F2 (protocolo, item 5).
Emite reconciliacao.json em _work/enxame_2026-09-19/auditoria_fluxo/."""
import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "modos_fluxo"))
import varredura as V
import passwords as PW
s1, meta1 = PW.build()
S1 = set(s1)
S2 = set(x.encode() for x in V.build_passwords())
inter = S1 & S2
out = {
    "F1_senhas": len(S1), "F1_camadas": meta1["camadas"],
    "F2_senhas": len(S2),
    "interseccao": len(inter), "so_F1": len(S1 - S2), "so_F2": len(S2 - S1),
    "uniao": len(S1 | S2),
    "decifracoes_duplicadas": len(inter) * 5 * 2 * 3,
    "sha256_conjunto_F1": hashlib.sha256(b"\n".join(sorted(S1))).hexdigest(),
    "sha256_conjunto_F2": hashlib.sha256(b"\n".join(sorted(S2))).hexdigest(),
    "sha256_passwords_py_F1": hashlib.sha256(
        open(os.path.join(HERE, "..", "modos_fluxo", "passwords.py"), "rb").read()).hexdigest(),
    "sha256_stream_scan_py_F1": hashlib.sha256(
        open(os.path.join(HERE, "..", "modos_fluxo", "stream_scan.py"), "rb").read()).hexdigest(),
}
p = os.path.join(V.OUT, "reconciliacao.json")
json.dump(out, open(p, "w"), indent=2, ensure_ascii=False)
print(json.dumps({k: v for k, v in out.items() if k != "F1_camadas"}, indent=1))
