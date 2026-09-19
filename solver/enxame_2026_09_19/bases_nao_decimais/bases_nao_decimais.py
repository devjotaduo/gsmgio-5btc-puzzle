# -*- coding: utf-8 -*-
"""
F11 bases_nao_decimais - conversao do residuo de ENDGAME.md Sec.6 em bases nao decimais
e teste pelo oraculo duro (senha nos 3 blobs x 2 KDF; escalar de 32B contra os 2 alvos).

Uso: python3 bases_nao_decimais.py
"""
import sys, json, hashlib
sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
import gsmg_common as G

L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
L83 = L84[:-1]
assert len(L84) == 61 and len(L83) == 60

# ---------------------------------------------------------------- 1. repertorio
from collections import Counter
c84 = Counter(L84)
print("== repertorio ==")
print("simbolos presentes (L84):", sorted(c84.keys()))
print("contagens L84:", dict(sorted(c84.items())))
assert set(c84.keys()) == set("abcdefghi"), "repertorio inesperado"
assert "o" not in L84 and "j" not in L84

CONV1 = {c: i + 1 for i, c in enumerate("abcdefghi")}   # a=1..i=9 (sem zero -> bijetiva)
CONV2 = {c: i for i, c in enumerate("abcdefghi")}        # a=0..i=8 (zero-based, base 9 padrao)

# ---------------------------------------------------------------- 2. prova de impossibilidade
print("\n== prova de impossibilidade por repertorio ==")
max_conv1 = max(CONV1[c] for c in c84)   # = 9 (letra i)
max_conv2 = max(CONV2[c] for c in c84)   # = 8 (letra i)
min_conv2 = min(CONV2[c] for c in c84)   # = 0 (letra a) presente -> nao ha "sem zero" em conv2
print(f"max digito conv1 (a=1..i=9): {max_conv1} -> exige b-1>=9 (padrao) ou k>=9 (bijetiva) -> b>=9 conv1")
print(f"max digito conv2 (a=0..i=8): {max_conv2} -> exige b-1>=8 -> b>=9 conv2")
print("logo bases 2..8 sao IMPOSSIVEIS nas duas convencoes (letra 'i' excede o maior digito legal)")
for b in range(2, 9):
    assert (b - 1) < max_conv1 and (b - 1) < max_conv2
print("verificado: nenhuma base <=8 admite o simbolo 'i' em nenhuma convencao")

impossible_bases = list(range(2, 9))

# ---------------------------------------------------------------- 3. bases admissiveis
# base 9: unica base "forcada" pela algebra (bijetiva conv1: sem zero por definicao;
#         padrao conv2: repertorio bate exatamente com o alfabeto de digitos 0..8)
# base 10: decimal, fora de escopo (ja fechada em Sec.6 por outras 3 leituras)
# b>=11 conv1: nao sao "forcadas" pelo argumento sem-zero (qualquer base>=10 aceitaria
#         ausencia de zero por acaso); familia infinita e nao motivada; regra 4 (teto de
#         complexidade) -> cobrir so o subconjunto de bases redondas que uma ferramenta
#         online (CyberChef "From Base" / dcode) oferece de forma direta.
ROUND_BASES = [11, 12, 13, 14, 15, 16, 20, 24, 32, 36, 60]

def eval_base(s, conv, base):
    n = 0
    for c in s:
        n = n * base + conv[c]
    return n

def to_bytes_forms(n):
    """Formas de bytes de um inteiro grande: completa, baixa-32B, alta-32B (quando >32B)."""
    if n == 0:
        full = b"\x00"
    else:
        full = n.to_bytes((n.bit_length() + 7) // 8, "big")
    forms = {}
    if len(full) <= 32:
        forms["pad32"] = full.rjust(32, b"\x00")
    else:
        forms["low32"] = full[-32:]
        forms["high32"] = full[:32]
    return forms

# ---------------------------------------------------------------- 4. controle positivo (decifra)
print("\n== controle positivo (decifra) ==")
import base64
raw = base64.b64decode(G.PHASE2_B64); s2, c2 = raw[8:16], raw[16:]
pw = G.shahex("causality").encode()
from Crypto.Hash import MD5, SHA256
ok_sha = ok_md5 = None
for hm, tag in ((SHA256, "sha"), (MD5, "md5")):
    k, iv = G.evp(pw, s2, hm)
    from Crypto.Cipher import AES
    p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c2))
    if tag == "sha": ok_sha = p is not None and p.startswith(b"The ironic")
    else: ok_md5 = p is not None and p.startswith(b"The ironic")
print(f"fase2 sha256hex('causality') via EVP-SHA256: {ok_sha} (esperado True)")
print(f"fase2 via EVP-MD5: {ok_md5} (esperado False)")
assert ok_sha and not ok_md5, "CONTROLE DE KDF FALHOU"

print("\n== controle positivo (privkey plantada) ==")
_k = G.sha(b"controle-f11-bases")
from coincurve import PublicKey as _PK
_h = G._h160_hex(_PK.from_valid_secret(_k).format(True))
before = G.fast_priv_scan(b"\x00" * 5 + _k + b"\x00" * 3)
G.TARGET_H160S = G.TARGET_H160S + (_h,)
after = G.fast_priv_scan(b"\x00" * 5 + _k + b"\x00" * 3)
G.TARGET_H160S = G.TARGET_H160S[:-1]
print(f"antes de injetar alvo: {before} (esperado [])")
print(f"depois de injetar alvo: {after} (esperado priv@5)")
assert before == [] and len(after) == 1 and after[0][1] == "priv@5", "CONTROLE DE PRIVKEY FALHOU"
print("controles positivos OK")

# ---------------------------------------------------------------- 5. varredura
print("\n== varredura ==")
jobs = []  # (base, conv_name, residuo_name, direcao, N)
def add_jobs(base, conv, conv_name):
    for res_name, s in (("L84", L84), ("L83", L83)):
        for dir_name, ss in (("fwd", s), ("rev", s[::-1])):
            n = eval_base(ss, conv, base)
            jobs.append((base, conv_name, res_name, dir_name, n))

# base 9, as duas convencoes
add_jobs(9, CONV1, "conv1_bijetiva(a=1..i=9)")
add_jobs(9, CONV2, "conv2_padrao(a=0..i=8)")
# bases redondas >=11, so conv1 (motivacao unica: leitura literal a-i=1..9)
for b in ROUND_BASES:
    add_jobs(b, CONV1, "conv1_bijetiva(a=1..i=9)")

print(f"total de leituras (base x convencao x residuo x direcao): {len(jobs)}")

n_bases = 1 + 1 + len(ROUND_BASES)  # base9-conv1, base9-conv2, + round bases (conv1 only), contamos combinacoes
n_pw_tests = 0
n_scalar_tests = 0
hits_pw = []
hits_scalar = []
n_soft = 0

for base, conv_name, res_name, dir_name, n in jobs:
    hexstr = format(n, "x")
    decstr = str(n)
    pw_candidates = {
        "dec": decstr,
        "hex": hexstr,
        "sha_dec": hashlib.sha256(decstr.encode()).hexdigest(),
        "sha_hex": hashlib.sha256(hexstr.encode()).hexdigest(),
    }
    for form, pw in pw_candidates.items():
        n_pw_tests += 1
        hard, soft = G.try_password_all(pw)
        n_soft += len(soft)
        if hard:
            hits_pw.append({"base": base, "conv": conv_name, "res": res_name, "dir": dir_name,
                             "form": form, "pw": pw, "hard": hard})
    # escalar de 32B
    for bform, b32 in to_bytes_forms(n).items():
        n_scalar_tests += 1
        r = G.priv_hit(b32)
        if r:
            hits_scalar.append({"base": base, "conv": conv_name, "res": res_name, "dir": dir_name,
                                 "bform": bform, "hex": b32.hex(), "hit": r})

print(f"total de testes de senha (try_password_all, cada um cobre 3 blobs x 2 kdf): {n_pw_tests}")
print(f"total de testes de escalar de 32B (priv_hit, cobre os 2 alvos comp/uncomp): {n_scalar_tests}")
print(f"hits de senha (CANDIDATO/oraculo duro): {len(hits_pw)}")
print(f"hits de escalar (CHAVE PRIVADA): {len(hits_scalar)}")
print(f"paddings PKCS7 validos sem sinal semantico (ruido, 1/255 esperado): {n_soft}")

result = {
    "residuo_L84": L84, "residuo_L83": L83,
    "bases_impossiveis_2_8": impossible_bases,
    "bases_testadas": {"base9_conv1_bijetiva": True, "base9_conv2_padrao": True,
                        "round_bases_conv1": ROUND_BASES, "base10_decimal": "fora de escopo (ja coberta em Sec.6)"},
    "n_leituras": len(jobs),
    "n_pw_tests": n_pw_tests,
    "n_scalar_tests": n_scalar_tests,
    "n_soft_padding_only": n_soft,
    "hits_pw": hits_pw,
    "hits_scalar": hits_scalar,
    "controle_kdf_ok": bool(ok_sha and not ok_md5),
    "controle_privkey_ok": True,
}
with open("/home/user/gsmgio-5btc-puzzle/_work/enxame_2026-09-19/bases_nao_decimais/resultado.json", "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)
print("\nresultado gravado em _work/enxame_2026-09-19/bases_nao_decimais/resultado.json")
