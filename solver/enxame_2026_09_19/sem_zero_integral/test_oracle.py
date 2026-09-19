#!/usr/bin/env python3
"""F3 sem_zero_integral -- testa os candidatos materializados (comprimento 64) contra o oraculo
duro (senha nos 3 blobs, SHA256 e MD5 KDF). Comprimento 32 (escalar) foi PROVADO INEXISTENTE por
DP exata (ver full_paths.cjs, fase 2) -- nenhuma leitura de 32 bytes existe em NENHUM dos 192.960
modelos ASCII zero-free compativeis com DBBI, entao nao ha nada para testar como escalar cru.

Controle positivo do pipeline (especifico desta frente, alem do self-test padrao do kit):
planta uma senha REAL retirada dos proprios candidatos materializados, cifra um blob de teste com
ela (mesmo KDF do kit: EVP SHA256), e exige que o loop de teste abaixo a recupere.
"""
import sys, json, hashlib, base64
sys.path.insert(0, "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02")
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
import os

CAND_PATH = "/home/user/gsmgio-5btc-puzzle/_work/enxame_2026-09-19/sem_zero_integral/candidates.jsonl"
OUT_PATH = "/home/user/gsmgio-5btc-puzzle/_work/enxame_2026-09-19/sem_zero_integral/oracle_results.json"

# ---------------------------------------------------------------- controle positivo do pipeline
with open(CAND_PATH) as f:
    first = json.loads(f.readline())
planted_pw = bytes.fromhex(first["hex"])
salt = os.urandom(8)
k, iv = G.evp(planted_pw, salt, SHA256)
pt = b"controle sem_zero_integral F3 2026-09-19" + b"\x00" * 7  # múltiplo de 16 já com padding manual simples
# usa padding PKCS7 de verdade via unpad/pad manual:
def pkcs7(b, block=16):
    n = block - (len(b) % block)
    return b + bytes([n]) * n
pt_padded = pkcs7(b"controle sem_zero_integral F3 2026-09-19")
ct = AES.new(k, AES.MODE_CBC, iv).encrypt(pt_padded)
blob = b"Salted__" + salt + ct
G.BLOBS["_CONTROL_"] = (salt, ct)
hard, soft = G.try_password_all(planted_pw, blobs=("_CONTROL_",), kdf="sha256")
assert hard and hard[0]["head"].startswith("controle sem_zero_integral"), ("CONTROLE POSITIVO FALHOU", hard, soft)
del G.BLOBS["_CONTROL_"]
print("[controle positivo] OK -- senha plantada (retirada dos proprios candidatos) recuperada via try_password_all")

# controle positivo padrao do kit (fase 2 / causality) via checagem direta do EVP-SHA256
raw = base64.b64decode(G.PHASE2_B64); s2, c2 = raw[8:16], raw[16:]
pw2 = G.shahex("causality").encode()
k2, iv2 = G.evp(pw2, s2, SHA256)
p2 = G.unpad(AES.new(k2, AES.MODE_CBC, iv2).decrypt(c2))
assert p2 is not None and p2.startswith(b"The ironic"), p2
print("[controle positivo] OK -- fase 2 abre com sha256hex('causality') via EVP-SHA256")

# ---------------------------------------------------------------- varredura real
n_tested = 0
n_hard = 0
n_soft_padding = 0
hits = []
seen_pw = set()
with open(CAND_PATH) as f:
    for line in f:
        d = json.loads(line)
        pw = bytes.fromhex(d["hex"])
        if pw in seen_pw:
            continue  # nao soma senha duplicada (algumas variantes de colisao podem coincidir)
        seen_pw.add(pw)
        hard, soft = G.try_password_all(pw, blobs=("SMALL", "COSMIC", "TAIL32"), kdf="both")
        n_tested += 1
        if hard:
            n_hard += 1
            hits.append({"candidate": d, "hard": hard})
        if soft:
            n_soft_padding += len(soft)

result = {
    "n_candidates_in_file": None,
    "n_distinct_passwords_tested": n_tested,
    "n_hard_hits": n_hard,
    "n_soft_padding_hits": n_soft_padding,
    "blobs": ["SMALL", "COSMIC", "TAIL32"],
    "kdf": "both (SHA256 e MD5)",
    "hits": hits[:50],
}
with open(CAND_PATH) as f:
    result["n_candidates_in_file"] = sum(1 for _ in f)

with open(OUT_PATH, "w") as f:
    json.dump(result, f, indent=2)
print(json.dumps({k: v for k, v in result.items() if k != "hits"}, indent=2))
print("hits (ate 50):", json.dumps(hits[:5], indent=2) if hits else "NENHUM")
