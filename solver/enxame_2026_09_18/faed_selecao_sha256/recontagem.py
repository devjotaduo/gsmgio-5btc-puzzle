# -*- coding: utf-8 -*-
"""Recontagem independente dos paddings da frente faed_selecao_sha256.

Segunda implementação do teste de padding: EVP_BytesToKey com hashlib (não Crypto.Hash), só o
último bloco em AES-ECB com XOR manual do bloco anterior (não G.aes_try/unpad). Recalcula U pelo
gerador de teste.py e confere, célula a célula (blob × KDF × forma), a contagem gravada em
paddings.jsonl e o conjunto exato de (senha, blob, kdf). Grava recontagem.json ao lado.
"""
import os, sys, json, hashlib, collections
from multiprocessing import Pool
from Crypto.Cipher import AES

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
import teste as T

KDFS = {"SHA256": hashlib.sha256, "MD5": hashlib.md5}


def evp(pw, salt, h):
    d = prev = b""
    while len(d) < 48:
        prev = h(prev + pw + salt).digest()
        d += prev
    return d[:32], d[32:48]


def pad_ok(ultimo):
    n = ultimo[-1]
    return 1 <= n <= 16 and ultimo[-n:] == bytes([n]) * n


def _conta(senha):
    out = []
    for b in T.C.BLOBS_PREMIO:
        salt, ct = T.G.BLOBS[b]
        for nome, h in KDFS.items():
            k, iv = evp(senha, salt, h)
            anterior = ct[-32:-16] if len(ct) > 16 else iv
            ult = bytes(x ^ y for x, y in zip(AES.new(k, AES.MODE_ECB).decrypt(ct[-16:]), anterior))
            if pad_ok(ult):
                out.append((senha.hex(), b, nome))
    return out


if __name__ == "__main__":
    U = T.distintos(T.gerar_ocorrencias(T.G.FAED))
    origem = T.origem_por_forma(list(U))
    with Pool(T.WORKERS) as pool:
        novos = {x for r in pool.imap_unordered(_conta, origem, chunksize=512) for x in r}
    gravados = set()
    for linha in open(os.path.join(T.SAIDA, "paddings.jsonl"), encoding="utf-8"):
        x = json.loads(linha)
        gravados.add((x["senha_hex"], x["blob"], x["kdf"]))
    cel = collections.Counter((b, k, origem[bytes.fromhex(s)][1]) for s, b, k in novos)
    invalidos = [u.hex() for u in U if not (0 < int.from_bytes(u, "big") < T.C.G.O.SECP256k1.order)]
    res = {"senhas": len(origem), "paddings_recontados": len(novos), "paddings_gravados": len(gravados),
           "conjuntos_identicos": novos == gravados,
           "celulas": {f"{b}/{k}/{f}": n for (b, k, f), n in sorted(cel.items())},
           "u_invalidos_como_escalar": invalidos}
    json.dump(res, open(os.path.join(T.SAIDA, "recontagem.json"), "w", encoding="utf-8"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "celulas"}))
    assert res["conjuntos_identicos"], "recontagem diverge do jsonl"
