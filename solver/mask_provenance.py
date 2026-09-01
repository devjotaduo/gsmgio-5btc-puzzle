# -*- coding: utf-8 -*-
"""A2 MASK-HUNTER: proveniencia de CHAIN4_MASK = b657264f2f6e6921.

Duas hipoteses falsificaveis:
  (C) CONSTRUCAO: mask == cc[158:166] XOR b"Salted__"  -> header imposto, nao ancora.
  (D) DERIVACAO : mask (8B) == fatia de sha256(token) / XOR de subsets / fatia de
      half/better_half/E_C/E_S/keymat / ascii-hex legivel -> Chain4 ancorado.

So reporta match byte-exato; nada de brute force cego.
"""
import hashlib
import itertools
import json
import os
import sys

import final_chain as FC
import oracles as O

MASK = FC.CHAIN4_MASK  # b657264f2f6e6921

R = FC.reproduce()
cc = R["cosmic"]            # 1327B plaintext do Cosmic
half = R["half"]            # components[:32]
better_half = R["better_half"]
matrix_tail = R["matrix_tail"]
chain1 = R["chain1"]
chain2 = R["chain2"]

out = {"mask": MASK.hex()}


def sha(b):
    return hashlib.sha256(b).digest()


# ---------- (C) CONSTRUCAO ----------
window = cc[158:166]
constructed = bytes(a ^ b for a, b in zip(window, b"Salted__"))
out["construction"] = {
    "cc[158:166]": window.hex(),
    "cc[158:166]_ascii": window.decode("latin-1"),
    "cc[158:166] XOR 'Salted__'": constructed.hex(),
    "equals_mask": constructed == MASK,
}
# checagem cruzada: chain4_blob[:8] realmente vira "Salted__"?
blob_head = FC.xor_cycle(cc[158:166], MASK)
out["construction"]["chain4_blob[:8]"] = blob_head.decode("latin-1")

# ---------- (D) DERIVACAO ----------
# tokens da pagina (a gramatica intertwined provada usa estes)
TOKENS = {
    "enter": b"enter",
    "matrixsumlist": b"matrixsumlist",
    "lastwordsbeforearchichoice": b"lastwordsbeforearchichoice",
    "thispassword": b"thispassword",
    "yourlastcommand": b"yourlastcommand",
    "secondanswer": b"secondanswer",
    "shabef": b"shabef",
    "our first hint is your last command": b"our first hint is your last command",
    "shabef ans too": b"shabef ans too",
    "Salted__": b"Salted__",
    # variacoes de caixa que a pagina usa
    "Enter": b"Enter",
    "MatrixSumList": b"MatrixSumList",
}

digests = {name: sha(tok) for name, tok in TOKENS.items()}

# D1: mask == primeiros/ultimos 8B de sha256(token)?  (qualquer offset 0..24)
d1 = []
for name, dg in digests.items():
    for off in range(0, 25):
        if dg[off:off + 8] == MASK:
            d1.append({"token": name, "offset": off, "kind": "sha256 slice"})
out["D1_sha_slice"] = d1

# D2: mask == XOR de sha256 de subsets pequenos (tamanho 2..4), fatia [0:8] e [off]
names = list(digests)
d2 = []
for r in (2, 3, 4, 5):
    for combo in itertools.combinations(names, r):
        acc = bytearray(32)
        for nm in combo:
            for i in range(32):
                acc[i] ^= digests[nm][i]
        acc = bytes(acc)
        for off in range(0, 25):
            if acc[off:off + 8] == MASK:
                d2.append({"combo": combo, "offset": off})
out["D2_xor_subset"] = d2

# D3: mask == fatia (qualquer offset) de artefatos-chave
artifacts = {
    "half": half,
    "better_half": better_half,
    "matrix_tail": matrix_tail,
    "chain1": chain1,
    "chain2": chain2,
    "cosmic": cc,
    "cosmic[:158]": cc[:158],
    "cosmic[158:]": cc[158:],
    "COSMIC_PASSWORD": FC.COSMIC_PASSWORD,
    "CHAIN4_PASSWORD": FC.CHAIN4_PASSWORD,
    "MATRIX_COMPONENTS": FC.MATRIX_COMPONENTS,
}
d3 = []
for name, buf in artifacts.items():
    idx = buf.find(MASK)
    if idx >= 0:
        d3.append({"artifact": name, "offset": idx, "len": len(buf)})
out["D3_artifact_slice"] = d3

# D4: mask legivel? ascii, hex-de-hex, base?
d4 = {
    "mask_ascii": MASK.decode("latin-1"),
    "mask_ascii_printable": "".join(chr(b) if 32 <= b < 127 else "." for b in MASK),
    "mask_as_hexstring": MASK.hex(),  # b6 57 26 4f 2f 6e 69 21
    # 2f='/', 6e='n', 69='i', 21='!'  -> ultimos 4 bytes = "/ni!" ? checar
    "tail4_ascii": MASK[4:].decode("latin-1"),
}
out["D4_readable"] = d4

# D5: o mask XOR "Salted__" (=cc[158:166]) tem alguma leitura? ja e o proprio window
out["D5_window_ascii"] = "".join(
    chr(b) if 32 <= b < 127 else "." for b in window
)

# D6: MD5 de tokens (EVP usa MD5) — fatia == mask?
import hashlib as _h
d6 = []
for name, tok in TOKENS.items():
    dg = _h.md5(tok).digest()
    for off in range(0, 9):
        if dg[off:off + 8] == MASK:
            d6.append({"token": name, "offset": off, "kind": "md5 slice"})
out["D6_md5_slice"] = d6

# D7: salts OpenSSL (small, cosmic) e o salt RESULTANTE do Chain4 — mask e derivado deles?
B = O.blobs()
small_salt, _ = B["SMALL"]
cosmic_salt, _ = B["COSMIC"]
chain4_salt = FC.xor_cycle(cc[166:174], MASK)  # bytes 8:16 do blob = salt OpenSSL
out["D7_salts"] = {
    "small_salt": small_salt.hex(),
    "cosmic_salt": cosmic_salt.hex(),
    "chain4_result_salt": chain4_salt.hex(),
    "chain4_salt_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chain4_salt),
    "mask==small_salt": MASK == small_salt,
    "mask==cosmic_salt": MASK == cosmic_salt,
    "mask==chain4_salt": MASK == chain4_salt,
    # o salt do Chain4 deriva de token? (mesma pergunta que o mask, mas no salt)
    "chain4_salt in cosmic": cc.find(chain4_salt),
}

# D8: E_C/E_S/E_B explicitos (as tres fatias que formam CHAIN4_PASSWORD)
E_C = chain1[64:79]
E_S = chain2[64:79]
E_B = cc[64:66]
d8 = []
for name, buf in (("E_C", E_C), ("E_S", E_S), ("E_B", E_B),
                  ("sha(E_C)", sha(E_C)), ("sha(E_S)", sha(E_S)), ("sha(E_B)", sha(E_B))):
    if MASK in buf:
        d8.append({"src": name, "offset": buf.find(MASK)})
out["D8_ecesb"] = d8

print(json.dumps(out, indent=2, ensure_ascii=False))

# log jsonl
logp = os.path.join(os.path.dirname(__file__), "..", "_work", "mask_provenance.jsonl")
with open(logp, "a", encoding="utf-8") as f:
    f.write(json.dumps(out, ensure_ascii=False) + "\n")
