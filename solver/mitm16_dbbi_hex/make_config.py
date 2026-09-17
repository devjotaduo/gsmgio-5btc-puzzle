# -*- coding: utf-8 -*-
"""
Gera o config.json do MITM `main.go`: pesos W_t (mod n) por token do dbbi para 4 ordens de leitura
dos 64 dígitos hex, a pubkey do prêmio e um controle plantado (bijeção aleatória → chave → pubkey).

Uso (da raiz do repositório):
    C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe solver/mitm16_dbbi_hex/make_config.py <dir_saida>
    cd <dir_saida> && go build -o mitm16.exe C:/.../solver/mitm16_dbbi_hex && ./mitm16.exe -control && ./mitm16.exe
"""
import json, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import oracles as O
from coincurve import PrivateKey

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PUB = ("04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
       "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")

def parse(s, pref):
    o, i = [], 0
    while i < len(s):
        if s[i] in pref:
            o.append(s[i:i + 2]); i += 2
        else:
            o.append(s[i]); i += 1
    return o

def order_positions(kind):
    idx = list(range(64))
    if kind == "fwd": return idx
    if kind == "rev": return idx[::-1]
    if kind == "byterev": return [(31 - (i // 2)) * 2 + (i % 2) for i in range(64)]
    if kind == "byterev_swap": return [(31 - (i // 2)) * 2 + (1 - (i % 2)) for i in range(64)]
    raise ValueError(kind)

def main(out_dir):
    dbbi = O.sources()["dbbi"]
    T = parse(dbbi, "bg")
    assert len(T) == 64 and len(set(T)) == 16, "tokenização b/g deveria dar 64 tokens / 16 tipos"
    toks = list(dict.fromkeys(T))
    cfg = {"tokens": toks, "orders": {}, "pub": PUB}
    for kind in ("fwd", "rev", "byterev", "byterev_swap"):
        pos = order_positions(kind)  # pos[j] = índice (0..63) do token que ocupa o dígito hex j
        W = {t: 0 for t in toks}
        for j in range(64):
            W[T[pos[j]]] = (W[T[pos[j]]] + pow(16, 63 - j, N)) % N
        cfg["orders"][kind] = {t: format(W[t], "064x") for t in toks}
    rnd = random.Random(163)
    vals = list(range(16)); rnd.shuffle(vals); pi = dict(zip(toks, vals))
    hexkey = "".join("0123456789abcdef"[pi[T[j]]] for j in range(64))
    d = int(hexkey, 16) % N
    assert d == sum(pi[t] * int(cfg["orders"]["fwd"][t], 16) for t in toks) % N
    cfg["control"] = {"pi": pi, "hex": hexkey, "pub": PrivateKey.from_int(d).public_key.format(False).hex()}
    os.makedirs(out_dir, exist_ok=True)
    json.dump(cfg, open(os.path.join(out_dir, "config.json"), "w"), indent=1)
    print("tokens:", toks)
    print("config gravado em", os.path.join(out_dir, "config.json"))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
