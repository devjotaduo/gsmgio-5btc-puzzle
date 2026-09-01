# -*- coding: utf-8 -*-
"""Checagens ceticas das AFIRMACOES concretas dos relatorios.

1. NULL-MODEL de INV1: keystreams ALEATORIOS dao o mesmo score (~-7.8) que
   half/bh sobre BIF_REST? Se sim, os resultados de INV1 sao indistinguiveis de
   ruido -> nenhum sinal fraco escondido (nao-apofenia, negativo solido).
2. half/better_half -> enderecos comprimidos (deve bater 1JG648 / 145ZQ9).
3. Tautologia da mascara Chain4: CHAIN4_MASK == cosmic[158:166] XOR "Salted__"?
   (afirmacao de INV1 de que o ramo matriz/35-blocos e fabricado).
"""
import hashlib, sys, os, statistics, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import dsl
from scorer import Scorer

ALPHA = "".join(sorted(set(dsl.bif_full()[7:])))
IDX = {c: i for i, c in enumerate(ALPHA)}
REST = dsl.bif_full()[7:]
sc = Scorer()

def apply_vig_dec(text, ks):
    ci = [IDX[c] for c in text]
    return "".join(ALPHA[(ci[i] - ks[i]) % 25] for i in range(len(ci)))

print("=== 1. NULL-MODEL INV1 (keystreams aleatorios sobre BIF_REST) ===")
raw = sc(REST)
scores = []
rng = random.Random(1)
for _ in range(500):
    ks = [rng.randrange(25) for _ in range(len(REST))]
    scores.append(sc(apply_vig_dec(REST, ks)))
mu, sd = statistics.mean(scores), statistics.pstdev(scores)
print(f"BIF_REST cru = {raw:.3f}")
print(f"null (500 keystreams aleatorios): mean={mu:.3f} sd={sd:.3f} "
      f"min={min(scores):.3f} max={max(scores):.3f}")
print(f"half/bh reportados ficaram em [-7.98,-7.72]; dentro do null? "
      f"{'SIM (ruido)' if mu-3*sd <= -7.72 <= mu+3*sd else 'FORA'}")

print("\n=== 2. half/better_half -> enderecos comprimidos ===")
import base58
def p2pkh_comp(priv32):
    import ecdsa
    from ecdsa import SECP256k1
    sk = ecdsa.SigningKey.from_string(priv32, curve=SECP256k1)
    px = sk.get_verifying_key().to_string()
    x, y = px[:32], px[32:]
    comp = (b"\x02" if y[-1] % 2 == 0 else b"\x03") + x
    h = hashlib.new("ripemd160", hashlib.sha256(comp).digest()).digest()
    payload = b"\x00" + h
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()

R = F.reproduce()
a_half = p2pkh_comp(R["half"])
a_bh = p2pkh_comp(R["better_half"])
print(f"half        -> {a_half}  (esperado 1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu) "
      f"{'OK' if a_half=='1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu' else 'DIVERGE'}")
print(f"better_half -> {a_bh}  (esperado 145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ) "
      f"{'OK' if a_bh=='145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ' else 'DIVERGE'}")

print("\n=== 3. Tautologia da mascara Chain4 ===")
cc = R["cosmic"]
seg = cc[158:166]
xored = bytes(a ^ b for a, b in zip(seg, b"Salted__"))
print(f"cosmic[158:166]        = {seg.hex()}")
print(f"XOR 'Salted__'         = {xored.hex()}")
print(f"CHAIN4_MASK (final_chain)= {F.CHAIN4_MASK.hex()}")
print(f"tautologica? {'SIM' if xored == F.CHAIN4_MASK else 'NAO'}  "
      f"(=> a mascara SO existe p/ forcar cosmic[158:166] a virar 'Salted__')")
# prova o efeito: o blob decifrado comeca com Salted__?
blob = F.xor_cycle(cc[158:-1], F.CHAIN4_MASK)
print(f"chain4_blob[:8] = {blob[:8]}  (b'Salted__'? {blob[:8]==b'Salted__'})")
