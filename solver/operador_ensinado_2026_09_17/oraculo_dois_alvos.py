# -*- coding: utf-8 -*-
"""Oraculo duro ESTENDIDO: inclui a SEGUNDA metade do premio.

1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe  = 1,25635374 BTC, 126 tx, JA GASTOU (pubkey exposta)
17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa  = 3,75055856 BTC,  45 tx, NUNCA GASTOU (so o h160 e conhecido)
Soma = 5,00691230 BTC = o "5 BTC" do premio. A mensagem da fase 3.2 diz "the private keyS
belong to half and better half" (plural) e o criador dividiu o premio a cada halving.
O oraculo historico do repo (solver/oracles.py) so testa o PRIMEIRO. Este testa os dois.
"""
import hashlib, base58
from coincurve import PublicKey

ADDR_A = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
ADDR_B = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
def h160_of_addr(a):
    return base58.b58decode_check(a)[1:].hex()
H160_A, H160_B = h160_of_addr(ADDR_A), h160_of_addr(ADDR_B)
TARGETS = {H160_A: ADDR_A, H160_B: ADDR_B}

def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).hexdigest()

def priv_hit2(sec: bytes):
    """Retorna (addr, forma) se sec de um dos dois enderecos do premio; senao None."""
    if len(sec) != 32: return None
    try:
        pk = PublicKey.from_valid_secret(sec)
    except Exception:
        return None
    for form, blob in (("unc", pk.format(False)), ("comp", pk.format(True))):
        h = h160(blob)
        if h in TARGETS:
            return (TARGETS[h], form)
    return None

def scan32(buf: bytes, both_orders=True):
    """Varre toda janela de 32 B (e a ordem inversa) de buf."""
    hits = []
    n = len(buf)
    for j in range(0, max(0, n - 31)):
        w = buf[j:j+32]
        r = priv_hit2(w)
        if r: hits.append((j, "fwd", w.hex(), r))
        if both_orders:
            r = priv_hit2(w[::-1])
            if r: hits.append((j, "rev", w[::-1].hex(), r))
    return hits

if __name__ == "__main__":
    print("H160 A =", H160_A, ADDR_A)
    print("H160 B =", H160_B, ADDR_B)
    # controle positivo: chave conhecida -> seu proprio endereco (nao e do premio)
    k = hashlib.sha256(b"controle").digest()
    print("controle (nao deve casar):", priv_hit2(k))
    # controle plantado: forjo o alvo trocando TARGETS por um h160 derivado
    pk = PublicKey.from_valid_secret(k)
    TARGETS[h160(pk.format(False))] = "PLANTADO"
    assert priv_hit2(k) == ("PLANTADO", "unc"), "controle plantado falhou"
    assert scan32(b"\x00"*7 + k + b"\x00"*7)[0][0] == 7, "scan32 nao acha a janela plantada"
    del TARGETS[h160(pk.format(False))]
    print("controles OK: detector acha chave plantada em offset 7 e nao dispara em ruido")
