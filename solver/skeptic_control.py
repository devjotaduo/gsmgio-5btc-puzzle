# -*- coding: utf-8 -*-
"""CONTROLE POSITIVO do motor de deteccao (ceticismo).

O self-check de strong_oracle_35 NUNCA prova que scan() dispara num alvo real
(nao tinha priv cujo pub == TARGET). Aqui eu ploto um alvo que EU controlo:
troco PUBS por {pub(priv_conhecida)} e confirmo que scan() acha a priv em
offset NAO-alinhado, em WIF, e em hex-ASCII. Se qualquer via falhar, o motor
tem ponto-cego e os negativos dos 3 relatorios estao contaminados.
"""
import hashlib, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import strong_oracle_35 as S
import final_chain as F
from coincurve import PublicKey
from Crypto.Cipher import AES

# priv conhecida -> pub. Vira o "alvo plantado".
PRIV = hashlib.sha256(b"skeptic-control-seed").digest()
PUB = PublicKey.from_valid_secret(PRIV).format(False)
S.PUBS = {PUB}  # monkeypatch: agora o motor procura ESTE pub

def wif_unc(p):
    import base58
    payload = b"\x80" + p
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()

def run():
    # (a) priv crua em offset NAO-multiplo-de-16 (offset 7)
    out = []
    S.scan(b"Z" * 7 + PRIV + b"W" * 40, "ctrl_raw", out)
    assert any(h[0] == "PRIVKEY" for h in out), f"FALHOU raw@7: {out}"
    print("[ctrl] raw priv @offset7 -> DETECTADO", [h[1] for h in out if h[0]=="PRIVKEY"])

    # (d) hex-ASCII 64 chars
    out = []
    S.scan(b"prefix " + PRIV.hex().encode() + b" suffix", "ctrl_hex", out)
    assert any(h[0] == "PRIVKEY" for h in out), f"FALHOU hexascii: {out}"
    print("[ctrl] hex-ascii priv -> DETECTADO")

    # (b) WIF base58
    out = []
    S.scan(b"...." + wif_unc(PRIV).encode() + b"....", "ctrl_wif", out)
    assert any(h[0] == "PRIVKEY" for h in out), f"FALHOU wif: {out}"
    print("[ctrl] WIF priv -> DETECTADO")

    # controle NEGATIVO: priv aleatoria diferente NAO pode disparar
    out = []
    S.scan(b"Z" * 7 + hashlib.sha256(b"other").digest() + b"W" * 40, "ctrl_neg", out)
    assert not any(h[0] == "PRIVKEY" for h in out), f"FALSO POSITIVO: {out}"
    print("[ctrl] priv-errada -> 0 hits (sem falso-positivo)")

    # (detect completo) planta a priv DENTRO do CBC: escolho key/iv tal que o
    # plaintext do bloco contenha PRIV. Uso ECB inverso: ct = AES_enc(key, PRIV-bloco).
    # Mais simples: verifico que detect() com key==PRIV pega keyself.
    S_pub_saved = S.PUBS
    R = F.reproduce()
    hits = S.detect(PRIV, "ctrl_keyself", R)
    assert any(h[0] == "PRIVKEY" and "keyself" in h[1] for h in hits), f"FALHOU keyself: {hits}"
    print("[ctrl] detect(key==priv) -> keyself DETECTADO")

    # planta PRIV no plaintext CBC de verdade: construo body cujo CBC-dec com key
    # zero e iv zero contenha PRIV no offset 7 (nao alinhado). Uso AES_enc.
    key0 = b"\x00" * 32
    plain = b"Z" * 7 + PRIV + b"W" * (1120 - 7 - 32)
    assert len(plain) == 1120
    ct = AES.new(key0, AES.MODE_CBC, b"\x00" * 16).encrypt(plain)
    R2 = dict(R); R2["blocks"] = ct
    hits = S.detect(key0, "ctrl_cbc", R2)
    assert any(h[0] == "PRIVKEY" for h in hits), f"FALHOU cbc-plant: {hits}"
    print("[ctrl] detect() acha priv plantada no CBC (iv zero, offset 7) -> DETECTADO")

    print("\nCONTROLE POSITIVO OK: o motor recupera alvo plantado por TODAS as vias.")

if __name__ == "__main__":
    run()
