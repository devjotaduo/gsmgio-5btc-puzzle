# -*- coding: utf-8 -*-
"""CONTROLE POSITIVO dos detectores de INV2 (hard/scan_stream) e INV3 (_inspect).

Os relatorios INV2/INV3 AFIRMAM ter rodado controle positivo, mas o self-check
commitado de INV2 so faz hard(1)->None e o main() de INV3 nao tem controle
nenhum. Aqui eu ploto alvos que EU controlo e exijo deteccao.
"""
import hashlib, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from coincurve import PublicKey

# ---------- INV2: hard() + scan_stream() ----------
import inv2_prime_geometry as I2

PRIV = hashlib.sha256(b"skeptic-inv2").digest()
PUB = PublicKey.from_valid_secret(PRIV).format(False)

def _h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

# (1) via pub-alvo: monkeypatch TARGET para o pub que controlo
I2.TARGET = PUB
assert I2.hard(PRIV) == "target-pub", "INV2.hard() nao reconhece target-pub plantado"
print("[inv2] hard() -> target-pub DETECTADO")

# (2) via mirror: monkeypatch MIRROR
I2.TARGET = b"\x00" * 65  # neutraliza target
I2.MIRROR = PUB
assert I2.hard(PRIV) == "mirror-pub", "INV2.hard() nao reconhece mirror-pub"
print("[inv2] hard() -> mirror-pub DETECTADO")

# (3) via prize h160 (comprimido e nao-comprimido)
I2.MIRROR = b"\x11" * 65
I2.TARGET_H160 = _h160(PUB)
assert I2.hard(PRIV) == "prize-unc", "INV2.hard() nao reconhece prize-unc (h160)"
print("[inv2] hard() -> prize-unc (h160) DETECTADO")
I2.TARGET_H160 = _h160(PublicKey.from_valid_secret(PRIV).format(True))
assert I2.hard(PRIV) == "prize-comp", "INV2.hard() nao reconhece prize-comp (h160)"
print("[inv2] hard() -> prize-comp (h160) DETECTADO")

# (4) scan_stream acha a priv plantada em offset NAO-alinhado (12) via hard()
I2.TARGET = PUB; I2.MIRROR = b"\x22" * 65; I2.TARGET_H160 = b"\x33" * 20
hits = []
I2.scan_stream(b"AB" * 6 + PRIV + b"CD" * 40, "inv2ctrl", hits)  # offset 12
assert any(h[0] == "target-pub" and "@12" in h[1] for h in hits), f"scan_stream falhou: {hits}"
print("[inv2] scan_stream() acha priv plantada @offset12 -> DETECTADO")

# NEGATIVO: priv errada, 0 hits
hits = []
I2.scan_stream(b"AB" * 6 + hashlib.sha256(b"x").digest() + b"CD" * 40, "neg", hits)
assert not any(h[0] in ("target-pub", "mirror-pub") for h in hits), "FALSO POSITIVO inv2"
print("[inv2] priv-errada -> 0 hits")

# ---------- INV3: _inspect() (SALTED / STRUCTURED / PRIVKEY) ----------
import inv3_second_layer as I3
import strong_oracle_35 as SO

# SALTED: plaintext contendo Salted__
hits = []
I3._inspect(b"junk...Salted__" + b"\x01" * 40, "inv3ctrl_salted", hits)
assert any(h["kind"] == "SALTED" for h in hits), f"INV3 SALTED falhou: {hits}"
print("[inv3] _inspect -> SALTED DETECTADO")

# STRUCTURED: corpo imprimivel + PKCS7 valido (bloco de 16)
body = b"HELLO WORLD THIS IS PRINTABLE TEXT"  # 34 bytes
padlen = 16 - (len(body) % 16)
pt = body + bytes([padlen]) * padlen
hits = []
I3._inspect(pt, "inv3ctrl_struct", hits)
assert any(h["kind"] == "STRUCTURED" for h in hits), f"INV3 STRUCTURED falhou: {hits}"
print("[inv3] _inspect -> STRUCTURED DETECTADO")

# PRIVKEY: planto priv-alvo via monkeypatch de SO.PUBS + priv em offset nao-alinhado
PRIV3 = hashlib.sha256(b"skeptic-inv3").digest()
SO.PUBS = {PublicKey.from_valid_secret(PRIV3).format(False)}
hits = []
I3._inspect(b"ZZZ" + PRIV3 + b"WWWW", "inv3ctrl_priv", hits)
assert any(h["kind"] == "PRIVKEY" for h in hits), f"INV3 PRIVKEY falhou: {hits}"
print("[inv3] _inspect -> PRIVKEY (offset nao-alinhado) DETECTADO")

# NEGATIVO INV3: lixo aleatorio de alta entropia, 0 hits
hits = []
I3._inspect(os.urandom(1312), "inv3ctrl_neg", hits)
# pode ter PKCS7 espurio raramente; exige que NAO haja PRIVKEY/SALTED
assert not any(h["kind"] in ("PRIVKEY", "SALTED") for h in hits), f"FALSO POSITIVO inv3: {hits}"
print("[inv3] lixo aleatorio -> 0 PRIVKEY/SALTED")

print("\nCONTROLES INV2/INV3 OK: ambos os motores recuperam alvo plantado.")
