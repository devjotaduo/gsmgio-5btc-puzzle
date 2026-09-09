# -*- coding: utf-8 -*-
"""
ABORDAGEM NOVA: a mecânica declarada pelo criador ("seven intertwined passwords")
já foi PROVADA (ENDGAME 2026-08-30) como XOR de sha256 dos tokens, resultando em
32 bytes = a795de11…52e50735. Todos os sweeps usaram esse valor como SENHA (via EVP).
Aqui ele é a CHAVE AES-256 crua (-K) — 32 bytes é exatamente uma chave-256 — testada
com uma matriz de IVs contra os 3 blobs reais, e como material de chave privada.
"""
import sys, os, hashlib, base64, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O
from Crypto.Cipher import AES

def sha(s): return hashlib.sha256(s.encode()).digest()
def xor(*bs):
    r=bytearray(32)
    for b in bs:
        for i in range(32): r[i]^=b[i]
    return bytes(r)

# passphrase provada (5 termos após cancelamento do matrixsumlist duplicado)
K5 = xor(sha("enter"), sha("lastwordsbeforearchichoice"), sha("thispassword"),
         sha("yourlastcommand"), sha("secondanswer"))
# variante 7-partes explícita (matrixsumlist entra 2x e cancela -> mesmo valor)
K7 = xor(sha("matrixsumlist"), sha("enter"), sha("lastwordsbeforearchichoice"),
         sha("thispassword"), sha("matrixsumlist"), sha("yourlastcommand"), sha("secondanswer"))
print("K5 =", K5.hex()); print("K7 =", K7.hex(), "(igual a K5?" , K5==K7, ")")

# blobs reais: SMALL, COSMIC (via oracles) + TAIL32 (fim da 3.2)
B = dict(O.blobs())
raw = base64.b64decode("U2FsdGVkX1+0Wl49gnWTyiimluu7V3+vl7st0gUt9sWDzNLxDmlPMsDSiuW2a46z"
                       "gKlIi8aaqY5gpJPPEzW1n9n3/26qs4zstWtPKF8Zs/BTNN4IiEh4qu18mdC0NAv4")
B["TAIL32"]=(raw[8:16], raw[16:])

def try_dec(ct, key, iv, tag):
    if len(ct)%16: return None
    if iv is None:  # ECB
        p=AES.new(key,AES.MODE_ECB).decrypt(ct)
    else:
        p=AES.new(key,AES.MODE_CBC,iv).decrypt(ct)
    pad=p[-1]
    body = p[:-pad] if 1<=pad<=16 and p.endswith(bytes([pad])*pad) else None
    asc=sum(32<=c<127 for c in p)/len(p)
    if body is not None:
        basc=sum(32<=c<127 for c in body)/max(1,len(body))
        return (tag, "pad=%d"%pad, "ascii=%.2f"%basc, body[:48])
    if asc>=0.85:  # sem padding válido mas legível (modo -nopad)
        return (tag, "NOPAD", "ascii=%.2f"%asc, p[:48])
    return None

hits=[]
for key,kn in ((K5,"K5"),(K7,"K7")):
    for name,(salt,ct) in B.items():
        ivs = {
            "zero": b"\x00"*16,
            "salt+salt": salt+salt,
            "salt+zero": salt+b"\x00"*8,
            "ct[:16]": ct[:16],
            "sha(key)[:16]": hashlib.sha256(key).digest()[:16],
            "key[:16]": key[:16],
            "key[16:]": key[16:],
            "ECB": None,
        }
        for ivn,iv in ivs.items():
            r=try_dec(ct,key,iv,f"{kn}/{name}/{ivn}")
            if r: hits.append(r)
print("\nAES chave-crua: hits =", len(hits))
for h in hits: print("  ",h)

# a passphrase como PRIVKEY direta e sha256(passphrase)
for key,kn in ((K5,"K5"),(K7,"K7")):
    for cand,how in ((key,"raw32"),(hashlib.sha256(key).digest(),"sha256(key)"),
                     (bytes.fromhex(key.hex()),"hex-bytes")):
        r=O.check_privkey(cand)
        if r: print("PRIVKEY HIT",kn,how,r)
    # sha256 do hex-string da passphrase (caso usada como texto)
    r=O.check_privkey(hashlib.sha256(key.hex().encode()).digest())
    if r: print("PRIVKEY HIT (sha256 hexstr)",kn,r)
print("privkey checks feitos.")

# controle: a chave-crua abre ALGO? teste sanity num blob cifrado por nós com K5
import os as _os
saltx=_os.urandom(8); ivx=_os.urandom(16)
msg=b"the quick brown fox jumps over the lazy dog....."  # 48 bytes
padlen=16-(len(msg)%16); ct_ctrl=AES.new(K5,AES.MODE_CBC,ivx).encrypt(msg+bytes([padlen])*padlen)
chk=try_dec(ct_ctrl,K5,ivx,"CTRL")
print("controle (deve abrir):", chk)
