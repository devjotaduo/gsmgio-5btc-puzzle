# -*- coding: utf-8 -*-
"""
Oraculos DUROS e fontes do endgame GSMG. Este e o NUCLEO CONFIAVEL:
o modelo local (llama) nunca "declara" solucao — so uma funcao daqui pode,
e todas retornam evidencia verificavel (endereco batido, checksum, padding).

Fontes carregadas do README.md (verbatim). Alvos on-chain fixos.
"""
import os, re, base64, hashlib, functools

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")

PRIZE_ADDR = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
# h160 (uncompressed) do alvo citado em PR #68/#88
TARGET_H160 = "a9553269572a317e39f0f518cb87c1a0ee1dbae4"

# ---------- fontes ----------
@functools.lru_cache(maxsize=1)
def _readme():
    return open(README, encoding="utf-8").read()

@functools.lru_cache(maxsize=1)
def sources():
    """Retorna dict com as strings-fonte do SalPhaseIon, extraidas do README."""
    txt = _readme()
    line = [l for l in txt.splitlines() if l.startswith("> d b b i")][0]
    s = line[2:].replace(" ", "").replace("*", "")
    dbbi, faed = s[0:91], s[195:765]
    assert set(dbbi) <= set("abcdefghi") and len(dbbi) == 91
    assert faed.startswith("faed") and len(faed) == 570 and set(faed) <= set("abcdefghi")
    return {
        "dbbi": dbbi,
        "faed": faed,
        "faed_no_prefix": faed[4:],
    }

# blobs AES (base64). SMALL = blob pequeno do SalPhaseIon (verbatim, 2 linhas).
_SMALL_B64 = ("U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z"
              "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ")

@functools.lru_cache(maxsize=1)
def blobs():
    """Retorna {'SMALL': (salt, ct), 'COSMIC': (salt, ct)} em bytes."""
    def parse(b64):
        raw = base64.b64decode(b64)
        assert raw[:8] == b"Salted__", "blob nao comeca com Salted__"
        return raw[8:16], raw[16:]
    txt = _readme()
    m = re.search(r"\*\*Cosmic Duality:\*\*\n\n```text\n(.*?)```", txt, re.S)
    cosmic_b64 = m.group(1).replace("\n", "").strip()
    return {"SMALL": parse(_SMALL_B64), "COSMIC": parse(cosmic_b64)}

# ---------- EVP_BytesToKey + AES ----------
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

def _evp(pw: bytes, salt: bytes, hmod, klen=32, ivlen=16):
    d = b""; prev = b""
    while len(d) < klen + ivlen:
        prev = hmod.new(prev + pw + salt).digest()
        d += prev
    return d[:klen], d[klen:klen + ivlen]

def aes_open(pw_str, which=("SMALL", "COSMIC"), min_ascii=0.90):
    """
    Tenta abrir os blobs usando pw_str como senha (formato openssl salted).
    Retorna lista de HITS onde o padding PKCS7 e valido E o corpo e >=min_ascii
    imprimivel. HIT real = pipeline abriu. (padding valido sozinho ~1/256, por
    isso exigimos ascii alto — mesmo criterio dos ataques verificados.)
    """
    hits = []
    B = blobs()
    pw = pw_str.encode() if isinstance(pw_str, str) else pw_str
    for name in which:
        salt, ct = B[name]
        if len(ct) % 16 != 0:
            continue
        for hmod in (MD5, SHA256):
            k, iv = _evp(pw, salt, hmod)
            p = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
            pad = p[-1]
            if 1 <= pad <= 16 and p.endswith(bytes([pad]) * pad):
                body = p[:-pad]
                if not body:
                    continue
                asc = sum(32 <= b < 127 for b in body) / len(body)
                if asc >= min_ascii:
                    hits.append({"blob": name, "kdf": hmod.__name__,
                                 "ascii": round(asc, 3), "plain": body[:80].decode("latin-1")})
    return hits

# ---------- endereco BTC ----------
import ecdsa, base58
from ecdsa import SECP256k1

def _h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def _p2pkh(h):
    payload = b"\x00" + h
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()

def priv_to_addresses(priv32: bytes):
    """(addr_uncompressed, addr_compressed, h160_unc_hex, h160_comp_hex)."""
    sk = ecdsa.SigningKey.from_string(priv32, curve=SECP256k1)
    px = sk.get_verifying_key().to_string()
    x, y = px[:32], px[32:]
    unc = b"\x04" + px
    comp = (b"\x02" if y[-1] % 2 == 0 else b"\x03") + x
    return (_p2pkh(_h160(unc)), _p2pkh(_h160(comp)),
            _h160(unc).hex(), _h160(comp).hex())

def check_privkey(priv32: bytes):
    """HIT se o priv gera o endereco-premio ou o h160-alvo. Retorna dict|None."""
    if len(priv32) != 32:
        return None
    n = int.from_bytes(priv32, "big")
    if n == 0 or n >= SECP256k1.order:
        return None
    au, ac, hu, hc = priv_to_addresses(priv32)
    if PRIZE_ADDR in (au, ac) or TARGET_H160 in (hu, hc):
        return {"priv": priv32.hex(), "addr_unc": au, "addr_comp": ac}
    return None

# ---------- BIP39 -> endereco ----------
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
_MNEMO = Mnemonic("english")
WORDLIST = _MNEMO.wordlist

def check_mnemonic(words):
    """
    words: lista de palavras BIP39. Exige checksum valido E diversidade real
    (>=60% distintas) para descartar coincidencias degeneradas. Se passar,
    deriva os primeiros enderecos BIP44 legacy e compara ao premio.
    Retorna dict com {'valid':bool,'match':bool,...}.
    """
    n = len(words)
    if n not in (12, 15, 18, 21, 24):
        return None
    if not all(w in WORDLIST for w in words):
        return None
    mnem = " ".join(words)
    if not _MNEMO.check(mnem):
        return {"valid": False, "match": False, "mnemonic": mnem}
    if len(set(words)) / n < 0.60:
        return {"valid": True, "degenerate": True, "match": False, "mnemonic": mnem}
    seed = Bip39SeedGenerator(mnem).Generate()
    matched = None
    acct = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    for a in range(2):
        for chg in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            ck = acct.Purpose().Coin().Account(a).Change(chg)
            for i in range(5):
                addr = ck.AddressIndex(i).PublicKey().ToAddress()
                if addr == PRIZE_ADDR:
                    matched = f"m/44'/0'/{a}'/{int(chg)}/{i}"
    return {"valid": True, "degenerate": False,
            "match": matched is not None, "path": matched, "mnemonic": mnem}


if __name__ == "__main__":
    # auto-verificacao rapida das fontes/oraculos
    src = sources()
    print("[sources] dbbi", len(src["dbbi"]), "faed", len(src["faed"]))
    B = blobs()
    print("[blobs] SMALL ct", len(B["SMALL"][1]), "COSMIC ct", len(B["COSMIC"][1]))
    print("[aes] senha lixo ->", aes_open("definitely_wrong_password_xyz"))
    print("[priv] sha256('test') ->", check_privkey(hashlib.sha256(b"test").digest()))
    print("[oraculos ok]")
