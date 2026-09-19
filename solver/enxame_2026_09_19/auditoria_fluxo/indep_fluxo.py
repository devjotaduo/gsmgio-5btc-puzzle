# -*- coding: utf-8 -*-
"""
F2 auditoria_fluxo — implementacao INDEPENDENTE do pipeline de modos de fluxo.

Nada aqui importa gsmg_common (o kit) no caminho critico. Tudo que o pipeline usa
(EVP_BytesToKey, CBC/CFB128/CFB8/CFB1/OFB/CTR, secp256k1, hash160) esta escrito
do zero sobre primitivas minimas:
  - AES-ECB de bloco unico (pycryptodome) -> unica primitiva de terceiros do caminho
    de cifra; os MODOS sao meus.
  - secp256k1 em Python puro (multiplicacao escalar por janela) -> usado para
    validar a coincurve numa amostra; a varredura em escala usa coincurve por
    velocidade, depois de a igualdade ser provada na amostra.
  - hashlib para sha256/ripemd160.

Controles:
  * `openssl enc` CLI como segunda implementacao para cada modo x KDF.
  * fase 2 abre com sha256hex("causality") sob EVP-SHA256 e NAO sob EVP-MD5.
  * chave plantada no INTERIOR binario (offset nao alinhado) de um plaintext de
    modo de fluxo, que o scanner tem de recuperar.
"""
import base64, hashlib, os, subprocess, sys, tempfile, time

from Crypto.Cipher import AES as _AES  # usada SO como AES-ECB de bloco unico

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# ------------------------------------------------------------------ primitiva de bloco
def _ecb(key32):
    c = _AES.new(key32, _AES.MODE_ECB)
    return lambda b16: c.encrypt(b16)

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# ------------------------------------------------------------------ EVP_BytesToKey (meu)
def evp_bytes_to_key(password: bytes, salt: bytes, algo: str, klen=32, ivlen=16):
    """EVP_BytesToKey sem iteracao (openssl enc -pass ...). algo in {'sha256','md5'}."""
    out = b""
    prev = b""
    while len(out) < klen + ivlen:
        h = hashlib.new(algo)
        h.update(prev + password + salt)
        prev = h.digest()
        out += prev
    return out[:klen], out[klen:klen + ivlen]

# ------------------------------------------------------------------ modos (meus)
def dec_cbc_nopad(key, iv, ct):
    c = _AES.new(key, _AES.MODE_ECB)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct) - len(ct) % 16, 16):
        blk = ct[i:i + 16]
        out += _xor(c.decrypt(blk), prev)
        prev = blk
    return bytes(out)

def dec_ofb(key, iv, ct):
    E = _ecb(key)
    out = bytearray()
    s = iv
    for i in range(0, len(ct), 16):
        s = E(s)
        out += _xor(ct[i:i + 16], s[:len(ct) - i])
    return bytes(out)

def dec_ctr(key, iv, ct):
    """openssl aes-256-ctr: o IV inteiro (128 bits) e o contador, incremento BE."""
    E = _ecb(key)
    out = bytearray()
    n = int.from_bytes(iv, "big")
    for i in range(0, len(ct), 16):
        ks = E((n % (1 << 128)).to_bytes(16, "big"))
        out += _xor(ct[i:i + 16], ks[:len(ct) - i])
        n += 1
    return bytes(out)

def dec_cfb128(key, iv, ct):
    E = _ecb(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        ks = E(prev)
        out += _xor(blk, ks[:len(blk)])
        prev = blk if len(blk) == 16 else (blk + prev[len(blk):])
    return bytes(out)

def dec_cfb8(key, iv, ct):
    E = _ecb(key)
    sr = bytearray(iv)
    out = bytearray()
    for cb in ct:
        ks = E(bytes(sr))[0]
        out.append(cb ^ ks)
        sr = sr[1:] + bytearray([cb])
    return bytes(out)

def dec_cfb1(key, iv, ct):
    """CFB de 1 bit: registrador deslocado 1 bit por vez; bit de keystream = MSB de E(sr)."""
    E = _ecb(key)
    sr = int.from_bytes(iv, "big")
    out = bytearray()
    for cb in ct:
        pb = 0
        for k in range(7, -1, -1):
            ksb = (E(sr.to_bytes(16, "big"))[0] >> 7) & 1
            cbit = (cb >> k) & 1
            pb |= (cbit ^ ksb) << k
            sr = ((sr << 1) | cbit) & ((1 << 128) - 1)
        out.append(pb)
    return bytes(out)

STREAM_MODES = {
    "cfb": dec_cfb128,   # openssl 'cfb' == cfb128
    "cfb1": dec_cfb1,
    "cfb8": dec_cfb8,
    "ofb": dec_ofb,
    "ctr": dec_ctr,
}
OPENSSL_NAME = {"cfb": "aes-256-cfb", "cfb1": "aes-256-cfb1", "cfb8": "aes-256-cfb8",
                "ofb": "aes-256-ofb", "ctr": "aes-256-ctr"}
KDFS = ("sha256", "md5")

def decrypt(mode, kdf, password: bytes, salt: bytes, ct: bytes) -> bytes:
    k, iv = evp_bytes_to_key(password, salt, kdf)
    return STREAM_MODES[mode](k, iv, ct)

# ------------------------------------------------------------------ secp256k1 em Python puro
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _pt_add(a, b):
    if a is None: return b
    if b is None: return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        l = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        l = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (l * l - x1 - x2) % P
    return (x3, (l * (x1 - x3) - y1) % P)

def pure_pubkey(sec: bytes):
    """Pubkey (uncompressed, compressed) por double-and-add em Python puro."""
    d = int.from_bytes(sec, "big")
    if not (0 < d < N): return None
    r, q = None, (GX, GY)
    while d:
        if d & 1: r = _pt_add(r, q)
        q = _pt_add(q, q)
        d >>= 1
    x, y = r
    unc = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    comp = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return unc, comp

def h160(b: bytes) -> str:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).hexdigest()

# ------------------------------------------------------------------ scanner raw32 BE/LE
class Scanner:
    """Varre TODA janela de 32 B, em BE e em LE, contra um conjunto de h160 alvo.
    Sem filtro de padding, sem filtro semantico: varredura cega do interior binario."""

    def __init__(self, targets):
        from coincurve import PublicKey
        self._PK = PublicKey
        self.targets = set(targets)
        self.windows = 0     # janelas de 32 B percorridas (buffers)
        self.scalars = 0     # escalares testados (2 por janela: BE e LE)
        self.ec = 0          # multiplicacoes escalares efetivamente feitas

    def _check(self, sec, where, tag):
        self.scalars += 1
        try:
            pk = self._PK.from_valid_secret(sec)
        except Exception:
            return None
        self.ec += 1
        for comp in (False, True):
            if h160(pk.format(comp)) in self.targets:
                return (where, tag, sec.hex(), "comp" if comp else "unc")
        return None

    def scan(self, buf: bytes, where=""):
        hits = []
        for j in range(0, len(buf) - 31):
            self.windows += 1
            w = buf[j:j + 32]
            r = self._check(w, where, "be@%d" % j)
            if r: hits.append(r)
            r = self._check(w[::-1], where, "le@%d" % j)
            if r: hits.append(r)
        return hits

# ------------------------------------------------------------------ blobs (lidos aqui, nao do kit)
SMALL_B64 = ("U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z"
             "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ")
TAIL32_B64 = ("U2FsdGVkX1+0Wl49gnWTyiimluu7V3+vl7st0gUt9sWDzNLxDmlPMsDSiuW2a46z"
              "gKlIi8aaqY5gpJPPEzW1n9n3/26qs4zstWtPKF8Zs/BTNN4IiEh4qu18mdC0NAv4")

def _split(b64):
    raw = base64.b64decode(b64)
    assert raw[:8] == b"Salted__", "blob sem cabecalho Salted__"
    return raw[8:16], raw[16:]

def load_blobs():
    """SMALL e TAIL32 inline (verbatim do README); COSMIC extraido do README desta copia.
    Os sha256 dos ciphertexts vao no relatorio, para amarrar a cobertura aos bytes exatos."""
    import re
    txt = open(os.path.join(REPO, "README.md"), encoding="utf-8").read()
    blobs = {"SMALL": _split(SMALL_B64), "TAIL32": _split(TAIL32_B64)}
    m = re.search(r"\*\*Cosmic Duality:\*\*\n\n```text\n(.*?)```", txt, re.S)
    if m:
        blobs["COSMIC"] = _split(m.group(1).replace("\n", "").strip())
    return blobs

def blob_digest(blobs):
    return {k: {"salt": s.hex(), "ct_len": len(c), "ct_sha256": hashlib.sha256(c).hexdigest()}
            for k, (s, c) in sorted(blobs.items())}
