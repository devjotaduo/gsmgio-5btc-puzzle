# -*- coding: utf-8 -*-
"""Referência em CPU: tokenização do dbbi, decodificação de Lehmer e montagem
da senha hex. É a "verdade" contra a qual o kernel OpenCL é validado.

Tudo aqui é determinístico. Importa o kit G (gsmg_common) para pegar DBBI,
os blobs e o oráculo AES de referência.
"""
import sys
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G  # noqa: E402

HEXDIGITS = "0123456789abcdef"

# ordem de primeira ocorrência dos 16 tipos de token (dada e verificada)
TOKEN_ORDER = ['d', 'bb', 'i', 'bf', 'bh', 'c', 'be', 'gb',
               'h', 'a', 'gg', 'e', 'ge', 'f', 'ba', 'gi']

# sequência esperada dos 64 tokens (para asserção)
EXPECTED_SEQ = ("d bb i bf bh c c be gb i h a be be i h be gg e ge be bb ge h h e "
                "bh h f ba bf d h be f f c d bb f c c c gb f be e gg e c be d c i "
                "bf bf f gi gb e e e a be").split()


def tokenize(dbbi=None):
    """Percorre o dbbi da esquerda p/ direita. 'b' e 'g' são prefixos: formam
    token de 2 chars com o símbolo seguinte; os demais são tokens de 1 char."""
    s = dbbi if dbbi is not None else G.DBBI
    toks, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c in ("b", "g") and i + 1 < n:
            toks.append(s[i:i + 2]); i += 2
        else:
            toks.append(c); i += 1
    return toks


def token_type_index(toks=None):
    """Para cada uma das 64 posições, o índice 0..15 do tipo de token
    (na ordem de primeira ocorrência TOKEN_ORDER)."""
    toks = toks if toks is not None else tokenize()
    idx = {t: k for k, t in enumerate(TOKEN_ORDER)}
    return [idx[t] for t in toks]


_FACT = [1] * 16
for _i in range(1, 16):
    _FACT[_i] = _FACT[_i - 1] * _i
FACT16 = _FACT[15] * 16  # 16! = 20_922_789_888_000


def lehmer_decode(index, n=16):
    """Código de Lehmer (número fatorial): inteiro 0<=index<n! -> permutação de 0..n-1.
    Dígito mais significativo primeiro (fator (n-1)!)."""
    elements = list(range(n))
    perm = []
    for i in range(n - 1, -1, -1):
        f = _FACT[i]
        d = index // f
        index -= d * f
        perm.append(elements.pop(d))
    return perm


def password_for_index(index, tti=None, upper=False):
    """Monta a senha de 64 bytes ASCII hex para o índice de permutação dado."""
    tti = tti if tti is not None else token_type_index()
    perm = lehmer_decode(index)
    hexd = HEXDIGITS.upper() if upper else HEXDIGITS
    return "".join(hexd[perm[k]] for k in tti).encode()


def _selfcheck():
    toks = tokenize()
    assert len(toks) == 64, f"esperado 64 tokens, veio {len(toks)}"
    assert toks == EXPECTED_SEQ, f"sequência divergente:\n{toks}"
    # tipos distintos na ordem de 1a ocorrência
    seen = []
    for t in toks:
        if t not in seen:
            seen.append(t)
    assert seen == TOKEN_ORDER, f"ordem de tipos divergente: {seen}"
    assert len(set(toks)) == 16
    # blob SMALL
    salt, ct = G.BLOBS["SMALL"]
    assert len(salt) == 8 and len(ct) == 80
    # Lehmer: identidade e último índice
    assert lehmer_decode(0) == list(range(16))
    assert lehmer_decode(FACT16 - 1) == list(range(15, -1, -1))
    # bijeção sempre (permutação de 0..15)
    import random
    for _ in range(1000):
        idx = random.randrange(FACT16)
        perm = lehmer_decode(idx)
        assert sorted(perm) == list(range(16))
    print("refkit OK: 64 tokens, 16 tipos, Lehmer bijetivo")
    print("salt(hex) =", salt.hex(), " ct len =", len(ct))
    print("exemplo idx=0 pw =", password_for_index(0).decode())
    return True


if __name__ == "__main__":
    _selfcheck()
