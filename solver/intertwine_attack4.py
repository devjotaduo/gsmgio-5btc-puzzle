# -*- coding: utf-8 -*-
"""INTERTWINE v4 — a gramatica XOR aplicada AS FRASES da pagina.
Cosmic pw provado = XOR(sha256(enter), sha256(lastwords), sha256(thispassword),
sha256(yourlastcommand), sha256(secondanswer)) — tokens da pagina.
Hipotese nova: 'our first hint is your last command' tem EXATAMENTE 7 palavras
(= 'seven intertwined passwords'!) -> XOR das 7 palavras = senha do SMALL
(a de 69 chars e suspeita de falso-positivo; frontier da retratacao #104 =
plaintext semantico >=85% ASCII). Testa todas as frases-chave da pagina.
"""
from __future__ import annotations
import hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

from coincurve import PublicKey
from Crypto.Cipher import AES

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
MIRROR_PUBKEY = b"\x04" + TARGET_PUBKEY[1:33] + (
    (P - int.from_bytes(TARGET_PUBKEY[33:65], "big")) % P).to_bytes(32, "big")


def pub(s):
    return PublicKey.from_valid_secret(s).format(compressed=False)


def pr(d):
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in d) / len(d) if d else 0.0


def evp_kdf(pw, salt):
    d = d_i = b""
    while len(d) < 48:
        d_i = hashlib.md5(d_i + pw + salt).digest()
        d += d_i
    return d[:32], d[32:48]


def evp_open(salt, ct, pw):
    key, iv = evp_kdf(pw, salt)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if not pt or len(pt) % 16:
        return None
    p = pt[-1]
    if not 1 <= p <= 16 or not pt.endswith(bytes([p]) * p):
        return None
    return pt[:-p]


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).digest()


def xorr(parts):
    x = bytes(32)
    for p in parts:
        x = bytes(a ^ b for a, b in zip(x, p))
    return x


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    small_salt, small_ct = O.blobs()["SMALL"]
    cosmic_salt, cosmic_ct = O.blobs()["COSMIC"]
    hits, n = [], 0

    def report(label, info):
        hits.append(f"{label}: {info}")
        print(hits[-1])

    def full_battery(label, key):
        nonlocal n
        if len(key) != 32:
            return
        n += 1
        for nm, s in (("T", TARGET_PUBKEY), ("M", MIRROR_PUBKEY)):
            try:
                if pub(key) == s:
                    report(f"!!! PRIVKEY[{nm}] {label}", key.hex())
            except ValueError:
                pass
        for ivn, iv in (("zero", b"\x00" * 16), ("hdr", header28[:16])):
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            if pt[:8] == b"Salted__" or (pt and pt[-1] <= 16 and pt.endswith(bytes([pt[-1]]) * pt[-1]) and pr(pt[:-pt[-1]]) >= .8):
                report(f"SOFT {label}_aes_{ivn}", pt[:60].hex())
            for j in range(0, len(pt) - 31, 16):
                c = pt[j:j + 32]
                for nm, s in (("T", TARGET_PUBKEY), ("M", MIRROR_PUBKEY)):
                    try:
                        if pub(c) == s:
                            report(f"!!! PRIVKEY[{nm}] {label}_aes_{ivn}_off{j}", c.hex())
                    except ValueError:
                        pass

    def evp_test(label, pw: bytes):
        nonlocal n
        n += 1
        for nm, salt, ct in (("SMALL", small_salt, small_ct), ("COSMIC", cosmic_salt, cosmic_ct)):
            pt = evp_open(salt, ct, pw)
            if pt is not None:
                ratio = pr(pt)
                if ratio >= 0.85:
                    report(f"!!! {label}_{nm} SEMANTICO ascii={ratio:.2f}", pt[:60].hex())
                else:
                    print(f"   [pad-ok] {label}_{nm} ascii={ratio:.2f} head={pt[:24].hex()}")
            pt = evp_open(salt, ct, sha(pw))
            if pt is not None and pr(pt) >= 0.85:
                report(f"!!! {label}_{nm}_sha SEMANTICO", pt[:60].hex())

    # ================= as 7 palavras da frase-chave =================
    sentences = {
        "firsthint7": ["our", "first", "hint", "is", "your", "last", "command"],
        "firsthint_ns": ["ourfirsthint", "isyourlastcommand"],
        "firsthint_2": ["ourfirsthint", "yourlastcommand"],
        "shabef3": ["shabef", "ans", "too"],
        "shabef_ans": ["shabef", "anstoo"],
        "ans2": ["ans", "too"],
        "page4": ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword"],
        "page4b": ["dbbi", "matrixsumlist", "faed", "enter"],
        "recipe5": ["enter", "lastwordsbeforearchichoice", "thispassword",
                    "yourlastcommand", "secondanswer"],
        "recipe5+7w": ["enter", "lastwordsbeforearchichoice", "thispassword",
                       "yourlastcommand", "secondanswer",
                       "our", "first", "hint", "is", "your", "last", "command"],
        "s322": ["incaseyoumanagetocrackthis", "theprivatekeysbelongtohalfandbetterhalf",
                 "theyalsoneedfundstolive"],
        "s322_words": ["in", "case", "you", "manage", "to", "crack", "this",
                       "the", "private", "keys", "belong", "to", "half", "and",
                       "better", "half", "they", "also", "need", "funds", "to", "live"],
        "halves": ["half", "betterhalf"],
        "halves2": ["half", "better half"],
    }
    for name, parts in sentences.items():
        key = xorr([sha(p) for p in parts])
        print(f"[{name}] XOR = {key.hex()[:32]}…")
        evp_test(name, b"".join(p.encode() for p in parts))  # a frase concat (controle)
        evp_test(name + "_xorkey", key)  # o XOR como passphrase raw
        evp_test(name + "_xorhex", key.hex().encode())  # o XOR em hex
        full_battery(name, key)

    # frase completa como EVP em mais formas (controles)
    evp_test("firsthint_sent", b"our first hint is your last command")
    evp_test("firsthint_sent_ns", b"ourfirsthintisyourlastcommand")
    evp_test("FIRSTHINT", b"OUR FIRST HINT IS YOUR LAST COMMAND")

    print()
    print("=" * 62)
    print(f"TOTAL: {n} testes | HITS: {len(hits)}")
    print("=" * 62)
    if not hits:
        print("NEGATIVO — gramatica XOR nas frases da pagina nao fecha SMALL/COSMIC/35.")


if __name__ == "__main__":
    main()
