# -*- coding: utf-8 -*-
"""Ataque 'Le Miroir de la Vie et de la Mort' (livro Cosmic Duality, p.39 do livro
= p.43 do PDF; hint CONFIRMADO pelo criador: '@barrystyle provided a very specific
hint already. (Cosmic Duality Book Page - Life and Death)', 2023-01-08).
O espelho = reversao/atbash. Fontes do verso:
  - _work/miroir_verse.txt  -> transcricao VERBATIM do usuario (se existir)
  - reconstrucao parcial nossa + tradução inglesa impressa na p.38 do livro
Testa: verso como senha (EVP SMALL/COSMIC, sha256->privkey, AES nos 35 blocos),
cifra-de-livro com indices primos no verso, e mecanicas de espelho no faed/dbbi.
"""
from __future__ import annotations
import hashlib, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
from search import bifid_decrypt
from scorer import Scorer

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"

TITLE_FR = "LE MIROIR DE LA VIE ET DE LA MORT"
TITLE_EN = "THE MIRROR OF LIFE AND DEATH"
CAPTION_EN = ("To love beauty is unwise, for time destroys it. "
              "In this world of contrasts, everything changes, "
              "and the moment we start to live, we start to die.")
# reconstrucao parcial nossa do frances (OCR ruidoso da p.43)
RECON_FR = """LE MIROIR DE LA VIE ET DE LA MORT
IL N'EST PAS SAGE D'AIMER LA BEAUTE D'UN VISAGE
CAR LE TEMPS L'EFFACE POUR LA FAIRE PASSER
TOUT CE MONDE ET NOTRE EST A PEU PRES ETRE
ET A MESURE QUE NOUS COMMENCONS A VIVRE NOUS COMMENCONS A MOURIR"""

VERSE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "_work", "miroir_verse.txt")


def matches_pubkey(s: bytes) -> bool:
    if len(s) != 32 or not any(s):
        return False
    try:
        return PublicKey.from_valid_secret(s).format(compressed=False) == TARGET_PUBKEY
    except ValueError:
        return False


def pr(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data)


def valid_pt(d: bytes) -> bool:
    if not d or len(d) % 16:
        return False
    p = d[-1]
    if not 1 <= p <= 16 or not d.endswith(bytes([p]) * p):
        return False
    return pr(d[:-p]) >= 0.80


def evp_kdf(pw: bytes, salt: bytes):
    d = d_i = b""
    while len(d) < 48:
        d_i = hashlib.md5(d_i + pw + salt).digest()
        d += d_i
    return d[:32], d[32:48]


def evp_open(salt: bytes, ct: bytes, pw: bytes):
    key, iv = evp_kdf(pw, salt)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if not pt or len(pt) % 16:
        return None
    p = pt[-1]
    if not 1 <= p <= 16 or not pt.endswith(bytes([p]) * p):
        return None
    return pt[:-p]


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def atbash9(s: str) -> str:
    return "".join(chr(ord("a") + (ord("i") - ord(c))) if "a" <= c <= "i" else c for c in s.lower())


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    half, bh = R["half"], R["better_half"]
    small_salt, small_ct = O.blobs()["SMALL"]
    cosmic_salt, cosmic_ct = O.blobs()["COSMIC"]
    src = O.sources()
    faed = src["faed"].upper().replace("J", "I")
    dbbi = src["dbbi"].upper().replace("J", "I")
    faed_l = src["faed"].lower()
    dbbi_l = src["dbbi"].lower()
    sc = Scorer()
    hard, soft = [], []
    tested = set()

    def add_pw(label: str, pw: bytes):
        if len(pw) < 4 or pw in tested:
            return
        tested.add(pw)
        sha = hashlib.sha256(pw).digest()
        if matches_pubkey(sha):
            hard.append({"label": f"sha256({label})", "priv": sha.hex()})
        if len(pw) == 32 and matches_pubkey(pw):
            hard.append({"label": f"raw({label})", "priv": pw.hex()})
        for ivn, iv in (("zero", b"\x00" * 16), ("hdr", header28[:16]), ("half", half[:16])):
            try:
                pt = AES.new(sha, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"{label}_aes_{ivn}", "head": pt[:60].hex()})
            for j in range(0, len(pt) - 31, 16):
                if matches_pubkey(pt[j:j + 32]):
                    hard.append({"label": f"{label}_aes_{ivn}_off{j}", "priv": pt[j:j + 32].hex()})
        for nm, salt, ct in (("SMALL", small_salt, small_ct), ("COSMIC", cosmic_salt, cosmic_ct)):
            pt = evp_open(salt, ct, pw)
            if pt and pr(pt) >= 0.85:
                soft.append({"label": f"{label}_{nm}", "ascii": round(pr(pt), 3)})
            pt = evp_open(salt, ct, sha.hex().encode())
            if pt and pr(pt) >= 0.85:
                soft.append({"label": f"{label}_{nm}_sha", "ascii": round(pr(pt), 3)})

    # ============ verso: verbatim do usuario (se existir) + variantes ============
    verses = {}
    if os.path.exists(VERSE_FILE):
        with open(VERSE_FILE, encoding="utf-8") as f:
            verses["verbatim"] = f.read().strip()
        print(f"[verso] usando verbatim de {VERSE_FILE} ({len(verses['verbatim'])} chars)")
    else:
        print(f"[verso] {VERSE_FILE} ausente — usando reconstrucao + traducao da p.38")
    verses["recon_fr"] = RECON_FR
    verses["caption_en"] = CAPTION_EN

    for vname, vtext in verses.items():
        raw = vtext.encode("utf-8")
        flat = re.sub(r"\s+", " ", vtext).strip()
        upper_nospace = re.sub(r"[^A-Z]", "", flat.upper())
        lower_nospace = upper_nospace.lower()
        add_pw(f"{vname}_raw", raw)
        add_pw(f"{vname}_upper", flat.upper().encode())
        add_pw(f"{vname}_nospace", upper_nospace.encode())
        add_pw(f"{vname}_nospace_lower", lower_nospace.encode())

        # cifra-de-livro: indices primos no verso normalizado (so letras)
        letters = upper_nospace
        words = flat.upper().split()
        for zero_based in (False, True):
            off = 0 if zero_based else 1
            prime_letters = "".join(letters[i - 1 + off] for i in range(1, len(letters) + 1)
                                    if is_prime(i - off))
            if prime_letters:
                add_pw(f"{vname}_primeL{int(zero_based)}", prime_letters.encode())
                add_pw(f"{vname}_primeL{int(zero_based)}_lower", prime_letters.lower().encode())
        # primeiros chars das palavras em posicoes primas
        for zero_based in (False, True):
            off = 0 if zero_based else 1
            prime_word_initials = "".join(w[0] for i, w in enumerate(words, start=off)
                                          if is_prime(i)) if words else ""
            if prime_word_initials:
                add_pw(f"{vname}_primeW{int(zero_based)}", prime_word_initials.encode())
        # palavras em posicoes primas
        for zero_based in (False, True):
            off = 0 if zero_based else 1
            prime_words = "".join(w for i, w in enumerate(words, start=off) if is_prime(i))
            if prime_words:
                add_pw(f"{vname}_primeWORDS{int(zero_based)}", prime_words.encode())

    # ============ titulos e legendas ============
    add_pw("title_fr", TITLE_FR.encode())
    add_pw("title_fr_nospace", re.sub(r"[^A-Z]", "", TITLE_FR).encode())
    add_pw("title_fr_lower", TITLE_FR.lower().encode())
    add_pw("title_en", TITLE_EN.encode())
    add_pw("title_en_nospace", re.sub(r"[^A-Z]", "", TITLE_EN).encode())
    add_pw("title_mixed", b"Le Miroir de la Vie et de la Mort")
    add_pw("lifeanddeath", b"LIFE AND DEATH")
    add_pw("lifeanddeath_ns", b"LIFEANDDEATH")
    add_pw("vieetlamort", b"LAVIEETLAMORT")
    add_pw("lavieetlamort", b"la vie et la mort")
    add_pw("ultimate_duality", b"THE ULTIMATE DUALITY")
    add_pw("ultimate_duality_ns", b"THEULTIMATEDUALITY")
    add_pw("memento_mori", b"MEMENTO MORI")

    # ============ mecanica do espelho (atbash/reversao) no faed/dbbi ============
    base = bifid_decrypt(faed, CANON, 570)
    print(f"[espelho] baseline canon: {sc(base):.3f} | {base[:20]}")
    variants = {
        "faed_atbash": bifid_decrypt(atbash9(faed_l).upper(), CANON, 570),
        "faed_rev": bifid_decrypt(faed[::-1], CANON, 570),
        "faed_atbash_rev": bifid_decrypt(atbash9(faed_l)[::-1].upper(), CANON, 570),
        "dbbi_atbash_fa": bifid_decrypt(atbash9(dbbi_l).upper(), CANON, 570),
    }
    # quadrado derivado do dbbi espelhado (atbash) -> keyword de 1a ocorrencia
    at_db = atbash9(dbbi_l).upper()
    seen = "".join(dict.fromkeys(at_db))
    filler = "".join(c for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ" if c not in seen)
    sq_mirror = (seen + filler)[:25]
    if len(set(sq_mirror)) == 25:
        variants["sq_from_atbash_dbbi"] = bifid_decrypt(faed, sq_mirror, 570)
        print(f"[espelho] quadrado do dbbi-atbash: {sq_mirror}")
    for vn, out in variants.items():
        s = sc(out)
        print(f"[espelho] {vn:24s} score={s:8.3f}  {out[:36]}")
        if "BTCSEED" in out or s > -4.6:
            soft.append({"label": f"espelho_{vn}", "score": round(s, 3), "head": out[:48]})
        add_pw(f"espelho_{vn}", out.encode("latin-1", "ignore"))
    # atbash no OUTPUT do bifid canonico (espelho pos-decodificacao)
    at_out = "".join(chr(ord("Z") - (ord(c) - ord("A"))) if "A" <= c <= "Z" else c for c in base)
    s = sc(at_out)
    print(f"[espelho] atbash(bifid)        score={s:8.3f}  {at_out[:36]}")
    add_pw("espelho_atbash_out", at_out.encode("latin-1", "ignore"))
    add_pw("espelho_atbash_rest", at_out[7:].encode("latin-1", "ignore"))

    # ============ relatorio ============
    print()
    print("=" * 60)
    print("ATAQUE MIROIR (p.39) - oraculo duro")
    print("=" * 60)
    print(f"senhas testadas: {len(tested)} | HARD: {len(hard)} | SOFT: {len(soft)}")
    if hard:
        print("\n!!! SOLVE !!!")
        for h in hard:
            print(f"  {h}")
    if soft:
        print("\n--- soft hits ---")
        for s in soft[:25]:
            print(f"  {s}")
    if not hard and not soft:
        print("NEGATIVO — verso/espelho nas leituras naturais nao fecham o oraculo.")


if __name__ == "__main__":
    main()
