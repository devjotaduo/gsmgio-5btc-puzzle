# -*- coding: utf-8 -*-
"""Teste falsificavel do lead mais motivado do endgame:

    "our first hint is your last command"  (texto literal da pagina SalPhaseion)
    + "in front of your eyes but you're not seeing it"  (Bingo do criador, 2026-03-03)
    + "very last step is a true give away promised"      (roadmap do criador)

Leitura: o HASH do primeiro hint = a chave do ULTIMO passo (os 35 blocos).
O hash do primeiro hint e:
    sha256("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
        = 89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32
que e EXATAMENTE a URL do endgame (32 bytes = tamanho de chave AES-256).
Esta "na frente dos olhos" de todos ha anos — ninguem o testou como chave
da fronteira real (35 blocos): first_hint_sweep so o testou contra SMALL/COSMIC
(ja abertos = teste vazio), e a lacuna posterior testou 47 OUTRAS frases.

Contrato: solve = bater a pubkey publica do premio (matches_pubkey) OU abrir
AES com padding PKCS7 valido E corpo >=80% ascii / `Salted__` / pubkey-alvo.
Padding isolado nao e solve.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

from coincurve import PublicKey
from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "_work", "first_hint_frontier.jsonl")

TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)

URL_SRC = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
URL_HASH_HEX = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
URL_HASH_BYTES = bytes.fromhex(URL_HASH_HEX)  # 32 bytes EXATOS -> chave AES-256 candidata


def matches_pubkey(secret: bytes) -> bool:
    if len(secret) != 32 or not any(secret):
        return False
    try:
        return PublicKey.from_valid_secret(secret).format(compressed=False) == TARGET_PUBKEY
    except ValueError:
        return False


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data)


def valid_plaintext(data: bytes) -> bool:
    if not data or len(data) % 16:
        return False
    pad = data[-1]
    if not 1 <= pad <= 16 or not data.endswith(bytes([pad]) * pad):
        return False
    body = data[:-pad]
    return bool(body) and printable_ratio(body) >= 0.80


def main() -> None:
    R = F.reproduce()
    header = R["header"]            # 31 bytes
    header28 = header[2:30]
    blocks = [R["blocks"][i * 32:(i + 1) * 32] for i in range(35)]
    body = R["blocks"]              # 1120 bytes
    half = R["half"]
    better_half = R["better_half"]
    tail = R["matrix_tail"]
    cosmic = R["cosmic"]

    log = open(OUT, "w", encoding="utf-8")
    hard_hits = []
    soft_hits = []
    n_keys = n_aes = n_priv = 0
    top = []

    def note(**kw):
        log.write(json.dumps(kw, ensure_ascii=False) + "\n")

    ivs = {
        "zero": b"\x00" * 16,
        "header16": header28[:16],
        "header28lo": header28[12:28],
        "half16": half[:16],
        "half16hi": half[16:32],
        "bh16": better_half[:16],
        "bh16hi": better_half[16:32],
        "tailpad": (tail * 4)[:16],
        "sevenpad": (b"7" * 16),
        "pm7": b"+-" + header28[:12] + b"7",
        "sha7": hashlib.sha256(b"+-" + header28 + b"7").digest()[:16],
        "urlhash16lo": URL_HASH_BYTES[:16],
        "urlhash16hi": URL_HASH_BYTES[16:32],
        "cosmic16": cosmic[:16],
        "cosmic1616": cosmic[16:32],
    }

    def test_aes(key: bytes, label: str):
        nonlocal n_aes, n_priv
        # stream inteiro 1120 B (CBC)
        for ivn, iv in ivs.items():
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            n_aes += 1
            r = printable_ratio(pt)
            if len(top) < 20:
                top.append((r, f"{label}/CBC-stream/{ivn}", pt[:32].hex()))
            else:
                top.sort(reverse=True)
                if r > top[-1][0]:
                    top[-1] = (r, f"{label}/CBC-stream/{ivn}", pt[:32].hex())
            if valid_plaintext(pt) or b"Salted__" in pt or TARGET_PUBKEY in pt:
                soft_hits.append({"label": f"{label}/CBC-stream/{ivn}",
                                  "ratio": round(r, 4), "head": pt[:80].hex()})
                note(kind="SOFT", label=f"{label}/CBC-stream/{ivn}", head=pt[:80].hex())
            for i in range(0, len(pt) - 31, 16):  # every 16B alignment slice of 32B
                n_priv += 1
                if matches_pubkey(pt[i:i + 32]):
                    hard_hits.append({"label": f"{label}/CBC-stream/{ivn}",
                                      "off": i, "priv": pt[i:i + 32].hex()})
        # por-bloco 32B (CBC + ECB)
        for ivn, iv in ivs.items():
            plains = []
            for blk in blocks:
                try:
                    plains.append(AES.new(key, AES.MODE_CBC, iv).decrypt(blk))
                except ValueError:
                    plains.append(b"")
            n_aes += 35
            joined = b"".join(plains)
            r = printable_ratio(joined)
            if len(top) < 20:
                top.append((r, f"{label}/CBC-pb/{ivn}", joined[:32].hex()))
            else:
                top.sort(reverse=True)
                if r > top[-1][0]:
                    top[-1] = (r, f"{label}/CBC-pb/{ivn}", joined[:32].hex())
            if valid_plaintext(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
                soft_hits.append({"label": f"{label}/CBC-pb/{ivn}",
                                  "ratio": round(r, 4), "head": joined[:80].hex()})
                note(kind="SOFT", label=f"{label}/CBC-pb/{ivn}", head=joined[:80].hex())
            for i, p in enumerate(plains):
                n_priv += 1
                if matches_pubkey(p):
                    hard_hits.append({"label": f"{label}/CBC-pb/{ivn}",
                                      "blk": i, "priv": p.hex()})
        plains = []
        for blk in blocks:
            try:
                plains.append(AES.new(key, AES.MODE_ECB).decrypt(blk))
            except ValueError:
                plains.append(b"")
        n_aes += 35
        joined = b"".join(plains)
        r = printable_ratio(joined)
        if len(top) < 20:
            top.append((r, f"{label}/ECB-pb", joined[:32].hex()))
        else:
            top.sort(reverse=True)
            if r > top[-1][0]:
                top[-1] = (r, f"{label}/ECB-pb", joined[:32].hex())
        if valid_plaintext(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
            soft_hits.append({"label": f"{label}/ECB-pb",
                              "ratio": round(r, 4), "head": joined[:80].hex()})
            note(kind="SOFT", label=f"{label}/ECB-pb", head=joined[:80].hex())
        for i, p in enumerate(plains):
            n_priv += 1
            if matches_pubkey(p):
                hard_hits.append({"label": f"{label}/ECB-pb", "blk": i, "priv": p.hex()})

    seen = set()

    def emit(key: bytes, src: str):
        nonlocal n_keys, n_priv
        if key in seen or len(key) != 32:
            return
        seen.add(key)
        n_keys += 1
        n_priv += 1
        if matches_pubkey(key):
            hard_hits.append({"label": f"DIRECT/{src}", "priv": key.hex()})
        test_aes(key, src)

    # ====== candidato estrela: o hash do primeiro hint (32 bytes) ======
    emit(URL_HASH_BYTES, "url_hash_bytes")
    # sha256 do hex-string (gramatica HASHTHETEXT sobre o hash)
    emit(hashlib.sha256(URL_HASH_HEX.encode()).digest(), "sha256(url_hash_hex)")
    emit(hashlib.sha256(URL_HASH_HEX.upper().encode()).digest(), "sha256(URL_HASH_HEX_UP)")
    # double sha256
    emit(hashlib.sha256(URL_HASH_BYTES).digest(), "sha256(url_hash_bytes)")
    emit(hashlib.sha256(hashlib.sha256(URL_HASH_BYTES).digest()).digest(), "dblsha256(url_hash_bytes)")
    # a string-fonte do primeiro hint (nao tem 32B, mas sha256 sim)
    emit(hashlib.sha256(URL_SRC.encode()).digest(), "sha256(url_src)")
    emit(hashlib.sha256(URL_SRC.upper().encode()).digest(), "sha256(URL_SRC_UP)")
    emit(hashlib.sha256(URL_SRC.lower().encode()).digest(), "sha256(url_src_lower)")
    emit(hashlib.sha256(URL_SRC.replace(" ", "").encode()).digest(), "sha256(url_src_nospace)")

    # ====== "our first hint is your last command" e variantes ======
    FIRST_HINT = [
        "our first hint is your last command",
        "ourfirsthintisyourlastcommand",
        "OURFIRSTHINTISYOURLASTCOMMAND",
        "Our First Hint Is Your Last Command",
        "our first hint is your last command.",
        "the first hint is your last command",
        "firsthintisyourlastcommand",
        "first hint is your last command",
        # com a gramatica /(aa, connected enf): minusculo sem espaco
        "ourfirsthintisyourlastcommand",
        # "shabef" = sha256; "our first hint" -> sha256(our first hint)
        "shabefourfirsthint",
        "shabefourfirsthintisyourlastcommand",
    ]
    for s in FIRST_HINT:
        emit(hashlib.sha256(s.encode()).digest(), f"sha256({s[:30]})")
        emit(hashlib.sha256(s.upper().encode()).digest(), f"sha256_UP({s[:30]})")
        if len(s) == 32:
            emit(s.encode(), f"raw32({s[:30]})")

    # ====== "HASHTHETEXT" operacao terminal sobre varios textos visiveis ======
    # HASHTHETEXT = sha256 UPPERCASE sem espaco (provado: gerou a URL 89727c)
    HASHTHETEXT_TARGETS = [
        # a pagina SalPhaseion inteira? usar so o texto-fonte canonico:
        "dbbibfbhc..." if False else "dbbi",  # placeholder; abaixo os reais
    ]
    # textos "na frente dos olhos" da pagina SalPhaseion (verbatim):
    VISIBLE = [
        "matrixsumlist",
        "matrixsumlistenter",
        "enter",
        "lastwordsbeforearchichoice",
        "thispassword",
        "lastwordsbeforearchichoicethispassword",
        "matrixsumlistenterlastwordsbeforearchichoicethispassword",
        "matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist",
        "shabefanstoo",
        "shabef anstoo",
        "shabefans too",
        "shabef ans too",
        "sha256 anstoo",
        # a URL/endereco literal:
        "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
        "1GSMG1JC9WTDsWFWAPGJ2XCMJPAWX7PRBE",
        "gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
        # o proprio hash hex em varias caixas:
        URL_HASH_HEX,
        URL_HASH_HEX.upper(),
    ]
    for s in VISIBLE:
        # HASHTHETEXT = sha256(UPPER(s) sem espaco)
        emit(hashlib.sha256(s.upper().replace(" ", "").encode()).digest(),
             f"HASHTHETEXT({s[:28]})")
        emit(hashlib.sha256(s.encode()).digest(), f"sha256({s[:28]})")
        emit(hashlib.sha256(s.lower().encode()).digest(), f"sha256_lower({s[:28]})")
        emit(hashlib.sha256(hashlib.sha256(s.encode()).digest()).digest(),
             f"dblsha256({s[:28]})")

    # ====== combinacao first-hint + better_half ("with the better half") ======
    # o hash do primeiro hint XOR better_half, concat, etc.
    emit(bytes(a ^ b for a, b in zip(URL_HASH_BYTES, better_half)),
         "url_hash^better_half")
    emit(bytes(a ^ b for a, b in zip(URL_HASH_BYTES, half)),
         "url_hash^half")
    emit(hashlib.sha256(URL_HASH_BYTES + better_half).digest(), "sha(url_hash+bh)")
    emit(hashlib.sha256(better_half + URL_HASH_BYTES).digest(), "sha(bh+url_hash)")
    emit(hashlib.sha256(URL_HASH_HEX.encode() + better_half).digest(), "sha(urlhex+bh)")
    emit(hashlib.sha256(URL_SRC.encode() + better_half).digest(), "sha(urlsrc+bh)")
    # first hint hash + matrix_tail (que da 11111=31=offset)
    emit(hashlib.sha256(URL_HASH_BYTES + tail).digest(), "sha(url_hash+tail)")
    emit(bytes(a ^ b for a, b in zip(URL_HASH_BYTES, (tail * 8)[:32])),
         "url_hash^tail")

    # ====== "last command" = openssl: a senha do openssl do Chain4 ja e conhecida
    #        (E_C||E_S||E_B). Mas "first hint is your LAST COMMAND" pode significar
    #        que o hash do primeiro hint substitui essa senha no ULTIMO blob (35 blocos).
    #        Testar tambem: hash do primeiro hint como PASSPHRASE (EVP_BytesToKey) dos 35 blocos
    #        como se fossem um blob salted. Mas os 35 blocos nao tem Salted__; usar o salt
    #        do chain4 (5bbd88ac...) e do cosmic.
    from Crypto.Hash import MD5, SHA256
    chain4_blob = R["chain4_blob"]
    salt_c4 = chain4_blob[8:16]  # 5bbd88ac32481bca
    salt_cosmic = cosmic[8:16] if cosmic[:8] == b"Salted__" else None
    salts = {"chain4": salt_c4}
    if salt_cosmic:
        salts["cosmic"] = salt_cosmic

    def evp(pw, salt, hmod, klen=32, ivlen=16):
        d = b""; prev = b""
        while len(d) < klen + ivlen:
            prev = hmod.new(prev + pw + salt).digest()
            d += prev
        return d[:klen], d[klen:klen + ivlen]

    # os 35 blocos como ct (sem Salted__); IV = zero / sha7 / etc.
    passphrases = {
        "url_hash_hex": URL_HASH_HEX.encode(),
        "url_hash_bytes": URL_HASH_BYTES,
        "url_src": URL_SRC.encode(),
        "first_hint": b"our first hint is your last command",
        "first_hint_enf": b"ourfirsthintisyourlastcommand",
    }
    for pname, pw in passphrases.items():
        for sname, salt in salts.items():
            for hmod in (MD5, SHA256):
                k, iv = evp(pw, salt, hmod)
                emit(k, f"EVP/{pname}/{sname}/{hmod.__name__}")
                # tambem decifra o chain4_blob REAL com essa passphrase (ja aberto, mas
                # a "ultima" camada pode ser diferente)
                try:
                    raw = AES.new(k, AES.MODE_CBC, iv).decrypt(chain4_blob[16:])
                    pad = raw[-1]
                    if 1 <= pad <= 16 and raw.endswith(bytes([pad]) * pad):
                        body2 = raw[:-pad]
                        if printable_ratio(body2) >= 0.5 or b"Salted__" in body2:
                            soft_hits.append({"label": f"EVP-chain4blob/{pname}/{sname}/{hmod.__name__}",
                                              "ratio": round(printable_ratio(body2), 4),
                                              "head": body2[:80].hex()})
                            note(kind="SOFT-EVP", label=f"chain4blob/{pname}/{sname}/{hmod.__name__}",
                                 head=body2[:80].hex())
                except Exception:
                    pass

    log.close()
    top.sort(reverse=True)
    print("=== first-hint-is-your-last-command: fronteira 35 blocos ===")
    print(f"chaves unicas: {n_keys} | AES: {n_aes} | privkey: {n_priv}")
    print(f"HARD hits (pubkey): {len(hard_hits)}")
    print(f"SOFT hits: {len(soft_hits)}")
    if hard_hits:
        print("!!! SOLVE !!!")
        for h in hard_hits:
            print(" ", h)
    if soft_hits:
        print("--- soft ---")
        for h in soft_hits:
            print(" ", h)
    print("--- top print ---")
    for r, lbl, head in top[:10]:
        print(f"  {r:.3f}  {lbl}  {head}")


if __name__ == "__main__":
    main()
