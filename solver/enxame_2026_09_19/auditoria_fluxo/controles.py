# -*- coding: utf-8 -*-
"""
F2 auditoria_fluxo — controles obrigatorios ANTES de qualquer varredura.

C1. secp256k1 puro == coincurve numa amostra (o EC da varredura e' confiavel).
C2. openssl enc CLI como segunda implementacao: para cada modo de fluxo x KDF,
    cifra um plaintext aleatorio e exige que a MINHA decifra reproduza byte a byte.
C3. controle de KDF do projeto: fase 2 abre com sha256hex("causality") sob
    EVP-SHA256 e NAO sob EVP-MD5.
C4. CONTROLE PLANTADO: privkey conhecida no INTERIOR binario (offset 37, nao
    alinhado a 16) de um plaintext, cifrado pelo openssl CLI num modo de fluxo.
    O pipeline completo (decifra + varredura raw32 cega) tem de recuperar a chave
    no offset exato, em BE e em LE. Sem isso, qualquer "0 hits" e' invalido.

Uso:  python3 controles.py
Saida: JSON em _work/enxame_2026-09-19/auditoria_fluxo/controles.json
"""
import base64, hashlib, json, os, random, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import indep_fluxo as X

OUT = os.path.join(X.REPO, "_work", "enxame_2026-09-19", "auditoria_fluxo")
os.makedirs(OUT, exist_ok=True)
R = {}

# ---------------------------------------------------------------- C1
def c1_ec():
    from coincurve import PublicKey
    rnd = random.Random(20260919)
    ok = 0
    for _ in range(40):
        sec = rnd.getrandbits(256).to_bytes(32, "big")
        mine = X.pure_pubkey(sec)
        if mine is None:
            continue
        pk = PublicKey.from_valid_secret(sec)
        assert mine[0] == pk.format(False) and mine[1] == pk.format(True), sec.hex()
        ok += 1
    # vetor conhecido: d=1 -> G
    assert X.pure_pubkey((1).to_bytes(32, "big"))[0][1:33].hex() == "%064x" % X.GX
    return {"amostras_iguais": ok, "vetor_d1_G": True}

# ---------------------------------------------------------------- C2
def c2_openssl():
    rnd = random.Random(7)
    res = {}
    for mode in X.STREAM_MODES:
        for kdf in X.KDFS:
            pt = bytes(rnd.randrange(256) for _ in range(200))
            pw = "senha-de-controle-%s-%s" % (mode, kdf)
            with tempfile.TemporaryDirectory() as d:
                fi, fo = os.path.join(d, "p.bin"), os.path.join(d, "c.bin")
                open(fi, "wb").write(pt)
                cmd = ["openssl", "enc", "-" + X.OPENSSL_NAME[mode], "-e",
                       "-md", kdf, "-pass", "pass:" + pw, "-in", fi, "-out", fo]
                subprocess.run(cmd, check=True, capture_output=True)
                raw = open(fo, "rb").read()
            assert raw[:8] == b"Salted__"
            salt, ct = raw[8:16], raw[16:]
            got = X.decrypt(mode, kdf, pw.encode(), salt, ct)
            res["%s/%s" % (mode, kdf)] = {
                "ct_len": len(ct), "pt_len": len(pt), "igual": got == pt,
            }
            assert got == pt, "divergencia em %s/%s" % (mode, kdf)
    return res

# ---------------------------------------------------------------- C3
def c3_fase2():
    txt = open(os.path.join(X.REPO, "README.md"), encoding="utf-8").read()
    i = txt.index("U2FsdGVkX18GKGYS")
    import re
    lines = []
    for l in txt[i:].splitlines():
        l = l.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]{4,64}", l):
            break
        lines.append(l)
    raw = base64.b64decode("".join(lines))
    salt, ct = raw[8:16], raw[16:]
    pw = hashlib.sha256(b"causality").hexdigest().encode()
    out = {}
    for kdf in ("sha256", "md5"):
        k, iv = X.evp_bytes_to_key(pw, salt, kdf)
        p = X.dec_cbc_nopad(k, iv, ct)
        pad = p[-1]
        valido = 1 <= pad <= 16 and p.endswith(bytes([pad]) * pad)
        out[kdf] = {"abre": bool(valido and p.startswith(b"The ironic")),
                    "head": p[:32].decode("latin-1", "replace")}
    assert out["sha256"]["abre"] and not out["md5"]["abre"], out
    return out

# ---------------------------------------------------------------- C4 (plantado)
def c4_plantado():
    """Chave conhecida no interior binario, offset 37 (nao alinhado), plaintext de 200 B,
    cifrado pelo openssl CLI em cada modo de fluxo. Pipeline completo tem de recuperar."""
    from coincurve import PublicKey
    rnd = random.Random(31337)
    sec_be = hashlib.sha256(b"F2-auditoria_fluxo-chave-plantada").digest()
    sec_le = hashlib.sha256(b"F2-auditoria_fluxo-chave-plantada-LE").digest()
    alvos = {X.h160(PublicKey.from_valid_secret(sec_be).format(True)),
             X.h160(PublicKey.from_valid_secret(sec_le).format(False))}
    OFF_BE, OFF_LE = 37, 113        # nenhum multiplo de 16
    assert OFF_BE % 16 and OFF_LE % 16

    pt = bytearray(rnd.randrange(256) for _ in range(200))
    pt[OFF_BE:OFF_BE + 32] = sec_be
    pt[OFF_LE:OFF_LE + 32] = sec_le[::-1]     # plantada em ordem invertida
    pt = bytes(pt)

    res = {}
    for mode in X.STREAM_MODES:
        pw = "controle-plantado"
        with tempfile.TemporaryDirectory() as d:
            fi, fo = os.path.join(d, "p.bin"), os.path.join(d, "c.bin")
            open(fi, "wb").write(pt)
            subprocess.run(["openssl", "enc", "-" + X.OPENSSL_NAME[mode], "-e", "-md", "sha256",
                            "-pass", "pass:" + pw, "-in", fi, "-out", fo],
                           check=True, capture_output=True)
            raw = open(fo, "rb").read()
        salt, ct = raw[8:16], raw[16:]
        got = X.decrypt(mode, "sha256", pw.encode(), salt, ct)
        assert got == pt, "decifra nao reproduziu o plaintext em %s" % mode

        sc = X.Scanner(alvos)
        hits = sc.scan(got, where=mode)
        tags = sorted(h[1] for h in hits)
        res[mode] = {"pt_igual": True, "janelas": sc.windows, "escalares": sc.scalars,
                     "hits": tags}
        assert "be@%d" % OFF_BE in tags, (mode, tags)
        assert "le@%d" % OFF_LE in tags, (mode, tags)

    # NEGATIVO casado: o MESMO scanner, com os alvos REAIS, nao dispara no mesmo plaintext
    sc = X.Scanner(("a9553269572a317e39f0f518cb87c1a0ee1dbae4",
                    "4bc468447fe1b048ad030a2f9a125478eabc4ed6"))
    assert sc.scan(pt, "negativo") == []
    return {"chave_be": sec_be.hex(), "offset_be": OFF_BE,
            "chave_le": sec_le.hex(), "offset_le": OFF_LE,
            "h160_alvos_plantados": sorted(alvos),
            "por_modo": res, "negativo_alvos_reais": "0 hits"}

if __name__ == "__main__":
    R["C1_secp256k1_puro_vs_coincurve"] = c1_ec(); print("C1 ok")
    R["C2_openssl_cli_por_modo_kdf"] = c2_openssl(); print("C2 ok (10 pares modo x kdf)")
    R["C3_fase2_kdf"] = c3_fase2(); print("C3 ok")
    R["C4_chave_plantada"] = c4_plantado(); print("C4 ok")
    R["blobs"] = X.blob_digest(X.load_blobs())
    json.dump(R, open(os.path.join(OUT, "controles.json"), "w"), indent=2)
    print(json.dumps(R["blobs"], indent=2))
    print("-> " + os.path.join(OUT, "controles.json"))
