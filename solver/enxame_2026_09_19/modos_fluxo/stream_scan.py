#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F1 "modos_fluxo" — enxame 2026-09-19.

LACUNA (ENDGAME.md tabela D + §3.13/§3.14): "Continua aberto: só os modos de fluxo".
Modos de fluxo do `openssl enc` (cfb, cfb1, cfb8, ofb, ctr) NÃO produzem padding PKCS7;
as campanhas históricas filtravam por padding válido antes de persistir o plaintext, de
modo que todo o material de modo de fluxo era descartado e seu interior binário (janelas
de 32 B que poderiam ser a chave privada) nunca foi varrido contra os dois alvos.

HIPÓTESE: o blob (SMALL/COSMIC/TAIL32) não é aes-256-cbc, mas um modo de fluxo do mesmo
`openssl enc`, e o plaintext contém — em algum offset — a chave privada de 32 B de um dos
dois endereços-alvo.

DOMÍNIO: 3 blobs x 5 modos de fluxo x 2 KDF (EVP_BytesToKey SHA256 e MD5) x o conjunto de
senhas reconstruível do repositório (passwords.py). SEM filtro de padding: toda janela
raw32 de todo plaintext, nas orientações BE e LE, contra os DOIS alvos.

ORÁCULO DURO: AGENTS.md regra 1. Só h160 (comprimida ou não) igual a um dos dois alvos, ou
blob aninhado que abre. Padding, printable e escore NÃO são solução.

Uso:
    python3 stream_scan.py --out <dir>            # domínio completo
    python3 stream_scan.py --out <dir> --limite N # primeiras N senhas (fração declarada)
"""
import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time

from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from coincurve import PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.abspath(os.path.join(HERE, "..", "..", "experiments", "claude_endgame_2026_09_02"))
sys.path.insert(0, KIT)
sys.path.insert(0, HERE)
import gsmg_common as G  # noqa: E402
import passwords as PW  # noqa: E402

MODOS = ("cfb", "cfb1", "cfb8", "ofb", "ctr")
KDFS = (("sha256", SHA256), ("md5", MD5))
BLOBS = ("SMALL", "COSMIC", "TAIL32")
ALVOS = {bytes.fromhex(h) for h in G.TARGET_H160S}

_sha256 = hashlib.sha256
_rmd = hashlib.new


# ------------------------------------------------------------------ cifra
def cfb1_decrypt(key, iv, ct):
    """CFB de 1 bit (NIST SP 800-38A), igual ao `openssl enc -aes-256-cfb1`."""
    ecb = AES.new(key, AES.MODE_ECB)
    enc = ecb.encrypt
    sr = int.from_bytes(iv, "big")
    M = (1 << 128) - 1
    out = bytearray()
    for byte in ct:
        ob = 0
        for k in (7, 6, 5, 4, 3, 2, 1, 0):
            o0 = enc(sr.to_bytes(16, "big"))[0]
            cb = (byte >> k) & 1
            ob = (ob << 1) | (cb ^ (o0 >> 7))
            sr = ((sr << 1) | cb) & M
        out.append(ob)
    return bytes(out)


def stream_decrypt(modo, key, iv, ct):
    if modo == "cfb":
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct)
    if modo == "cfb8":
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(ct)
    if modo == "cfb1":
        return cfb1_decrypt(key, iv, ct)
    if modo == "ofb":
        return AES.new(key, AES.MODE_OFB, iv=iv).decrypt(ct)
    if modo == "ctr":
        return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv).decrypt(ct)
    raise ValueError(modo)


# ------------------------------------------------------------------ oráculo duro
def scan_raw32(buf, alvos=ALVOS):
    """Toda janela de 32 B do buffer como privkey secp256k1; compara o h160 das pubkeys
    comprimida E não comprimida com os alvos. Devolve (n_janelas, lista_de_hits)."""
    hits = []
    n = len(buf) - 31
    if n <= 0:
        return 0, hits
    for j in range(n):
        sec = buf[j:j + 32]
        try:
            pk = PublicKey.from_valid_secret(sec)
        except Exception:
            continue
        fmt = pk.format
        for comp in (True, False):
            if _rmd("ripemd160", _sha256(fmt(comp)).digest()).digest() in alvos:
                hits.append({"offset": j, "comprimida": comp, "priv": sec.hex()})
    return n, hits


def scan_both(buf, alvos=ALVOS):
    """BE (buffer como está) e LE (buffer invertido: o conjunto exato das janelas
    little-endian). Devolve (janelas_totais, hits)."""
    n1, h1 = scan_raw32(buf, alvos)
    n2, h2 = scan_raw32(buf[::-1], alvos)
    for h in h1:
        h["orient"] = "BE"
    for h in h2:
        h["orient"] = "LE"
    return n1 + n2, h1 + h2


# ------------------------------------------------------------------ controles
def controle_kdf_fase2():
    """Controle positivo obrigatório: a fase 2 abre com sha256hex('causality') em
    aes-256-cbc via EVP-SHA256 (e NÃO via MD5)."""
    import base64
    raw = base64.b64decode(G.PHASE2_B64)
    salt, ct = raw[8:16], raw[16:]
    pw = G.shahex("causality").encode()
    res = {}
    for nome, hm in KDFS:
        k, iv = G.evp(pw, salt, hm)
        p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        res[nome] = bool(p and p.startswith(b"The ironic"))
    assert res["sha256"] and not res["md5"], res
    return res


def controle_openssl_cli(tmpdir):
    """Cada modo x KDF é conferido contra o `openssl enc` REAL: cifra um plaintext
    conhecido pelo CLI e exige que esta implementação o reproduza byte a byte."""
    pt = bytes(range(256)) * 2 + b"controle de modos de fluxo F1\n"
    src = os.path.join(tmpdir, "pt.bin")
    with open(src, "wb") as f:
        f.write(pt)
    out = {}
    for modo in MODOS:
        for nome, hm in KDFS:
            dst = os.path.join(tmpdir, f"c_{modo}_{nome}.bin")
            r = subprocess.run(["openssl", "enc", f"-aes-256-{modo}", "-e", "-md", nome,
                                "-pass", "pass:controle123", "-in", src, "-out", dst],
                               capture_output=True)
            assert r.returncode == 0, r.stderr
            raw = open(dst, "rb").read()
            k, iv = G.evp(b"controle123", raw[8:16], hm)
            out[f"{modo}/{nome}"] = stream_decrypt(modo, k, iv, raw[16:]) == pt
    assert all(out.values()), out
    return out


def controle_chave_plantada(tmpdir):
    """Controle plantado ponta a ponta: uma chave conhecida é escondida DENTRO de um
    plaintext, o plaintext é cifrado pelo openssl CLI em modo de fluxo, e o pipeline
    (decifra + scan_both) tem de recuperá-la — em BE e em LE."""
    k_be = G.sha(b"F1-controle-plantado-BE")
    k_le = G.sha(b"F1-controle-plantado-LE")
    alvos = set()
    for k in (k_be, k_le):
        pk = PublicKey.from_valid_secret(k)
        alvos.add(_rmd("ripemd160", _sha256(pk.format(True)).digest()).digest())
    pt = b"\x11" * 7 + k_be + b"\x22" * 13 + k_le[::-1] + b"\x33" * 9
    src = os.path.join(tmpdir, "plant.bin")
    with open(src, "wb") as f:
        f.write(pt)
    res = {}
    for modo in ("ofb", "cfb1"):
        dst = os.path.join(tmpdir, f"plant_{modo}.bin")
        r = subprocess.run(["openssl", "enc", f"-aes-256-{modo}", "-e", "-md", "sha256",
                            "-pass", "pass:plantado", "-in", src, "-out", dst],
                           capture_output=True)
        assert r.returncode == 0, r.stderr
        raw = open(dst, "rb").read()
        k, iv = G.evp(b"plantado", raw[8:16], SHA256)
        p = stream_decrypt(modo, k, iv, raw[16:])
        _, hits = scan_both(p, alvos)
        orients = {h["orient"] for h in hits}
        res[modo] = {"hits": len(hits), "orientacoes": sorted(orients)}
        assert orients == {"BE", "LE"}, res
    # e o scanner NÃO dispara nos alvos reais com o mesmo material
    n, h = scan_both(pt)
    assert h == [], h
    res["falso_positivo_alvos_reais"] = 0
    res["janelas_controle"] = n
    return res


# ------------------------------------------------------------------ nulo casado
def nulo_casado(n=200, seed=20260919):
    """Sem scorer de quadgramas neste clone (result.json ausente): o critério estrutural
    é `printable` e G.semantic. O nulo mede a distribuição de printable de plaintexts de
    modo de fluxo sob senhas aleatórias, nos mesmos 3 blobs x 5 modos x 2 KDF."""
    rnd = random.Random(seed)
    vals = []
    semanticos = 0
    for _ in range(n):
        pw = bytes(rnd.randrange(256) for _ in range(rnd.randrange(8, 40)))
        for b in BLOBS:
            salt, ct = G.BLOBS[b]
            for nome, hm in KDFS:
                k, iv = G.evp(pw, salt, hm)
                for modo in MODOS:
                    p = stream_decrypt(modo, k, iv, ct)
                    vals.append(G.printable(p))
                    if G.semantic(p):
                        semanticos += 1
    vals.sort()
    return {"senhas": n, "decifracoes": len(vals), "printable_media": round(sum(vals) / len(vals), 4),
            "printable_max": round(vals[-1], 4), "printable_p99": round(vals[int(0.99 * len(vals))], 4),
            "semanticos": semanticos}


# ------------------------------------------------------------------ varredura
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--limite", type=int, default=0)
    ap.add_argument("--nulo", type=int, default=200)
    ap.add_argument("--tempo-max", type=float, default=2400.0)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    tmp = os.path.join(a.out, "tmp")
    os.makedirs(tmp, exist_ok=True)

    t0 = time.time()
    ctrl = {"kdf_fase2": controle_kdf_fase2(),
            "openssl_cli": controle_openssl_cli(tmp),
            "chave_plantada": controle_chave_plantada(tmp)}
    print("controles OK", json.dumps(ctrl["chave_plantada"]), flush=True)

    senhas, meta = PW.build()
    if a.limite:
        senhas = senhas[:a.limite]
    hits_path = os.path.join(a.out, "hits.jsonl")
    open(hits_path, "w").close()
    cand_path = os.path.join(a.out, "candidatos.jsonl")
    open(cand_path, "w").close()

    n_dec = 0
    n_jan = 0
    n_hits = 0
    n_cand = 0
    top = []  # (printable, senha, blob, modo, kdf)
    por_modo = {m: 0 for m in MODOS}
    interrompido = None

    for i, pw in enumerate(senhas):
        if time.time() - t0 > a.tempo_max:
            interrompido = i
            break
        for b in BLOBS:
            salt, ct = G.BLOBS[b]
            for nome, hm in KDFS:
                k, iv = G.evp(pw, salt, hm)
                for modo in MODOS:
                    p = stream_decrypt(modo, k, iv, ct)
                    n_dec += 1
                    por_modo[modo] += 1
                    j, hits = scan_both(p)
                    n_jan += j
                    if hits:
                        n_hits += len(hits)
                        with open(hits_path, "a") as f:
                            for h in hits:
                                h.update({"senha": pw.decode("latin-1"), "blob": b,
                                          "kdf": nome, "modo": modo})
                                f.write(json.dumps(h) + "\n")
                    if G.semantic(p) or G.nested_blob(p):
                        n_cand += 1
                        with open(cand_path, "a") as f:
                            f.write(json.dumps({"senha": pw.decode("latin-1"), "blob": b,
                                                "kdf": nome, "modo": modo,
                                                "printable": round(G.printable(p), 4),
                                                "hex": p.hex()}) + "\n")
                    pr = G.printable(p)
                    if len(top) < 20:
                        top.append((pr, pw.decode("latin-1"), b, modo, nome, p[:32].hex()))
                        top.sort(reverse=True)
                    elif pr > top[-1][0]:
                        top[-1] = (pr, pw.decode("latin-1"), b, modo, nome, p[:32].hex())
                        top.sort(reverse=True)
        if i % 50 == 0:
            print(f"{i}/{len(senhas)} dec={n_dec} jan={n_jan} t={time.time()-t0:.0f}s", flush=True)

    t_scan = time.time() - t0
    nulo = nulo_casado(a.nulo)

    resumo = {
        "frente": "F1 modos_fluxo", "campanha": "enxame_2026-09-19",
        "commit_base": "66fecdc",
        "kit_sha256": hashlib.sha256(open(os.path.join(KIT, "gsmg_common.py"), "rb").read()).hexdigest(),
        "senhas_meta": meta,
        "senhas_processadas": len(senhas) if interrompido is None else interrompido,
        "senhas_no_dominio": len(senhas),
        "interrompido_por_tempo": interrompido,
        "modos": list(MODOS), "kdfs": [k[0] for k in KDFS], "blobs": list(BLOBS),
        "decifracoes": n_dec, "decifracoes_por_modo": por_modo,
        "janelas_raw32_BE_LE": n_jan,
        "alvos": list(G.TARGET_H160S),
        "hits_oraculo_duro": n_hits,
        "candidatos_semanticos": n_cand,
        "top_printable": [{"printable": round(x[0], 4), "senha": x[1][:64], "blob": x[2],
                           "modo": x[3], "kdf": x[4], "head_hex": x[5]} for x in top],
        "nulo_casado": nulo,
        "controles": ctrl,
        "segundos": round(t_scan, 1),
    }
    # `summary.json` e `controls.json` são os dois nomes que o .gitignore deixa entrar em _work/
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(resumo, f, indent=2, ensure_ascii=False)
    with open(os.path.join(a.out, "controls.json"), "w") as f:
        json.dump(ctrl, f, indent=2, ensure_ascii=False)
    print(json.dumps({k: resumo[k] for k in ("decifracoes", "janelas_raw32_BE_LE",
                                             "hits_oraculo_duro", "candidatos_semanticos",
                                             "segundos")}, indent=2))


if __name__ == "__main__":
    main()
