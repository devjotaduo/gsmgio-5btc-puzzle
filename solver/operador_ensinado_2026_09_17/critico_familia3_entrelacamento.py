# -*- coding: utf-8 -*-
r"""
CRITICO ADVERSARIAL da FAMILIA 3 — "seven intertwined passwords" como ENTRELACAMENTO.

=========================  HIPOTESE DO CRITICO (escrita ANTES de codar)  =========================

O agente da familia 3 reportou NEGATIVO com 9.108.000 materiais, 109.296.000 AES e 2.113.020
privkeys, e reportou dois "achados de mapa" (o denominador 1/255 do padding e um teto novo de
`printable`). Minha hipotese adversarial, finita e falsificavel, tem quatro partes:

 H1 (COBERTURA INFLADA). O numero 9.108.000 e "distinto POR TAREFA": o mesmo material pode ter
    sido decifrado varias vezes em tarefas diferentes. Conjuntos cujos sete operandos tem todos o
    mesmo comprimento colapsam `preencher` com `truncar`; conjuntos ja inteiramente minusculos
    colapsam `minusculo` com `como esta`. Previsao: a cobertura GLOBALMENTE distinta e menor que
    9.108.000. Falsificavel contando: gero os 1.904 conjuntos-tarefa com implementacao propria e
    dedup global por hash de 64 bits.

 H2 (ORACULO FROUXO / HIT FABRICADO). Se algum "sinal" dele (z=+2,71, printable 0,646) for
    apresentado como evidencia, e ruido. Previsao: (a) a probabilidade exata de padding valido sob
    a regra de `G.unpad` e Sigma_{p=1..16} 256^-p e o z corrigido cai para ~0; (b) a distribuicao
    dos COMPRIMENTOS de padding observada bate com a geometrica teorica; (c) o maximo de
    `printable` bate com a cauda binomial exata de 79 bytes uniformes. Falsificavel por calculo
    fechado + qui-quadrado.

 H3 (ORACULO INCOMPLETO). Ele varreu privkey so como sha256(material) e so em k in {1,2} da fase A,
    e NUNCA passou `fast_priv_scan` nos PLAINTEXTS (o script anterior `v3_interleave.py` passava).
    Previsao: rodando o oraculo duro completo sobre os 428.706 plaintexts logados (semantic,
    nested_blob, ebcdic_sig e privkey em TODA janela de 32 B nas DUAS ordens de byte) e o braco
    privkey sobre os 9,1 M materiais, nada muda. Se mudar, o negativo dele era falso.

 H4 (LACUNAS QUE IMPORTAM). As lacunas (b),(c),(d),(f) que ele declarou sao pequenas e rodaveis:
    braco privkey em TODO o espaco, blocos k in {5..9}, e as formas de senha que faltavam
    (hex MAIUSCULO, sha256 duplo, os 32 B crus do digest). Previsao: 0 hits duros.

Se H1 for verdadeira a cobertura real e menor que a reportada (NEGATIVO_PARCIAL na contagem);
se H2..H4 se confirmarem, a familia esta fechada dentro da cobertura corrigida.

=========================================  ORACULO  =========================================
Duro e unico: privkey de 32 B cuja pubkey == 04f4d1bb...bf33559 (coincurve, serializacao NAO
comprimida — cobre comp e uncomp, e o mesmo ponto), ou plaintext AES semantico (>=85% ASCII,
WIF/hex64 plausivel, blob openssl aninhado Salted__/U2FsdGVk, assinatura EBCDIC cp273 >= 0,75).
PADDING PKCS7 VALIDO SOZINHO E RUIDO. Escore de texto nao e usado como prova em lugar nenhum.

Controle positivo: fase 2 com sha256hex("causality") sob EVP-SHA256, com EVP e unpad
REIMPLEMENTADOS aqui (hashlib puro) — nao reaproveito o `G.evp`/`G.unpad` do kit no caminho
critico, para que um bug do kit nao passe despercebido nas duas pontas.

Nulo casado: 120 replicas com randomizacao DIFERENTE da dele (ele embaralhou os caracteres dentro
de cada operando; eu sorteio cada operando uniformemente do multiconjunto GLOBAL de caracteres,
preservando o comprimento), rodando o MESMO pipeline na MESMA sub-familia S0/k=1.

Uso:  python critico_familia3_entrelacamento.py --stage all
      python critico_familia3_entrelacamento.py --autoteste
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import itertools
import json
import math
import os
import random
import sys
import time
from math import comb
from multiprocessing import Pool

import numpy as np

REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(REPO, "solver", "experiments", "claude_endgame_2026_09_02"))
import gsmg_common as G  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402
from coincurve import PublicKey  # noqa: E402

DIR_AG = os.path.join(REPO, "_work", "operador_ensinado_2026-09-17", "familia3_entrelacamento")
OUT = os.path.join(REPO, "_work", "operador_ensinado_2026-09-17", "critico_familia3_entrelacamento")

TGT = bytes.fromhex("04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a46"
                    "49c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
assert TGT == bytes.fromhex(G.TARGET_PUBKEY_HEX), "pubkey do premio divergente do kit"

# ------------------------------------------------------------------ cripto reimplementada
def evp2(pw: bytes, salt: bytes, algo: str):
    """EVP_BytesToKey do openssl (1 iteracao, sem PBKDF2). Reimplementado com hashlib."""
    d = b""
    prev = b""
    while len(d) < 48:
        prev = hashlib.new(algo, prev + pw + salt).digest()
        d += prev
    return d[:32], d[32:48]


def unpad2(p: bytes):
    """PKCS7 exatamente como `G.unpad` (aceita 1..16) — e essa regra que fixa o denominador."""
    n = p[-1]
    if 1 <= n <= 16 and p.endswith(bytes([n]) * n):
        return p[:-n]
    return None


P_PAD = sum(256.0 ** -n for n in range(1, 17))   # = 1/255 (regra 1..16), NAO 1/256

# salts documentados no ENDGAME.md §1 — checagem independente dos dados do kit
SALTS_DOC = {"SMALL": "3ab585348552415d", "COSMIC": "2d3f6fe06dc950e6", "TAIL32": "b45a5e3d827593ca"}
for _b, _s in SALTS_DOC.items():
    assert G.BLOBS[_b][0].hex() == _s, f"salt de {_b} divergente"
assert (len(G.BLOBS["SMALL"][1]), len(G.BLOBS["COSMIC"][1]), len(G.BLOBS["TAIL32"][1])) == (80, 1328, 80)

CELLS = [(b, a, *G.BLOBS[b]) for b in ("SMALL", "COSMIC", "TAIL32") for a in ("sha256", "md5")]

# ------------------------------------------------------------------ os operandos (reconstruidos)
P3_PARTES = [
    "causality", "Safenet", "Luna", "HSM", "11110",
    "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F"
    "20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
    "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
]
O1 = "theflowerblossomsthroughwhatseemstobeaconcretesurface"
O2 = "causality"
O3 = "".join(P3_PARTES)
O4 = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
O5 = "thematrixhasyou"
O6 = "gsmg.io/theseedisplanted"
O7 = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
S0 = [O1, O2, O3, O4, O5, O6, O7]
assert [len(x) for x in S0] == [53, 9, 227, 62, 15, 24, 59]
assert hashlib.sha256(O3.encode()).hexdigest().startswith("1a57c572")
assert hashlib.sha256(O7.encode()).hexdigest() == \
    "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
SHX = G.shahex


def conjuntos():
    c = {"S0_atlas": list(S0)}
    for i in range(7):
        for tok in ("thispassword", "lastwordsbeforearchichoice"):
            s = list(S0); s[i] = tok
            c[f"S_{tok[:8]}_{i + 1}"] = s
    c["S_url_hash"] = [*S0[:5], SHX(O6), O7]
    c["S_title_hash"] = [*S0[:6], SHX(O7)]
    c["S_url_curta"] = [*S0[:5], "theseedisplanted", O7]
    c["S_p3_partes"] = list(P3_PARTES)
    for j, parte in enumerate(P3_PARTES):
        s = list(S0); s[2] = parte
        c[f"S_p3parte_{j + 1}"] = s
    c["S_todos_hash"] = [SHX(x) for x in S0]
    c["S_joins_hash"] = [O1, O2, SHX(O3), SHX(O4), O5, O6, O7]
    return c


CONJ = conjuntos()
assert len(CONJ) == 28 and all(len(v) == 7 for v in CONJ.values())


# ------------------------------------------------------------------ entrelacamento (reimplementado)
def tranca(partes, k: int, preencher: bool) -> str:
    """Round-robin de blocos de k caracteres. Implementacao independente da do agente."""
    nch = [(len(p) + k - 1) // k for p in partes]
    rodadas = max(nch) if preencher else min(nch)
    saida = []
    for i in range(rodadas):
        for p, n in zip(partes, nch):
            if i < n:
                saida.append(p[i * k:(i + 1) * k])
    return "".join(saida)


def materiais(partes7, k, preencher, rev_mask, minusculo):
    base = [p[::-1] if (rev_mask >> i) & 1 else p for i, p in enumerate(partes7)]
    vistos = set()
    for ordem in itertools.permutations(base):
        m = tranca(ordem, k, preencher)
        if minusculo:
            m = m.lower()
        if m in vistos:
            continue
        vistos.add(m)
        yield m


def h64(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8", "surrogatepass"), digest_size=8).digest(), "big")


# ------------------------------------------------------------------ oraculo duro
# O premio tem DOIS enderecos (ENDGAME/memoria 2026-09-17): 1GSMG… (pubkey exposta, = TGT) e
# 17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa (3,75 BTC, nunca gastou: so o h160 e conhecido). O
# `G.priv_hit` que o agente usou (-> O.check_privkey) testa SO o 1GSMG. Aqui testo os dois:
# pubkey nao-comprimida == TGT (1GSMG) OU h160(unc|comp) == h160 do 17ucy.
import base58  # noqa: E402
H160_B = base58.b58decode_check("17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa")[1:]
assert H160_B.hex() == "4bc468447fe1b048ad030a2f9a125478eabc4ed6"
assert base58.b58decode_check(G.PRIZE_ADDR)[1:].hex() == G.TARGET_H160   # 1GSMG do kit
_RIP = hashlib.new("ripemd160")
_sha = hashlib.sha256


def _h160(b: bytes) -> bytes:
    r = _RIP.copy(); r.update(_sha(b).digest()); return r.digest()


def priv_ok(sec: bytes) -> bool:
    try:
        pk = PublicKey.from_valid_secret(sec)
    except Exception:
        return False
    u = pk.format(False)
    if u == TGT:
        return True
    return _h160(u) == H160_B or _h160(pk.format(True)) == H160_B


def scan_janelas(buf: bytes):
    """Privkey em TODA janela de 32 B, nas DUAS ordens de byte. + hex64/WIF embutidos."""
    achados = []
    for j in range(0, len(buf) - 31):
        w = buf[j:j + 32]
        if priv_ok(w):
            achados.append(("janela", j, w.hex()))
        r = w[::-1]
        if priv_ok(r):
            achados.append(("janela_rev", j, r.hex()))
    t = buf.decode("latin-1")
    for h in G.hex64_candidates(t):
        try:
            if priv_ok(bytes.fromhex(h)):
                achados.append(("hex64", -1, h))
        except Exception:
            pass
    for w in G.wif_candidates(t):
        try:
            import base58
            raw = base58.b58decode_check(w)
            if len(raw) >= 33 and priv_ok(raw[1:33]):
                achados.append(("wif", -1, w))
        except Exception:
            pass
    return achados


def aes_celulas(pwb: bytes):
    """Devolve [(blob, kdf, plaintext)] com padding valido."""
    out = []
    for bn, algo, salt, ct in CELLS:
        k, iv = evp2(pwb, salt, algo)
        p = unpad2(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        if p is not None:
            out.append((bn, algo, p))
    return out


# ------------------------------------------------------------------ STAGE 1: repro + privkey + formas
FORMAS_NOVAS = ("HEXUP", "SHA2X2", "RAW32")   # lacuna (f) declarada pelo agente


def _stage1(args):
    nome, k, pre, rev, lo, fase = args
    t0 = time.time()
    hs = []
    hits = []
    pads = []
    n_aes = 0
    for m in materiais(CONJ[nome], k, pre, rev, lo):
        hs.append(h64(m))
        mb = m.encode("utf-8", "surrogatepass")
        d = hashlib.sha256(mb).digest()
        if priv_ok(d):
            hits.append({"tipo": "PRIVKEY", "conjunto": nome, "k": k, "pre": pre,
                         "rev": rev, "lo": lo, "material": m})
        if fase != "A":
            continue
        hx = d.hex()
        for forma, pwb in (("HEXUP", hx.upper().encode()),
                           ("SHA2X2", hashlib.sha256(hx.encode()).hexdigest().encode()),
                           ("RAW32", d)):
            for bn, algo, p in aes_celulas(pwb):
                pads.append({"blob": bn, "kdf": algo, "forma": forma, "printable": round(G.printable(p), 3),
                             "hex": p.hex() if bn != "COSMIC" else p[:64].hex(),
                             "tarefa": f"{nome}/k{k}/{'pad' if pre else 'trunc'}/rev{rev}/{'lo' if lo else 'as'}"})
                if G.semantic(p):
                    hits.append({"tipo": "SEMANTICO", "blob": bn, "kdf": algo, "forma": forma,
                                 "material": m, "hex": p.hex()})
            n_aes += 6
    return ({"conjunto": nome, "k": k, "preencher": pre, "rev_mask": rev, "minusculo": lo,
             "n_pw": len(hs), "n_aes_novas_formas": n_aes, "pads_novas_formas": len(pads),
             "seg": round(time.time() - t0, 1)},
            np.asarray(hs, dtype=np.uint64), hits, pads)


# ------------------------------------------------------------------ STAGE 2: k in {5..9} (lacuna c)
def _stage2(args):
    nome, k, pre, rev, lo = args
    n_pw = n_aes = np_ok = 0
    hits = []
    pads = []
    for m in materiais(CONJ[nome], k, pre, rev, lo):
        n_pw += 1
        mb = m.encode("utf-8", "surrogatepass")
        d = hashlib.sha256(mb).digest()
        if priv_ok(d):
            hits.append({"tipo": "PRIVKEY", "conjunto": nome, "k": k, "material": m})
        for pwb in (mb, d.hex().encode()):
            for bn, algo, p in aes_celulas(pwb):
                np_ok += 1
                pads.append({"blob": bn, "kdf": algo, "k": k,
                             "hex": p.hex() if bn != "COSMIC" else p[:64].hex()})
                if G.semantic(p):
                    hits.append({"tipo": "SEMANTICO", "blob": bn, "kdf": algo, "k": k,
                                 "material": m, "hex": p.hex()})
            n_aes += 6
    return ({"conjunto": nome, "k": k, "preencher": pre, "rev_mask": rev, "minusculo": lo,
             "n_pw": n_pw, "n_aes": n_aes, "pads": np_ok}, hits, pads)


# ------------------------------------------------------------------ STAGE 3: nulo casado (meu)
ALFA_GLOBAL = "".join(S0)


def _nulo(semente):
    """Randomizacao DIFERENTE da do agente: cada operando e resorteado do multiconjunto GLOBAL de
    caracteres dos sete (preserva o comprimento de cada fio e a composicao global)."""
    rng = random.Random(1_000_000 + semente)
    partes = ["".join(rng.choice(ALFA_GLOBAL) for _ in range(len(p))) for p in S0]
    n_aes = pads = 0
    for pre in (True, False):
        for rev in (0, 127):
            for lo in (False, True):
                for m in materiais(partes, 1, pre, rev, lo):
                    for pwb in (m.encode("utf-8", "surrogatepass"),
                                hashlib.sha256(m.encode("utf-8", "surrogatepass")).hexdigest().encode()):
                        for bn, algo, salt, ct in CELLS:
                            kk, ivv = evp2(pwb, salt, algo)
                            if unpad2(AES.new(kk, AES.MODE_CBC, ivv).decrypt(ct)) is not None:
                                pads += 1
                            n_aes += 1
    return {"semente": semente, "n_aes": n_aes, "pads": pads}


# ------------------------------------------------------------------ STAGE 4: re-varredura do log
def _retro(lote):
    res = {"n": 0, "sem": 0, "nested": 0, "ebc_max": 0.0, "pr_max": 0.0, "janelas": 0}
    hits = []
    for rec in lote:
        p = bytes.fromhex(rec["hex"])
        res["n"] += 1
        res["pr_max"] = max(res["pr_max"], G.printable(p))
        e = G.ebcdic_sig(p)
        res["ebc_max"] = max(res["ebc_max"], e)
        if G.nested_blob(p):
            res["nested"] += 1
            hits.append({"tipo": "NESTED", **rec})
        if G.semantic(p):
            res["sem"] += 1
            hits.append({"tipo": "SEMANTICO", **rec})
        if e >= 0.75:
            hits.append({"tipo": "EBCDIC", "ebc": round(e, 3), **rec})
        if len(p) >= 32:
            res["janelas"] += 2 * (len(p) - 31)
            a = scan_janelas(p)
            if a:
                hits.append({"tipo": "PRIVKEY_NO_PLAINTEXT", "achados": a, **rec})
    return res, hits


# ------------------------------------------------------------------ STAGE 4b: COSMIC inteiro
CELLS_COSMIC = [c for c in CELLS if c[0] == "COSMIC"]


def _cosmic(args):
    """O log do agente so tem 64 B de cada plaintext COSMIC (1328 B). Regenero as celulas COSMIC
    (2 formas x 2 KDF) de cada tarefa e passo o oraculo completo — incluindo privkey em TODAS
    as 1.297 janelas de 32 B, nas duas ordens — no plaintext inteiro."""
    nome, k, pre, rev, lo = args
    res = {"n_aes": 0, "pads": 0, "janelas": 0, "sem": 0, "nested": 0, "ebc_max": 0.0, "pr_max": 0.0}
    hits = []
    for m in materiais(CONJ[nome], k, pre, rev, lo):
        mb = m.encode("utf-8", "surrogatepass")
        for pwb in (mb, hashlib.sha256(mb).hexdigest().encode()):
            for bn, algo, salt, ct in CELLS_COSMIC:
                kk, ivv = evp2(pwb, salt, algo)
                p = unpad2(AES.new(kk, AES.MODE_CBC, ivv).decrypt(ct))
                res["n_aes"] += 1
                if p is None:
                    continue
                res["pads"] += 1
                res["pr_max"] = max(res["pr_max"], G.printable(p))
                e = G.ebcdic_sig(p)
                res["ebc_max"] = max(res["ebc_max"], e)
                if G.nested_blob(p):
                    res["nested"] += 1
                if G.semantic(p) or e >= 0.75:
                    res["sem"] += 1
                    hits.append({"tipo": "SEMANTICO_COSMIC", "kdf": algo, "material": m, "hex": p.hex()})
                res["janelas"] += 2 * (len(p) - 31)
                a = scan_janelas(p)
                if a:
                    hits.append({"tipo": "PRIVKEY_NO_PLAINTEXT_COSMIC", "achados": a,
                                 "material": m, "hex": p.hex()})
    return res, hits


# ------------------------------------------------------------------ STAGE 4c: operando (5) verbatim
# README linha 538: "the password is THEMATRIXHASYOU" — MAIUSCULO. O agente usou "thematrixhasyou"
# no ramo "como esta", logo o operando verbatim nunca entrou em material algum (o ramo "minusculo"
# e identico ao dele e nao se repete). Fases A (k 1..4, rev 0/127) e B (k 1..2, rev 1..126) de S0.
S0_UP5 = [O1, O2, O3, O4, "THEMATRIXHASYOU", O6, O7]


def _o5up(args):
    k, pre, rev = args
    res = {"n_pw": 0, "n_aes": 0, "pads": 0, "janelas": 0}
    hits, regs = [], []
    for m in materiais(S0_UP5, k, pre, rev, False):
        res["n_pw"] += 1
        mb = m.encode("utf-8", "surrogatepass")
        d = hashlib.sha256(mb).digest()
        if priv_ok(d):
            hits.append({"tipo": "PRIVKEY", "conjunto": "S0_up5", "k": k, "material": m})
        for forma, pwb in (("raw", mb), ("sha256hex", d.hex().encode())):
            for bn, algo, p in aes_celulas(pwb):
                res["pads"] += 1
                regs.append({"blob": bn, "kdf": algo, "forma": forma, "k": k, "pre": pre, "rev": rev,
                             "printable": round(G.printable(p), 3),
                             "hex": p.hex() if bn != "COSMIC" else p[:64].hex()})
                res["janelas"] += 2 * (len(p) - 31)
                a = scan_janelas(p)
                if G.semantic(p) or a:
                    hits.append({"tipo": "SEMANTICO/PRIV_NO_PT", "blob": bn, "kdf": algo, "forma": forma,
                                 "material": m, "hex": p.hex(), "achados": a})
            res["n_aes"] += 6
    return res, hits, regs


# ------------------------------------------------------------------ STAGE 5: verificacao amostral
def _verif(args):
    """Re-roda tarefas do agente com pipeline 100% independente e conta paddings."""
    nome, k, pre, rev, lo = args
    n_pw = n_aes = pads = 0
    for m in materiais(CONJ[nome], k, pre, rev, lo):
        n_pw += 1
        mb = m.encode("utf-8", "surrogatepass")
        for pwb in (mb, hashlib.sha256(mb).hexdigest().encode()):
            for bn, algo, salt, ct in CELLS:
                kk, ivv = evp2(pwb, salt, algo)
                if unpad2(AES.new(kk, AES.MODE_CBC, ivv).decrypt(ct)) is not None:
                    pads += 1
                n_aes += 1
    return {"conjunto": nome, "k": k, "preencher": pre, "rev_mask": rev, "minusculo": lo,
            "n_pw": n_pw, "n_aes": n_aes, "pads": pads}


# ------------------------------------------------------------------ estatistica
def z_pad(pads, n, p=P_PAD):
    if not n:
        return 0.0
    return (pads - n * p) / math.sqrt(n * p * (1 - p))


def cauda_binomial(n, p, kmin):
    return sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(kmin, n + 1))


def controle_positivo():
    salt, ct = G._parse(G.PHASE2_B64)
    k, iv = evp2(hashlib.sha256(b"causality").hexdigest().encode(), salt, "sha256")
    p = unpad2(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
    assert p and p[:10] == b"The ironic", "CONTROLE POSITIVO FALHOU"
    return p[:52].decode("latin-1")


# ------------------------------------------------------------------ main
def tarefas_agente():
    """As 1.904 tarefas do agente, reconstruidas a partir da especificacao do script dele."""
    A = [(n, k, pr, rm, lo, "A") for n in CONJ for k in (1, 2, 3, 4)
         for pr in (True, False) for rm in (0, 127) for lo in (False, True)]
    B = [("S0_atlas", k, pr, rm, lo, "B") for k in (1, 2)
         for pr in (True, False) for rm in range(1, 127) for lo in (False, True)]
    return A + B


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="all",
                    choices=["all", "repro", "k59", "nulo", "retro", "cosmic", "verif", "o5up"])
    ap.add_argument("--workers", type=int, default=18)
    ap.add_argument("--nulo", type=int, default=120)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    ctrl = controle_positivo()
    print("CONTROLE POSITIVO (EVP/unpad reimplementados):", ctrl, flush=True)
    R = {"controle_positivo": ctrl, "P_pad_teorico": P_PAD}
    t_ini = time.time()
    hits_todos = []

    # ---------------- estatistica fechada sobre os numeros do agente (nao precisa rodar nada)
    sm = json.load(open(os.path.join(DIR_AG, "summary.json"), encoding="utf-8"))
    n, kp = sm["totais"]["aes"], sm["totais"]["paddings"]
    R["auditoria_z"] = {"aes": n, "pads": kp,
                        "z_vs_1_256": round(z_pad(kp, n, 1 / 256), 3),
                        "z_vs_sigma_1_16": round(z_pad(kp, n, P_PAD), 3),
                        "vies_sistematico_em_n": round(math.sqrt(n) * (P_PAD - 1 / 256) /
                                                       math.sqrt(P_PAD * (1 - P_PAD)), 3)}
    print("auditoria z:", R["auditoria_z"], flush=True)

    if a.stage in ("all", "verif"):
        rng = random.Random(7)
        amostra = rng.sample(tarefas_agente(), 24)
        with Pool(a.workers) as pool:
            got = pool.map(_verif, [(t[0], t[1], t[2], t[3], t[4]) for t in amostra])
        ind = {(g["conjunto"], g["k"], g["preencher"], g["rev_mask"], g["minusculo"]): g for g in got}
        conf = []
        for t in sm["tarefas"]:
            key = (t["conjunto"], t["k"], t["preencher"], t["rev_mask"], t["minusculo"])
            if key in ind:
                g = ind[key]
                conf.append({"tarefa": "/".join(map(str, key)), "n_pw_ag": t["n_pw"], "n_pw_meu": g["n_pw"],
                             "pads_ag": t["pads"], "pads_meu": g["pads"],
                             "bate": t["n_pw"] == g["n_pw"] and t["pads"] == g["pads"]})
        R["verificacao_amostral"] = {"tarefas": len(conf), "todas_batem": all(c["bate"] for c in conf),
                                     "detalhe": conf}
        print(f"verificacao amostral: {len(conf)} tarefas, todas batem="
              f"{R['verificacao_amostral']['todas_batem']}", flush=True)

    if a.stage in ("all", "repro"):
        print("STAGE repro: 1.904 tarefas, dedup global + privkey em TODO material + 3 formas novas (fase A)",
              flush=True)
        tl = tarefas_agente()
        hashes = []
        resumo = []
        pads_novos = []
        t0 = time.time()
        with Pool(a.workers) as pool:
            for i, (r, hs, hh, pp) in enumerate(pool.imap_unordered(_stage1, tl, chunksize=1)):
                resumo.append(r); hashes.append(hs); pads_novos.extend(pp)
                for h in hh:
                    print("!!! HIT DURO:", json.dumps(h)[:300], flush=True)
                    hits_todos.append(h)
                if (i + 1) % 200 == 0:
                    print(f"  {i+1}/{len(tl)}  {time.time()-t0:.0f}s", flush=True)
        todos = np.concatenate(hashes)
        uniq = np.unique(todos)
        conf_ag = {(t["conjunto"], t["k"], t["preencher"], t["rev_mask"], t["minusculo"]): t["n_pw"]
                   for t in sm["tarefas"]}
        divergentes = [r for r in resumo
                       if conf_ag.get((r["conjunto"], r["k"], r["preencher"], r["rev_mask"],
                                       r["minusculo"])) != r["n_pw"]]
        n_aes_nv = sum(r["n_aes_novas_formas"] for r in resumo)
        R["repro"] = {
            "tarefas": len(resumo),
            "n_pw_por_tarefa_somado": int(todos.size),
            "n_pw_agente": sm["totais"]["materiais_distintos_por_tarefa_somados"],
            "tarefas_com_contagem_divergente": len(divergentes),
            "divergentes": divergentes[:10],
            "materiais_GLOBALMENTE_distintos": int(uniq.size),
            "fator_de_inflacao": round(todos.size / max(1, uniq.size), 4),
            "privkeys_varridas": int(todos.size),
            "privkeys_agente": sm["totais"]["privkeys_testadas"],
            "novas_formas": {"formas": list(FORMAS_NOVAS), "aes": n_aes_nv,
                             "pads": len(pads_novos),
                             "z_vs_sigma": round(z_pad(len(pads_novos), n_aes_nv), 3)},
            "seg": round(time.time() - t0, 1),
        }
        print(json.dumps(R["repro"], indent=1)[:1500], flush=True)
        with gzip.open(os.path.join(OUT, "pads_formas_novas.jsonl.gz"), "wt", encoding="utf-8") as f:
            for p in pads_novos:
                f.write(json.dumps(p) + "\n")

    if a.stage in ("all", "k59"):
        print("STAGE k59: blocos k in {5..9} nos 28 conjuntos (lacuna c do agente)", flush=True)
        tl = [(n, k, pr, rm, lo) for n in CONJ for k in (5, 6, 7, 8, 9)
              for pr in (True, False) for rm in (0, 127) for lo in (False, True)]
        t0 = time.time(); res = []; pads5 = []
        with Pool(a.workers) as pool:
            for i, (r, hh, pp) in enumerate(pool.imap_unordered(_stage2, tl, chunksize=1)):
                res.append(r); pads5.extend(pp)
                for h in hh:
                    print("!!! HIT DURO:", json.dumps(h)[:300], flush=True)
                    hits_todos.append(h)
                if (i + 1) % 200 == 0:
                    print(f"  {i+1}/{len(tl)}  {time.time()-t0:.0f}s", flush=True)
        tot_pw = sum(r["n_pw"] for r in res); tot_aes = sum(r["n_aes"] for r in res)
        tot_pad = sum(r["pads"] for r in res)
        R["k59"] = {"tarefas": len(res), "materiais": tot_pw, "aes": tot_aes, "privkeys": tot_pw,
                    "pads": tot_pad, "z_vs_sigma": round(z_pad(tot_pad, tot_aes), 3),
                    "seg": round(time.time() - t0, 1)}
        print(json.dumps(R["k59"], indent=1), flush=True)
        with gzip.open(os.path.join(OUT, "pads_k59.jsonl.gz"), "wt", encoding="utf-8") as f:
            for p in pads5:
                f.write(json.dumps(p) + "\n")

    if a.stage in ("all", "retro"):
        print("STAGE retro: oraculo completo nos 428.706 plaintexts do agente", flush=True)
        t0 = time.time()

        def lotes():
            lote = []
            with gzip.open(os.path.join(DIR_AG, "paddings.jsonl.gz"), "rt", encoding="utf-8") as f:
                for line in f:
                    r = json.loads(line)
                    lote.append({"hex": r["hex"], "blob": r["blob"], "kdf": r["kdf"],
                                 "tarefa": r["tarefa"], "trunc": r.get("trunc", False),
                                 "printable": r["printable"]})
                    if len(lote) >= 1500:
                        yield lote; lote = []
            if lote:
                yield lote

        agg = {"n": 0, "sem": 0, "nested": 0, "ebc_max": 0.0, "pr_max": 0.0, "janelas": 0}
        retro_hits = []
        with Pool(a.workers) as pool:
            for j, (r, hh) in enumerate(pool.imap_unordered(_retro, lotes(), chunksize=1)):
                for k2 in ("n", "sem", "nested", "janelas"):
                    agg[k2] += r[k2]
                agg["ebc_max"] = max(agg["ebc_max"], r["ebc_max"])
                agg["pr_max"] = max(agg["pr_max"], r["pr_max"])
                retro_hits.extend(hh)
                if (j + 1) % 50 == 0:
                    print(f"  {agg['n']:,} plaintexts  {time.time()-t0:.0f}s", flush=True)
        R["retro"] = {**agg, "ebc_max": round(agg["ebc_max"], 3), "pr_max": round(agg["pr_max"], 3),
                      "hits": retro_hits[:20], "n_hits": len(retro_hits),
                      "seg": round(time.time() - t0, 1),
                      "obs": "COSMIC so tem 64 B logados (o agente truncou 143.225/143.225): "
                             "a varredura de janelas cobre 33 de 1.297 janelas por plaintext COSMIC"}
        hits_todos.extend(retro_hits)
        print(json.dumps({k: v for k, v in R["retro"].items() if k != "hits"}, indent=1), flush=True)

    if a.stage in ("all", "cosmic"):
        print("STAGE cosmic: regenera as celulas COSMIC das 1.904 tarefas; janelas de 32 B no plaintext "
              "INTEIRO (1.297 x 2 ordens)", flush=True)
        t0 = time.time()
        tl = [(t[0], t[1], t[2], t[3], t[4]) for t in tarefas_agente()]
        agg = {"n_aes": 0, "pads": 0, "janelas": 0, "sem": 0, "nested": 0, "ebc_max": 0.0, "pr_max": 0.0}
        c_hits = []
        with Pool(a.workers) as pool:
            for j, (r, hh) in enumerate(pool.imap_unordered(_cosmic, tl, chunksize=1)):
                for k2 in ("n_aes", "pads", "janelas", "sem", "nested"):
                    agg[k2] += r[k2]
                agg["ebc_max"] = max(agg["ebc_max"], r["ebc_max"])
                agg["pr_max"] = max(agg["pr_max"], r["pr_max"])
                for h in hh:
                    print("!!! HIT DURO:", json.dumps(h)[:300], flush=True)
                c_hits.extend(hh)
                if (j + 1) % 200 == 0:
                    print(f"  {j+1}/{len(tl)}  AES={agg['n_aes']:,} pads={agg['pads']:,} "
                          f"janelas={agg['janelas']:,}  {time.time()-t0:.0f}s", flush=True)
        R["cosmic_inteiro"] = {**agg, "ebc_max": round(agg["ebc_max"], 3), "pr_max": round(agg["pr_max"], 3),
                               "pads_agente_COSMIC": 143225, "n_hits": len(c_hits),
                               "z_vs_sigma": round(z_pad(agg["pads"], agg["n_aes"]), 3),
                               "seg": round(time.time() - t0, 1)}
        hits_todos.extend(c_hits)
        print(json.dumps(R["cosmic_inteiro"], indent=1), flush=True)

    if a.stage in ("o5up",):
        print("STAGE o5up: S0 com (5)=THEMATRIXHASYOU verbatim; fases A+B do agente, oraculo completo",
              flush=True)
        t0 = time.time()
        tl = [(k, pr, rm) for k in (1, 2, 3, 4) for pr in (True, False) for rm in (0, 127)]
        tl += [(k, pr, rm) for k in (1, 2) for pr in (True, False) for rm in range(1, 127)]
        agg = {"n_pw": 0, "n_aes": 0, "pads": 0, "janelas": 0}
        u_hits = []
        with gzip.open(os.path.join(OUT, "pads_o5up.jsonl.gz"), "wt", encoding="utf-8") as f, \
                Pool(a.workers) as pool:
            for j, (r, hh, regs) in enumerate(pool.imap_unordered(_o5up, tl, chunksize=1)):
                for k2 in agg:
                    agg[k2] += r[k2]
                for g in regs:
                    f.write(json.dumps(g) + "\n")
                for h in hh:
                    print("!!! HIT DURO:", json.dumps(h)[:300], flush=True)
                u_hits.extend(hh)
                if (j + 1) % 100 == 0:
                    print(f"  {j+1}/{len(tl)}  AES={agg['n_aes']:,} pads={agg['pads']:,}  "
                          f"{time.time()-t0:.0f}s", flush=True)
        R["o5up"] = {**agg, "tarefas": len(tl), "n_hits": len(u_hits),
                     "z_vs_sigma": round(z_pad(agg["pads"], agg["n_aes"]), 3),
                     "seg": round(time.time() - t0, 1)}
        hits_todos.extend(u_hits)
        print(json.dumps(R["o5up"], indent=1), flush=True)
        # nao sobrescreve o resumo principal: grava em arquivo proprio
        with open(os.path.join(OUT, "resumo_o5up.json"), "w", encoding="utf-8") as f:
            json.dump(R, f, ensure_ascii=False, indent=1)
        return

    if a.stage in ("all", "nulo"):
        print(f"STAGE nulo: {a.nulo} replicas (resorteio do multiconjunto global)", flush=True)
        t0 = time.time(); nl = []
        with Pool(a.workers) as pool:
            for j, r in enumerate(pool.imap_unordered(_nulo, range(a.nulo), chunksize=1)):
                nl.append(r)
                if (j + 1) % 40 == 0:
                    print(f"  nulo {j+1}/{a.nulo}  {time.time()-t0:.0f}s", flush=True)
        taxas = [x["pads"] / x["n_aes"] for x in nl]
        mu = sum(taxas) / len(taxas)
        sd = (sum((t - mu) ** 2 for t in taxas) / (len(taxas) - 1)) ** 0.5
        real = [0, 0]
        for t in sm["tarefas"]:
            if t["conjunto"] == "S0_atlas" and t["k"] == 1 and t["rev_mask"] in (0, 127):
                real[0] += t["pads"]; real[1] += t["n_aes"]
        tr = real[0] / real[1]
        R["nulo"] = {"replicas": len(nl), "aes_por_replica": nl[0]["n_aes"],
                     "aes_total": sum(x["n_aes"] for x in nl),
                     "taxa_media": round(mu, 7), "sd": round(sd, 7),
                     "taxa_teorica_sigma": round(P_PAD, 7), "taxa_1_256": round(1 / 256, 7),
                     "z_da_media_do_nulo_vs_sigma": round(
                         (mu - P_PAD) / (sd / math.sqrt(len(nl))), 3),
                     "taxa_real_S0_k1_faseA": round(tr, 7),
                     "z_real_vs_nulo": round((tr - mu) / sd, 3),
                     "seg": round(time.time() - t0, 1)}
        print(json.dumps(R["nulo"], indent=1), flush=True)

    # ---------------- look-elsewhere do teto de printable (calculo fechado)
    le = {}
    for frac, nrec, nome in ((0.646, 142606, "SMALL"), (0.633, 142875, "TAIL32")):
        kmin = math.ceil(frac * 79)
        p = cauda_binomial(79, 95 / 256, kmin)
        le[nome] = {"max_observado": frac, "limiar_bytes": f"{kmin}/79", "P_por_plaintext": p,
                    "esperados_no_blob": round(p * nrec, 4),
                    "P_de_ver_ao_menos_um": round(1 - math.exp(-p * nrec), 4),
                    "P_no_conjunto_SMALL+TAIL32": round(1 - math.exp(-p * 285481), 4)}
    pc = 1327
    mu_c, sd_c = 95 / 256, math.sqrt((95 / 256) * (1 - 95 / 256) / pc)
    le["COSMIC"] = {"max_observado": 0.428, "z_normal": round((0.428 - mu_c) / sd_c, 2),
                    "esperados_no_blob": round(143225 * 0.5 * math.erfc((0.428 - mu_c) / sd_c / math.sqrt(2)), 3)}
    R["look_elsewhere_printable"] = le
    print("look-elsewhere printable:", json.dumps(le, indent=1), flush=True)

    R["hits_duros_totais"] = hits_todos
    R["segundos_totais"] = round(time.time() - t_ini, 1)
    with open(os.path.join(OUT, "resumo_critico.json"), "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    with open(os.path.join(OUT, "hits.jsonl"), "w", encoding="utf-8") as f:
        for h in hits_todos:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")
    print("HITS DUROS TOTAIS:", len(hits_todos), " tempo:", R["segundos_totais"], "s")


def _autoteste():
    """ponytail: um unico check runnable que quebra se a logica critica quebrar."""
    # 1. minha tranca == a do agente (importo o script dele e comparo em 2000 casos aleatorios)
    sys.path.insert(0, os.path.join(REPO, "solver", "operador_ensinado_2026_09_17"))
    import familia3_entrelacamento as F
    rng = random.Random(0)
    for _ in range(2000):
        ps = ["".join(rng.choice("abcXY9") for _ in range(rng.randint(1, 12)))
              for _ in range(rng.randint(2, 7))]
        k = rng.randint(1, 5); pre = rng.random() < 0.5
        assert tranca(ps, k, pre) == F.trancar(list(ps), k, pre), (ps, k, pre)
    # 2. meus conjuntos == os dele
    assert {k: v for k, v in CONJ.items()} == {k: v for k, v in F.CONJ.items()}
    # 3. EVP/unpad reimplementados == os do kit, e o controle positivo passa
    from Crypto.Hash import SHA256 as _S
    salt, ct = G.BLOBS["SMALL"]
    assert evp2(b"zz", salt, "sha256") == G.evp(b"zz", salt, _S)
    assert controle_positivo().startswith("The ironic")
    # 4. probabilidade de padding: a regra 1..16 da 1/255, nao 1/256
    assert abs(P_PAD - 1 / 255) < 1e-12 and abs(P_PAD - 1 / 256) > 1e-5
    # 5. oraculo duro: a privkey do genesis NAO bate; um ponto plantado bate
    assert not priv_ok(bytes(31) + b"\x01")
    import os as _o
    sec = hashlib.sha256(b"plantado").digest()
    global TGT
    velho = TGT
    TGT = PublicKey.from_valid_secret(sec).format(False)
    assert priv_ok(sec) and scan_janelas(b"\x00" * 8 + sec + b"\x00" * 8)
    assert scan_janelas(b"\x00" * 8 + sec[::-1] + b"\x00" * 8)   # ordem de byte invertida
    TGT = velho
    # 6. caminho do SEGUNDO endereco (17ucy): planto o h160 comprimido de outra chave
    global H160_B
    sec2 = hashlib.sha256(b"plantado-17ucy").digest()
    velho_b = H160_B
    H160_B = _h160(PublicKey.from_valid_secret(sec2).format(True))
    assert priv_ok(sec2) and not priv_ok(sec)
    H160_B = velho_b
    assert not priv_ok(sec2)
    _o.environ.pop("_", None)
    print("autoteste OK")


if __name__ == "__main__":
    if "--autoteste" in sys.argv:
        _autoteste()
    else:
        main()
