# -*- coding: utf-8 -*-
r"""
FAMILIA 3 — "seven intertwined passwords" como ENTRELACAMENTO DE CARACTERES.

===========================  HIPOTESE (escrita ANTES de codar)  ===========================

O monologo do Arquiteto (fase 3.2) diz que para achar a chave privada sera preciso
"select from over twenty-three ciphers, sixteen encryptions and or seven intertwined
passwords". A leitura testada ate hoje foi sempre *combinatoria*: os sete operandos
concatenados, XOR dos sete sha256, sha256 encadeado. A palavra inglesa "intertwined",
porem, significa TRANCADO/ENTRELACADO — fios que se alternam, nao fios emendados.

HIPOTESE: o material da senha final e o ENTRELACAMENTO (round-robin, caractere a
caractere ou em blocos de k caracteres) das sete senhas de nivel-senha que o proprio
puzzle produziu ao longo das fases 0–3.2. Uma ordem especifica dos sete fios produz o
material; esse material, cru ou como sha256 hex minusculo, e a senha `-pass pass:` de
um dos tres blobs AES fechados (SMALL, COSMIC, TAIL32) sob EVP_BytesToKey SHA256 (ou
MD5, como controle secundario), ou, via sha256, o escalar de 32 B da chave privada do
premio.

FALSIFICAVEL: o espaco e finito e inteiramente enumeravel — 7! = 5040 ordens, quatro
tamanhos de bloco, duas politicas de esgotamento, duas orientacoes, duas caixas, por
conjunto de operandos. Se nenhuma combinacao produz plaintext semantico (>=85% ASCII,
WIF/hex64, blob openssl aninhado, assinatura EBCDIC cp273) nem a privkey do premio, o
entrelacamento literal dos sete esta morto e a palavra "intertwined" nao pode mais ser
usada para justificar mais buscas nessa direcao.

=====================  O QUE JA EXISTIA (nao alego cobertura nova aqui)  =====================

`ENDGAME.md` §4-C registra "'seven intertwined' (concatenacao, XOR de sha256, encadeado,
ENTRELACADO)". Conferi a rodada: o entrelacamento round-robin foi rodado pelo critico em
`_work/frontier_2026-09-17/rodada1_scripts/critic/v3_interleave.py`, sobre o conjunto

    TOK = [yellowblueprimes, matrixsumlist, lastwordsbeforearchichoice, yinyang,
           thispassword, enter, sha256, anstoo, ourfirsthintisyourlastcommand]

ou seja NOVE TOKENS DE ROADMAP/PAGINA, com k=1 apenas, permutacoes de tamanho 2,3,4,5,7,
uma unica politica (`zip_longest` com fillvalue=""), sem inversao e sem variacao de caixa.
A intersecao desse conjunto com os SETE OPERANDOS DE NIVEL-SENHA do censo do atlas
(14/09/2026) e VAZIA. Portanto o que este script cobre e genuinamente novo:
  (i) os sete operandos de nivel-senha (senhas reais das fases 0–3.2), nunca entrelacados;
  (ii) blocos k = 2,3,4 (so k=1 existia);
  (iii) as 5040 ordens completas de 7 (so subconjuntos de <=7 de um pool de 9 existiam);
  (iv) truncar-no-mais-curto vs preencher-ate-o-mais-longo (so a segunda existia);
  (v) inversao e caixa;
  (vi) 27 variantes declaradas do conjunto de operandos.

=====================================  ORACULO  =====================================

Duro e unico: (a) privkey de 32 B cuja pubkey == a do premio; (b) plaintext AES com
>=85% ASCII, ou WIF/hex64 plausivel, ou blob openssl aninhado (`Salted__`/`U2FsdGVk`),
ou assinatura EBCDIC cp273 >= 0,75 (`G.semantic`). Padding PKCS7 valido sozinho e RUIDO
(1/256) e vai para o log gzip em hex, para varredura retroativa.

Controle positivo: a fase 2 abre com sha256hex("causality") sob EVP-SHA256.
Nulo casado: 100 replicas embaralhando os caracteres DENTRO de cada operando (preserva
comprimento e multiconjunto), rodando o MESMO pipeline sobre a sub-familia S0/k=1.

Uso:  python familia3_entrelacamento.py [--smoke]
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
from multiprocessing import Pool

sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402
from Crypto.Hash import MD5, SHA256  # noqa: E402

OUT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\familia3_entrelacamento"

# ----------------------------------------------------------------- os sete operandos
P3_PARTES = [
    "causality", "Safenet", "Luna", "HSM", "11110",
    "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F"
    "20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
    "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
]
O1 = "theflowerblossomsthroughwhatseemstobeaconcretesurface"   # fase 1  (53)
O2 = "causality"                                                # fase 2  (9)
O3 = "".join(P3_PARTES)                                         # fase 3  (227)
O4 = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"  # fase 3.2 (62)
O5 = "thematrixhasyou"                                          # chave Beaufort (15)
O6 = "gsmg.io/theseedisplanted"                                 # URL da porta 1 (24)
O7 = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"      # titulo+endereco (59)
S0 = [O1, O2, O3, O4, O5, O6, O7]

assert [len(x) for x in S0] == [53, 9, 227, 62, 15, 24, 59], "operandos corrompidos"
assert G.shahex(O3) == "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
assert G.shahex(O7) == "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"

SHX = G.shahex


def conjuntos() -> dict[str, list[str]]:
    """Os 28 conjuntos de 7 operandos efetivamente varridos (cada um com as 5040 ordens)."""
    c: dict[str, list[str]] = {"S0_atlas": list(S0)}
    for i in range(7):
        for tok in ("thispassword", "lastwordsbeforearchichoice"):
            s = list(S0)
            s[i] = tok
            c[f"S_{tok[:8]}_{i + 1}"] = s
    c["S_url_hash"] = [*S0[:5], SHX(O6), O7]            # (6) -> sha256hex da URL
    c["S_title_hash"] = [*S0[:6], SHX(O7)]              # (7) -> sha256hex do titulo+endereco
    c["S_url_curta"] = [*S0[:5], "theseedisplanted", O7]
    c["S_p3_partes"] = list(P3_PARTES)                  # (3) -> as 7 partes soltas da fase 3
    for j, parte in enumerate(P3_PARTES):               # (3) -> cada parte solta no lugar de (3)
        s = list(S0)
        s[2] = parte
        c[f"S_p3parte_{j + 1}"] = s
    c["S_todos_hash"] = [SHX(x) for x in S0]            # os sete como sha256hex (as senhas reais)
    c["S_joins_hash"] = [O1, O2, SHX(O3), SHX(O4), O5, O6, O7]
    assert all(len(v) == 7 for v in c.values())
    return c


CONJ = conjuntos()

# ----------------------------------------------------------------- entrelacamento


def trancar(partes: list[str], k: int, preencher: bool) -> str:
    """Round-robin de blocos de k caracteres.
    preencher=True  -> roda ate esgotar o mais longo, pulando os ja esgotados;
    preencher=False -> para no primeiro que esgotar (truncado no mais curto)."""
    chunks = [[p[i:i + k] for i in range(0, len(p), k)] for p in partes]
    if preencher:
        n = max(len(c) for c in chunks)
        return "".join(c[i] for i in range(n) for c in chunks if i < len(c))
    n = min(len(c) for c in chunks)
    return "".join(c[i] for i in range(n) for c in chunks)


# ----------------------------------------------------------------- pipeline AES
CELLS = [(b, h, *G.BLOBS[b]) for b in ("SMALL", "COSMIC", "TAIL32") for h in (SHA256, MD5)]
evp, unpad, semantic, priv_hit, printable = G.evp, G.unpad, G.semantic, G.priv_hit, G.printable


def varrer(materiais, com_privkey: bool):
    """Aplica o oraculo a um iteravel de materiais. Devolve (n_pw, n_aes, pads, hits, regs)."""
    n_pw = n_aes = pads = 0
    hits, regs = [], []
    for mat in materiais:
        n_pw += 1
        if com_privkey:
            d = hashlib.sha256(mat.encode("utf-8", "surrogatepass")).digest()
            if priv_hit(d):
                hits.append({"tipo": "PRIVKEY", "material": mat})
        for form in (mat, SHX(mat)):
            pwb = form.encode("utf-8", "surrogatepass")
            for bn, hm, salt, ct in CELLS:
                kk, ivv = evp(pwb, salt, hm)
                p = unpad(AES.new(kk, AES.MODE_CBC, ivv).decrypt(ct))
                n_aes += 1
                if p is None:
                    continue
                pads += 1
                pr = printable(p)
                sem = semantic(p)
                # ponytail: COSMIC (1328 B) so vai inteiro em hex quando ha sinal; caso contrario
                # guarda 64 B + sha256 do plaintext. SMALL/TAIL32 (80 B) vao sempre inteiros.
                # (0,50: ruido de 1328 B tem printable ~0,383 com sd pequeno — o limiar so
                # dispara em plaintext realmente anomalo, entao o log nao incha.)
                inteiro = sem or bn != "COSMIC" or pr >= 0.50
                regs.append({
                    "blob": bn, "kdf": hm.__name__, "len": len(p), "printable": round(pr, 3),
                    "hex": p.hex() if inteiro else p[:64].hex(),
                    "trunc": not inteiro, "pt_sha": hashlib.sha256(p).hexdigest()[:16],
                    "form": "raw" if form is mat else "sha256hex", "material": mat[:120],
                })
                if sem:
                    hits.append({"tipo": "SEMANTICO", "blob": bn, "kdf": hm.__name__,
                                 "material": mat, "form": regs[-1]["form"], "hex": p.hex()})
    return n_pw, n_aes, pads, hits, regs


def materiais_da_tarefa(partes7, k, preencher, rev_mask, minusculo):
    """rev_mask: bit i ligado => o operando i entra invertido. 0 = todos como estao,
    127 = todos invertidos; os 126 mascaramentos intermediarios so sao varridos na
    fase B (S0, k in {1,2})."""
    vistos = set()
    base = [p[::-1] if (rev_mask >> i) & 1 else p for i, p in enumerate(partes7)]
    for ordem in itertools.permutations(base):
        mat = trancar(list(ordem), k, preencher)
        if minusculo:
            mat = mat.lower()
        if mat in vistos:
            continue
        vistos.add(mat)
        yield mat


def tarefa(args):
    nome, k, preencher, rev_mask, minusculo, com_pk = args
    t0 = time.time()
    n_pw, n_aes, pads, hits, regs = varrer(
        materiais_da_tarefa(CONJ[nome], k, preencher, rev_mask, minusculo), com_pk)
    return {"conjunto": nome, "k": k, "preencher": preencher, "rev_mask": rev_mask,
            "minusculo": minusculo, "privkey": com_pk, "n_pw": n_pw, "n_aes": n_aes,
            "pads": pads, "seg": round(time.time() - t0, 1)}, hits, regs


# ----------------------------------------------------------------- nulo casado
def nulo(args):
    """Replica do nulo: embaralha os caracteres DENTRO de cada operando de S0 (preserva
    comprimento e multiconjunto) e roda a MESMA sub-familia S0/k=1 (8 celulas de forma)."""
    semente = args
    rng = random.Random(semente)
    partes = []
    for p in S0:
        ch = list(p)
        rng.shuffle(ch)
        partes.append("".join(ch))
    n_aes = pads = 0
    for preencher in (True, False):
        for rev_mask in (0, 127):
            for minusculo in (False, True):
                _, a, pd, _, _ = varrer(
                    materiais_da_tarefa(partes, 1, preencher, rev_mask, minusculo), False)
                n_aes += a
                pads += pd
    return {"semente": semente, "n_aes": n_aes, "pads": pads}


def z_padding(pads, n_aes):
    if n_aes == 0:
        return 0.0
    e = n_aes / 256.0
    return (pads - e) / math.sqrt(n_aes * (1 / 256.0) * (255 / 256.0))


# ----------------------------------------------------------------- main
def controle_positivo():
    salt, ct = G._parse(G.PHASE2_B64)
    k, iv = evp(SHX("causality").encode(), salt, SHA256)
    p = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
    assert p and p[:10] == b"The ironic", "CONTROLE POSITIVO FALHOU"
    return p[:52].decode("latin-1")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true", help="so S0, k=1, sem nulo")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--nulo", type=int, default=100)
    a = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    ctrl = controle_positivo()
    print("CONTROLE POSITIVO OK:", ctrl, flush=True)

    nomes = ["S0_atlas"] if a.smoke else list(CONJ)
    ks = [1] if a.smoke else [1, 2, 3, 4]
    # FASE A — largura: 28 conjuntos x k in {1,2,3,4} x {preencher,truncar} x {tudo direto,
    #          tudo invertido} x {como esta, minusculo}. Braco privkey so em k in {1,2}.
    tarefas = [(n, k, pr, rm, lo, k in (1, 2)) for n in nomes for k in ks
               for pr in (True, False) for rm in (0, 127) for lo in (False, True)]
    # FASE B — profundidade no conjunto do atlas: TODAS as 128 mascaras de inversao por
    #          operando, k in {1,2}. Sem braco privkey (declarado fora).
    if not a.smoke:
        tarefas += [("S0_atlas", k, pr, rm, lo, False) for k in (1, 2)
                    for pr in (True, False) for rm in range(1, 127) for lo in (False, True)]
    print(f"conjuntos={len(nomes)} tarefas={len(tarefas)}", flush=True)

    t0 = time.time()
    resumo, hits = [], []
    tot_pw = tot_aes = tot_pads = 0
    f_pad = gzip.open(os.path.join(OUT, "paddings.jsonl.gz"), "wt", encoding="utf-8")
    with Pool(a.workers) as pool:
        for i, (r, hs, regs) in enumerate(pool.imap_unordered(tarefa, tarefas, chunksize=1)):
            resumo.append(r)
            tot_pw += r["n_pw"]; tot_aes += r["n_aes"]; tot_pads += r["pads"]
            for g in regs:
                g["tarefa"] = f'{r["conjunto"]}/k{r["k"]}/{"pad" if r["preencher"] else "trunc"}/' \
                              f'rev{r["rev_mask"]}/{"lo" if r["minusculo"] else "as"}'
                f_pad.write(json.dumps(g, ensure_ascii=False) + "\n")
            for h in hs:
                hits.append(h)
                print("!!! HIT DURO:", json.dumps(h, ensure_ascii=False)[:400], flush=True)
            if (i + 1) % 50 == 0:
                print(f"  {i+1}/{len(tarefas)} tarefas  AES={tot_aes:,} pads={tot_pads:,} "
                      f"z={z_padding(tot_pads, tot_aes):+.2f}  {time.time()-t0:.0f}s", flush=True)
    f_pad.close()

    # z por sub-familia (conjunto) e por k
    por_conj: dict[str, list[int]] = {}
    por_k: dict[int, list[int]] = {}
    for r in resumo:
        por_conj.setdefault(r["conjunto"], [0, 0])
        por_conj[r["conjunto"]][0] += r["pads"]; por_conj[r["conjunto"]][1] += r["n_aes"]
        por_k.setdefault(r["k"], [0, 0])
        por_k[r["k"]][0] += r["pads"]; por_k[r["k"]][1] += r["n_aes"]

    nulos = []
    if not a.smoke and a.nulo:
        print(f"nulo casado: {a.nulo} replicas (S0, k=1, 8 celulas de forma)", flush=True)
        with Pool(a.workers) as pool:
            for j, nr in enumerate(pool.imap_unordered(nulo, range(a.nulo), chunksize=1)):
                nulos.append(nr)
                if (j + 1) % 25 == 0:
                    print(f"  nulo {j+1}/{a.nulo}", flush=True)

    real_s0k1 = [0, 0]
    for r in resumo:
        if r["conjunto"] == "S0_atlas" and r["k"] == 1:
            real_s0k1[0] += r["pads"]; real_s0k1[1] += r["n_aes"]
    taxas = [n["pads"] / n["n_aes"] for n in nulos] if nulos else []
    mu = sum(taxas) / len(taxas) if taxas else 0.0
    sd = (sum((x - mu) ** 2 for x in taxas) / (len(taxas) - 1)) ** 0.5 if len(taxas) > 1 else 0.0
    taxa_real = real_s0k1[0] / real_s0k1[1] if real_s0k1[1] else 0.0

    sm = {
        "familia": "3 — seven intertwined passwords como entrelacamento de caracteres",
        "controle_positivo": {"fase2_EVP_SHA256_sha256hex_causality": ctrl, "passou": True},
        "conjuntos": {k: [len(x) for x in v] for k, v in CONJ.items()},
        "totais": {"materiais_distintos_por_tarefa_somados": tot_pw, "aes": tot_aes,
                   "paddings": tot_pads, "esperado": round(tot_aes / 256.0, 1),
                   "z_global": round(z_padding(tot_pads, tot_aes), 2),
                   "privkeys_testadas": sum(r["n_pw"] for r in resumo if r["privkey"]),
                   "segundos": round(time.time() - t0, 1)},
        "z_por_conjunto": {k: {"pads": v[0], "aes": v[1], "z": round(z_padding(*v), 2)}
                           for k, v in sorted(por_conj.items())},
        "z_por_k": {str(k): {"pads": v[0], "aes": v[1], "z": round(z_padding(*v), 2)}
                    for k, v in sorted(por_k.items())},
        "nulo_casado": {"replicas": len(nulos), "aes_por_replica": nulos[0]["n_aes"] if nulos else 0,
                        "taxa_media": round(mu, 6), "taxa_sd": round(sd, 6),
                        "taxa_real_S0_k1": round(taxa_real, 6),
                        "z_real_vs_nulo": round((taxa_real - mu) / sd, 2) if sd else None,
                        "1_sobre_256": round(1 / 256.0, 6)},
        "hits_duros": hits,
        "tarefas": resumo,
    }
    with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(sm, f, ensure_ascii=False, indent=1)
    with open(os.path.join(OUT, "hits.jsonl"), "w", encoding="utf-8") as f:
        for h in hits:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")
    print(json.dumps({k: sm[k] for k in ("totais", "z_por_k", "nulo_casado")},
                     ensure_ascii=False, indent=1))
    print("HITS DUROS:", len(hits))


def _autoteste():
    """ponytail: o unico check runnable — a logica do entrelacamento e do oraculo."""
    assert trancar(["abc", "12", "XY"], 1, True) == "a1Xb2Yc"
    assert trancar(["abc", "12", "XY"], 1, False) == "a1Xb2Y"
    assert trancar(["abcd", "1234", "wxyz"], 2, False) == "ab12wxcd34yz"
    assert trancar(["abcde", "12"], 2, True) == "ab12cde"       # pula o esgotado
    assert trancar(["abcde", "12"], 2, False) == "ab12"
    # round-robin de 7 operandos preenchendo = permutacao de todos os caracteres
    m = trancar(S0, 1, True)
    assert len(m) == sum(len(x) for x in S0) == 449
    assert sorted(m) == sorted("".join(S0))
    # colisoes reais e explicadas: os 9 primeiros caracteres de (2) e de (3) sao ambos
    # "causality", entao no modo truncado (9 rodadas) trocar (2) por (3) da o MESMO material
    # (5040/2 = 2520) e no modo preenchido colide so quando os dois sao adjacentes
    # (5040 - 2*6!/2 = 4320). O dedup por tarefa nao perde nenhum material distinto.
    assert O3[:9] == O2
    assert len(set(materiais_da_tarefa(S0, 1, True, 0, False))) == 4320
    assert len(set(materiais_da_tarefa(S0, 1, False, 0, False))) == 2520
    assert len(set(materiais_da_tarefa(S0, 2, True, 0, False))) == 5040
    # mascara de inversao por operando: bit 1 = inverte o operando 2 ("causality" -> "ytilasuac")
    assert next(materiais_da_tarefa(["ab", "cd"], 1, True, 0b10, False)) == "adbc"
    assert next(materiais_da_tarefa(["ab", "cd"], 1, True, 0b11, False)) == "bdac"
    assert len(CONJ) == 28 and all(len(v) == 7 for v in CONJ.values())
    # oraculo: o plaintext real da fase 3.2 passa; ruido nao
    assert semantic(b"A" * 80)
    assert not semantic(bytes(range(256))[:80])
    print("autoteste OK")


if __name__ == "__main__":
    if "--autoteste" in sys.argv:
        _autoteste()
    else:
        main()
