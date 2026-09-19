#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Conjunto de senhas RECONSTRUÍVEL do repositório para a frente F1 (modos_fluxo),
enxame 2026-09-19.

Não há acesso ao corpus histórico (466.310 bases / 1,27 M formas) neste clone:
ver _work/enxame_2026-09-19/spec.json, "corpora_ausentes". Este módulo constrói um
conjunto pequeno, DECLARADO e determinístico, a partir de:

  A. operandos de nível-senha provados das fases 0-3.2 (README.md verbatim)
  B. os 7 tokens do roadmap de 2023-02-23 (ENDGAME.md §2)
  C. campos da página SalPhaseIon (dbbi, faed, rótulos, frases)
  D. objetos de ENDGAME.md §6 (resíduos L83/L84, bits dos marcadores, somas da matriz)
  E. tokens do monólogo do Arquiteto (plaintext autêntico da fase 3.2, no README)

Cada base gera até 6 formas (literal, normalizada, e quatro sha256-hex).
`build()` devolve (lista_de_senhas_bytes, metadados_de_cobertura).
"""
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.abspath(os.path.join(HERE, "..", "..", "experiments", "claude_endgame_2026_09_02"))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, KIT)
import gsmg_common as G  # noqa: E402


def sha_hex(s):
    b = s.encode("utf-8") if isinstance(s, str) else s
    return hashlib.sha256(b).hexdigest()


def norm(s):
    """minúsculo, só [a-z0-9] — a normalização que o criador usou (`causalitySafenet...`
    mantém caixa, mas as pré-imagens curtas são minúsculas e sem espaço)."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


# ------------------------------------------------------------------ camada A
# pré-imagens verbatim do README.md (fases 1-3.2) + alvos
P3_PREIMAGE = ("causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F6365"
               "7320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F3330207"
               "3656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1")
P32_PREIMAGE = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
PHASE0_PREIMAGE = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

CAMADA_A = [
    "causality",
    P3_PREIMAGE,
    P32_PREIMAGE,
    "thematrixhasyou",
    "theseedisplanted",
    "gsmg.io/theseedisplanted",
    PHASE0_PREIMAGE,
    "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",  # sha256(causality)
    "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",  # sha256(fase 3)
    "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",  # sha256(fase 3.2)
    "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa",
    "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",  # a URL do endgame
]

# ------------------------------------------------------------------ camada B
ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit",
           "verylaststepisatruegiveawaypromised"]
CAMADA_B = list(ROADMAP) + ["".join(ROADMAP), " ".join(ROADMAP)]

# ------------------------------------------------------------------ camada C
CAMADA_C = [
    "thispassword", "enter", "sha256", "shabef", "shabefanstoo",
    "our first hint is your last command", "sha256 answer too",
    "SalPhaseIon", "Cosmic Duality", "salphaseion", "cosmicduality",
    "salphaseioncosmicduality", "GSMG Puzzle",
    G.DBBI, G.FAED, G.FAED[4:],
    "dbbi", "faed",
]

# ------------------------------------------------------------------ camada D (§6)
RES_L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
RES_L83 = RES_L84[:-1]
BITS_L84 = "00001000110000100110010"
BITS_L83 = "00001000110000100110011"
ROW = G.row_sums(G.MATRIX_README)
COL = G.col_sums(G.MATRIX_README)
CAMADA_D = [
    RES_L84, RES_L83, BITS_L84, BITS_L83,
    "".join(map(str, ROW)), "".join(map(str, COL)),
    "".join(map(str, ROW + COL)), ",".join(map(str, ROW + COL)),
    " ".join(map(str, ROW + COL)),
    str(sum(ROW)), "101", "163",
    RES_L84 + BITS_L84, BITS_L84 + RES_L84,
]


# ------------------------------------------------------------------ camada E
def monologo_fase32():
    """O plaintext autêntico da fase 3.2 (trecho em inglês), lido do README.md."""
    txt = open(os.path.join(REPO, "README.md"), encoding="utf-8").read()
    i = txt.index("I've been waiting for you.")
    j = txt.index("One for one, four for one.", i) + len("One for one, four for one.")
    return txt[i:j]


def camada_e():
    mono = monologo_fase32()
    toks = sorted({w.lower() for w in re.findall(r"[A-Za-z]{4,}", mono)})
    return toks, mono


def camada_f():
    """Transcrições verbatim das páginas do puzzle no README: toda linha em blockquote
    (`> `). Inclui, sem prejuízo, tokens em português da prosa do próprio README."""
    txt = open(os.path.join(REPO, "README.md"), encoding="utf-8").read()
    bq = [l[2:] for l in txt.splitlines() if l.startswith("> ")]
    return sorted({w.lower() for l in bq for w in re.findall(r"[A-Za-z]{4,}", l)})


def camada_g():
    """Concatenação ordenada de pares distintos dos 7 tokens do roadmap — o mecanismo
    'palavras concatenadas numa ordem específica' das fases 1-3.2 (42 pares)."""
    return [a + b for a in ROADMAP for b in ROADMAP if a != b]


def camada_h():
    """Mesmo mecanismo, aridade 3: trios ordenados distintos do roadmap (210)."""
    return [a + b + c for a in ROADMAP for b in ROADMAP for c in ROADMAP
            if a != b and b != c and a != c]


# ------------------------------------------------------------------ montagem
def formas(base, n_formas=6):
    """Até 6 formas por base. A forma provada pelas fases é sha256hex(pré-imagem)."""
    n = norm(base)
    out = [base, sha_hex(base), sha_hex(n), n, sha_hex(base.upper()), sha_hex(sha_hex(base))]
    return out[:n_formas]


def build():
    mono_toks, mono = camada_e()
    camadas = [
        ("A_operandos_fases", CAMADA_A, 6),
        ("B_roadmap", CAMADA_B, 6),
        ("C_pagina_endgame", CAMADA_C, 6),
        ("D_primos_residuo", CAMADA_D, 6),
        ("E_monologo_arquiteto", mono_toks + [mono, norm(mono)], 6),
        ("F_transcricoes_readme", camada_f(), 6),
        ("G_pares_roadmap", camada_g(), 2),
        ("H_trios_roadmap", camada_h(), 2),
    ]
    vistas = {}
    meta = {"camadas": {}, "bases_total": 0}
    for nome, bases, nf in camadas:
        bases = list(dict.fromkeys(bases))
        meta["camadas"][nome] = {"bases": len(bases), "formas": nf, "senhas_novas": 0}
        meta["bases_total"] += len(bases)
        for b in bases:
            for f in formas(b, nf):
                fb = f.encode("utf-8")
                if fb and fb not in vistas:
                    vistas[fb] = nome
                    meta["camadas"][nome]["senhas_novas"] += 1
    senhas = list(vistas.keys())
    meta["senhas_unicas"] = len(senhas)
    return senhas, meta


if __name__ == "__main__":
    import json
    s, m = build()
    print(json.dumps(m, indent=2, ensure_ascii=False))
    print("amostra:", [x[:40] for x in s[:3]])
