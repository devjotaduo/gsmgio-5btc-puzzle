# -*- coding: utf-8 -*-
"""A2: os codecs da família 4 sobre os 1.723 conteúdos que a recoleta corrigida recuperou.

O item 7 (PR #4) corrigiu `retro_dois_alvos.collect()`, que perdia linhas de `.jsonl` por
`str.splitlines()`. Os 1.723 conteúdos recuperados passaram por raw32 BE/LE e pelas 7 visões, mas
ficaram de fora dos codecs da família 4 (§4-C, "twenty-three ciphers"), porque
`familia4_codecs.py` e `critico_familia4_codecs.py` coletam com o mesmo padrão de `splitlines()` e
as campanhas deles estão fechadas. Este script fecha esse resíduo.

Reusa a lógica exata da família 4 (CODECS, scan_bytes, traduz, duro_traduzido, varre) importando o
módulo — com `open` redirecionado durante a importação, para não sobrescrever o log de 17/09 no
checkout principal. Acrescenta o que falta: todo hex64/WIF detectado na saída traduzida é confirmado
com `G.priv_hit` contra os DOIS alvos do prêmio.
Uso: python codecs_1723.py
"""
import builtins, hashlib, json, sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
OUT = REPO / "_work" / "lacunas_2026-09-18" / "codecs_1723"
OUT.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(AQUI))
sys.path.insert(0, str(REPO / "solver" / "operador_ensinado_2026_09_17"))

# a família 4 abre o log em "w" na importação; redireciona para cá e preserva o artefato de 17/09
_real_open = builtins.open


def _guard(arquivo, modo="r", *a, **k):
    if "familia4_codecs.jsonl" in str(arquivo):
        return _real_open(OUT / "familia4_codecs.jsonl", modo, *a, **k)
    return _real_open(arquivo, modo, *a, **k)


builtins.open = _guard
try:
    import familia4_codecs as F4  # noqa: E402
finally:
    builtins.open = _real_open

import splitlines as SP  # noqa: E402  (collect antigo × corrigido; traz o kit e o orfaos)

G = F4.G


def conteudos():
    """Recomputa a diferença entre a coleta antiga (splitlines) e a corrigida (split \\n)."""
    antigo = SP.collect_antigo()
    velho, novo = set(antigo["collect"]()), set(SP.R.collect())
    so_novo = sorted(novo - velho)
    return [bytes.fromhex(h) for h in so_novo]


def confirmar_chaves(hits):
    """Todo hex64/WIF da saída traduzida vira privkey testada contra os dois alvos."""
    import base58
    conf = []
    for h in hits:
        out = F4.traduz(bytes.fromhex(h["hex"]), h["codec"], h["dir"])
        txt = out.decode("latin-1")
        for hx in G.hex64_candidates(txt):
            conf.append({"tipo": "hex64", "valor": hx, "priv_hit": G.priv_hit(bytes.fromhex(hx))})
        for w in G.wif_candidates(txt):
            try:
                raw = base58.b58decode_check(w)
            except Exception:
                continue
            if len(raw) in (33, 34):
                conf.append({"tipo": "wif", "valor": w, "priv_hit": G.priv_hit(raw[1:33])})
    return conf


def controle():
    """Um conteúdo plantado cuja tradução por um codec vira blob aninhado tem de ser detectado."""
    alvo = b"Salted__" + bytes(range(24))            # cabeçalho openssl = nested_blob
    c, d = "cp273", "dec"
    # constrói bytes que, traduzidos por (c, d), devolvem `alvo`
    tab = (F4.ENC if d == "enc" else F4.DEC)[c]
    inv = {}
    for v in range(256):
        if tab[v] >= 0:
            inv.setdefault(tab[v] & 0xFF, v)
    if any(x not in inv for x in alvo):
        return {"controle": "codec sem imagem completa; pulado"}
    plantado = bytes(inv[x] for x in alvo)
    assert F4.traduz(plantado, c, d) == alvo
    assert F4.duro_traduzido(alvo) == "nested_blob", F4.duro_traduzido(alvo)
    return {"traducao_reversivel": True, "duro_detecta_nested_blob": True,
            "codec": c, "dir": d, "plantado_hex": plantado.hex()}


def main():
    ctl = controle()
    dados = conteudos()
    itens = [(b, "splitlines_recuperado", "") for b in dados]
    hits, dist, melhor, n_altos = F4.varre(itens, "A2_splitlines_1723")
    duros = [h for h in hits if h["oraculo_duro"]]
    conf = confirmar_chaves(hits)
    res = {"item": "A2: codecs da família 4 sobre os conteúdos recuperados pelo splitlines",
           "conteudos": len(dados), "bytes": sum(map(len, dados)),
           "com_8_ou_mais_bytes_altos": n_altos, "codecs": len(F4.CODECS),
           "reinterpretacoes": len(dados) * len(F4.CODECS) * 2,
           "detector_disparou": len(hits), "oraculo_duro": len(duros),
           "duros_detalhe": duros[:20],
           "melhor_lower": {"valor": round(melhor[0], 3), "print": round(melhor[1], 3),
                            "codec": melhor[2], "dir": melhor[3]},
           "distribuicao_lower": {str(k): v for k, v in sorted(dist.items())},
           "chaves_confirmadas": conf, "hits_de_chave": [c for c in conf if c["priv_hit"]],
           "controle": ctl, "alvos": dict(zip(G.O.PRIZE_ADDRS, G.TARGET_H160S)),
           "sha256_conteudos": hashlib.sha256(b"".join(hashlib.sha256(b).digest() for b in dados)).hexdigest(),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(res, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k not in ("duros_detalhe", "distribuicao_lower")},
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
