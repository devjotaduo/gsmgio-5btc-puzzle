# -*- coding: utf-8 -*-
"""Teste do par "half and better half" (fora da caixa, 2026-09-18).

Reframe. A última linha decodificada da fase 3.2.2 diz, literal, "the private keyS belong to half and
better half" (plural). O prêmio tem dois endereços: 1GSMG (1,25 BTC) e 17ucy (3,75 BTC, 3× maior,
nunca gastou = "better half"). Hipótese: a SalPhaseIon não dá uma senha de blob, e sim DUAS chaves de
uma vez — uma de `dbbi` (estruturado: primos b/be comprovados) e uma de `faed` (i.i.d., cara de
material de chave). Ninguém montou uma operação que emita o PAR e o valide junto.

Por que o par vale como oráculo. Exigir que a MESMA operação O dê O(fonte_dbbi)→um alvo e
O(fonte_faed)→o outro tem chance de coincidência dupla ~2^-320. Isso deixa varrer operações
paramétricas/ambíguas que, contra um alvo só, dariam candidatos de ruído — aqui um par espúrio é
impossível na prática. Não é força bruta nova: é um critério de sucesso mais forte sobre leituras
estruturais baratas (as do roadmap: yellowblueprimes, matrixsumlist, yinyang).

Cobertura. Fontes dbbi-like × fontes faed-like × (redução base-9/10/sha) × (modificador do roadmap:
identidade, offset/xor por matrixsumlist, negação N-k, yinyang split). Cada op também é testada
"cruzada" (dbbi→17ucy, faed→1GSMG). Controle plantado confirma que o detector do par dispara.
Uso: python par_half_betterhalf.py
"""
import hashlib, json, sys
from itertools import product
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "solver" / "experiments" / "claude_endgame_2026_09_02"))
import gsmg_common as G  # noqa: E402
from coincurve import PublicKey  # noqa: E402

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
OUT = REPO / "_work" / "half_betterhalf_2026-09-18"
TGT = {bytes.fromhex(h): a for h, a in zip(G.O.TARGET_H160S, G.O.PRIZE_ADDRS)}
PRIZE = {a: bytes.fromhex(h) for h, a in zip(G.O.TARGET_H160S, G.O.PRIZE_ADDRS)}
GSMG = next(a for a in TGT.values() if a.startswith("1GSMG"))
UCY = next(a for a in TGT.values() if a.startswith("17ucy"))

# matrixsumlist: as somas de linha e coluna da matriz (ENDGAME §1)
LINHAS = [6, 10, 8, 7, 6, 6, 5, 4, 9, 9, 7, 8, 7, 9]
COLUNAS = [8, 10, 8, 10, 8, 7, 3, 6, 7, 5, 9, 6, 6, 8]
SOMAS = LINHAS + COLUNAS
SOMA_INT = int("".join(str(x) for x in SOMAS))            # 6108766549978789810810... como número
SOMA_BYTES = (bytes(SOMAS) * 32)[:32]                      # somas como 32 bytes para XOR
RESID_L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
RESID_L83 = RESID_L84[:-1]

MAPS = {"a1i9o0": {**{c: str(i + 1) for i, c in enumerate("abcdefghi")}, "o": "0"},
        "a0i8": {c: str(i) for i, c in enumerate("abcdefghi")}}


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def addr_de(sec):
    if not 0 < int.from_bytes(sec, "big") < N:
        return set()
    pk = PublicKey.from_valid_secret(sec)
    return {TGT.get(h160(pk.format(c))) for c in (False, True)} - {None}


def reducoes(s):
    """Escalares-base (int de 32 B) que uma fonte de símbolos rende, antes dos modificadores."""
    out = {}
    for mn, m in MAPS.items():
        if all(ch in m for ch in s):
            digs = "".join(m[ch] for ch in s)
            for base in (9, 10):
                if all(int(d) < base for d in digs):
                    out[f"{mn}/base{base}"] = int(digs, base) % N
            out[f"{mn}/sha_digits"] = int.from_bytes(hashlib.sha256(digs.encode()).digest(), "big") % N
    out["sha_raw"] = int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % N
    out["sha_raw_d"] = int.from_bytes(hashlib.sha256(hashlib.sha256(s.encode()).digest()).digest(), "big") % N
    return out


def modificadores(v):
    """v (int) -> {nome: escalar de 32 B} pelos passos do roadmap."""
    return {"id": v, "neg": (N - v) % N,
            "somaoff": (v + SOMA_INT) % N, "somaoff_neg": (N - (v + SOMA_INT)) % N,
            "somaxor": (v ^ int.from_bytes(SOMA_BYTES, "big")) % N}


def escalares(s):
    """{op: sec(32 B)} de uma fonte de símbolos: redução × modificador."""
    out = {}
    for rn, v in reducoes(s).items():
        for mnn, w in modificadores(v).items():
            out[f"{rn}/{mnn}"] = w.to_bytes(32, "big")
    return out


def yinyang(s):
    """faed dividido em duas metades (yin/yang): metades cruas, XOR e soma como fontes extras."""
    h = len(s) // 2
    a, b = s[:h], s[h:2 * h]
    return {"h1": a, "h2": b}


def fontes():
    dbbi, faed = G.DBBI, G.FAED
    d = {"dbbi": dbbi, "dbbi_rev": dbbi[::-1], "resid_L84": RESID_L84, "resid_L83": RESID_L83}
    f = {"faed": faed, "faed_rev": faed[::-1], **{f"faed_{k}": v for k, v in yinyang(faed).items()}}
    return d, f


def par_bate(secs_d, secs_f):
    """Devolve (isolados, pares). CORREÇÃO 2026-09-18 (auditoria da PR #6, mesmo defeito aqui): antes
    só o par completo era devolvido, então um acerto de UM alvo por um dos lados sumia — a regra 1 do
    AGENTS.md manda declarar qualquer privkey que bata com um dos endereços. Agora todo acerto isolado
    é registrado e o par é só uma classificação adicional."""
    isolados, achados = [], []
    for op in secs_d.keys() & secs_f.keys():
        ad, af = addr_de(secs_d[op]), addr_de(secs_f[op])
        isolados += [{"op": op, "lado": "dbbi", "alvo": a, "sec": secs_d[op].hex()} for a in sorted(ad)]
        isolados += [{"op": op, "lado": "faed", "alvo": a, "sec": secs_f[op].hex()} for a in sorted(af)]
        if GSMG in (ad | af) and UCY in (ad | af):
            achados.append({"op": op, "dbbi_da": sorted(ad), "faed_da": sorted(af)})
    return isolados, achados


def controle():
    """Planta os h160 de dois secrets sintéticos como alvos e confirma que o par dispara."""
    sd = hashlib.sha256(b"par-controle-dbbi").digest()
    sf = hashlib.sha256(b"par-controle-faed").digest()
    hd = h160(PublicKey.from_valid_secret(sd).format(True))
    hf = h160(PublicKey.from_valid_secret(sf).format(False))
    TGT[hd] = GSMG
    TGT[hf] = UCY
    try:
        iso, ok = par_bate({"id/id": sd}, {"id/id": sf})
    finally:
        del TGT[hd], TGT[hf]
    assert len(ok) == 1 and len(iso) == 2, (iso, ok)
    # regressão do bug: só um lado acerta -> sem par, MAS o isolado tem de ser registrado
    so_d = hashlib.sha256(b"par-controle-so-dbbi").digest()
    h = h160(PublicKey.from_valid_secret(so_d).format(True))
    TGT[h] = GSMG
    try:
        iso2, ok2 = par_bate({"id/id": so_d}, {"id/id": hashlib.sha256(b"nada").digest()})
    finally:
        del TGT[h]
    assert not ok2 and any(x["lado"] == "dbbi" and x["alvo"] == GSMG for x in iso2), (iso2, ok2)
    assert len(TGT) == 2, TGT
    return {"detector_do_par_ok": True, "acerto_isolado_registrado": True,
            "regressao_do_bug_da_PR6": "coberta"}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ctl = controle()
    d_src, f_src = fontes()
    hits, isolados, pares_testados = [], [], 0
    detalhe = {}
    for (dn, ds), (fn, fs) in product(d_src.items(), f_src.items()):
        secs_d, secs_f = escalares(ds), escalares(fs)
        comuns = secs_d.keys() & secs_f.keys()
        pares_testados += len(comuns)
        iso, got = par_bate(secs_d, secs_f)
        detalhe[f"{dn}×{fn}"] = len(comuns)
        isolados += [{"dbbi_fonte": dn, "faed_fonte": fn, **x} for x in iso]
        for g in got:
            hits.append({"dbbi_fonte": dn, "faed_fonte": fn, **g})
    res = {"reframe": "half and better half = 1GSMG (half) e 17ucy (better half); a fase dá o PAR de chaves",
           "alvos": {"half_1GSMG": GSMG, "better_half_17ucy": UCY},
           "controle": ctl, "pares_de_fontes": len(d_src) * len(f_src),
           "operacoes_por_par": detalhe, "ops_de_par_testadas": pares_testados,
           "criterio": "regra 1: TODO acerto isolado é registrado; o par é classificação adicional",
           "hits_isolados": isolados, "hits_par": hits,
           "assuncao_nao_demonstrada": "que 'half'=1GSMG e 'better half'=17ucy, e que dbbi e faed "
           "correspondam a cada um: o criador glosou 'better half' como a esposa, o que fala de "
           "PERTENCIMENTO e não especifica formato nem qual campo gera qual chave",
           "kit": G.__file__,
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(res, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "operacoes_por_par"}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
