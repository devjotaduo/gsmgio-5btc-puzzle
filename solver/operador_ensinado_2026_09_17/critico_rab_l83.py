# -*- coding: utf-8 -*-
"""
ADENDO DO CRITICO: o buraco L83 da familia "matrixsumlist_rab".

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O script rab_a1z26.py afirma cobrir "a saida do passo anterior do roadmap (`yellowblueprimes`)".
Mas ele escreveu no codigo:

    bitsL84 = "00001000110000100110010"
    bitsL83 = bitsL84   # "L83 difere so no 'e' final do residuo; a sequencia de tipos e a mesma"
    assert bitsL83 == bitsL84

Isso e FALSO. `solver/primos_2026_09_17/matrixsumlist_struct__msl_struct.py` prova, com assert
sobre a segmentacao real de dbbi, que BITS[83] == "00001000110000100110011": o 'e' final do
residuo de L84 e justamente o que vira o 23.o marcador `be` em L83, logo o ULTIMO BIT MUDA.
Consequencia: das duas segmentacoes que ENDGAME secao 6 diz existirem (e nao desambigua), ele
so alimentou o operador com UMA. Pela mesma razao, das cinco selecoes de 23 celulas coloridas
que casam (L84: omitir {22,25} ou {23,25}; L83: omitir {22,24}, {23,24} ou {24,25}) ele gerou
duas, ambas de L84 — as tres de L83 ficaram de fora.

HIPOTESE TESTADA: as saidas de `yellowblueprimes` na segmentacao L83 (bits, indices espirais das
tres selecoes compativeis, e as cores correspondentes), passadas pelo MESMO operador RAB
(a1z26 1-based e 0-based, 11 serializacoes dele + 8 minhas, 10 formas numero->senha + 3 formas
sha256 extras), produzem a senha de SMALL/TAIL32/COSMIC ou a privkey do premio.
FALSIFICACAO: oraculo duro; nulo casado de 100 replicas preservando a forma das listas.

NAO reabre familia refutada: nao alimento o operador com o residuo de dbbi nem com faed
(ENDGAME secoes 4B e 6). So a SAIDA do passo `yellowblueprimes` na segmentacao que faltava.

CONTROLE POSITIVO: fase 2 com sha256hex("causality") sob EVP-SHA256 (assert).
CONTROLE ESTRUTURAL: assert de que as 5 selecoes de cor reproduzem BITS[83]/BITS[84] bit a bit.
"""
import sys, os, json, time, random, statistics, hashlib

REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(REPO, r"solver\experiments\claude_endgame_2026_09_02"))
sys.path.insert(0, os.path.join(REPO, r"solver\operador_ensinado_2026_09_17"))
import gsmg_common as G
import rab_a1z26 as R
import critico_rab_a1z26 as C

OUT = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\critico_rab_a1z26")
os.makedirs(OUT, exist_ok=True)

BITS84 = "00001000110000100110010"
BITS83 = "00001000110000100110011"


def entradas_l83():
    """So o que FALTOU: a segmentacao L83 e as selecoes de cor compativeis com ela."""
    col25 = "".join("1" if G.COLORED[k][0] == "Y" else "0" for k in sorted(G.COLORED))
    idx = sorted(G.COLORED.keys())
    assert len(col25) == 25 and len(idx) == 25

    def sel(omit):
        return [i for i in range(25) if i + 1 not in omit]

    # controle estrutural: as 5 selecoes que casam (ENDGAME secao 6)
    casa84 = [(22, 25), (23, 25)]
    casa83 = [(22, 24), (23, 24), (24, 25)]
    for o in casa84:
        assert "".join(col25[i] for i in sel(o)) == BITS84, o
    for o in casa83:
        assert "".join(col25[i] for i in sel(o)) == BITS83, o
    assert BITS83 != BITS84, "a premissa errada do rab_a1z26.py"

    d = {}
    d["yb83:bits"] = [int(c) for c in BITS83]
    d["yb83:bits_1based"] = [int(c) + 1 for c in BITS83]
    d["yb83:bits_rev"] = [int(c) for c in BITS83[::-1]]
    # a polaridade contraria (be=0) tambem: ele so rodou uma polaridade para L84
    d["yb83:bits_inv"] = [1 - int(c) for c in BITS83]
    d["yb84:bits_inv"] = [1 - int(c) for c in BITS84]
    d["yb84:bits_1based_rev"] = [int(c) + 1 for c in BITS84[::-1]]
    for nome, o in [("C", (22, 24)), ("D", (23, 24)), ("E", (24, 25))]:
        s = sel(o)
        d[f"yb83:spiral23_{nome}"] = [idx[i] for i in s]
        d[f"yb83:cores23_{nome}_a1z26"] = [25 if col25[i] == "1" else 2 for i in s]
        d[f"yb83:cores23_{nome}_bits"] = [int(col25[i]) for i in s]
    # os 23 marcadores como a1z26 do proprio token ('b'=2, 'be'=2,5) — a leitura literal do operador
    d["yb83:marc_a1z26"] = [7 if c == "1" else 2 for c in BITS83]   # b=2, be=2+5=7
    d["yb84:marc_a1z26"] = [7 if c == "1" else 2 for c in BITS84]
    d["yb83:marc_lista"] = [x for c in BITS83 for x in ([2, 5] if c == "1" else [2])]
    d["yb84:marc_lista"] = [x for c in BITS84 for x in ([2, 5] if c == "1" else [2])]
    # contagens: L84 = 16 b + 7 be; L83 = 15 b + 8 be
    d["yb:contagens84"] = [16, 7, 23, 61]
    d["yb:contagens83"] = [15, 8, 23, 60]
    return d


def gerar(ent_num):
    """Operador completo: 1-based + 0-based, serializacoes dele + minhas, formas dele + minhas."""
    senhas = {}

    def add(pw, prov):
        b = pw.encode() if isinstance(pw, str) else pw
        if b and len(b) <= 4096:
            senhas.setdefault(b, prov)

    for nome, L in ent_num.items():
        for tag, LL in (("1b", L), ("0b", [max(0, x - 1) for x in L])):
            ser = dict(R.serializacoes(LL))
            ser.update({("x:" + k): v for k, v in C.serializa_extra(LL).items()})
            for sname, dig in ser.items():
                for fname, pw in R.formas(dig):
                    add(pw, f"{tag}:{nome}|{sname}|{fname}")
                for fname, pw in C.formas_extra(dig):
                    add(pw, f"{tag}:{nome}|{sname}|{fname}")
            for sname, L2 in C.encadeia(LL).items():
                for s2, dig2 in R.serializacoes(L2).items():
                    for fname, pw in R.formas(dig2):
                        add(pw, f"{tag}:{nome}|chain({sname})|{s2}|{fname}")
    return senhas


def main():
    t0 = time.time()
    ok, _ = R.controle_positivo()
    assert ok, "controle positivo FALHOU"
    ent = entradas_l83()
    senhas = gerar(ent)
    print(f"[cobertura] {len(ent)} objetos L83/omitidos -> {len(senhas)} senhas unicas "
          f"({len(senhas)*6} decifracoes)")

    # oraculo (a)
    pk = {}
    for pw in senhas:
        pk.setdefault(hashlib.sha256(pw).digest(), 1)
        if pw.isdigit():
            n = int(pw)
            b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")[-32:]
            pk.setdefault(bytes(32 - len(b)) + b, 1)
    pkh = [k for k in pk if G.priv_hit(k)]

    hits, soft = [], []
    cnt = dict.fromkeys(C.SUBFAM, 0)
    for pw, prov in senhas.items():
        h, s = G.try_password_all(pw)
        for rec in h + s:
            rec["senha"] = pw.decode("latin-1")[:120]
            rec["prov"] = prov
            cnt[f"{rec['blob']}/{rec['kdf'].rsplit('.',1)[-1]}"] += 1
        hits.extend(h)
        soft.extend(s)

    # re-varredura completa dos paddings novos
    ach, jan, mp, me = [], 0, 0.0, 0.0
    for r in soft:
        p = bytes.fromhex(r["hex"])
        jan += 2 * max(0, len(p) - 31)
        o, e, pr = C.oraculo_completo(p, r["blob"])
        mp, me = max(mp, pr), max(me, e)
        if o:
            ach.append({"prov": r["prov"], "oraculo": o})

    # nulo casado: 100 replicas, listas do mesmo tamanho e mesma faixa
    rnd = random.Random(20260920)
    taxas = {k: [] for k in C.SUBFAM}
    for _ in range(100):
        nn = {n: [rnd.randint(min(L), max(L)) for _ in L] for n, L in ent.items()}
        ns = gerar(nn)
        c, m = C.padding_count(ns.keys())
        for k, v in c.items():
            taxas[k].append(v / max(1, m))
    sub = {}
    for k in C.SUBFAM:
        obs = cnt[k] / len(senhas)
        mu = statistics.fmean(taxas[k])
        sd = statistics.pstdev(taxas[k]) or 1e-12
        sub[k] = {"padding_ok": cnt[k], "taxa_obs": round(obs, 5), "nulo_media": round(mu, 5),
                  "nulo_sd": round(sd, 5), "z": round((obs - mu) / sd, 2)}

    res = {"objetos": len(ent), "senhas_unicas": len(senhas), "decifracoes": len(senhas) * 6,
           "privkeys": len(pk), "privkey_hits": len(pkh), "hits_duros": len(hits),
           "padding_total": sum(cnt.values()), "revarredura_janelas_32B": jan,
           "printable_max": round(mp, 3), "ebcdic_max": round(me, 3), "achados_oraculo": len(ach),
           "subfamilias": sub, "n_nulo": 100, "segundos": round(time.time() - t0, 1)}
    with open(os.path.join(OUT, "l83_resumo.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    with open(os.path.join(OUT, "l83_soft.jsonl"), "w", encoding="utf-8") as f:
        for r in soft:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
