# -*- coding: utf-8 -*-
r"""
FAMILIA 6 — a referencia PESSOAL montada pela gramatica que as fases resolvidas ensinam.

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
Toda senha verificada deste puzzle e o NOME EXATO ou a LINHA EXATA de algo do mundo do
criador, alcancado por uma descricao obliqua; as partes sao concatenadas verbatim, em ordem
de pagina, sem separador; o sha256 do resultado, em hex minusculo, e a senha do envelope
(fase 2 = "causality"; fase 3 = "causalitySafenetLunaHSM11110" + hex + FEN; fase 3.2 =
"jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple").

Em 2026-07-12 o criador escreveu "My close friends have the best chance of solving it (a few
tried). But they don't have the skills some of you do." e, na mensagem seguinte, "NOTE: that
is a hint." — a unica fala que ele marcou como hint. Em 2023-11 disse que a internet nao e
mais necessaria; em 2024-09, que falta "1 microstep".

A hipotese: a senha do ultimo envelope e uma referencia do MUNDO DELE — um item que um amigo
proximo reconheceria de imediato e que ja aparece no proprio material do puzzle — composta
pela mesma gramatica: item sozinho, ou 2/3 itens concatenados verbatim sem separador, ou um
item colado a um token do roadmap, ou 4-6 itens da lista curta; testado como senha direta e
como sha256 hex (minusculo e MAIUSCULO), nos 3 blobs, sob os 2 KDF.

FALSIFICACAO: se nenhuma das ~N composicoes deste inventario, em nenhuma das formas de caixa
que o puzzle usa, abre SMALL/COSMIC/TAIL32 sob EVP-SHA256 ou EVP-MD5 com plaintext semantico
(>=85% ASCII, WIF/hex64, blob aninhado, assinatura EBCDIC cp273) nem produz privkey do premio,
a hipotese esta refutada PARA ESTE INVENTARIO E ESTAS ARIDADES (1-3 itens quaisquer; 4-6 itens
na lista curta do atlas) — e nao para a familia inteira, porque o inventario e um recorte do
que o repositorio registra e a composicao testada e sempre concatenacao sem separador.

REGRA ETICA: o inventario usa SOMENTE o que ja esta escrito no repositorio e nas falas
publicas do criador no grupo. Nenhum dado de identidade civil, endereco, familia ou conjuge.
"the better half" entra como a GLOSA PUBLICA que ele mesmo deu, nunca como nome de pessoa.
Nenhuma busca na internet foi feita.

CONTROLE POSITIVO: a fase 2 abre no MESMO pipeline com sha256hex("causality") sob EVP-SHA256;
uma senha-lixo nao abre.
NULO CASADO: 100 rodadas; em cada uma, uma subamostra fixa de candidatos reais tem os
caracteres embaralhados (preserva comprimento e multiconjunto de caracteres) e passa pelo
MESMO pipeline. Reporta taxa de padding observada vs 1/256 e z por sub-familia.
"""
import sys, os, json, time, random, hashlib, itertools, collections

sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G

OUT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\familia6_referencia_pessoal"
os.makedirs(OUT, exist_ok=True)
LOG = os.path.join(OUT, "familia6.jsonl")
PAD = os.path.join(OUT, "paddings.jsonl")   # todo plaintext com padding valido, em hex

# ---------------------------------------------------------------- controle positivo
import base64
def _parse(b64):
    raw = base64.b64decode(b64); return raw[8:16], raw[16:]
G.BLOBS["FASE2"] = _parse(G.PHASE2_B64)
_h, _s = G.try_password_all(G.shahex("causality"), blobs=("FASE2",))
assert _h and _h[0]["kdf"].endswith("SHA256") and _h[0]["head"].startswith("The ironic"), (_h, _s)
_h2, _ = G.try_password_all("nao_e_a_senha_xyz", blobs=("FASE2",))
assert not _h2
del G.BLOBS["FASE2"]
print("[controle+] fase 2 abre com sha256hex('causality') sob EVP-SHA256; senha-lixo nao abre")

BLOBS = ("SMALL", "COSMIC", "TAIL32")

# ---------------------------------------------------------------- inventario do mundo dele
# Cada entrada: (tag, string verbatim como o repositorio/as falas publicas a registram).
# PRIO=True marca os itens que a propria sintese do atlas chama de "os fatos pessoais do
# material" — sao os usados nas triplas (a aridade 3 explode combinatoriamente).
INV = [
    # --- empresa e glosa dele
    ("gsmg", "GSMG", True),
    ("gsmg", "GSMG.io", True),
    ("gsmg", "gsmg.io", True),
    ("gsmg", "Globally supporting my generation", True),
    ("gsmg", "us guys at gsmg", True),
    ("gsmg", "GSMG MEGANIGMA", False),
    ("gsmg", "MEGANIGMA", False),
    # --- handles publicos da despedida de 2026-04 (handles, nunca nome civil)
    ("handle", "JRK", True),
    ("handle", "d0d", True),
    ("handle", "Darky", True),
    ("handle", "Bloctite", True),
    ("handle", "SoWut", True),
    ("handle", "Jrk Bgrt", False),
    ("handle", "JRKd0dDarkyBloctite", False),
    # --- a glosa publica "better half" (a esposa, SEM nome — so a glosa dele)
    ("half", "the better half", True),
    ("half", "better half", True),
    ("half", "half and better half", True),
    ("half", "HALF AND BETTER HALF", False),
    # --- Venus Project / Jacque Fresco
    ("venus", "Jacque Fresco", True),
    ("venus", "jacquefresco", True),
    ("venus", "The Venus Project", True),
    ("venus", "The Choice Is Ours", True),
    ("venus", "help us build it", True),
    ("venus", "resource based economy", False),
    # --- Decentraland
    ("dcl", "-41,-17", True),
    ("dcl", "-41-17", False),
    ("dcl", "41,17", False),
    ("dcl", "Only -41,-17 matters", True),
    ("dcl", "Decentraland", True),
    ("dcl", "MANA", True),
    # --- o livro
    ("book", "Cosmic Duality", True),
    ("book", "Mysteries of the Unknown", True),
    ("book", "Time-Life", False),
    ("book", "Time Life Books", False),
    # --- Mr. Robot / HSM
    ("robot", "eps3.4", False),
    ("robot", "eps3.5", True),
    ("robot", "eps3.4_runtime-err0r.r00", False),
    ("robot", "eps3.5_kill-pr0cess.inc", True),
    ("robot", "rewatch episode 3.5 with the better half", True),
    ("robot", "SafeNet Luna HSM", True),
    ("robot", "Safenet", False),
    ("robot", "Luna", False),
    ("robot", "HSM", False),
    # --- musica e o primeiro puzzle dele
    ("music", "Logic Pro X", True),
    ("music", "Logic Pro", False),
    ("music", "The Warning", True),
    ("music", "Logic", False),
    ("music", "Never Gonna Give You Up", True),
    ("music", "Rick Astley", False),
    ("music", "rickroll", True),
    # --- ferramentas que ele mesmo citou
    ("tool", "Paint", False),
    ("tool", "MS Paint", False),
    ("tool", "passwordsgenerator.net", True),
    ("tool", "openssl", False),
    ("tool", "CyberChef", False),
    ("tool", "dcode", False),
    # --- paises, lugares, holandes (inclui a grafia DELE, "geestveruimend")
    ("place", "Holland", False),
    ("place", "the Netherlands", False),
    ("place", "Nederland", False),
    ("place", "Ibiza", True),
    ("place", "Rotterdam", False),
    ("place", "geestveruimend", True),      # grafia do criador (#66976)
    ("place", "geestverruimend", True),     # grafia correta
    ("place", "Miffy", False),
    ("place", "nijntje", False),
    ("place", "orange carrot", False),
    ("place", "purple carrot", False),
    # --- datas com que ele brinca
    ("date", "April Fools", False),
    ("date", "1 April", False),
    ("date", "11 SEP 01", False),
    ("date", "11SEP01", False),
    ("date", "halving", False),
    ("date", "Happy halving", False),
    ("date", "2017 - 2026", False),
    # --- falas dele, verbatim (a marcada como hint primeiro)
    ("fala", "My close friends have the best chance of solving it", True),
    ("fala", "close friends", True),
    ("fala", "NOTE: that is a hint", True),
    ("fala", "that is a hint", False),
    ("fala", "Give yourself yourself and yourself will be given yourself.", True),
    ("fala", "Iykyk", True),
    ("fala", "Same same", False),
    ("fala", "Couple hours", False),
    ("fala", "Enjoying life", False),
    ("fala", "Always a joy", False),
    ("fala", "Fairly sober", False),
    ("fala", "One mystery remains", True),
    ("fala", "Follow the white rabbit", True),
    ("fala", "The lights are off.", False),
    ("fala", "Nine years of chaos ended.", False),
    ("fala", "Hello :-)", False),
    ("fala", "Nice to see you around!", False),
    ("fala", "You made it to the next step!", False),
    ("fala", "Good luck little bunny hunter ;)", False),
    ("fala", "The 5 btc was never the actual prize", False),
    ("fala", "hidden laptop", False),
    ("fala", "a room with a hidden door", False),
    # --- reuso das fases (G8: ele reusa a resposta anterior)
    ("fase", "causality", True),
    ("fase", "thematrixhasyou", True),
    ("fase", "THEMATRIXHASYOU", False),
    ("fase", "SalPhaseIon", True),
    ("fase", "Cosmic Duality", False),   # duplicado de book: dedup cuida
    ("fase", "salphaseion", False),
    ("fase", "cosmicduality", False),
    ("fase", "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple", False),
]

ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit",
           "verylaststepisatruegiveawaypromised", "thispassword", "theseedisplanted"]

# ---------------------------------------------------------------- formas de caixa/espaco
def formas(s):
    """As formas de caixa/espaco que o puzzle de fato usa nas fases resolvidas."""
    low_ns = "".join(s.split()).lower()
    out = [s,                               # verbatim (fase 3: "causalitySafenet…")
           low_ns,                          # minusculo sem espaco (fase 3.2)
           s.lower(),                       # minusculo com espaco
           "".join(s.split()),              # sem espaco, caixa preservada
           "".join(s.split()).upper()]      # MAIUSCULO sem espaco
    return out

def join_ns(parts):
    """Concatenacao verbatim sem separador, a regra do puzzle."""
    return "".join(parts)

# ---------------------------------------------------------------- geracao de candidatos
def gerar():
    """Devolve dict: string-candidata -> sub-familia (a primeira que a produziu)."""
    cand = {}
    def add(s, fam):
        if s and len(s) <= 400 and s not in cand:
            cand[s] = fam

    itens = [(t, s) for (t, s, _p) in INV]
    prio = [s for (_t, s, p) in INV if p]

    # F1 — item sozinho, em todas as formas
    for _t, s in itens:
        for f in formas(s):
            add(f, "F1_single")

    # F2 — pares concatenados verbatim, nas duas ordens, em 2 formas de juncao
    base_low = sorted({"".join(s.split()).lower() for _t, s in itens})
    base_vb = sorted({s for _t, s in itens})
    for a, b in itertools.permutations(base_low, 2):
        add(a + b, "F2_pair_low")
    for a, b in itertools.permutations(base_vb, 2):
        add(join_ns((a, b)), "F2_pair_verbatim")

    # F3 — triplas sobre o recorte prioritario (os "fatos pessoais do material")
    prio_low = sorted({"".join(s.split()).lower() for s in prio})
    for a, b, c in itertools.permutations(prio_low, 3):
        add(a + b + c, "F3_triple_low")

    # F3v — triplas em forma VERBATIM (a fase 3 concatena partes com a caixa natural de cada
    # uma: "causality"+"Safenet"+"Luna"+"HSM"+"11110"); a forma minuscula-sem-espaco e a 3.2.
    prio_vb = sorted(set(prio))
    for a, b, c in itertools.permutations(prio_vb, 3):
        add(join_ns((a, b, c)), "F3_triple_verbatim")

    # F5 — aridade 4 e 5 sobre a lista curta que a propria sintese do atlas chama de "os fatos
    # pessoais do material": better half, us guys at gsmg, Jacque Fresco, a glosa da empresa,
    # a parcela do Decentraland, o livro.
    curta_vb = ["the better half", "us guys at gsmg", "Jacque Fresco",
                "Globally supporting my generation", "-41,-17", "Cosmic Duality"]
    curta_low = ["".join(x.split()).lower() for x in curta_vb]
    for base in (curta_vb, curta_low):
        for k in (4, 5, 6):
            for combo in itertools.permutations(base, k):
                add(join_ns(combo), "F5_shortlist")

    # F4 — item colado a token do roadmap (as duas ordens) + token-item-token
    for _t, s in itens:
        sl = "".join(s.split()).lower()
        sv = "".join(s.split())
        for r in ROADMAP:
            add(r + sl, "F4_roadmap"); add(sl + r, "F4_roadmap")
            add(r + sv, "F4_roadmap"); add(sv + r, "F4_roadmap")
    for sl in prio_low:
        for r1, r2 in itertools.permutations(ROADMAP, 2):
            add(r1 + sl + r2, "F4_roadmap_sandwich")
    return cand

# ---------------------------------------------------------------- pipeline
def materiais(s):
    """Cada candidato vira senha direta e sha256 hex (minusculo e MAIUSCULO)."""
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return (("raw", s), ("sha256hex", h), ("SHA256HEX", h.upper()))

def roda(cands, logf=None, padf=None, coletar_pad=True):
    """Roda o pipeline. Devolve (hits_duros, contador_padding_por_subfamilia, n_decifracoes)."""
    hits, pad = [], collections.Counter()
    ndec = 0
    for s, fam in cands.items():
        for mat, pw in materiais(s):
            hard, soft = G.try_password_all(pw, blobs=BLOBS)
            ndec += len(BLOBS) * 2
            pad[fam] += len(hard) + len(soft)
            if coletar_pad and padf is not None:
                for rec in hard + soft:
                    padf.write(json.dumps({"fam": fam, "cand": s, "mat": mat, **rec}) + "\n")
            for rec in hard:
                rec2 = {"HIT": True, "fam": fam, "cand": s, "mat": mat, **rec}
                hits.append(rec2)
                if logf: logf.write(json.dumps(rec2) + "\n")
                print("[HIT DURO]", json.dumps(rec2)[:400])
        # brainwallet: sha256(cand) como privkey crua de 32 B ("Regular Bitcoin Private key")
        r = G.priv_hit(hashlib.sha256(s.encode("utf-8")).digest())
        if r:
            rec2 = {"HIT": True, "fam": fam, "cand": s, "mat": "brainwallet", "priv": str(r)}
            hits.append(rec2)
            if logf: logf.write(json.dumps(rec2) + "\n")
            print("[HIT DURO/PRIVKEY]", json.dumps(rec2)[:400])
    return hits, pad, ndec

# ---------------------------------------------------------------- nulo casado
def nulo(cands, rodadas=100, amostra=400, seed=20260917):
    """Embaralha os caracteres de uma subamostra fixa (preserva comprimento e multiconjunto)
    e roda o MESMO pipeline. Devolve lista de taxas de padding por rodada e por sub-familia."""
    rnd = random.Random(seed)
    pool = list(cands.items())
    sub = rnd.sample(pool, min(amostra, len(pool)))
    taxas = []
    for i in range(rodadas):
        emb = {}
        for s, fam in sub:
            ch = list(s); rnd.shuffle(ch)
            emb["".join(ch) + ("\x00" * 0)] = fam   # colisao eventual so reduz N, nao enviesa
        _h, pad, ndec = roda(emb, coletar_pad=False)
        taxas.append({"rodada": i, "pad": dict(pad), "ndec": ndec,
                      "n_por_fam": dict(collections.Counter(emb.values()))})
    return taxas

# ---------------------------------------------------------------- main
def main(only=None, sufixo=""):
    """only: conjunto de sub-familias a rodar (None = todas). sufixo: distingue os logs."""
    t0 = time.time()
    cands = gerar()
    if only:
        cands = {k: v for k, v in cands.items() if v in only}
    por_fam = collections.Counter(cands.values())
    print("[gerado] candidatos distintos:", len(cands))
    for k, v in sorted(por_fam.items()):
        print("   ", k, v)

    logf = open(LOG.replace(".jsonl", sufixo + ".jsonl"), "w", encoding="utf-8")
    padf = open(PAD.replace(".jsonl", sufixo + ".jsonl"), "w", encoding="utf-8")
    hits, pad, ndec = roda(cands, logf, padf)
    padf.close()
    print("[real] decifracoes: %d | padding valido: %d | hits duros: %d | %.1fs"
          % (ndec, sum(pad.values()), len(hits), time.time() - t0))

    # nulo casado
    t1 = time.time()
    taxas = nulo(cands)
    print("[nulo] 100 rodadas em %.1fs" % (time.time() - t1))

    # z por sub-familia: taxa real vs distribuicao do nulo
    resumo = {}
    for fam, n_cand in por_fam.items():
        n_dec_real = n_cand * 3 * len(BLOBS) * 2      # 3 materiais
        taxa_real = pad[fam] / n_dec_real if n_dec_real else 0.0
        amostras = []
        for t in taxas:
            nf = t["n_por_fam"].get(fam, 0)
            if nf:
                amostras.append(t["pad"].get(fam, 0) / (nf * 3 * len(BLOBS) * 2))
        if len(amostras) >= 10:
            mu = sum(amostras) / len(amostras)
            var = sum((x - mu) ** 2 for x in amostras) / (len(amostras) - 1)
            sd = var ** 0.5
            z = (taxa_real - mu) / sd if sd > 0 else 0.0
        else:
            mu = sd = z = None
        resumo[fam] = {"n_cand": n_cand, "n_decifracoes": n_dec_real, "padding": pad[fam],
                       "taxa_real": taxa_real, "esperado_1_256": 1 / 256,
                       "nulo_mu": mu, "nulo_sd": sd, "z": z, "n_rodadas_nulo": len(amostras)}
        print("[z] %-22s n=%6d taxa=%.5f nulo_mu=%s z=%s"
              % (fam, n_cand, taxa_real, ("%.5f" % mu) if mu is not None else "-",
                 ("%+.2f" % z) if z is not None else "-"))

    total_real = sum(pad.values()) / sum(v["n_decifracoes"] for v in resumo.values())
    print("[global] taxa de padding real = %.5f (1/256 = %.5f)" % (total_real, 1 / 256))

    resumo_json = {"candidatos": len(cands), "decifracoes_reais": ndec,
                   "hits_duros": hits, "por_subfamilia": resumo,
                   "taxa_global_real": total_real, "esperado": 1 / 256,
                   "segundos": round(time.time() - t0, 1)}
    logf.write(json.dumps({"RESUMO": resumo_json}) + "\n")
    logf.close()
    json.dump(resumo_json, open(os.path.join(OUT, "resumo%s.json" % sufixo), "w"), indent=1)
    print("[fim] %.1fs — log: %s" % (time.time() - t0, LOG))
    return resumo_json


def _autoteste():
    """Check minimo: a gramatica reproduz as senhas conhecidas e o gerador compoe como o puzzle."""
    assert G.shahex("causality") == "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf"
    assert G.shahex("jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple") == \
        "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
    assert join_ns(("causality", "Safenet", "Luna", "HSM", "11110")) == "causalitySafenetLunaHSM11110"
    f = formas("The Venus Project")
    assert "thevenusproject" in f and "The Venus Project" in f and "THEVENUSPROJECT" in f
    print("[autoteste] gramatica OK (fases 2/3/3.2 reproduzidas)")


if __name__ == "__main__":
    _autoteste()
    if len(sys.argv) > 1:
        main(only=set(sys.argv[1].split(",")), sufixo="_" + sys.argv[2])
    else:
        main()
