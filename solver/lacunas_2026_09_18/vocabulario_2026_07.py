# -*- coding: utf-8 -*-
"""O registro pessoal-informal do criador como classe de senha (2026-09-18).

O único hint que o criador marcou como hint ("NOTE: that is a hint", 2026-07-12) está sobre "My close
friends have the best chance of solving it (a few tried). But they don't have the skills some of you
do." A estrutura é paradoxal de propósito: os amigos ganham APESAR de menos habilidade técnica. O que
eles têm é o VOCABULÁRIO dele. Isso não anuncia mecanismo novo — anuncia classe de senha: palavra ou
expressão do registro pessoal-informal, como `causality` e `thematrixhasyou`.

A família 6 (§4-C, 17/09) já atacou isso com 104 itens e ≈1,7 M candidatos: 0. Mas o inventário dela
capturou só parte do registro da noite de 12/07 e da de 16/07. Aqui entra o que ficou de fora — e a
DISJUNÇÃO é garantida por construção: todo candidato gerado contém pelo menos um item inédito, então
nenhum repete a campanha anterior (a família 6 só combinava itens do inventário dela).

Fonte: falas públicas no grupo, curadas verbatim em _work/creator_msgs_2026-07_09.txt (checkout
principal), conferidas contra o export. Somente o que ele escreveu num grupo aberto. Nenhum dado de
identidade, endereço, família ou terceiros (AGENTS.md, regra 6).

Gramática: a mesma das fases resolvidas e da família 6 — item sozinho em todas as formas de caixa,
pares concatenados sem separador (inédito×inédito e inédito×prioritário-antigo, nas duas ordens) e
item colado a token do roadmap. Cada candidato vira senha `raw`, `sha256hex` e `SHA256HEX`, nos 3
blobs × 2 KDF, e ainda sha256(candidato) como privkey contra os dois alvos.
Uso: python vocabulario_2026_07.py
"""
import hashlib, itertools, json, re, sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI.parent / "enxame_2026_09_18"))
import comum as C  # noqa: E402  (executor: 3 blobs × 2 KDF, dedup, z de padding)
from coincurve import PublicKey  # noqa: E402

G = C.G
OUT = AQUI.parents[1] / "_work" / "vocabulario_2026-07"
FAM6 = AQUI.parents[1] / "solver" / "operador_ensinado_2026_09_17" / "familia6_referencia_pessoal.py"
ALVOS = {bytes.fromhex(h): a for h, a in zip(G.O.TARGET_H160S, G.O.PRIZE_ADDRS)}

ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit",
           "verylaststepisatruegiveawaypromised", "thispassword", "theseedisplanted"]

# Registro pessoal-informal das noites de 12/07 e 16/07 e de 01/09 que a família 6 não inventariou.
# (tag, verbatim como ele escreveu — typos dele inclusos, que são assinatura de registro, prioritário)
INEDITOS = [
    # o puzzle contado por ele
    ("criacao", "the rickroll effect", True),
    ("criacao", "rickroll effect", True),
    ("criacao", "matrix cypher", True),
    ("criacao", "in a matrix cypher kinda way", False),
    ("criacao", "life enjoying project", True),
    ("criacao", "monstrosity", True),
    ("criacao", "spur of the moment", True),
    ("criacao", "frenzy", True),
    ("criacao", "ego-centric", False),
    ("criacao", "egocentric", False),
    ("criacao", "I rushed (t)it", False),
    # meta e AI
    ("meta", "meta", True),
    ("meta", "Meta hunting", True),
    ("meta", "ELI5", True),
    ("meta", "ELI4.5", True),
    ("meta", "ELI4.5 is meta", False),
    ("meta", "many NOTES", True),
    ("meta", "NOTES", True),
    ("meta", "Latetly", False),            # typo dele (#66962)
    # quantum e bitcoin
    ("quantum", "bip360", True),
    ("quantum", "BIP 360", False),
    ("quantum", "stable qubits", True),
    ("quantum", "a few stable qubits", False),
    ("quantum", "piggy bank", True),
    ("quantum", "nation state", False),
    # o trocadilho com primos (o lead aberto é de primos)
    ("prime", "in your prime", True),
    ("prime", "You have to be in your prime for that", False),
    # koans e despedida
    ("koan", "Going dark again", True),
    ("koan", "Going dark", False),
    ("koan", "Some already found it", True),
    ("koan", "quite a secret in my head", True),
    ("koan", "share with the planet", True),
    ("koan", "a tiny fraction", True),
    ("koan", "still saw double", False),
    ("koan", "I might me drunk", False),   # typo dele (#66549)
    # o registro de bar
    ("bar", "It kills braincells", True),
    ("bar", "braincells", True),
    ("bar", "Beer, red wine and champagne", False),
    ("bar", "ketamine", False),
    ("bar", "ayahuasca", False),
    ("bar", "mao-inhibitors", False),
]


def norma(s):
    return "".join(s.split()).lower()


def inventario_antigo():
    """Lê as strings do INV da família 6 (texto, sem importar: o kit dela aponta para o checkout
    principal). Devolve (todas normalizadas, prioritárias verbatim)."""
    src = FAM6.read_text(encoding="utf-8")
    bloco = src[src.index("INV = ["):src.index("ROADMAP = [")]
    itens = re.findall(r'\(\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*(True|False)\s*\)', bloco)
    todas = {norma(s.encode().decode("unicode_escape")) for _t, s, _p in itens}
    prio = [s.encode().decode("unicode_escape") for _t, s, p in itens if p == "True"]
    return todas, prio


def formas(s):
    """As formas de caixa/espaço que as fases resolvidas usam (cópia fiel da família 6)."""
    return [s, norma(s), s.lower(), "".join(s.split()), "".join(s.split()).upper()]


def gerar(prio_antigo):
    """Todo candidato contém ao menos um item inédito — daí a disjunção com a família 6."""
    cand = {}

    def add(s, fam):
        if s and len(s) <= 400:
            cand.setdefault(s, fam)

    novos_vb = [s for _t, s, _p in INEDITOS]
    novos_prio = [s for _t, s, p in INEDITOS if p]
    novos_low = sorted({norma(s) for s in novos_vb})
    for s in novos_vb:                                    # F1 — item sozinho
        for f in formas(s):
            add(f, "F1_single")
    for a, b in itertools.permutations(novos_low, 2):     # F2 — par inédito×inédito
        add(a + b, "F2_par_low")
    for a, b in itertools.permutations(sorted(set(novos_vb)), 2):
        add(a + b, "F2_par_verbatim")
    antigos_low = sorted({norma(s) for s in prio_antigo})  # F2x — inédito × prioritário antigo
    for a in novos_low:
        for b in antigos_low:
            add(a + b, "F2x_novo_antigo")
            add(b + a, "F2x_antigo_novo")
    for s in novos_vb:                                    # F4 — colado a token do roadmap
        sl, sv = norma(s), "".join(s.split())
        for r in ROADMAP:
            for x in (sl, sv):
                add(r + x, "F4_roadmap")
                add(x + r, "F4_roadmap")
    for a, b, c in itertools.permutations(sorted({norma(s) for s in novos_prio}), 3):
        add(a + b + c, "F3_tripla_prio")                  # F3 — triplas só entre os prioritários
    return cand


def brainwallet(cands):
    """sha256(candidato) como privkey dos dois alvos (o gesto brainwallet, fora do AES)."""
    n = 0
    hits = []
    for s in cands:
        sec = hashlib.sha256(s.encode("utf-8")).digest()
        if not 0 < int.from_bytes(sec, "big") < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            continue
        n += 1
        pk = PublicKey.from_valid_secret(sec)
        for comp in (False, True):
            h = hashlib.new("ripemd160", hashlib.sha256(pk.format(comp)).digest()).digest()
            if h in ALVOS:
                hits.append({"candidato": s, "alvo": ALVOS[h], "comprimida": comp, "priv": sec.hex()})
    return n, hits


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ctl = C.controle_positivo()
    antigas, prio_antigo = inventario_antigo()
    novas = {norma(s) for _t, s, _p in INEDITOS}
    colisao = sorted(novas & antigas)
    assert not colisao, f"itens já inventariados pela família 6: {colisao}"
    cand = gerar(prio_antigo)
    r = C.testar(list(cand), formas=("raw", "sha256hex", "sha256HEX"), workers=8,
                 rotulo="vocabulario_2026-07")
    n_bw, hits_bw = brainwallet(cand)
    # nulo casado: embaralha os caracteres de uma subamostra e passa pelo MESMO pipeline
    import random
    rnd = random.Random(20260918)
    amostra = rnd.sample(sorted(cand), min(3000, len(cand)))
    nulo = C.testar(["".join(rnd.sample(s, len(s))) for s in amostra],
                    formas=("raw", "sha256hex", "sha256HEX"), workers=8, rotulo="nulo")
    res = {"hipotese": "classe de senha do hint marcado: registro pessoal-informal do criador",
           "fonte": "falas públicas no grupo (creator_msgs_2026-07_09.txt), regra 6 respeitada",
           "itens_ineditos": len(INEDITOS), "disjuncao_com_familia6": "garantida: 0 colisões de item "
           "e todo candidato contém ao menos um item inédito",
           "itens_prioritarios_antigos_reusados_em_pares": len(set(map(norma, prio_antigo))),
           "candidatos": len(cand), "por_subfamilia": {f: sum(1 for v in cand.values() if v == f)
                                                       for f in sorted(set(cand.values()))},
           "controle_positivo_fase2": bool(ctl["candidatos"]),
           "aes": r["aes"], "senhas": r["senhas"], "paddings": r["paddings"],
           "paddings_esperados": r["paddings_esperados"], "z_padding": r["z_padding"],
           "candidatos_hard": r["candidatos"],
           "brainwallet": {"escalares": n_bw, "hits": hits_bw},
           "nulo": {k: nulo[k] for k in ("senhas", "aes", "paddings", "paddings_esperados", "z_padding")},
           "nulo_candidatos": nulo["candidatos"], "kit": C.commit_do_kit(),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(res, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "por_subfamilia"}, ensure_ascii=False, indent=1))
    print("por subfamília:", res["por_subfamilia"])


if __name__ == "__main__":
    main()
