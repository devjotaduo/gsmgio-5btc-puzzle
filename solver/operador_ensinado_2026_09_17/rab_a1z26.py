# -*- coding: utf-8 -*-
"""
FAMILIA "operador ensinado" — RAB (a1z26 -> SOMA | LISTA) como o passo `matrixsumlist`.

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
Em 2021-04-01 (msg #6913 do Telegram, mesma manha do "another door might be found on
{1},{4},{21}") o criador escreveu, sem que ninguem pedisse:

    R=18 / A=1 / B=2   ...   "Could also be 21 or 1812 bit"

Isto e uma DEMONSTRACAO do operador: uma PALAVRA -> letras como ordinais A=1..Z=26 ->
ou a SOMA dos ordinais (18+1+2 = 21) ou a LISTA deles concatenada ("18"+"1"+"2" = 1812).
O segundo passo do roadmap dele chama-se literalmente `matrixsumlist` (matrix / sum / list),
e a propria pagina final usa o ramo "lista" ao contrario (campos `z`: letras a-i,o -> digitos ->
inteiro decimal -> hex -> ASCII, que deu `lastwordsbeforearchichoice` e `thispassword`).

HIPOTESE TESTADA AQUI: aplicar o operador RAB a cada objeto NOMEADO do puzzle (tokens do
roadmap, respostas das fases, a frase de 23 palavras da 3.2, os nomes proprios da pagina) e
tambem a saida do passo anterior do roadmap (`yellowblueprimes`: os 23 marcadores de dbbi como
bits de cor, os 23 indices espirais das celulas coloridas, os bytes da URL que elas codificam)
produz, por alguma das serializacoes/codificacoes abaixo, a senha de SMALL / TAIL32 / COSMIC.

FALSIFICACAO: varredura exaustiva do produto cartesiano
  {objeto} x {11 serializacoes} x {10 formas numero->senha} x {3 blobs} x {2 KDF},
julgada SO pelo oraculo duro (G.semantic / G.fast_priv_scan / nested_blob / ebcdic_sig).
Se nenhum hit duro aparecer e a taxa de padding valido ficar dentro do nulo casado, a familia
esta refutada com a cobertura declarada no relatorio.

O QUE E NOVO (vs ENDGAME.md secao 4): ja caiu a senha LITERAL dos tokens (corpus historico,
1,27 M), o a1z26 CRU sobre dbbi/faed, e as leituras decimais de dbbi/faed. O que nunca rodou e
a SERIALIZACAO RAB (soma|lista) de PALAVRAS e da selecao de 23 como material de senha.
`matrixsum_attack.py` e `roadmap_yb_matrixsum_attack.py` leem "matrixsumlist" como a lista de
somas da matriz 14x14 (101) — interpretacao diferente, nao sobreposta.

CONTROLE POSITIVO: o blob da fase 2 abre com sha256hex("causality") sob EVP-SHA256.
NULO CASADO: 100 reamostragens que preservam a FORMA de cada entrada (mesmo numero de palavras,
mesmos comprimentos; listas numericas com mesmo tamanho e mesma faixa) rodando o MESMO pipeline;
reporta taxa de padding observada vs 1/256 e z por sub-familia (blob x kdf).

Saida: _work/operador_ensinado_2026-09-17/rab_a1z26/{hits,soft,resumo}.jsonl|json
"""
import sys, os, json, time, random, hashlib, base64, statistics
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

OUT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\rab_a1z26"
os.makedirs(OUT, exist_ok=True)

# --------------------------------------------------------------- entradas nomeadas
ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit",
           "verylaststepisatruegiveawaypromised"]

TOKENS_PAGINA = ["thispassword", "enter", "shabef", "sha256", "ans too", "shabef ans too",
                 "sha256 answer too", "our first hint is your last command",
                 "SalPhaseIon", "Cosmic Duality", "salphaseion", "cosmicduality",
                 "yingyang", "yin yang", "dbbi", "faed", "GSMG", "gsmg",
                 "gsmg.io/theseedisplanted", "theseedisplanted",
                 "gsmg.io/theseedisplante", "theseedisplante",   # selecao A do atlas (23 bytes)
                 "RAB", "rab", "rabbit", "half", "better half", "betterhalf",
                 "followthewhiterabbit", "the matrix has you", "thematrixhasyou"]

RESPOSTAS = ["causality", "Safenet", "Luna", "HSM", "jacquefresco", "giveitjustonesecond",
             "heisenbergsuncertaintyprinciple",
             "theflowerblossomsthroughwhatseemstobeaconcretesurface",
             "causalitySafenetLunaHSM",
             "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
             "THEMATRIXHASYOU"]

# frase de 23 palavras do plaintext da fase 3.2
FRASE32 = ("IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF "
           "AND THEY ALSO NEED FUNDS TO LIVE").split()
assert len(FRASE32) == 23, len(FRASE32)


def entradas_texto():
    """dict nome -> texto. Palavras isoladas, janelas contiguas e frases inteiras."""
    d = {}
    for t in ROADMAP:
        d["roadmap:" + t] = t
    d["roadmap:todos"] = "".join(ROADMAP)
    d["roadmap:todos_espaco"] = " ".join(ROADMAP)
    for tam in (2, 3):                      # janelas contiguas do roadmap
        for i in range(0, len(ROADMAP) - tam + 1):
            d[f"roadmap:{tam}@{i+1}"] = "".join(ROADMAP[i:i + tam])
    for t in TOKENS_PAGINA:
        d["pag:" + t] = t
    for t in RESPOSTAS:
        d["resp:" + t] = t
    for i, w in enumerate(FRASE32):
        d[f"f32:w{i+1}:{w}"] = w
    for tam in (2, 3, 4, 5):
        for i in range(0, 23 - tam + 1):
            d[f"f32:{tam}@{i+1}"] = " ".join(FRASE32[i:i + tam])
    d["f32:frase"] = " ".join(FRASE32)
    return d


def entradas_numericas():
    """dict nome -> lista de inteiros (saida do passo `yellowblueprimes` e afins)."""
    d = {}
    # 23 marcadores de dbbi (L84) como bits de cor: b=0, be=1
    bitsL84 = "00001000110000100110010"
    bitsL83 = bitsL84  # L83 difere so no 'e' final do residuo; a sequencia de tipos e a mesma
    d["yb:bitsL84"] = [int(c) for c in bitsL84]
    d["yb:bitsL84_1based"] = [int(c) + 1 for c in bitsL84]
    d["yb:bitsL84_rev"] = [int(c) for c in bitsL84[::-1]]
    assert bitsL83 == bitsL84
    # indices espirais dos 25 eventos coloridos (G.COLORED inclui o #FEFEFE em 163).
    # Selecao A do atlas = omitir os eventos 22 e 25 (1-based); variante B = 23 e 25.
    idx = sorted(G.COLORED.keys())
    assert len(idx) == 25 and 163 in idx
    cores25 = [("B" if G.COLORED[i][0].startswith("W") else G.COLORED[i][0]) for i in idx]
    bitsA = "".join("0" if c == "B" else "1" for k, c in enumerate(cores25) if k not in (21, 24))
    assert bitsA == "00001000110000100110010", bitsA   # casa com os tipos b/be de L84
    d["yb:spiral25"] = idx
    d["yb:spiral23_A"] = [v for k, v in enumerate(idx) if k not in (21, 24)]
    d["yb:spiral23_B"] = [v for k, v in enumerate(idx) if k not in (22, 24)]
    d["yb:spiral_ord"] = list(range(1, 26))
    # sequencias de cores como bits e como ordinais das letras B/Y
    d["yb:colorseq24_bits"] = [1 if c == "B" else 0 for c in G.COLOR_SEQ]
    d["yb:colorseq24_a1z26"] = [2 if c == "B" else 25 for c in G.COLOR_SEQ]
    d["yb:colorseq25_bits"] = [1 if c == "B" else 0 for c in cores25]
    d["yb:colorseq25_a1z26"] = [2 if c == "B" else 25 for c in cores25]
    # bytes da URL que as 23/24 celulas coloridas codificam (ASCII, nao a1z26)
    d["yb:url24_ascii"] = list(b"gsmg.io/theseedisplanted")
    d["yb:url23A_ascii"] = list(b"gsmg.io/theseedisplante")
    # somas da matriz da fase 0
    d["m0:rowsums"] = G.row_sums(G.MATRIX_README)
    d["m0:colsums"] = G.col_sums(G.MATRIX_README)
    d["m0:row+col"] = G.row_sums(G.MATRIX_README) + G.col_sums(G.MATRIX_README)
    return d


# --------------------------------------------------------------- operador RAB
def ordinais(texto):
    """a1z26 sobre as letras (caixa ignorada); nao-letras descartados."""
    return [ord(c) - 96 for c in texto.lower() if "a" <= c <= "z"]


def _digitsum(s):
    return sum(int(c) for c in str(s) if c.isdigit())


def serializacoes(L, palavras=None):
    """Recebe a lista de ordinais (e, opcionalmente, as listas por palavra).
    Devolve dict nome -> string de digitos."""
    if not L:
        return {}
    s = {}
    total = sum(L)
    s["soma"] = str(total)
    s["soma_mod26"] = str(total % 26)
    s["soma_digitsum"] = str(_digitsum(total))
    lista = "".join(str(x) for x in L)
    lista02 = "".join(f"{x:02d}" for x in L)
    s["lista"] = lista
    s["lista02"] = lista02
    s["lista_ordrev"] = "".join(str(x) for x in reversed(L))       # palavra invertida
    s["lista02_ordrev"] = "".join(f"{x:02d}" for x in reversed(L))
    s["lista_digrev"] = lista[::-1]                                 # lista invertida (digitos)
    s["lista02_digrev"] = lista02[::-1]
    s["lista_digitsum"] = str(_digitsum(lista))
    if palavras and len(palavras) > 1:
        s["somas_por_palavra"] = "".join(str(sum(w)) for w in palavras if w)
    return s


def formas(digitos):
    """String de digitos -> candidatos de senha (bytes|str). Cada forma tambem em sha256 hex."""
    out = []
    if not digitos or not digitos.isdigit():
        return out
    n = int(digitos)
    out.append(("str", digitos))
    h = format(n, "x")
    out.append(("hex", h))
    out.append(("HEX", h.upper()))
    try:
        out.append(("zmethod", G.z_method([int(c) for c in digitos])))  # int -> hex -> bytes ascii
    except Exception:
        pass
    nb = max(1, (n.bit_length() + 7) // 8)
    out.append(("be_bytes", n.to_bytes(nb, "big")))
    # convencao de todas as fases: sha256 hex minusculo do material
    base = list(out)
    for nome, v in base:
        b = v.encode() if isinstance(v, str) else v
        out.append(("sha256:" + nome, hashlib.sha256(b).hexdigest()))
    return out


def privkeys_candidatas(ent_txt, ent_num):
    """Oraculo (a): o inteiro serializado tambem como chave privada crua de 32 B.
    Formas: big-endian com zero-padding a esquerda (e truncado nos 32 B baixos se maior),
    e o sha256 de cada forma de senha. Devolve dict key32 -> proveniencia."""
    cands = {}

    def add(b, prov):
        if len(b) > 32:
            b = b[-32:]
        b = bytes(32 - len(b)) + b          # zero-padding a esquerda ate 32 B
        cands.setdefault(b, prov)

    fontes = [(n, serializacoes(ordinais(t), [ordinais(w) for w in t.split()]))
              for n, t in ent_txt.items()]
    fontes += [(n, serializacoes(L)) for n, L in ent_num.items()]
    for nome, ser in fontes:
        for sname, dig in ser.items():
            n = int(dig)
            nb = max(1, (n.bit_length() + 7) // 8)
            add(n.to_bytes(nb, "big"), f"{nome}|{sname}|int32be")
            for fname, pw in formas(dig):
                b = pw.encode() if isinstance(pw, str) else pw
                add(hashlib.sha256(b).digest(), f"{nome}|{sname}|sha256({fname})")
    return cands


def gerar_senhas(ent_txt, ent_num):
    """Devolve dict senha(bytes) -> proveniencia (str), deduplicado."""
    senhas = {}

    def add(pw, prov):
        b = pw.encode() if isinstance(pw, str) else pw
        if not b or len(b) > 4096:
            return
        senhas.setdefault(b, prov)

    for nome, texto in ent_txt.items():
        palavras = [ordinais(w) for w in texto.split()]
        L = ordinais(texto)
        for sname, dig in serializacoes(L, palavras).items():
            for fname, pw in formas(dig):
                add(pw, f"{nome}|{sname}|{fname}")
    for nome, L in ent_num.items():
        for sname, dig in serializacoes(L).items():
            for fname, pw in formas(dig):
                add(pw, f"{nome}|{sname}|{fname}")
    return senhas


# --------------------------------------------------------------- AES (rapido, so padding)
_BLOBS = [(b, G.BLOBS[b][0], G.BLOBS[b][1]) for b in ("SMALL", "TAIL32", "COSMIC")]
_KDFS = [("MD5", MD5), ("SHA256", SHA256)]
def _kdf(nome):
    """G.aes_try devolve hm.__name__ ('Crypto.Hash.SHA256'); aqui so o sufixo."""
    return nome.rsplit(".", 1)[-1]


def contar_padding(senhas):
    """Conta padding valido por sub-familia (blob x kdf). Devolve dict chave -> (ok, total)."""
    cont = {f"{b}/{k}": 0 for b, _, _ in _BLOBS for k, _ in _KDFS}
    n = len(senhas)
    for pw in senhas:
        for bname, salt, ct in _BLOBS:
            for kname, hm in _KDFS:
                key, iv = G.evp(pw, salt, hm)
                if G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct)) is not None:
                    cont[f"{bname}/{kname}"] += 1
    return cont, n


# --------------------------------------------------------------- nulo casado
def _palavra_aleatoria(w, rnd):
    return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in w)


def nulo_entradas(ent_txt, ent_num, rnd):
    """Reamostra preservando a FORMA: mesmo numero de palavras e mesmos comprimentos;
    listas numericas com mesmo tamanho e valores uniformes na mesma faixa."""
    t = {}
    for nome, texto in ent_txt.items():
        t[nome] = " ".join(_palavra_aleatoria(w, rnd) for w in texto.split())
    nm = {}
    for nome, L in ent_num.items():
        lo, hi = min(L), max(L)
        nm[nome] = [rnd.randint(lo, hi) for _ in L]
    return t, nm


# --------------------------------------------------------------- controle positivo
def controle_positivo():
    raw = base64.b64decode(G.PHASE2_B64)
    assert raw[:8] == b"Salted__"
    salt, ct = raw[8:16], raw[16:]
    key, iv = G.evp(G.shahex("causality").encode(), salt, SHA256)
    p = G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct))
    ok = p is not None and G.printable(p) > 0.9
    return ok, (p[:60].decode("latin-1") if p else None)


# --------------------------------------------------------------- main
def main():
    t0 = time.time()
    ok, amostra = controle_positivo()
    print(f"[controle positivo] fase2 + sha256hex('causality') EVP-SHA256 -> {ok}: {amostra!r}")
    assert ok, "controle positivo FALHOU — abortando"

    ent_txt, ent_num = entradas_texto(), entradas_numericas()
    senhas = gerar_senhas(ent_txt, ent_num)
    print(f"[cobertura] {len(ent_txt)} entradas de texto + {len(ent_num)} numericas "
          f"-> {len(senhas)} senhas unicas ({len(senhas)*6} decifracoes AES)")

    # oraculo (a): privkey crua
    pk = privkeys_candidatas(ent_txt, ent_num)
    pk_hits = [(G.priv_hit(k), v) for k, v in pk.items() if G.priv_hit(k)]
    print(f"[oraculo privkey] {len(pk)} chaves de 32 B testadas -> {len(pk_hits)} hits")

    hits, soft, cont = [], [], {f"{b}/{k}": 0 for b, _, _ in _BLOBS for k, _ in _KDFS}
    for pw, prov in senhas.items():
        h, s = G.try_password_all(pw)
        for rec in h + s:
            rec["senha"] = pw.decode("latin-1")
            rec["proveniencia"] = prov
            cont[f"{rec['blob']}/{_kdf(rec['kdf'])}"] += 1
        hits.extend(h)
        soft.extend(s)

    with open(os.path.join(OUT, "hits.jsonl"), "w", encoding="utf-8") as f:
        for r in hits:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(OUT, "soft_padding.jsonl"), "w", encoding="utf-8") as f:
        for r in soft:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # nulo casado
    N_NULO = int(os.environ.get("N_NULO", "100"))
    rnd = random.Random(20260917)
    nulo = {k: [] for k in cont}
    for i in range(N_NULO):
        nt, nn = nulo_entradas(ent_txt, ent_num, rnd)
        ns = gerar_senhas(nt, nn)
        c, _ = contar_padding(ns)
        for k, v in c.items():
            nulo[k].append(v / max(1, len(ns)))
        if (i + 1) % 10 == 0:
            print(f"  nulo {i+1}/{N_NULO} ({time.time()-t0:.0f}s)")

    resumo = {"privkeys_testadas": len(pk), "privkey_hits": len(pk_hits),
              "senhas_unicas": len(senhas), "entradas_texto": len(ent_txt),
              "entradas_numericas": len(ent_num), "decifracoes": len(senhas) * 6,
              "hits_duros": len(hits), "n_nulo": N_NULO, "subfamilias": {}}
    for k in sorted(cont):
        obs = cont[k] / len(senhas)
        mu = statistics.fmean(nulo[k])
        sd = statistics.pstdev(nulo[k]) or 1e-12
        resumo["subfamilias"][k] = {"padding_ok": cont[k], "taxa_obs": round(obs, 5),
                                    "taxa_nulo_media": round(mu, 5),
                                    "taxa_nulo_sd": round(sd, 5),
                                    "z": round((obs - mu) / sd, 2),
                                    "esperado_1_256": round(1 / 256, 5)}
    resumo["segundos"] = round(time.time() - t0, 1)
    with open(os.path.join(OUT, "resumo.json"), "w", encoding="utf-8") as f:
        json.dump(resumo, f, ensure_ascii=False, indent=2)
    print(json.dumps(resumo, ensure_ascii=False, indent=2))
    if hits:
        print("!!! HITS DUROS — conferir hits.jsonl")


def demo():
    """Checagem minima: o operador reproduz a demonstracao do proprio criador (RAB)."""
    L = ordinais("RAB")
    assert L == [18, 1, 2], L
    s = serializacoes(L, [L])
    assert s["soma"] == "21", s["soma"]
    assert s["lista"] == "1812", s["lista"]
    assert G.z_method([1, 8, 1, 2]) == bytes.fromhex("0714"), G.z_method([1, 8, 1, 2])  # 1812 = 0x714
    ok, _ = controle_positivo()
    assert ok
    print("demo OK: RAB -> soma 21, lista 1812; controle positivo da fase 2 passa")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
