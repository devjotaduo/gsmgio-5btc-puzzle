# -*- coding: utf-8 -*-
"""
CRITICO ADVERSARIAL da familia "matrixsumlist_rab" (rab_a1z26.py).

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O agente anterior afirma ter FECHADO a leitura RAB de `matrixsumlist` (a1z26 -> SOMA | LISTA)
com 9.722 senhas unicas, 58.332 decifracoes, 10.994 privkeys e nulo casado de 100 replicas,
0 hits duros. Minha hipotese de critico e a NEGACAO dessa suficiencia, em tres partes,
cada uma falsificavel por medida:

  H1 (cobertura): os numeros que ele reporta nao batem com o que o codigo dele realmente
      enumera (senhas unicas, privkeys, entradas, formas distintas). FALSIFICA-SE recontando
      o conjunto de forma independente e comparando cardinalidades exatas.
  H2 (oraculo): algum dos 230 plaintexts com padding valido que ele gravou passa no oraculo
      duro COMPLETO (semantic / nested_blob / ebcdic_sig / privkey em TODA janela de 32 B,
      nas DUAS ordens de byte) e ele nao viu. FALSIFICA-SE re-varrendo os 230 em hex.
  H3 (fechamento): o que ele declarou de fora muda o resultado. Rodo aqui os gaps mais
      baratos e mais proximos da demonstracao do criador:
        (1) ordinais 0-based (A=0..Z=25);
        (2) serializacoes aritmeticas extras (produto, soma de quadrados, soma alternada,
            diferencas sucessivas, somas mod 9/10/16/100);
        (3) encadeamento do operador consigo mesmo (RAB aplicado aos bytes de z_method da
            saida de RAB);
        (4) TODAS as janelas contiguas das 23 palavras (comprimentos 1..23 = 276 janelas),
            nao so 1..5 e a frase;
        (6) sha256 duplo e sha256 em MAIUSCULAS.
      FALSIFICA-SE pelo mesmo oraculo duro; se 0 hits e a taxa de padding ficar dentro do
      nulo casado, a familia esta fechada TAMBEM nesses eixos.

CONTROLE POSITIVO: fase 2 abre com sha256hex("causality") sob EVP-SHA256 (assert, aborta se falhar).
NULO CASADO: 100 replicas preservando a FORMA das entradas, semente DIFERENTE da dele (20260918),
  no pipeline original E no pipeline estendido (este ultimo com replicas sobre o mesmo gerador).

Saida: _work/operador_ensinado_2026-09-17/critico_rab_a1z26/
"""
import sys, os, json, time, random, hashlib, base64, statistics

REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(REPO, r"solver\experiments\claude_endgame_2026_09_02"))
sys.path.insert(0, os.path.join(REPO, r"solver\operador_ensinado_2026_09_17"))
import gsmg_common as G
import rab_a1z26 as R                      # so para RECONTAR o que ele enumera
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

OUT = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\critico_rab_a1z26")
os.makedirs(OUT, exist_ok=True)
# append, nunca "w": este modulo tambem e IMPORTADO por critico_rab_l83.py e um open("w") no
# nivel do modulo truncaria o log de uma execucao em andamento.
LOG = open(os.path.join(OUT, "critico.jsonl"), "a", encoding="utf-8")


def reg(ev, **kw):
    kw["ev"] = ev
    LOG.write(json.dumps(kw, ensure_ascii=False) + "\n")
    LOG.flush()
    print(f"[{ev}] " + json.dumps(kw, ensure_ascii=False)[:400])


BLOBS = [(b, G.BLOBS[b][0], G.BLOBS[b][1]) for b in ("SMALL", "TAIL32", "COSMIC")]
KDFS = [("MD5", MD5), ("SHA256", SHA256)]
SUBFAM = [f"{b}/{k}" for b, _, _ in BLOBS for k, _ in KDFS]


def padding_count(senhas):
    """Conta padding valido por sub-familia. senhas: iteravel de bytes."""
    c = dict.fromkeys(SUBFAM, 0)
    n = 0
    for pw in senhas:
        n += 1
        for bname, salt, ct in BLOBS:
            for kname, hm in KDFS:
                key, iv = G.evp(pw, salt, hm)
                if G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct)) is not None:
                    c[f"{bname}/{kname}"] += 1
    return c, n


# ============================================================ 1. REPRODUZIR / RECONTAR
def passo_repro():
    ok, amostra = R.controle_positivo()
    assert ok, "controle positivo FALHOU"
    reg("controle_positivo", ok=ok, head=amostra)

    ent_txt, ent_num = R.entradas_texto(), R.entradas_numericas()
    senhas = R.gerar_senhas(ent_txt, ent_num)
    pk = R.privkeys_candidatas(ent_txt, ent_num)

    # objetos de texto REALMENTE distintos (o operador ignora caixa e nao-letras)
    ordset = {tuple(R.ordinais(t)) for t in ent_txt.values()}
    # formas distintas de verdade: zmethod e be_bytes coincidem sempre (int -> hex par -> bytes)
    dig = "13120189241921131291920"
    fm = dict(R.formas(dig))
    zmeth_eq_be = fm["zmethod"] == fm["be_bytes"]

    cnt, n = padding_count(senhas.keys())
    hits = []
    for pw, prov in senhas.items():
        h, s = G.try_password_all(pw)
        for rec in h:
            rec["senha"] = pw.decode("latin-1")
            rec["prov"] = prov
            hits.append(rec)
    pk_hits = [v for k, v in pk.items() if G.priv_hit(k)]

    reg("repro", senhas_unicas=len(senhas), privkeys=len(pk), privkey_hits=len(pk_hits),
        entradas_texto=len(ent_txt), entradas_numericas=len(ent_num),
        objetos_texto_distintos_pelo_operador=len(ordset),
        formas_declaradas=10, formas_realmente_distintas=(9 if zmeth_eq_be else 10),
        zmethod_identico_a_be_bytes=zmeth_eq_be,
        decifracoes=len(senhas) * 6, hits_duros=len(hits), padding=cnt)
    return ent_txt, ent_num, senhas, cnt


# ============================================================ 2. RE-VARRER OS PADDINGS DELE
def oraculo_completo(p, tag):
    """Oraculo duro COMPLETO sobre um plaintext: semantic, nested, ebcdic, privkey em toda
    janela de 32 B nas DUAS ordens de byte (big-endian como esta, e invertido)."""
    out = {}
    if G.semantic(p):
        out["semantic"] = True
    if G.nested_blob(p):
        out["nested"] = True
    e = G.ebcdic_sig(p)
    if e >= 0.75:
        out["ebcdic"] = e
    if len(p) >= 32:
        h1 = G.fast_priv_scan(p, tag + "/be")
        h2 = G.fast_priv_scan(p[::-1], tag + "/le")
        if h1:
            out["priv_be"] = h1
        if h2:
            out["priv_le"] = h2
    return out, e, G.printable(p)


def passo_revarredura():
    src = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\rab_a1z26\soft_padding.jsonl")
    n = 0
    janelas = 0
    achados = []
    max_print = 0.0
    max_ebcdic = 0.0
    with open(src, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            p = bytes.fromhex(rec["hex"])
            n += 1
            janelas += 2 * max(0, len(p) - 31)
            o, e, pr = oraculo_completo(p, rec.get("blob", "?"))
            max_print = max(max_print, pr)
            max_ebcdic = max(max_ebcdic, e)
            if o:
                achados.append({"prov": rec.get("proveniencia"), "oraculo": o})
    # hits.jsonl dele
    hj = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\rab_a1z26\hits.jsonl")
    nh = sum(1 for _ in open(hj, encoding="utf-8")) if os.path.exists(hj) else None
    reg("revarredura", plaintexts=n, janelas_32B_testadas=janelas, achados=len(achados),
        printable_max=round(max_print, 3), ebcdic_max=round(max_ebcdic, 3),
        hits_jsonl_dele=nh, detalhe=achados[:5])
    return n, janelas


# ============================================================ 3. NULO CASADO INDEPENDENTE
def passo_nulo(ent_txt, ent_num, cnt_obs, n_senhas, n_rep=100, semente=20260918, gerador=None):
    gerador = gerador or R.gerar_senhas
    rnd = random.Random(semente)
    taxas = {k: [] for k in SUBFAM}
    t0 = time.time()
    for i in range(n_rep):
        nt, nn = R.nulo_entradas(ent_txt, ent_num, rnd)
        ns = gerador(nt, nn)
        c, m = padding_count(ns.keys())
        for k, v in c.items():
            taxas[k].append(v / max(1, m))
        if (i + 1) % 25 == 0:
            print(f"   nulo {i+1}/{n_rep} ({time.time()-t0:.0f}s)")
    res = {}
    for k in SUBFAM:
        obs = cnt_obs[k] / n_senhas
        mu = statistics.fmean(taxas[k])
        sd = statistics.pstdev(taxas[k]) or 1e-12
        res[k] = {"padding_ok": cnt_obs[k], "taxa_obs": round(obs, 5),
                  "nulo_media": round(mu, 5), "nulo_sd": round(sd, 5),
                  "z": round((obs - mu) / sd, 2), "um_256": round(1 / 256, 5)}
    return res


# ============================================================ 4. EXTENSAO (gaps declarados)
def ordinais0(t):
    """gap (1): a1z26 0-based, A=0..Z=25."""
    return [ord(c) - 97 for c in t.lower() if "a" <= c <= "z"]


def _ds(x):
    return sum(int(c) for c in str(x) if c.isdigit())


def serializa_extra(L):
    """gap (2): serializacoes aritmeticas alem das 11 dele."""
    if not L:
        return {}
    s = {}
    tot = sum(L)
    prod = 1
    for x in L:
        prod *= max(1, x)
    s["produto"] = str(prod)
    s["soma_quadrados"] = str(sum(x * x for x in L))
    s["soma_alternada"] = str(abs(sum(x if i % 2 == 0 else -x for i, x in enumerate(L))))
    s["diferencas"] = "".join(str(abs(L[i + 1] - L[i])) for i in range(len(L) - 1)) or "0"
    for m in (9, 10, 16, 100):
        s[f"soma_mod{m}"] = str(tot % m)
    s["produto_digitsum"] = str(_ds(prod))
    return s


def formas_extra(dig):
    """gap (6): sha256 duplo e sha256 em MAIUSCULAS, sobre as formas base dele."""
    out = []
    if not dig or not dig.isdigit():
        return out
    base = [(n, v) for n, v in R.formas(dig) if not n.startswith("sha256:")]
    for nome, v in base:
        b = v.encode() if isinstance(v, str) else v
        h = hashlib.sha256(b).hexdigest()
        out.append(("SHA256U:" + nome, h.upper()))
        out.append(("sha256x2:" + nome, hashlib.sha256(h.encode()).hexdigest()))
        out.append(("sha256raw:" + nome, hashlib.sha256(b).digest().hex().upper()))
    return out


def encadeia(L):
    """gap (3): RAB(RAB(x)) — os digitos da saida viram bytes por z_method e esses bytes,
    lidos como texto latin-1, voltam ao operador."""
    saidas = {}
    for sname, dig in R.serializacoes(L).items():
        try:
            b = G.z_method([int(c) for c in dig])
        except Exception:
            continue
        t = b.decode("latin-1")
        L2 = R.ordinais(t)
        if L2:
            saidas[sname] = L2
    return saidas


def janelas_todas_23():
    """gap (4): TODAS as janelas contiguas das 23 palavras (1..23), nao so 1..5."""
    d = {}
    W = R.FRASE32
    for tam in range(1, 24):
        for i in range(0, 23 - tam + 1):
            d[f"f32all:{tam}@{i+1}"] = " ".join(W[i:i + tam])
    return d


def gerar_senhas_ext(ent_txt, ent_num):
    """Gerador ESTENDIDO: tudo o que ele rodou + os gaps (1),(2),(3),(4),(6)."""
    senhas = {}

    def add(pw, prov):
        b = pw.encode() if isinstance(pw, str) else pw
        if b and len(b) <= 4096:
            senhas.setdefault(b, prov)

    def emite(nome, L, palavras=None):
        ser = dict(R.serializacoes(L, palavras))
        ser.update({("x:" + k): v for k, v in serializa_extra(L).items()})
        for sname, dig in ser.items():
            for fname, pw in R.formas(dig):
                add(pw, f"{nome}|{sname}|{fname}")
            for fname, pw in formas_extra(dig):
                add(pw, f"{nome}|{sname}|{fname}")
        # gap (3): encadeamento
        for sname, L2 in encadeia(L).items():
            for s2, dig2 in R.serializacoes(L2).items():
                for fname, pw in R.formas(dig2):
                    add(pw, f"{nome}|chain({sname})|{s2}|{fname}")

    for nome, texto in ent_txt.items():
        emite("1b:" + nome, R.ordinais(texto), [R.ordinais(w) for w in texto.split()])
        emite("0b:" + nome, ordinais0(texto), [ordinais0(w) for w in texto.split()])
    for nome, L in ent_num.items():
        emite("num:" + nome, L)
        emite("num0:" + nome, [max(0, x - 1) for x in L])
    return senhas


def passo_extensao():
    ent_txt = dict(R.entradas_texto())
    ent_txt.update(janelas_todas_23())          # gap (4)
    ent_num = R.entradas_numericas()
    t0 = time.time()
    senhas = gerar_senhas_ext(ent_txt, ent_num)
    reg("extensao_cobertura", entradas_texto=len(ent_txt), entradas_numericas=len(ent_num),
        senhas_unicas=len(senhas), decifracoes=len(senhas) * 6, seg_geracao=round(time.time() - t0, 1))

    # oraculo (a): privkeys
    pk = {}
    for pw in senhas:
        k = hashlib.sha256(pw).digest()
        pk.setdefault(k, 1)
        if len(pw) <= 32 and pw.isdigit():
            n = int(pw)
            b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")[-32:]
            pk.setdefault(bytes(32 - len(b)) + b, 1)
    pkh = [k for k in pk if G.priv_hit(k)]
    reg("extensao_privkey", privkeys=len(pk), hits=len(pkh))

    hits, soft = [], []
    cnt = dict.fromkeys(SUBFAM, 0)
    t0 = time.time()
    for pw, prov in senhas.items():
        h, s = G.try_password_all(pw)
        for rec in h + s:
            rec["senha"] = pw.decode("latin-1")[:120]
            rec["prov"] = prov
            cnt[f"{rec['blob']}/{rec['kdf'].rsplit('.',1)[-1]}"] += 1
        hits.extend(h)
        soft.extend(s)
    with open(os.path.join(OUT, "extensao_soft.jsonl"), "w", encoding="utf-8") as f:
        for r in soft:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(OUT, "extensao_hits.jsonl"), "w", encoding="utf-8") as f:
        for r in hits:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    reg("extensao_aes", senhas=len(senhas), hits_duros=len(hits), padding_ok=sum(cnt.values()),
        padding=cnt, seg=round(time.time() - t0, 1))

    # re-varredura completa dos paddings NOVOS
    ach, jan = [], 0
    mp = me = 0.0
    for r in soft:
        p = bytes.fromhex(r["hex"])
        jan += 2 * max(0, len(p) - 31)
        o, e, pr = oraculo_completo(p, r["blob"])
        mp, me = max(mp, pr), max(me, e)
        if o:
            ach.append({"prov": r["prov"], "oraculo": o})
    reg("extensao_revarredura", plaintexts=len(soft), janelas_32B=jan, achados=len(ach),
        printable_max=round(mp, 3), ebcdic_max=round(me, 3), detalhe=ach[:5])
    return ent_txt, ent_num, senhas, cnt, len(soft), jan


def main():
    t0 = time.time()
    print("== 1. REPRODUZIR ==")
    ent_txt, ent_num, senhas, cnt = passo_repro()

    print("== 2. RE-VARRER OS PADDINGS DELE ==")
    n_rev, jan_rev = passo_revarredura()

    print("== 4. EXTENSAO (gaps declarados) ==")
    e_txt, e_num, e_senhas, e_cnt, e_soft, e_jan = passo_extensao()

    print("== 3. NULO CASADO INDEPENDENTE (pipeline original, semente 20260918) ==")
    nulo_orig = passo_nulo(ent_txt, ent_num, cnt, len(senhas), n_rep=100, semente=20260918)
    reg("nulo_original", n_rep=100, semente=20260918, subfamilias=nulo_orig)

    n_ext = int(os.environ.get("N_NULO_EXT", "100"))
    print(f"== 3b. NULO CASADO DA EXTENSAO ({n_ext} replicas) ==")
    nulo_ext = passo_nulo(e_txt, e_num, e_cnt, len(e_senhas), n_rep=n_ext,
                          semente=20260919, gerador=gerar_senhas_ext)
    reg("nulo_extensao", n_rep=n_ext, semente=20260919, subfamilias=nulo_ext)

    resumo = {"repro_senhas": len(senhas), "repro_padding": cnt,
              "revarredura_plaintexts_dele": n_rev, "revarredura_janelas_dele": jan_rev,
              "extensao_senhas": len(e_senhas), "extensao_decifracoes": len(e_senhas) * 6,
              "extensao_padding": e_cnt, "extensao_soft": e_soft, "extensao_janelas": e_jan,
              "nulo_original": nulo_orig, "nulo_extensao": nulo_ext,
              "segundos": round(time.time() - t0, 1)}
    with open(os.path.join(OUT, "resumo.json"), "w", encoding="utf-8") as f:
        json.dump(resumo, f, ensure_ascii=False, indent=2)
    print(json.dumps(resumo, ensure_ascii=False, indent=2))


def demo():
    """Checagem minima do critico: o operador 0-based e as serializacoes extras estao corretos,
    e o oraculo completo acha uma privkey PLANTADA numa janela de 32 B em ordem invertida."""
    assert ordinais0("RAB") == [17, 0, 1], ordinais0("RAB")
    s = serializa_extra([18, 1, 2])
    assert s["produto"] == "36" and s["soma_quadrados"] == "329", s
    assert s["diferencas"] == "171", s          # |1-18|=17, |2-1|=1
    # privkey plantada: um segredo conhecido, colocado INVERTIDO dentro de um bloco maior
    import coincurve
    sec = bytes.fromhex("00" * 31 + "07")
    pub = coincurve.PrivateKey(sec).public_key.format(False)
    salvo = G.TARGET_PUBKEY_HEX
    try:
        G.TARGET_PUBKEY_HEX = pub.hex()
        blob = b"\x00" * 10 + sec[::-1] + b"\x00" * 10
        o, _, _ = oraculo_completo(blob, "demo")
        assert "priv_le" in o, o
    finally:
        G.TARGET_PUBKEY_HEX = salvo
    ok, _ = R.controle_positivo()
    assert ok
    print("demo OK: 0-based, serializacoes extras e oraculo de privkey nas duas ordens de byte")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
