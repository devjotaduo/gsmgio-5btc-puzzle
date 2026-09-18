# -*- coding: utf-8 -*-
r"""
CRITICO ADVERSARIAL da FAMILIA 6 ("referencia pessoal").

HIPOTESE DESTE SCRIPT (prosa, finita, falsificavel)
---------------------------------------------------
O relatorio da familia 6 afirma um NEGATIVO com cobertura de 198.345 senhas e 3.570.210
decifracoes AES, com nulo casado de 100 rodadas e z entre -0,15 e +0,12. Este script
testa TRES afirmacoes independentes e falsificaveis:

 (H-A) COBERTURA: o gerador dele produz exatamente 198.345 strings DISTINTAS e cada uma
       foi de fato decifrada 18 vezes (3 materiais x 3 blobs x 2 KDF). Falsifica-se se a
       contagem distinta ou a contagem de padding valido por sub-familia nao reproduzir.
 (H-B) NULO: os z que ele reporta medem a taxa real (dezenas de milhares de decifracoes)
       contra o desvio-padrao de rodadas do nulo com POUCAS decifracoes cada. Se o nulo
       dele tiver 1-10 candidatos por sub-familia por rodada, o denominador esta inflado
       e os z sao artefato -- o nulo nao tem poder. Falsifica-se recalculando z binomial
       exato contra a taxa PKCS7 e rodando um nulo casado com N por rodada da mesma ordem.
 (H-C) COBERTURA DECLARADA COMO "FORA": as triplas sobre o inventario INTEIRO (ele so rodou
       o recorte de 44 itens prioritarios) e os materiais alternativos (digest cru de 32 B,
       sha256 dupla, raw+LF) nao produzem hit duro. Falsifica-se com um hit duro.

Alem disso: RE-VARREDURA dos 14.002 plaintexts com padding valido que ele registrou, com o
oraculo completo MAIS a ordem de byte INVERTIDA -- que o G.try_password_all NAO faz (o
fast_priv_scan dele so varre janelas de 32 B na ordem direta).

ORACULO DURO (identico ao do repo): privkey de 32 B -> pubkey do premio, OU plaintext
semantico (>=85% ASCII, WIF/hex64 plausivel, blob openssl aninhado, EBCDIC cp273 >= 0,75).
Padding PKCS7 valido sozinho e RUIDO (1/256) e nunca e reportado como sinal.

CAMINHO RAPIDO (e seu controle): para triar padding basta o ULTIMO bloco CBC
(P_n = D(C_n) XOR C_{n-1}). Isso e ~20x mais rapido que decifrar o blob inteiro. Todo
candidato que passa na triagem e RE-DECIFRADO por inteiro com G.try_password_all, entao o
caminho rapido nunca decide nada sozinho -- so poda. O controle positivo exige que a fase 2
passe pelos dois caminhos, e o varre() afirma (assert) que triagem e decifracao completa
concordam em TODO candidato que passa.
"""
import sys, os, json, time, random, hashlib, itertools, collections, math

REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(REPO, r"solver\experiments\claude_endgame_2026_09_02"))
sys.path.insert(0, os.path.join(REPO, r"solver\operador_ensinado_2026_09_17"))
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

OUT = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\critico_familia6")
os.makedirs(OUT, exist_ok=True)
BLOBS = ("SMALL", "COSMIC", "TAIL32")
# hashlib (OpenSSL) e ~2,5x mais rapido que pycryptodome e da EXATAMENTE o mesmo padding
# (conferido em 540.000 decifracoes: 2.168 = 2.168). O nome do KDF fica o do pycryptodome.
HASHES = ((hashlib.md5, "Crypto.Hash.MD5"), (hashlib.sha256, "Crypto.Hash.SHA256"))
P_PKCS7 = sum(256.0 ** -k for k in range(1, 17))   # 0,0039216 -- taxa exata de padding em ruido

# ---------------------------------------------------------------- caminho rapido
_FAST = [(b, G.BLOBS[b][0], G.BLOBS[b][1][-16:], G.BLOBS[b][1][-32:-16]) for b in BLOBS]


def triagem(pw_bytes, fast=_FAST):
    """Devolve lista de (blob, kdf) cujo ULTIMO bloco tem padding PKCS7 valido. So poda."""
    out = []
    for name, salt, cn, cprev in fast:
        for hm, kdfname in HASHES:
            d = hm(pw_bytes + salt).digest()
            d += hm(d + pw_bytes + salt).digest()
            blk = AES.new(d[:32], AES.MODE_ECB).decrypt(cn)
            n = blk[-1] ^ cprev[-1]
            if 1 <= n <= 16 and bytes(a ^ b for a, b in zip(blk[-n:], cprev[-n:])) == bytes([n]) * n:
                out.append((name, kdfname))
    return out


# ---------------------------------------------------------------- controle positivo
def controle_positivo():
    import base64
    raw = base64.b64decode(G.PHASE2_B64)
    G.BLOBS["FASE2"] = (raw[8:16], raw[16:])
    pw = G.shahex("causality")
    h, s = G.try_password_all(pw, blobs=("FASE2",))
    assert h and h[0]["kdf"].endswith("SHA256") and h[0]["head"].startswith("The ironic"), (h, s)
    assert not G.try_password_all("nao_e_a_senha_xyz", blobs=("FASE2",))[0]
    f2 = [("FASE2", G.BLOBS["FASE2"][0], G.BLOBS["FASE2"][1][-16:], G.BLOBS["FASE2"][1][-32:-16])]
    t = triagem(pw.encode(), f2)
    assert ("FASE2", "Crypto.Hash.SHA256") in t, t
    assert not triagem(b"nao_e_a_senha_xyz", f2)
    del G.BLOBS["FASE2"]
    assert G.priv_hit(bytes(32)) is None
    print("[controle+] fase 2 abre por G.try_password_all E pela triagem rapida; lixo nao abre; priv_hit vivo")


# ---------------------------------------------------------------- pipeline (triagem + confirmacao)
def varre(iter_cands, materiais, padf=None, tag=""):
    """iter_cands: iteravel de (string, subfamilia). materiais: fn(str)->[(nome, bytes_senha)].
    Triagem rapida; tudo que passa e RE-DECIFRADO por G.try_password_all (oraculo completo)."""
    hits = []
    pad = collections.Counter()
    ncand = collections.Counter()
    ndec = 0
    t0 = time.time()
    i = 0
    for s, fam in iter_cands:
        ncand[fam] += 1
        i += 1
        for mat, pwb in materiais(s):
            t = triagem(pwb)
            ndec += 6
            if not t:
                continue
            pad[fam] += len(t)
            hard, soft = G.try_password_all(pwb, blobs=BLOBS)
            assert len(hard) + len(soft) == len(t), (s, mat, t, len(hard) + len(soft))
            if padf is not None:
                for rec in hard + soft:
                    padf.write(json.dumps({"fam": fam, "cand": s, "mat": mat, **rec}) + "\n")
            for rec in hard:
                r2 = {"HIT": True, "fam": fam, "cand": s, "mat": mat, **rec}
                hits.append(r2)
                print("[HIT DURO]", json.dumps(r2)[:400])
        if i % 100000 == 0:
            print("   %s %d cands %.0fs" % (tag, i, time.time() - t0), flush=True)
    return hits, pad, ncand, ndec


def mat_padrao(s):
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return (("raw", s.encode("utf-8")), ("sha256hex", h.encode()), ("SHA256HEX", h.upper().encode()))


def mat_extra(s):
    """Materiais que o relatorio declarou FORA: digest cru de 32 B, sha256 dupla (hex), raw+LF,
    e sha256hex(raw+LF)."""
    b = s.encode("utf-8")
    d = hashlib.sha256(b).digest()
    dd = hashlib.sha256(d).hexdigest()
    lf = hashlib.sha256(b + b"\n").hexdigest()
    return (("digest32", d), ("sha256d_hex", dd.encode()), ("raw_lf", b + b"\n"), ("sha256hex_lf", lf.encode()))


# ---------------------------------------------------------------- z binomial
def zbin(k, n, p=P_PKCS7):
    if n == 0:
        return None
    return (k - n * p) / math.sqrt(n * p * (1 - p))


# ---------------------------------------------------------------- etapas
def etapa_reproducao():
    import familia6_referencia_pessoal as F
    c = F.gerar()
    por = collections.Counter(c.values())
    print("[repro] candidatos distintos:", len(c), dict(sorted(por.items())))
    padf = open(os.path.join(OUT, "paddings_repro.jsonl"), "w", encoding="utf-8")
    hits, pad, ncand, ndec = varre(c.items(), mat_padrao, padf, tag="repro")
    padf.close()
    ref = {}
    for f in ("resumo.json", "resumo_extra.json"):
        j = json.load(open(os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\familia6_referencia_pessoal", f)))
        ref.update(j["por_subfamilia"])
    linhas = {}
    for fam in sorted(por):
        n_dec = por[fam] * 18
        linhas[fam] = {"n_cand": por[fam], "n_dec": n_dec, "padding_meu": pad[fam],
                       "padding_dele": ref[fam]["padding"], "bate": pad[fam] == ref[fam]["padding"],
                       "n_cand_dele": ref[fam]["n_cand"], "taxa": pad[fam] / n_dec,
                       "z_binomial_meu": round(zbin(pad[fam], n_dec), 3),
                       "z_reportado_dele": round(ref[fam]["z"], 3)}
        print("[repro] %-22s n=%6d pad_meu=%5d pad_dele=%5d bate=%s  z_bin=%+.2f (ele: %+.2f)"
              % (fam, por[fam], pad[fam], ref[fam]["padding"], pad[fam] == ref[fam]["padding"],
                 zbin(pad[fam], n_dec), ref[fam]["z"]), flush=True)
    tot_pad, tot_dec = sum(pad.values()), sum(por.values()) * 18
    print("[repro] GLOBAL pad=%d dec=%d taxa=%.6f (1/256=%.6f, pkcs7=%.6f) z=%+.2f  hits=%d"
          % (tot_pad, tot_dec, tot_pad / tot_dec, 1 / 256, P_PKCS7, zbin(tot_pad, tot_dec), len(hits)))
    json.dump({"candidatos_distintos": len(c), "decifracoes": tot_dec, "padding": tot_pad,
               "taxa": tot_pad / tot_dec, "z_global": zbin(tot_pad, tot_dec),
               "hits_duros": hits, "por_subfamilia": linhas},
              open(os.path.join(OUT, "reproducao.json"), "w"), indent=1)


def etapa_nulo(rodadas=100, por_rodada=2000, seed=777):
    """Nulo casado FORTE: cada rodada embaralha os caracteres de `por_rodada` candidatos reais
    (preserva comprimento e multiconjunto) -> 2000*18 = 36.000 decifracoes por rodada."""
    import familia6_referencia_pessoal as F
    c = list(F.gerar().items())
    rnd = random.Random(seed)
    taxas = []
    tot_k = tot_n = 0
    t0 = time.time()
    for i in range(rodadas):
        sub = rnd.sample(c, por_rodada)
        k = n = 0
        for s, fam in sub:
            ch = list(s)
            rnd.shuffle(ch)
            sh = "".join(ch)
            for mat, pwb in mat_padrao(sh):
                k += len(triagem(pwb))
                n += 6
        taxas.append(k / n)
        tot_k += k
        tot_n += n
        if (i + 1) % 20 == 0:
            print("   nulo %d/%d %.0fs taxa_acum=%.6f" % (i + 1, rodadas, time.time() - t0, tot_k / tot_n), flush=True)
    mu = sum(taxas) / len(taxas)
    sd = (sum((x - mu) ** 2 for x in taxas) / (len(taxas) - 1)) ** 0.5
    sd_teor = math.sqrt(P_PKCS7 * (1 - P_PKCS7) / (por_rodada * 18))
    res = {"rodadas": rodadas, "por_rodada": por_rodada, "dec_por_rodada": por_rodada * 18,
           "dec_total": tot_n, "padding_total": tot_k, "taxa_nulo": tot_k / tot_n,
           "mu_rodada": mu, "sd_rodada": sd, "sd_teorico_binomial": sd_teor,
           "dispersao_sd_obs_sobre_teorico": sd / sd_teor, "z_nulo_vs_pkcs7": zbin(tot_k, tot_n),
           "segundos": round(time.time() - t0, 1)}
    print("[nulo]", json.dumps(res, indent=1))
    json.dump(res, open(os.path.join(OUT, "nulo.json"), "w"), indent=1)


def _inventario():
    import familia6_referencia_pessoal as F
    base_low = sorted({"".join(s.split()).lower() for _t, s, _p in F.INV})
    base_vb = sorted({s for _t, s, _p in F.INV})
    prio_low = sorted({"".join(s.split()).lower() for _t, s, p in F.INV if p})
    prio_vb = sorted({s for _t, s, p in F.INV if p})
    return F, base_low, base_vb, prio_low, prio_vb


def etapa_triplas(formas=("low", "vb"), sufixo=""):
    """H-C parte 1: triplas sobre o inventario INTEIRO (ele so rodou o recorte prioritario)."""
    F, base_low, base_vb, prio_low, prio_vb = _inventario()
    ja_low = set(itertools.permutations(prio_low, 3))
    ja_vb = set(itertools.permutations(prio_vb, 3))

    def gen():
        if "low" in formas:
            for t in itertools.permutations(base_low, 3):
                if t not in ja_low:
                    yield "".join(t), "T3_low_completo"
        if "vb" in formas:
            for t in itertools.permutations(base_vb, 3):
                if t not in ja_vb:
                    yield "".join(t), "T3_verbatim_completo"
    padf = open(os.path.join(OUT, "paddings_triplas%s.jsonl" % sufixo), "w", encoding="utf-8")
    hits, pad, ncand, ndec = varre(gen(), mat_padrao, padf, tag="triplas")
    padf.close()
    res = {"por_subfamilia": {f: {"n_cand": ncand[f], "n_dec": ncand[f] * 18, "padding": pad[f],
                                 "taxa": pad[f] / (ncand[f] * 18),
                                 "z_binomial": round(zbin(pad[f], ncand[f] * 18), 3)} for f in ncand},
           "decifracoes": ndec, "hits_duros": hits,
           "base_low": len(base_low), "base_vb": len(base_vb)}
    print("[triplas]", json.dumps(res["por_subfamilia"], indent=1), "dec=", ndec, "hits=", len(hits))
    json.dump(res, open(os.path.join(OUT, "triplas%s.json" % sufixo), "w"), indent=1)


def etapa_triplas_low():
    etapa_triplas(formas=("low",), sufixo="_low")


def etapa_triplas_vb():
    etapa_triplas(formas=("vb",), sufixo="_vb")


def etapa_materiais():
    """H-C parte 2: materiais declarados FORA (digest cru 32 B, sha256 dupla, raw+LF, sha256(raw+LF))
    sobre singles + pares + roadmap + shortlist (tudo menos as triplas dele)."""
    import familia6_referencia_pessoal as F
    c = {k: v for k, v in F.gerar().items() if not v.startswith("F3_")}
    print("[materiais] candidatos:", len(c))
    padf = open(os.path.join(OUT, "paddings_materiais.jsonl"), "w", encoding="utf-8")
    hits, pad, ncand, ndec = varre(c.items(), mat_extra, padf, tag="materiais")
    padf.close()
    bw = 0
    for s in c:
        b = s.encode("utf-8")
        for k in (hashlib.sha256(hashlib.sha256(b).digest()).digest(), hashlib.sha256(b + b"\n").digest()):
            bw += 1
            if G.priv_hit(k):
                print("[HIT DURO/PRIVKEY]", s, k.hex())
                hits.append({"HIT": True, "cand": s, "priv": k.hex()})
    res = {"n_cand": len(c), "decifracoes": ndec, "padding": sum(pad.values()),
           "taxa": sum(pad.values()) / ndec, "z_binomial": round(zbin(sum(pad.values()), ndec), 3),
           "brainwallets_extra": bw, "hits_duros": hits,
           "por_subfamilia": {f: {"n_cand": ncand[f], "padding": pad[f]} for f in ncand}}
    print("[materiais]", json.dumps({k: v for k, v in res.items() if k != "hits_duros"}, indent=1))
    json.dump(res, open(os.path.join(OUT, "materiais.json"), "w"), indent=1)


def etapa_revarredura():
    """Re-varre TODO plaintext com padding valido que ele registrou (campo hex), com o oraculo
    completo E a ordem de byte INVERTIDA -- que o fast_priv_scan do kit nao cobre."""
    from coincurve import PublicKey
    tgt = bytes.fromhex(G.TARGET_PUBKEY_HEX)
    base = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\familia6_referencia_pessoal")
    arqs = [os.path.join(base, f) for f in ("paddings.jsonl", "paddings_extra.jsonl")]
    n = 0
    janelas = 0
    hits = []
    maxpr = 0.0
    maxeb = 0.0
    nested = 0
    porblob = collections.Counter()
    t0 = time.time()
    for a in arqs:
        for ln in open(a, encoding="utf-8"):
            r = json.loads(ln)
            p = bytes.fromhex(r["hex"])
            n += 1
            porblob[r["blob"] + "/" + r["kdf"].split(".")[-1]] += 1
            if G.semantic(p):
                hits.append({"tipo": "semantic", **{k: r[k] for k in ("fam", "cand", "mat", "blob", "kdf")}})
            if G.nested_blob(p):
                nested += 1
            maxpr = max(maxpr, G.printable(p))
            maxeb = max(maxeb, G.ebcdic_sig(p))
            for buf in (p, p[::-1]):
                for j in range(0, len(buf) - 31):
                    janelas += 1
                    try:
                        if PublicKey.from_valid_secret(buf[j:j + 32]).format(False) == tgt:
                            hits.append({"tipo": "privkey", "priv": buf[j:j + 32].hex(), **r})
                            print("[HIT DURO/PRIVKEY]", buf[j:j + 32].hex())
                    except Exception:
                        pass
            if n % 2000 == 0:
                print("   revarredura %d janelas=%d %.0fs" % (n, janelas, time.time() - t0), flush=True)
    res = {"plaintexts_varridos": n, "janelas_32B_ambas_ordens": janelas, "nested_blob": nested,
           "max_printable": round(maxpr, 3), "max_ebcdic_sig": round(maxeb, 3),
           "por_blob_kdf": dict(porblob), "hits_duros": hits, "segundos": round(time.time() - t0, 1)}
    print("[revarredura]", json.dumps({k: v for k, v in res.items() if k != "hits_duros"}, indent=1),
          "hits:", len(hits))
    json.dump(res, open(os.path.join(OUT, "revarredura.json"), "w"), indent=1)


def etapa_separadores():
    """H-C parte 3: pares com SEPARADOR (espaco, hifen, "and", "-and-") -- o relatorio declarou
    isso fora. Prior baixo (nenhuma senha verificada do puzzle usa separador), mas e barato."""
    F, base_low, base_vb, prio_low, prio_vb = _inventario()
    seps_low = (" ", "-", "and", "_", ".")
    def gen():
        for a, b in itertools.permutations(base_low, 2):
            for sp in seps_low:
                yield a + sp + b, "SEP_pair_low"
        for a, b in itertools.permutations(base_vb, 2):
            for sp in (" ", "-", " and "):
                yield a + sp + b, "SEP_pair_verbatim"
    padf = open(os.path.join(OUT, "paddings_separadores.jsonl"), "w", encoding="utf-8")
    hits, pad, ncand, ndec = varre(gen(), mat_padrao, padf, tag="separadores")
    padf.close()
    res = {"por_subfamilia": {f: {"n_cand": ncand[f], "n_dec": ncand[f] * 18, "padding": pad[f],
                                 "taxa": pad[f] / (ncand[f] * 18),
                                 "z_binomial": round(zbin(pad[f], ncand[f] * 18), 3)} for f in ncand},
           "decifracoes": ndec, "hits_duros": hits}
    print("[separadores]", json.dumps(res["por_subfamilia"], indent=1), "dec=", ndec, "hits=", len(hits))
    json.dump(res, open(os.path.join(OUT, "separadores.json"), "w"), indent=1)


def etapa_calibracao(n=1000000, seed=4242):
    """Calibracao independente do MEU pipeline: n senhas de bytes aleatorios (comprimento sorteado
    na mesma faixa dos candidatos reais) -> taxa de padding por blob e por KDF contra a taxa PKCS7
    exata. Serve para decidir se um z de padding levemente alto num braco e sinal ou e a taxa-base
    do proprio par (C_n, C_{n-1}) destes blobs."""
    rnd = random.Random(seed)
    cnt = collections.Counter()
    tot = collections.Counter()
    t0 = time.time()
    for i in range(n):
        L = rnd.randint(8, 120)
        pw = bytes(rnd.randrange(256) for _ in range(L))
        for name, salt, cn, cprev in _FAST:
            for hm, kdfname in HASHES:
                key = name + "/" + kdfname.split(".")[-1]
                tot[key] += 1
                d = hm(pw + salt).digest()
                d += hm(d + pw + salt).digest()
                blk = AES.new(d[:32], AES.MODE_ECB).decrypt(cn)
                k = blk[-1] ^ cprev[-1]
                if 1 <= k <= 16 and bytes(a ^ b for a, b in zip(blk[-k:], cprev[-k:])) == bytes([k]) * k:
                    cnt[key] += 1
        if (i + 1) % 250000 == 0:
            print("   calib %d %.0fs" % (i + 1, time.time() - t0), flush=True)
    linhas = {k: {"n": tot[k], "pad": cnt[k], "taxa": cnt[k] / tot[k], "z": round(zbin(cnt[k], tot[k]), 3)}
              for k in sorted(tot)}
    K, N = sum(cnt.values()), sum(tot.values())
    res = {"n_senhas": n, "dec_total": N, "padding": K, "taxa": K / N, "p_pkcs7": P_PKCS7,
           "z_global": zbin(K, N), "por_blob_kdf": linhas, "segundos": round(time.time() - t0, 1)}
    print("[calibracao]", json.dumps(res, indent=1))
    json.dump(res, open(os.path.join(OUT, "calibracao.json"), "w"), indent=1)


# ================================================================ continuacao (sessao 2)
def _gen_triplas(forma):
    """Gera as triplas do inventario INTEIRO menos as que ele ja rodou (recorte prioritario)."""
    F, base_low, base_vb, prio_low, prio_vb = _inventario()
    base, prio, fam = ((base_low, prio_low, "T3_low_completo") if forma == "low"
                       else (base_vb, prio_vb, "T3_verbatim_completo"))
    ja = set(itertools.permutations(prio, 3))
    for t in itertools.permutations(base, 3):
        if t not in ja:
            yield "".join(t), fam


def _roda_triplas(gen, fam, sufixo):
    """Roda varre() e grava json. Conta tambem strings DISTINTAS (as triplas nao passam pelo
    dedup do gerar() dele)."""
    padf = open(os.path.join(OUT, "paddings_triplas%s.jsonl" % sufixo), "w", encoding="utf-8")
    dist = set()

    def g():
        for s, f in gen:
            dist.add(hashlib.blake2b(s.encode(), digest_size=8).digest())
            yield s, f
    hits, pad, ncand, ndec = varre(g(), mat_padrao, padf, tag=sufixo)
    padf.close()
    res = {"subfamilia": fam, "n_cand": ncand[fam], "n_cand_distintos": len(dist), "n_dec": ndec,
           "padding": pad[fam], "taxa": pad[fam] / ndec if ndec else None,
           "z_binomial": round(zbin(pad[fam], ndec), 3) if ndec else None, "hits_duros": hits}
    print("[triplas%s]" % sufixo, json.dumps({k: v for k, v in res.items() if k != "hits_duros"}),
          "hits=", len(hits), flush=True)
    json.dump(res, open(os.path.join(OUT, "triplas%s.json" % sufixo), "w"), indent=1)
    return res


def etapa_triplas_low_resume():
    """Retoma T3_low_completo a partir do ULTIMO candidato com padding registrado no parcial
    (inclusive: ele pode ter sido interrompido no meio dos 3 materiais). Na fusao, os paddings
    desse candidato no arquivo parcial sao descartados."""
    last = None
    for ln in open(os.path.join(OUT, "paddings_triplas_low.jsonl"), encoding="utf-8"):
        last = json.loads(ln)["cand"]
    idx = None
    for i, (s, _f) in enumerate(_gen_triplas("low")):
        if s == last:
            idx = i
            break
    print("[resume] ultimo cand do parcial: %r  indice=%s" % (last, idx), flush=True)
    assert idx is not None
    gen = (x for i, x in enumerate(_gen_triplas("low")) if i >= idx)
    res = _roda_triplas(gen, "T3_low_completo", "_low_resume")
    res["retomado_do_indice"] = idx
    res["ultimo_cand_parcial"] = last
    json.dump(res, open(os.path.join(OUT, "triplas_low_resume.json"), "w"), indent=1)


def etapa_triplas_vb_full():
    _roda_triplas(_gen_triplas("vb"), "T3_verbatim_completo", "_vb")


def etapa_f5_lookelsewhere(rodadas=200, seed=99):
    """F5_shortlist: 684 paddings em 151.200 decifracoes (3 materiais padrao + 4 extra) => z_bin +3,7.
    Nulo ESPECIFICO: `rodadas` rodadas; em cada uma os 3.600 candidatos F5 com caracteres embaralhados
    (mesmo comprimento, mesmo multiconjunto) passam pelos MESMOS 7 materiais. Conta rodadas >= 684 e
    da a distribuicao. Se o excesso fosse artefato de comprimento/charset, o nulo o reproduziria."""
    import familia6_referencia_pessoal as F
    f5 = [s for s, f in F.gerar().items() if f == "F5_shortlist"]
    assert len(f5) == 3600
    rnd = random.Random(seed)

    def mats(s):
        return mat_padrao(s) + mat_extra(s)
    ks = []
    t0 = time.time()
    for i in range(rodadas):
        k = n = 0
        for s in f5:
            ch = list(s)
            rnd.shuffle(ch)
            sh = "".join(ch)
            for _m, pwb in mats(sh):
                k += len(triagem(pwb))
                n += 6
        ks.append(k)
        if (i + 1) % 25 == 0:
            print("   f5nulo %d/%d %.0fs media=%.1f max=%d" % (i + 1, rodadas, time.time() - t0,
                                                              sum(ks) / len(ks), max(ks)), flush=True)
    n_dec = 3600 * 7 * 6
    mu = sum(ks) / len(ks)
    sd = (sum((x - mu) ** 2 for x in ks) / (len(ks) - 1)) ** 0.5
    obs = 684
    z = zbin(obs, n_dec)
    p1 = 0.5 * math.erfc(z / math.sqrt(2))
    bracos = 8 + 6 + 2 + 2   # repro(8 subfams) + materiais(6) + separadores(2) + triplas(2)
    res = {"rodadas": rodadas, "n_dec_por_rodada": n_dec, "obs_real": obs, "esperado_pkcs7": n_dec * P_PKCS7,
           "z_binomial_real": round(z, 3), "p_unilateral": p1, "bracos_look_elsewhere": bracos,
           "p_corrigido_bonferroni": min(1.0, p1 * bracos),
           "nulo_mu": mu, "nulo_sd": sd, "nulo_max": max(ks), "nulo_min": min(ks),
           "rodadas_nulo_ge_obs": sum(1 for x in ks if x >= obs),
           "z_real_vs_nulo_empirico": round((obs - mu) / sd, 3) if sd else None,
           "ks": ks, "segundos": round(time.time() - t0, 1)}
    print("[f5] ", json.dumps({k: v for k, v in res.items() if k != "ks"}, indent=1), flush=True)
    json.dump(res, open(os.path.join(OUT, "f5_lookelsewhere.json"), "w"), indent=1)


def etapa_materiais2():
    """Material que faltou na lista dele e na minha: sha256hex aplicado DUAS vezes no estilo do puzzle
    (hex -> string -> sha256 -> hex), sobre TODOS os 198.345 candidatos; + brainwallet desse digest."""
    import familia6_referencia_pessoal as F
    c = F.gerar()

    def m(s):
        h1 = hashlib.sha256(s.encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(h1.encode()).hexdigest()
        return (("hexhex", h2.encode()),)
    padf = open(os.path.join(OUT, "paddings_materiais2.jsonl"), "w", encoding="utf-8")
    hits, pad, ncand, ndec = varre(c.items(), m, padf, tag="hexhex")
    padf.close()
    bw = 0
    for s in c:
        h1 = hashlib.sha256(s.encode("utf-8")).hexdigest()
        k = hashlib.sha256(h1.encode()).digest()
        bw += 1
        if G.priv_hit(k):
            hits.append({"HIT": True, "cand": s, "priv": k.hex()})
            print("[HIT DURO/PRIVKEY]", s)
    res = {"material": "sha256hex(sha256hex(s))", "n_cand": len(c), "decifracoes": ndec,
           "padding": sum(pad.values()), "taxa": sum(pad.values()) / ndec,
           "z_binomial": round(zbin(sum(pad.values()), ndec), 3), "brainwallets": bw, "hits_duros": hits}
    print("[materiais2]", json.dumps({k: v for k, v in res.items() if k != "hits_duros"}), flush=True)
    json.dump(res, open(os.path.join(OUT, "materiais2.json"), "w"), indent=1)


def etapa_revarredura_novos():
    """Re-varre com oraculo completo + ordem de byte INVERTIDA todos os paddings que ESTE critico
    produziu (os do relatorio dele ja foram varridos em etapa_revarredura)."""
    from coincurve import PublicKey
    tgt = bytes.fromhex(G.TARGET_PUBKEY_HEX)
    todos = ("paddings_materiais.jsonl", "paddings_materiais2.jsonl", "paddings_separadores.jsonl",
             "paddings_triplas_low.jsonl", "paddings_triplas_low_resume.jsonl", "paddings_triplas_vb.jsonl")
    # CRIT_ARQS="a.jsonl,b.jsonl" restringe; CRIT_SUF distingue o json de saida (varredura em lotes)
    sel = os.environ.get("CRIT_ARQS")
    arqs = [f for f in (sel.split(",") if sel else todos) if os.path.exists(os.path.join(OUT, f))]
    suf = os.environ.get("CRIT_SUF", "")
    n = janelas = nested = 0
    hits = []
    maxpr = maxeb = 0.0
    porarq = collections.Counter()
    t0 = time.time()
    for a in arqs:
        for ln in open(os.path.join(OUT, a), encoding="utf-8"):
            r = json.loads(ln)
            p = bytes.fromhex(r["hex"])
            n += 1
            porarq[a] += 1
            if G.semantic(p):
                hits.append({"tipo": "semantic", "arq": a,
                             **{k: r.get(k) for k in ("fam", "cand", "mat", "blob", "kdf")}})
            if G.nested_blob(p):
                nested += 1
            maxpr = max(maxpr, G.printable(p))
            maxeb = max(maxeb, G.ebcdic_sig(p))
            for buf in (p, p[::-1]):
                for j in range(0, len(buf) - 31):
                    janelas += 1
                    try:
                        if PublicKey.from_valid_secret(buf[j:j + 32]).format(False) == tgt:
                            hits.append({"tipo": "privkey", "priv": buf[j:j + 32].hex(), "arq": a, **r})
                            print("[HIT DURO/PRIVKEY]")
                    except Exception:
                        pass
            if n % 10000 == 0:
                print("   revarredura_novos %d janelas=%d %.0fs" % (n, janelas, time.time() - t0), flush=True)
    res = {"arquivos": dict(porarq), "plaintexts_varridos": n, "janelas_32B_ambas_ordens": janelas,
           "nested_blob": nested, "max_printable": round(maxpr, 3), "max_ebcdic_sig": round(maxeb, 3),
           "hits_duros": hits, "segundos": round(time.time() - t0, 1)}
    print("[revarredura_novos]", json.dumps({k: v for k, v in res.items() if k != "hits_duros"}, indent=1),
          "hits:", len(hits), flush=True)
    json.dump(res, open(os.path.join(OUT, "revarredura_novos%s.json" % suf), "w"), indent=1)


def etapa_final():
    """Consolida TODOS os jsons deste critico (sessao 1 + sessao 2) num resumo unico com totais
    honestos: decifracoes, paddings, hits, candidatos distintos por braco e sobreposicao low/vb."""
    F, base_low, base_vb, prio_low, prio_vb = _inventario()
    J = {}
    for f in os.listdir(OUT):
        if f.endswith(".json") and f != "resumo_critico_final.json":
            J[f[:-5]] = json.load(open(os.path.join(OUT, f), encoding="utf-8"))
    # triplas low: parcial (ate o indice retomado, exclusive) + resume
    low_par = J.get("triplas_low_parcial", {})
    low_res = J.get("triplas_low_resume", {})
    last = low_res.get("ultimo_cand_parcial")
    pad_par_sem_last = 0
    for ln in open(os.path.join(OUT, "paddings_triplas_low.jsonl"), encoding="utf-8"):
        if json.loads(ln)["cand"] != last:
            pad_par_sem_last += 1
    idx = low_res.get("retomado_do_indice")
    n_low = len(base_low) * (len(base_low) - 1) * (len(base_low) - 2) - len(prio_low) * (len(prio_low) - 1) * (len(prio_low) - 2)
    low_tot = {"n_cand": n_low, "n_cand_parcial": idx, "n_cand_resume": low_res.get("n_cand"),
               "completo": (idx or 0) + (low_res.get("n_cand") or 0) == n_low,
               "n_dec": n_low * 18, "padding": pad_par_sem_last + (low_res.get("padding") or 0)}
    low_tot["taxa"] = low_tot["padding"] / low_tot["n_dec"]
    low_tot["z_binomial"] = round(zbin(low_tot["padding"], low_tot["n_dec"]), 3)
    # sobreposicao low/vb: itens verbatim que ja sao minusculo-sem-espaco geram a MESMA string nas duas formas
    ident = [s for s in base_vb if s == "".join(s.split()).lower()]
    k = len(ident)
    ident_prio = [s for s in prio_vb if s == "".join(s.split()).lower()]
    kp = len(ident_prio)
    overlap = k * (k - 1) * (k - 2) - kp * (kp - 1) * (kp - 2)
    vb = J.get("triplas_vb", {})
    bracos = {
        "reproducao_dele": {"n_cand": J["reproducao"]["candidatos_distintos"], "n_dec": J["reproducao"]["decifracoes"],
                            "padding": J["reproducao"]["padding"], "z": round(J["reproducao"]["z_global"], 3)},
        "materiais_extra(4)": {"n_cand": J["materiais"]["n_cand"], "n_dec": J["materiais"]["decifracoes"],
                               "padding": J["materiais"]["padding"], "z": J["materiais"]["z_binomial"],
                               "brainwallets": J["materiais"]["brainwallets_extra"]},
        "materiais2_hexhex": {k2: J["materiais2"].get(k2) for k2 in ("n_cand", "decifracoes", "padding", "z_binomial", "brainwallets")} if "materiais2" in J else None,
        "separadores": {"n_cand": sum(v["n_cand"] for v in J["separadores"]["por_subfamilia"].values()),
                        "n_dec": J["separadores"]["decifracoes"],
                        "padding": sum(v["padding"] for v in J["separadores"]["por_subfamilia"].values())},
        "T3_low_completo": low_tot,
        "T3_verbatim_completo": {"n_cand": vb.get("n_cand"), "n_cand_distintos": vb.get("n_cand_distintos"),
                                 "n_dec": vb.get("n_dec"), "padding": vb.get("padding"), "z_binomial": vb.get("z_binomial"),
                                 "strings_identicas_a_T3_low": overlap,
                                 "itens_vb_ja_minusculos": k, "itens_prio_vb_ja_minusculos": kp},
        "nulo_forte": {"dec": J["nulo"]["dec_total"], "padding": J["nulo"]["padding_total"], "taxa": J["nulo"]["taxa_nulo"],
                       "sd_obs/sd_binomial": round(J["nulo"]["dispersao_sd_obs_sobre_teorico"], 3),
                       "z_vs_pkcs7": round(J["nulo"]["z_nulo_vs_pkcs7"], 2)},
        "calibracao_bytes_aleatorios": {"dec": J["calibracao"]["dec_total"], "padding": J["calibracao"]["padding"],
                                        "z": round(J["calibracao"]["z_global"], 2)},
        "f5_lookelsewhere": {k2: J["f5_lookelsewhere"].get(k2) for k2 in
                             ("obs_real", "esperado_pkcs7", "z_binomial_real", "p_unilateral", "bracos_look_elsewhere",
                              "p_corrigido_bonferroni", "nulo_mu", "nulo_sd", "nulo_max", "rodadas_nulo_ge_obs",
                              "z_real_vs_nulo_empirico", "rodadas")} if "f5_lookelsewhere" in J else None,
        "revarredura_dele": {k2: J["revarredura"].get(k2) for k2 in ("plaintexts_varridos", "janelas_32B_ambas_ordens", "max_printable", "max_ebcdic_sig", "nested_blob")},
        "revarredura_novos": {k2: J["revarredura_novos"].get(k2) for k2 in ("plaintexts_varridos", "janelas_32B_ambas_ordens", "max_printable", "max_ebcdic_sig", "nested_blob", "arquivos")} if "revarredura_novos" in J else None,
        "sobreposicao_corpus_historico": J["sobreposicao_corpus"],
    }
    dec_real = (J["reproducao"]["decifracoes"] + J["materiais"]["decifracoes"] + J["separadores"]["decifracoes"]
                + low_tot["n_dec"] + (vb.get("n_dec") or 0) + (J["materiais2"]["decifracoes"] if "materiais2" in J else 0))
    hits = []
    for name, j in J.items():
        h = j.get("hits_duros")
        if h:
            hits.append((name, h))
    res = {"bracos": bracos, "TOTAL_DECIFRACOES_HIPOTESE": dec_real,
           "TOTAL_DECIFRACOES_NULO_E_CALIBRACAO": J["nulo"]["dec_total"] + J["calibracao"]["dec_total"]
           + (J["f5_lookelsewhere"]["rodadas"] * J["f5_lookelsewhere"]["n_dec_por_rodada"] if "f5_lookelsewhere" in J else 0),
           "HITS_DUROS": hits, "n_itens_inventario": len(F.INV),
           "base_low": len(base_low), "base_vb": len(base_vb), "prio_low": len(prio_low), "prio_vb": len(prio_vb)}
    print(json.dumps(res, indent=1, ensure_ascii=False))
    json.dump(res, open(os.path.join(OUT, "resumo_critico_final.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)


if __name__ == "__main__":
    controle_positivo()
    for etapa in sys.argv[1:]:
        print("=" * 30, etapa, flush=True)
        globals()["etapa_" + etapa]()
