# -*- coding: utf-8 -*-
"""
CRITICO ADVERSARIAL da familia 5 ("yinyang como operacao de dualidade").

HIPOTESE EM PROSA (finita, falsificavel) — o que ESTE script tenta provar
------------------------------------------------------------------------
O agente da familia 5 afirma ter fechado, com 10.920 senhas distintas e nulo casado, a ideia de que
"THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF" seja uma instrucao estrutural cujo resultado
(uma metade servindo de senha da outra, ou a combinacao dual das duas) abre um dos tres blobs.
A hipotese adversarial e que esse negativo NAO se sustenta como declarado, por um destes motivos:
(H1) a cobertura esta inflada — as "10.920 senhas distintas" contem duplicatas;
(H2) o pipeline dele diverge de uma implementacao independente de EVP_BytesToKey+AES-256-CBC,
     escondendo ou inventando padding valido;
(H3) o oraculo aplicado foi frouxo, ou algum dos 246 plaintexts com padding valido passa no oraculo
     duro completo (nested_blob / ebcdic_sig / privkey em qualquer janela de 32 B, NAS DUAS ORDENS
     DE BYTE — ele so varreu a ordem direta);
(H4) o nulo dele e fraco: a sub-familia E (7.650 senhas) so foi embaralhada com uma amostra de 2.000
     senhas por replica (NULL_CAP=2000), o que nao foi declarado no relatorio;
(H5) os buracos que ele declarou sao o pedaco que importa: (i) cortes de dbbi/faed em TODOS os
     pontos, nao so no meio; (ii) triplas na gramatica do par; (iii) particoes internas do COSMIC.

FALSIFICACAO DE CADA UMA: H1 se resolve contando; H2, se a taxa de padding independente bater com a
dele em cada sub-familia; H3, se nenhum dos 246 plaintexts disparar o oraculo completo; H4, se um
nulo de 100 replicas SEM cap sobre o conjunto INTEIRO devolver z dentro da banda calibrada
(-1,2 a +2,1); H5, se as tres extensoes rodarem e derem 0 hits duros com taxa de padding em 1/256.
Se tudo isso acontecer, a familia esta CONFIRMADO_NEGATIVO com a cobertura corrigida.

CONTROLE POSITIVO: o blob da fase 2 abre com sha256hex("causality") sob EVP-SHA256 e NAO sob MD5 —
verificado por implementacao PROPRIA de EVP_BytesToKey (hashlib puro) e, alem disso, pelo binario
openssl real do sistema. Controle negativo casado: sha256hex("caUsality") nao abre.
NULO CASADO: 100 replicas por sub-familia preservando tipo/comprimento/alfabeto, conjunto inteiro.

Uso: python critico_familia5.py
"""
import sys, os, json, time, random, base64, hashlib, itertools, statistics, subprocess, multiprocessing as mp

SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
FAM5 = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\operador_ensinado_2026_09_17"
sys.path.insert(0, SP)
sys.path.insert(0, FAM5)
import gsmg_common as G
from Crypto.Cipher import AES

OUT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\critico_familia5"
FAM5_LOG = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\familia5_dualidade\familia5_dualidade.jsonl"
os.makedirs(OUT, exist_ok=True)
LOG = os.path.join(OUT, "critico_familia5.jsonl")
TARGETS = ("SMALL", "COSMIC", "TAIL32")
NULL_ITERS = 100
WORKERS = 12

TGT_PUB = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")


# ---------------------------------------------------------------- pipeline INDEPENDENTE
def evp_indep(pw, salt, algo):
    """EVP_BytesToKey do openssl, reimplementado com hashlib puro (nao usa G.evp)."""
    d = b""
    prev = b""
    while len(d) < 48:
        prev = hashlib.new(algo, prev + pw + salt).digest()
        d += prev
    return d[:32], d[32:48]


def unpad_indep(p):
    """PKCS7 reimplementado (nao usa G.unpad)."""
    if not p:
        return None
    n = p[-1]
    if n < 1 or n > 16 or len(p) < n:
        return None
    return p[:-n] if p[-n:] == bytes([n]) * n else None


def dec_indep(pw, blob, algo):
    salt, ct = G.BLOBS[blob]
    pw = pw.encode() if isinstance(pw, str) else pw
    k, iv = evp_indep(pw, salt, algo)
    return unpad_indep(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))


# ---------------------------------------------------------------- oraculo duro COMPLETO
def priv_scan_bothways(buf):
    """fast_priv_scan em toda janela de 32 B, NA ORDEM DIRETA E NA INVERTIDA (o agente so fez direta)."""
    from coincurve import PublicKey
    hits = []
    for nome, b in (("fwd", buf), ("rev", buf[::-1])):
        for j in range(0, len(b) - 31):
            sec = b[j:j + 32]
            try:
                if PublicKey.from_valid_secret(sec).format(False) == TGT_PUB:
                    hits.append({"ordem": nome, "off": j, "priv": sec.hex()})
            except Exception:
                pass
    return hits


def oraculo_duro(p):
    """Devolve dict com TODOS os componentes do oraculo duro, nada de escore frouxo."""
    return {"printable": round(G.printable(p), 3),
            "semantic": bool(G.semantic(p)),
            "nested": bool(G.nested_blob(p)),
            "ebcdic": round(G.ebcdic_sig(p), 3),
            "wif": G.wif_candidates(p.decode("latin-1")),
            "hex64": G.hex64_candidates(p.decode("latin-1")),
            "priv": priv_scan_bothways(p) if len(p) >= 32 else []}


def eh_hit(o):
    return bool(o["semantic"] or o["nested"] or o["ebcdic"] >= 0.75 or o["wif"] or o["hex64"] or o["priv"])


# ---------------------------------------------------------------- controles
def controle_positivo():
    raw = base64.b64decode(G.PHASE2_B64)
    salt, ct = raw[8:16], raw[16:]
    pw = G.shahex("causality").encode()
    out = {}
    for algo in ("sha256", "md5"):
        k, iv = evp_indep(pw, salt, algo)
        p = unpad_indep(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        out[algo] = None if p is None else p[:40].decode("latin-1")
    k, iv = evp_indep(G.shahex("caUsality").encode(), salt, "sha256")
    neg = unpad_indep(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
    # controle com o binario openssl REAL do sistema (base64 em linhas de 64, como o arquivo do site)
    cli = {}
    for md in ("sha256", "md5"):
        try:
            r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-d", "-a", "-md", md,
                                "-pass", "pass:" + G.shahex("causality")],
                               input=openssl_b64(G.PHASE2_B64), capture_output=True, timeout=60)
            cli[md] = r.stdout[:40].decode("latin-1") if r.returncode == 0 else "rc=%d" % r.returncode
        except Exception as e:
            cli[md] = "erro:%s" % e
    ok = bool(out["sha256"] and out["sha256"].startswith("The ironic") and out["md5"] is None
              and (neg is None or not G.semantic(neg))
              and str(cli.get("sha256", "")).startswith("The ironic") and cli.get("md5") == "rc=1")
    return {"passou": ok, "evp_sha256": out["sha256"], "evp_md5": out["md5"],
            "negativo_caUsality": None if neg is None else neg[:40].decode("latin-1"),
            "openssl_cli": cli}


def openssl_b64(s):
    import textwrap
    return ("\n".join(textwrap.wrap(s, 64)) + "\n").encode()


def openssl_spot(recs, k=5):
    """Cross-check com o binario openssl REAL: k plaintexts com padding valido devem bater byte a byte."""
    import textwrap
    out = []
    for rec in recs[:k]:
        salt, ct = G.BLOBS[rec["blob"]]
        b64 = base64.b64encode(b"Salted__" + salt + ct).decode()
        pw = rec["pw"]
        r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-d", "-a", "-md", rec["kdf"],
                            "-pass", "pass:" + pw],
                           input=openssl_b64(b64), capture_output=True, timeout=60)
        out.append({"tag": rec["tag"], "blob": rec["blob"], "kdf": rec["kdf"],
                    "bate": r.returncode == 0 and r.stdout.hex() == rec["hex"]})
    return out


# ---------------------------------------------------------------- workers
def _w_medido(args):
    """Roda um lote de senhas pelo pipeline INDEPENDENTE nos 3 blobs x 2 KDF."""
    lote, = args
    trials = pad = 0
    mx = 0.0
    recs = []
    for tag, pw in lote:
        for blob in TARGETS:
            for algo in ("sha256", "md5"):
                trials += 1
                p = dec_indep(pw, blob, algo)
                if p is None:
                    continue
                pad += 1
                pr = G.printable(p)
                mx = max(mx, pr)
                recs.append({"tag": tag, "blob": blob, "kdf": algo, "len": len(p),
                             "printable": round(pr, 3), "hex": p.hex(),
                             "pw": pw.hex() if isinstance(pw, bytes) else pw,
                             "pw_str": isinstance(pw, str)})
    return trials, pad, mx, recs


def _shuffle_like(pw, rnd):
    if isinstance(pw, bytes):
        return bytes(rnd.randrange(256) for _ in range(len(pw)))
    alpha = sorted(set(pw)) or ["a"]
    return "".join(rnd.choice(alpha) for _ in pw)


def _w_nulo(args):
    """Uma replica de nulo casado sobre o conjunto INTEIRO da sub-familia."""
    pws, seed = args
    r = random.Random(seed)
    trials = pad = sem = 0
    mx = 0.0
    for pw in pws:
        q = _shuffle_like(pw, r)
        for blob in TARGETS:
            for algo in ("sha256", "md5"):
                trials += 1
                p = dec_indep(q, blob, algo)
                if p is None:
                    continue
                pad += 1
                pr = G.printable(p)
                mx = max(mx, pr)
                if G.semantic(p):
                    sem += 1
    return trials, pad, sem, mx


def chunk(seq, n):
    k = max(1, (len(seq) + n - 1) // n)
    return [seq[i:i + k] for i in range(0, len(seq), k)]


def roda(pool, nome, pws, fh, com_nulo=True):
    t0 = time.time()
    lotes = [(c,) for c in chunk(pws, WORKERS * 4)]
    trials = pad = 0
    mx = 0.0
    recs = []
    for t, pd, m, rr in pool.imap_unordered(_w_medido, lotes):
        trials += t
        pad += pd
        mx = max(mx, m)
        recs += rr
    hits = []
    for rec in recs:
        p = bytes.fromhex(rec["hex"])
        o = oraculo_duro(p)
        rec["oraculo"] = o
        fh.write(json.dumps({"tipo": "padding", **rec}, ensure_ascii=False) + "\n")
        if eh_hit(o):
            hits.append(rec)
            fh.write(json.dumps({"tipo": "HARD", **rec}, ensure_ascii=False) + "\n")
    spot = openssl_spot([r for r in recs if r.get("pw_str")]) if recs else []
    res = {"familia": nome, "senhas_listadas": len(pws), "openssl_spot": spot,
           "senhas_distintas": len({(x if isinstance(x, bytes) else x.encode()) for _, x in pws}),
           "decifracoes": trials, "padding_valido": pad,
           "taxa_padding": round(pad / max(1, trials), 6), "max_printable": round(mx, 3),
           "hits_duros": len(hits)}
    if com_nulo:
        so = [pw for _, pw in pws]
        jobs = [(so, 7000 + i) for i in range(NULL_ITERS)]
        taxas, sems, mxs = [], 0, []
        for t, pd, sm, m in pool.imap_unordered(_w_nulo, jobs):
            taxas.append(pd / t)
            sems += sm
            mxs.append(m)
        mu = statistics.mean(taxas)
        sd = statistics.pstdev(taxas) or 1e-12
        res["nulo"] = {"replicas": NULL_ITERS, "senhas_por_replica": len(so),
                       "decifracoes": NULL_ITERS * len(so) * 6, "taxa_media": round(mu, 6),
                       "taxa_sd": round(sd, 6), "hits_semanticos": sems,
                       "max_printable_max": round(max(mxs), 3)}
        res["z_padding"] = round((res["taxa_padding"] - mu) / sd, 3)
    res["segundos"] = round(time.time() - t0, 1)
    fh.write(json.dumps({"tipo": "resumo", **res}, ensure_ascii=False) + "\n")
    print(json.dumps(res, ensure_ascii=False))
    return res


# ---------------------------------------------------------------- extensoes (o que ele deixou de fora)
def text_forms(s):
    for t in sorted({s, s.lower(), s.upper()}):
        yield "txt", t
        yield "sha", G.shahex(t)


def ext_cortes_todos():
    """(i) TODOS os pontos de corte de dbbi (1..90) e de faed (1..569), nao so o meio."""
    out = []
    for nome, txt in (("dbbi", G.DBBI), ("faed", G.FAED)):
        n = len(txt)
        for i in range(1, n):
            a, b = txt[:i], txt[i:]
            out.append(("X1/%s/%d/A" % (nome, i), a))
            out.append(("X1/%s/%d/B" % (nome, i), b))
            out.append(("X1/%s/%d/shaA" % (nome, i), G.shahex(a)))
            out.append(("X1/%s/%d/shaB" % (nome, i), G.shahex(b)))
            out.append(("X1/%s/%d/shaAB" % (nome, i), G.shahex(a + b)))
            out.append(("X1/%s/%d/shaBA" % (nome, i), G.shahex(b + a)))
            out.append(("X1/%s/%d/BA" % (nome, i), b + a))
            out.append(("X1/%s/%d/shashas" % (nome, i), G.shahex(G.shahex(a) + G.shahex(b))))
    return out


def ext_cosmic_interno():
    """(iii) particoes internas do COSMIC: todo limite de bloco de 16 B, cada metade como senha."""
    C_SALT, C_CT = G.BLOBS["COSMIC"]
    raw = b"Salted__" + C_SALT + C_CT
    out = []
    for i in range(16, len(C_CT), 16):
        a, b = C_CT[:i], C_CT[i:]
        out.append(("X3/ct/%d/shaA" % i, G.shahex(a)))
        out.append(("X3/ct/%d/shaB" % i, G.shahex(b)))
        out.append(("X3/ct/%d/hexA" % i, a.hex()))
        out.append(("X3/ct/%d/hexB" % i, b.hex()))
        out.append(("X3/ct/%d/shashas" % i, G.shahex(G.shahex(a) + G.shahex(b))))
        out.append(("X3/ct/%d/xor" % i, bytes(x ^ y for x, y in zip(a, b)).hex()))
    for i in range(16, len(raw), 16):
        a, b = raw[:i], raw[i:]
        out.append(("X3/raw/%d/shaA" % i, G.shahex(a)))
        out.append(("X3/raw/%d/shaB" % i, G.shahex(b)))
    return out


def ext_triplas():
    """(ii) triplas ordenadas na gramatica do par (ele so rodou pares 51x50)."""
    import familia5_dualidade as F
    S_RAW, T_RAW = F.S_RAW, F.T_RAW
    S_CT, T_CT = F.S_CT, F.T_CT
    pool = {}
    byte_objs = {"S_h1": S_RAW[:48], "S_h2": S_RAW[48:], "T_h1": T_RAW[:48], "T_h2": T_RAW[48:],
                 "S_ct_h1": S_CT[:40], "S_ct_h2": S_CT[40:],
                 "T_ct_h1": T_CT[:40], "T_ct_h2": T_CT[40:],
                 "S_ct": S_CT, "T_ct": T_CT, "S_salt": F.S_SALT, "T_salt": F.T_SALT}
    for n, b in byte_objs.items():
        pool[n + ".hex"] = b.hex()
        pool[n + ".b64"] = base64.b64encode(b).decode()
        pool[n + ".sha"] = G.shahex(b)
    pool["url"] = "gsmg.io/theseedisplanted"
    pool["url_bitflip"] = "".join(chr(b ^ 1) for b in F.URL)
    pool["colorseq"] = G.COLOR_SEQ
    pool["colorseq_swap"] = G.COLOR_SEQ.translate(str.maketrans("BY", "YB"))
    pool["whitestar"] = "whitestar"
    pool["yellowstar"] = "yellowstar"
    pool["half"] = "half"
    pool["betterhalf"] = "betterhalf"
    pool["yinyang"] = "yinyang"
    pool["dbbi_h1"], pool["dbbi_h2"] = G.DBBI[:45], G.DBBI[45:]
    pool["faed_h1"], pool["faed_h2"] = G.FAED[:285], G.FAED[285:]
    pool["resid_h1"], pool["resid_h2"] = F.RESID84[:30], F.RESID84[30:]
    items = sorted(pool.items())
    out = []
    for (na, a), (nb, b), (nc, c) in itertools.permutations(items, 3):
        t = "X2/%s+%s+%s" % (na, nb, nc)
        out.append((t + "/cat", a + b + c))
        out.append((t + "/sha_cat", G.shahex(a + b + c)))
    return out


# ---------------------------------------------------------------- retro-varredura dos 246 dele
def retro(fh):
    n = 0
    hits = []
    maxpr = 0.0
    maxeb = 0.0
    for L in open(FAM5_LOG, encoding="utf-8"):
        r = json.loads(L)
        if r.get("tipo") not in ("padding", "HARD") or "hex" not in r:
            continue
        p = bytes.fromhex(r["hex"])
        n += 1
        o = oraculo_duro(p)
        maxpr = max(maxpr, o["printable"])
        maxeb = max(maxeb, o["ebcdic"])
        if eh_hit(o):
            hits.append({"tag": r.get("tag"), "blob": r.get("blob"), "kdf": r.get("kdf"), **o})
    res = {"tipo": "retro_familia5", "plaintexts_varridos": n, "hits": hits,
           "max_printable": maxpr, "max_ebcdic": maxeb}
    fh.write(json.dumps(res, ensure_ascii=False) + "\n")
    print(json.dumps({k: v for k, v in res.items() if k != "hits"}, ensure_ascii=False),
          "hits:", len(hits))
    return res


def privkeys_diretas(pws, fh):
    """Toda senha de 32 B, todo hex64 e o sha256 de toda senha, contra a pubkey do premio."""
    from coincurve import PublicKey
    vistos = set()
    hits = []
    for _, pw in pws:
        cands = []
        if isinstance(pw, bytes):
            if len(pw) == 32:
                cands.append(pw)
            cands.append(G.sha(pw))
        else:
            if len(pw) == 64 and all(c in "0123456789abcdefABCDEF" for c in pw):
                cands.append(bytes.fromhex(pw))
            cands.append(G.sha(pw))
        for c in cands:
            if c in vistos:
                continue
            vistos.add(c)
            try:
                if PublicKey.from_valid_secret(c).format(False) == TGT_PUB:
                    hits.append(c.hex())
            except Exception:
                pass
    res = {"tipo": "privkeys", "testadas": len(vistos), "hits": hits}
    fh.write(json.dumps(res, ensure_ascii=False) + "\n")
    print(json.dumps(res, ensure_ascii=False))
    return res


def main():
    t0 = time.time()
    ctrl = controle_positivo()
    print("controle positivo:", json.dumps(ctrl, ensure_ascii=False))
    assert ctrl["passou"], "CONTROLE POSITIVO FALHOU"
    import familia5_dualidade as F
    fams = {"A_blobs_duais": F.fam_A(), "B_matriz_complemento": F.fam_B(),
            "C_par_de_estrelas": F.fam_C(), "D_corte_ao_meio": F.fam_D(),
            "E_gramatica_do_par": F.fam_E()}
    ext = {"X1_cortes_todos": ext_cortes_todos(), "X3_cosmic_interno": ext_cosmic_interno(),
           "X2_triplas": ext_triplas()}
    with open(LOG, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"tipo": "hipotese", "texto": __doc__.strip()}, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"tipo": "controle_positivo", **ctrl}, ensure_ascii=False) + "\n")
        retro(fh)
        with mp.Pool(WORKERS) as pool:
            rep = [roda(pool, n, p, fh, com_nulo=True) for n, p in fams.items()]
            nov = [roda(pool, n, p, fh, com_nulo=(n != "X2_triplas")) for n, p in ext.items()]
        todas = [x for p in fams.values() for x in p] + [x for p in ext.values() for x in p]
        pk = privkeys_diretas(todas, fh)
        tot = {"tipo": "TOTAL",
               "reproducao_senhas_listadas": sum(r["senhas_listadas"] for r in rep),
               "reproducao_senhas_distintas": len({(x if isinstance(x, bytes) else x.encode())
                                                   for p in fams.values() for _, x in p}),
               "reproducao_decifracoes": sum(r["decifracoes"] for r in rep),
               "reproducao_padding": sum(r["padding_valido"] for r in rep),
               "novo_senhas_listadas": sum(r["senhas_listadas"] for r in nov),
               "novo_senhas_distintas": len({(x if isinstance(x, bytes) else x.encode())
                                             for p in ext.values() for _, x in p}),
               "novo_decifracoes": sum(r["decifracoes"] for r in nov),
               "novo_padding": sum(r["padding_valido"] for r in nov),
               "decifracoes_nulo": sum(r["nulo"]["decifracoes"] for r in rep + nov if "nulo" in r),
               "hits_duros": sum(r["hits_duros"] for r in rep + nov),
               "privkeys_testadas": pk["testadas"], "privkey_hits": len(pk["hits"]),
               "segundos": round(time.time() - t0, 1)}
        fh.write(json.dumps(tot, ensure_ascii=False) + "\n")
    print("TOTAL:", json.dumps(tot, ensure_ascii=False))
    print("log:", LOG)


if __name__ == "__main__":
    main()
