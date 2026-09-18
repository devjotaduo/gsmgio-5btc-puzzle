# -*- coding: utf-8 -*-
"""Frente de teste "lista_mais_fala" (hipótese I3 do Codex Astra), campanha enxame_2026-09-18.

Hipótese (finita, falsificável): `matrixsumlist → lastwordsbeforearchichoice` pede dois operandos
concatenados na ordem da página: b = uma das 270 listas numéricas isoladas de
reinsert_primes.generate_materials (primo p reinserido nos marcadores de DBBI, L83/L84) e
f = as 1–30 palavras imediatamente antes de uma das 5 ocorrências de "choice" na cena do Arquiteto
(parser cena_completa do critico_familia2 sobre MISC.txt), coladas sem espaço, caixa e apóstrofo
U+2019 preservados, mais a forma minúscula. Senha = sha256hex(UTF8(b+f)); 270 × 233 = 62.910.
Refutada se nenhuma senha abrir SMALL/COSMIC/TAIL32 (EVP SHA256 e MD5) com candidato nem
sha256(b+f) for a privkey de um dos dois alvos.

Extensões declaradas (fora do núcleo I3): forma raw; ordem inversa f+b; F com apóstrofo ASCII e
sem apóstrofo. Cada grupo só recebe as senhas que os grupos anteriores não testaram.

Uso: python lista_mais_fala.py   (2 processos; saída em _work/enxame_2026-09-18/lista_mais_fala/)
"""
import ast, base64, hashlib, json, os, re, subprocess, sys, tempfile, time

AQUI = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(AQUI, "..", "..", ".."))
PRINCIPAL = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(AQUI, ".."))
sys.path.insert(0, os.path.join(REPO, "solver", "multiagente_2026_09_18"))
import comum as C                      # noqa: E402
import reinsert_primes as R            # noqa: E402
import reinsert_architect as RA        # noqa: E402

G = C.G
WORKERS = 2
OUT = os.path.join(REPO, "_work", "enxame_2026-09-18", "lista_mais_fala")
MISC = os.path.join(PRINCIPAL, "ChatExport_2026-09-08", "files", "MISC.txt")
MISC_SHA = "223d7f7687bda05af22999dee19f7cb3affc14ac470c478ea9dd3f9762bc5ac7"
CRITICO = os.path.join(REPO, "solver", "operador_ensinado_2026_09_17", "critico_familia2.py")
SHA_NUCLEO = "ba03b9f52e8466c009a758fe19a953cd60ac662cc39bd0f7f5fd7ffe8af88b3d"
OPENSSL = r"C:\Program Files\Git\usr\bin\openssl.exe"
PARTES_FASE3 = ("causality", "Safenet", "Luna", "HSM", "11110",
                "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65"
                "636E61684320393030322F6E614A2F33302073656D695420656854",
                "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1")
SENHA_FASE3 = "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
PALAVRA = r"[A-Za-z][A-Za-z'\u2019]*"      # o mesmo reconhecimento de palavras do crítico


def sha_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def concatenar(*partes):
    """O concatenador da frente: partes coladas sem separador (gramática da fase 3)."""
    return "".join(partes)


def carregar(caminho, nomes, ns):
    """Executa só as definições de topo nomeadas de um script (sem os efeitos de módulo dele:
    o critico_familia2 trunca o próprio log ao ser importado)."""
    src = open(caminho, encoding="utf-8").read()
    alvo = [ast.get_source_segment(src, n) for n in ast.parse(src).body
            if (isinstance(n, ast.FunctionDef) and n.name in nomes)
            or (isinstance(n, ast.Assign) and any(getattr(t, "id", "") in nomes for t in n.targets))]
    exec("\n".join(alvo), ns)
    return ns


def cena():
    assert hashlib.sha256(open(MISC, "rb").read()).hexdigest() == MISC_SHA
    ns = carregar(CRITICO, {"FALA", "cena_completa"}, {"re": re, "MISC": MISC})
    return " ".join(t for _, t in ns["cena_completa"]())


def janelas(texto, limpa=lambda w: w):
    """1–30 palavras antes de cada "choice", coladas; forma original e minúscula, em ordem."""
    ws = re.findall(PALAVRA, texto)
    low = [w.lower().replace("\u2019", "'") for w in ws]
    occ = [k for k, w in enumerate(low) if w == "choice"]
    assert len(occ) == 5 and min(occ) >= 30, occ
    out = []
    for i in occ:
        for n in range(1, 31):
            s = "".join(limpa(w) for w in ws[i - n:i])
            out += [s, s.lower()]
    return list(dict.fromkeys(out)), len(out)


def bases():
    tok = {n: R.segment_dbbi(n) for n in (83, 84)}
    return sorted(RA.bases_for(tok))


def montar():
    """Grupos em ordem; senha -> proveniência; cada grupo só com senhas inéditas."""
    texto = cena()
    F_u, n_ocorr = janelas(texto)
    F_a, _ = janelas(texto.replace("\u2019", "'").replace("\u2013", "-"))
    F_s, _ = janelas(texto, lambda w: w.replace("\u2019", "").replace("'", ""))
    F_ext = [f for f in dict.fromkeys(F_a + F_s) if f not in set(F_u)]
    B = bases()
    grupos = [
        ("nucleo_sha256hex_b+f", [(b + f, "sha256hex", "b+f", "u2019") for b in B for f in F_u]),
        ("ext_raw_b+f", [(b + f, "raw", "b+f", "u2019") for b in B for f in F_u]),
        ("ext_inversa_f+b", [(f + b, fm, "f+b", "u2019") for b in B for f in F_u
                             for fm in ("sha256hex", "raw")]),
        ("ext_apostrofo", [(m, fm, o, "ascii/sem") for b in B for f in F_ext
                           for m, o in ((b + f, "b+f"), (f + b, "f+b")) for fm in ("sha256hex", "raw")]),
    ]
    visto, saida = {}, []
    for rot, itens in grupos:
        g = {}
        for mat, fm, ordem, var in itens:
            pw = (sha_hex(mat) if fm == "sha256hex" else mat).encode("utf-8")
            if pw not in visto:
                visto[pw] = g[pw] = {"grupo": rot, "material": mat, "forma": fm, "ordem": ordem,
                                     "variante": var}
        saida.append((rot, g, len(itens)))
    meta = {"F_nucleo": len(F_u), "F_ocorrencias_textuais": n_ocorr, "F_ext_novas": len(F_ext),
            "F_ascii": len(F_a), "F_sem_apostrofo": len(F_s), "bases": len(B),
            "F_nucleo_amostra": F_u[:4] + F_u[-2:]}
    return saida, meta, B, F_u


# ------------------------------------------------------------------ lacuna
def _strings(o, acc):
    if isinstance(o, dict):
        for v in o.values(): _strings(v, acc)
    elif isinstance(o, list):
        for v in o: _strings(v, acc)
    elif isinstance(o, str):
        acc.add(o.encode("utf-8", "surrogatepass"))
        if len(o) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", o):
            acc.add(bytes.fromhex(o))


def conjunto_critico():
    ns = carregar(CRITICO, {"FALA", "cena_completa", "materiais_completos", "formas", "operadores",
                            "COMPOS", "composicoes"}, {"re": re, "MISC": MISC, "G": G})
    pws = set()
    def add(pw):
        b = pw.encode("utf-8", "surrogateescape") if isinstance(pw, str) else pw
        if b: pws.add(b)
    for frase in ns["materiais_completos"]().values():
        for f in ns["formas"](frase):
            for _, pw in ns["operadores"](f): add(pw)
            for c in ns["composicoes"](f):
                add(c); add(G.shahex(c))
    return pws


def lacuna(senhas, materiais):
    """Interseção das senhas e materiais desta frente com os conjuntos anteriores adjacentes."""
    alvo = set(senhas) | {m.encode("utf-8") for m in materiais}
    nucleo = {p for p, v in senhas.items() if v["grupo"].startswith("nucleo")}
    res = {}
    crit = conjunto_critico()
    res["critico_familia2_regerado"] = {"senhas": len(crit), "esperado_log": 55576,
                                        "intersecao": len(crit & alvo), "intersecao_nucleo": len(crit & nucleo)}
    tok = {n: R.segment_dbbi(n) for n in (83, 84)}
    rp = {pw for m in R.generate_materials(tok) for _, pw in R.password_forms(m["material"])}
    rp |= {m["material"].encode() for m in R.generate_materials(tok)}
    res["reinsert_primes_todas_composicoes"] = {"valores": len(rp), "intersecao": len(rp & alvo)}
    ra = set(RA.passwords_for(set(bases()))[1])
    res["reinsert_architect_1080"] = {"senhas": len(ra), "intersecao": len(ra & alvo)}
    corp = json.load(open(os.path.join(REPO, "_work", "multiagente_2026-09-18",
                                       "reinsert_architect_evidence", "comparison.json"), encoding="utf-8"))
    acc = set()
    for c in corp["corpora"]:
        p = os.path.join(PRINCIPAL, c["source"])
        assert hashlib.sha256(open(p, "rb").read()).hexdigest() == c["sha256"], p
        if p.endswith(".jsonl"):
            for l in open(p, encoding="utf-8"):
                if l.strip(): _strings(json.loads(l), acc)
        else:
            _strings(json.load(open(p, encoding="utf-8")), acc)
    res["corpora_14_reinsert_architect_evidence"] = {"valores": len(acc), "intersecao": len(acc & alvo)}
    logs = set()
    for rel in ("critico_familia2", "familia2_lastwords"):
        for l in open(os.path.join(PRINCIPAL, "_work", "operador_ensinado_2026-09-17", rel, "run.jsonl"),
                      encoding="utf-8"):
            o = json.loads(l)
            if "pw" in o: logs.add(o["pw"].encode("latin-1", "replace"))
    res["logs_padding_familia2_pw"] = {"valores": len(logs), "intersecao": len(logs & alvo)}
    res["codigo"] = {
        "reinsert_primes.py compose_materials": "lista + rótulo literal lastwordsbeforearchichoice/thispassword",
        "reinsert_architect.py CLAUSES": "lista + 2 cláusulas fixas (reinserting..., sheisgoingtodie...)",
        "critico_familia2.py COMPOS/composicoes": "fala + rótulos fixos; nenhuma lista numérica",
        "familia2_lastwords.py:209 COMPOS": "idem",
    }
    return res


# ------------------------------------------------------------------ controles
def openssl_abre(blob_b64, senha, md):
    """openssl CLI; a senha vai por arquivo (bytes UTF-8 exatos, sem passar pelo argv do Windows)."""
    if not os.path.exists(OPENSSL):
        return None
    with tempfile.NamedTemporaryFile(delete=False) as t:
        t.write(senha.encode("utf-8") + b"\n")
    try:
        r = subprocess.run([OPENSSL, "enc", "-aes-256-cbc", "-d", "-a", "-A", "-md", md, "-pass",
                            "file:" + t.name], input="".join(blob_b64.split()).encode(),
                           capture_output=True, timeout=30)
    finally:
        os.unlink(t.name)
    return r.stdout if r.returncode == 0 else None


def controles(B, F_u, senhas):
    ctl = {}
    ctl["fase2_comum"] = bool(C.controle_positivo(workers=1)["candidatos"])
    # ponte: o concatenador reproduz a senha autêntica da fase 3 e ela abre (SHA256, não MD5)
    s3 = sha_hex(concatenar(*PARTES_FASE3))
    G.BLOBS["PHASE3"] = G._parse(G.PHASE3_B64)
    ab = {k.split(".")[-1]: G.printable(p) > 0.9 for k, p in G.aes_try(s3.encode(), "PHASE3", "both")}
    ctl["fase3_concatenador"] = {"senha_ok": s3 == SENHA_FASE3, "abre": ab}
    assert s3 == SENHA_FASE3 and ab == {"SHA256": True}, ctl
    o2 = openssl_abre(G.PHASE2_B64, sha_hex("causality"), "sha256")
    o3 = openssl_abre(G.PHASE3_B64, s3, "sha256")
    ctl["openssl_cli"] = {"fase2": bool(o2 and o2.startswith(b"The ironic")), "fase3": bool(o3)}
    # ponte: as 270 bases batem byte a byte com as salvas pela reinserção v2
    salvas = set()
    for l in open(os.path.join(REPO, "_work", "multiagente_2026-09-18", "reinsert_primes_v2",
                               "materials.jsonl"), encoding="utf-8"):
        o = json.loads(l)
        if o["run"] == "real" and o["meta"]["composition"] == "isolated": salvas.add(o["material"])
    ctl["bases_270_iguais_v2"] = set(B) == salvas and len(B) == 270
    # plantado: chave sintética num blob cifrado com uma senha do núcleo, pelo mesmo caminho (_um)
    from coincurve import PublicKey
    mat = B[137] + F_u[101]
    pw = sha_hex(mat).encode()
    assert senhas[pw]["grupo"].startswith("nucleo")
    k = hashlib.sha256(b"lista_mais_fala sintetico").digest()
    h = G._h160_hex(PublicKey.from_valid_secret(k).format(True))
    km = hashlib.sha256(mat.encode()).digest()
    hm = G._h160_hex(PublicKey.from_valid_secret(km).format(False))
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256, MD5
    G.TARGET_H160S = G.TARGET_H160S + (h, hm)
    try:
        ok = {}
        for nome, hmod in (("SHA256", SHA256), ("MD5", MD5)):
            salt = os.urandom(8)
            key, iv = G.evp(pw, salt, hmod)
            pt = b"xyz\x00" * 3 + k + b"fim"
            pt += bytes([16 - len(pt) % 16]) * (16 - len(pt) % 16)
            G.BLOBS["PLANT"] = (salt, AES.new(key, AES.MODE_CBC, iv).encrypt(pt))
            r = C._um((pw, ("PLANT",), "both"))
            ok[nome] = bool(r and any(c.get("privkey") and c["kdf"].endswith(nome) for c in r[1]))
        ok["privkey_material"] = varrer_privkeys([mat], {})["hits"] != []
        ok["alvo_sintetico_nao_vaza"] = varrer_privkeys([B[0] + F_u[0]], {})["hits"] == []
    finally:
        G.TARGET_H160S = tuple(x for x in G.TARGET_H160S if x not in (h, hm))
        G.BLOBS.pop("PLANT", None)
    assert len(G.TARGET_H160S) == 2 and G.TARGET_H160S == G.O.TARGET_H160S
    ctl["plantado"] = ok
    assert not os.path.exists(OPENSSL) or all(ctl["openssl_cli"].values()), ctl
    assert all(ok.values()) and all(v for kk, v in ctl.items() if isinstance(v, bool)), ctl
    return ctl


def varrer_privkeys(materiais, senhas):
    """sha256(material) e sha256(senha) como privkey dos dois alvos (comp e não comp)."""
    ds = {hashlib.sha256(m.encode("utf-8")).digest() for m in materiais}
    ds |= {hashlib.sha256(p).digest() for p in senhas}
    hits = [h for d in ds for h in G.fast_priv_scan(d, "sha256")]
    return {"privkeys": len(ds), "hits": hits}


def main():
    t0 = time.time()
    os.makedirs(OUT, exist_ok=True)
    grupos, meta, B, F_u = montar()
    senhas = {p: v for _, g, _ in grupos for p, v in g.items()}
    nucleo = sorted(p for p, v in senhas.items() if v["grupo"].startswith("nucleo"))
    meta["sha_nucleo"] = hashlib.sha256(b"".join(nucleo)).hexdigest()
    assert len(nucleo) == 62910 and meta["sha_nucleo"] == SHA_NUCLEO, meta
    print("[montagem]", json.dumps({k: v for k, v in meta.items() if k != "F_nucleo_amostra"}), flush=True)

    materiais = sorted({v["material"] for v in senhas.values()})
    lac = lacuna(senhas, materiais)
    print("[lacuna]", json.dumps(lac, ensure_ascii=False), flush=True)
    assert lac["critico_familia2_regerado"]["senhas"] == 55576
    lacuna_ok = all(v["intersecao"] == 0 for v in lac.values() if isinstance(v, dict) and "intersecao" in v)
    ctl = controles(B, F_u, senhas)
    json.dump({"controles": ctl, "lacuna": lac}, open(os.path.join(OUT, "controls.json"), "w",
              encoding="utf-8"), indent=2, ensure_ascii=False)
    print("[controles]", json.dumps(ctl), flush=True)
    if not lacuna_ok:
        print("lacuna NÃO reproduzida: campanha não executada", flush=True)
        return

    resultados, cands = [], []
    with open(os.path.join(OUT, "paddings.jsonl"), "w", encoding="utf-8") as fp:
        for rot, g, n_itens in grupos:
            r = C.testar(list(g), formas=("raw",), workers=WORKERS, rotulo=rot)
            por = {}
            for rec in r["registros_padding"]:
                pw = rec["senha"].encode("latin-1")
                prov = g[pw]
                out = {**prov, "senha": pw.decode("utf-8"), **{k: rec[k] for k in rec
                       if k not in ("senha", "base", "forma", "head")}}
                fp.write(json.dumps(out, ensure_ascii=False) + "\n")
                chave = rec["blob"] + "/" + rec["kdf"].split(".")[-1]
                por[chave] = por.get(chave, 0) + 1
            for c in r["candidatos"]:
                cands.append({**g[c["senha"].encode("latin-1")], **{k: c[k] for k in c if k != "base"}})
            resultados.append({k: r[k] for k in ("rotulo", "senhas", "aes", "paddings",
                                                  "paddings_esperados", "z_padding")}
                              | {"itens_gerados": n_itens, "candidatos": len(r["candidatos"]),
                                 "paddings_por_blob_kdf": por})
            print("[grupo]", json.dumps(resultados[-1]), "t=%.0fs" % (time.time() - t0), flush=True)

    pk = varrer_privkeys(materiais, senhas)
    print("[privkeys]", pk["privkeys"], "hits", len(pk["hits"]), flush=True)
    for c in cands:  # reprodução pelo openssl CLI (não é certificado)
        blob = G.BLOBS[c["blob"]]
        b64 = base64.b64encode(b"Salted__" + blob[0] + blob[1]).decode()
        o = openssl_abre(b64, c["senha"].encode("latin-1").decode("utf-8"), "sha256" if c["kdf"].endswith("SHA256") else "md5")
        c["openssl_cli_igual"] = o is not None and o.hex() == c["hex"]
    if cands:
        with open(os.path.join(OUT, "candidatos.jsonl"), "w", encoding="utf-8") as fc:
            for c in cands: fc.write(json.dumps(c, ensure_ascii=False) + "\n")

    tot = {k: sum(x[k] for x in resultados) for k in ("senhas", "aes", "paddings", "paddings_esperados")}
    esp = tot["aes"] * C.TAXA_PADDING
    tot["z_padding"] = round((tot["paddings"] - esp) / (esp * (1 - C.TAXA_PADDING)) ** 0.5, 2)
    arq = os.path.join(OUT, "paddings.jsonl")
    resumo = {"frente": "lista_mais_fala", "montagem": meta, "grupos": resultados, "total": tot,
              "privkeys": {"testadas": pk["privkeys"], "hits": pk["hits"]},
              "candidatos": len(cands), "materiais_distintos": len(materiais),
              "senhas_distintas": len(senhas), "kit": C.commit_do_kit(),
              "hashes": {"script": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
                         "comum": hashlib.sha256(open(C.__file__, "rb").read()).hexdigest(),
                         "reinsert_primes": hashlib.sha256(open(R.__file__, "rb").read()).hexdigest(),
                         "critico_familia2": hashlib.sha256(open(CRITICO, "rb").read()).hexdigest(),
                         "misc_txt": MISC_SHA,
                         "paddings_jsonl": hashlib.sha256(open(arq, "rb").read()).hexdigest()},
              "segundos": round(time.time() - t0, 1)}
    json.dump(resumo, open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)
    print("[total]", json.dumps(tot), "candidatos", len(cands), flush=True)


if __name__ == "__main__":
    main()
