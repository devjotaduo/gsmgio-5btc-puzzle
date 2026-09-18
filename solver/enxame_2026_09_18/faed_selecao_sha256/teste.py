# -*- coding: utf-8 -*-
"""Frente faed_selecao_sha256 (campanha enxame_2026-09-18, hipótese I2 do Codex Astra).

HIPÓTESE (finita, falsificável): os argumentos de 32 B que select_bits.materialize(do_bits=True,
do_pw=False) e select_bits.multibit mandam a pcheck, nos 23 seletores de
select_bits.selections(FAED, 'faed') sem prefixo mod/mult, na subsequência e na reversa (conjunto U,
47.862 valores distintos), são material intermediário de senha: sha256(u).hexdigest() (também u cru,
SHA256HEX e, como extensão declarada, u.hex()) abre SMALL, COSMIC ou TAIL32 (EVP SHA256 e MD5), ou
u / sha256(u) é a privkey de 1GSMG… ou 17ucy…. Falsifica-se por zero candidatos no oráculo duro.

LACUNA: pcheck (select_bits.py) só compara a pubkey não comprimida de 1GSMG e não encaminha o
argumento ao AES; multibit só chama pcheck; o ramo reverso usa do_pw=False. Este script reproduz o
fluxo histórico real (main e main2 com os oráculos trocados por gravadores) antes de testar.

Rodar: python teste.py   (2 processos; saídas em _work/enxame_2026-09-18/faed_selecao_sha256/)
"""
import sys, os, json, time, hashlib, inspect, random, subprocess, contextlib, io, math
from multiprocessing import Pool

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, ".."))
import comum as C                    # carrega o kit da worktree primeiro
G = C.G
import select_bits as S              # resolve para o select_bits da worktree; S.G é o mesmo kit
from coincurve import PublicKey

SAIDA = os.path.abspath(os.path.join(AQUI, "..", "..", "..", "_work", "enxame_2026-09-18",
                                     "faed_selecao_sha256"))
OPENSSL = r"C:\Program Files\Git\usr\bin\openssl.exe"
SHA_SELECT_BITS = "2178925efb0841cf33aaf55d235cc31b094d4ec2c24927170437a857585e14a1"
SHA_SENHAS_CODEX = "85eec0d5b7d522f57e3df6787245ea5c52268cf953062902a2aa0b7897afa209"
WORKERS = 2
N_NULO = 100
NT_LOG_HISTORICO = (512996, 652435)
# ponytail: forma extra registrada só neste processo (senhas_de roda no pai); comum.py fica intacto.
C.FORMAS.setdefault("hex", lambda b: b.hex().encode())
FORMAS = ("raw", "sha256hex", "sha256HEX", "hex")
BLOBS_NULO = ("SMALL", "TAIL32")


def sha_arq(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


@contextlib.contextmanager
def trocar(obj, **novos):
    """Troca atributos temporariamente e sempre restaura."""
    velhos = {k: getattr(obj, k) for k in novos}
    for k, v in novos.items():
        setattr(obj, k, v)
    try:
        yield
    finally:
        for k, v in velhos.items():
            setattr(obj, k, v)


# ------------------------------------------------------------------ U (exatamente como na I2)
def gerar_ocorrencias(faed):
    """(u, onde) de cada argumento que materialize(do_bits=True, do_pw=False) e multibit mandam a
    pcheck, nos 23 seletores sem mod/mult, subsequência e reversa."""
    oc = []
    with trocar(S, pcheck=lambda sec, where="": oc.append((sec, where))):
        for lbl, idx in S.selections(faed, "faed").items():
            if lbl.startswith(("mod", "mult")):
                continue
            sub = "".join(faed[i] for i in idx)
            for s, tag in ((sub, lbl), (sub[::-1], lbl + "/rev")):
                S.materialize(s, f"faed/{tag}", do_bits=True, do_pw=False)
                S.multibit(s, f"faed/{tag}")
    return oc


def distintos(oc):
    U = {}
    for u, onde in oc:
        U.setdefault(u, onde)
    return U


def origem_por_forma(us):
    """senha -> (u, forma), com a ordem de FORMAS como prioridade: a forma pedida vence a extensão
    'hex' quando sha256(u1) == u2 (os dois em U). Mesmo conjunto de senhas que C.senhas_de."""
    origem = {}
    for f in FORMAS:
        for u in us:
            origem.setdefault(C.FORMAS[f](u), (u, f))
    return origem


def hash_senhas_codex(U):
    return hashlib.sha256(b"".join(sorted(hashlib.sha256(u).hexdigest().encode() for u in U))).hexdigest()


# ------------------------------------------------------------------ fluxo histórico real
def ramo_antigo(faed):
    """Roda os main() e main2() reais de select_bits com G.FAED = faed, pcheck/try_pw trocados por
    gravadores e G.jsonl mudo (nada é escrito no log histórico). Devolve as senhas que o ramo AES
    tentaria, os NT de cada fase e os argumentos de pcheck em forma de contagem."""
    senhas, args = [], {"main": 0, "main2": 0}
    fase = ["main"]

    def pc(sec, where=""):
        S.NT += 1
        args[fase[0]] += 1
        return False

    def tp(pw, where):
        S.NT += 3
        senhas.append((pw, where, fase[0]))

    nt = {}
    with trocar(G, FAED=faed, jsonl=lambda *a, **k: None), trocar(S, pcheck=pc, try_pw=tp, NT=0):
        with contextlib.redirect_stdout(io.StringIO()):
            S.main()
            nt["main"] = S.NT
            S.NT = 0
            fase[0] = "main2"
            S.main2()
            nt["main2"] = S.NT
    return senhas, nt, args


def evidencia_estatica():
    """Linhas do select_bits.py que definem a lacuna, conferidas por asserts sobre o fonte."""
    def linhas(fn):
        src, ini = inspect.getsourcelines(fn)
        return ini, "".join(src)
    ev = {}
    i, s = linhas(S.pcheck)
    assert "format(False) == TGT" in s and "aes" not in s.lower() and "try_pw" not in s
    ev["pcheck"] = f"linhas {i}-{i + s.count(chr(10)) - 1}: compara só PublicKey.format(False) == TGT; nenhum AES"
    assert S.TGT == bytes.fromhex(G.TARGET_PUBKEY_HEX)
    ev["TGT"] = "TGT = pubkey não comprimida de 1GSMG (G.TARGET_PUBKEY_HEX); 17ucy ausente"
    i, s = linhas(S.multibit)
    assert "pcheck(" in s and "try_pw" not in s
    ev["multibit"] = f"linhas {i}-{i + s.count(chr(10)) - 1}: só pcheck, nenhuma senha"
    i, s = linhas(S.main2)
    assert "materialize(sub[::-1]" in s and "do_pw=False" in s
    n = i + [k for k, l in enumerate(s.splitlines()) if "materialize(sub[::-1]" in l][0]
    ev["main2_reverso"] = f"linha {n}: materialize(sub[::-1], ..., do_pw=False)"
    i, s = linhas(S.materialize)
    ev["materialize_senhas"] = (f"linhas {i}-{i + s.count(chr(10)) - 1}: com do_pw só tenta shahex(texto), "
                                "texto cru e hex dos bits no offset 0; os 32 B de pcheck nunca viram "
                                "pré-imagem de senha")
    return ev


# ------------------------------------------------------------------ oráculos da frente
def varrer_privkeys(us):
    """u e sha256(u) como privkey contra os dois alvos (h160 comp/uncomp, G.fast_priv_scan)."""
    hits, invalidos = [], {"u": 0, "sha256(u)": 0}
    for u in us:
        for tag, k in (("u", u), ("sha256(u)", G.sha(u))):
            try:
                PublicKey.from_valid_secret(k)
            except Exception:
                invalidos[tag] += 1
                continue
            for h in G.fast_priv_scan(k, tag):
                hits.append({"u": u.hex(), "forma": tag, "priv": h[2]})
    return hits, invalidos


def h160s_de(k):
    pk = PublicKey.from_valid_secret(k)
    return tuple(G._h160_hex(pk.format(c)) for c in (False, True))


def plantar(h):
    G.TARGET_H160S = G.TARGET_H160S + h
    G.O.TARGET_H160S = G.O.TARGET_H160S + h


def desplantar(h):
    G.TARGET_H160S = tuple(x for x in G.TARGET_H160S if x not in h)
    G.O.TARGET_H160S = tuple(x for x in G.O.TARGET_H160S if x not in h)


def openssl(args, entrada):
    r = subprocess.run([OPENSSL] + args, input=entrada, capture_output=True, timeout=60)
    return r.returncode, r.stdout, r.stderr.decode("latin-1", "replace")


# ------------------------------------------------------------------ controles
def faed_sintetico(K, semente=7):
    """K em base 9 nas 104 posições primas de um faed aleatório (mesma construção de
    select_bits.control); o seletor primes_b0 materializa K em 'b9/rpad'."""
    rnd = random.Random(semente)
    P = S.primes_below(570)
    v, digs = int.from_bytes(K, "big"), []
    for _ in P:
        digs.append(v % 9)
        v //= 9
    assert v == 0
    s = [rnd.choice("abcdefghi") for _ in range(570)]
    for p, d in zip(P, digs[::-1]):
        s[p] = chr(97 + d)
    return "".join(s)


def ponte():
    """Chave sintética selecionada -> sha256hex -> abre envelope plantado (openssl CLI).
    O ramo antigo, no mesmo faed sintético, não abre: nenhuma senha dele é a certa."""
    K = hashlib.sha256(b"enxame 2026-09-18 faed_selecao_sha256: chave sintetica da ponte").digest()
    syn = faed_sintetico(K)
    Us = distintos(gerar_ocorrencias(syn))
    assert K in Us, "gerador não recuperou a chave plantada"
    senha = hashlib.sha256(K).hexdigest()
    pt = b"enxame 2026-09-18 ponte faed_selecao_sha256: envelope plantado; sha256(u) como senha abre."
    rc, env, err = openssl(["enc", "-aes-256-cbc", "-md", "sha256", "-salt",
                            "-pass", "pass:" + senha], pt)
    assert rc == 0 and env[:8] == b"Salted__", err
    rc2, dec, _ = openssl(["enc", "-d", "-aes-256-cbc", "-md", "sha256", "-pass", "pass:" + senha], env)
    assert rc2 == 0 and dec == pt
    G.BLOBS["PONTE"] = (env[8:16], env[16:])
    try:
        # ramo novo: o mesmo caminho de código das frentes (C._um = G.try_password_all), em processo
        # porque o blob plantado só existe aqui
        origem = origem_por_forma(list(Us))
        aberturas, paddings = [], 0
        for s in origem:
            r = C._um((s, ("PONTE",), "both"))
            if not r:
                continue
            for rec in r[1] + r[2]:
                paddings += 1
                if bytes.fromhex(rec["hex"]) == pt:
                    aberturas.append({"forma": origem[s][1], "u": origem[s][0].hex(), "kdf": rec["kdf"],
                                      "candidato": rec in r[1]})
        # ramo antigo: senhas reais de main()/main2() no mesmo faed sintético
        velhas, nt, args = ramo_antigo(syn)
        abre_antigo = sum(1 for pw, _, _ in velhas for _k, p in G.aes_try(pw, "PONTE", "both") if p == pt)
        # o ramo antigo de privkey recebe K, mas só compara com a pubkey de 1GSMG
        with trocar(G, jsonl=lambda *a, **k: None):
            pcheck_antigo = S.pcheck(K, "ponte")
    finally:
        del G.BLOBS["PONTE"]
    assert len(aberturas) == 1 and aberturas[0]["forma"] == "sha256hex" and aberturas[0]["candidato"]
    assert abre_antigo == 0 and pcheck_antigo is False
    return {"K": K.hex(), "onde_K": Us[K], "U_sintetico": len(Us), "senha": senha,
            "envelope_b64": __import__("base64").b64encode(env).decode(), "senhas_novas": len(origem),
            "aberturas_ramo_novo": aberturas, "paddings_ramo_novo": paddings,
            "senhas_ramo_antigo": len(velhas), "senhas_ramo_antigo_distintas": len({p for p, _, _ in velhas}),
            "aberturas_ramo_antigo": abre_antigo, "pcheck_antigo_em_K": pcheck_antigo,
            "openssl_cli_decifra_igual": True, "nt_ramo_antigo": nt}


def controle_privkey(U):
    """Alvos sintéticos: K1 como u direto e sha256(K2) como privkey; varrer_privkeys acha os dois.
    O pcheck antigo não acha K1 (falso negativo do segundo alvo)."""
    K1 = hashlib.sha256(b"enxame faed_selecao_sha256: alvo sintetico u").digest()
    K2 = hashlib.sha256(b"enxame faed_selecao_sha256: alvo sintetico sha256(u)").digest()
    h = h160s_de(K1) + h160s_de(G.sha(K2))
    amostra = list(U)[:500] + [K1, K2]
    plantar(h)
    try:
        hits, _ = varrer_privkeys(amostra)
        kit_o = G.O.check_privkey(K1) is not None
        with trocar(G, jsonl=lambda *a, **k: None):
            antigo = S.pcheck(K1, "controle")
    finally:
        desplantar(h)
    limpo, _ = varrer_privkeys(amostra)
    ok = ({(x["u"], x["forma"]) for x in hits} == {(K1.hex(), "u"), (K2.hex(), "sha256(u)")}
          and not limpo and kit_o and antigo is False)
    assert ok, (hits, limpo, kit_o, antigo)
    return {"hits_plantados": hits, "sem_plantio": len(limpo), "oracles_check_privkey_acha": kit_o,
            "pcheck_antigo_acha_segundo_alvo": antigo}


# ------------------------------------------------------------------ nulo casado
def _nulo_um(semente):
    """faed embaralhado (contagens preservadas) -> U -> sha256hex em SMALL/TAIL32 x 2 KDF."""
    f = list(G.FAED)
    random.Random(semente).shuffle(f)
    U = distintos(gerar_ocorrencias("".join(f)))
    n = sum(len(G.aes_try(hashlib.sha256(u).hexdigest(), b, "both")) for u in U for b in BLOBS_NULO)
    return semente, len(U), n


def celula(registros, blobs, forma):
    return sum(1 for r in registros if r["blob"] in blobs and r["forma"] == forma)


# ------------------------------------------------------------------ principal
def main():
    t0 = time.time()
    os.makedirs(SAIDA, exist_ok=True)
    assert S.G is G, "select_bits carregou outro kit"
    assert sha_arq(S.__file__) == SHA_SELECT_BITS, "select_bits.py mudou"

    # 1) lacuna: fonte + fluxo histórico real
    estatica = evidencia_estatica()
    oc = gerar_ocorrencias(G.FAED)
    U = distintos(oc)
    h_codex = hash_senhas_codex(U)
    assert (len(oc), len(U), h_codex) == (50988, 47862, SHA_SENHAS_CODEX), (len(oc), len(U), h_codex)
    velhas, nt_hist, args_hist = ramo_antigo(G.FAED)
    senhas_velhas = {p.encode() if isinstance(p, str) else p for p, _, _ in velhas}
    assert not [1 for _, _, f in velhas if f == "main2"], "main2 tentou senha"
    # o log histórico (checkout principal, select_bits.jsonl) tem SUMMARY 512.996 e SUMMARY2 652.435
    assert (nt_hist["main"], nt_hist["main2"]) == NT_LOG_HISTORICO, nt_hist
    origem = origem_por_forma(list(U))
    assert set(origem) == set(C.senhas_de(list(U), FORMAS))
    sobreposicao = {f: sum(1 for s, (_, ff) in origem.items() if ff == f and s in senhas_velhas) for f in FORMAS}
    por_forma = {f: sum(1 for _, ff in origem.values() if ff == f) for f in FORMAS}
    lacuna = {"estatica": estatica, "ocorrencias": len(oc), "U": len(U), "sha256_senhas_ordenadas": h_codex,
              "nt_historico_main": nt_hist["main"], "nt_historico_main2": nt_hist["main2"],
              "reconcilia_log_historico": True,
              "pcheck_calls_main": args_hist["main"], "pcheck_calls_main2": args_hist["main2"],
              "senhas_ramo_antigo_total": len(velhas), "senhas_ramo_antigo_distintas": len(senhas_velhas),
              "senhas_ramo_antigo_main2": 0,
              "senhas_novas_por_forma": por_forma, "sobreposicao_com_ramo_antigo_por_forma": sobreposicao}
    assert sobreposicao["sha256hex"] == 0 and sobreposicao["sha256HEX"] == 0 and sobreposicao["raw"] == 0
    print("lacuna:", json.dumps({k: v for k, v in lacuna.items() if k != "estatica"}), flush=True)

    # 2) controles
    cp = C.controle_positivo(workers=WORKERS)
    ctl = {"fase2": {"senhas": cp["senhas"], "candidatos": len(cp["candidatos"]),
                     "head": cp["candidatos"][0]["head"][:40]},
           "privkey_plantada": controle_privkey(U), "ponte": ponte()}
    print("controles OK", round(time.time() - t0, 1), "s", flush=True)

    # 3) teste: senhas nos 3 blobs x 2 KDF; u e sha256(u) como privkey
    r = C.testar(list(U), formas=FORMAS, workers=WORKERS, rotulo="faed_selecao_sha256")
    assert r["senhas"] == len(origem)
    priv_hits, invalidos = varrer_privkeys(U)
    regs = []
    for rec in r["registros_padding"]:
        s = rec["senha"].encode("latin-1")
        u, forma = origem[s]
        regs.append({"u": u.hex(), "forma": forma, "senha_hex": s.hex(), "blob": rec["blob"],
                     "kdf": rec["kdf"].rsplit(".", 1)[-1], "len": rec["len"], "printable": rec["printable"],
                     "ebcdic_sig": round(G.ebcdic_sig(bytes.fromhex(rec["hex"])), 3),
                     "privkey": rec.get("privkey", []), "nested": rec.get("nested", False),
                     "candidato": rec in r["candidatos"], "hex": rec["hex"]})
    with open(os.path.join(SAIDA, "paddings.jsonl"), "w", encoding="utf-8") as f:
        for x in regs:
            f.write(json.dumps(x) + "\n")
    celulas = {}
    for b in C.BLOBS_PREMIO:
        for k in ("SHA256", "MD5"):
            for fo in FORMAS:
                n = sum(1 for x in regs if x["blob"] == b and x["kdf"] == k and x["forma"] == fo)
                celulas[f"{b}/{k}/{fo}"] = {"paddings": n, "esperado": round(por_forma[fo] * C.TAXA_PADDING, 2)}
    candidatos = []
    for c in r["candidatos"]:
        s = c["senha"].encode("latin-1")
        u, forma = origem[s]
        rep = None
        if forma != "raw":
            md = "sha256" if c["kdf"].endswith("SHA256") else "md5"
            salt, ct = G.BLOBS[c["blob"]]
            rc, dec, _ = openssl(["enc", "-d", "-aes-256-cbc", "-md", md, "-pass", "pass:" + s.decode()],
                                 b"Salted__" + salt + ct)
            rep = (rc == 0 and dec.hex() == c["hex"])
        candidatos.append({"u": u.hex(), "forma": forma, "blob": c["blob"], "kdf": c["kdf"], "head": c["head"],
                           "printable": c["printable"], "privkey": c.get("privkey"), "nested": c.get("nested"),
                           "openssl_cli_reproduz": rep})
    print("teste:", {k: r[k] for k in ("senhas", "aes", "paddings", "paddings_esperados", "z_padding")},
          "candidatos", len(candidatos), "priv", len(priv_hits), round(time.time() - t0, 1), "s", flush=True)

    # 4) nulo casado: 100 embaralhamentos de faed (contagens preservadas), célula sha256hex x SMALL/TAIL32 x 2 KDF
    with Pool(WORKERS) as pool:
        nulo = sorted(pool.map(_nulo_um, range(1, N_NULO + 1)))
    obs = celula(regs, BLOBS_NULO, "sha256hex")
    ns = [n for _, _, n in nulo]
    media = sum(ns) / len(ns)
    dp = math.sqrt(sum((x - media) ** 2 for x in ns) / (len(ns) - 1))
    nulo_res = {"embaralhamentos": N_NULO, "celula": "sha256hex x SMALL,TAIL32 x SHA256,MD5",
                "observado": obs, "esperado_analitico": round(len(U) * 4 * C.TAXA_PADDING, 2),
                "nulo_media": round(media, 2), "nulo_dp": round(dp, 2), "nulo_min": min(ns), "nulo_max": max(ns),
                "p_emp_ge": round((1 + sum(x >= obs for x in ns)) / (N_NULO + 1), 3),
                "U_por_embaralhamento_min_max": [min(u for _, u, _ in nulo), max(u for _, u, _ in nulo)]}
    print("nulo:", nulo_res, flush=True)

    sha_saida = sha_arq(os.path.join(SAIDA, "paddings.jsonl"))
    summary = {"frente": "faed_selecao_sha256", "hipotese": "I2 (Codex Astra)", "commit_kit": C.commit_do_kit(),
               "sha256_script": sha_arq(__file__), "sha256_comum": sha_arq(C.__file__),
               "sha256_select_bits": SHA_SELECT_BITS, "sha256_paddings_jsonl": sha_saida,
               "U": len(U), "ocorrencias": len(oc), "sha256_senhas_codex": h_codex,
               "sha256_U_ordenado": hashlib.sha256(b"".join(sorted(U))).hexdigest(),
               "formas": list(FORMAS), "senhas_por_forma": por_forma, "senhas": r["senhas"],
               "aes": r["aes"], "paddings": r["paddings"], "paddings_esperados": r["paddings_esperados"],
               "z_padding": r["z_padding"], "celulas": celulas, "candidatos": candidatos,
               "privkeys_testadas": 2 * len(U), "privkeys_invalidas": invalidos, "priv_hits": priv_hits,
               "nulo": nulo_res, "segundos": round(time.time() - t0, 1)}
    json.dump(summary, open(os.path.join(SAIDA, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"lacuna": lacuna, **ctl}, open(os.path.join(SAIDA, "controls.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("FIM", json.dumps({k: summary[k] for k in ("senhas", "aes", "paddings", "paddings_esperados",
                                                       "z_padding", "privkeys_testadas", "segundos")}))


if __name__ == "__main__":
    main()
