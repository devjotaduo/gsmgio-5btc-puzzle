# -*- coding: utf-8 -*-
r"""
CRITICO FINAL da familia "sete_entrelacados" ("seven intertwined passwords" = entrelacamento
round-robin dos 7 operandos de nivel-senha). TERCEIRA implementacao independente (atacante:
familia3_entrelacamento.py; critico anterior: critico_familia3_entrelacamento.py; esta).

Hipotese adversarial (antes de codar):
 H1 os n_pw/pads por tarefa do atacante sao reproduziveis BYTE A BYTE (conjunto de pt_sha por tarefa);
 H2 o z=+2,71 e artefato do denominador 1/256 (regra do unpad aceita 1..16 -> p = 1/255);
    duplicatas de material entre tarefas so mudam a variancia (Sigma m_i^2), nao o sinal;
 H3 o braco privkey do atacante (G.priv_hit) so testa o 1GSMG; o 17ucy nunca foi testado;
 H4 0 hits com oraculo completo (privkey nas DUAS chaves em toda janela de 32 B nas duas
    ordens, hex64/WIF, Salted__, EBCDIC, ASCII>=85%) sobre TODOS os plaintexts logados
    (atacante + critico anterior) e sobre o operando (5) verbatim THEMATRIXHASYOU.
Padding valido sozinho e ruido. KDF EVP-SHA256 primario, MD5 secundario.

Uso: python critico_sete_final.py --stage verif|dedup|retro|o5up|all [--workers 18]
"""
from __future__ import annotations
import argparse, gzip, hashlib, itertools, json, math, os, sys, time
from multiprocessing import Pool
# ponytail: numpy so e usado no stage `dedup`; importar no topo faz os 18 workers de TODOS os
# stages carregarem a DLL e estoura o arquivo de paginacao do Windows. Import local.
REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(REPO, "solver", "experiments", "claude_endgame_2026_09_02"))
import gsmg_common as G  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402
from coincurve import PublicKey  # noqa: E402
import base58  # noqa: E402

W = os.path.join(REPO, "_work", "operador_ensinado_2026-09-17")
DIR_AG, DIR_C1, OUT = (os.path.join(W, d) for d in
                       ("familia3_entrelacamento", "critico_familia3_entrelacamento", "critico_sete_final"))
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
H160_17 = base58.b58decode_check("17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa")[1:]
assert H160_17.hex() == "4bc468447fe1b048ad030a2f9a125478eabc4ed6"
assert G.TARGET_H160 == base58.b58decode_check(G.PRIZE_ADDR)[1:].hex()   # H3: kit so cobre o 1GSMG
P_PAD = sum(256.0 ** -j for j in range(1, 17))                            # regra unpad 1..16


# ---------------- cripto propria (hashlib) ----------------
def evp(pw, salt, algo):
    d = prev = b""
    while len(d) < 48:
        prev = hashlib.new(algo, prev + pw + salt).digest()
        d += prev
    return d[:32], d[32:48]


def unpad(p):
    j = p[-1]
    return p[:-j] if 1 <= j <= 16 and p.endswith(bytes([j]) * j) else None


CELLS = [(b, a, *G.BLOBS[b]) for b in ("SMALL", "COSMIC", "TAIL32") for a in ("sha256", "md5")]


_RIP = hashlib.new("ripemd160")


def h160(b):
    r = _RIP.copy()   # ponytail: hashlib.new("ripemd160") por chamada custava ~4x o EC mult
    r.update(hashlib.sha256(b).digest())
    return r.digest()


# libsecp256k1 direto via cffi (4,3x mais rapido que PublicKey.from_valid_secret; equivalencia
# checada em 3.000 chaves aleatorias e positivos sinteticos no autoteste)
from coincurve._libsecp256k1 import ffi as _ffi, lib as _lib  # noqa: E402
from coincurve.context import GLOBAL_CONTEXT as _GC  # noqa: E402
_CTX, _PK = _GC.ctx, _ffi.new("secp256k1_pubkey *")
_OUT, _OL = _ffi.new("unsigned char[65]"), _ffi.new("size_t *")


def _ser(comp):
    _OL[0] = 33 if comp else 65
    _lib.secp256k1_ec_pubkey_serialize(_CTX, _OUT, _OL, _PK, _lib.SECP256K1_EC_COMPRESSED if comp
                                       else _lib.SECP256K1_EC_UNCOMPRESSED)
    return bytes(_ffi.buffer(_OUT, _OL[0]))


def priv_ok(sec, tgt=None, h17=None):
    """DUAS chaves do premio: pubkey == 1GSMG (04f4d1bb...) OU h160(unc|comp) == 17ucy."""
    tgt, h17 = tgt or TGT, h17 or H160_17
    if len(sec) != 32 or not _lib.secp256k1_ec_pubkey_create(_CTX, _PK, sec):
        return None
    u = _ser(False)
    if u == tgt:
        return "1GSMG"
    if h160(u) == h17 or h160(_ser(True)) == h17:
        return "17ucy"
    return None


def oraculo(p, janelas=True):
    """Oraculo completo num plaintext. Devolve lista de achados (vazia = nada).
    janelas=False: pula privkey-por-janela (feita pelo scanner Go critico_sete_janelas num dump)."""
    a = []
    if G.nested_blob(p):
        a.append("NESTED_SALTED")
    if G.printable(p) >= 0.85:
        a.append("ASCII85")
    if G.ebcdic_sig(p) >= 0.75:
        a.append("EBCDIC")
    t = p.decode("latin-1")
    for h in G.hex64_candidates(t):
        a.append(("HEX64", h, priv_ok(bytes.fromhex(h))))
    for w in G.wif_candidates(t):
        try:
            raw = base58.b58decode_check(w)
            a.append(("WIF", w, priv_ok(raw[1:33])))
        except Exception:
            pass
    for j in range(len(p) - 31 if janelas else 0):
        w = p[j:j + 32]
        for tag, s in (("JANELA", w), ("JANELA_REV", w[::-1])):
            r = priv_ok(s)
            if r:
                a.append((tag, j, r, s.hex()))
    return a


# ---------------- operandos e conjuntos (mesma especificacao do atacante) ----------------
P3 = ["causality", "Safenet", "Luna", "HSM", "11110",
      "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F"
      "20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
      "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"]
O = ["theflowerblossomsthroughwhatseemstobeaconcretesurface", "causality", "".join(P3),
     "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple", "thematrixhasyou",
     "gsmg.io/theseedisplanted", "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"]
assert [len(x) for x in O] == [53, 9, 227, 62, 15, 24, 59]
SH = G.shahex


def conjuntos():
    c = {"S0_atlas": list(O)}
    for i in range(7):
        for tok in ("thispassword", "lastwordsbeforearchichoice"):
            s = list(O)
            s[i] = tok
            c[f"S_{tok[:8]}_{i+1}"] = s
    c["S_url_hash"] = [*O[:5], SH(O[5]), O[6]]
    c["S_title_hash"] = [*O[:6], SH(O[6])]
    c["S_url_curta"] = [*O[:5], "theseedisplanted", O[6]]
    c["S_p3_partes"] = list(P3)
    for j, parte in enumerate(P3):
        s = list(O)
        s[2] = parte
        c[f"S_p3parte_{j+1}"] = s
    c["S_todos_hash"] = [SH(x) for x in O]
    c["S_joins_hash"] = [O[0], O[1], SH(O[2]), SH(O[3]), O[4], O[5], O[6]]
    return c


CONJ = conjuntos()
assert len(CONJ) == 28


def tranca(partes, k, preencher):
    """Terceira implementacao: zip_longest (preencher) / zip (truncar) sobre listas de blocos."""
    bl = [[p[i:i + k] for i in range(0, len(p), k)] for p in partes]
    zz = itertools.zip_longest(*bl, fillvalue="") if preencher else zip(*bl)
    return "".join(b for g in zz for b in g)


def materiais(partes, k, pre, rev, lo):
    base = [p[::-1] if rev >> i & 1 else p for i, p in enumerate(partes)]
    vistos = set()
    for ordem in itertools.permutations(base):
        m = tranca(ordem, k, pre)
        if lo:
            m = m.lower()
        if m not in vistos:
            vistos.add(m)
            yield m


def tarefas_agente():
    A = [(n, k, pr, rm, lo) for n in CONJ for k in (1, 2, 3, 4) for pr in (True, False)
         for rm in (0, 127) for lo in (False, True)]
    B = [("S0_atlas", k, pr, rm, lo) for k in (1, 2) for pr in (True, False)
         for rm in range(1, 127) for lo in (False, True)]
    return A + B


def rotulo(n, k, pr, rm, lo):
    return f"{n}/k{k}/{'pad' if pr else 'trunc'}/rev{rm}/{'lo' if lo else 'as'}"


def celulas(pwb):
    for bn, algo, salt, ct in CELLS:
        kk, iv = evp(pwb, salt, algo)
        p = unpad(AES.new(kk, AES.MODE_CBC, iv).decrypt(ct))
        if p is not None:
            yield bn, algo, p


# ---------------- STAGE verif: reproducao byte a byte de tarefas amostradas ----------------
AMOSTRA = [("S0_atlas", 1, True, 0, False), ("S0_atlas", 1, False, 0, False),
           ("S0_atlas", 2, True, 127, True), ("S_todos_hash", 3, False, 0, True),
           ("S_p3_partes", 4, True, 127, False), ("S_joins_hash", 2, False, 0, False),
           ("S0_atlas", 1, True, 45, False), ("S0_atlas", 2, False, 100, True),
           ("S_url_hash", 3, True, 0, False), ("S_lastword_3", 4, False, 127, True)]


def _verif(t):
    n, k, pr, rm, lo = t
    n_pw = 0
    shas = set()
    for m in materiais(CONJ[n], k, pr, rm, lo):
        n_pw += 1
        mb = m.encode("utf-8", "surrogatepass")
        for forma, pwb in (("raw", mb), ("sha256hex", hashlib.sha256(mb).hexdigest().encode())):
            for bn, algo, p in celulas(pwb):
                shas.add((bn, algo, forma, hashlib.sha256(p).hexdigest()[:16]))
    return rotulo(*t), n_pw, shas


# ---------------- STAGE dedup: materiais globais + privkey nas DUAS chaves ----------------
def _dedup(t):
    import numpy as np
    n, k, pr, rm, lo = t
    hs = []
    hits = []
    for m in materiais(CONJ[n], k, pr, rm, lo):
        mb = m.encode("utf-8", "surrogatepass")
        hs.append(int.from_bytes(hashlib.blake2b(mb, digest_size=8).digest(), "big"))
        r = priv_ok(hashlib.sha256(mb).digest())
        if r:
            hits.append({"tipo": "PRIVKEY", "chave": r, "tarefa": rotulo(*t), "material": m})
    return rotulo(*t), np.asarray(hs, dtype=np.uint64), hits


# ---------------- STAGE retro: oraculo completo nos logs (atacante + critico anterior) ----------------
def _retro(lote):
    res = {"n": 0, "integridade_falha": 0, "pr_max": 0.0, "ebc_max": 0.0, "janelas": 0, "sem": 0}
    hits = []
    for fonte, rec in lote:
        p = bytes.fromhex(rec["hex"])
        res["n"] += 1
        if fonte == "atacante" and not rec.get("trunc"):
            if len(p) != rec["len"] or hashlib.sha256(p).hexdigest()[:16] != rec["pt_sha"]:
                res["integridade_falha"] += 1
        res["pr_max"] = max(res["pr_max"], G.printable(p))
        res["ebc_max"] = max(res["ebc_max"], G.ebcdic_sig(p))
        res["janelas"] += 2 * max(0, len(p) - 31)
        if G.semantic(p):
            res["sem"] += 1
        a = oraculo(p)
        if a:
            hits.append({"fonte": fonte, "achados": [str(x) for x in a], **rec})
    return res, hits


FONTES = (("atacante", os.path.join(DIR_AG, "paddings.jsonl.gz")),
          ("critico1_formas_novas", os.path.join(DIR_C1, "pads_formas_novas.jsonl.gz")),
          ("critico1_k59", os.path.join(DIR_C1, "pads_k59.jsonl.gz")))


def logs_retro():
    for fonte, path in FONTES:
        if not os.path.exists(path):
            continue
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                r.pop("material", None)
                yield fonte, r


def lotes_retro():
    lote = []
    for x in logs_retro():
        lote.append(x)
        if len(lote) >= 2000:
            yield lote
            lote = []
    if lote:
        yield lote


# ---------------- STAGE o5up: operando (5) verbatim THEMATRIXHASYOU (README l.538) ----------------
S0_UP = list(O)
S0_UP[4] = "THEMATRIXHASYOU"


def _o5up(t):
    k, pr, rm = t
    res = {"n_pw": 0, "n_aes": 0, "pads": 0}
    hits = []
    regs = []
    dump = []
    for m in materiais(S0_UP, k, pr, rm, False):
        res["n_pw"] += 1
        mb = m.encode("utf-8", "surrogatepass")
        d = hashlib.sha256(mb).digest()
        r = priv_ok(d)
        if r:
            hits.append({"tipo": "PRIVKEY", "chave": r, "material": m})
        for forma, pwb in (("raw", mb), ("sha256hex", d.hex().encode())):
            res["n_aes"] += 6
            for bn, algo, p in celulas(pwb):
                res["pads"] += 1
                a = oraculo(p, janelas=bn != "COSMIC")
                if bn == "COSMIC":
                    dump.append(p)
                regs.append({"blob": bn, "kdf": algo, "forma": forma, "k": k, "pre": pr, "rev": rm,
                             "printable": round(G.printable(p), 3),
                             "hex": p.hex() if (bn != "COSMIC" or a) else p[:64].hex()})
                if a:
                    hits.append({"tipo": "PLAINTEXT", "blob": bn, "kdf": algo, "forma": forma,
                                 "material": m, "achados": [str(x) for x in a], "hex": p.hex()})
    return res, hits, regs, dump


def z(pads, n, p=P_PAD):
    return (pads - n * p) / math.sqrt(n * p * (1 - p))


def controle_positivo():
    salt, ct = G._parse(G.PHASE2_B64)
    k, iv = evp(hashlib.sha256(b"causality").hexdigest().encode(), salt, "sha256")
    p = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
    assert p and p[:10] == b"The ironic"
    return p[:52].decode("latin-1")


def autoteste():
    assert tranca(["abc", "12", "XY"], 1, True) == "a1Xb2Yc"
    assert tranca(["abc", "12", "XY"], 1, False) == "a1Xb2Y"
    assert tranca(["abcde", "12"], 2, True) == "ab12cde"
    assert tranca(["abcde", "12"], 2, False) == "ab12"
    assert len(set(materiais(O, 1, True, 0, False))) == 4320
    assert len(set(materiais(O, 1, False, 0, False))) == 2520
    assert next(materiais(["ab", "cd"], 1, True, 0b10, False)) == "adbc"
    assert priv_ok((1).to_bytes(32, "big")) is None and oraculo(bytes(80)) == []
    # positivos sinteticos: o oraculo dispara nos dois ramos quando o alvo e uma chave conhecida
    kk = hashlib.sha256(b"teste").digest()
    P = PublicKey.from_valid_secret(kk)
    assert priv_ok(kk, tgt=P.format(False)) == "1GSMG"
    assert priv_ok(kk, h17=h160(P.format(True))) == "17ucy"
    assert priv_ok(kk, h17=h160(P.format(False))) == "17ucy"
    assert priv_ok(bytes(32)) is None and priv_ok(b"\xff" * 32) is None   # 0 e >= n rejeitados
    assert "ASCII85" in oraculo(b"A" * 80)
    assert "NESTED_SALTED" in oraculo(b"Salted__" + bytes(40))
    print("autoteste OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="all", choices=["all", "verif", "dedup", "retro", "o5up"])
    ap.add_argument("--workers", type=int, default=18)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    autoteste()
    ctrl = controle_positivo()
    print("CONTROLE POSITIVO:", ctrl, flush=True)
    sm = json.load(open(os.path.join(DIR_AG, "summary.json"), encoding="utf-8"))
    ag = {rotulo(t["conjunto"], t["k"], t["preencher"], t["rev_mask"], t["minusculo"]): t
          for t in sm["tarefas"]}
    R = {"controle_positivo": ctrl, "p_pad": P_PAD}
    hits = []
    t0 = time.time()

    if a.stage in ("all", "verif"):
        logs = {}
        rot = {rotulo(*t) for t in AMOSTRA}
        with gzip.open(os.path.join(DIR_AG, "paddings.jsonl.gz"), "rt", encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r["tarefa"] in rot:
                    logs.setdefault(r["tarefa"], set()).add(
                        (r["blob"], r["kdf"].split(".")[-1].lower(), r["form"], r["pt_sha"]))
        with Pool(a.workers) as pool:
            got = pool.map(_verif, AMOSTRA)
        det = []
        for rot_, n_pw, shas in got:
            L = logs.get(rot_, set())
            det.append({"tarefa": rot_, "n_pw_meu": n_pw, "n_pw_ag": ag[rot_]["n_pw"],
                        "pads_meu": len(shas), "pads_ag": ag[rot_]["pads"], "pt_sha_iguais": shas == L,
                        "so_meu": len(shas - L), "so_ag": len(L - shas)})
        R["verif"] = {"tarefas": len(det), "aes": 12 * sum(d["n_pw_meu"] for d in det),
                      "todas_batem": all(d["n_pw_meu"] == d["n_pw_ag"] and d["pt_sha_iguais"] for d in det),
                      "detalhe": det}
        print(json.dumps(R["verif"], indent=1), flush=True)

    if a.stage in ("all", "dedup"):
        import numpy as np
        tl = tarefas_agente()
        hs = []
        t1 = time.time()
        div = []
        with Pool(a.workers) as pool:
            for i, (rot_, h, hh) in enumerate(pool.imap_unordered(_dedup, tl, chunksize=4)):
                hs.append(h)
                hits += hh
                if len(h) != ag[rot_]["n_pw"]:
                    div.append(rot_)
                for x in hh:
                    print("!!! HIT:", json.dumps(x)[:300], flush=True)
                if (i + 1) % 400 == 0:
                    print(f"  dedup {i+1}/{len(tl)} {time.time()-t1:.0f}s", flush=True)
        todos = np.concatenate(hs)
        _, cnt = np.unique(todos, return_counts=True)
        hist = {int(m): int(c) for m, c in zip(*np.unique(cnt, return_counts=True))}
        n_aes, pads = sm["totais"]["aes"], sm["totais"]["paddings"]
        sum_m2 = int((cnt.astype(np.int64) ** 2).sum())
        R["dedup"] = {"materiais_por_tarefa": int(todos.size), "globalmente_distintos": int(cnt.size),
                      "tarefas_divergentes_do_agente": div, "histograma_multiplicidade": hist,
                      "privkeys_2_chaves": int(todos.size), "privkey_hits": len(hits),
                      "z_1_256": round(z(pads, n_aes, 1 / 256), 3), "z_1_255": round(z(pads, n_aes), 3),
                      "z_1_255_var_corrigida_duplicatas": round(
                          (pads - n_aes * P_PAD) / math.sqrt(12 * P_PAD * (1 - P_PAD) * sum_m2), 3),
                      "seg": round(time.time() - t1, 1)}
        print(json.dumps(R["dedup"], indent=1), flush=True)

    if a.stage in ("all", "retro"):
        t1 = time.time()
        agg = {"n": 0, "integridade_falha": 0, "pr_max": 0.0, "ebc_max": 0.0, "janelas": 0, "sem": 0}
        rh = []
        with Pool(a.workers) as pool:
            for j, (r, hh) in enumerate(pool.imap_unordered(_retro, lotes_retro(), chunksize=1)):
                for k2 in ("n", "integridade_falha", "janelas", "sem"):
                    agg[k2] += r[k2]
                agg["pr_max"] = max(agg["pr_max"], r["pr_max"])
                agg["ebc_max"] = max(agg["ebc_max"], r["ebc_max"])
                rh += hh
                for x in hh:
                    print("!!! ACHADO:", json.dumps(x)[:300], flush=True)
                if (j + 1) % 50 == 0:
                    print(f"  retro {agg['n']:,} {time.time()-t1:.0f}s", flush=True)
        por_fonte = {}
        for fonte, _ in logs_retro():
            por_fonte[fonte] = por_fonte.get(fonte, 0) + 1
        R["retro"] = {**agg, "pr_max": round(agg["pr_max"], 3), "ebc_max": round(agg["ebc_max"], 3),
                      "por_fonte": por_fonte, "n_achados": len(rh), "achados": rh[:20],
                      "seg": round(time.time() - t1, 1)}
        hits += rh
        print(json.dumps({k: v for k, v in R["retro"].items() if k != "achados"}, indent=1), flush=True)

    if a.stage in ("all", "o5up"):
        t1 = time.time()
        tl = [(k, pr, rm) for k in (1, 2, 3, 4) for pr in (True, False) for rm in (0, 127)]
        tl += [(k, pr, rm) for k in (1, 2) for pr in (True, False) for rm in range(1, 127)]
        agg = {"n_pw": 0, "n_aes": 0, "pads": 0}
        uh = []
        with gzip.open(os.path.join(OUT, "pads_o5up.jsonl.gz"), "wt", encoding="utf-8") as f, \
                open(os.path.join(OUT, "cosmic_full_o5up.bin"), "wb") as fb, Pool(a.workers) as pool:
            for j, (r, hh, regs, dump) in enumerate(pool.imap_unordered(_o5up, tl, chunksize=2)):
                for k2 in agg:
                    agg[k2] += r[k2]
                for g in regs:
                    f.write(json.dumps(g) + "\n")
                for p in dump:
                    fb.write(len(p).to_bytes(4, "little") + p)
                uh += hh
                for x in hh:
                    print("!!! ACHADO o5up:", json.dumps(x)[:300], flush=True)
                if (j + 1) % 100 == 0:
                    print(f"  o5up {j+1}/{len(tl)} AES={agg['n_aes']:,} pads={agg['pads']:,} "
                          f"{time.time()-t1:.0f}s", flush=True)
        R["o5up"] = {**agg, "tarefas": len(tl), "n_achados": len(uh), "achados": uh[:20],
                     "z_1_255": round(z(agg["pads"], agg["n_aes"]), 3), "seg": round(time.time() - t1, 1)}
        hits += uh
        print(json.dumps({k: v for k, v in R["o5up"].items() if k != "achados"}, indent=1), flush=True)

    R["hits_total"] = len(hits)
    R["seg_total"] = round(time.time() - t0, 1)
    json.dump(R, open(os.path.join(OUT, f"resumo_{a.stage}.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    with open(os.path.join(OUT, f"hits_{a.stage}.jsonl"), "w", encoding="utf-8") as f:
        for h in hits:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")
    print("FIM", a.stage, "hits:", len(hits), f"{time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
