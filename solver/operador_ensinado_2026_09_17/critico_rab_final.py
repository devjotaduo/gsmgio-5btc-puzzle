# -*- coding: utf-8 -*-
"""
CRITICO FINAL da familia "matrixsumlist_rab" (rab_a1z26.py). Fecha o que os criticos anteriores
(critico_rab.py; critico_rab_a1z26.py + critico_rab_l83.py, que morreu antes do nulo da extensao)
deixaram aberto. Nao repete o que eles ja reproduziram; confere e completa.

HIPOTESE (prosa, finita, falsificavel): o negativo do agente NAO se sustenta por uma destas vias.
  H1 cobertura inflada — recontagem independente (senhas unicas, privkeys, objetos e formas
     realmente distintos) e recontagem do padding por sub-familia sem usar o pipeline dele.
  H2 oraculo incompleto — G.priv_hit / G.fast_priv_scan / O.check_privkey comparam SO com o
     1GSMG (TARGET_H160 a9553269… E o h160 do proprio 1GSMG). O segundo endereco do premio,
     17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa (h160 4bc46844…), nunca foi alvo nem do agente nem dos
     criticos anteriores — apesar de o critico_rab.py dizer "h160 dos DOIS enderecos".
     Re-testo TODAS as privkeys candidatas das 4 rodadas e TODOS os plaintexts com padding
     valido das 4 rodadas (janelas de 32 B nas duas ordens + hex64/WIF em ASCII) contra os dois.
  H3 lacuna pequena do operador: os 23 bits dos marcadores lidos como numero BINARIO (o agente e
     os criticos leram a string de bits como digitos DECIMAIS), L83/L84 x polaridade x ordem.
  H4 look-elsewhere: os z de padding reportados (max +2,42) sao o esperado em 24 testes.
  H5 nulo casado (100 replicas, forma preservada) da extensao de 219.630 senhas do
     critico_rab_a1z26.py, que ficou sem nulo.
FALSIFICACAO: qualquer hit duro (privkey -> h160 comp/uncomp de 1GSMG ou 17ucy; plaintext
semantico por G.semantic) derruba o negativo. Sem hits e com padding dentro do binomial
(p0 = sum_{k=1..16} 256^-k ~ 1/255) e do nulo casado, o negativo fica CONFIRMADO.
CONTROLES: fase 2 abre com sha256hex("causality") sob EVP-SHA256; chave PLANTADA (invertida,
offset 13) e achada pelo oraculo de dois alvos; o contador rapido de padding (so o ultimo bloco
CBC) reproduz exatamente os 6 contadores do agente antes de ser usado no nulo.

Saida: _work/operador_ensinado_2026-09-17/critico_rab_final/{resumo.json, *.json}
Uso:   python critico_rab_final.py [--demo] [--n-nulo N]
"""
import sys, os, json, time, math, hashlib, random, statistics, builtins, re
from multiprocessing import Pool

REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
SOLV = os.path.join(REPO, r"solver\operador_ensinado_2026_09_17")
WORK = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17")
OUT = os.path.join(WORK, "critico_rab_final")
sys.path.insert(0, os.path.join(REPO, r"solver\experiments\claude_endgame_2026_09_02"))
sys.path.insert(0, SOLV)
import gsmg_common as G
import rab_a1z26 as R
import oraculo_dois_alvos as D
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

# critico_rab_a1z26.py abre o critico.jsonl (arquivo de OUTRO agente) em modo append no import.
# Redireciono esse open para devnull: preciso das funcoes dele, nao posso tocar no log dele.
_open = builtins.open
def _open_sem_log(p, *a, **k):
    if isinstance(p, str) and p.replace("/", "\\").endswith(r"critico_rab_a1z26\critico.jsonl"):
        p = os.devnull
    return _open(p, *a, **k)
builtins.open = _open_sem_log
import critico_rab_a1z26 as C      # extensao de 219 k (0-based, 276 janelas, encadeamento...)
import critico_rab_l83 as L        # adendo L83
builtins.open = _open
import critico_rab as K            # primeiro critico (extensao de 102 k)

os.makedirs(OUT, exist_ok=True)
BLOBS = [(b, G.BLOBS[b][0], G.BLOBS[b][1]) for b in ("SMALL", "TAIL32", "COSMIC")]
KDFS = [("MD5", MD5), ("SHA256", SHA256)]
SUBFAM = [f"{b}/{k}" for b, _, _ in BLOBS for k, _ in KDFS]
P0 = sum(256.0 ** -k for k in range(1, 17))        # P(padding PKCS7 valido | chave errada)
BITS84, BITS83 = "00001000110000100110010", "00001000110000100110011"
SOFT_FILES = [("agente", r"rab_a1z26\soft_padding.jsonl"),
              ("critico_rab", r"critico_rab\ext_soft.jsonl"),
              ("critico_rab_a1z26", r"critico_rab_a1z26\extensao_soft.jsonl"),
              ("critico_rab_l83", r"critico_rab_a1z26\l83_soft.jsonl")]
NP = max(1, (os.cpu_count() or 4) - 4)


def salvar(nome, obj):
    with open(os.path.join(OUT, nome), "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


# ------------------------------------------------------------------ padding rapido (ultimo bloco)
def pad_ok_last(pw, salt, ct, hm):
    """CBC: P_n = D(C_n) xor C_{n-1}. So o ultimo bloco decide o padding — 6x mais barato no COSMIC."""
    key, iv = G.evp(pw, salt, hm)
    prev = ct[-32:-16] if len(ct) >= 32 else iv
    last = bytes(a ^ b for a, b in zip(AES.new(key, AES.MODE_ECB).decrypt(ct[-16:]), prev))
    k = last[-1]
    return 1 <= k <= 16 and last.endswith(bytes([k]) * k)


def pad_count_fast(senhas):
    c = dict.fromkeys(SUBFAM, 0)
    n = 0
    for pw in senhas:
        n += 1
        for bname, salt, ct in BLOBS:
            for kname, hm in KDFS:
                if pad_ok_last(pw, salt, ct, hm):
                    c[f"{bname}/{kname}"] += 1
    return c, n


# ------------------------------------------------------------------ oraculo de dois alvos
def scan_buf(buf, tag):
    """Janelas de 32 B nas duas ordens + hex64/WIF em ASCII, contra os DOIS h160 do premio."""
    hits = []
    for j in range(0, max(0, len(buf) - 31)):
        w = buf[j:j + 32]
        r = D.priv_hit2(w)
        if r: hits.append({"src": tag, "ordem": "fwd", "off": j, "priv": w.hex(), "addr": r[0], "forma": r[1]})
        r = D.priv_hit2(w[::-1])
        if r: hits.append({"src": tag, "ordem": "rev", "off": j, "priv": w[::-1].hex(), "addr": r[0], "forma": r[1]})
    t = buf.decode("latin-1")
    for h in G.hex64_candidates(t):
        r = D.priv_hit2(bytes.fromhex(h))
        if r: hits.append({"src": tag, "ordem": "hex64", "priv": h, "addr": r[0], "forma": r[1]})
    for wif in G.wif_candidates(t):
        try:
            import base58
            raw = base58.b58decode_check(wif)
            if len(raw) in (33, 34):
                r = D.priv_hit2(raw[1:33])
                if r: hits.append({"src": tag, "ordem": "wif", "priv": raw[1:33].hex(), "addr": r[0], "forma": r[1]})
        except Exception:
            pass
    return hits


def _pk_chunk(items):
    return [{"priv": k.hex(), "prov": prov, "addr": r[0], "forma": r[1]}
            for k, prov in items if (r := D.priv_hit2(k))]


def _rescan_chunk(items):
    out = {"n": 0, "janelas": 0, "hits": [], "semantic": 0, "nested": 0, "wif_hex64": 0,
           "ebcdic_ge075": 0, "max_printable": 0.0, "max_ebcdic": 0.0, "top": []}
    for hx, (src, blob, prov) in items:
        p = bytes.fromhex(hx)
        out["n"] += 1
        out["janelas"] += 2 * max(0, len(p) - 31)
        out["hits"] += scan_buf(p, f"{src}|{blob}|{prov}")
        for buf in (p, p[::-1]):
            if G.semantic(buf): out["semantic"] += 1
            if G.nested_blob(buf): out["nested"] += 1
            t = buf.decode("latin-1")
            if G.wif_candidates(t) or G.hex64_candidates(t): out["wif_hex64"] += 1
        pr, eb = G.printable(p), G.ebcdic_sig(p)
        if eb >= 0.75: out["ebcdic_ge075"] += 1
        out["max_printable"] = max(out["max_printable"], pr)
        out["max_ebcdic"] = max(out["max_ebcdic"], eb)
        out["top"].append((round(pr, 3), src, blob, prov))
    out["top"] = sorted(out["top"], reverse=True)[:3]
    return out


# ------------------------------------------------------------------ controles
def controles():
    ok, head = R.controle_positivo()
    assert ok, "controle positivo da fase 2 FALHOU"
    from coincurve import PublicKey
    k = hashlib.sha256(b"critico-rab-final").digest()
    h = D.h160(PublicKey.from_valid_secret(k).format(True))    # forma comprimida, so para variar
    D.TARGETS[h] = "PLANTADO"
    try:
        assert D.priv_hit2(k) == ("PLANTADO", "comp")
        hits = scan_buf(b"\x11" * 13 + k[::-1] + b"\x22" * 9, "ctrl")
        assert any(x["off"] == 13 and x["ordem"] == "rev" and x["addr"] == "PLANTADO" for x in hits), hits
        assert not D.priv_hit2(hashlib.sha256(b"lixo").digest())
    finally:
        del D.TARGETS[h]
    assert D.H160_A == "a9553269572a317e39f0f518cb87c1a0ee1dbae4"
    assert D.H160_B == "4bc468447fe1b048ad030a2f9a125478eabc4ed6"
    # o contador rapido tem de reproduzir G.unpad(AES-CBC completo) — testado na recontagem
    return head


# ------------------------------------------------------------------ H1 recontagem
def recontagem():
    ent_txt, ent_num = R.entradas_texto(), R.entradas_numericas()
    senhas = R.gerar_senhas(ent_txt, ent_num)
    pk = R.privkeys_candidatas(ent_txt, ent_num)
    ord_set = {tuple(R.ordinais(t)) for t in ent_txt.values()}
    ord_set_pal = {(tuple(R.ordinais(t)), tuple(tuple(R.ordinais(w)) for w in t.split()))
                   for t in ent_txt.values()}
    num_set = {tuple(v) for v in ent_num.values()}
    formas = R.formas("13120189241921131291920")
    formas_distintas = len({(v if isinstance(v, bytes) else v.encode()) for _, v in formas})
    idx = sorted(G.COLORED)
    selA = [v for k, v in enumerate(idx) if k not in (21, 24)]
    assert selA == [7, 15, 23, 31, 39, 47, 55, 63, 71, 79, 87, 95, 103, 111, 119, 127, 135, 143,
                    151, 159, 163, 175, 183], selA
    assert ent_num["yb:spiral23_A"] == selA and ent_num["yb:url23A_ascii"] == list(b"gsmg.io/theseedisplante")
    assert ent_num["yb:bitsL84"] == [int(c) for c in BITS84]
    t0 = time.time()
    cnt, n = pad_count_fast(senhas.keys())
    # verificacao do contador rapido contra o pipeline completo (G.aes_try) numa amostra
    amostra = list(senhas)[:1500]
    lento = dict.fromkeys(SUBFAM, 0)
    for pw in amostra:
        for b, _, _ in BLOBS:
            for kname, p in G.aes_try(pw, b):
                lento[f"{b}/{kname.rsplit('.', 1)[-1]}"] += 1
    rapido, _ = pad_count_fast(amostra)
    assert lento == rapido, (lento, rapido)
    return {"senhas_unicas": len(senhas), "privkeys": len(pk), "entradas_texto": len(ent_txt),
            "entradas_numericas": len(ent_num),
            "objetos_texto_distintos_pelo_operador": len(ord_set),
            "objetos_texto_distintos_com_split": len(ord_set_pal),
            "objetos_numericos_distintos": len(num_set),
            "formas_declaradas": 10, "formas_distintas": formas_distintas,
            "padding_por_subfamilia": cnt, "decifracoes": n * 6,
            "contador_rapido_vs_aes_try_1500_senhas": "identico",
            "seg": round(time.time() - t0, 1)}, senhas, ent_txt, ent_num


# ------------------------------------------------------------------ H2a privkeys de todas as rodadas
def privkeys_todas(ent_txt, ent_num):
    keys, origem = {}, {}
    def add(k, prov, src):
        if k not in keys:
            keys[k] = prov; origem[src] = origem.get(src, 0) + 1
    for k, v in R.privkeys_candidatas(ent_txt, ent_num).items():
        add(k, v, "agente")
    _, p1 = K.gerar_ext(*K.entradas_ext())
    for k, v in p1.items():
        add(k, v, "critico_rab")
    et = dict(ent_txt); et.update(C.janelas_todas_23())
    for pw, prov in C.gerar_senhas_ext(et, ent_num).items():
        add(hashlib.sha256(pw).digest(), "sha256|" + prov, "critico_rab_a1z26")
        if len(pw) <= 32 and pw.isdigit():
            n = int(pw); b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")[-32:]
            add(bytes(32 - len(b)) + b, "int|" + prov, "critico_rab_a1z26")
    for pw, prov in L.gerar(L.entradas_l83()).items():
        add(hashlib.sha256(pw).digest(), "sha256|" + prov, "critico_rab_l83")
        if pw.isdigit():
            n = int(pw); b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")[-32:]
            add(bytes(32 - len(b)) + b, "int|" + prov, "critico_rab_l83")
    return keys, origem


# ------------------------------------------------------------------ H3 bits como numero binario
def extra_bits():
    senhas, privs = {}, {}
    for nome, bits in (("L84", BITS84), ("L83", BITS83)):
        for pol, s in (("be=1", bits), ("be=0", "".join("1" if c == "0" else "0" for c in bits))):
            for ordem, ss in (("fwd", s), ("rev", s[::-1])):
                n = int(ss, 2)
                dig = str(n)
                prov = f"{nome}|{pol}|{ordem}|bin={n}"
                b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
                privs.setdefault(bytes(32 - len(b)) + b, prov + "|int32be")
                for fname, pw in R.formas(dig):
                    pb = pw.encode() if isinstance(pw, str) else pw
                    senhas.setdefault(pb, prov + "|" + fname)
                    privs.setdefault(hashlib.sha256(pb).digest(), prov + "|sha256(" + fname + ")")
    hits, soft = [], []
    for pw, prov in senhas.items():
        h, s = G.try_password_all(pw)
        for rec in h + s:
            rec["senha"] = pw.decode("latin-1"); rec["prov"] = prov
        hits += h; soft += s
    pk_hits = [{"priv": k.hex(), "prov": v, "r": r} for k, v in privs.items() if (r := D.priv_hit2(k))]
    resc = _rescan_chunk([(r["hex"], ("extra_bits", r["blob"], r["prov"])) for r in soft]) if soft else None
    return {"senhas": len(senhas), "decifracoes": len(senhas) * 6, "privkeys": len(privs),
            "hits_duros": len(hits), "privkey_hits_dois_alvos": pk_hits, "paddings": len(soft),
            "revarredura": resc, "exemplo": {k: v for k, v in list(senhas.items())[:0]}}, soft


# ------------------------------------------------------------------ H4 look-elsewhere
def _logpmf(n, i, p):
    return (math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
            + i * math.log(p) + (n - i) * math.log1p(-p))


def binom_tails(n, k, p=P0):
    mu, sd = n * p, math.sqrt(n * p * (1 - p))
    lo, hi = max(0, int(mu - 15 * sd)), min(n, int(mu + 15 * sd))
    up = sum(math.exp(_logpmf(n, i, p)) for i in range(k, hi + 1))
    low = sum(math.exp(_logpmf(n, i, p)) for i in range(lo, k + 1))
    return {"z": round((k - mu) / sd, 2), "p_up": up, "p_low": low, "p_two": min(1.0, 2 * min(up, low))}


def _ler_jsonl_sujo(path):
    """critico.jsonl tem NULs no inicio (truncamento concorrente); le o que for JSON valido."""
    out = []
    for line in open(path, encoding="utf-8", errors="replace").read().replace("\x00", "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try: out.append(json.loads(line))
            except Exception: pass
    return out


def look_elsewhere(extra_cnt=None, extra_n=None):
    rodadas = {}
    a = json.load(open(os.path.join(WORK, r"rab_a1z26\resumo.json"), encoding="utf-8"))
    rodadas["agente"] = (a["senhas_unicas"], {k: v["padding_ok"] for k, v in a["subfamilias"].items()})
    b = json.load(open(os.path.join(WORK, r"critico_rab\resumo.json"), encoding="utf-8"))
    rodadas["critico_rab_ext"] = (b["senhas_ext"], {k: v["padding_ok"] for k, v in b["subfamilias"].items()})
    for ev in _ler_jsonl_sujo(os.path.join(WORK, r"critico_rab_a1z26\critico.jsonl")):
        if ev.get("ev") == "extensao_aes":
            rodadas["critico_rab_a1z26_ext"] = (ev["senhas"], ev["padding"])
    c = json.load(open(os.path.join(WORK, r"critico_rab_a1z26\l83_resumo.json"), encoding="utf-8"))
    rodadas["critico_rab_l83"] = (c["senhas_unicas"], {k: v["padding_ok"] for k, v in c["subfamilias"].items()})
    if extra_cnt:
        rodadas["critico_final_extra_bits"] = (extra_n, extra_cnt)
    res, todos = {}, []
    for nome, (n, cnt) in rodadas.items():
        res[nome] = {"n_senhas": n, "p0": P0, "sub": {}}
        for k, v in cnt.items():
            t = binom_tails(n, v)
            res[nome]["sub"][k] = {"padding_ok": v, "esperado": round(n * P0, 1), **t}
            todos.append((abs(t["z"]), t["p_two"], nome, k))
    m = len(todos)
    zmax = max(todos)
    pmin = min(x[1] for x in todos)
    res["global"] = {"testes": m, "max_abs_z": zmax[0], "onde": f"{zmax[2]}:{zmax[3]}",
                     "p_two_min": pmin, "sidak_p": 1 - (1 - pmin) ** m,
                     "esperado_max_abs_z_em_m_normais": round(math.sqrt(2 * math.log(m)) - 0.1, 2),
                     "veredito": "ruido" if 1 - (1 - pmin) ** m > 0.05 else "olhar"}
    return res


# ------------------------------------------------------------------ H5 nulo casado da extensao 219k
def _ent_ext():
    et = dict(R.entradas_texto()); et.update(C.janelas_todas_23())
    return et, R.entradas_numericas()


def _nulo_ext_replica(i):
    rnd = random.Random(20260921 * 1000 + i)
    et, en = _ent_ext()
    nt, nn = R.nulo_entradas(et, en, rnd)
    ns = C.gerar_senhas_ext(nt, nn)
    c, m = pad_count_fast(ns.keys())
    return {k: v / m for k, v in c.items()}, m


def nulo_ext(N):
    obs = None
    for ev in _ler_jsonl_sujo(os.path.join(WORK, r"critico_rab_a1z26\critico.jsonl")):
        if ev.get("ev") == "extensao_aes":
            obs = (ev["senhas"], ev["padding"])
    assert obs, "nao achei o evento extensao_aes no critico.jsonl"
    # recontagem propria da extensao (o log dele e a unica fonte; confiro)
    et, en = _ent_ext()
    ns = C.gerar_senhas_ext(et, en)
    cnt, n = pad_count_fast(ns.keys())
    t0 = time.time()
    with Pool(NP) as pool:
        reps = pool.map(_nulo_ext_replica, range(N))
    sub = {}
    for k in SUBFAM:
        xs = [r[k] for r, _ in reps]
        mu, sd = statistics.fmean(xs), (statistics.pstdev(xs) or 1e-12)
        o = cnt[k] / n
        sub[k] = {"padding_ok": cnt[k], "taxa_obs": round(o, 5), "nulo_media": round(mu, 5),
                  "nulo_sd": round(sd, 5), "z": round((o - mu) / sd, 2), "p0": round(P0, 5)}
    return {"senhas_recontadas": n, "senhas_no_log_dele": obs[0], "padding_recontado": cnt,
            "padding_no_log_dele": obs[1], "bate_com_log": (n == obs[0] and cnt == obs[1]),
            "n_replicas": N, "senhas_por_replica_media": round(statistics.fmean(m for _, m in reps)),
            "subfamilias": sub, "seg": round(time.time() - t0)}


# ------------------------------------------------------------------ main
def main(n_nulo):
    T0 = time.time()
    head = controles()
    print(f"[controles] fase2 OK: {head!r}; oraculo dois alvos acha chave plantada; H160_B = 17ucy")

    rec, senhas, ent_txt, ent_num = recontagem()
    salvar("recontagem.json", rec)
    print("[H1 recontagem]", json.dumps({k: v for k, v in rec.items() if k != "padding_por_subfamilia"}),
          rec["padding_por_subfamilia"])

    keys, origem = privkeys_todas(ent_txt, ent_num)
    items = list(keys.items())
    with Pool(NP) as pool:
        parts = pool.map(_pk_chunk, [items[i::NP] for i in range(NP)])
    pk_hits = [h for p in parts for h in p]
    pk = {"privkeys_unicas": len(keys), "por_origem_(novas_nessa_ordem)": origem,
          "alvos": [D.ADDR_A, D.ADDR_B], "hits": pk_hits, "seg": round(time.time() - T0)}
    salvar("privkeys_dois_alvos.json", pk)
    print("[H2a privkeys dois alvos]", json.dumps(pk))

    recs, por_arquivo = {}, {}
    for src, rel in SOFT_FILES:
        n = 0
        for line in open(os.path.join(WORK, rel), encoding="utf-8"):
            if not line.strip(): continue
            d = json.loads(line); n += 1
            recs.setdefault(d["hex"], (src, d.get("blob"), d.get("proveniencia") or d.get("prov")))
        por_arquivo[src] = n
    items = list(recs.items())
    with Pool(NP) as pool:
        parts = pool.map(_rescan_chunk, [items[i::NP] for i in range(NP)])
    rs = {"registros_por_arquivo": por_arquivo, "registros_total": sum(por_arquivo.values()),
          "plaintexts_unicos": len(recs), "janelas_32B_duas_ordens": sum(p["janelas"] for p in parts),
          "hits_privkey_dois_alvos": [h for p in parts for h in p["hits"]],
          "semantic": sum(p["semantic"] for p in parts), "nested": sum(p["nested"] for p in parts),
          "wif_hex64": sum(p["wif_hex64"] for p in parts), "ebcdic_ge075": sum(p["ebcdic_ge075"] for p in parts),
          "max_printable": round(max(p["max_printable"] for p in parts), 3),
          "max_ebcdic": round(max(p["max_ebcdic"] for p in parts), 3),
          "top3_printable": sorted([t for p in parts for t in p["top"]], reverse=True)[:3],
          "seg": round(time.time() - T0)}
    salvar("revarredura_dois_alvos.json", rs)
    print("[H2b revarredura]", json.dumps(rs))

    ex, ex_soft = extra_bits()
    salvar("extra_bits_binario.json", ex)
    with open(os.path.join(OUT, "extra_bits_soft.jsonl"), "w", encoding="utf-8") as f:
        for r in ex_soft: f.write(json.dumps(r, ensure_ascii=False) + "\n")
    ex_cnt = dict.fromkeys(SUBFAM, 0)
    for r in ex_soft: ex_cnt[f"{r['blob']}/{r['kdf'].rsplit('.', 1)[-1]}"] += 1
    print("[H3 bits binario]", json.dumps(ex))

    le = look_elsewhere(ex_cnt, ex["senhas"])
    salvar("look_elsewhere.json", le)
    print("[H4 look-elsewhere]", json.dumps(le["global"]))

    nu = nulo_ext(n_nulo) if n_nulo > 0 else None
    if nu:
        salvar("nulo_ext_219k.json", nu)
        print("[H5 nulo ext]", json.dumps(nu))

    resumo = {"controles": "fase2 + chave plantada dois alvos + contador rapido == aes_try",
              "H1_recontagem": rec, "H2a_privkeys": {k: v for k, v in pk.items() if k != "hits"} | {"hits": len(pk_hits)},
              "H2b_revarredura": {k: v for k, v in rs.items() if k != "hits_privkey_dois_alvos"} | {"hits": len(rs["hits_privkey_dois_alvos"])},
              "H3_bits_binario": ex, "H4_look_elsewhere_global": le["global"],
              "H5_nulo_ext": (nu["subfamilias"] if nu else None), "segundos": round(time.time() - T0)}
    salvar("resumo.json", resumo)
    print("[FIM]", json.dumps({k: v for k, v in resumo.items() if k in ("segundos",)}), f"NP={NP}")


def demo():
    print(controles())
    s = R.gerar_senhas(R.entradas_texto(), R.entradas_numericas())
    amostra = list(s)[:300]
    lento = dict.fromkeys(SUBFAM, 0)
    for pw in amostra:
        for b, _, _ in BLOBS:
            for kname, _p in G.aes_try(pw, b):
                lento[f"{b}/{kname.rsplit('.', 1)[-1]}"] += 1
    assert lento == pad_count_fast(amostra)[0]
    assert abs(P0 - 1 / 255) < 1e-9
    print("demo OK: controles, contador rapido == aes_try em 300 senhas, P0 = 1/255")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        n = int(sys.argv[sys.argv.index("--n-nulo") + 1]) if "--n-nulo" in sys.argv else 100
        main(n)
