# -*- coding: utf-8 -*-
r"""
SINTETIZADOR da rodada "operador ensinado" (2026-09-17) — verificação independente.

HIPÓTESE (prosa, finita, falsificável)
--------------------------------------
Nenhuma das seis famílias alegou hit duro. O que sobrou para verificar são três pontos que os
logs em disco deixaram em aberto e que, se estiverem errados, mudam o veredito da rodada:

 V2  O crítico da família 6 mediu um EXCESSO de padding PKCS7 na sub-família F5_shortlist:
     684 paddings em 151.200 decifrações (esperado 593; z ≈ +3,7; 0/200 réplicas nulas ≥ 684).
     Padding em excesso não tem mecanismo causal por senha certa (cada chave errada é um ensaio
     Bernoulli independente com p = Σ_{n=1..16} 256^-n), então a explicação é acaso, duplicação
     de ensaios ou erro de contagem. Falsificável: regenero os 3.600 candidatos F5 e os 7
     materiais (3 do agente + 4 do crítico) de forma independente, decifro os 3 blobs × 2 KDF
     por inteiro com EVP_BytesToKey e PKCS7 próprios, conto por material e por célula, e conto
     senhas DISTINTAS. Se a contagem não for 684 ou houver duplicatas, o "excesso" era artefato;
     se for 684 com 25.200 senhas distintas, é um desvio de acaso a registrar (não é sinal).

 V3  O braço C5 do crítico da família 4 gravou 247.594 detecções "ascii85+hex64" em registros de
     MATERIAL sem registro de resumo (execução cortada). Cada uma é uma string ASCII de 64 hex.
     Falsificável: decodifico cada uma para 32 B e testo como privkey (comprimida e não
     comprimida) contra os DOIS endereços do prêmio.

 V4  O retro do orquestrador (694.386 plaintexts, 81,9 M janelas, 2 endereços) rodou antes de
     os logs dos críticos crescerem. Falsificável: coleto TODO plaintext em hex desta rodada
     (jsonl, json e jsonl.gz), deduplico, e passo o oráculo duro completo — G.semantic,
     G.nested_blob, G.ebcdic_sig e privkey em toda janela de 32 B nas DUAS ordens de byte contra
     os DOIS endereços (pubkey 04f4d1bb… de 1GSMG… e h160 de 17ucy…).

 V1  Controle positivo obrigatório com o pipeline DESTE script (não o do kit): a fase 2 abre com
     sha256hex("causality") sob EVP-SHA256 e não abre sob EVP-MD5; chave plantada é achada pelo
     scanner de janelas nas duas ordens e para os dois formatos de pubkey.

Saída: _work/operador_ensinado_2026-09-17/sintese/{sintese.jsonl, sintese.json}
Uso:   python sintese_verificacao.py [--workers N] [--so V1,V2,V3,V4]
"""
import sys, os, json, time, gzip, glob, hashlib, itertools, collections, math, argparse
from multiprocessing import Pool

REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(REPO, r"solver\experiments\claude_endgame_2026_09_02"))
import gsmg_common as G
from Crypto.Cipher import AES
from coincurve import PublicKey
import base58

OUT = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\sintese")
os.makedirs(OUT, exist_ok=True)
LOGP = os.path.join(OUT, "sintese.jsonl")
P_PKCS7 = sum(256.0 ** -k for k in range(1, 17))          # 0,0039216 (G.unpad aceita 1..16)
ADDRS = ("1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa")
H160 = {base58.b58decode_check(a)[1:]: a for a in ADDRS}
TARGET_PUB = bytes.fromhex(G.TARGET_PUBKEY_HEX)
BLOBS = ("SMALL", "COSMIC", "TAIL32")


def log(**rec):
    with open(LOGP, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(json.dumps({k: v for k, v in rec.items() if k not in ("hex",)}, ensure_ascii=False)[:600], flush=True)


# ---------------------------------------------------------------- pipeline próprio (não usa G.evp/G.unpad)
def evp(pw: bytes, salt: bytes, h, klen=32, ivlen=16):
    d, prev = b"", b""
    while len(d) < klen + ivlen:
        prev = h(prev + pw + salt).digest()
        d += prev
    return d[:klen], d[klen:klen + ivlen]


def unpad(p):
    n = p[-1]
    if 1 <= n <= 16 and p[-n:] == bytes([n]) * n:
        return p[:-n]
    return None


def decifra(pw: bytes, blob: str, kdf: str):
    salt, ct = G.BLOBS[blob]
    k, iv = evp(pw, salt, hashlib.md5 if kdf == "md5" else hashlib.sha256)
    return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def priv2(sec: bytes):
    """(endereço, formato) se sec de um dos dois endereços do prêmio; senão None."""
    try:
        pk = PublicKey.from_valid_secret(sec)
    except Exception:
        return None
    u = pk.format(False)
    if u == TARGET_PUB:
        return (ADDRS[0], "pubkey")
    for form, blob in (("unc", u), ("comp", pk.format(True))):
        a = H160.get(h160(blob))
        if a:
            return (a, form)
    return None


def scan32(buf: bytes):
    hits = []
    for tag, b in (("fwd", buf), ("rev", buf[::-1])):
        for j in range(0, len(b) - 31):
            r = priv2(b[j:j + 32])
            if r:
                hits.append((tag, j, b[j:j + 32].hex(), r))
    return hits


# ---------------------------------------------------------------- V1
def v1():
    import base64
    raw = base64.b64decode(G.PHASE2_B64)
    G.BLOBS["FASE2"] = (raw[8:16], raw[16:])
    pw = G.shahex("causality").encode()
    p_sha = decifra(pw, "FASE2", "sha256")
    p_md5 = decifra(pw, "FASE2", "md5")
    del G.BLOBS["FASE2"]
    ok1 = p_sha is not None and p_sha.startswith(b"The ironic") and G.semantic(p_sha)
    ok2 = p_md5 is None or not G.semantic(p_md5)
    # chave plantada: gera uma privkey, seu endereço P2PKH, e injeta o alvo temporariamente
    sec = hashlib.sha256(b"controle plantado sintese").digest()
    pk = PublicKey.from_valid_secret(sec)
    global H160
    saved = dict(H160)
    H160[h160(pk.format(True))] = "PLANTADO_comp"
    # planta a chave na ordem direta (offset 40) e invertida (offset 109): o scanner tem de achar as duas
    buf = os.urandom(40) + sec + os.urandom(37) + sec[::-1] + os.urandom(5)
    hf = scan32(buf)
    H160 = saved
    ok3 = (any(t == "fwd" and j == 40 for t, j, _, _ in hf)
           and any(t == "rev" and j == len(buf) - 109 - 32 for t, j, _, _ in hf) and len(hf) == 2)
    log(etapa="V1_controle", fase2_sha256_abre=bool(ok1), fase2_md5_nao_abre=bool(ok2),
        head=(p_sha or b"")[:40].decode("latin-1"), plantado_fwd_rev=bool(ok3), p_pkcs7=P_PKCS7)
    assert ok1 and ok2 and ok3, "controle positivo falhou"


# ---------------------------------------------------------------- V2
CURTA_VB = ["the better half", "us guys at gsmg", "Jacque Fresco",
            "Globally supporting my generation", "-41,-17", "Cosmic Duality"]


def f5_candidatos():
    curta_low = ["".join(x.split()).lower() for x in CURTA_VB]
    out = []
    for base in (CURTA_VB, curta_low):
        for k in (4, 5, 6):
            for combo in itertools.permutations(base, k):
                out.append("".join(combo))
    return out


def materiais7(s: str):
    b = s.encode("utf-8")
    d = hashlib.sha256(b).digest()
    h = d.hex()
    return (("raw", b), ("sha256hex", h.encode()), ("SHA256HEX", h.upper().encode()),
            ("digest32", d), ("sha256d_hex", hashlib.sha256(d).hexdigest().encode()),
            ("raw_lf", b + b"\n"), ("sha256hex_lf", hashlib.sha256(b + b"\n").hexdigest().encode()))


def _v2_worker(chunk):
    pad = collections.Counter()
    padlen = collections.Counter()
    sem = []
    n = 0
    for s in chunk:
        for mat, pw in materiais7(s):
            for blob in BLOBS:
                for kdf in ("md5", "sha256"):
                    n += 1
                    p = decifra(pw, blob, kdf)
                    if p is None:
                        continue
                    pad[(mat, blob, kdf)] += 1
                    padlen[len(G.BLOBS[blob][1]) - len(p)] += 1
                    if G.semantic(p) or scan32(p):
                        sem.append({"cand": s, "mat": mat, "blob": blob, "kdf": kdf, "hex": p.hex()})
    return n, pad, padlen, sem


def v2(workers):
    try:
        sys.path.insert(0, os.path.join(REPO, r"solver\operador_ensinado_2026_09_17"))
        import familia6_referencia_pessoal as F
        f5_dele = sorted(s for s, f in F.gerar().items() if f == "F5_shortlist")
    except Exception as e:                       # o import roda o controle do agente; se falhar, segue sem comparar
        f5_dele = None
        log(etapa="V2_aviso", erro=str(e)[:200])
    cands = f5_candidatos()
    assert len(cands) == 3600 and len(set(cands)) == 3600
    senhas = set()
    for s in cands:
        for _m, pw in materiais7(s):
            senhas.add(pw)
    iguais = (f5_dele is not None and sorted(cands) == f5_dele)
    chunks = [cands[i::workers] for i in range(workers)]
    n = 0
    pad = collections.Counter()
    padlen = collections.Counter()
    sem = []
    t0 = time.time()
    with Pool(workers) as pool:
        for nn, pp, pl, ss in pool.imap_unordered(_v2_worker, chunks):
            n += nn; pad.update(pp); padlen.update(pl); sem.extend(ss)
    k = sum(pad.values())
    z = (k - n * P_PKCS7) / math.sqrt(n * P_PKCS7 * (1 - P_PKCS7))
    por_mat = collections.Counter()
    por_cel = collections.Counter()
    for (m, b, kd), v in pad.items():
        por_mat[m] += v; por_cel[b + "/" + kd] += v
    agente = {"raw": 97, "sha256hex": 81, "SHA256HEX": 104}
    critico = {"sha256d_hex": 119, "raw_lf": 104, "digest32": 95, "sha256hex_lf": 84}
    bate = all(por_mat[m] == v for m, v in {**agente, **critico}.items())
    log(etapa="V2_F5", candidatos=len(cands), candidatos_iguais_ao_agente=iguais,
        senhas_distintas=len(senhas), senhas_esperadas=3600 * 7, decifracoes=n, paddings=k,
        esperado=round(n * P_PKCS7, 1), z_binomial=round(z, 3),
        p_unilateral=0.5 * math.erfc(z / math.sqrt(2)),
        por_material=dict(por_mat), por_celula=dict(por_cel),
        bate_agente_282_e_critico_402=bate, agente_mais_critico=684,
        comprimentos_de_padding=dict(sorted(padlen.items())),
        esperado_pad1_fracao=round(256 ** -1 / P_PKCS7, 4),
        hits_semanticos_ou_privkey=len(sem), segundos=round(time.time() - t0, 1))
    for r in sem:
        log(etapa="V2_HIT?", **r)
    return k


# ---------------------------------------------------------------- V3
def _v3_worker(hexs):
    hits = []
    n32 = 0
    for hx in hexs:
        try:
            s = bytes.fromhex(hx).decode("ascii", "strict").strip()
            sec = bytes.fromhex(s)
        except Exception:
            continue
        if len(sec) != 32:
            continue
        n32 += 1
        for tag, b in (("fwd", sec), ("rev", sec[::-1])):
            r = priv2(b)
            if r:
                hits.append((tag, hx, r))
    return n32, hits


def v3(workers):
    fn = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17\critico_familia4_codecs\critico_familia4_codecs.jsonl")
    hexs, tipos = [], collections.Counter()
    for ln in open(fn, encoding="utf-8"):
        r = json.loads(ln)
        if r.get("arm") == "C5_det":
            tipos[r.get("oraculo")] += 1
            hexs.append(r["hex"])
    chunks = [hexs[i::workers] for i in range(workers)]
    n32, hits = 0, []
    t0 = time.time()
    with Pool(workers) as pool:
        for a, b in pool.imap_unordered(_v3_worker, chunks):
            n32 += a; hits.extend(b)
    log(etapa="V3_C5_hex64", registros_C5_det=len(hexs), por_tipo=dict(tipos), decodificados_32B=n32,
        privkeys_testadas_2ordens_2enderecos=2 * n32, hits=hits, segundos=round(time.time() - t0, 1))


# ---------------------------------------------------------------- V4
HEXK = ("hex", "plain_hex", "plaintext_hex", "pt_hex")


def _walk(o, out):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in HEXK and isinstance(v, str) and len(v) >= 64 and len(v) % 2 == 0:
                out.append(v)
            else:
                _walk(v, out)
    elif isinstance(o, list):
        for v in o:
            _walk(v, out)


def coleta():
    root = os.path.join(REPO, r"_work\operador_ensinado_2026-09-17")
    seen, itens, por_arq = set(), [], collections.Counter()
    files = sorted(glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True) +
                   glob.glob(os.path.join(root, "**", "*.json"), recursive=True) +
                   glob.glob(os.path.join(root, "**", "*.jsonl.gz"), recursive=True))
    for p in files:
        if os.path.abspath(os.path.dirname(p)) == os.path.abspath(OUT):
            continue
        rel = os.path.relpath(p, root)
        got = []
        try:
            if p.endswith(".gz"):
                fh = gzip.open(p, "rt", encoding="utf-8", errors="replace")
            else:
                fh = open(p, encoding="utf-8", errors="replace")
            with fh:
                if p.endswith(".json"):
                    try:
                        _walk(json.load(fh), got)
                    except Exception:
                        pass
                else:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                _walk(json.loads(line), got)
                            except Exception:
                                pass
        except Exception:
            continue
        for h in got:
            try:
                b = bytes.fromhex(h)
            except ValueError:
                continue
            por_arq[rel] += 1
            if b not in seen:
                seen.add(b)
                itens.append((b, "C5" if "critico_familia4_codecs" in rel else "AES"))
    return itens, por_arq


def _v4_worker(chunk):
    n = jan = nested = sem = 0
    maxpr = maxeb = 0.0
    hits = []
    for b, kind in chunk:
        n += 1
        if kind == "AES":                      # em material C5 o "hex64 plausível" é tautológico
            if G.semantic(b):
                sem += 1; hits.append({"tipo": "semantic", "hex": b.hex()[:400]})
            if G.nested_blob(b):
                nested += 1; hits.append({"tipo": "nested", "hex": b.hex()[:400]})
            maxpr = max(maxpr, G.printable(b))
            maxeb = max(maxeb, G.ebcdic_sig(b))
        if len(b) >= 32:
            jan += 2 * (len(b) - 31)
            for t, j, sec, r in scan32(b):
                hits.append({"tipo": "privkey", "ordem": t, "off": j, "sec": sec, "alvo": r, "hex": b.hex()[:400]})
    return n, jan, nested, sem, maxpr, maxeb, hits


def v4(workers):
    t0 = time.time()
    itens, por_arq = coleta()
    ja = sum(1 for _, k in itens if k == "AES")
    log(etapa="V4_coleta", plaintexts_distintos=len(itens), aes=ja, material_c5=len(itens) - ja,
        bytes=sum(len(b) for b, _ in itens), arquivos=len(por_arq),
        janelas_previstas=sum(2 * max(0, len(b) - 31) for b, _ in itens), segundos=round(time.time() - t0, 1))
    with open(os.path.join(OUT, "v4_por_arquivo.json"), "w", encoding="utf-8") as f:
        json.dump(por_arq, f, ensure_ascii=False, indent=1)
    sz = 4000
    chunks = [itens[i:i + sz] for i in range(0, len(itens), sz)]
    n = jan = nested = sem = 0
    maxpr = maxeb = 0.0
    hits = []
    t1 = time.time()
    with Pool(workers) as pool:
        for i, (a, b, c, d, e, f, h) in enumerate(pool.imap_unordered(_v4_worker, chunks)):
            n += a; jan += b; nested += c; sem += d; maxpr = max(maxpr, e); maxeb = max(maxeb, f); hits.extend(h)
            if (i + 1) % 25 == 0:
                print(f"  V4 {i+1}/{len(chunks)} chunks  plaintexts={n:,} janelas={jan:,} hits={len(hits)}  {time.time()-t1:.0f}s", flush=True)
    log(etapa="V4_retro", plaintexts=n, janelas_32B_2ordens=jan, semantic=sem, nested=nested,
        max_printable=round(maxpr, 3), max_ebcdic=round(maxeb, 3), hits=len(hits), segundos=round(time.time() - t1, 1))
    for h in hits:
        log(etapa="V4_HIT?", **h)


# ---------------------------------------------------------------- main
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--so", default="V1,V2,V3,V4")
    a = ap.parse_args()
    so = set(a.so.split(","))
    t0 = time.time()
    log(etapa="inicio", workers=a.workers, so=sorted(so))
    v1()
    if "V2" in so:
        v2(a.workers)
    if "V3" in so:
        v3(a.workers)
    if "V4" in so:
        v4(a.workers)
    log(etapa="fim", segundos=round(time.time() - t0, 1))
