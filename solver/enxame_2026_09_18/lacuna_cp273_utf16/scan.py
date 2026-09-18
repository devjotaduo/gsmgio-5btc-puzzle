# -*- coding: utf-8 -*-
"""Frente lacuna_cp273_utf16 (campanha enxame_2026-09-18; ENDGAME §3.13).

Recoleta os dois corpora da §3.11 com a lógica exata de `retro_dois_alvos.collect()` (694.386
conteúdos) e `v4_rodada_dois_alvos.collect()` (1.331.155), deduplica por conteúdo e passa cada
conteúdo pelas visões que a §3.11 não cobriu: cp273 inversa (a direção autêntica da fase 3.2),
cp273 direta e UTF-16 LE/BE nos dois alinhamentos. Em cada visão procura hex64 (todo offset de
nibble) e WIF com checksum, conferidos contra os dois alvos (G.fast_priv_scan, confirmação por
G.priv_hit), G.semantic, ASCII imprimível ≥ 48 B e Salted__/U2FsdGVk em qualquer offset. As janelas
raw32 da visão original já foram varridas na §3.11 e não são refeitas; hex64/WIF da original são
refeitos em todo offset porque a §3.11 usou finditer não sobreposto.

Rodar em primeiro plano (Windows/spawn):  python scan.py [--workers 6] [--limite N]
Saída: _work/enxame_2026-09-18/lacuna_cp273_utf16/{controls.json, summary.json, candidates.jsonl}.
O corpus não é gravado. Qualquer achado é CANDIDATO (AGENTS.md, regra 1), nunca solução.
"""
import argparse, base64, glob, gzip, hashlib, json, os, re, subprocess, sys, time
from bisect import bisect_left
from collections import Counter
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

import base58
import numpy as np
from coincurve import PublicKey
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

REPO = Path(__file__).resolve().parents[3]
KIT_DIR = REPO / "solver" / "experiments" / "claude_endgame_2026_09_02"
ORACULO_DUPLO = REPO / "solver" / "oraculo_duplo_2026_09_17"
sys.path.insert(0, str(KIT_DIR))
sys.path.insert(0, str(ORACULO_DUPLO))
import gsmg_common as G  # noqa: E402
from oracle import ORDER, cp273_inverse_view, decoded_candidates  # noqa: E402  (auditados em §3.12–3.13)

MAIN = Path(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle")  # dados locais (AGENTS.md)
OE = MAIN / "_work" / "operador_ensinado_2026-09-17"
RETRO_LOG = OE / "orquestrador" / "retro_dois_alvos.log"
V4_RES = OE / "orquestrador" / "v4_resultado.json"
OUT = REPO / "_work" / "enxame_2026-09-18" / "lacuna_cp273_utf16"
ESPERADO = {"retro": {"conteudos": 694386, "bytes": 62457317},
            "v4": {"conteudos": 1331155, "janelas": 115603741}}

# ------------------------------------------------------------------ recoleta (cópia fiel)
HEXK = ("hex", "plain_hex", "plaintext_hex", "pt_hex")
CHAVES = tuple(f'"{k}"' for k in HEXK)
HEXRE = re.compile(r"[0-9a-fA-F]+")


def walk(o, out):
    """Cópia fiel do walk() de retro_dois_alvos.collect() e de v4_rodada_dois_alvos."""
    if isinstance(o, dict):
        for k, v in o.items():
            if k in HEXK and isinstance(v, str) and len(v) >= 64 and len(v) % 2 == 0 and HEXRE.fullmatch(v):
                out.append(v.lower())
            else:
                walk(v, out)
    elif isinstance(o, list):
        for v in o:
            walk(v, out)


def _tem_chave(txt):
    # ponytail: sem a chave literal o walk() não coleta nada; o filtro só poupa json.loads.
    return any(k in txt for k in CHAVES)


def ler_retro(p):
    """Como retro_dois_alvos.collect(): .jsonl por splitlines(), .json inteiro; erro de leitura = fora."""
    got = []
    try:
        with open(p, encoding="utf-8", errors="replace", newline="") as f:
            if p.endswith(".jsonl"):
                for bruto in f:  # newline='' + splitlines() reproduz txt.splitlines() sem ler tudo
                    for line in bruto.splitlines():
                        line = line.strip()
                        if line and _tem_chave(line):
                            try:
                                walk(json.loads(line), got)
                            except Exception:
                                pass
            else:
                txt = f.read()
                if _tem_chave(txt):
                    try:
                        walk(json.loads(txt), got)
                    except Exception:
                        pass
    except Exception:
        return None
    return got


def ler_v4(p):
    """Como v4_rodada_dois_alvos.collect(): exclusão C5 por linha e dos hex de 64 caracteres."""
    got = []
    try:
        with (gzip.open if p.endswith(".gz") else open)(p, "rt", encoding="utf-8", errors="replace") as f:
            if p.endswith(".json"):
                txt = f.read()
                if _tem_chave(txt):
                    try:
                        walk(json.loads(txt), got)
                    except Exception:
                        pass
            else:
                for line in f:
                    line = line.strip()
                    if not line or not _tem_chave(line):
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(o, dict) and str(o.get("kind", o.get("tipo", ""))).startswith("C5"):
                        continue
                    walk(o, got)
    except Exception as e:
        print("  falha lendo", p, e, flush=True)
        return None
    return [h for h in got if len(h) != 64]


def _utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def recoletar():
    """corpus: bytes -> máscara (1 = retro, 2 = v4, 4 = retro fora de operador_ensinado);
    mt: bytes -> menor mtime entre os arquivos retro que o contêm (para a reconciliação)."""
    corpus, mt, arquivos = {}, {}, {"retro": [], "v4": []}
    for pat in ("_work/**/*.jsonl", "_work/**/*.json", "solver/**/*.jsonl"):
        for p in glob.glob(os.path.join(str(MAIN), pat), recursive=True):
            got = ler_retro(p)
            if not got:
                continue
            m_arq, fora_oe = os.path.getmtime(p), not Path(p).is_relative_to(OE)
            bs = [bytes.fromhex(h) for h in got]
            novos = sum(1 for b in bs if not corpus.get(b, 0) & 1)
            for b in bs:
                m = corpus.get(b, 0)
                corpus[b] = m | 1 | (4 if fora_oe else 0)
                mt[b] = min(mt.get(b, m_arq), m_arq)
            arquivos["retro"].append({"arquivo": os.path.relpath(p, MAIN), "mtime_utc": _utc(m_arq),
                                      "fora_oe": fora_oe, "lidos": len(got), "novos": novos})
    for pat in ("**/*.jsonl", "**/*.json", "**/*.jsonl.gz"):
        for p in glob.glob(os.path.join(str(OE), pat), recursive=True):
            rel = os.path.relpath(p, OE)
            if rel.startswith("orquestrador") or rel.startswith("sintese"):
                continue
            got = ler_v4(p)
            if not got:
                continue
            bs = [bytes.fromhex(h) for h in got]
            novos = sum(1 for b in bs if not corpus.get(b, 0) & 2)  # como o v4: antes de atualizar
            for b in bs:
                corpus[b] = corpus.get(b, 0) | 2
            arquivos["v4"].append({"arquivo": rel, "lidos": len(got), "novos": novos})
    return corpus, mt, arquivos


def reconciliar(corpus, mt, arquivos):
    """Compara a recoleta com 694.386 / 62.457.317 B e 1.331.155 / 115.603.741 janelas."""
    retro = [b for b, m in corpus.items() if m & 1]
    v4 = [b for b, m in corpus.items() if m & 2]
    fim_retro = os.path.getmtime(RETRO_LOG)
    tempos = sorted(mt[b] for b in retro)
    antes = [b for b in retro if mt[b] <= fim_retro]
    # menor corte (mtime de arquivo) em que a recoleta alcança o total histórico
    cortes = sorted({os.path.getmtime(os.path.join(str(MAIN), a["arquivo"])) for a in arquivos["retro"]})
    alcance = next(((c, bisect_left(tempos, c + 1e-6)) for c in cortes
                    if bisect_left(tempos, c + 1e-6) >= ESPERADO["retro"]["conteudos"]), None)
    v4_hist = json.load(open(V4_RES, encoding="utf-8"))["por_arquivo"]
    v4_agora = {a["arquivo"]: {"lidos": a["lidos"], "novos": a["novos"]} for a in arquivos["v4"]}
    return {
        "retro": {"esperado": ESPERADO["retro"], "recoletado_agora": len(retro),
                  "bytes_agora": sum(map(len, retro)),
                  "fora_de_operador_ensinado": sum(1 for b in retro if corpus[b] & 4),
                  "bytes_fora_de_operador_ensinado": sum(len(b) for b in retro if corpus[b] & 4),
                  "mtime_max_arquivos_fora_de_oe": max(a["mtime_utc"] for a in arquivos["retro"] if a["fora_oe"]),
                  "fim_da_retro_utc (mtime do log)": _utc(fim_retro),
                  "com_mtime_ate_o_fim_da_retro": len(antes), "bytes_ate_o_fim_da_retro": sum(map(len, antes)),
                  "menor_corte_que_alcanca_694386": None if alcance is None else
                  {"corte_utc": _utc(alcance[0]), "conteudos": alcance[1]},
                  "arquivos_com_hex": len(arquivos["retro"])},
        "v4": {"esperado": ESPERADO["v4"], "recoletado_agora": len(v4),
               "janelas_agora": sum(max(0, len(b) - 31) for b in v4),
               "por_arquivo_identico_ao_v4_resultado": v4_agora == v4_hist,
               "arquivos_divergentes": [{"arquivo": k, "agora": v4_agora.get(k), "v4": v4_hist.get(k)}
                                        for k in sorted(set(v4_agora) | set(v4_hist))
                                        if v4_agora.get(k) != v4_hist.get(k)][:30]},
        "uniao": {"conteudos": len(corpus), "so_retro": sum(1 for m in corpus.values() if m & 3 == 1),
                  "so_v4": sum(1 for m in corpus.values() if m & 3 == 2),
                  "ambos": sum(1 for m in corpus.values() if m & 3 == 3),
                  "bytes": sum(map(len, corpus))},
    }


# ------------------------------------------------------------------ visões e inspeção
ASCII_RUN = re.compile(rb"[\t\n\r\x20-\x7e]{48,}")          # cópia fiel de audit_recovered_semantic
BASE64_NESTED = re.compile(rb"U2FsdGVk[A-Za-z0-9+/\r\n]*={0,2}")


def utf16(data, ordem, alinh):
    """Cada code unit UTF-16 (LE/BE, a partir de `alinh`) vira um byte: o valor se ≤ 0xFF (latin-1),
    senão 0x00. É decode(utf-16, errors='surrogatepass') unidade a unidade + encode(latin-1) com
    substituição explícita por 0x00, que não é imprimível nem pertence a hex/base58/base64."""
    fim = len(data) - ((len(data) - alinh) % 2)
    if fim - alinh < 2:
        return b""
    u = np.frombuffer(data[alinh:fim], dtype="<u2" if ordem == "le" else ">u2")
    return np.where(u <= 0xFF, u, 0).astype(np.uint8).tobytes()


def visoes(data):
    """(nome, bytes, início, passo): offset no conteúdo = início + passo × offset na visão."""
    yield "cp273-inverse", cp273_inverse_view(data), 0, 1  # desfaz ASCII.decode(cp273).encode(latin-1)
    yield "cp273", data.decode("cp273").encode("latin-1", errors="replace"), 0, 1  # como o script auditado
    for ordem in ("le", "be"):
        for a in (0, 1):
            yield f"utf-16-{ordem}@{a}", utf16(data, ordem, a), a, 2


def inspecionar(v):
    """audit_recovered_semantic.inspect() + subcausas de G.semantic + cabeçalho em qualquer offset."""
    reasons = []
    if G.semantic(v):
        t = v.decode("latin-1")
        reasons.append("semantic_whole")
        reasons += [f"sem:{n}" for n, ok in (
            ("nested", G.nested_blob(v)), ("printable", G.printable(v) >= 0.85),
            ("ebcdic", G.ebcdic_sig(v) >= 0.75), ("wif", bool(G.wif_candidates(t))),
            ("hex64", bool(G.hex64_candidates(t)))) if ok]
    if G.nested_blob(v):
        reasons.append("nested_prefix")
    runs = [(m.start(), len(m[0])) for m in ASCII_RUN.finditer(v)]
    if runs:
        reasons.append("ascii_run_ge48")
    nested = []
    off = v.find(b"Salted__")
    while off >= 0:
        if len(v) - off >= 32:
            nested.append((off, "raw"))
        off = v.find(b"Salted__", off + 1)
    for m in BASE64_NESTED.finditer(v):
        try:
            dec = base64.b64decode(re.sub(rb"[\r\n]", b"", m[0]), validate=True)
        except ValueError:
            continue
        if dec.startswith(b"Salted__") and len(dec) >= 32:
            nested.append((m.start(), "base64"))
    if nested:
        reasons.append("nested_any_offset")
    if b"Salted__" in v or b"U2FsdGVk" in v:
        reasons.append("header_any")
    return reasons, runs, nested


def _cobertura(a, b, runs):
    """Fração de [a, b) coberta pelos trechos (início, tamanho) da visão original."""
    return sum(max(0, min(b, s + n) - max(a, s)) for s, n in runs) / max(1, b - a)


def novos_motivos(reasons, runs_conteudo, orig_reasons, orig_runs):
    """Motivo 'novo' = não explicado pela visão original. ASCII: a região do trecho no conteúdo não
    está coberta em ≥ 50 % por trechos ASCII ≥ 48 B da original (UTF-16 e o segmento EBCDIC da 3.2
    passam; texto já legível na original não).
    Cabeçalho/blob aninhado numa visão transcodificada é sempre novo (não ocorre por acaso)."""
    novos = []
    for r in reasons:
        if r == "semantic_whole":
            continue
        if r == "ascii_run_ge48":
            if any(_cobertura(a, b, orig_runs) < 0.5 for a, b in runs_conteudo):
                novos.append(r)
        elif r in ("nested_prefix", "nested_any_offset", "header_any") or r not in orig_reasons:
            novos.append(r)
    return novos


def conferir(sec):
    """(hit|None, válido). G.fast_priv_scan (coincurve; h160 das duas formas × dois alvos) e
    confirmação por G.priv_hit (O.check_privkey, python-ecdsa)."""
    if not 0 < int.from_bytes(sec, "big") < ORDER:
        return None, False
    if not G.fast_priv_scan(sec):
        return None, True
    return {"confirmado_G.priv_hit": G.priv_hit(sec)}, True


def processar(data):
    """Todas as visões de um conteúdo; devolve motivos, tentativas de chave e hits."""
    orig_reasons, orig_runs, _ = inspecionar(data)
    res = {"orig": orig_reasons, "visoes": {}, "tent": Counter(), "validos": 0, "hits": []}
    for nome, v, ini, passo in [("original", data, 0, 1), *visoes(data)]:
        for kind, off, sec in decoded_candidates(v):  # hex64 em todo offset de nibble + WIF c/ checksum
            res["tent"][f"{nome}:{kind}"] += 1
            hit, valido = conferir(sec)
            res["validos"] += valido
            if hit:
                res["hits"].append({"visao": nome, "formato": kind, "offset": ini + passo * off,
                                    "privkey": sec.hex(), **hit})
        if nome == "original":
            continue  # ponytail: raw32/semântica da original já cobertas em §3.7/§3.11
        reasons, runs, nested = inspecionar(v)
        if not reasons:
            continue
        runs_c = [(ini + passo * a, ini + passo * (a + n)) for a, n in runs]
        res["visoes"][nome] = {
            "reasons": reasons, "novos": novos_motivos(reasons, runs_c, orig_reasons, orig_runs),
            "ascii_runs": [{"offset": ini + passo * a, "length": n,
                            "texto": v[a:a + n][:160].decode("latin-1")} for a, n in runs],
            "nested": [{"offset": ini + passo * o, "kind": k} for o, k in nested]}
    return res


ORIGEM = {1: "retro", 2: "v4", 3: "ambos"}
ART_DIRETA = "artefato: sem:ebcdic na cp273 direta mede as minúsculas ASCII da própria original"
ART_INVERSA = "artefato: sem:ebcdic na cp273 inversa de conteúdo já legível na original"


def triar(visoes_, orig_reasons):
    """Classe do candidato. (1) Na cp273 direta, byte ≥ 0x80 da visão ∈ imagem de a–z ⇔ byte da
    original ∈ a–z (provado nos 256 bytes em controle_regra_ebcdic): a assinatura é propriedade
    visível da original. (2) Na inversa, só conta como artefato se a original já é texto legível."""
    novos = {(n, r) for n, vi in visoes_.items() for r in vi["novos"]}
    if all((n, r) == ("cp273", "sem:ebcdic") for n, r in novos):
        return ART_DIRETA
    if orig_reasons and all(n.startswith("cp273") and r == "sem:ebcdic" for n, r in novos):
        return ART_INVERSA
    return "a examinar"


def trabalhar(lote):
    agg = {"n": 0, "bytes": 0, "motivos": Counter(), "novos": Counter(), "tent": Counter(),
           "validos": 0, "hits": [], "candidatos": [], "artefatos": 0, "digest": {1: 0, 2: 0}}
    for data, mask in lote:
        dg = hashlib.sha256(data).digest()
        for bit in (1, 2):
            if mask & bit:
                agg["digest"][bit] = (agg["digest"][bit] + int.from_bytes(dg, "big")) % (1 << 256)
        r = processar(data)
        agg["n"] += 1
        agg["bytes"] += len(data)
        agg["tent"].update(r["tent"])
        agg["validos"] += r["validos"]
        rec = {"sha256": dg.hex(), "origem": ORIGEM[mask & 3], "len": len(data)}
        for h in r["hits"]:
            agg["hits"].append({**rec, "hex": data.hex(), **h})
        for nome, vi in r["visoes"].items():
            agg["motivos"].update(f"{nome}:{x}" for x in vi["reasons"])
            agg["novos"].update(f"{nome}:{x}" for x in vi["novos"])
        if any(vi["novos"] for vi in r["visoes"].values()):
            agg["candidatos"].append({**rec, "classe": "CANDIDATO (triagem, não solução)",
                                      "triagem": triar(r["visoes"], r["orig"]), "hex": data.hex(), "orig_reasons": r["orig"], "visoes": r["visoes"]})
        elif r["visoes"]:
            agg["artefatos"] += 1  # só motivos já explicados pela visão original
    return agg


# ------------------------------------------------------------------ controles
CODIFICA = {  # texto -> bytes cuja visão devolve o texto
    "cp273-inverse": lambda t: t.decode("cp273").encode("latin-1"),  # o que o autor fez na fase 3.2
    "cp273": lambda t: t.decode("latin-1").encode("cp273"),
    "utf-16-le": lambda t: t.decode("latin-1").encode("utf-16-le"),
    "utf-16-be": lambda t: t.decode("latin-1").encode("utf-16-be"),
}


def _visao_de(familia, prefixo):
    return familia if familia.startswith("cp273") else f"{familia}@{len(prefixo) % 2}"


def _plantar(h160s):
    G.TARGET_H160S = G.TARGET_H160S + h160s
    G.O.TARGET_H160S = G.O.TARGET_H160S + h160s


def _desplantar(h160s):
    G.TARGET_H160S = tuple(h for h in G.TARGET_H160S if h not in h160s)
    G.O.TARGET_H160S = tuple(h for h in G.O.TARGET_H160S if h not in h160s)


def controle_chaves():
    """Chave sintética em hex64/WIF, codificada em cada visão, num plaintext falso."""
    seg = hashlib.sha256(b"enxame 2026-09-18 lacuna_cp273_utf16: chave sintetica").digest()
    pk = PublicKey.from_valid_secret(seg)
    h160s = tuple(G._h160_hex(pk.format(c)) for c in (False, True))
    textos = {"hex64": seg.hex().encode(),
              "wif-uncompressed": base58.b58encode_check(b"\x80" + seg),
              "wif-compressed": base58.b58encode_check(b"\x80" + seg + b"\x01")}
    casos = []
    for familia, cod in CODIFICA.items():
        for kind, texto in textos.items():
            for pre in (b"\xff" * 13, b"\xff" * 14):
                data = pre + cod(texto) + b"\xff" * 9
                vis = _visao_de(familia, pre)
                assert not processar(data)["hits"], "hit sem alvo plantado"
                _plantar(h160s)
                try:
                    hits = processar(data)["hits"]
                finally:
                    _desplantar(h160s)
                esperado = [h for h in hits if (h["visao"], h["formato"], h["offset"]) == (vis, kind, len(pre))]
                assert esperado and all(h["privkey"] == seg.hex() and h["confirmado_G.priv_hit"] for h in hits), \
                    (familia, kind, len(pre), hits)
                casos.append({"visao": vis, "formato": kind, "offset": len(pre), "hits": len(hits)})
    assert G.TARGET_H160S == G.O.TARGET_H160S and len(G.TARGET_H160S) == 2
    return {"casos": casos, "n": len(casos), "privkey_sintetica_sha256_de": "enxame 2026-09-18 ...",
            "sem_alvo_plantado_hits": 0}


def controle_texto_e_aninhado():
    """Texto ASCII ≥ 48 B e blob openssl aninhado (cru e base64) codificados em cada visão."""
    msg = b"This is a synthetic instruction for a semantic audit; it is not a puzzle solution."
    for i in range(1000):  # sal que torna o blob cru codificável nas duas direções cp273
        salt = i.to_bytes(8, "big")
        key, iv = G.evp(b"public synthetic control", salt, SHA256)
        pad = 16 - len(msg) % 16
        cru = b"Salted__" + salt + AES.new(key, AES.MODE_CBC, iv).encrypt(msg + bytes([pad]) * pad)
        try:
            [cod(cru) for cod in CODIFICA.values()]
            break
        except UnicodeError:
            continue
    casos = []
    for familia, cod in CODIFICA.items():
        for rotulo, payload, motivo in (("ascii", msg, "ascii_run_ge48"),
                                        ("aninhado-base64", base64.b64encode(cru), "nested_any_offset"),
                                        ("aninhado-cru", cru, "nested_any_offset")):
            for pre in (b"\xff" * 19, b"\xff" * 20):
                data = pre + cod(payload) + b"\xff" * 21
                vis = _visao_de(familia, pre)
                vi = processar(data)["visoes"].get(vis, {})
                assert motivo in vi.get("novos", []), (familia, rotulo, len(pre), vi)
                offs = [x["offset"] for x in vi["ascii_runs" if rotulo == "ascii" else "nested"]]
                assert len(pre) in offs, (familia, rotulo, offs)
                casos.append({"visao": vis, "payload": rotulo, "offset": len(pre)})
    return {"casos": casos, "n": len(casos), "sal_usado": salt.hex()}


def controle_fase32():
    """O plaintext autêntico da 3.2 dispara a assinatura EBCDIC e, na visão cp273 inversa,
    devolve os 1.539 B do Beaufort como ASCII (offset 447), marcado como novo."""
    pt = (REPO / "_work" / "phase32_plaintext.bin").read_bytes()
    raw = base64.b64decode(G.PHASE32_B64)
    pw = G.shahex("jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple").encode()
    key, iv = G.evp(pw, raw[8:16], SHA256)
    assert pt == G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw[16:])) and len(pt) == 2422
    assert G.ebcdic_sig(pt) >= 0.75 and G.semantic(pt)
    vi = processar(pt)["visoes"]["cp273-inverse"]
    alvo = [x for x in vi["ascii_runs"] if x["offset"] <= 447 and x["offset"] + x["length"] >= 447 + 1539]
    assert alvo and "ascii_run_ge48" in vi["novos"], vi
    return {"sha256": hashlib.sha256(pt).hexdigest(), "ebcdic_sig": G.ebcdic_sig(pt),
            "cp273_inverse_run": {k: alvo[0][k] for k in ("offset", "length")},
            "texto_inicio": alvo[0]["texto"][:60], "novos": vi["novos"]}


def controle_utf16_codec():
    """A visão UTF-16 vetorizada é igual à do codec Python unidade a unidade (surrogatepass)."""
    rng = np.random.default_rng(18092026)
    n = 0
    for tam in (0, 1, 2, 3, 33, 80, 81, 1328):
        for _ in range(50):
            data = rng.integers(0, 256, tam, dtype=np.uint8).tobytes()
            data = data[: tam // 3] + "Ab\U0001F600z".encode("utf-16-le") + data[tam // 3:]
            for ordem in ("le", "be"):
                for a in (0, 1):
                    fim = len(data) - ((len(data) - a) % 2)
                    ref = bytes(ord(c) if ord(c) <= 0xFF else 0
                                for i in range(a, fim - 1, 2)
                                for c in data[i:i + 2].decode(f"utf-16-{ordem}", "surrogatepass"))
                    assert utf16(data, ordem, a) == ref, (tam, ordem, a)
                    n += 1
    return {"comparacoes": n}


def controle_regra_ebcdic():
    """Prova exaustiva da regra (1) de triar(): nos 256 bytes, a visão cp273 direta cai na imagem
    ≥ 0x80 de a–z (o conjunto de G.ebcdic_sig) exatamente quando o byte original é a–z."""
    az = set(b"abcdefghijklmnopqrstuvwxyz")
    for b in range(256):
        v = bytes([b]).decode("cp273").encode("latin-1", errors="replace")[0]
        if v >= 0x80:
            assert (v in G._EBCDIC_AZ) == (b in az), b
    assert triar({"cp273": {"novos": ["sem:ebcdic"]}}, []) == ART_DIRETA
    assert triar({"cp273-inverse": {"novos": ["sem:ebcdic"]}}, []) == "a examinar"
    assert triar({"utf-16-le@0": {"novos": ["ascii_run_ge48"]}}, ["sem:printable"]) == "a examinar"
    return {"bytes_verificados": 256, "imagem_az_total": len(G._EBCDIC_AZ),
            "imagem_az_ge_0x80": sum(v >= 0x80 for v in G._EBCDIC_AZ)}


def rodar_controles():
    kit = KIT_DIR / "gsmg_common.py"
    r = subprocess.run([sys.executable, "-B", str(kit)], cwd=REPO, capture_output=True, text=True, check=True)
    assert "gsmg_common OK" in r.stdout  # fase 2 com sha256hex('causality') e checkerboard 3.2.2
    return {"kit_selftest": r.stdout.strip()[:200], "chaves_plantadas": controle_chaves(),
            "texto_e_aninhado": controle_texto_e_aninhado(), "fase32": controle_fase32(),
            "utf16_vs_codec": controle_utf16_codec(), "regra_ebcdic": controle_regra_ebcdic(), "passou": True}


# ------------------------------------------------------------------ execução
def _sha_arquivo(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _grava(nome, valor):
    with open(OUT / nome, "w", encoding="utf-8") as f:
        json.dump(valor, f, ensure_ascii=False, indent=1)
        f.write("\n")


def _lotes(corpus, tam, limite):
    lote = []
    for i, item in enumerate(corpus.items()):
        if limite and i >= limite:
            break
        lote.append(item)
        if len(lote) == tam:
            yield lote
            lote = []
    if lote:
        yield lote


def varrer(corpus, workers, lote, limite):
    tot = {"n": 0, "bytes": 0, "motivos": Counter(), "novos": Counter(), "tent": Counter(),
           "validos": 0, "hits": [], "candidatos": 0, "artefatos": 0, "digest": {1: 0, 2: 0},
           "triagem": Counter()}
    t0 = time.monotonic()
    with open(OUT / "candidates.jsonl", "w", encoding="utf-8") as cand, Pool(workers) as pool:
        for i, agg in enumerate(pool.imap_unordered(trabalhar, _lotes(corpus, lote, limite)), 1):
            for k in ("n", "bytes", "validos", "artefatos"):
                tot[k] += agg[k]
            for k in ("motivos", "novos", "tent"):
                tot[k].update(agg[k])
            for bit in (1, 2):
                tot["digest"][bit] = (tot["digest"][bit] + agg["digest"][bit]) % (1 << 256)
            tot["hits"] += agg["hits"]
            tot["candidatos"] += len(agg["candidatos"])
            for c in agg["candidatos"]:
                tot["triagem"][f'{c["triagem"]} | {c["origem"]}'] += 1
                cand.write(json.dumps(c, ensure_ascii=False) + "\n")
            if i % 100 == 0:
                print(f"  {tot['n']:,} conteúdos  candidatos={tot['candidatos']}  hits={len(tot['hits'])}"
                      f"  {time.monotonic() - t0:.0f}s", flush=True)
    tot["segundos"] = round(time.monotonic() - t0, 1)
    return tot


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--lote", type=int, default=2000)
    ap.add_argument("--limite", type=int, default=0, help="só os N primeiros conteúdos (ensaio)")
    a = ap.parse_args()
    if not 1 <= a.workers <= 8:
        ap.error("no máximo 8 processos: outras frentes rodam em paralelo")
    OUT.mkdir(parents=True, exist_ok=True)
    fontes = [Path(__file__), KIT_DIR / "gsmg_common.py", REPO / "solver" / "oracles.py",
              ORACULO_DUPLO / "oracle.py", REPO / "solver/multiagente_2026_09_18/audit_recovered_semantic.py",
              REPO / "solver/operador_ensinado_2026_09_17/retro_dois_alvos.py",
              REPO / "solver/operador_ensinado_2026_09_17/v4_rodada_dois_alvos.py"]
    hashes = {str(p.relative_to(REPO)): _sha_arquivo(p) for p in fontes}
    t0 = time.monotonic()
    controles = rodar_controles()
    controles["hashes"] = hashes
    _grava("controls.json", controles)
    print("controles OK:", controles["chaves_plantadas"]["n"], "chaves,",
          controles["texto_e_aninhado"]["n"], "texto/aninhado; fase 3.2:", controles["fase32"]["cp273_inverse_run"],
          flush=True)
    corpus, mt, arquivos = recoletar()
    rec = reconciliar(corpus, mt, arquivos)
    del mt
    print(json.dumps(rec, ensure_ascii=False, indent=1), flush=True)
    tot = varrer(corpus, a.workers, a.lote, a.limite)
    completo = not a.limite and tot["n"] == len(corpus)
    for h in tot["hits"]:
        h["classe"] = "CANDIDATO: exige proof-certificate (AGENTS.md, regra 1)"
    summary = {
        "frente": "lacuna_cp273_utf16", "status": "completo" if completo else f"ensaio ({tot['n']} conteúdos)",
        "reconciliacao": rec,
        "cobertura": {"conteudos_varridos": tot["n"], "bytes_varridos": tot["bytes"],
                      "impressao_multiconjunto": {"retro": f"{tot['digest'][1]:064x}", "v4": f"{tot['digest'][2]:064x}",
                                                  "definicao": "Σ sha256(conteúdo) mod 2^256 por origem"},
                      "visoes": ["cp273-inverse", "cp273", "utf-16-le@0", "utf-16-le@1", "utf-16-be@0", "utf-16-be@1"],
                      "hex_wif_tambem_na_original": True},
        "tentativas_de_chave": dict(sorted(tot["tent"].items())), "escalares_validos": tot["validos"],
        "hits": tot["hits"], "motivos_por_visao": dict(sorted(tot["motivos"].items())),
        "motivos_novos_por_visao": dict(sorted(tot["novos"].items())),
        "conteudos_candidatos": tot["candidatos"], "triagem_dos_candidatos": dict(tot["triagem"]),
        "candidatos_a_examinar": sum(v for k, v in tot["triagem"].items() if k.startswith("a examinar")),
        "conteudos_so_com_motivos_da_original": tot["artefatos"],
        "arquivos_retro": arquivos["retro"], "arquivos_v4": arquivos["v4"],
        "segundos_varredura": tot["segundos"], "segundos_total": round(time.monotonic() - t0, 1),
        "workers": a.workers, "hashes": hashes, "fim_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "solucao_declarada": False,
    }
    _grava("summary.json", summary)
    print(json.dumps({k: summary[k] for k in ("status", "cobertura", "escalares_validos", "conteudos_candidatos",
                                              "conteudos_so_com_motivos_da_original", "segundos_total")},
                     ensure_ascii=False), flush=True)
    print("HITS:", len(tot["hits"]), "| motivos novos:", dict(tot["novos"]), flush=True)
    print("triagem:", json.dumps(dict(tot["triagem"]), ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
