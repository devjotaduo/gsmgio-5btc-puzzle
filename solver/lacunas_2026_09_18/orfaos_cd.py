# -*- coding: utf-8 -*-
"""Item 9 (lacunas 2026-09-18): camadas C e D do corpus órfão de %TEMP% contra 17ucy e em LE.

C: plaintexts das outras 15 cifras (11 com padding e 4 de fluxo) de premissa_cifra, que a frente orfaos_temp
   deixou de fora. Mesma varredura das camadas A+B (orfaos.trabalhar): raw32 BE/LE contra os dois alvos e
   scan.processar nas 7 visões (hex64/WIF, semântica, blob aninhado, ASCII ≥ 48 B).
D: as montagens do ataque montagem_ct (17/09). Cada sobrevivente guarda D_hex (os 5 blocos decifrados em ECB)
   e iv_hex; as 16 montagens saem só com XOR, como em montage_attack.py (montages_for, montage_plain). Na
   época as janelas foram vistas só em BE, contra a pubkey não comprimida de 1GSMG; aqui toda janela única
   de cada sobrevivente é conferida em BE e LE, nas duas formas de pubkey, contra os dois alvos.
   Reconciliação com montage_summary.json: 797.172 sobreviventes, 12.754.752 montagens e 339.511.437 janelas
   únicas; a montagem 'best' de cada sobrevivente é refeita byte a byte.
Uso: python orfaos_cd.py --camada C|D [--workers 10]
"""
import argparse, glob, hashlib, json, random, sys, time
from collections import Counter
from itertools import permutations
from multiprocessing import Pool
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "enxame_2026_09_18" / "orfaos_temp"))
import orfaos as O  # noqa: E402
from coincurve import PublicKey  # noqa: E402

G = O.G
OUT = REPO / "_work" / "lacunas_2026-09-18" / "orfaos_cd"
MONT = O.ORFAO / "montagem_ct"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ALVOS = {bytes.fromhex(h): a for h, a in zip(G.TARGET_H160S, G.O.PRIZE_ADDRS)}
REAIS = sorted(ALVOS.values())
CTS = {"S": G.BLOBS["SMALL"][1], "T": G.BLOBS["TAIL32"][1]}
BLOCOS = {k: [v[i:i + 16] for i in range(0, len(v), 16)] for k, v in CTS.items()}


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def _alvos_do_filho(_):
    return sorted(ALVOS.values()), list(G.TARGET_H160S)


def conferir_filhos(workers):
    with Pool(workers) as pool:
        vistos = pool.map(_alvos_do_filho, range(workers))
    assert all(v == (REAIS, list(G.TARGET_H160S)) for v in vistos) and len(REAIS) == 2, vistos
    return {"processos": workers, "alvos_vistos": REAIS}


# ------------------------------------------------------------------ camada C
def extrair_c():
    arqs = [(0, Path(p)) for p in sorted(glob.glob(str(O.ORFAO / "premissa_cifra" / "**" / "*.json*"), recursive=True))]
    corpus, origem, cif, invalidas = {}, {}, Counter(), 0
    for _, p in arqs:
        rel = str(p.relative_to(O.ORFAO))
        for n, linha in O._registros(p):
            linha = linha.strip()
            if not linha:
                continue
            try:
                o = json.loads(linha)
            except json.JSONDecodeError:
                invalidas += 1
                continue
            got = []
            O._hexes(o, got)
            for d, _k, v in got:
                if d.get("cipher") == "aes-256-cbc":
                    continue                     # camada A, já varrida pela frente orfaos_temp
                cif[d.get("cipher")] += 1
                b = bytes.fromhex(v)
                corpus[b] = 0
                origem.setdefault(b, {"arquivo": rel, "linha": n, **{c: d[c] for c in ("cipher", "blob", "kdf", "kind")
                                                                      if isinstance(d.get(c), str)}})
    return corpus, origem, {"arquivos": len(arqs), "manifesto_sha256": hashlib.sha256(
        json.dumps(O.manifesto(arqs), sort_keys=True).encode()).hexdigest(), "linhas_invalidas": invalidas,
        "campos": sum(cif.values()), "por_cifra": dict(cif), "conteudos": len(corpus),
        "janelas_BE_LE": 2 * sum(max(0, len(b) - 31) for b in corpus)}


def camada_c(workers):
    corpus, origem, ext = extrair_c()
    assert ext["campos"] == 330613, ext["campos"]
    ctl = {"alvos": O.controle_alvos(), "raw32_plantado_via_trabalhar": O.controle_raw32(),
           "filhos": conferir_filhos(workers)}
    itens = sorted(corpus.items(), key=lambda kv: hashlib.sha256(kv[0]).digest())
    tot = O.varrer(itens, origem, workers, 100, OUT / "candidatos_C.jsonl")
    assert tot["n"] == ext["conteudos"] and tot["raw32_janelas"] == ext["janelas_BE_LE"], (tot["n"], tot["raw32_janelas"])
    return {"camada": "C", "extracao": ext, "varredura": {k: (dict(v) if isinstance(v, Counter) else v)
                                                          for k, v in tot.items() if k != "digest"}}, ctl


# ------------------------------------------------------------------ camada D
def montagens(last, prev, nb=5):
    """Cópia de montage_attack.montages_for: prefixo = qualquer arranjo ordenado dos outros blocos."""
    resto = [i for i in range(nb) if i not in (last, prev)]
    return [list(pre) + [prev, last] for r in range(len(resto) + 1) for pre in permutations(resto, r)]


def montagem(D, C, iv, seq):
    out, ant = b"", iv
    for i in seq:
        out += bytes(a ^ b for a, b in zip(D[16 * i:16 * i + 16], ant))
        ant = C[i]
    return out


def unpad(p):
    n = p[-1]
    return p[:-n] if 1 <= n <= 16 and p.endswith(bytes([n]) * n) else None


def janelas(rec):
    D, iv, C = bytes.fromhex(rec["D_hex"]), bytes.fromhex(rec["iv_hex"]), BLOCOS[rec["ct"]]
    vistas, best_ok, nm = set(), False, 0
    for seq in montagens(rec["last"], rec["prev"]):
        p = unpad(montagem(D, C, iv, seq))
        nm += 1
        if seq == rec["best"]["seq"]:
            best_ok = p.hex() == rec["best"]["plain_hex"]
        vistas.update(p[j:j + 32] for j in range(len(p) - 31))
    return vistas, nm, best_ok


def conferir(w):
    """[(ordem, comprimida, endereço)] para a janela em BE e invertida (LE)."""
    out = []
    for ordem, k in (("be", w), ("le", w[::-1])):
        if not 0 < int.from_bytes(k, "big") < N:
            continue
        pk = PublicKey.from_valid_secret(k)
        for comp in (False, True):
            a = ALVOS.get(h160(pk.format(comp)))
            if a:
                out.append((ordem, comp, a))
    return out


def trabalhar_d(linhas):
    agg = {"sobreviventes": 0, "montagens": 0, "janelas_unicas": 0, "best_ok": 0, "hits": [], "alvos": sorted(ALVOS.values())}
    for linha in linhas:
        rec = json.loads(linha)
        vistas, nm, bok = janelas(rec)
        agg["sobreviventes"] += 1
        agg["montagens"] += nm
        agg["janelas_unicas"] += len(vistas)
        agg["best_ok"] += bok
        for w in vistas:
            for ordem, comp, a in conferir(w):
                agg["hits"].append({"alvo": a, "ordem": ordem, "comprimida": comp, "janela": w.hex(),
                                    "form_sha": rec["form_sha"], "salt": rec["salt"], "kdf": rec["kdf"], "ct": rec["ct"]})
    return agg


def controles_d():
    """No próprio processo, pelas mesmas funções da varredura: plantio BE e LE numa janela real, sem hit antes;
    amostra de janelas com python-ecdsa (O.priv_to_addresses) contra coincurve."""
    linha = open(sorted(MONT.glob("survivors_*.jsonl"))[0], encoding="utf-8").readline()
    vistas = sorted(janelas(json.loads(linha))[0])
    assert not trabalhar_d([linha])["hits"], "hit sem alvo plantado"
    w_be, w_le = vistas[len(vistas) // 3], vistas[2 * len(vistas) // 3]
    plantas = {h160(PublicKey.from_valid_secret(w_be).format(True)): "PLANTADO_BE",
               h160(PublicKey.from_valid_secret(w_le[::-1]).format(False)): "PLANTADO_LE"}
    ALVOS.update(plantas)
    try:
        hits = trabalhar_d([linha])["hits"]
    finally:
        for h in plantas:
            del ALVOS[h]
    achados = {(x["alvo"], x["ordem"], x["comprimida"], x["janela"]) for x in hits}
    assert achados == {("PLANTADO_BE", "be", True, w_be.hex()), ("PLANTADO_LE", "le", False, w_le.hex())}, achados
    rnd, div = random.Random(20260918), 0
    for w in rnd.sample(vistas, min(200, len(vistas))):
        if 0 < int.from_bytes(w, "big") < N:
            _au, _ac, hu, hc = G.O.priv_to_addresses(w)
            pk = PublicKey.from_valid_secret(w)
            div += (h160(pk.format(False)).hex(), h160(pk.format(True)).hex()) != (hu, hc)
    assert div == 0 and sorted(ALVOS.values()) == REAIS
    return {"plantio_be_comprimida_e_le_nao_comprimida": sorted(achados), "janelas_do_sobrevivente": len(vistas),
            "ecdsa_amostra": 200, "ecdsa_divergencias": div}


def camada_d(workers, lote=400):
    esperado = json.load(open(MONT / "montage_summary.json", encoding="utf-8"))
    ctl = {"alvos": O.controle_alvos(), "plantio_e_ecdsa": controles_d(), "filhos": conferir_filhos(workers)}
    partes = OUT / "partes_D"
    partes.mkdir(parents=True, exist_ok=True)
    tot = Counter()
    hits, arquivos = [], {}
    t0 = time.monotonic()
    with Pool(workers) as pool:
        for arq in sorted(MONT.glob("survivors_*.jsonl")):
            cp = partes / (arq.stem + ".json")
            if cp.exists():                      # checkpoint por arquivo
                r = json.load(open(cp, encoding="utf-8"))
            else:
                # split("\n"): 'form' foi gravado com ensure_ascii=False e pode ter \x85/U+2028 (o bug do item 7)
                linhas = [x for x in open(arq, encoding="utf-8").read().split("\n") if x]
                r = {"sha256": hashlib.sha256(arq.read_bytes()).hexdigest(), "sobreviventes": 0, "montagens": 0,
                     "janelas_unicas": 0, "best_ok": 0, "hits": []}
                for agg in pool.imap_unordered(trabalhar_d, [linhas[i:i + lote] for i in range(0, len(linhas), lote)]):
                    assert agg["alvos"] == REAIS, agg["alvos"]
                    for k in ("sobreviventes", "montagens", "janelas_unicas", "best_ok"):
                        r[k] += agg[k]
                    r["hits"] += agg["hits"]
                json.dump(r, open(cp, "w", encoding="utf-8"), indent=1)
            arquivos[arq.name] = {k: r[k] for k in ("sha256", "sobreviventes", "janelas_unicas")}
            for k in ("sobreviventes", "montagens", "janelas_unicas", "best_ok"):
                tot[k] += r[k]
            hits += r["hits"]
            print(f"  {arq.name}: {r['sobreviventes']:,} sobreviventes, {r['janelas_unicas']:,} janelas, "
                  f"hits={len(r['hits'])}  total {tot['janelas_unicas']:,}  {time.monotonic() - t0:.0f}s", flush=True)
    rec = {"sobreviventes": (tot["sobreviventes"], esperado["n_pad_survivors"]),
           "montagens": (tot["montagens"], esperado["n_montages_decrypted"]),
           "janelas_unicas": (tot["janelas_unicas"], esperado["n_priv_windows"]),
           "best_refeito": (tot["best_ok"], tot["sobreviventes"])}
    assert all(a == b for a, b in rec.values()), rec
    return {"camada": "D", "reconciliacao_montage_summary": rec, "verificacoes_EC": 2 * tot["janelas_unicas"],
            "verificacoes_h160": 4 * tot["janelas_unicas"], "hits": hits, "por_arquivo": arquivos,
            "segundos": round(time.monotonic() - t0, 1)}, ctl


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--camada", choices=("C", "D"), required=True)
    ap.add_argument("--workers", type=int, default=10)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    res, ctl = (camada_c if a.camada == "C" else camada_d)(a.workers)
    res |= {"alvos": dict(zip(G.O.PRIZE_ADDRS, G.TARGET_H160S)), "workers": a.workers,
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "orfaos_sha256": hashlib.sha256(Path(O.__file__).read_bytes()).hexdigest()}
    json.dump(res, open(OUT / f"summary_{a.camada}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(ctl, open(OUT / f"controls_{a.camada}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k not in ("por_arquivo",)}, ensure_ascii=False, indent=1)[:4000])


if __name__ == "__main__":
    main()
