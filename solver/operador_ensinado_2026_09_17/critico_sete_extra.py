# -*- coding: utf-8 -*-
r"""
CRITICO FINAL "sete_entrelacados" — etapas de complemento (reusa critico_sete_final.py).

 cosmic : o log do atacante guarda so 64 B de cada plaintext COSMIC (143.225/143.225 truncados).
          Regenero as 4 celulas COSMIC (raw/sha256hex x SHA256/MD5) das 1.904 tarefas, filtro o
          padding pelo ULTIMO bloco (CBC: P_n = D(C_n) xor C_{n-1}), decifro inteiro so o que passa,
          confiro pt_sha contra o log (reproducao byte a byte de 1/3 das AES dele) e passo o oraculo
          completo no plaintext INTEIRO (1.297 janelas x 2 ordens x DUAS chaves, hex64/WIF, Salted__,
          EBCDIC, ASCII>=85%).
 extra  : lacunas declaradas pelo atacante, as de maior prior:
          (e) caixa MAIUSCULA do material inteiro (o puzzle usou THEMATRIXHASYOU / GSMGIO5BTC... em
              maiusculas) nos 28 conjuntos x k 1..4 x {preencher,truncar} x rev {0,127};
          (a) as 126 mascaras intermediarias de inversao em S0 para k in {3,4} (ele so fez k 1..2).
          Braco privkey (sha256(material), DUAS chaves) em todo material; oraculo completo inline.
Uso: python critico_sete_extra.py --stage cosmic|extra [--workers 18]
"""
from __future__ import annotations
import argparse, gzip, hashlib, json, os, time
from multiprocessing import Pool
from Crypto.Cipher import AES
import critico_sete_final as C

G = C.G
SALT_C, CT_C = G.BLOBS["COSMIC"]
LAST, PREV = CT_C[-16:], CT_C[-32:-16]


def cosmic_pt(pwb, algo):
    """Plaintext COSMIC com padding valido (ou None), filtrando pelo ultimo bloco."""
    k, iv = C.evp(pwb, SALT_C, algo)
    last = bytes(a ^ b for a, b in zip(AES.new(k, AES.MODE_ECB).decrypt(LAST), PREV))
    j = last[-1]
    if not (1 <= j <= 16 and last.endswith(bytes([j]) * j)):
        return None
    return C.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(CT_C))


def _cosmic(t):
    rot = C.rotulo(*t)
    n_aes = 0
    shas = set()
    hits = []
    pr_max = ebc_max = 0.0
    dump = []
    for m in C.materiais(C.CONJ[t[0]], *t[1:]):
        mb = m.encode("utf-8", "surrogatepass")
        for forma, pwb in (("raw", mb), ("sha256hex", hashlib.sha256(mb).hexdigest().encode())):
            for algo in ("sha256", "md5"):
                n_aes += 1
                p = cosmic_pt(pwb, algo)
                if p is None:
                    continue
                shas.add((algo, forma, hashlib.sha256(p).hexdigest()[:16]))
                pr_max = max(pr_max, G.printable(p))
                ebc_max = max(ebc_max, G.ebcdic_sig(p))
                dump.append(p)
                a = C.oraculo(p, janelas=False)
                if a:
                    hits.append({"tarefa": rot, "kdf": algo, "forma": forma, "material": m,
                                 "achados": [str(x) for x in a], "hex": p.hex()})
    return rot, n_aes, shas, hits, pr_max, ebc_max, dump


def _extra(t):
    """t = (partes7_nome, k, pre, rev, caixa) com caixa in {'as','lo','up'}."""
    nome, k, pre, rev, caixa = t
    res = {"n_pw": 0, "n_aes": 0, "pads": 0, "pads_cosmic": 0}
    hits = []
    regs = []
    dump = []
    for m in C.materiais(C.CONJ[nome], k, pre, rev, caixa == "lo"):
        if caixa == "up":
            m = m.upper()
        res["n_pw"] += 1
        mb = m.encode("utf-8", "surrogatepass")
        d = hashlib.sha256(mb).digest()
        r = C.priv_ok(d)
        if r:
            hits.append({"tipo": "PRIVKEY", "chave": r, "material": m})
        for forma, pwb in (("raw", mb), ("sha256hex", d.hex().encode())):
            res["n_aes"] += 6
            for bn, algo, p in C.celulas(pwb):
                res["pads"] += 1
                res["pads_cosmic"] += bn == "COSMIC"
                a = C.oraculo(p, janelas=bn != "COSMIC")
                if bn == "COSMIC":
                    dump.append(p)
                regs.append({"blob": bn, "kdf": algo, "forma": forma, "tarefa": f"{nome}/k{k}/{pre}/rev{rev}/{caixa}",
                             "printable": round(G.printable(p), 3),
                             "hex": p.hex() if (bn != "COSMIC" or a) else p[:64].hex()})
                if a:
                    hits.append({"tipo": "PLAINTEXT", "blob": bn, "kdf": algo, "forma": forma,
                                 "material": m, "achados": [str(x) for x in a], "hex": p.hex()})
    return res, hits, regs, dump


def autoteste():
    # o filtro de ultimo bloco concorda com a decifracao inteira (1.000 senhas aleatorias)
    for i in range(1000):
        pw = hashlib.sha256(str(i).encode()).hexdigest().encode()
        k, iv = C.evp(pw, SALT_C, "sha256")
        assert cosmic_pt(pw, "sha256") == C.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(CT_C))
    print("autoteste extra OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", required=True, choices=["cosmic", "extra"])
    ap.add_argument("--workers", type=int, default=18)
    a = ap.parse_args()
    C.autoteste()
    autoteste()
    print("CONTROLE POSITIVO:", C.controle_positivo(), flush=True)
    t0 = time.time()
    R = {}
    hits = []

    if a.stage == "cosmic":
        ag = {}
        with gzip.open(os.path.join(C.DIR_AG, "paddings.jsonl.gz"), "rt", encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r["blob"] == "COSMIC":
                    ag.setdefault(r["tarefa"], set()).add((r["kdf"].split(".")[-1].lower(), r["form"], r["pt_sha"]))
        tl = C.tarefas_agente()
        agg = {"n_aes": 0, "pads": 0, "tarefas_divergentes": [], "pr_max": 0.0, "ebc_max": 0.0}
        with open(os.path.join(C.OUT, "cosmic_full_agente.bin"), "wb") as fb, Pool(a.workers) as pool:
            for i, (rot, n, shas, hh, pr, eb, dump) in enumerate(pool.imap_unordered(_cosmic, tl, chunksize=2)):
                for p in dump:
                    fb.write(len(p).to_bytes(4, "little") + p)
                agg["n_aes"] += n
                agg["pads"] += len(shas)
                agg["pr_max"] = max(agg["pr_max"], pr)
                agg["ebc_max"] = max(agg["ebc_max"], eb)
                if shas != ag.get(rot, set()):
                    agg["tarefas_divergentes"].append(rot)
                hits += hh
                for x in hh:
                    print("!!! ACHADO cosmic:", json.dumps(x)[:300], flush=True)
                if (i + 1) % 200 == 0:
                    print(f"  cosmic {i+1}/{len(tl)} AES={agg['n_aes']:,} pads={agg['pads']:,} "
                          f"{time.time()-t0:.0f}s", flush=True)
        R["cosmic"] = {**agg, "pads_agente": sum(len(v) for v in ag.values()),
                       "janelas_priv_via_go": 2 * 1297 * agg["pads"], "z_1_255": round(C.z(agg["pads"], agg["n_aes"]), 3),
                       "n_achados": len(hits), "seg": round(time.time() - t0, 1)}
        print(json.dumps(R["cosmic"], indent=1), flush=True)

    if a.stage == "extra":
        tl = [(n, k, pr, rm, "up") for n in C.CONJ for k in (1, 2, 3, 4) for pr in (True, False) for rm in (0, 127)]
        tl += [("S0_atlas", k, pr, rm, cx) for k in (3, 4) for pr in (True, False)
               for rm in range(1, 127) for cx in ("as", "lo")]
        agg = {"n_pw": 0, "n_aes": 0, "pads": 0, "pads_cosmic": 0}
        with gzip.open(os.path.join(C.OUT, "pads_extra.jsonl.gz"), "wt", encoding="utf-8") as f, \
                open(os.path.join(C.OUT, "cosmic_full_extra.bin"), "wb") as fb, Pool(a.workers) as pool:
            for i, (r, hh, regs, dump) in enumerate(pool.imap_unordered(_extra, tl, chunksize=2)):
                for p in dump:
                    fb.write(len(p).to_bytes(4, "little") + p)
                for k2 in agg:
                    agg[k2] += r[k2]
                for g in regs:
                    f.write(json.dumps(g) + "\n")
                hits += hh
                for x in hh:
                    print("!!! ACHADO extra:", json.dumps(x)[:300], flush=True)
                if (i + 1) % 200 == 0:
                    print(f"  extra {i+1}/{len(tl)} AES={agg['n_aes']:,} pads={agg['pads']:,} "
                          f"{time.time()-t0:.0f}s", flush=True)
        R["extra"] = {**agg, "tarefas": len(tl), "privkeys_2_chaves": agg["n_pw"],
                      "janelas_priv_cosmic_via_go": 2 * 1297 * agg["pads_cosmic"],
                      "z_1_255": round(C.z(agg["pads"], agg["n_aes"]), 3), "n_achados": len(hits),
                      "seg": round(time.time() - t0, 1)}
        print(json.dumps(R["extra"], indent=1), flush=True)

    R["hits_total"] = len(hits)
    json.dump(R, open(os.path.join(C.OUT, f"resumo_{a.stage}.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    with open(os.path.join(C.OUT, f"hits_{a.stage}.jsonl"), "w", encoding="utf-8") as f:
        for h in hits:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")
    print("FIM", a.stage, "hits:", len(hits), f"{time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
