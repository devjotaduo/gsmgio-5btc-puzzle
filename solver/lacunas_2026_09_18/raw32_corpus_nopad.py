# -*- coding: utf-8 -*-
"""A1: raw32 sem unpad do corpus de 1,27 M formas em SMALL/TAIL32 (2026-09-18).

Último aberto barato da §3.14. A frente `cbc_sem_padding` do enxame fechou duas metades:
  - parte A: os 7 operandos (10.080 senhas) em SMALL/TAIL32 sem unpad, raw32 BE/LE — 3,95 M checagens;
  - parte B: COSMIC por bloco sobre o corpus de 1.272.149 formas.
Ficou de fora o cruzamento: o CORPUS inteiro contra SMALL/TAIL32 sem exigir PKCS7, varrendo os 80 B do
plaintext como janelas raw32 nas duas ordens de byte contra os dois alvos. É isto.

Reusa `_a_um` de cbc_sem_padding/scan.py sem editá-lo: a mesma função que rodou na parte A, que decifra
sem unpad, chama scan_raw32 (BE/LE, h160 comprimido e não, confirmação por G.priv_hit) e semantic_extra,
e registra todo padding válido com o plaintext em hex (regra 5).

Custo: 1.272.149 formas × 2 blobs × 2 KDF = 5.088.596 decifrações; 49 janelas × 2 orientações cada,
≈ 498,7 M checagens de chave. Roda em partes para caber no teto de 10 min por chamada, com checkpoint.
Uso: python raw32_corpus_nopad.py [--workers 10] [--partes 12]
"""
import argparse, hashlib, json, pickle, sys, time
from pathlib import Path
from multiprocessing import Pool

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI.parent / "enxame_2026_09_18" / "cbc_sem_padding"))
import scan as S  # noqa: E402  (_a_um, make_forms, KDFS, G)

G = S.G
REPO = AQUI.parents[1]
CORPUS = REPO / "_work" / "enxame_2026-09-18" / "cbc_sem_padding" / "corpus.pkl"
OUT = REPO / "_work" / "lacunas_2026-09-18" / "raw32_corpus_nopad"
TAXA = sum(256.0 ** -j for j in range(1, 17))          # ≈ 1/255, ENDGAME §3.9


def sha_arquivo(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def controles():
    """Os do próprio scan.py que cobrem este caminho, mais o alvo plantado por `_a_um`."""
    c = {"alvos": list(G.TARGET_H160S)}
    assert len(G.TARGET_H160S) == 2, G.TARGET_H160S
    # planta a chave de uma janela real de um plaintext sem unpad e exige que _a_um a ache
    pw = b"controle-raw32-corpus"
    salt, ct = G.BLOBS["SMALL"]
    k, iv = G.evp(pw, salt, S._SHA256)      # o kit usa o módulo Hash do pycryptodome (.new)
    from Crypto.Cipher import AES
    P = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
    assert S._a_um(pw)["candidatos"] == [], "hit sem alvo plantado"
    from coincurve import PublicKey
    sec = P[17:49]
    h = G._h160_hex(PublicKey.from_valid_secret(sec).format(True))
    antes = G.TARGET_H160S
    G.TARGET_H160S = G.O.TARGET_H160S = tuple(antes) + (h,)
    try:
        got = S._a_um(pw)["candidatos"]
    finally:
        G.TARGET_H160S = G.O.TARGET_H160S = antes
    achou = [r for c_ in got for r in c_.get("raw32", []) if r["off"] == 17 and r["orient"] == "BE"]
    assert achou, ("controle plantado falhou", got)
    assert G.TARGET_H160S == antes and len(G.TARGET_H160S) == 2
    c["raw32_plantado_em_plaintext_sem_unpad"] = {"offset": 17, "orient": "BE", "achado": True}
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--partes", type=int, default=12)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    partes = OUT / "partes"
    partes.mkdir(exist_ok=True)

    d = pickle.load(open(CORPUS, "rb"))
    formas = S.make_forms(d["pws"])
    assert len(formas) == 1272149, len(formas)
    ctl = controles()
    t0 = time.monotonic()
    tot = {"aes": 0, "paddings": 0, "candidatos": [], "pad_recs": 0, "formas": 0}
    with Pool(a.workers) as pool:
        for k in range(a.partes):
            cp = partes / f"parte{k}de{a.partes}.json"
            if cp.exists():
                r = json.load(open(cp, encoding="utf-8"))
            else:
                fatia = formas[k::a.partes]          # classes determinísticas que particionam
                r = {"formas": len(fatia), "paddings": 0, "candidatos": [], "pad_recs": 0}
                with open(OUT / f"paddings_parte{k}.jsonl", "w", encoding="utf-8") as pf:
                    for x in pool.imap_unordered(S._a_um, fatia, chunksize=64):
                        r["paddings"] += x["paddings"]
                        r["candidatos"] += x["candidatos"]
                        for rec in x.get("pad_rec", []):
                            pf.write(json.dumps(rec, ensure_ascii=False) + "\n")
                            r["pad_recs"] += 1
                json.dump(r, open(cp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            for key in ("formas", "paddings", "pad_recs"):
                tot[key] += r[key]
            tot["candidatos"] += r["candidatos"]
            tot["aes"] += r["formas"] * 2 * len(S.KDFS)
            print(f"  parte {k+1}/{a.partes}: {tot['formas']:,}/{len(formas):,} formas  "
                  f"aes={tot['aes']:,}  paddings={tot['paddings']}  "
                  f"candidatos={len(tot['candidatos'])}  {time.monotonic()-t0:.0f}s", flush=True)
    assert tot["formas"] == len(formas), (tot["formas"], len(formas))
    esperado = tot["aes"] * TAXA
    z = (tot["paddings"] - esperado) / (esperado * (1 - TAXA)) ** 0.5 if esperado else 0.0
    res = {"item": "A1: raw32 sem unpad do corpus em SMALL/TAIL32",
           "corpus_pkl_sha256": sha_arquivo(CORPUS), "bases": len(d["pws"]), "formas": len(formas),
           "blobs": ["SMALL", "TAIL32"], "kdf": ["sha256", "md5"], "aes": tot["aes"],
           "raw32_janelas": tot["aes"] * (80 - 32 + 1) * 2,
           "paddings": tot["paddings"], "paddings_esperados": round(esperado, 2), "z_padding": round(z, 2),
           "candidatos": tot["candidatos"], "controles": ctl,
           "alvos": dict(zip(G.O.PRIZE_ADDRS, G.TARGET_H160S)),
           "scan_sha256": sha_arquivo(S.__file__), "script_sha256": sha_arquivo(__file__),
           "kit": {"sha256": sha_arquivo(Path(S.KIT) / "gsmg_common.py")},
           "segundos": round(time.monotonic() - t0, 1)}
    json.dump(res, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "candidatos"}, ensure_ascii=False, indent=1))
    print("candidatos:", len(tot["candidatos"]))


if __name__ == "__main__":
    main()
