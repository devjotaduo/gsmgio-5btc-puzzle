# -*- coding: utf-8 -*-
"""
CRITICO da familia 5 — passo 2: VERIFICACAO do proprio log do critico (critico_familia5.jsonl).

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O log do critico (246 s, 8,4 MB) afirma que a reproducao independente bateu com o agente e que
nenhum dos 6.274 plaintexts com padding valido passa no oraculo duro. Este script tenta REFUTAR
o proprio critico:
(V1) as contagens "distintas" por sub-familia (939/416/918/576/7650) sao recontadas do zero a
     partir das funcoes fam_A..fam_E do agente;
(V2) o "12.864 privkeys" do agente e recontado do zero com a mesma regra dele;
(V3) os 246 plaintexts do agente sao comparados BYTE A BYTE (blob, kdf, hex) com os 246 da
     reproducao independente do critico — se um so divergir, o pipeline nao e o mesmo;
(V4) os 6.274 plaintexts sao re-varridos com o oraculo COMPLETO, e desta vez a janela de 32 B
     tambem e comparada com o h160 alvo (a9553269…, o segundo endereco do premio), que nem o
     agente nem o critico anterior checaram — so a pubkey 04f4d1bb…;
(V5) o z = -2,26 da extensao X3 (deficit de padding) recebe p-valor exato de Poisson e correcao
     de look-elsewhere; a extensao X2 (sem nulo) recebe z binomial analitico.
Se V1–V5 confirmarem o log, a familia fica CONFIRMADO_NEGATIVO com a cobertura corrigida.

Uso: python critico_familia5_verificacao.py
"""
import sys, os, json, time, math, hashlib, multiprocessing as mp

SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
FAM5 = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\operador_ensinado_2026_09_17"
sys.path.insert(0, SP)
sys.path.insert(0, FAM5)
import gsmg_common as G

OUT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\critico_familia5"
LOG_AGENTE = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\familia5_dualidade\familia5_dualidade.jsonl"
LOG_CRITICO = os.path.join(OUT, "critico_familia5.jsonl")
LOG = os.path.join(OUT, "verificacao.jsonl")
TGT_PUB = bytes.fromhex(G.TARGET_PUBKEY_HEX)
TGT_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
WORKERS = 12


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def _w_scan(rec):
    """Oraculo completo num plaintext: pubkey 1GSMG + h160 alvo, janelas fwd/rev; mais os textuais."""
    from coincurve import PublicKey
    p = bytes.fromhex(rec["hex"])
    hits, janelas = [], 0
    for ordem, b in (("fwd", p), ("rev", p[::-1])):
        for j in range(0, len(b) - 31):
            janelas += 1
            sec = b[j:j + 32]
            try:
                pk = PublicKey.from_valid_secret(sec)
            except Exception:
                continue
            unc, comp = pk.format(False), pk.format(True)
            if unc == TGT_PUB or h160(unc) == TGT_H160 or h160(comp) == TGT_H160:
                hits.append({"ordem": ordem, "off": j, "priv": sec.hex()})
    t = p.decode("latin-1")
    o = {"semantic": bool(G.semantic(p)), "nested": bool(G.nested_blob(p)),
         "ebcdic": round(G.ebcdic_sig(p), 3), "printable": round(G.printable(p), 3),
         "wif": G.wif_candidates(t), "hex64": G.hex64_candidates(t), "priv": hits}
    o["hit"] = bool(o["semantic"] or o["nested"] or o["ebcdic"] >= 0.75 or o["wif"] or o["hex64"] or hits)
    return rec["tag"], rec["blob"], rec["kdf"], janelas, o


def poisson_cdf(k, lam):
    # em espaco log para nao estourar com k ~ 170
    return sum(math.exp(-lam + i * math.log(lam) - math.lgamma(i + 1)) for i in range(k + 1))


def key(x):
    return x if isinstance(x, bytes) else x.encode()


def main():
    t0 = time.time()
    import familia5_dualidade as F
    fh = open(LOG, "w", encoding="utf-8")
    fh.write(json.dumps({"tipo": "hipotese", "texto": __doc__.strip()}, ensure_ascii=False) + "\n")

    # V1 — recontagem das senhas
    fams = {"A_blobs_duais": F.fam_A(), "B_matriz_complemento": F.fam_B(),
            "C_par_de_estrelas": F.fam_C(), "D_corte_ao_meio": F.fam_D(),
            "E_gramatica_do_par": F.fam_E()}
    v1 = {}
    todas = set()
    for n, p in fams.items():
        d = {key(pw) for _, pw in p}
        v1[n] = {"listadas": len(p), "distintas": len(d), "ja_vistas_em_familia_anterior": len(d & todas)}
        todas |= d
    v1["TOTAL"] = {"listadas": sum(len(p) for p in fams.values()), "distintas": len(todas)}
    fh.write(json.dumps({"tipo": "V1_contagem", **v1}, ensure_ascii=False) + "\n")
    print("V1", json.dumps(v1))

    # V2 — privkeys do agente
    cands = set()
    for p in fams.values():
        for _, pw in p:
            if isinstance(pw, bytes):
                if len(pw) == 32:
                    cands.add(pw)
                cands.add(G.sha(pw))
            else:
                if len(pw) == 64 and all(c in "0123456789abcdefABCDEF" for c in pw):
                    cands.add(bytes.fromhex(pw))
                cands.add(G.sha(pw))
    v2 = {"privkeys_distintas_agente": len(cands), "bate_12864": len(cands) == 12864,
          "hits_priv_hit_kit_dois_alvos": sum(1 for c in cands if G.priv_hit(c))}
    fh.write(json.dumps({"tipo": "V2_privkeys", **v2}) + "\n")
    print("V2", json.dumps(v2))

    # sanidade dos objetos que o agente usou
    yells = sorted(i for i, v in G.COLORED.items() if v[0] == "Y")
    san = {"len_SMALL_B64": len(G.SMALL_B64), "len_TAIL32_B64": len(G.TAIL32_B64),
           "COLORED_163": G.COLORED.get(163), "n_amarelas": len(yells), "amarelas": yells,
           "len_COSMIC_raw": len(F.C_RAW), "len_DBBI": len(G.DBBI), "len_FAED": len(G.FAED)}
    fh.write(json.dumps({"tipo": "sanidade", **san}) + "\n")
    print("SAN", json.dumps(san))

    # V3 — 246 do agente vs 246 da reproducao do critico, byte a byte
    ag = {}
    for L in open(LOG_AGENTE, encoding="utf-8"):
        r = json.loads(L)
        if r.get("tipo") == "padding":
            ag[(r["tag"], r["blob"], r["kdf"].lower().replace("crypto.hash.", ""))] = r["hex"]
    cr, cr_all = {}, []
    for L in open(LOG_CRITICO, encoding="utf-8"):
        r = json.loads(L)
        if r.get("tipo") == "padding":
            cr_all.append(r)
            if r["tag"][0] in "ABCDE" and r["tag"][1] == "/":
                cr[(r["tag"], r["blob"], r["kdf"])] = r["hex"]
    iguais = sum(1 for k, v in ag.items() if cr.get(k) == v)
    v3 = {"agente_paddings": len(ag), "critico_reproducao_paddings": len(cr),
          "identicos_byte_a_byte": iguais, "so_no_agente": sorted(str(k) for k in ag.keys() - cr.keys())[:10],
          "so_no_critico": sorted(str(k) for k in cr.keys() - ag.keys())[:10],
          "kdfs_agente": sorted({k[2] for k in ag})}
    fh.write(json.dumps({"tipo": "V3_byte_a_byte", **v3}) + "\n")
    print("V3", json.dumps(v3))

    # V4 — re-varredura completa dos 6.274 (pubkey 1GSMG + h160 alvo, fwd/rev)
    with mp.Pool(WORKERS) as pool:
        res = list(pool.imap_unordered(_w_scan, cr_all, chunksize=64))
    janelas = sum(r[3] for r in res)
    hits = [r for r in res if r[4]["hit"]]
    v4 = {"plaintexts": len(res), "janelas_32B_fwd_rev": janelas, "hits_duros": len(hits),
          "max_printable": max(r[4]["printable"] for r in res),
          "max_ebcdic": max(r[4]["ebcdic"] for r in res),
          "n_wif": sum(len(r[4]["wif"]) for r in res), "n_hex64": sum(len(r[4]["hex64"]) for r in res),
          "n_nested": sum(r[4]["nested"] for r in res), "por_blob": {}}
    for b in ("SMALL", "COSMIC", "TAIL32"):
        v4["por_blob"][b] = sum(1 for r in res if r[1] == b)
    for r in hits:
        fh.write(json.dumps({"tipo": "HARD", "tag": r[0], "blob": r[1], "kdf": r[2], **r[4]}) + "\n")
    fh.write(json.dumps({"tipo": "V4_revarredura", **v4}) + "\n")
    print("V4", json.dumps(v4))

    # V5 — estatistica dos resumos do critico
    resumos = [json.loads(L) for L in open(LOG_CRITICO, encoding="utf-8") if '"tipo": "resumo"' in L]
    v5 = {"z_por_subfamilia": {}, "look_elsewhere": {}}
    zs = []
    for r in resumos:
        n, k = r["decifracoes"], r["padding_valido"]
        z_bin = (k / n - 1 / 256) / math.sqrt((1 / 256) * (255 / 256) / n)
        e = {"n": n, "k": k, "esperado_1_256": round(n / 256, 2), "z_binomial_vs_1_256": round(z_bin, 3)}
        if "nulo" in r:
            e["z_vs_nulo"] = r["z_padding"]
            zs.append(r["z_padding"])
            lam = r["nulo"]["taxa_media"] * n
            e["p_poisson_cauda_inferior"] = round(poisson_cdf(k, lam), 4) if k < lam else None
            e["p_poisson_cauda_superior"] = round(1 - poisson_cdf(k - 1, lam), 4) if k >= lam else None
        v5["z_por_subfamilia"][r["familia"]] = e
    # look-elsewhere: sub-familias com nulo; P(min z <= z_min | normais independentes)
    zmin = min(zs)
    p1 = 0.5 * math.erfc(-zmin / math.sqrt(2))
    v5["look_elsewhere"] = {"subfamilias_com_nulo": len(zs), "z_min": zmin, "z_max": max(zs),
                            "p_unilateral_z_min": round(p1, 4),
                            "p_algum_tao_baixo": round(1 - (1 - p1) ** len(zs), 4),
                            "banda_calibrada": [-1.2, 2.1],
                            "nota": "deficit de padding nao e sinal: uma senha certa produz UM hit, nao menos paddings"}
    fh.write(json.dumps({"tipo": "V5_estatistica", **v5}) + "\n")
    print("V5", json.dumps(v5))

    tot = {"tipo": "TOTAL_VERIFICACAO", "segundos": round(time.time() - t0, 1),
           "hits_duros": len(hits), "plaintexts_revarridos": len(res), "janelas": janelas}
    fh.write(json.dumps(tot) + "\n")
    fh.close()
    print("TOTAL", json.dumps(tot))
    print("log:", LOG)


if __name__ == "__main__":
    main()
