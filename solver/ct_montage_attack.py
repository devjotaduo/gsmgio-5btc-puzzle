# -*- coding: utf-8 -*-
"""
montage_attack — FAMÍLIA "montagem do ciphertext × corpus histórico".

HIPÓTESE (falsificável): o CT publicado do SMALL (e do TAIL32, mesmo tamanho: 80 B = 5 blocos)
está com os blocos em ordem diferente da ordem de decifração pretendida (o binário `enter`
intercalado entre as duas linhas base64 seria a marca disso). Se for verdade, TODAS as senhas
históricas falharam por MONTAGEM e não por estarem erradas — logo, re-testar o corpus inteiro
(466k senhas-base × 3 formas) contra TODAS as montagens possíveis dos 5 blocos resgataria
os negativos de uma vez.

TRUQUE que torna isso barato: em CBC, P_last = D_k(C_last) XOR C_prev. O padding PKCS7 do
último bloco da montagem depende SÓ do par (último, anterior). Por chave: 1 AES-ECB de 80 B
(D_0..D_4) e 20 checagens de par (as 120 permutações caem em 20 classes de 6). Sobrevivente
=> reconstroem-se, só com XOR, as 16 montagens compatíveis (6 permutações completas + 10
truncamentos ordenados — cobre "linha 1 sozinha" [0,1], "linha 2 sozinha" [2,3,4], etc.) e
aplica-se o oráculo estendido (semantic ⊃ nested_blob; fast_priv_scan com coincurve).

Montagens: 4 combos (salt S/T × CT S/T, i.e. inclui salt de um blob com CT do outro) ×
2 KDFs (EVP-SHA256 e MD5) × 120 permutações + 10 sub-montagens por par. Identidade
(seq [0,1,2,3,4], par (4,3)) = controle que reproduz o negativo conhecido.

Registro lossless por sobrevivente: D_hex (ECB-decrypt dos 5 blocos) + iv_hex; qualquer
montagem seq se reconstrói por P_k = D[seq[k]] XOR (iv se k==0 senão C[seq[k-1]]).
"""
import sys, os, io, json, time, hashlib, itertools, pickle, random, math
KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
HERE = os.path.dirname(os.path.abspath(__file__))
from Crypto.Cipher import AES

# ------------------------------------------------------------------ dados (lidos sem importar G no pai)
import gsmg_common as G
SALTS = {"S": G.BLOBS["SMALL"][0], "T": G.BLOBS["TAIL32"][0]}
CTS = {"S": G.BLOBS["SMALL"][1], "T": G.BLOBS["TAIL32"][1]}
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
KDFS = (("sha256", hashlib.sha256), ("md5", hashlib.md5))
P_PAD = sum(256.0 ** -n for n in range(1, 17))   # prob. exata de PKCS7 válido em bloco aleatório ≈ 1/255

def evp(pw, salt, h):
    d = prev = b""
    while len(d) < 48:
        prev = h(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]

def unpad(p):
    n = p[-1]
    if 1 <= n <= 16 and p.endswith(bytes([n]) * n): return p[:-n]
    return None

def xor16(a, b): return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")

def blocks(ct): return [ct[i:i + 16] for i in range(0, len(ct), 16)]

def scan_pairs(D, C, Clast):
    """Pares (last, prev) cujo P_last = D[last]^C[prev] tem padding PKCS7 válido. D = ECB-decrypt(CT)."""
    out = []
    nb = len(C)
    for last in range(nb):
        dl = D[16 * last + 15]
        for prev in range(nb):
            if prev == last: continue
            n = dl ^ Clast[prev]
            if 1 <= n <= 16:
                P = xor16(D[16 * last:16 * last + 16], C[prev])
                if P.endswith(bytes([n]) * n): out.append((last, prev, n))
    return out

def montage_plain(D, C, iv, seq):
    out = b""; prev = iv
    for i in seq:
        out += xor16(D[16 * i:16 * i + 16], prev); prev = C[i]
    return out

def montages_for(last, prev, nb=5):
    """Todas as sequências ordenadas de blocos terminando em [..., prev, last]: prefixo = qualquer
    subconjunto ordenado dos demais (5 blocos: 1+3+6+6 = 16 montagens, das quais 6 são perms completas)."""
    rest = [i for i in range(nb) if i not in (last, prev)]
    seqs = []
    for r in range(len(rest) + 1):
        for pre in itertools.permutations(rest, r):
            seqs.append(list(pre) + [prev, last])
    return seqs

def priv_scan(p, seen):
    from coincurve import PublicKey
    hits = []
    for j in range(0, len(p) - 31):
        sec = p[j:j + 32]
        if sec in seen: continue
        seen.add(sec)
        try:
            if PublicKey.from_valid_secret(sec).format(False) == TGT: hits.append((j, sec.hex()))
        except Exception:
            pass
    return hits

# ------------------------------------------------------------------ worker
_SHARD = [None]
def _shard():
    if _SHARD[0] is None:
        _SHARD[0] = open(os.path.join(HERE, f"survivors_{os.getpid()}.jsonl"), "a", encoding="utf-8")
    return _SHARD[0]

def work(args):
    """args = (forms:list[(bytes, src, fk)], do_eval:bool, combos). Devolve contagens + hard hits + best."""
    forms, do_eval, tag = args
    counts = {}      # (salt, kdf, ct, last, prev) -> n sobreviventes de padding
    soft06 = {}      # idem -> n montagens com printable >= 0.6
    hard = []; best = {"printable": -1.0}; n_surv = 0; n_mont = 0; n_priv_windows = 0
    C = {k: blocks(v) for k, v in CTS.items()}
    Clast = {k: [b[15] for b in C[k]] for k in C}
    out = _shard() if do_eval else None
    for form, src, fk in forms:
        for stag, salt in SALTS.items():
            for kn, h in KDFS:
                key, iv = evp(form, salt, h)
                ecb = AES.new(key, AES.MODE_ECB)
                for ctag in ("S", "T"):
                    D = ecb.decrypt(CTS[ctag])
                    for last, prev, n in scan_pairs(D, C[ctag], Clast[ctag]):
                        k = (stag, kn, ctag, last, prev)
                        counts[k] = counts.get(k, 0) + 1
                        n_surv += 1
                        if not do_eval: continue
                        rec_best = {"printable": -1.0}; nested = False; privs = []; sem = []
                        seen = set()
                        for seq in montages_for(last, prev):
                            p = unpad(montage_plain(D, C[ctag], iv, seq))
                            n_mont += 1
                            pr = G.printable(p)
                            if pr > rec_best["printable"]:
                                rec_best = {"printable": round(pr, 3), "seq": seq, "len": len(p), "plain_hex": p.hex()}
                            if pr >= 0.6: soft06[k] = soft06.get(k, 0) + 1
                            if G.nested_blob(p): nested = True
                            if G.semantic(p): sem.append({"seq": seq, "printable": round(pr, 3), "plain_hex": p.hex()})
                            if len(p) >= 32:
                                hh = priv_scan(p, seen)
                                if hh: privs.append({"seq": seq, "hits": hh, "plain_hex": p.hex()})
                        n_priv_windows += len(seen)
                        rec = {"form": form.decode("latin-1")[:160], "form_sha": hashlib.sha256(form).hexdigest()[:16],
                               "src": src, "fk": fk, "salt": stag, "kdf": kn, "ct": ctag, "last": last, "prev": prev,
                               "npad": n, "D_hex": D.hex(), "iv_hex": iv.hex(), "best": rec_best}
                        if nested: rec["nested"] = True
                        if sem: rec["semantic"] = sem
                        if privs: rec["priv"] = privs
                        if sem or privs or nested:
                            hard.append(rec)
                        out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        if rec_best["printable"] > best["printable"]:
                            best = dict(rec_best, form=rec["form"], src=src, fk=fk, salt=stag, kdf=kn, ct=ctag, last=last, prev=prev)
    if out: out.flush()
    return {"tag": tag, "n_forms": len(forms), "counts": counts, "soft06": soft06, "hard": hard, "best": best,
            "n_surv": n_surv, "n_mont": n_mont, "n_priv_windows": n_priv_windows}

# ------------------------------------------------------------------ formas
def make_forms(pws, srcs):
    seen = set(); forms = []
    for pw, src in zip(pws, srcs):
        hx = hashlib.sha256(pw).hexdigest()
        for fk, f in (("raw", pw), ("sha256hex", hx.encode()), ("SHA256HEX", hx.upper().encode())):
            if f in seen: continue
            seen.add(f); forms.append((f, src, fk))
    return forms

def chunks(lst, n):
    for i in range(0, len(lst), n): yield lst[i:i + n]

def merge(results):
    tot = {"counts": {}, "soft06": {}, "hard": [], "best": {"printable": -1.0}, "n_forms": 0, "n_surv": 0, "n_mont": 0, "n_priv_windows": 0}
    for r in results:
        for k, v in r["counts"].items(): tot["counts"][k] = tot["counts"].get(k, 0) + v
        for k, v in r["soft06"].items(): tot["soft06"][k] = tot["soft06"].get(k, 0) + v
        tot["hard"] += r["hard"]
        if r["best"]["printable"] > tot["best"]["printable"]: tot["best"] = r["best"]
        for k in ("n_forms", "n_surv", "n_mont", "n_priv_windows"): tot[k] += r[k]
    return tot

def zstats(counts, N):
    """z por classe (salt,kdf,ct,last,prev) sob p = P_PAD; N = nº de formas testadas."""
    exp = N * P_PAD; sd = math.sqrt(N * P_PAD * (1 - P_PAD))
    keys = [(s, k, c, l, p) for s in "ST" for k, _ in KDFS for c in "ST" for l in range(5) for p in range(5) if l != p]
    return {"|".join(map(str, key)): {"obs": counts.get(key, 0), "z": round((counts.get(key, 0) - exp) / sd, 2)} for key in keys}, exp

# ------------------------------------------------------------------ controles positivos
def control():
    import base64
    LOG = os.path.join(HERE, "control.jsonl"); open(LOG, "w").close()
    raw2 = base64.b64decode(G.PHASE2_B64); salt2, ct2 = raw2[8:16], raw2[16:]
    pw = G.shahex("causality").encode()
    key, iv = evp(pw, salt2, hashlib.sha256)
    # (a) fase 2 real (41 blocos): embaralha com permutação conhecida, recupera a ordem por
    #     pares (padding no último + printabilidade encadeada para trás)
    C2 = blocks(ct2); nb = len(C2)
    rng = random.Random(20260917); perm = list(range(nb)); rng.shuffle(perm)      # publicado[i] = original[perm[i]]
    shuffled = b"".join(C2[i] for i in perm)
    Cs = blocks(shuffled); Clast = [b[15] for b in Cs]
    D = AES.new(key, AES.MODE_ECB).decrypt(shuffled)
    pairs = scan_pairs(D, Cs, Clast)
    assert len(pairs) >= 1
    # encadeia para trás: prev de j = o k com D[j]^C[k] mais imprimível (>=0.85); posição 0 = D[j]^iv
    def chain(last, prev):
        seq = [prev, last]; used = {last, prev}
        while len(seq) < nb:
            j = seq[0]; cands = []
            for k in range(nb):
                if k in used: continue
                cands.append((G.printable(xor16(D[16 * j:16 * j + 16], Cs[k])), k))
            cands.sort(reverse=True)
            if cands[0][0] < 0.85: return None
            seq.insert(0, cands[0][1]); used.add(cands[0][1])
        return seq
    recovered = None
    for last, prev, n in pairs:
        seq = chain(last, prev)
        if seq and G.printable(xor16(D[16 * seq[0]:16 * seq[0] + 16], iv)) >= 0.85:
            recovered = seq; break
    inv = [perm.index(i) for i in range(nb)]    # posição publicada do bloco original i => ordem correta
    plain = unpad(montage_plain(D, Cs, iv, recovered))
    ok_a = recovered == inv and plain.startswith(b"The ironic") and G.semantic(plain)
    # (b) blob sintético de 5 blocos (mesma senha/salt, plaintext = 70 B da fase 2) embaralhado:
    #     o motor de 120 permutações (scan_pairs + montages_for) devolve a ordem certa e SÓ ela
    msg = plain[:70]; n = 16 - len(msg) % 16
    ct5 = AES.new(key, AES.MODE_CBC, iv).encrypt(msg + bytes([n]) * n); assert len(ct5) == 80
    C5 = blocks(ct5); perm5 = [3, 0, 4, 1, 2]; sh5 = b"".join(C5[i] for i in perm5)
    Cs5 = blocks(sh5); D5 = AES.new(key, AES.MODE_ECB).decrypt(sh5)
    sem_seqs = []
    for last, prev, nn in scan_pairs(D5, Cs5, [b[15] for b in Cs5]):
        for seq in montages_for(last, prev):
            p = unpad(montage_plain(D5, Cs5, iv, seq))
            if len(seq) == 5 and G.semantic(p): sem_seqs.append((seq, p))
    inv5 = [perm5.index(i) for i in range(5)]
    ok_b = len(sem_seqs) == 1 and sem_seqs[0][0] == inv5 and sem_seqs[0][1] == msg
    # (c) negativo: senha errada no mesmo blob embaralhado -> nenhuma montagem semântica
    keyw, ivw = evp(b"wrongpassword", salt2, hashlib.sha256); Dw = AES.new(keyw, AES.MODE_ECB).decrypt(sh5)
    n_sem_wrong = sum(1 for l, p_, _ in scan_pairs(Dw, Cs5, [b[15] for b in Cs5]) for seq in montages_for(l, p_)
                      if G.semantic(unpad(montage_plain(Dw, Cs5, ivw, seq))))
    # (d) MD5 não abre a fase 2 (KDF padrão = SHA256)
    keym, ivm = evp(pw, salt2, hashlib.md5)
    ok_d = unpad(AES.new(keym, AES.MODE_CBC, ivm).decrypt(ct2)) is None
    rec = {"kind": "control", "phase2_41blocks_shuffled": {"perm_first10": perm[:10], "pairs_surviving": len(pairs),
                                                           "recovered_order_ok": ok_a, "plain_head": plain[:40].decode("latin-1")},
           "synthetic_5blocks": {"perm": perm5, "true_order": inv5, "semantic_full_perms": [s for s, _ in sem_seqs], "ok": ok_b},
           "wrong_password_semantic_montages": n_sem_wrong, "phase2_md5_opens": not ok_d}
    G.jsonl(LOG, rec); print(json.dumps(rec, ensure_ascii=False))
    assert ok_a and ok_b and n_sem_wrong == 0 and ok_d, "CONTROLE FALHOU"
    return rec

# ------------------------------------------------------------------ nulo
def null_model(pool, n_rep=100, n_base=20000):
    LOG = os.path.join(HERE, "null.jsonl"); open(LOG, "w").close()
    rng = random.Random(1234); maxz = []; pooled = {}; Ntot = 0
    jobs = []
    for r in range(n_rep):
        pws = [rng.randbytes(12) for _ in range(n_base)]
        jobs.append((make_forms(pws, ["null"] * n_base), False, r))
    for res in pool.imap_unordered(work, jobs):
        N = res["n_forms"]; Ntot += N
        zs, exp = zstats(res["counts"], N)
        m = max(abs(v["z"]) for v in zs.values())
        maxz.append(m)
        for k, v in res["counts"].items(): pooled[k] = pooled.get(k, 0) + v
        G.jsonl(LOG, {"kind": "null_rep", "rep": res["tag"], "n_forms": N, "exp_per_class": round(exp, 1), "max_abs_z": m,
                      "rate": round(res["n_surv"] / (N * 160), 7)})
    maxz.sort()
    zs, exp = zstats(pooled, Ntot)
    summ = {"kind": "null_summary", "n_rep": n_rep, "n_forms_per_rep": Ntot // n_rep, "p_pad_exact": P_PAD,
            "pooled_rate": sum(pooled.values()) / (Ntot * 160), "pooled_max_abs_z": max(abs(v["z"]) for v in zs.values()),
            "max_abs_z_over_160_classes": {"mean": round(sum(maxz) / len(maxz), 2), "p50": maxz[len(maxz) // 2],
                                           "p95": maxz[int(0.95 * len(maxz))], "max": maxz[-1]}}
    G.jsonl(LOG, summ); print(json.dumps(summ)); return summ

# ------------------------------------------------------------------ principal
def main(pool):
    LOG = os.path.join(HERE, "montage_attack.jsonl"); open(LOG, "w").close()
    for f in os.listdir(HERE):
        if f.startswith("survivors_"): os.remove(os.path.join(HERE, f))
    G.jsonl(LOG, {"kind": "hypothesis", "text": __doc__.strip()})
    d = pickle.load(open(os.path.join(HERE, "corpus.pkl"), "rb"))
    forms = make_forms(d["pws"], d["srcs"])
    G.jsonl(LOG, {"kind": "corpus", "n_base": len(d["pws"]), "n_forms": len(forms), "sources": d["src_count"]})
    print(f"corpus: {len(d['pws'])} senhas-base -> {len(forms)} formas únicas", flush=True)
    t0 = time.time(); results = []
    jobs = [(c, True, i) for i, c in enumerate(chunks(forms, 4000))]
    for i, res in enumerate(pool.imap_unordered(work, jobs)):
        results.append(res)
        if res["hard"]:
            for h in res["hard"]:
                G.jsonl(LOG, {"kind": "HARD", **h}); print("!!! HARD", json.dumps(h, ensure_ascii=False)[:600], flush=True)
        if i % 20 == 0: print(f"  chunk {i}/{len(jobs)} {time.time()-t0:.0f}s", flush=True)
    tot = merge(results); N = tot["n_forms"]
    zs, exp = zstats(tot["counts"], N)
    zl = sorted(zs.items(), key=lambda kv: -abs(kv[1]["z"]))
    ident = {f"{s}|{k}|{c}": zs[f"{s}|{k}|{c}|4|3"] for s in "ST" for k, _ in KDFS for c in "ST"}
    summary = {"kind": "summary", "n_forms": N, "n_montage_classes": 160, "n_perms_per_class": 6, "n_submontages_per_class": 10,
               "n_pad_checks": N * 160, "n_logical_montage_tests": N * 8 * 120, "n_pad_survivors": tot["n_surv"],
               "n_montages_decrypted": tot["n_mont"], "n_priv_windows": tot["n_priv_windows"],
               "expected_per_class": round(exp, 1), "sd_per_class": round(math.sqrt(N * P_PAD * (1 - P_PAD)), 1),
               "pooled_rate": tot["n_surv"] / (N * 160), "p_pad_exact": P_PAD,
               "max_abs_z": abs(zl[0][1]["z"]), "top5_z": zl[:5], "identity_classes": ident,
               "soft06_total": sum(tot["soft06"].values()), "hard": len(tot["hard"]), "best": tot["best"], "seconds": round(time.time() - t0)}
    G.jsonl(LOG, summary); G.jsonl(LOG, {"kind": "z_all", "z": zs})
    json.dump(summary, open(os.path.join(HERE, "montage_summary.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(json.dumps({k: v for k, v in summary.items() if k != "best"}, ensure_ascii=False, indent=1))
    print("best:", {k: v for k, v in tot["best"].items() if k != "plain_hex"}, tot["best"].get("plain_hex", "")[:80])
    return summary

if __name__ == "__main__":
    import multiprocessing as mp
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("control", "all"): control()
    if mode in ("null", "main", "all"):
        with mp.Pool(20) as pool:
            if mode in ("null", "all"): null_model(pool)
            if mode in ("main", "all"): main(pool)
