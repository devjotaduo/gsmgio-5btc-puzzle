# -*- coding: utf-8 -*-
"""
multicipher_attack — FAMÍLIA "premissa da cifra" (endgame GSMG.IO 5 BTC).

HIPÓTESE (falsificável): todos os ataques históricos assumiram `openssl enc -aes-256-cbc` porque as
fases 2/3/3.2 usaram isso. Mas o cabeçalho `Salted__` só prova `openssl enc` com `-pass`/`-k`
(EVP_BytesToKey) — NÃO prova a cifra nem o modo. Um autor que "raised the stakes" pode ter trocado
a cifra no último passo mantendo a mesma gramática de senha. Se for assim, alguma das 1.272.149
formas do corpus histórico (466.310 senhas-base × {crua, sha256hex, SHA256HEX}) abre SMALL, TAIL32
ou COSMIC com OUTRA cifra/modo do `openssl enc`, com KDF EVP-SHA256 (openssl ≥ 1.1.0) ou EVP-MD5.

Cifras/modos cobertos (nome openssl -> klen/ivlen/bloco): aes-128-cbc 16/16/16, aes-192-cbc 24/16/16,
aes-256-cbc 32/16/16 (CONTROLE = negativo conhecido), aes-256-ecb 32/0/16, aes-256-cfb 32/16 (cfb128),
aes-256-ofb 32/16, aes-256-ctr 32/16, chacha20 32/16, bf-cbc 16/8/8, des-ede3-cbc 24/8/8,
cast5-cbc 16/8/8, rc2-cbc 16/8/8 (efetivo 128 bits), camellia-256-cbc 32/16/16, seed-cbc 16/16/16,
idea-cbc 16/8/8, sm4-cbc 16/16/16.  aria-256-cbc: SEM implementação Python (pycryptodome e
cryptography não têm ARIA) — declarado indisponível; só o CLI openssl o cifra.

Truque de custo: EVP_BytesToKey é um encadeamento de digests cujo resultado para (klen+ivlen) menor
é PREFIXO do resultado para 48 B — por (forma, salt, digest) calcula-se UMA vez 48 B e fatia-se
por cifra. Modos com padding: oráculo do último bloco (1 decifra CBC de 1 bloco com IV = penúltimo
bloco do CT); sobrevivente => decifra completa + oráculo estendido (semantic ⊃ nested_blob,
WIF/hex64, fast_priv_scan). Modos de fluxo (cfb/ofb/ctr/chacha20): decifra tudo; oráculo = printable
>= 0,85 OU nested_blob OU WIF/hex64 OU privkey crua no offset 0 / final; printable >= 0,60 => soft
(+ varredura completa de privkey).

Controles: (a) por cifra, texto conhecido cifrado pelo CLI `openssl enc -<cifra> -pass -S -md` e
reaberto pelo pipeline (SHA256 e MD5); (b) a fase 2 real abre com aes-256-cbc/EVP-SHA256 e com
NENHUMA outra cifra/KDF. Nulo: senhas aleatórias no mesmo pipeline => taxa de padding por classe e
máximo esperado de |z| e de printable.
"""
import sys, os, json, time, hashlib, pickle, random, math, re, base64, subprocess
KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(HERE), "montagem_ct", "corpus.pkl")
import gsmg_common as G
from Crypto.Cipher import AES, Blowfish, DES3, CAST, ARC2, ChaCha20
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers import algorithms as dalg

BLOBS = {k: G.BLOBS[k] for k in ("SMALL", "TAIL32", "COSMIC")}
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
KDFS = (("sha256", hashlib.sha256), ("md5", hashlib.md5))
PRINT = bytes(range(32, 127))
HEX64 = re.compile(rb"[0-9a-fA-F]{64}"); WIF = re.compile(rb"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}")

# ------------------------------------------------------------------ tabela de cifras
# nome -> (klen, ivlen, bs, modo, engine). engine: ("pc", classe, kwargs) | ("cg", algoritmo) | ("stream", fn)
def _ctr(k, iv, ct):
    return AES.new(k, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big")).decrypt(ct)
def _chacha(k, iv, ct):   # openssl chacha20: IV = contador 32 bits LE || nonce 96 bits (RFC 7539)
    c = ChaCha20.new(key=k, nonce=iv[4:]); c.seek(64 * int.from_bytes(iv[:4], "little")); return c.decrypt(ct)
CIPHERS = {
    "aes-128-cbc": (16, 16, 16, "cbc", ("pc", AES, {})),
    "aes-192-cbc": (24, 16, 16, "cbc", ("pc", AES, {})),
    "aes-256-cbc": (32, 16, 16, "cbc", ("pc", AES, {})),
    "aes-256-ecb": (32, 0, 16, "ecb", ("pc", AES, {})),
    "aes-256-cfb": (32, 16, 16, "stream", ("stream", lambda k, iv, ct: AES.new(k, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct))),
    "aes-256-ofb": (32, 16, 16, "stream", ("stream", lambda k, iv, ct: AES.new(k, AES.MODE_OFB, iv=iv).decrypt(ct))),
    "aes-256-ctr": (32, 16, 16, "stream", ("stream", _ctr)),
    "chacha20":    (32, 16, 64, "stream", ("stream", _chacha)),
    "bf-cbc":      (16, 8, 8, "cbc", ("pc", Blowfish, {})),
    "des-ede3-cbc": (24, 8, 8, "cbc", ("pc", DES3, {})),
    "cast5-cbc":   (16, 8, 8, "cbc", ("pc", CAST, {})),
    "rc2-cbc":     (16, 8, 8, "cbc", ("pc", ARC2, {"effective_keylen": 128})),
    "camellia-256-cbc": (32, 16, 16, "cbc", ("cg", algorithms.Camellia)),
    "seed-cbc":    (16, 16, 16, "cbc", ("cg", dalg.SEED)),
    "idea-cbc":    (16, 8, 8, "cbc", ("cg", dalg.IDEA)),
    "sm4-cbc":     (16, 16, 16, "cbc", ("cg", algorithms.SM4)),
}
UNAVAILABLE = {"aria-256-cbc": "sem implementação em pycryptodome 3.23 / cryptography 46 (só CLI openssl)"}
PADDED = [c for c, v in CIPHERS.items() if v[3] in ("cbc", "ecb")]
STREAM = [c for c, v in CIPHERS.items() if v[3] == "stream"]
LEGACY_CLI = {"bf-cbc", "cast5-cbc", "rc2-cbc", "seed-cbc", "idea-cbc"}   # openssl 3: -provider legacy
def p_pad(bs): return sum(256.0 ** -n for n in range(1, bs + 1))            # PKCS7 válido por acaso

def evp48(pw, salt, h):
    """EVP_BytesToKey(digest=h, iter=1) para 48 B; qualquer (klen+ivlen) <= 48 é prefixo."""
    d = prev = b""
    while len(d) < 48:
        prev = h(prev + pw + salt).digest(); d += prev
    return d[:48]

def dec_last(cname, key, ct):
    """Último bloco em claro (CBC: IV = penúltimo bloco do CT; ECB: direto)."""
    klen, ivlen, bs, mode, eng = CIPHERS[cname]
    if mode == "cbc":
        if eng[0] == "pc": return eng[1].new(key, eng[1].MODE_CBC, iv=ct[-2 * bs:-bs], **eng[2]).decrypt(ct[-bs:])
        return Cipher(eng[1](key), modes.CBC(ct[-2 * bs:-bs])).decryptor().update(ct[-bs:])
    if eng[0] == "pc": return eng[1].new(key, eng[1].MODE_ECB, **eng[2]).decrypt(ct[-bs:])
    return Cipher(eng[1](key), modes.ECB()).decryptor().update(ct[-bs:])

def dec_full(cname, key, iv, ct):
    klen, ivlen, bs, mode, eng = CIPHERS[cname]
    if mode == "stream": return eng[1](key, iv, ct)
    if mode == "cbc":
        if eng[0] == "pc": return eng[1].new(key, eng[1].MODE_CBC, iv=iv, **eng[2]).decrypt(ct)
        d = Cipher(eng[1](key), modes.CBC(iv)).decryptor(); return d.update(ct) + d.finalize()
    if eng[0] == "pc": return eng[1].new(key, eng[1].MODE_ECB, **eng[2]).decrypt(ct)
    d = Cipher(eng[1](key), modes.ECB()).decryptor(); return d.update(ct) + d.finalize()

def unpad(p, bs):
    n = p[-1]
    if 1 <= n <= bs and p.endswith(bytes([n]) * n): return p[:-n]
    return None

def printable(p): return 1.0 - len(p.translate(None, PRINT)) / len(p)

def priv_at(p, j):
    from coincurve import PublicKey
    try:
        return PublicKey.from_valid_secret(p[j:j + 32]).format(False) == TGT
    except Exception:
        return False

def open_with(cname, pw, salt, ct, kdf="sha256"):
    """Abre um CT com (cifra, senha, salt, kdf). Devolve plaintext (sem padding) ou None."""
    h = dict(KDFS)[kdf]; klen, ivlen, bs, mode, eng = CIPHERS[cname]
    km = evp48(pw if isinstance(pw, bytes) else pw.encode(), salt, h)
    p = dec_full(cname, km[:klen], km[klen:klen + ivlen], ct)
    return p if mode == "stream" else unpad(p, bs)

# ------------------------------------------------------------------ worker
def work(args):
    """args = (forms:[(bytes, src, fk)], do_eval, tag). Contagens de padding por classe, hits e melhores."""
    forms, do_eval, tag = args
    counts = {}; hard = []; soft = []; best = {}; n_tests = 0; n_surv = 0; errors = {}
    out = open(os.path.join(HERE, f"survivors_{os.getpid()}.jsonl"), "a", encoding="utf-8") if do_eval else None
    try:
        _work_loop(forms, do_eval, counts, hard, soft, best, errors, out, lambda: None)
    finally:
        if out: out.close()
    return {"tag": tag, "n_forms": len(forms), "n_tests": _work_loop.n_tests, "n_surv": _work_loop.n_surv, "counts": counts,
            "hard": hard, "soft": soft, "best": best, "errors": errors}

def _work_loop(forms, do_eval, counts, hard, soft, best, errors, out, _):
    n_tests = 0; n_surv = 0
    for form, src, fk in forms:
        for bname, (salt, ct) in BLOBS.items():
            for kn, h in KDFS:
                km = evp48(form, salt, h)
                for cname in PADDED:
                    klen, ivlen, bs, mode, eng = CIPHERS[cname]
                    if len(ct) % bs: continue
                    n_tests += 1
                    try:
                        last = dec_last(cname, km[:klen], ct)
                    except Exception as e:          # ex.: DES3 com chave degenerada
                        errors[cname] = errors.get(cname, 0) + 1; continue
                    n = last[-1]
                    if not (1 <= n <= bs and last.endswith(bytes([n]) * n)): continue
                    k = (cname, bname, kn); counts[k] = counts.get(k, 0) + 1; n_surv += 1
                    if not do_eval: continue
                    p = unpad(dec_full(cname, km[:klen], km[klen:klen + ivlen], ct), bs)
                    pr = printable(p) if p else 0.0
                    rec = {"cipher": cname, "blob": bname, "kdf": kn, "form": form.decode("latin-1")[:160],
                           "src": src, "fk": fk, "npad": n, "len": len(p), "printable": round(pr, 3),
                           "plain_hex": p.hex()}
                    priv = G.fast_priv_scan(p, f"{cname}/{bname}/{kn}") if len(p) >= 32 else []
                    if priv: rec["privkey"] = priv
                    if G.nested_blob(p): rec["nested"] = True
                    if priv or G.semantic(p): hard.append(rec)
                    elif pr >= 0.6: soft.append(rec)
                    bk = (cname, bname)
                    if pr > best.get(bk, {"printable": -1})["printable"]: best[bk] = {k_: v_ for k_, v_ in rec.items()}
                    out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                for cname in STREAM:
                    klen, ivlen, bs, mode, eng = CIPHERS[cname]
                    n_tests += 1
                    try:
                        p = eng[1](km[:klen], km[klen:klen + ivlen], ct)
                    except Exception:
                        errors[cname] = errors.get(cname, 0) + 1; continue
                    pr = printable(p)
                    hx = HEX64.search(p); wf = WIF.search(p)
                    is_hard = pr >= 0.85 or G.nested_blob(p) or priv_at(p, 0) or priv_at(p, len(p) - 32)
                    if hx and re.search(rb"\d", hx.group()) and re.search(rb"[a-fA-F]", hx.group()):
                        is_hard = True
                    if wf and re.search(rb"\d", wf.group()) and re.search(rb"[a-z]", wf.group()) and re.search(rb"[A-Z]", wf.group()):
                        is_hard = True
                    bk = (cname, bname)
                    if pr > best.get(bk, {"printable": -1})["printable"]:
                        best[bk] = {"cipher": cname, "blob": bname, "kdf": kn, "form": form.decode("latin-1")[:160],
                                    "src": src, "fk": fk, "printable": round(pr, 3), "plain_hex": p[:96].hex()}
                    if not (is_hard or pr >= 0.6): continue
                    rec = {"cipher": cname, "blob": bname, "kdf": kn, "form": form.decode("latin-1")[:160],
                           "src": src, "fk": fk, "len": len(p), "printable": round(pr, 3), "plain_hex": p.hex()}
                    priv = G.fast_priv_scan(p, f"{cname}/{bname}/{kn}")
                    if priv: rec["privkey"] = priv; is_hard = True
                    if hx: rec["hex64"] = hx.group().decode()
                    if wf: rec["wif"] = wf.group().decode()
                    if G.nested_blob(p): rec["nested"] = True
                    (hard if is_hard else soft).append(rec)
                    if out: out.write(json.dumps(rec, ensure_ascii=False) + "\n")
    _work_loop.n_tests = n_tests; _work_loop.n_surv = n_surv

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
    tot = {"n_forms": 0, "n_tests": 0, "n_surv": 0, "counts": {}, "hard": [], "soft": [], "best": {}, "errors": {}}
    for r in results:
        for k in ("n_forms", "n_tests", "n_surv"): tot[k] += r[k]
        for k, v in r["counts"].items(): tot["counts"][k] = tot["counts"].get(k, 0) + v
        for k, v in r["errors"].items(): tot["errors"][k] = tot["errors"].get(k, 0) + v
        tot["hard"] += r["hard"]; tot["soft"] += r["soft"]
        for k, v in r["best"].items():
            if v["printable"] > tot["best"].get(k, {"printable": -1})["printable"]: tot["best"][k] = v
    return tot

def zstats(counts, N):
    """z por classe (cifra, blob, kdf) sob p = p_pad(bs); N = formas testadas."""
    zs = {}
    for c in PADDED:
        bs = CIPHERS[c][2]; p = p_pad(bs); exp = N * p; sd = math.sqrt(N * p * (1 - p))
        for b in BLOBS:
            for kn, _ in KDFS:
                o = counts.get((c, b, kn), 0)
                zs[f"{c}|{b}|{kn}"] = {"obs": o, "exp": round(exp, 1), "z": round((o - exp) / sd, 2)}
    return zs

# ------------------------------------------------------------------ controles
def openssl_enc(cname, msg, pw, salt, md):
    cmd = ["openssl", "enc", f"-{cname}", "-a", "-A", "-pass", f"pass:{pw}", "-S", salt.hex(), "-md", md]
    if cname in LEGACY_CLI: cmd += ["-provider", "legacy", "-provider", "default"]
    r = subprocess.run(cmd, input=msg, capture_output=True, check=True)
    raw = base64.b64decode(r.stdout.strip())
    # openssl 3.5 com -S explícito NÃO grava o cabeçalho Salted__ (verificado: key/iv de -p batem com evp48)
    if raw[:8] == b"Salted__": assert raw[8:16] == salt; raw = raw[16:]
    return raw

def control():
    LOG = os.path.join(HERE, "control.jsonl"); open(LOG, "w").close()
    raw2 = base64.b64decode(G.PHASE2_B64); salt2, ct2 = raw2[8:16], raw2[16:]
    pw2 = G.shahex("causality")
    p2 = open_with("aes-256-cbc", pw2, salt2, ct2, "sha256"); assert p2.startswith(b"The ironic")
    msg = p2[:70] + b"\n"   # 71 B: exercita padding != bloco cheio em bs 8 e 16
    salt = bytes.fromhex("3ab585348552415d")   # salt real do SMALL
    per_cipher = {}
    for cname in CIPHERS:
        r = {}
        for md in ("sha256", "md5"):
            ct = openssl_enc(cname, msg, pw2, salt, md)
            p = open_with(cname, pw2, salt, ct, md)
            ok_open = p == msg
            # o oráculo de último bloco dispara com a chave certa (modos com padding)
            klen, ivlen, bs, mode, eng = CIPHERS[cname]
            km = evp48(pw2.encode(), salt, dict(KDFS)[md])
            ok_oracle = True
            if mode != "stream":
                last = dec_last(cname, km[:klen], ct); n = last[-1]
                ok_oracle = 1 <= n <= bs and last.endswith(bytes([n]) * n)
            # senha errada não abre (padding inválido ou printable baixo)
            pw_wrong = open_with(cname, "wrongpassword", salt, ct, md)
            ok_wrong = pw_wrong is None or printable(pw_wrong) < 0.85
            # pipeline via work(): a forma certa produz hit duro nesse CT
            r[md] = {"opens": ok_open, "oracle": ok_oracle, "wrong_fails": ok_wrong, "ct_len": len(ct)}
            assert ok_open and ok_oracle and ok_wrong, (cname, md, r)
        per_cipher[cname] = r
    # (b) fase 2 real: abre SÓ com aes-256-cbc/sha256
    phase2 = {}
    for cname in CIPHERS:
        for md in ("sha256", "md5"):
            p = open_with(cname, pw2, salt2, ct2, md)
            phase2[f"{cname}|{md}"] = {"pad_ok": p is not None, "printable": round(printable(p), 3) if p else None,
                                       "semantic": bool(p) and G.semantic(p)}
    opened = [k for k, v in phase2.items() if v["semantic"]]
    assert opened == ["aes-256-cbc|sha256"], opened
    # (c) pipeline completo (work) sobre a fase 2 re-cifrada em cada cifra: hit duro com a senha certa
    global BLOBS
    saved = BLOBS; pipeline = {}
    try:
        for cname in CIPHERS:
            for md in ("sha256", "md5"):
                ct = openssl_enc(cname, p2, pw2, salt, md)
                BLOBS = {"SYN": (salt, ct)}
                res = work(([(pw2.encode(), "ctl", "sha256hex"), (b"notit", "ctl", "raw")], True, "ctl"))
                hits = [(h["cipher"], h["kdf"]) for h in res["hard"]]
                pipeline[f"{cname}|{md}"] = hits
                assert (cname, md) in hits, (cname, md, hits)
    finally:
        BLOBS = saved
        for f in os.listdir(HERE):
            if f.startswith("survivors_"): os.remove(os.path.join(HERE, f))
    rec = {"kind": "control", "known_text_roundtrip": per_cipher, "phase2_real": phase2, "phase2_opens_only": opened,
           "pipeline_synthetic_hits": pipeline, "unavailable": UNAVAILABLE}
    G.jsonl(LOG, rec); print(json.dumps({k: v for k, v in rec.items() if k != "phase2_real"}, ensure_ascii=False)[:1500])
    print("phase2 stream printable:", {k: v["printable"] for k, v in phase2.items() if v["pad_ok"]})
    return rec

# ------------------------------------------------------------------ nulo
def null_model(pool, n_rep=6, n_base=10000):
    LOG = os.path.join(HERE, "null.jsonl"); open(LOG, "w").close()
    rng = random.Random(1234); maxz = []; pooled = {}; Ntot = 0; best = {}
    jobs = []
    for r in range(n_rep):
        pws = [rng.randbytes(12) for _ in range(n_base)]
        jobs.append((make_forms(pws, ["null"] * n_base), False, r))
    for res in pool.imap_unordered(work, jobs):
        N = res["n_forms"]; Ntot += N
        zs = zstats(res["counts"], N); m = max(abs(v["z"]) for v in zs.values()); maxz.append(m)
        for k, v in res["counts"].items(): pooled[k] = pooled.get(k, 0) + v
        for k, v in res["best"].items():
            if v["printable"] > best.get(k, {"printable": -1})["printable"]: best[k] = v
        G.jsonl(LOG, {"kind": "null_rep", "rep": res["tag"], "n_forms": N, "max_abs_z": m, "n_surv": res["n_surv"]})
    maxz.sort(); zs = zstats(pooled, Ntot)
    summ = {"kind": "null_summary", "n_rep": n_rep, "n_forms_total": Ntot, "n_classes": len(zs),
            "pooled_max_abs_z": max(abs(v["z"]) for v in zs.values()),
            "max_abs_z_per_rep": {"mean": round(sum(maxz) / len(maxz), 2), "max": maxz[-1]},
            "pooled_rate_bs16": sum(v for k, v in pooled.items() if CIPHERS[k[0]][2] == 16) / (Ntot * 6 * sum(1 for c in PADDED if CIPHERS[c][2] == 16)),
            "pooled_rate_bs8": sum(v for k, v in pooled.items() if CIPHERS[k[0]][2] == 8) / (Ntot * 6 * sum(1 for c in PADDED if CIPHERS[c][2] == 8)),
            "p_pad_16": p_pad(16), "p_pad_8": p_pad(8),
            "max_printable_stream": {f"{k[0]}|{k[1]}": v["printable"] for k, v in best.items() if k[0] in STREAM}}
    G.jsonl(LOG, summ); G.jsonl(LOG, {"kind": "null_z_all", "z": zs}); print(json.dumps(summ)); return summ

# ------------------------------------------------------------------ principal
def main(pool):
    LOG = os.path.join(HERE, "multicipher_attack.jsonl"); open(LOG, "w").close()
    for f in os.listdir(HERE):
        if f.startswith("survivors_"): os.remove(os.path.join(HERE, f))
    G.jsonl(LOG, {"kind": "hypothesis", "text": __doc__.strip()})
    d = pickle.load(open(CORPUS, "rb"))
    forms = make_forms(d["pws"], d["srcs"])
    G.jsonl(LOG, {"kind": "corpus", "n_base": len(d["pws"]), "n_forms": len(forms), "sources": d["src_count"]})
    print(f"corpus: {len(d['pws'])} senhas-base -> {len(forms)} formas únicas", flush=True)
    t0 = time.time(); results = []
    jobs = [(c, True, i) for i, c in enumerate(chunks(forms, 2000))]
    for i, res in enumerate(pool.imap_unordered(work, jobs)):
        results.append(res)
        for h in res["hard"]:
            G.jsonl(LOG, {"kind": "HARD", **h}); print("!!! HARD", json.dumps(h, ensure_ascii=False)[:600], flush=True)
        if i % 40 == 0: print(f"  chunk {i}/{len(jobs)} {time.time()-t0:.0f}s", flush=True)
    tot = merge(results); N = tot["n_forms"]
    zs = zstats(tot["counts"], N)
    zl = sorted(zs.items(), key=lambda kv: -abs(kv[1]["z"]))
    best_stream = sorted(({"class": f"{k[0]}|{k[1]}", **v} for k, v in tot["best"].items() if k[0] in STREAM),
                         key=lambda r: -r["printable"])
    best_pad = sorted(({"class": f"{k[0]}|{k[1]}", **v} for k, v in tot["best"].items() if k[0] in PADDED),
                      key=lambda r: -r["printable"])
    summary = {"kind": "summary", "n_forms": N, "n_ciphers": len(CIPHERS), "n_padded": len(PADDED), "n_stream": len(STREAM),
               "n_tests": tot["n_tests"], "n_pad_survivors": tot["n_surv"], "n_pad_classes": len(zs),
               "max_abs_z": abs(zl[0][1]["z"]), "top8_z": zl[:8],
               "control_class_aes256cbc": {k: v for k, v in zs.items() if k.startswith("aes-256-cbc")},
               "hard": len(tot["hard"]), "soft": len(tot["soft"]), "errors": tot["errors"],
               "best_stream_top5": best_stream[:5], "best_padded_top5": best_pad[:5], "seconds": round(time.time() - t0)}
    G.jsonl(LOG, summary); G.jsonl(LOG, {"kind": "z_all", "z": zs})
    for s in tot["soft"]: G.jsonl(LOG, {"kind": "SOFT", **s})
    json.dump(summary, open(os.path.join(HERE, "summary.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(json.dumps({k: v for k, v in summary.items() if not k.startswith("best")}, ensure_ascii=False, indent=1))
    for r in best_stream[:5] + best_pad[:5]: print("best:", {k: v for k, v in r.items() if k != "plain_hex"}, r["plain_hex"][:64])
    return summary

if __name__ == "__main__":
    import multiprocessing as mp
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("control", "all"): control()
    if mode in ("null", "main", "all"):
        with mp.Pool(16) as pool:
            if mode in ("null", "all"): null_model(pool)
            if mode in ("main", "all"): main(pool)
