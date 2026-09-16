# -*- coding: utf-8 -*-
"""
Família symbol_map_variants — o mapa símbolo→valor de faed/dbbi é OUTRO (não a=1..i=9 / a=0..h=8).
Hipótese: sob um dos 14 mapas principiados, uma leitura já catalogada (base-10/z-method, base-9, pares,
trios, nibbles, seleções por primos/cores/matriz/mod k, janelas, 1 bit/símbolo) dá a privkey do prêmio
ou uma senha (crua/hex/sha256hex) que abre SMALL/COSMIC/TAIL32.
Oráculos: privkey→pubkey-alvo (coincurve) e padding rápido (1 AES-ECB no último bloco CBC, EVP-SHA256).
"""
import os, sys, time, json, random, hashlib, collections
SP = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
from coincurve import PublicKey, PrivateKey

LOG = os.path.join(SP, "symbol_map_variants.jsonl")
def log(o): G.jsonl(LOG, o)
T0 = time.time()

# ------------------------------------------------------------ oráculos
BL = {}
for name in ("SMALL", "COSMIC", "TAIL32"):
    salt, ct = G.BLOBS[name]; BL[name] = (salt, ct, ct[-32:-16], ct[-16:])
TARGET = bytes.fromhex(G.TARGET_PUBKEY_HEX)
N = collections.Counter()          # contadores de oráculo
HARD, SOFT, PRINT = [], [], []
SEEN_PW = set()

def evp_key(pw, salt):
    d = b""; prev = b""
    while len(d) < 48:
        prev = hashlib.sha256(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]

def pad_ok(pt):
    p = pt[-1]; return 1 <= p <= 16 and pt.endswith(bytes([p]) * p)

def try_pw(pw, how, ctx):
    """Oráculo de padding rápido nos 3 blobs (EVP-SHA256)."""
    if not pw or len(pw) > 4096: return
    key = (pw, )
    if key in SEEN_PW: return
    SEEN_PW.add(key)
    for name, (salt, ct, cprev, clast) in BL.items():
        N["aes"] += 1
        k, iv = evp_key(pw, salt)
        blk = AES.new(k, AES.MODE_ECB).decrypt(clast)
        if not pad_ok(bytes(a ^ b for a, b in zip(blk, cprev))): continue
        pt = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        if pt is None: continue
        rec = {"how": how, **ctx, "blob": name, "kdf": "EVP-SHA256", "pw_hex": pw.hex(), "len": len(pt),
               "printable": round(G.printable(pt), 3), "head": pt[:48].decode("latin-1")}
        if G.semantic(pt):
            rec["plaintext_hex"] = pt.hex(); HARD.append(rec); log({"kind": "HARD", **rec})
        else:
            SOFT.append(rec); log({"kind": "soft_pad", **rec})

def priv_scan(buf, how, ctx, target=TARGET):
    for j in range(0, len(buf) - 31):
        N["priv"] += 1
        try:
            if PublicKey.from_valid_secret(buf[j:j + 32]).format(False) == target:
                rec = {"how": how, **ctx, "priv_hex": buf[j:j + 32].hex(), "offset": j}
                HARD.append(rec); log({"kind": "HARD", **rec}); return True
        except Exception:
            pass
    return False

# ------------------------------------------------------------ mapas símbolo→valor
def perm_maps(name, order):
    return {f"{name}1": {c: i + 1 for i, c in enumerate(order)},
            f"{name}0": {c: i for i, c in enumerate(order)}}
MAPS = {}
MAPS.update(perm_maps("CANON", "dbifhcega"))     # 1ª ocorrência do dbbi
MAPS.update(perm_maps("FAED", "faedgcbhi"))      # 1ª ocorrência do faed
MAPS.update(perm_maps("FREQD", "giehfacbd"))     # frequência decrescente do faed
MAPS.update(perm_maps("FREQA", "dbcafhei" "g"))  # frequência crescente
MAPS.update(perm_maps("KEYED", "fbcdaehig"))     # FUBCDORA.LETHINGKYMVPS.JQZXW restrito a a–i
MAPS.update(perm_maps("REV", "ihgfedcba"))       # i=1..a=9
MAPS["GDBL0"] = {c: v for c, v in zip("abcdefghi", [1, 2, 3, 4, 5, 6, 0, 8, 9])}
MAPS["GDBL7"] = {c: v for c, v in zip("abcdefghi", [1, 2, 3, 4, 5, 6, 7, 8, 9])}
ALPHA1 = {c: i + 1 for i, c in enumerate("abcdefghi")}   # só para controle/referência (família fechada)

# ------------------------------------------------------------ fontes e seleções
def primes_upto(n): return [p for p in range(n) if G.is_prime(p)]
def selections(n):
    """Índices selecionados de uma string de tamanho n (nome -> lista de índices)."""
    S = {"all": list(range(n))}
    P = primes_upto(n + 1)
    S["prime_b0"] = [p for p in P if p < n]                  # posição p (base 0) é prima
    S["prime_b1"] = [p - 1 for p in P if 1 <= p <= n]        # posição p (base 1) é prima
    S["nonprime_b0"] = [i for i in range(n) if i not in set(S["prime_b0"])]
    S["colored24"] = [i for i in sorted(G.BLUE_IDX + G.YELLOW_IDX) if i < n]
    S["colored25"] = [i for i in sorted(G.COLORED) if i < n]
    S["blue"] = [i for i in G.BLUE_IDX if i < n]
    S["yellow"] = [i for i in G.YELLOW_IDX if i < n]
    sp = [G.MATRIX_README[r][c] for r, c in G.SPIRAL]
    rm = [G.MATRIX_README[r][c] for r in range(14) for c in range(14)]
    for tag, bits in (("spiral", sp), ("rowmajor", rm)):
        m = min(n, 196)
        S[f"mat1_{tag}"] = [i for i in range(m) if bits[i] == 1]
        S[f"mat0_{tag}"] = [i for i in range(m) if bits[i] == 0]
    for k in range(2, 10):
        for r in range(k):
            S[f"mod{k}_{r}"] = list(range(r, n, k))
    return {k: v for k, v in S.items() if len(v) >= 8}

def sources(faed, dbbi):
    A, B = faed[:285], faed[285:]
    return {"faed": faed, "dbbi": dbbi, "faedA": A, "faedB": B, "faed_rev": faed[::-1], "dbbi_rev": dbbi[::-1],
            "faedBA": B + A, "faed+dbbi": faed + dbbi, "dbbi+faed": dbbi + faed}
SEL_SOURCES = ("faed", "dbbi", "faedA", "faedB")   # seleções só nestas (as outras são derivadas)

# ------------------------------------------------------------ materializações
def int_bytes(n):
    h = format(n, "x")
    if len(h) % 2: h = "0" + h
    return bytes.fromhex(h) if h != "0" else b"\x00"

def materialize(v):
    """v: lista de valores (0..9). Gera (nome, bytes)."""
    out = []
    dec = "".join(str(x) for x in v)
    out.append(("b10", int_bytes(int(dec))))                                     # z-method da página
    if max(v) <= 8:
        n = 0
        for x in v: n = n * 9 + x
        out.append(("b9", int_bytes(n)))
        out.append(("b9pair", bytes(v[i] * 9 + v[i + 1] for i in range(0, len(v) - 1, 2))))
    for o in (0, 1):
        out.append((f"nib{o}", bytes((v[i] << 4) | v[i + 1] for i in range(o, len(v) - 1, 2))))
        out.append((f"dec2_{o}", bytes(v[i] * 10 + v[i + 1] for i in range(o, len(v) - 1, 2))))
    for o in (0, 1, 2):
        out.append((f"dec3_{o}", bytes((v[i] * 100 + v[i + 1] * 10 + v[i + 2]) & 255 for i in range(o, len(v) - 2, 3))))
    par = [x & 1 for x in v]; thr = [1 if x >= 5 else 0 for x in v]
    for tag, bits in (("par", par), ("thr", thr)):
        for o in range(8):
            b = bits[o:]; b = b[:len(b) // 8 * 8]
            if len(b) >= 8:
                out.append((f"{tag}{o}", bytes(int("".join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))))
    return dec, out

def evaluate(dec, outs, ctx, target=TARGET):
    """Oráculos sobre uma leitura: privkey em todo offset (+reverso), printable, senhas."""
    hit = False
    best_pr = 0.0
    try_pw(dec.encode(), "dec_raw", ctx); try_pw(G.shahex(dec).encode(), "dec_sha", ctx)
    for name, B in outs:
        c = {**ctx, "mat": name}
        if len(B) >= 32:
            hit |= priv_scan(B, "priv", c, target); hit |= priv_scan(B[::-1], "priv_rev", c, target)
        pr = G.printable(B)
        if len(B) >= 8 and pr >= 0.85 and not name.startswith(("dec2", "b9pair")):  # ponytail: dec2/b9pair são ASCII por construção
            PRINT.append({**c, "printable": round(pr, 3), "len": len(B), "head": B[:60].decode("latin-1")})
            log({"kind": "printable", **c, "printable": round(pr, 3), "len": len(B), "head": B[:60].decode("latin-1")})
        best_pr = max(best_pr, pr if len(B) >= 8 else 0)
        try_pw(B, "raw", c); try_pw(B.hex().encode(), "hex", c); try_pw(G.shahex(B).encode(), "sha", c)
    return hit, best_pr

def windows(v, dec, ctx, target=TARGET):
    """Janelas de 32/64 símbolos (nibbles, senha) e 77 (base-10) / 81 (base-9) → privkey direta."""
    hit = False
    n = len(v)
    for w in (32, 64):
        for o in range(0, n - w + 1):
            seg = v[o:o + w]; s = dec[o:o + w]
            c = {**ctx, "mat": f"win{w}", "offset": o}
            try_pw(s.encode(), "win_raw", c); try_pw(G.shahex(s).encode(), "win_sha", c)
            if w == 64:
                B = bytes((seg[i] << 4) | seg[i + 1] for i in range(0, 64, 2))
                N["priv"] += 1
                try:
                    if PublicKey.from_valid_secret(B).format(False) == target:
                        HARD.append({**c, "how": "win64_nib", "priv_hex": B.hex()}); log({"kind": "HARD", **c, "priv_hex": B.hex()}); hit = True
                except Exception: pass
    for w, base in ((77, 10), (78, 10), (81, 9), (80, 9)):
        if base == 9 and max(v) > 8: continue
        for o in range(0, n - w + 1):
            seg = v[o:o + w]; num = 0
            for x in seg: num = num * base + x
            if not (0 < num < 2 ** 256): continue
            B = num.to_bytes(32, "big"); N["priv"] += 1
            try:
                if PublicKey.from_valid_secret(B).format(False) == target:
                    c = {**ctx, "mat": f"win{w}_b{base}", "offset": o}
                    HARD.append({**c, "how": "win_int", "priv_hex": B.hex()}); log({"kind": "HARD", **c, "priv_hex": B.hex()}); hit = True
            except Exception: pass
    return hit

# ------------------------------------------------------------ pipeline
def run(faed, dbbi, maps, tag, target=TARGET, do_windows=True):
    srcs = sources(faed, dbbi)
    nreads = 0; found = False; best = (0.0, None)
    for mname, mp in maps.items():
        for sname, s in srcs.items():
            sels = selections(len(s)) if sname in SEL_SOURCES else {"all": list(range(len(s)))}
            for selname, idx in sels.items():
                v = [mp[s[i]] for i in idx]
                ctx = {"tag": tag, "map": mname, "src": sname, "sel": selname, "n": len(v)}
                dec, outs = materialize(v)
                hit, pr = evaluate(dec, outs, ctx, target)
                if selname == "all" and do_windows and len(v) >= 32:
                    hit |= windows(v, dec, ctx, target)
                nreads += 1; found |= hit
                if pr > best[0]: best = (pr, ctx)
                log({"kind": "read", **ctx, "n_out": len(outs), "best_printable": round(pr, 3), "hit": hit})
        print(f"[{tag}] mapa {mname} ok  reads={nreads} aes={N['aes']} priv={N['priv']} soft={len(SOFT)} print={len(PRINT)} t={time.time()-T0:.0f}s", flush=True)
    return nreads, found, best

# ------------------------------------------------------------ controle positivo
def control():
    """Planta privkeys conhecidas em faed sintético sob CANON e recupera via
    (a) primos(b0)→base-10→janela de 32 B, (b) mod9_0→nib0, (c) janela de 81 dígitos base-9."""
    rnd = random.Random(1327)
    inv1 = {v: c for c, v in MAPS["CANON1"].items()}; inv0 = {v: c for c, v in MAPS["CANON0"].items()}
    P = primes_upto(570)                                   # 104 primos < 570
    # (a) 104 dígitos sem zero nas posições primas; chave esperada = últimos 32 B do inteiro
    digs = "".join(rnd.choice("123456789") for _ in range(len(P)))
    Ka = int_bytes(int(digs))[-32:]; tgta = PublicKey.from_valid_secret(Ka).format(False)
    fake = list("".join(rnd.choice("abcdefghi") for _ in range(570)))
    for p, d in zip(P, digs): fake[p] = inv1[int(d)]
    fake = "".join(fake)
    # (b) chave com nibbles 0..8 nos índices mod9_0 (64 símbolos) sob CANON0
    Kb = bytes((rnd.randrange(9) << 4) | rnd.randrange(9) for _ in range(32)); tgtb = PublicKey.from_valid_secret(Kb).format(False)
    fake3 = list("".join(rnd.choice("abcdefghi") for _ in range(570)))
    nibs = [x for b in Kb for x in (b >> 4, b & 15)]
    for i, d in enumerate(nibs): fake3[9 * i] = inv0[d]
    fake3 = "".join(fake3)
    # (c) chave em base-9 (81 dígitos) na janela [200,281) de outro faed sintético
    fake2 = list("".join(rnd.choice("abcdefghi") for _ in range(570)))
    Kc = rnd.getrandbits(255).to_bytes(32, "big"); n = int.from_bytes(Kc, "big"); b9 = []
    while n: b9.append(n % 9); n //= 9
    b9 = (b9 + [0] * 81)[:81][::-1]
    for i, d in enumerate(b9): fake2[200 + i] = inv0[d]
    fake2 = "".join(fake2); tgtc = PublicKey.from_valid_secret(Kc).format(False)
    h0 = len(HARD)
    run(fake, G.DBBI, {"CANON1": MAPS["CANON1"]}, "ctl_primes", target=tgta, do_windows=False)
    a = any(r.get("priv_hex") == Ka.hex() for r in HARD[h0:]); h1 = len(HARD)
    run(fake3, G.DBBI, {"CANON0": MAPS["CANON0"]}, "ctl_mod9", target=tgtb, do_windows=False)
    b = any(r.get("priv_hex") == Kb.hex() for r in HARD[h1:]); h2 = len(HARD)
    run(fake2, G.DBBI, {"CANON0": MAPS["CANON0"]}, "ctl_win81", target=tgtc, do_windows=True)
    c = any(r.get("priv_hex") == Kc.hex() for r in HARD[h2:])
    del HARD[h0:]
    log({"kind": "control", "primes_b10_recovered": a, "mod9_nib0_recovered": b, "win81_b9_recovered": c})
    print("CONTROLE: primos→b10", a, "| mod9_0→nib0", b, "| janela81 b9", c, flush=True)
    assert a and b and c, "controle positivo falhou"

if __name__ == "__main__":
    open(LOG, "w").close()
    log({"kind": "hypothesis", "text": "Mapa símbolo→valor de faed/dbbi é outro (14 mapas principiados); sob ele, "
         "uma leitura catalogada (b10/b9/pares/trios/nibbles/seleções/janelas/bits) dá privkey ou senha dos 3 blobs."})
    control()
    n_ctl = dict(N); soft_ctl = len(SOFT)
    N.clear(); SOFT.clear(); PRINT.clear(); SEEN_PW.clear()
    nreads, found, best = run(G.FAED, G.DBBI, MAPS, "real")
    real = {"reads": nreads, "aes": N["aes"], "priv": N["priv"], "soft": len(SOFT), "printable": len(PRINT), "best": best}
    # nulo casado: embaralhar faed e dbbi (preserva contagens de símbolos), mesmos mapas/leituras
    rnd = random.Random(42); nulls = []
    for k in range(2):
        f = list(G.FAED); rnd.shuffle(f); d = list(G.DBBI); rnd.shuffle(d)
        N.clear(); SOFT.clear(); PRINT.clear(); SEEN_PW.clear()
        run("".join(f), "".join(d), MAPS, f"null{k}")
        nulls.append({"aes": N["aes"], "priv": N["priv"], "soft": len(SOFT), "printable": len(PRINT)})
    summ = {"kind": "summary", "control": n_ctl, "real": real, "nulls": nulls, "hard": HARD, "t": round(time.time() - T0)}
    log(summ)
    json.dump(summ, open(os.path.join(SP, "symbol_map_variants_summary.json"), "w"), indent=1, default=str)
    print(json.dumps({k: v for k, v in summ.items() if k != "hard"}, default=str, indent=1))
    print("HARD:", HARD)
