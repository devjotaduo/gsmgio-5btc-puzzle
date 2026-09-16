# -*- coding: utf-8 -*-
"""Familia yinyang_interleave: metades do faed (A=faed[:285], B=faed[285:]) e outros pares de canais
combinados por INTERCALACAO / CONCATENACAO de digitos (nao aritmetica modular, ja fechada)."""
import sys, os, random, itertools, json, time, math
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = os.path.join(SP, "yinyang_interleave.jsonl")
HYP = ("'half and better half / yinyang' = A=faed[:285] e B=faed[285:] (tambem impar/par, faed/reverso, dbbi/faed) "
       "sao dois canais de um codigo de 2 digitos por simbolo: juntam-se por intercalacao A0B0A1B1, par 10A+B, "
       "soma/produto/|dif| concatenados, base-19/81, ou (linha,coluna) de quadrado 9x9 keyed; a string resultante "
       "decodifica por z-method/base9/checkerboard/Bifid/ASCII ou hasheia para senha/privkey.")
PHRASES = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "cosmicduality", "yinyang", "salphaseion"]
P322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
B81 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,;:!?-_/+=@#$%&*()"[:81]
assert len(B81) == 81 and len(set(B81)) == 81
STATS = {"n": 0}
RES = {"hard": [], "soft": [], "readable": []}

# ---------------------------------------------------------------- estatistica: dependencia conjunta 9x9
def chi2_9x9(X, Y):
    n = len(X); tab = [[0] * 9 for _ in range(9)]
    for x, y in zip(X, Y): tab[x][y] += 1
    rs = [sum(r) for r in tab]; cs = [sum(tab[r][c] for r in range(9)) for c in range(9)]
    return sum((tab[r][c] - rs[r] * cs[c] / n) ** 2 / (rs[r] * cs[c] / n) for r in range(9) for c in range(9)
               if rs[r] and cs[c])
def joint_test(name, X, Y, k=200):
    random.seed(42); obs = chi2_9x9(X, Y); Y2 = list(Y); null = []
    for _ in range(k):
        random.shuffle(Y2); null.append(chi2_9x9(X, Y2))
    mu = sum(null) / k; sd = (sum((v - mu) ** 2 for v in null) / (k - 1)) ** 0.5
    z = (obs - mu) / sd
    r = {"joint": name, "n": len(X), "chi2": round(obs, 2), "null_mean": round(mu, 2), "null_sd": round(sd, 2),
         "z": round(z, 2), "p_emp": round(sum(v >= obs for v in null) / k, 3)}
    G.jsonl(LOG, r); print(r); return r

# ---------------------------------------------------------------- construcoes
def pair_sources(base):
    f = [ord(c) - 97 + base for c in G.FAED]; d = [ord(c) - 97 + base for c in G.DBBI]
    return {"halves": (f[:285], f[285:]), "odd_even": (f[1::2], f[0::2]), "faed_rev": (f, f[::-1]),
            "dbbi_faedtail": (d, f[-91:]), "faedhead_dbbi": (f[:91], d)}
def big2bytes(n):
    h = format(n, "x"); h = "0" + h if len(h) % 2 else h
    return bytes.fromhex(h)
def build(base):
    """-> (digit_strings: name->list[int], byte_strings: name->bytes, text_strings: name->str)"""
    D, Bt, T = {}, {}, {}
    for pn, (X, Y) in pair_sources(base).items():
        p = f"b{base}_{pn}"
        D[p + "_zipXY"] = [v for xy in zip(X, Y) for v in xy]
        D[p + "_zipYX"] = [v for xy in zip(Y, X) for v in xy]
        D[p + "_sumcat"] = [int(c) for x, y in zip(X, Y) for c in str(x + y)]
        D[p + "_prodcat"] = [int(c) for x, y in zip(X, Y) for c in str(x * y)]
        D[p + "_absdiff"] = [abs(x - y) for x, y in zip(X, Y)]
        pairs = [10 * x + y for x, y in zip(X, Y)]
        Bt[p + "_pair_ascii"] = bytes(pairs)
        T[p + "_pair_mod26"] = "".join(AZ[v % 26] for v in pairs)
        T[p + "_pair_a1z26"] = "".join(AZ[v - 1] if 1 <= v <= 26 else "?" for v in pairs)
        T[p + "_sum_a1z26"] = "".join(AZ[x + y - 1] if 1 <= x + y <= 26 else "?" for x, y in zip(X, Y))
        T[p + "_prod_mod26"] = "".join(AZ[(x * y) % 26] for x, y in zip(X, Y))
        # bases posicionais (big-int -> bytes), como o z-method da pagina
        Bt[p + "_base19_sum"] = big2bytes(sum((x + y) * 19 ** i for i, (x, y) in enumerate(zip(X, Y))))
        Bt[p + "_base19_sum_rev"] = big2bytes(sum((x + y) * 19 ** i for i, (x, y) in enumerate(zip(X[::-1], Y[::-1]))))
        Bt[p + "_base81_9XY"] = big2bytes(sum(((x - base) * 9 + (y - base)) * 81 ** i for i, (x, y) in enumerate(zip(X, Y))))
        Bt[p + "_base81_9XY_rev"] = big2bytes(sum(((x - base) * 9 + (y - base)) * 81 ** i for i, (x, y) in enumerate(zip(X[::-1], Y[::-1]))))
        Bt[p + "_base81_9YX"] = big2bytes(sum(((y - base) * 9 + (x - base)) * 81 ** i for i, (x, y) in enumerate(zip(X, Y))))
        if base == 1:  # quadrado 9x9: indices identicos p/ a=0, evita duplicar
            for ph in PHRASES + ["AZaz09"]:
                sq = G.keyed_alphabet("" if ph == "AZaz09" else ph, base=B81, merge_j=False)
                T[p + f"_sq9_{ph}_rowXcolY"] = "".join(sq[(x - 1) * 9 + (y - 1)] for x, y in zip(X, Y))
                T[p + f"_sq9_{ph}_rowYcolX"] = "".join(sq[(y - 1) * 9 + (x - 1)] for x, y in zip(X, Y))
    return D, Bt, T

# ---------------------------------------------------------------- decoders de strings de digitos
def alpha_for(name, uni):
    if name == "p322": return P322 if uni == "0123456789" else P322.replace(".", "")[:25]
    if name == "canon": return G.CANON if uni == "123456789" else G.keyed_alphabet("DBIFHCEGA", base=AZ, merge_j=False)
    if uni == "123456789": return G.keyed_alphabet(name, base="ABCDEFGHIKLMNOPQRSTUVWXYZ")
    return G.keyed_alphabet(name, base=AZ, merge_j=False)
CB_ALPHAS = ["p322", "canon"] + PHRASES
def dec_digits(digs):
    out = []
    try: out.append(("zmethod", G.z_method(digs)))
    except Exception: pass
    if max(digs) <= 8: out.append(("base9", big2bytes(int("".join(map(str, digs)), 9))))
    if min(digs) >= 1 and max(digs) <= 9: out.append(("base9_m1", big2bytes(int("".join(str(v - 1) for v in digs), 9))))
    s = "".join(map(str, digs))
    for off in (0, 1):
        ch = [int(s[i:i + 2]) for i in range(off, len(s) - 1, 2)]
        out.append((f"a1z26_off{off}", "".join(AZ[v - 1] if 1 <= v <= 26 else "?" for v in ch)))
        out.append((f"ascii2_off{off}", bytes(ch)))
    letters = "".join(AZ[v - 1] for v in digs if 1 <= v <= 9)
    if len(letters) >= 40:
        for per in (len(letters), 285, 570, 5, 19):
            if per <= len(letters):
                out.append((f"bifid5_canon_p{per}", G.bifid(letters, G.CANON, per, 5)))
                out.append((f"bifid3_canon9_p{per}", G.bifid(letters, "DBIFHCEGA", per, 3)))
    return out
def dec_checker(digs):
    unis = ["123456789", "0123456789"] if min(digs) >= 1 else ["0123456789"]
    for uni in unis:
        U = [int(c) for c in uni]
        for an in CB_ALPHAS:
            alpha = alpha_for(an, uni)
            for e1, e2 in itertools.permutations(U, 2):
                yield f"cb_{an}_u{uni[0]}_e{e1}{e2}", G.checkerboard_decode(digs, alpha, (e1, e2), uni)

# ---------------------------------------------------------------- detectores
def deep_pw(pw, how, src):
    """sha256hex -> senha nos 3 blobs (KDF SHA256) e -> privkey."""
    for b in ("SMALL", "COSMIC", "TAIL32"):
        for kdf, p in G.aes_try(pw, b, kdf="sha256"):
            rec = {"kind": "aes", "pw": pw, "blob": b, "kdf": kdf, "how": how, "src": src,
                   "printable": round(G.printable(p), 3), "hex": p.hex()}
            (RES["hard"] if G.semantic(p) else RES["soft"]).append(rec)
    r = G.priv_hit(bytes.fromhex(pw))
    if r: RES["hard"].append({"kind": "privkey_sha", "pw": pw, "how": how, "src": src, "hit": str(r)})
def check(val, how, src, deep=True):
    STATS["n"] += 1
    if isinstance(val, bytes):
        b = val; t = b.decode("latin-1")
        for h in G.fast_priv_scan(b, how): RES["hard"].append({"kind": "privkey_raw", "how": how, "src": src, "hit": str(h)})
        pr = G.printable(b)
        if pr >= 0.85:
            sem = G.semantic_text(t)
            RES["readable" if not sem else "hard"].append({"kind": "printable_bytes" if not sem else "semantic_bytes",
                                                           "how": how, "src": src, "printable": round(pr, 3),
                                                           "score": round(G.english_score(t), 3), "hex": b.hex()[:120]})
        pw = G.shahex(b)
    else:
        t = val; b = None; pw = G.shahex(t)
    letters = "".join(c for c in t.upper() if "A" <= c <= "Z")
    sc = G.english_score(letters) if len(letters) >= 20 else -99
    if b is None and G.semantic_text(t):
        RES["readable"].append({"kind": "semantic_text", "how": how, "src": src, "score": round(sc, 3),
                                "words6": G.word_hits(letters, 6)[:8], "wif": G.wif_candidates(t)[:3],
                                "hex64": G.hex64_candidates(t)[:3], "text": t[:100]})
    if deep or sc > -5.0:
        deep_pw(pw, how, src)
        if letters and letters != t: deep_pw(G.shahex(letters), how + "_letters", src)
    return {"score": round(sc, 3), "how": how, "src": src, "text": t[:80]}

def run_digits(name, digs):
    best = None
    s = "".join(map(str, digs)); STATS["n"] += 1
    deep_pw(G.shahex(s), "digits_sha", name)
    for b in ("SMALL", "COSMIC", "TAIL32"):   # a string crua tambem como senha
        for kdf, p in G.aes_try(s, b, kdf="sha256"):
            (RES["hard"] if G.semantic(p) else RES["soft"]).append({"kind": "aes", "pw": s[:40] + "...", "blob": b, "kdf": kdf,
                                                                    "how": "digits_raw_pw", "src": name, "hex": p.hex()})
    for how, val in dec_digits(digs):
        info = check(val, how, name, deep=True)
        if best is None or info["score"] > best["score"]: best = info
    for how, val in dec_checker(digs):
        info = check(val, how, name, deep=False)
        if best is None or info["score"] > best["score"]: best = info
    return best

# ---------------------------------------------------------------- controle positivo + nulo
def cb_encode(msg, alpha, uni, esc):
    top = [d for d in uni if int(d) not in esc]; enc = {}; k = 0
    for d in top: enc[alpha[k]] = str(d); k += 1
    for e in esc:
        for d in uni: enc[alpha[k]] = f"{e}{d}"; k += 1
    return [int(c) for c in "".join(enc[c] for c in msg)]
def control():
    n0 = STATS["n"]; ok = {}
    msg = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVEANDPROSPERINTHEMATRIXFOREVERANDEVER"
    digs = cb_encode(msg, P322, "0123456789", (1, 4))[:570]
    A, B = digs[0::2], digs[1::2]                       # metades = canais par/impar do fluxo
    zipped = [v for xy in zip(A, B) for v in xy]; assert zipped == digs[:len(zipped)]
    b = run_digits("CONTROL_cb_zip", zipped)
    ok["checkerboard_zip"] = b["how"] == "cb_p322_u0_e14" and b["text"].startswith("INCASEYOU")
    # z-method: texto -> digitos decimais -> canais
    txt = b"the private key belongs to half and better half; they also need funds to live. seed planted: yinyang, ok"
    ds = [int(c) for c in str(int(txt.hex(), 16))]
    A, B = ds[0::2], ds[1::2]; zipped = [v for xy in itertools.zip_longest(A, B) for v in xy if v is not None]
    assert zipped == ds; before = len(RES["hard"]); run_digits("CONTROL_z_zip", zipped)
    ok["zmethod_zip"] = any(h["src"] == "CONTROL_z_zip" and h["how"] == "zmethod" for h in RES["hard"][before:])
    # quadrado 9x9 keyed: texto -> (linha,coluna) -> canais A/B -> reconstrucao
    sq = G.keyed_alphabet("cosmicduality", base=B81, merge_j=False)
    m = "The private keys belong to half and better half 2024"
    X = [sq.index(c) // 9 + 1 for c in m]; Y = [sq.index(c) % 9 + 1 for c in m]
    rec = "".join(sq[(x - 1) * 9 + (y - 1)] for x, y in zip(X, Y)); ok["sq9_roundtrip"] = rec == m
    ok["sq9_semantic_text"] = bool(G.semantic_text(rec))
    # pares 10A+B -> ASCII
    pa = [10 * (ord(c) // 10) + ord(c) % 10 for c in "HALF AND BETTER HALF NEED FUNDS"]
    ok["pair_ascii"] = G.semantic_text(bytes(pa).decode()) and all(0 <= v <= 99 for v in pa)
    # limpar hits do controle
    for k in RES: RES[k] = [x for x in RES[k] if not str(x.get("src", "")).startswith("CONTROL")]
    G.jsonl(LOG, {"control": ok, "n_tests": STATS["n"] - n0}); print("CONTROLE:", ok)
    assert all(ok.values()), ok
    return STATS["n"] - n0
def null_model(k=20):
    """20 embaralhados de zipXY(a=1): distribuicao do melhor score e n de semantic_text por string."""
    random.seed(1327); base = build(1)[0]["b1_halves_zipXY"]; out = []
    for i in range(k):
        d = base[:]; random.shuffle(d)
        before = len(RES["readable"]); b = run_digits(f"NULL{i}", d)
        out.append({"best": b["score"], "n_semantic": len(RES["readable"]) - before})
        RES["readable"] = RES["readable"][:before]
    r = {"null": {"k": k, "best_max": max(o["best"] for o in out), "best_mean": round(sum(o["best"] for o in out) / k, 3),
                  "semantic_per_string_max": max(o["n_semantic"] for o in out),
                  "semantic_per_string_mean": round(sum(o["n_semantic"] for o in out) / k, 2)}}
    G.jsonl(LOG, r); print(r); return r["null"]

if __name__ == "__main__":
    t0 = time.time(); open(LOG, "w").close()
    G.jsonl(LOG, {"family": "yinyang_interleave", "hypothesis": HYP})
    f0 = [ord(c) - 97 for c in G.FAED]; d0 = [ord(c) - 97 for c in G.DBBI]
    joints = [joint_test("A[i],B[i] halves", f0[:285], f0[285:]),
              joint_test("faed[2i],faed[2i+1]", f0[0::2], f0[1::2]),
              joint_test("dbbi[i],faed[i]", d0, f0[:91]),
              joint_test("dbbi[i],faed[-91+i]", d0, f0[-91:]),
              joint_test("faed[i],faed[569-i]", f0[:285], f0[::-1][:285])]
    n_ctrl = control(); null = null_model()
    n_null = STATS["n"]
    bests = []; seen = set()
    for base in (0, 1):
        D, Bt, T = build(base)
        for name, digs in D.items():
            key = tuple(digs)
            if key in seen: continue
            seen.add(key); b = run_digits(name, digs); bests.append(b)
            G.jsonl(LOG, {"string": name, "len": len(digs), "best": b})
            print(name, len(digs), b["score"], b["how"], f"{time.time()-t0:.0f}s", flush=True)
        for name, val in list(Bt.items()) + list(T.items()):
            key = val if isinstance(val, bytes) else val.encode()
            if key in seen: continue
            seen.add(key); b = check(val, "direct", name, deep=True); bests.append(b)
            G.jsonl(LOG, {"string": name, "len": len(val), "best": b})
    bests.sort(key=lambda x: -x["score"])
    summary = {"n_tests": STATS["n"], "n_control": n_ctrl, "n_null": n_null, "n_strings": len(seen), "joints": joints,
               "null": null, "hard": RES["hard"], "soft": RES["soft"][:30], "n_soft": len(RES["soft"]),
               "readable": sorted(RES["readable"], key=lambda x: -x.get("score", -99))[:30], "n_readable": len(RES["readable"]),
               "top5": bests[:5], "secs": round(time.time() - t0)}
    G.jsonl(LOG, {"summary": summary})
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:12000])
