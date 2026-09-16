# -*- coding: utf-8 -*-
"""Familia halfhalf_arith: metades do faed combinadas aritmeticamente -> string de digitos -> decoders."""
import sys, os, hashlib, random, itertools, json, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = os.path.join(SP, "halfhalf_arith.jsonl")
HYP = ("Cosmic Duality = metades do faed (d[i], d[285+i]) combinadas aritmeticamente (+,-,rev-,|.|,x) mod 9/10, "
       "com a=0..8 ou 1..9, 0 mantido ou 0->9, tambem A op rev(B), rev(A) op B, e faed op dbbi; a string de "
       "digitos resultante decodifica por z-method / pares a1z26-ASCII / base-9 / checkerboard / Bifid.")

OPS = {"add": lambda a, b: a + b, "sub": lambda a, b: a - b, "rsub": lambda a, b: b - a,
       "abs": lambda a, b: abs(a - b), "mul": lambda a, b: a * b}
PHRASES = {"p322": "FUBCDORA.LETHINGKYMVPS.JQZXW", "matrixsumlist": None, "lastwordsbeforearchichoice": None,
           "thispassword": None, "yellowblueprimes": None, "salphaseion": None, "cosmicduality": None, "AZ": ""}
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def alpha_for(name, universe):
    """Alfabeto de checkerboard p/ universo 1-9 (25 slots) ou 0-9 (28 slots)."""
    if name == "p322":
        s = PHRASES[name]
        return s if universe == "0123456789" else s.replace(".", "")[:25]  # ponytail: 1-9 perde o W
    phrase = "" if name == "AZ" else name
    if universe == "123456789":
        return G.keyed_alphabet(phrase, base="ABCDEFGHIKLMNOPQRSTUVWXYZ", merge_j=True)
    return G.keyed_alphabet(phrase, base=AZ, merge_j=False)  # 26 + 2 '.'

def build_strings():
    """Gera todas as strings de digitos da familia. Retorna dict nome -> list[int]."""
    out = {}
    F = G.FAED; D = G.DBBI
    for base in (0, 1):
        f = [ord(c) - 97 + base for c in F]; d = [ord(c) - 97 + base for c in D]
        A, B = f[:285], f[285:]
        pairs = {"A_B": (A, B), "A_revB": (A, B[::-1]), "revA_B": (A[::-1], B),
                 "faed_dbbi570": (f, [d[k % 91] for k in range(570)]), "faed91_dbbi": (f[:91], d)}
        for pname, (X, Y) in pairs.items():
            for oname, op in OPS.items():
                for mod in (9, 10):
                    raw = [op(x, y) % mod for x, y in zip(X, Y)]
                    variants = {"z0": raw}
                    if 0 in raw: variants["z9"] = [9 if v == 0 else v for v in raw]
                    for vname, digs in variants.items():
                        out[f"b{base}_{pname}_{oname}_m{mod}_{vname}"] = digs
    # dedupe por conteudo
    seen = {}; uniq = {}
    for k, v in out.items():
        key = tuple(v)
        if key in seen: continue
        seen[key] = k; uniq[k] = v
    return uniq

# ---------------------------------------------------------------- decoders (cada um -> lista de (how, text|bytes))
def dec_z(digs):
    try: return [("zmethod", G.z_method(digs))]
    except Exception: return []
def dec_pairs(digs):
    s = "".join(map(str, digs)); out = []
    for off in (0, 1):
        ch = [int(s[i:i + 2]) for i in range(off, len(s) - 1, 2)]
        out.append((f"a1z26_off{off}", "".join(chr(64 + v) if 1 <= v <= 26 else "?" for v in ch)))
        out.append((f"ascii2_off{off}", bytes(ch)))
    for off in (0, 1, 2):
        ch = [int(s[i:i + 3]) for i in range(off, len(s) - 2, 3)]
        out.append((f"ascii3_off{off}", bytes(v & 255 for v in ch)))
    return out
def dec_base9(digs):
    out = []
    if max(digs) <= 8:
        n = int("".join(map(str, digs)), 9); h = format(n, "x"); h = "0" + h if len(h) % 2 else h
        out.append(("base9", bytes.fromhex(h)))
    if min(digs) >= 1 and max(digs) <= 9:
        n = int("".join(str(v - 1) for v in digs), 9); h = format(n, "x"); h = "0" + h if len(h) % 2 else h
        out.append(("base9_minus1", bytes.fromhex(h)))
    return out
def dec_checker(digs):
    out = []
    universes = ["123456789"] if min(digs) >= 1 else ["0123456789"]
    if min(digs) >= 1: universes.append("0123456789")  # tambem tabela 0-9 mesmo sem zeros
    for uni in universes:
        U = [int(c) for c in uni]
        for name in PHRASES:
            alpha = alpha_for(name, uni)
            for e1, e2 in itertools.permutations(U, 2):
                t = G.checkerboard_decode(digs, alpha, (e1, e2), uni)
                out.append((f"cb_{name}_u{uni[0]}_e{e1}{e2}", t))
    return out
def dec_bifid(digs):
    out = []
    letters = "".join(chr(64 + v) for v in digs if 1 <= v <= 9)
    if len(letters) < 20: return out
    for per in (len(letters), 3, 5, 15, 19, 57, 95):
        out.append((f"bifid5_canon_p{per}", G.bifid(letters, G.CANON, per, 5)))
        for an, alpha in (("abc", "ABCDEFGHI"), ("canon9", "DBIFHCEGA")):
            out.append((f"bifid3_{an}_p{per}", G.bifid(letters, alpha, per, 3)))
    return out

# ---------------------------------------------------------------- detectores
def check(text_or_bytes, how, sname, stats, deep):
    """Retorna dict com score/hits; incrementa stats. deep=True roda sha256->senha/privkey."""
    hard, soft = [], []
    if isinstance(text_or_bytes, bytes):
        b = text_or_bytes; t = b.decode("latin-1")
        for h in G.scan_priv(b, how): hard.append({"kind": "privkey", "how": how, "src": sname, "hit": str(h)})
    else:
        t = text_or_bytes; b = None
    letters = "".join(c for c in t.upper() if "A" <= c <= "Z")
    sc = G.english_score(letters) if len(letters) >= 20 else -99
    if b is not None and G.semantic(b):
        # ponytail: ascii2/ascii3 sao imprimiveis por construcao -> exigir ingles ou WIF/hex64
        real = (not how.startswith("ascii")) or sc > -4.5 or G.WIF_RE.search(t) or G.HEX64_RE.search(t)
        (hard if real else soft).append({"kind": "semantic_bytes" if real else "printable_by_construction",
                                         "how": how, "src": sname, "score": round(sc, 3), "hex": b.hex()[:64]})
    wh = [w for w in G.word_hits(letters, 6)] if sc > -5.5 else []
    if deep or sc > -5.2:
        pw_forms = [G.shahex(letters) if letters else None, G.shahex(b) if b else None]
        for pw in {p for p in pw_forms if p}:
            h, s = G.try_password_all(pw)
            for x in h: hard.append({"kind": "aes_open", "pw": pw, "how": how, "src": sname, **x})
            for x in s: soft.append({"kind": "aes_pad", "pw": pw, "how": how, "src": sname, **x})
            r = G.priv_hit(bytes.fromhex(pw))
            if r: hard.append({"kind": "privkey_sha", "pw": pw, "how": how, "src": sname, "hit": str(r)})
        stats["deep"] += 1
    stats["n"] += 1
    return {"score": sc, "words6": wh, "text": (t[:120]), "how": how, "src": sname}, hard, soft

def run_string(sname, digs, stats, results):
    decs = dec_z(digs) + dec_pairs(digs) + dec_base9(digs) + dec_bifid(digs)
    # a propria string de digitos como senha / privkey
    s = "".join(map(str, digs))
    for pw in (s, G.shahex(s)):
        h, so = G.try_password_all(pw)
        for x in h: results["hard"].append({"kind": "aes_open", "pw": pw, "how": "digits_as_pw", "src": sname, **x})
        for x in so: results["soft"].append({"kind": "aes_pad", "pw": pw, "how": "digits_as_pw", "src": sname, **x})
        stats["n"] += 1
    r = G.priv_hit(G.sha(s))
    if r: results["hard"].append({"kind": "privkey_sha_digits", "src": sname, "hit": str(r)})
    best = None
    for how, val in decs:
        info, hard, soft = check(val, how, sname, stats, deep=True)
        results["hard"] += hard; results["soft"] += soft
        if best is None or info["score"] > best["score"]: best = info
    for how, val in dec_checker(digs):
        info, hard, soft = check(val, how, sname, stats, deep=False)
        results["hard"] += hard; results["soft"] += soft
        if best is None or info["score"] > best["score"]: best = info
        if info["score"] > -4.5 or len(info["words6"]) >= 3: results["readable"].append(info)
    return best

# ---------------------------------------------------------------- controle positivo
def control():
    """Cifra um ingles conhecido com a construcao (A+B mod 10 = digitos) e verifica recuperacao."""
    random.seed(1327)
    stats = {"n": 0, "deep": 0}; res = {"hard": [], "soft": [], "readable": []}
    # (1) checkerboard p322, escapes (1,4), universo 0-9
    msg = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVEANDPROSPERINTHEMATRIX"
    alpha = PHRASES["p322"]; uni = "0123456789"; esc = (1, 4)
    top = [d for d in uni if int(d) not in esc]; enc = {}; k = 0
    for d in top: enc[alpha[k]] = str(d); k += 1
    for e in esc:
        for d in uni: enc[alpha[k]] = f"{e}{d}"; k += 1
    digs = [int(c) for c in "".join(enc[c] for c in msg)][:285]
    B = [random.randrange(10) for _ in digs]; A = [(x - y) % 10 for x, y in zip(digs, B)]
    comb = [(a + b) % 10 for a, b in zip(A, B)]
    assert comb == digs
    best = run_string("CONTROL_cb", comb, stats, res)
    ok1 = best["how"] == "cb_p322_u0_e14" and best["text"].startswith("INCASEYOU") and best["score"] > -4.5
    # (2) z-method: texto ascii -> hex -> decimal -> 285 digitos
    txt = b"the private key belongs to half and better half; they also need funds to live. seed planted: yinyang"
    n = int(txt.hex(), 16); ds = [int(c) for c in str(n)]
    B = [random.randrange(9) for _ in ds]; A = [(x - y) % 9 for x, y in zip(ds, B)]  # mod 9 nao cobre digito 9!
    B = [random.randrange(10) for _ in ds]; A = [(x - y) % 10 for x, y in zip(ds, B)]
    comb = [(a + b) % 10 for a, b in zip(A, B)]
    res2 = {"hard": [], "soft": [], "readable": []}
    run_string("CONTROL_z", comb, stats, res2)
    ok2 = any(h["kind"] == "semantic_bytes" and h["how"] == "zmethod" for h in res2["hard"])
    G.jsonl(LOG, {"control": {"checkerboard_recovered": ok1, "cb_best": best, "zmethod_recovered": ok2}})
    print("CONTROLE checkerboard:", ok1, round(best["score"], 3), best["text"][:40]); print("CONTROLE z-method:", ok2)
    assert ok1 and ok2
    return stats["n"]

def null_baseline(k=6, L=285):
    """Max score de checkerboard em strings aleatorias -> calibra o limiar."""
    random.seed(7); mx = []
    for _ in range(k):
        digs = [random.randrange(1, 10) for _ in range(L)]
        stats = {"n": 0, "deep": 0}; res = {"hard": [], "soft": [], "readable": []}
        b = run_string("NULL", digs, stats, res); mx.append(round(b["score"], 3))
    G.jsonl(LOG, {"null_baseline_max_scores": mx, "len": L})
    print("NULL max scores:", mx)
    return mx

if __name__ == "__main__":
    t0 = time.time(); open(LOG, "w").close()
    G.jsonl(LOG, {"family": "halfhalf_arith", "hypothesis": HYP})
    n_ctrl = control(); null = null_baseline() + null_baseline(L=91)
    strings = build_strings(); print("strings unicas:", len(strings))
    stats = {"n": 0, "deep": 0}; results = {"hard": [], "soft": [], "readable": []}
    bests = []
    for i, (sname, digs) in enumerate(strings.items()):
        b = run_string(sname, digs, stats, results); bests.append(b)
        G.jsonl(LOG, {"string": sname, "len": len(digs), "best": b})
        if i % 20 == 0: print(i, sname, round(b["score"], 3), b["how"], f"{time.time()-t0:.0f}s", flush=True)
    bests.sort(key=lambda x: -x["score"])
    summary = {"n_tests": stats["n"], "n_deep": stats["deep"], "n_control": n_ctrl, "null_max": max(null),
               "hard": results["hard"], "soft": results["soft"], "readable": results["readable"][:50],
               "top5": bests[:5]}
    G.jsonl(LOG, {"summary": summary})
    summary["soft"]=[x for x in summary["soft"] if x["kind"]!="printable_by_construction"]
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:9000])
