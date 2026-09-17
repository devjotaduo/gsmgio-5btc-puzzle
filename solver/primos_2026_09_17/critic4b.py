# -*- coding: utf-8 -*-
"""Critico, parte 2.
(A) re-varredura de TODOS os paddings gravados (agentes 1,3,4 + agente paralelo Node) com o oraculo completo
    (semantic/nested/ebcdic/WIF/hex64/privkey em toda janela) + cadeia aninhada (plaintext como senha dos 3 blobs);
(B) nulo family-wise do poly3 (agente 1: 4 configs p<0,005 vs 1,1 esperado);
(D) faed sob todas as regras x/x+sufixo em primos logicos (confirma agente 2);
(E) p post hoc das somas parciais da matriz atingirem 60/61 (agente 3) com look-elsewhere."""
import sys, os, json, random, math, itertools
from collections import Counter
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
HERE = os.path.dirname(os.path.abspath(__file__)); SP = os.path.dirname(HERE)
sys.path.insert(0, HERE); from critic4 import segment, SCHEMES, L9, PR
WORK = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work"
LOG = os.path.join(HERE, "critic4b.jsonl"); out = {}

# ---------------- (A) paddings
plains = {}
def add(hx, src):
    if hx and hx not in plains: plains[hx] = src
for o in json.load(open(os.path.join(SP, "resid_decoders", "soft_aes_paddings.json"), encoding="utf-8")): add(o.get("hex"), "ag1")
for line in open(os.path.join(SP, "matrixsumlist_struct", "paddings.jsonl"), encoding="utf-8"):
    try: add(json.loads(line).get("hex"), "ag3")
    except Exception: pass
for line in open(os.path.join(SP, "marcadores", "marcadores.jsonl"), encoding="utf-8"):
    try:
        o = json.loads(line)
        if "soft" in o: add(o["soft"].get("hex"), "ag4")
    except Exception: pass
for f in ("prime_host_delta_2026-09-17", "prime_host_l84_2026-09-17"):
    for o in json.load(open(os.path.join(WORK, f, "run1", "padding.json"), encoding="utf-8")): add(o.get("hex"), "node")
src_counts = Counter(plains.values()); print("(A) paddings distintos:", len(plains), dict(src_counts))
hard = []; stats = {"max_printable": 0, "max_ebcdic": 0, "nested": 0, "salted_anywhere": 0, "wif": 0, "hex64": 0, "priv": 0,
                    "chain_paddings": 0, "chain_hard": 0, "n_chain_aes": 0}
best_text = []
for hx, src in plains.items():
    p = bytes.fromhex(hx)
    pr = G.printable(p); eb = G.ebcdic_sig(p)
    stats["max_printable"] = max(stats["max_printable"], pr); stats["max_ebcdic"] = max(stats["max_ebcdic"], eb)
    if G.nested_blob(p): stats["nested"] += 1; hard.append((src, "nested", hx[:40]))
    if b"Salted__" in p or b"U2FsdGVk" in p: stats["salted_anywhere"] += 1; hard.append((src, "salted_anywhere", hx[:40]))
    t = p.decode("latin-1")
    if G.wif_candidates(t): stats["wif"] += 1; hard.append((src, "wif", hx[:40]))
    if G.hex64_candidates(t): stats["hex64"] += 1; hard.append((src, "hex64", hx[:40]))
    if G.semantic(p): hard.append((src, "semantic", hx[:40]))
    if len(p) >= 32 and G.fast_priv_scan(p, src): stats["priv"] += 1; hard.append((src, "priv", hx[:40]))
    # cadeia aninhada: plaintext como senha (cru, hex, sha256hex) nos 3 blobs x 2 KDF
    for pw in (p, hx.encode(), G.shahex(p).encode()):
        h, s = G.try_password_all(pw); stats["n_chain_aes"] += 6
        stats["chain_paddings"] += len(s)
        if h: stats["chain_hard"] += 1; hard.append((src, "chain_hard", hx[:40], [x["head"] for x in h]))
    letters = "".join(c for c in t.upper() if "A" <= c <= "Z")
    if len(letters) >= 12: best_text.append((round(G.english_score(letters), 3), src, letters[:60]))
best_text.sort(reverse=True)
out["A_paddings"] = {"n_distintos": len(plains), "fontes": dict(src_counts), "stats": stats, "hard": hard[:20], "top_english_letras": best_text[:5]}
print("(A)", json.dumps(out["A_paddings"], ensure_ascii=False))

# ---------------- (B) poly3 family-wise
resid84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"; resid83 = resid84[:-1]
def dig(s): return [ord(c) - 96 for c in s]
COORD = {"d%3": lambda d: d % 3, "(d-1)%3": lambda d: (d - 1) % 3, "(d-1)//3": lambda d: ((d - 1) // 3) % 3}
A9 = {"ETAOINSHR": "ETAOINSHR", "ETAOINSHR@dbifhcega": "".join("ETAOINSHR"["dbifhcega".index(c)] for c in "abcdefghi")}
def poly_pairs(s, f, g, alpha, off):
    d = dig(s)[off:]; d = d[:len(d) - len(d) % 2]
    return "".join(alpha[f(d[i]) * 3 + g(d[i + 1])] for i in range(0, len(d), 2))
CFGS = [(off, f, g, a) for off in (0, 1) for f in COORD.values() for g in COORD.values() for a in A9.values()]
def fam_best(s): return max(G.english_score(poly_pairs(s, f, g, a, off)) for off, f, g, a in CFGS)
B = {}
for name, inp in (("R84", resid84), ("R83", resid83), ("R84r", resid84[::-1]), ("R83r", resid83[::-1])):
    real = fam_best(inp); r = random.Random(11); ch = list(inp); null = []
    for _ in range(500): r.shuffle(ch); null.append(fam_best("".join(ch)))
    mu = sum(null)/len(null); sd = (sum((v-mu)**2 for v in null)/len(null))**.5
    B[name] = {"real_best": round(real, 3), "null_mu": round(mu, 3), "null_sd": round(sd, 3), "p_familywise": sum(v >= real for v in null)/len(null), "n_cfg": len(CFGS)}
out["B_poly3_familywise"] = B; print("(B)", json.dumps(B))

# ---------------- (D) faed sob regras x / x+sufixo em primos logicos (1-based e 0-based)
D = {}
for x in L9:
    for sn, suf in [("none", ""), ("any", L9)] + [(y, y) for y in L9]:
        for scn in ("prime1", "prime0"):
            c = segment(G.FAED, x, suf, SCHEMES[scn])[0]
            if c: D[f"{x}/{sn}/{scn}"] = c
out["D_faed_hits"] = D; print("(D) faed hits:", D)

# ---------------- (E) somas parciais da matriz atingem 60/61: p com look-elsewhere
rs = G.row_sums(G.MATRIX_README); cs = G.col_sums(G.MATRIX_README)
def cums(v): return set(itertools.accumulate(v))
def hits(M):
    r = [sum(x) for x in M]; c = [sum(M[i][j] for i in range(14)) for j in range(14)]
    sets = [cums(r), cums(r[::-1]), cums(c), cums(c[::-1])]
    return sum(1 for S_ in sets for t in (60, 61) if t in S_)
real_hits = hits(G.MATRIX_README); rng = random.Random(5); n = 20000; ge = 0; ge1 = 0
cells = [1]*101 + [0]*95
for _ in range(n):
    rng.shuffle(cells); M = [cells[i*14:(i+1)*14] for i in range(14)]; h = hits(M); ge += h >= real_hits; ge1 += h >= 1
out["E_somas_parciais"] = {"real_hits_de_8_testes": real_hits, "p_ge_real": ge/n, "p_ge_1": ge1/n,
                          "cum_rows": sorted(cums(rs)), "cum_cols": sorted(cums(cs))}
print("(E)", json.dumps(out["E_somas_parciais"]))
json.dump(out, open(os.path.join(HERE, "summary_b.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
G.jsonl(LOG, {"hipotese": "critico parte 2: re-varredura de paddings, poly3 family-wise, faed, somas parciais", "resultado": out})
