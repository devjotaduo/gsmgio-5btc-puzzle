# -*- coding: utf-8 -*-
"""
FAMILIA checkerboard_keystream_lowres (fatia NOVA da familia checkerboard_keystream; lead #3 do briefing).

Hipotese (falsificavel, espaco finito): a rodada 2 refutou camada aditiva com chave de >=3 residuos
variados sobre faed, mas o unigrama enviesado SEM memoria serial continua compativel com uma camada
aditiva de POUCOS residuos (mascara binaria 0/d, ou ternaria 0/+d/-d) aplicada antes do checkerboard —
mascaras "0/1" existem literalmente na pagina (binario a/b de `enter` e `matrixsumlist`, bits da matriz
14x14, azul/amarelo). Se verdadeira, existe (mascara x delta x config) tal que o faed re-chaveado
recupera a estrutura serial de checkerboard (H_cond/token-IoC muito fora do nulo) e decodifica em texto.
DIAGNOSTICO DECISIVO acoplado: medir, no controle, quanto H_cond de um checkerboard sobrevive a uma
camada binaria — se sobreviver forte (z << -4), o faed real (z=-0.75) e' INCOMPATIVEL com qualquer
chave de 2 residuos e a hipotese morre por medida, nao por varredura.
"""
import sys, json, time, math, random, hashlib, collections, itertools
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
LOG = SP + r"\checkerboard_keystream_lowres.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"event": "hypothesis", "family": "checkerboard_keystream_lowres", "text": __doc__.strip()})
rng = np.random.default_rng(20260902)
NSHUF, NSHUF2, ZTHR = 25, 60, 3.0

# ---------------------------------------------------------------- estatisticas invariantes (mesmo detector da rodada 2)
def hcond_np(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).reshape(n, n).astype(float)
    rows = bg.sum(1, keepdims=True); N = bg.sum()
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(bg > 0, bg * np.log2(bg / rows), 0.0)
    return -t.sum() / N
def hcond_z(seq, n, nshuf=NSHUF):
    a = np.asarray(seq, dtype=np.int64); obs = hcond_np(a, n)
    null = np.array([hcond_np(rng.permutation(a), n) for _ in range(nshuf)])
    sd = null.std() or 1e-9
    return float((obs - null.mean()) / sd), float(obs)
def tokenize(digs, esc):
    out = []; i = 0; N = len(digs)
    while i < N:
        d = digs[i]
        if d in esc and i + 1 < N: out.append((d, digs[i + 1])); i += 2
        else: out.append((d,)); i += 1
    return out
def ioc(toks):
    c = collections.Counter(toks); N = len(toks)
    return sum(v * (v - 1) for v in c.values()) / (N * (N - 1))
def token_ioc_best(seq, uni_vals, nshuf=NSHUF2):
    pairs = list(itertools.combinations(uni_vals, 2))
    sh = [list(rng.permutation(seq)) for _ in range(nshuf)]
    best = (0.0, None, 0.0)
    for e in pairs:
        E = set(e); obs = ioc(tokenize(seq, E))
        null = np.array([ioc(tokenize(s, E)) for s in sh]); sd = null.std() or 1e-9
        z = (obs - null.mean()) / sd
        if abs(z) > abs(best[0]): best = (float(z), e, obs)
    return best

# ---------------------------------------------------------------- configs do faed (identicas a rodada 2)
FD = G.digits(G.FAED)   # a=1..i=9
CONFIGS = {
    "m9":    dict(n=9,  c=[d - 1 for d in FD],              uni="123456789",  back=lambda p: p + 1),
    "m10a":  dict(n=10, c=FD[:],                            uni="0123456789", back=lambda p: p),
    "m10i0": dict(n=10, c=[0 if d == 9 else d for d in FD], uni="0123456789", back=lambda p: p),
}
NF = len(FD)   # 570

def apply_mask(c, mask, d, n):
    """p[i] = (c[i] - d*mask[i]) mod n; mask periodica ou de comprimento >= len(c)."""
    L = len(mask)
    return [(c[i] - d * mask[i % L]) % n for i in range(len(c))]

# ---------------------------------------------------------------- mascaras
def bits_ascii(s): return [int(b) for ch in s for b in format(ord(ch), "08b")]
def rots(m): return [m[r:] + m[:r] for r in range(len(m))]
MASKS = {}   # nome -> lista de valores pequenos (0/1 ou 0/1/2)

# (A) padroes binarios periodicos exaustivos L=2..10, canonicos (m[0]=0), nao-constantes
for L in range(2, 11):
    for bits in range(1, 1 << (L - 1)):          # m[0]=0, resto varia; exclui all-zero
        m = [0] + [(bits >> k) & 1 for k in range(L - 1)]
        MASKS[f"binP{L}:{bits}"] = m
# (B) padroes ternarios {0,1,2} periodicos L=2..6, m[0]=0, nao-constantes
for L in range(2, 7):
    for code in range(1, 3 ** (L - 1)):
        m = [0]; x = code
        for _ in range(L - 1): m.append(x % 3); x //= 3
        MASKS[f"terP{L}:{code}"] = m
# (C) mascaras estruturais da pagina
def add_rot(prefix, m, step=1):
    for r in range(0, len(m), step):
        MASKS[f"{prefix}|rot{r}"] = m[r:] + m[:r]
add_rot("bits(enter)", bits_ascii("enter"))                       # 40
add_rot("bits(matrixsumlist)", bits_ascii("matrixsumlist"))       # 104
add_rot("colorseq(B=1)", [1 if ch == 'B' else 0 for ch in G.COLOR_SEQ])   # 24
mrm = [G.MATRIX_README[r][c] for r in range(14) for c in range(14)]
add_rot("matrix196:row", mrm, step=2)
add_rot("matrix196:spiral", [G.MATRIX_README[r][c] for (r, c) in G.SPIRAL], step=2)
for w in ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "yellowblueprimes",
          "hashthetext", "thematrixhasyou", "enter"]:
    a = [ord(ch) - 96 for ch in w]
    add_rot(f"a1z26mod2({w})", [x % 2 for x in a])
    add_rot(f"a1z26mod3({w})", [x % 3 for x in a])
DB = G.digits(G.DBBI)
MASKS["dbbi:in_gi"] = [1 if d in (7, 9) else 0 for d in DB]        # g,i = escapes do faed
MASKS["dbbi:in_be"] = [1 if d in (2, 5) else 0 for d in DB]        # escapes do dbbi
MASKS["dbbi:parity"] = [d % 2 for d in DB]
MASKS["dbbi:mod3"] = [d % 3 for d in DB]
MASKS["primepos1"] = [1 if G.is_prime(i + 1) else 0 for i in range(NF)]
MASKS["primepos0"] = [1 if G.is_prime(i) else 0 for i in range(NF)]
MASKS["fib_pos"] = [0] * NF
_a, _b = 1, 2
while _a < NF:
    MASKS["fib_pos"][_a] = 1; _a, _b = _b, _a + _b
MASKS["half2"] = [0] * 285 + [1] * 285                             # "half and better half"
MASKS["colidx_pos"] = [1 if i in G.COLORED else 0 for i in range(NF)]
print("mascaras:", len(MASKS), flush=True)

# ---------------------------------------------------------------- decode + oraculos
AL322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
PHRASES = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
 "ourfirsthintisyourlastcommand", "anstoo", "shabef", "shabefanstoo", "yellowblueprimes",
 "rosesarewhitebutoftenred", "yellowhasanumberandsodoesblue", "hushhush", "salphaseion",
 "salvation", "cosmicduality", "yinyang", "yingyang", "followthewhiterabbit", "theseedisplanted",
 "gsmgmeganigma", "gsmgio5btcpuzzlechallenge", "hashthetext", "thematrixhasyou", "causality",
 "theflowerblossomsthroughwhatseemstobeaconcretesurface", "jacquefresco",
 "lastwordsbeforearchichoicethispassword", "halfandbetterhalf", "thewarning", "logic",
 "knockknockneo", "temetnosce", "whiterabbit", "keymaker", "merovingian", "architect", "oracle",
 "zion", "source", "purplepill", "globallysupportingmygeneration", "gsmg", "bitcoin",
 "safenetlunahsm", "heisenbergsuncertaintyprinciple", "giveitjustonesecond",
 "lifeanddeath", "lemiroirdelavieetdelamort", "killprocess", "betterhalf", "primebasics",
 "returntothesourcecodes", "thedoortoyourright", "fubcdkingoraclequeenthingkymvps",
 "dbbi", "faed", "abcdefghijklmnopqrstuvwxyz", "etaoinshrdlcumwfgypbvkjxqz",
 "qwertyuiopasdfghjklzxcvbnm", "zyxwvutsrqponmlkjihgfedcba"]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH9 = {"CANON": G.CANON, "al322_25": AL322.replace(".", "")[:25]}
ALPH10 = {"al322": AL322, "CANON+..": G.CANON + "J.."}
for p in PHRASES:
    ALPH9[f"kw:{p}"] = G.keyed_alphabet(p)
    ALPH10[f"kw26:{p}"] = G.keyed_alphabet(p, base=AZ, merge_j=False) + ".."
ALPH9 = {k: v for k, v in ALPH9.items() if len(v) == 25}
ALPH10 = {k: v for k, v in ALPH10.items() if len(v) == 28}
for D in (ALPH9, ALPH10):
    seen = {}
    for k, v in list(D.items()):
        if v in seen: del D[k]
        else: seen[v] = k
ESC9 = [(a, b) for a in range(1, 10) for b in range(1, 10) if a != b]
ESC10 = [(a, b) for a in range(10) for b in range(10) if a != b]
print("alfabetos u1-9:", len(ALPH9), "u0-9:", len(ALPH10), flush=True)

hard, soft = [], []
best = {"score": -99.0}
n_decodes = 0
def oracle(pt, how):
    for pw in (pt, pt.lower(), G.shahex(pt), G.shahex(pt.lower())):
        for b in ("SMALL", "COSMIC", "TAIL32"):
            for kdf, p in G.aes_try(pw, b, kdf="sha256"):
                r = {"how": how, "pw": pw[:80], "blob": b, "kdf": kdf,
                     "printable": round(G.printable(p), 3), "head": p[:40].decode("latin-1")}
                if G.semantic(p): hard.append({**r, "plaintext_hex": p.hex()})
                else: soft.append(r)
    for k in (G.sha(pt.encode()), G.sha(pt.lower().encode())):
        r = G.priv_hit(k)
        if r: hard.append({"how": how, "privkey": k.hex(), "addr": r})
def neighbor(alpha, r):
    a = list(alpha); i, j = r.sample(range(len(a)), 2); a[i], a[j] = a[j], a[i]; return "".join(a)
def decode_stream(seq, cfg, how):
    global n_decodes, best
    n = cfg["n"]; digs = [cfg["back"](p) for p in seq]
    alphs, escs, uni = (ALPH9, ESC9, "123456789") if n == 9 else (ALPH10, ESC10, "0123456789")
    r = random.Random(7)
    for an, al in alphs.items():
        for e in escs:
            n_decodes += 1
            pt = G.checkerboard_decode(digs, al, e, uni)
            sc = G.english_score(pt)
            if sc > best["score"]: best = {"score": round(sc, 3), "text": pt[:120], "how": f"{how}|{an}|esc{e}"}
            if G.semantic_text(pt):
                nb = [G.english_score(G.checkerboard_decode(digs, neighbor(al, r), e, uni)) for _ in range(2)]
                ok = all(sc > x for x in nb)
                G.jsonl(LOG, {"event": "semantic_cand", "how": f"{how}|{an}|esc{e}", "score": round(sc, 3),
                              "neighbors": [round(x, 3) for x in nb], "validated": ok, "head": pt[:100]})
                if ok: oracle(pt, f"{how}|{an}|esc{e}")

# ---------------------------------------------------------------- CONTROLE POSITIVO + DIAGNOSTICO
def cb_encode(text, alpha, esc, uni):
    top = [d for d in uni if int(d) not in esc]; table = {}; k = 0
    for d in top: table[alpha[k]] = [int(d)]; k += 1
    for e in esc:
        for d in uni: table[alpha[k]] = [e, int(d)]; k += 1
    out = []
    for ch in text.upper():
        if ch in table: out += table[ch]
    return out
CTRL_TXT = ("THE ARCHITECT SAID THAT THE DOOR TO YOUR RIGHT LEADS TO THE SOURCE AND THE SALVATION OF ZION "
            "WHILE THE DOOR TO YOUR LEFT LEADS BACK TO THE MATRIX TO HER AND TO THE END OF YOUR SPECIES "
            "YOU ARE HERE BECAUSE ZION IS ABOUT TO BE DESTROYED ITS EVERY LIVING INHABITANT TERMINATED "
            "ITS ENTIRE EXISTENCE ERADICATED THE FUNCTION OF THE ONE IS NOW TO RETURN TO THE SOURCE "
            "THE PROBLEM IS CHOICE THE FIRST MATRIX WAS DESIGNED TO BE A PERFECT HUMAN WORLD")
ctrl_p = cb_encode(CTRL_TXT, AL322, (1, 4), "0123456789")[:NF]
assert G.checkerboard_decode(ctrl_p, AL322, (1, 4), "0123456789")[:16] == CTRL_TXT.replace(" ", "")[:16]
mk = bits_ascii("enter")
DIAG = []
for d in range(1, 10):
    cc = [(p + d * mk[i % len(mk)]) % 10 for i, p in enumerate(ctrl_p)]
    zc, _ = hcond_z(cc, 10)
    zk, _ = hcond_z(apply_mask(cc, mk, d, 10), 10)                     # dekey correto
    zw, _ = hcond_z(apply_mask(cc, mk[5:] + mk[:5], d, 10), 10)        # rotacao errada
    DIAG.append({"delta": d, "z_cipher": round(zc, 2), "z_dekeyed": round(zk, 2), "z_wrongrot": round(zw, 2)})
zp, _ = hcond_z(ctrl_p, 10)
# controle de recuperacao completo (delta=3): filtro + decode devem devolver o texto
d0 = 3
cc0 = [(p + d0 * mk[i % len(mk)]) % 10 for i, p in enumerate(ctrl_p)]
rec = apply_mask(cc0, mk, d0, 10)
ctrl_pt = G.checkerboard_decode(rec, AL322, (1, 4), "0123456789")
z_rec, _ = hcond_z(rec, 10)
ctrl_ok = bool(ctrl_pt.startswith("THEARCHITECT") and G.semantic_text(ctrl_pt) and z_rec < -8)
faed_z = {cn: round(hcond_z(cfg["c"], cfg["n"])[0], 2) for cn, cfg in CONFIGS.items()}
G.jsonl(LOG, {"event": "control", "z_plain_checkerboard": round(zp, 2), "diag_binary_layer": DIAG,
              "z_recovered": round(z_rec, 2), "decoded_head": ctrl_pt[:40], "control_ok": ctrl_ok,
              "faed_raw_z": faed_z})
print("CTRL ok:", ctrl_ok, "z(pt cb)=", round(zp, 2), "z(recuperado)=", round(z_rec, 2), flush=True)
print("DIAG binario:", DIAG, flush=True)
print("faed cru z:", faed_z, flush=True)
assert ctrl_ok

# ---------------------------------------------------------------- varredura
t0 = time.time()
PASS, ALLZ = [], []
n_streams = 0; n_pass = 0
for cn, cfg in CONFIGS.items():
    n, c = cfg["n"], cfg["c"]
    for mname, m in MASKS.items():
        for d in range(1, n):
            seq = apply_mask(c, m, d, n)
            n_streams += 1
            z1, _ = hcond_z(seq, n)
            how = f"{cn}|{mname}|d{d}"
            ALLZ.append((round(z1, 2), how))
            if abs(z1) > 2.5:
                z2, e, obs = token_ioc_best(seq, [int(x) for x in cfg["uni"]])
                if abs(z1) > ZTHR or abs(z2) > ZTHR:
                    n_pass += 1
                    G.jsonl(LOG, {"event": "filter_pass", "how": how, "hcond_z": round(z1, 2),
                                  "tok_z": round(z2, 2), "tok_esc": e, "tok_ioc": round(obs, 4)})
                    PASS.append((max(abs(z1), abs(z2)), seq, cfg, how))
    print(cn, "streams", n_streams, "pass", n_pass, round(time.time() - t0), "s", flush=True)

# ---------------------------------------------------------------- decode dos melhores (ambas polaridades)
PASS.sort(key=lambda t: -t[0])
CAP = 100
for i, (zz, seq, cfg, how) in enumerate(PASS[:CAP]):
    n = cfg["n"]
    decode_stream(seq, cfg, how)
    decode_stream([(-p) % n for p in seq], cfg, how + "|neg")
    if i % 10 == 0:
        print("decode", i, how, "z", round(zz, 2), "decodes", n_decodes, "best", best["score"],
              round(time.time() - t0), "s", flush=True)
ALLZ.sort(key=lambda t: -abs(t[0]))
summary = {"event": "summary", "n_masks": len(MASKS), "n_streams": n_streams, "n_filter_pass": n_pass,
           "n_decoded_streams": min(len(PASS), CAP) * 2, "n_decodes": n_decodes,
           "n_tests": n_streams + n_decodes, "hard": hard, "n_soft": len(soft), "soft": soft[:10],
           "best": best, "top_z": ALLZ[:15], "diag_binary_layer": DIAG, "faed_raw_z": faed_z,
           "secs": round(time.time() - t0)}
G.jsonl(LOG, summary)
print(json.dumps(summary, ensure_ascii=False, indent=1))
