# -*- coding: utf-8 -*-
"""
tail32_history — o blob TAIL32 (fim da fase 3.2) contra TODO o histórico de senhas
comunitário (re-gerado dos scripts de solver/) + a gramática local da fase 3.2.

HIPÓTESE (falsificável, espaço finito): o TAIL32 segue a gramática das fases 1–3.2
(senha = sha256hex ou string crua de uma concatenação ordenada de palavras-chave) e
nunca foi testado contra o histórico (~230k senhas só bateram em SMALL/COSMIC) nem
contra os tokens da própria fase 3.2. Se a senha está nesse universo, AES-256-CBC
com KDF EVP-SHA256 abre com plaintext semântico; senão, negativo.

Oráculo duro: padding PKCS7 válido E G.semantic(plaintext) (ASCII ≥ 85% ou WIF/hex64),
ou sha256(senha) → endereço-prêmio. Padding válido sem semântica = soft.
"""
import sys, os, io, re, json, time, hashlib, itertools, contextlib, base64
SCRATCH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRATCH)
import gsmg_common as G
import oracles as O
from Crypto.Cipher import AES
from coincurve import PublicKey

LOG = os.path.join(SCRATCH, "tail32_history.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)

HYP = ("TAIL32 segue a gramática sha256hex/raw de concatenação de palavras-chave e nunca foi "
       "testado contra o histórico comunitário (~230k senhas) nem contra os tokens da fase 3.2; "
       "se a senha está nesse universo finito, EVP-SHA256 + AES-CBC abre com plaintext semântico.")
log({"kind": "hypothesis", "text": HYP})

# ------------------------------------------------------------------ coletor de senhas
CANDS = {}          # bytes -> fonte (primeira)
SRC_COUNT = {}
def add(pw, src):
    if isinstance(pw, str): pw = pw.encode("utf-8", "surrogateescape")
    if not pw: return
    if pw not in CANDS:
        CANDS[pw] = src
        SRC_COUNT[src] = SRC_COUNT.get(src, 0) + 1

_cur_src = ["?"]
def _collect_aes_open(pw, *a, **k):
    add(pw, _cur_src[0]); return []
def _collect_evp_open(salt, ct, pw, *a, **k):
    add(pw, _cur_src[0]); return None
def _no_priv(*a, **k): return None

REAL_OPEN = open
def dummy_open(path, mode="r", *a, **k):
    # escrita vai para o nada (não sobrescrever _work/ do usuário); leitura é real
    if any(c in mode for c in "wa+x"): return io.StringIO()
    return REAL_OPEN(path, mode, *a, **k)

STRLIT = re.compile(r'''b?(?:"((?:[^"\\]|\\.){3,})"|'((?:[^'\\]|\\.){3,})')''')
def extract_literals(src_text):
    out = []
    for m in STRLIT.finditer(src_text):
        s = m.group(1) or m.group(2)
        if s and not s.startswith(("%", "{", "\\", "[")) and "{" not in s:
            out.append(s.encode().decode("unicode_escape"))
    return out

def run_script(name, entry=None, fixups=None, fallback_only=False):
    """Exec o script de solver/ com oracles/evp_open trocados por coletor; se falhar,
    extrai literais de string do código. Retorna (modo, n_coletadas)."""
    path = os.path.join(G.SOLVER, name)
    src = REAL_OPEN(path, encoding="utf-8").read()
    _cur_src[0] = name
    before = len(CANDS)
    mode = "literals" if fallback_only else "exec"
    if not fallback_only:
        ns = {"__name__": "hist_" + name[:-3], "__file__": path, "open": dummy_open}
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                exec(compile(src, path, "exec"), ns)
                for k in ("evp_open",):
                    if k in ns: ns[k] = _collect_evp_open
                if fixups: fixups(ns)
                if entry:
                    for fn, args in entry:
                        ns[fn](*args)
        except Exception as e:
            mode = f"fallback_literals ({type(e).__name__}: {str(e)[:80]})"
    if mode != "exec":
        for s in extract_literals(src): add(s, name)
    n = len(CANDS) - before
    log({"kind": "source", "script": name, "mode": mode, "new": n})
    print(f"  [{name}] {mode} -> +{n}")
    return mode, n

# patch global dos oráculos ANTES de executar qualquer gerador
O.aes_open = _collect_aes_open
O.check_privkey = _no_priv

print("== (a) re-gerando listas históricas ==")
t0 = time.time()
# 1. salphaseion_passphrase_sweep: iterar sources()/passwords() diretamente (~232k)
def _salph(ns):
    for s in ns["sources"]():
        for value, m, pw in ns["passwords"](s): add(pw, "salphaseion_passphrase_sweep.py")
run_script("salphaseion_passphrase_sweep.py", fixups=_salph)
run_script("roadmap_sweep.py")                              # roda no import
run_script("focused_aes.py", entry=[("run", ())])
run_script("answer_phrase_sweep.py", entry=[("main", ())])
run_script("first_hint_sweep.py", entry=[("main", ())])
run_script("new_hints_attack.py", entry=[("main", ())])
def _arch(ns):
    orig = ns["transcript_corpora"]
    def safe():
        try: return orig()
        except Exception:
            m = re.search(r"YOUR LIFE IS THE SUM.*?CIAO BELLA O", O._readme(), re.S)
            return {"phase-3.2": m.group(0)}
    ns["transcript_corpora"] = safe
run_script("architect_sum_attack.py", entry=[("main", ())], fixups=_arch)
def _cosmic(ns):
    npw, extra = ns["run_f3"]()
    ns["run_f1"](extra_candidates=extra)
run_script("cosmic_book_attack.py", fixups=_cosmic)
run_script("intertwine_attack4.py", entry=[("main", ())])
# scripts cujas senhas vivem dentro de main() com chaves cruas (não EVP): literais do código
for nm in ("eps35_attack.py", "pop_culture_attack.py", "miroir_attack.py",
           "intertwine_attack.py", "intertwine_attack2.py", "intertwine_attack3.py"):
    run_script(nm, fallback_only=True)
n_hist = len(CANDS)
print(f"  histórico: {n_hist} senhas únicas em {time.time()-t0:.0f}s")

# ------------------------------------------------------------------ (b) gramática da fase 3.2
print("== (b) gramática da fase 3.2 ==")
VIC = ("15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213"
       "131281491109166131412199114371612126021664313711154112")
INCASE = "IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE"
RAISING = ("Raising the stakes without extra chances of winning. A fubcd-king & oracle-queen, thingky mvps, "
           "on a sad board but as wide as the first one seen.")
CORE = ["fubcd", "king", "oracle", "queen", "thingky", "mvps", "sad", "board", "wide", "first", "seen",
        "half", "betterhalf", "halfandbetterhalf", "THEMATRIXHASYOU", "1141"]
EXTRA = ["jacquefresco", "giveit", "justonesecond", "heisenbergsuncertaintyprinciple",
         INCASE, INCASE.replace(" ", ""), INCASE.replace(" ", "").lower(),
         "FUBCDORA.LETHINGKYMVPS.JQZXW", "FUBCDORALETHINGKYMVPSJQZXW", "FUBCDORA.LETHINGKYMVPS/JQZXW",
         RAISING, re.sub(r"[^A-Za-z0-9]", "", RAISING), re.sub(r"[^A-Za-z0-9]", "", RAISING).lower(),
         VIC, "fubcdking", "oraclequeen", "thingkymvps", "fubcdkingoraclequeen", "raisingthestakes",
         "sadboard", "aswideasthefirstoneseen", "oneforonefourforone", "beaufort", "beautifulstrategicposition",
         "ciaobellao", "privatekeynote", "halfandbetterhalfandtheyalsoneedfundstolive", "14", "1", "4",
         "cp1141", "ebcdic", "ebcdic1141", "vic", "checkerboard", "straddlingcheckerboard", "thematrixhasyou",
         "wakeupneo", "whyamihere"]
ALL = list(dict.fromkeys(CORE + EXTRA))
def case_forms(s):
    return {s, s.lower(), s.upper()}
MID = list(dict.fromkeys(CORE + EXTRA[:14]))   # ponytail: 3-partes só sobre 30 tokens (2-partes sobre todos)
grammar = set()
for r in (1, 2):
    for combo in itertools.permutations(ALL, r):
        grammar.add("".join(combo))
for combo in itertools.permutations(MID, 3):
    grammar.add("".join(combo))
for combo in itertools.permutations(CORE, 4):
    grammar.add("".join(combo))
for s in list(grammar):
    for f in case_forms(s): add(f, "grammar32")
n_gram = len(CANDS) - n_hist
print(f"  gramática 3.2: {len(grammar)} concatenações -> +{n_gram} senhas (com caixa)")
log({"kind": "grammar", "tokens": len(ALL), "core": len(CORE), "concats": len(grammar), "new": n_gram})

# ------------------------------------------------------------------ motor rápido
SALT, CT = G.BLOBS["TAIL32"]
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
def evp(pw, salt, h):
    d = prev = b""
    while len(d) < 48:
        prev = h(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]
def unpad(p):
    n = p[-1]
    if 1 <= n <= 16 and p.endswith(bytes([n]) * n): return p[:-n]
    return None
def aes_open(pw, salt, ct, h=hashlib.sha256):
    k, iv = evp(pw, salt, h)
    return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
def priv_ok(sec):
    try: return PublicKey.from_valid_secret(sec).format(False) == TGT
    except Exception: return False

def forms(pw):
    hx = hashlib.sha256(pw).hexdigest()
    return (("raw", pw), ("sha256hex", hx.encode()), ("SHA256HEX", hx.upper().encode()))

STATS = {"aes_sha256": 0, "aes_md5": 0, "priv": 0}
hard, soft, best = [], [], {"printable": -1}
def test_blob(pw, src, salt=SALT, ct=CT, kdfs=(("sha256", hashlib.sha256),), tested=None):
    for fname, f in forms(pw):
        if tested is not None:
            if f in tested: continue
            tested.add(f)
        for kn, h in kdfs:
            STATS["aes_" + kn] += 1
            p = aes_open(f, salt, ct, h)
            if p is None: continue
            pr = G.printable(p)
            rec = {"src": src, "pw": pw.decode("latin-1")[:120], "form": fname, "kdf": kn,
                   "printable": round(pr, 3), "len": len(p), "plain_hex": p.hex()}
            if G.semantic(p):
                hard.append(rec); log({"kind": "HARD_AES", **rec}); print("!!! HARD AES", rec)
            else:
                soft.append(rec); log({"kind": "soft_pad", **rec})
            if pr > best["printable"]:
                best.update(rec)
    # privkey: sha256(senha) e sha256(sha256hex(senha))
    for tag, sec in (("sha256(pw)", hashlib.sha256(pw).digest()),
                     ("sha256(sha256hex(pw))", hashlib.sha256(hashlib.sha256(pw).hexdigest().encode()).digest())):
        STATS["priv"] += 1
        if priv_ok(sec):
            rec = {"src": src, "pw": pw.decode("latin-1")[:120], "how": tag, "priv": sec.hex()}
            hard.append(rec); log({"kind": "HARD_PRIV", **rec}); print("!!! HARD PRIV", rec)

# ------------------------------------------------------------------ controle positivo
print("== controle positivo ==")
raw2 = base64.b64decode(G.PHASE2_B64)
p2 = aes_open(G.shahex("causality").encode(), raw2[8:16], raw2[16:])
assert p2 and p2.startswith(b"The ironic") and G.semantic(p2), "fase 2 não abriu via motor local"
assert aes_open(G.shahex("causality").encode(), raw2[8:16], raw2[16:], hashlib.md5) is None
# blob sintético com o salt do TAIL32 e uma senha da gramática 3.2 (forma sha256hex)
def enc(pw, salt, msg):
    k, iv = evp(pw, salt, hashlib.sha256); n = 16 - len(msg) % 16
    return AES.new(k, AES.MODE_CBC, iv).encrypt(msg + bytes([n]) * n)
ctrl_pw = b"fubcdkingoraclequeen"
ctrl_ct = enc(hashlib.sha256(ctrl_pw).hexdigest().encode(), SALT, b"CONTROL: the private key is planted here 5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF")
assert ctrl_pw in CANDS
h0 = len(hard); test_blob(ctrl_pw, "CONTROL", ct=ctrl_ct)
assert len(hard) == h0 + 1 and hard[-1]["form"] == "sha256hex", "controle falhou"
ctrl = hard.pop(); STATS.update({k: 0 for k in STATS}); best.clear(); best["printable"] = -1
print(f"  controle OK: fase2 abre só com SHA256; blob plantado abre com {ctrl['form']} -> {bytes.fromhex(ctrl['plain_hex'])[:30]}")
log({"kind": "control", "phase2_sha256": True, "phase2_md5": False, "planted": ctrl["form"]})

# ------------------------------------------------------------------ varredura TAIL32
print(f"== TAIL32 × {len(CANDS)} senhas × 3 formas × SHA256 ==")
t0 = time.time(); tested = set()
for i, (pw, src) in enumerate(CANDS.items()):
    test_blob(pw, src, tested=tested)
    if i % 50000 == 0 and i: print(f"  {i}/{len(CANDS)} {time.time()-t0:.0f}s")
t_sha = time.time() - t0
print(f"  SHA256: {STATS['aes_sha256']} testes AES, {STATS['priv']} privkey em {t_sha:.0f}s")

# MD5 (openssl antigo) — barato, só como cobertura secundária
print("== MD5 secundário ==")
t0 = time.time()
for f in list(tested):
    STATS["aes_md5"] += 1
    p = aes_open(f, SALT, CT, hashlib.md5)
    if p is None: continue
    pr = G.printable(p)
    rec = {"src": CANDS.get(f, "form"), "pw": f.decode("latin-1")[:120], "form": "final", "kdf": "md5",
           "printable": round(pr, 3), "len": len(p), "plain_hex": p.hex()}
    if G.semantic(p): hard.append(rec); log({"kind": "HARD_AES", **rec}); print("!!! HARD AES md5", rec)
    else: soft.append(rec); log({"kind": "soft_pad", **rec})
    if pr > best["printable"]: best.update(rec)
print(f"  MD5: {STATS['aes_md5']} testes em {time.time()-t0:.0f}s")

# ------------------------------------------------------------------ relatório
soft.sort(key=lambda r: -r["printable"])
n_tests = STATS["aes_sha256"] + STATS["aes_md5"] + STATS["priv"]
summary = {
    "kind": "summary", "n_candidates": len(CANDS), "n_final_forms": len(tested), "sources": SRC_COUNT,
    "stats": STATS, "n_tests": n_tests, "hard": len(hard), "soft": len(soft),
    "soft_expected_1_256": round((STATS["aes_sha256"] + STATS["aes_md5"]) / 256, 1),
    "soft_ge_0.6": [r for r in soft if r["printable"] >= 0.6][:20],
    "best": best, "top_soft": soft[:10],
}
log(summary)
json.dump(summary, REAL_OPEN(os.path.join(SCRATCH, "tail32_history_summary.json"), "w"), indent=1, ensure_ascii=False)
print(json.dumps({k: v for k, v in summary.items() if k not in ("soft_ge_0.6", "top_soft", "best")}, indent=1, ensure_ascii=False))
print("best:", {k: best[k] for k in best if k != "plain_hex"})
print("HARD:", hard)
