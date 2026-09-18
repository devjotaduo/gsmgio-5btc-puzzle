# -*- coding: utf-8 -*-
"""
corpus_collect — re-gera o corpus histórico de senhas-base (coletor de tail32_history.py,
SEM o teste AES) e grava em corpus.pkl: lista de bytes únicos + contagem por fonte.
"""
import sys, os, io, re, json, time, itertools, contextlib, pickle
KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
import gsmg_common as G
import oracles as O
# enxame 2026-09-18 / cbc_sem_padding: cópia de solver/ct_montage_corpus_collect.py
# (sha256 fa214ca0…3008f); a única mudança é o destino do corpus.pkl e do log.
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                    "_work", "enxame_2026-09-18", "cbc_sem_padding")
LOG = os.path.join(HERE, "corpus_collect.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)

# ------------------------------------------------------------------ coletor (cópia de tail32_history.py)
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
    print(f"  [{name}] {mode} -> +{n}", flush=True)
    return mode, n

O.aes_open = _collect_aes_open
O.check_privkey = _no_priv

print("== (a) re-gerando listas históricas ==", flush=True)
t0 = time.time()
def _salph(ns):
    for s in ns["sources"]():
        for value, m, pw in ns["passwords"](s): add(pw, "salphaseion_passphrase_sweep.py")
run_script("salphaseion_passphrase_sweep.py", fixups=_salph)
run_script("roadmap_sweep.py")
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
for nm in ("eps35_attack.py", "pop_culture_attack.py", "miroir_attack.py",
           "intertwine_attack.py", "intertwine_attack2.py", "intertwine_attack3.py"):
    run_script(nm, fallback_only=True)
n_hist = len(CANDS)
print(f"  histórico: {n_hist} senhas únicas em {time.time()-t0:.0f}s", flush=True)

# ------------------------------------------------------------------ (b) gramática da fase 3.2
print("== (b) gramática da fase 3.2 ==", flush=True)
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
MID = list(dict.fromkeys(CORE + EXTRA[:14]))
grammar = set()
for r in (1, 2):
    for combo in itertools.permutations(ALL, r):
        grammar.add("".join(combo))
for combo in itertools.permutations(MID, 3):
    grammar.add("".join(combo))
for combo in itertools.permutations(CORE, 4):
    grammar.add("".join(combo))
for s in list(grammar):
    for f in {s, s.lower(), s.upper()}: add(f, "grammar32")
n_gram = len(CANDS) - n_hist
print(f"  gramática 3.2: {len(grammar)} concatenações -> +{n_gram} senhas (com caixa)", flush=True)
log({"kind": "grammar", "tokens": len(ALL), "core": len(CORE), "concats": len(grammar), "new": n_gram})

# núcleo (item 3a do briefing): tokens da página/roadmap/fase 3.2 = grammar32 + salphaseion_passphrase_sweep
pws = list(CANDS.keys()); srcs = list(CANDS.values())
with REAL_OPEN(os.path.join(HERE, "corpus.pkl"), "wb") as f:
    pickle.dump({"pws": pws, "srcs": srcs, "src_count": SRC_COUNT}, f)
log({"kind": "corpus", "n_base": len(pws), "sources": SRC_COUNT})
print(json.dumps({"n_base": len(pws), "sources": SRC_COUNT}, ensure_ascii=False), flush=True)
