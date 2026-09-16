# -*- coding: utf-8 -*-
"""
FAMILIA pop_culture_exact — leitura LITERAL de "lastwordsbeforearchichoice".

HIPOTESE: o token "lastwordsbeforearchichoice" e uma INSTRUCAO literal: pegue as
ULTIMAS PALAVRAS (N=1..8) imediatamente ANTES de uma ESCOLHA. As unicas fontes
admissiveis sao internas ao proprio puzzle (README/ENDGAME: textos das fases 2,
3, 3.2.1, 3.2.2; mensagens do criador) + nomes proprios/titulos curtos. A frase
resultante (crua ou seu sha256hex) e a senha EVP-SHA256 de SMALL/COSMIC/TAIL32,
ou sha256(frase) e a privkey do endereco-premio.

ESPACO FINITO: ocorrencias de {select,choice,choose,door,decide,pill,archi*} nos
3 textos x N=1..8 palavras anteriores x {com,sem} o gatilho, + ~50 nomes curtos,
+ concatenacoes ordenadas de 2 partes com os 7 tokens da pagina, + titulos
MAIUSCULOS <=4 palavras do cosmic_duality.txt -> ~11 formas ortograficas cada.

ORACULO DURO: (a) blob AES com plaintext semantico (G.semantic), (b) privkey ->
endereco-premio (coincurve vs pubkey on-chain). Padding valido sem semantica = soft.

CONTROLE POSITIVO: o blob da fase 2 (G.PHASE2_B64) e injetado em G.BLOBS e
"causality" e injetado na lista de candidatos; o pipeline TEM de abri-lo via
forma sha256hex + EVP-SHA256.
"""
import sys, os, re, json, hashlib, itertools

SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G

REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
LOG = os.path.join(SP, "pop_culture_exact.jsonl")
open(LOG, "w").close()

from coincurve import PublicKey
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)

def priv_ok(b32):
    try:
        return PublicKey.from_valid_secret(b32).format(False) == TGT
    except Exception:
        return False

# ---------------------------------------------------------------- controle
G.BLOBS["PHASE2"] = G._parse(G.PHASE2_B64)

# ---------------------------------------------------------------- fontes
def rd(p):
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()

SRC = {
    "README": rd(os.path.join(REPO, "README.md")),
    "ENDGAME": rd(os.path.join(REPO, "ENDGAME.md")),
    "CREATOR": rd(os.path.join(SP, "creator_all.txt")),
}
CD_PATH = os.path.join(REPO, "_work", "cosmic_duality.txt")
CD = rd(CD_PATH) if os.path.exists(CD_PATH) else ""

TRIG = {"select", "selects", "selected", "selection", "choice", "choices",
        "choose", "chooses", "chosen", "door", "doors", "decide", "decides",
        "decision", "pill", "pills"}

WORD = re.compile(r"[A-Za-z0-9'\-]+")

def is_trigger(w):
    lw = w.lower()
    return lw in TRIG or lw.startswith("archi")

cands = {}  # frase -> origem

def add(p, how):
    p = p.strip()
    if 2 <= len(p) <= 120 and p not in cands:
        cands[p] = how

for name, txt in SRC.items():
    toks = WORD.findall(txt)
    for i, w in enumerate(toks):
        if not is_trigger(w):
            continue
        for N in range(1, 9):
            if i - N < 0:
                continue
            pre = toks[i - N:i]
            add(" ".join(pre), f"{name}/pre{N}")
            add(" ".join(pre + [w]), f"{name}/pre{N}+trig")

# frases-hint curtas do criador que contem os gatilhos (<=8 palavras)
for sent in re.split(r"[.\n!?]+", SRC["CREATOR"]):
    ws = WORD.findall(sent)
    if 1 <= len(ws) <= 8 and any(is_trigger(w) for w in ws):
        add(" ".join(ws), "CREATOR/sent")

# nomes proprios / titulos curtos (sem falas)
NAMES = ["Architect", "Oracle", "Neo", "Trinity", "Morpheus", "Merovingian",
         "Persephone", "Keymaker", "Zion", "Source", "Matrix Reloaded", "Alice",
         "Cheshire Cat", "White Rabbit", "Elliot", "Mr Robot", "Whiterose",
         "Dark Army", "Jacque Fresco", "Venus Project", "red pill", "blue pill",
         "purple pill", "left door", "right door", "the door to the right",
         "the door to the left", "salvation", "choice", "causality", "hope",
         "love", "ergo", "concordantly", "vis-a-vis", "anomaly", "the one",
         "system failure", "SalPhaseIon", "Cosmic Duality", "the door",
         "archichoice", "lastwords", "the architect", "the source",
         "salvation of zion", "the door to your right", "causality"]
for n in NAMES:
    add(n, "name")

# titulos MAIUSCULOS <=4 palavras do livro (so titulos)
if CD:
    seen = 0
    for line in CD.splitlines():
        s = line.strip()
        ws = WORD.findall(s)
        if 1 <= len(ws) <= 4 and s == s.upper() and any(c.isalpha() for c in s) \
           and all(len(w) >= 2 for w in ws) and len(s) <= 40:
            add(" ".join(ws), "cosmic/title")
            seen += 1
            if seen > 400:
                break

# (o controle positivo roda a parte, abaixo — "causality" ja esta em NAMES)


# ---------------------------------------------------------------- "ULTIMAS PALAVRAS" de blocos
# leitura alternativa, ainda literal: as ultimas palavras do proprio monologo do
# Arquiteto (fase 3.2.1) e do texto da fase 3.2.2 — o que ele diz ANTES de voce
# ter de escolher. Fonte = README (bloco entre o Beaufort e "phase 3.2.2").
RM = SRC["README"]
try:
    i0 = RM.index("REINSERTING THE PRIME BASICS")
    i0 = RM.rindex("```", 0, i0)
    i1 = RM.index("phase 3.2.2", i0)
    ARCH = RM[i0:i1]
except ValueError:
    ARCH = ""
if ARCH:
    at = WORD.findall(ARCH)
    for N in range(1, 13):
        if len(at) >= N:
            add(" ".join(at[-N:]), f"arch/last{N}")
            add(" ".join(at[:N]), f"arch/first{N}")
    # ultima palavra de cada linha do monologo, concatenadas ("last words")
    lastw = [WORD.findall(l)[-1] for l in ARCH.splitlines() if WORD.findall(l)]
    for k in range(2, len(lastw) + 1):
        add(" ".join(lastw[:k]), f"arch/lineends{k}")
        add(" ".join(lastw[-k:]), f"arch/lineends-tail{k}")
    firstw = [WORD.findall(l)[0] for l in ARCH.splitlines() if WORD.findall(l)]
    add(" ".join(firstw), "arch/linestarts")
    add(" ".join(lastw), "arch/lineends_all")
# fase 3.2.2 (VIC): ultimas palavras
try:
    j0 = RM.index("IN CASE YOU MANAGE TO CRACK THIS")
    j1 = min(RM.index(chr(10) * 2, j0), j0 + 900)
    vt = WORD.findall(RM[j0:j1])
    for N in range(1, 13):
        if len(vt) >= N:
            add(" ".join(vt[-N:]), f"vic/last{N}")
except ValueError:
    pass

BASE = dict(cands)

# concatenacoes ordenadas de 2 partes: nomes curtos x 7 tokens da pagina
TOKS = list(G.TOKENS.values())
for n in NAMES:
    a = re.sub(r"[^A-Za-z0-9]", "", n).lower()
    for t in TOKS:
        tt = re.sub(r"[^A-Za-z0-9]", "", t).lower()
        add(a + tt, "concat")
        add(tt + a, "concat")

print(f"candidatos base={len(BASE)} total={len(cands)}", flush=True)

# ---------------------------------------------------------------- formas
def forms(p):
    nospace = p.replace(" ", "")
    alnum = re.sub(r"[^A-Za-z0-9]", "", p)
    out = [p, p.lower(), p.upper(), nospace, nospace.lower(), alnum,
           alnum.lower(), alnum.upper(), p + "\n", alnum.lower() + "\n",
           "giveit" + alnum.lower(), alnum.lower() + "thispassword",
           alnum.lower() + "matrixsumlist", alnum.lower() + "enter"]
    seen, res = set(), []
    for f in out:
        if f and f not in seen:
            seen.add(f)
            res.append(f)
    return res

BLOBS = ("SMALL", "COSMIC", "TAIL32")
n_tests = 0
pads = 0
hard, soft = [], []
tested_forms = set()

# ---------------------------------------------------------------- CONTROLE POSITIVO
# o pipeline (gerar formas -> sha256hex -> aes_try EVP-SHA256 -> semantic) tem de
# abrir o blob da fase 2 a partir do candidato "causality".
ctl_ok = False
for f in forms("causality"):
    for pw in (f, hashlib.sha256(f.encode()).hexdigest()):
        for kdf, pt in G.aes_try(pw, "PHASE2", kdf="sha256"):
            if G.semantic(pt):
                ctl_ok = True
                G.jsonl(LOG, {"kind": "control_ok", "pw": pw, "kdf": kdf,
                              "head": pt[:60].decode("latin-1", "replace")})
assert ctl_ok, "CONTROLE POSITIVO FALHOU — pipeline quebrado"
print("CONTROLE POSITIVO OK (fase 2 aberta pelo pipeline)", flush=True)

for p, how in cands.items():
    for f in forms(p):
        if f in tested_forms:
            continue
        tested_forms.add(f)
        h = hashlib.sha256(f.encode()).hexdigest()
        # senhas: forma crua e sha256hex da forma
        for pw in (f, h):
            for b in BLOBS:
                n_tests += 1
                for kdf, pt in G.aes_try(pw, b, kdf="sha256"):
                    pads += 1
                    if G.semantic(pt):
                        rec = {"kind": "hard_aes", "pw": pw, "blob": b, "kdf": kdf,
                               "pt_hex": pt.hex(), "how": how, "phrase": p}
                        hard.append(rec)
                        G.jsonl(LOG, rec)
                    else:
                        if True:  # todo padding valido vira soft (ranqueado por printable)
                            soft.append({"pw": pw, "blob": b, "printable": round(G.printable(pt), 3),
                                         "head": pt[:32].hex(), "how": how})
        # privkeys: sha256(forma) e sha256(sha256hex(forma))
        for k in (hashlib.sha256(f.encode()).digest(),
                  hashlib.sha256(h.encode()).digest()):
            n_tests += 1
            if priv_ok(k):
                rec = {"kind": "hard_priv", "form": f, "priv_hex": k.hex(),
                       "how": how, "phrase": p}
                hard.append(rec)
                G.jsonl(LOG, rec)

print(f"pads_validos={pads} formas testadas={len(tested_forms)} n_tests={n_tests} hard={len(hard)} soft={len(soft)} control={ctl_ok}", flush=True)
soft.sort(key=lambda d: -d["printable"])
G.jsonl(LOG, {"kind": "summary", "n_tests": n_tests, "valid_pads": pads, "forms": len(tested_forms),
              "candidates": len(cands), "control_positive": ctl_ok,
              "hard": len(hard), "soft_top": soft[:10]})
print(json.dumps(soft[:5], ensure_ascii=False)[:800])
