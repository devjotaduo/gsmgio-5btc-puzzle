# -*- coding: utf-8 -*-
"""
LEAD NOVO (export Telegram 2026-09-08, PROGRESS.md de 'X' + verificacao propria):
`dbbi` (91) lido com b,g como prefixos de 2 chars => 64 tokens, 16 distintos =
assinatura de um digest SHA-256 (64 nibbles hex, 16 simbolos) sob substituicao.

Se dbbi == sha256(X) hex sob bijecao token->nibble, entao o PADRAO DE IGUALDADE
dos 64 tokens (particao por 1a ocorrencia) tem de ser identico ao padrao dos 64
nibbles de sha256(X). Isso acha a pre-imagem X SEM conhecer o mapa, e sem falso-
positivo (P(colisao de particao 64/16) ~ 1e-50). Achando X: recupera o hex real,
que (gramatica shabef=sha256 do puzzle) e a senha AES do proximo blob.

Roda: PYTHONPATH nao necessario se chamado de solver/. Usa oracles.aes_open/check_privkey.
"""
import sys, os, hashlib, itertools, hmac
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles

DBBI = oracles.sources()["dbbi"]
FAED = oracles.sources()["faed"]

def parse_prefix(s, prefixes):
    toks=[]; i=0
    while i < len(s):
        if s[i] in prefixes:
            if i+1 >= len(s): return None
            toks.append(s[i:i+2]); i+=2
        else:
            toks.append(s[i]); i+=1
    return toks

def pattern(seq):
    """particao normalizada por 1a ocorrencia -> tupla de ints."""
    lab={}; out=[]
    for x in seq:
        if x not in lab: lab[x]=len(lab)
        out.append(lab[x])
    return tuple(out)

def hexpattern(hexstr):
    return pattern(list(hexstr))

# ---- padroes-alvo de dbbi (varias orientacoes baratas) ----
tok = parse_prefix(DBBI, "bg")
assert tok and len(tok)==64 and len(set(tok))==16, (len(tok), len(set(tok)) if tok else None)
targets = {
    "dbbi_bg":            pattern(tok),
    "dbbi_bg_rev":        pattern(tok[::-1]),
}
# g,b como prefixo da string invertida (simetria)
tok_rs = parse_prefix(DBBI[::-1], "bg")
if tok_rs and len(tok_rs)==64 and len(set(tok_rs))==16:
    targets["dbbi_revstr_bg"] = pattern(tok_rs)
    targets["dbbi_revstr_bg_rev"] = pattern(tok_rs[::-1])

target_set = {k:v for k,v in targets.items()}
print("[alvos] padroes dbbi:", {k: len(set(v)) for k,v in target_set.items()})
print("[alvo dbbi_bg] =", ''.join('0123456789abcdef'[i] for i in target_set['dbbi_bg']))

HITS=[]
def consider(cand):
    """testa sha256(cand) (varias formas) contra os padroes-alvo."""
    if isinstance(cand, str): data = cand.encode()
    else: data = cand
    h = hashlib.sha256(data).hexdigest()   # 64 nibbles lower
    hp = hexpattern(h)
    for name, tp in target_set.items():
        if hp == tp:
            HITS.append((name, cand if isinstance(cand,str) else repr(cand), h))
            print(f"\n*** PATTERN HIT [{name}] cand={cand!r} sha256={h}")
            # usar o hex como senha AES (lower e upper) e como privkey
            for pw in (h, h.upper()):
                r = oracles.aes_open(pw)
                if r: print("   AES OPEN:", r)
            try:
                pr = oracles.check_privkey(bytes.fromhex(h))
                if pr: print("   PRIVKEY:", pr)
            except Exception: pass
            return True
    return False

# ---------- candidatos ----------
def matrix_bits():
    """14x14, black/blue=1, white/yellow=0, a partir do rabbit puzzle.xlsx se existir; senao README."""
    import glob
    grid=None
    xlsx=r"C:/Users/ruthe/Downloads/Telegram Desktop/ChatExport_2026-09-08/files/rabbit puzzle.xlsx"
    if os.path.exists(xlsx):
        import openpyxl
        wb=openpyxl.load_workbook(xlsx, data_only=True)
        ws=wb["Sheet1"]
        rows=[]
        for row in ws.iter_rows(values_only=True):
            r=[]
            for v in row[:14]:
                v=(str(v) or "").lower()
                r.append(1 if ("black" in v or "blue" in v) else 0)
            if len(r)==14: rows.append(r)
            if len(rows)==14: break
        grid=rows
    return grid

def serializations():
    out=set()
    known=["matrixsumlist","lastwordsbeforearchichoice","thispassword","enter",
           "ourfirsthintisyourlastcommand","shabef","theseedisplanted",
           "causalitySafenetLunaHSM11110","thematrixhasyou","fubcdoravlethingkymvpsjqwz./",
           "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
           "theflowerblossomsthroughwhatseemstobeaconcretesurface",
           "GSMGIO5BTCPUZZLECHALLENGE","GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
           "HASHTHETEXT","hashthetext","matrixsumlist101","101",
           "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyangwewontgiveawaythepassworditsinfrontofyoureyesbutyourenotseeingitverylaststepisatruegiveawaypromised",
           ]
    for k in known:
        out.add(k)
        for v in (k.lower(), k.upper(), k.replace(" ",""), k+"\n"):
            out.add(v)
    # matrixsumlist como lista de somas por linha/coluna
    g=matrix_bits()
    if g:
        rs=[sum(r) for r in g]
        cs=[sum(col) for col in zip(*g)]
        tot=sum(rs)
        print("[matriz] linhas",rs,"total",tot,"colunas",cs)
        for lst in (rs, cs, rs+cs, cs+rs):
            for sep in ("", ",", " ", "-", ";"):
                out.add(sep.join(map(str,lst)))
        out.add(str(tot))
    # combos da pipeline
    combos=[
        "matrixsumlistlastwordsbeforearchichoicethispassword",
        "lastwordsbeforearchichoicethispassword",
        "matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist",
        "enterlastwordsbeforearchichoicethispassword",
        "thispasswordlastwordsbeforearchichoice",
    ]
    out.update(combos)
    return out

print("\n[fase 1] curados + serializacoes de matrixsumlist")
n=0
for c in sorted(serializations()):
    consider(c); n+=1
print(f"  {n} candidatos.")

print("\n[fase 2] BIP39 singles + pares ordenados (concat sem separador)")
wl=oracles.WORDLIST
cnt=0
for w in wl:
    consider(w); cnt+=1
for a in wl:
    for b in wl:
        consider(a+b); cnt+=1
    # sem separador tambem com espaco entre pares
print(f"  {cnt} candidatos BIP39.")

print("\n=== RESUMO ===")
if HITS:
    for h in HITS: print("HIT", h)
else:
    print("Nenhum pattern-hit. dbbi != sha256(candidato testado) sob b/g-prefix.")
