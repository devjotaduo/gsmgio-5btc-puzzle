# -*- coding: utf-8 -*-
"""
Continuacao do lead dbbi=SHA256(64/16). Dois testes que faltavam:
 (A) tokens como CHAVE/SENHA direta sob mapeamentos naturais token->nibble:
     - 64 nibbles => 32 bytes privkey (check_privkey)
     - 64 hex chars => senha AES do SMALL/COSMIC (aes_open, lower/upper)
 (B) pre-imagem ampliada: vocabulario do proprio criador + plaintexts das fases
     + numeros, singles e pares, contra o padrao de igualdade de dbbi.
"""
import sys, os, hashlib, itertools, re, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles

DBBI = oracles.sources()["dbbi"]; FAED = oracles.sources()["faed"]
def parse_prefix(s, pref):
    o=[]; i=0
    while i<len(s):
        if s[i] in pref:
            if i+1>=len(s): return None
            o.append(s[i:i+2]); i+=2
        else: o.append(s[i]); i+=1
    return o
def pattern(seq):
    lab={}; return tuple(lab.setdefault(x,len(lab)) for x in seq)

TOK = parse_prefix(DBBI,"bg")
assert len(TOK)==64 and len(set(TOK))==16
uniq = list(dict.fromkeys(TOK))           # 1a ocorrencia
cnt = collections.Counter(TOK)
HEX = "0123456789abcdef"

# ---- (A) mapas naturais token->nibble ----
maps = {}
maps["firstocc"]   = {t:i for i,t in enumerate(uniq)}
maps["alpha"]      = {t:i for i,t in enumerate(sorted(set(TOK)))}
maps["alpha_rev"]  = {t:15-i for i,t in enumerate(sorted(set(TOK)))}
maps["freq_desc"]  = {t:i for i,(t,_) in enumerate(cnt.most_common())}
maps["freq_asc"]   = {t:i for i,(t,_) in enumerate(sorted(cnt.items(),key=lambda x:(x[1],x[0])))}
maps["firstocc_rev"]={t:15-i for i,t in enumerate(uniq)}
# a1z26-ish: valor do 1o char (a=1..i=9), depois normaliza p/ 0..15 por ranking
def a1(t): return ord(t[0])-ord('a')+1
maps["a1z26rank"]  = {t:i for i,t in enumerate(sorted(set(TOK), key=lambda t:(a1(t), len(t), t)))}

def hits_for_hex(hexstr, tag):
    found=[]
    for pw in (hexstr, hexstr.upper()):
        r=oracles.aes_open(pw)
        if r: found.append(("AES",tag,pw,r))
    try:
        pr=oracles.check_privkey(bytes.fromhex(hexstr))
        if pr: found.append(("PRIV",tag,hexstr,pr))
    except Exception: pass
    return found

print("== (A) tokens como chave/senha direta ==")
anyA=False
for mname, mp in maps.items():
    for order,seq in (("fwd",TOK),("rev",TOK[::-1])):
        hx="".join(HEX[mp[t]] for t in seq)
        f=hits_for_hex(hx, f"{mname}/{order}")
        if f:
            anyA=True
            for x in f: print("  HIT", x)
if not anyA: print("  0 hits (nenhum mapa natural abre AES nem bate privkey).")

# tambem: os 64 nibbles como ENTROPIA BIP39? 32 bytes -> 24 palavras (checksum)
print("== (A2) 32 bytes como entropia BIP39 (checksum) ==")
try:
    from mnemonic import Mnemonic
    M=Mnemonic("english"); anyB=False
    for mname,mp in maps.items():
        for order,seq in (("fwd",TOK),("rev",TOK[::-1])):
            b=bytes(int("".join(HEX[mp[t]] for t in seq)[i:i+2],16) for i in range(0,64,2))
            mn=M.to_mnemonic(b)
            res=oracles.check_mnemonic(mn.split())
            if res and res.get("match"):
                anyB=True; print("  BIP39 MATCH", mname,order,mn)
    if not anyB: print("  0 BIP39 match.")
except Exception as e:
    print("  skip", e)

# ---- (B) pre-imagem ampliada ----
targets={"bg":pattern(TOK),"bg_rev":pattern(TOK[::-1])}
def hexpat(h): return pattern(list(h))
HITS=[]
def consider(cand):
    data=cand.encode() if isinstance(cand,str) else cand
    hp=hexpat(hashlib.sha256(data).hexdigest())
    for name,tp in targets.items():
        if hp==tp:
            h=hashlib.sha256(data).hexdigest()
            HITS.append((name,cand,h)); print("  *** PREIMAGE HIT",name,repr(cand),h)
            for pw in (h,h.upper()):
                r=oracles.aes_open(pw)
                if r: print("     AES",r)

# vocabulario do criador + grupo + plaintexts
vocab=set()
for path in [
    r"C:/Users/ruthe/Downloads/Telegram Desktop/ChatExport_2026-09-08/files/GSMG_JRK.md",
    r"C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle/_work/looking_forward.txt",
]:
    if os.path.exists(path):
        t=open(path,encoding="utf-8",errors="ignore").read().lower()
        vocab.update(re.findall(r"[a-z]{3,20}", t))
# plaintexts conhecidos (palavras)
pt=("your life is the sum of a remainder of an unbalanced equation inherent to the programming of this puzzle "
    "in case you manage to crack this the private keys belong to half and better half and they also need funds to live "
    "the function of the one is now to return to the source reinserting the prime the matrix has you follow the white rabbit "
    "yellow blue primes matrix sum list last words before archichoice yin yang").split()
vocab.update(pt)
# numeros tematicos
for n in ("101","163","140","1141","91","570","23","16","7","42","1539","11110","0"):
    vocab.add(n)
print(f"== (B) pre-imagem: {len(vocab)} termos, singles + pares ==")
V=sorted(vocab)
for w in V: consider(w)
# pares (concat e com espaco) dos ~1500 termos -> ~4.5M
for a in V:
    for b in V:
        consider(a+b)
if not HITS: print("  0 preimage hits (singles+pares do vocabulario).")
print("\nFIM.")
