# -*- coding: utf-8 -*-
"""
LEAD 2026-09-08: dbbi/faed como STRADDLING CHECKERBOARD com digitos de escape
b(=2) e g(=7) -- a MESMA familia de cifra ja provada na fase 3.2.2 (escapes 1,4).

Estrutura (verificada):
  alfabeto de dbbi/faed = a..i (1..9), sem 'o'/0.
  escapes b,g => 7 slots de 1 digito + 9 + 9 = 25 slots = alfabeto A-Z sem J.
  dbbi -> 64 tokens / 16 distintos ; faed -> 451 tokens / 25 distintos (capacidade CHEIA).

Teste: hill-climb monoalfabetico (quadgramas EN) sobre os tokens, com teto de
controle medido no mesmo tamanho. Qualquer plaintext -> oraculos AES/privkey.
"""
import random, time, sys
from collections import Counter
from scorer import Scorer
import oracles as O

sc = Scorer()
DBBI = O.sources()["dbbi"]; FAED = O.sources()["faed"]
ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # sem J (padrao do puzzle)

def parse_prefix(s, pref):
    o=[]; i=0
    while i<len(s):
        if s[i] in pref:
            if i+1>=len(s): return None
            o.append(s[i:i+2]); i+=2
        else: o.append(s[i]); i+=1
    return o

def hill(tokens, iters=30000, restarts=14, seed=0, patience=1500):
    syms=sorted(set(tokens)); k=len(syms)
    idx={s:i for i,s in enumerate(tokens[0:0])}  # placeholder
    idx={s:i for i,s in enumerate(syms)}
    ci=[idx[t] for t in tokens]
    rng=random.Random(seed)
    pool=list(ALPHA25)
    best=(-1e9,"",None)
    for r in range(restarts):
        key=pool[:]; rng.shuffle(key); key=key[:k]
        # garante k letras distintas
        cur=key[:]
        dec=lambda kk: "".join(kk[c] for c in ci)
        cur_s=sc(dec(cur)); since=0
        for it in range(iters):
            a=rng.randrange(k)
            if rng.random()<0.5:
                b=rng.randrange(k)
                if a==b: continue
                cur[a],cur[b]=cur[b],cur[a]
                s=sc(dec(cur))
                if s>cur_s: cur_s=s; since=0
                else: cur[a],cur[b]=cur[b],cur[a]; since+=1
            else:
                # troca com letra fora da chave (explora as 25-k restantes)
                out=[c for c in pool if c not in cur]
                if not out: since+=1; continue
                nl=out[rng.randrange(len(out))]; old=cur[a]; cur[a]=nl
                s=sc(dec(cur))
                if s>cur_s: cur_s=s; since=0
                else: cur[a]=old; since+=1
            if since>=patience: break
        if cur_s>best[0]: best=(cur_s,dec(cur),cur[:])
    return best

def control(n, seed=1):
    """teto: texto EN de n chars cifrado por subst. aleatoria, recuperado pelo mesmo motor"""
    en=("THEUNANIMOUSDECLARATIONOFTHETHIRTEENUNITEDSTATESOFAMERICAWHENINTHECOURSEOFHUMANEVENTS"
        "ITBECOMESNECESSARYFORONEPEOPLETODISSOLVETHEPOLITICALBANDSWHICHHAVECONNECTEDTHEMWITH"
        "ANOTHERANDTOASSUMEAMONGTHEPOWERSOFTHEEARTHTHESEPARATEANDEQUALSTATIONTOWHICHTHELAWS"
        "OFNATUREANDOFNATURESGODENTITLETHEMADECENTRESPECTTOTHEOPINIONSOFMANKINDREQUIRESTHAT"
        "THEYSHOULDDECLARETHECAUSESWHICHIMPELTHEMTOTHESEPARATION")
    en=en.replace("J","I")[:n]
    rng=random.Random(seed); perm=list(ALPHA25); rng.shuffle(perm)
    m={ALPHA25[i]:perm[i] for i in range(25)}
    ct=[m[c] for c in en]
    s,pt,_=hill(ct,seed=seed)
    acc=sum(a==b for a,b in zip(pt,en))/len(en)
    return s, acc, pt[:60]

def report(name, tokens):
    print(f"\n=== {name}: {len(tokens)} tokens, {len(set(tokens))} distintos ===", flush=True)
    t0=time.time(); s,pt,key=hill(tokens); el=time.time()-t0
    print(f"  hill-climb score/char = {s/len(tokens):+.3f}   ({el:.0f}s)", flush=True)
    print(f"  plaintext: {pt[:200]}", flush=True)
    cs,acc,cpt=control(len(tokens))
    print(f"  CONTROLE mesmo tamanho: score/char = {cs/len(tokens):+.3f}, recuperacao {acc*100:.0f}%", flush=True)
    print(f"  controle pt: {cpt}", flush=True)
    hits=[]
    for form in (pt, pt.lower(), pt.title()):
        r=O.aes_open(form)
        if r: hits.append(r)
    import hashlib
    for form in (pt, pt.lower()):
        h=hashlib.sha256(form.encode()).hexdigest()
        r=O.aes_open(h)
        if r: hits.append(("sha256",r))
        pr=O.check_privkey(bytes.fromhex(h))
        if pr: hits.append(("priv",pr))
    print("  oraculos:", hits if hits else "0 hits", flush=True)
    return s/len(tokens), cs/len(tokens)

tk_d=parse_prefix(DBBI,"bg"); tk_f=parse_prefix(FAED,"bg")
print("dbbi:",len(tk_d),len(set(tk_d)),"| faed:",len(tk_f),len(set(tk_f)), flush=True)
report("FAED / escapes b,g", tk_f)
report("DBBI / escapes b,g", tk_d)
