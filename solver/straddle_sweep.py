# -*- coding: utf-8 -*-
"""Varredura COMPLETA da familia 'straddling checkerboard + substituicao mono':
todos os conjuntos de digitos de escape (1,2,3 escapes sobre a..i) para dbbi e faed,
hill-climb com quadgramas EN, e NULO CASADO (mesmos tokens embaralhados).
Fecha ou abre a leitura descoberta no export 2026-09-08."""
import random, itertools, time
from collections import Counter
from scorer import Scorer
import oracles as O
sc=Scorer()
ALPHA25="ABCDEFGHIKLMNOPQRSTUVWXYZ"
DBBI=O.sources()["dbbi"]; FAED=O.sources()["faed"]

def parse_prefix(s,pref):
    o=[];i=0
    while i<len(s):
        if s[i] in pref:
            if i+1>=len(s): return None
            o.append(s[i:i+2]); i+=2
        else: o.append(s[i]); i+=1
    return o

def hill(tokens, iters=20000, restarts=6, seed=0, patience=900):
    syms=sorted(set(tokens)); k=len(syms)
    if k>25: return None
    idx={s:i for i,s in enumerate(syms)}; ci=[idx[t] for t in tokens]
    rng=random.Random(seed); pool=list(ALPHA25); best=(-1e9,"")
    dec=lambda kk:"".join(kk[c] for c in ci)
    for r in range(restarts):
        key=pool[:]; rng.shuffle(key); cur=key[:k]
        cur_s=sc(dec(cur)); since=0
        for it in range(iters):
            a=rng.randrange(k)
            if rng.random()<0.6:
                b=rng.randrange(k)
                if a==b: continue
                cur[a],cur[b]=cur[b],cur[a]; s=sc(dec(cur))
                if s>cur_s: cur_s=s; since=0
                else: cur[a],cur[b]=cur[b],cur[a]; since+=1
            else:
                out=[c for c in pool if c not in cur]
                if not out: since+=1; continue
                nl=out[rng.randrange(len(out))]; old=cur[a]; cur[a]=nl; s=sc(dec(cur))
                if s>cur_s: cur_s=s; since=0
                else: cur[a]=old; since+=1
            if since>=patience: break
        if cur_s>best[0]: best=(cur_s,dec(cur))
    return best

def null_dist(tokens, n=8, seed=99):
    rng=random.Random(seed); L=list(tokens); out=[]
    for i in range(n):
        rng.shuffle(L)
        b=hill(L,restarts=3,iters=12000,seed=1000+i)
        if b: out.append(b[0]/len(L))
    out.sort(); return out

results=[]
for name,src in (("dbbi",DBBI),("faed",FAED)):
    print(f"\n########## {name} ##########", flush=True)
    cands=[]
    for k in (1,2,3):
        for pre in itertools.combinations("abcdefghi",k):
            t=parse_prefix(src,"".join(pre))
            if t and len(set(t))<=25 and len(t)>=40: cands.append(("".join(pre),t))
    print(f"{len(cands)} conjuntos de escape validos", flush=True)
    scored=[]
    t0=time.time()
    for pre,t in cands:
        b=hill(t,seed=hash(pre)%9999)
        if b: scored.append((b[0]/len(t), pre, len(t), len(set(t)), b[1]))
    scored.sort(reverse=True)
    print(f"  ({time.time()-t0:.0f}s) TOP 6 por score/char:", flush=True)
    for s,pre,n,d,pt in scored[:6]:
        print(f"   escapes={pre:<3} n={n:<4} dist={d:<3} score/char={s:+.4f}  {pt[:70]}", flush=True)
    # nulo casado no melhor
    s,pre,n,d,pt = scored[0]
    nd=null_dist(parse_prefix(src,pre))
    print(f"  NULO (8 embaralhamentos do melhor, escapes={pre}): min {nd[0]:+.4f} max {nd[-1]:+.4f}", flush=True)
    print(f"  REAL {s:+.4f}  ->  {'ACIMA do nulo' if s>nd[-1] else 'DENTRO do nulo (sem sinal)'}", flush=True)
    results.append((name,s,nd[-1],pre,pt))
    # oraculos no melhor plaintext
    import hashlib
    hits=[]
    for form in (pt,pt.lower()):
        r=O.aes_open(form)
        if r: hits.append(r)
        h=hashlib.sha256(form.encode()).hexdigest()
        r=O.aes_open(h)
        if r: hits.append(("sha256",r))
        p=O.check_privkey(bytes.fromhex(h))
        if p: hits.append(("priv",p))
    print("  oraculos:", hits if hits else "0 hits", flush=True)

print("\n===== VEREDITO =====")
for name,s,nmax,pre,pt in results:
    print(f"{name}: melhor {s:+.4f} vs nulo-max {nmax:+.4f} -> {'SINAL' if s>nmax else 'sem sinal'}")
