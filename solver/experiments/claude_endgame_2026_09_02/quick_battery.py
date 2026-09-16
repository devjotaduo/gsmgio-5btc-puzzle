# -*- coding: utf-8 -*-
"""Bateria rapida de codificacoes diretas de dbbi/faed (oraculo duro + triagem ASCII)."""
import sys, hashlib, itertools
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver")
import oracles as O, dsl
src=O.sources(); dbbi,faed=src["dbbi"],src["faed"]
D=lambda s,base1=True: [ord(c)-96 if base1 else ord(c)-97 for c in s]
def ascii_frac(b): return sum(32<=x<127 for x in b)/max(1,len(b))
def is_prime(n):
    if n<2: return False
    return all(n%p for p in range(2,int(n**0.5)+1))
res=[]
def report(name,b):
    if not b: return
    af=ascii_frac(b)
    hit_aes=[]
    for form in (b, b.hex().encode(), hashlib.sha256(b).hexdigest().encode()):
        hit_aes+=O.aes_open(form)
    hits=[]
    for off in range(0,max(1,len(b)-31)):
        r=O.check_privkey(b[off:off+32])
        if r: hits.append(r)
    r=O.check_privkey(hashlib.sha256(b).digest())
    if r: hits.append(r)
    flag = "  <<<HIT" if (hit_aes or hits) else ""
    print(f"{name:45s} len={len(b):4d} ascii={af:.2f} {b[:40]!r}{flag}")
    res.append((name,af,hit_aes,hits))
def num_to_bytes(n):
    h=format(n,"x"); h="0"+h if len(h)%2 else h
    return bytes.fromhex(h)
for nm,s in (("dbbi",dbbi),("faed",faed),("faed_np",faed[4:])):
    d1=D(s,True); d0=D(s,False)
    # z-method decimal->bytes
    report(f"{nm} dec->bytes", num_to_bytes(int("".join(map(str,d1)))))
    # base 9 (a=0..i=8) -> bytes
    n=0
    for x in d0: n=n*9+x
    report(f"{nm} base9(a=0)->bytes", num_to_bytes(n))
    n=0
    for x in d1: n=n*10+x  # same as dec
    # base 9 with a=1..i=9 digits mod 9? (i=0)
    n=0
    for x in d1: n=n*9+(x%9)
    report(f"{nm} base9(i=0)->bytes", num_to_bytes(n))
    # triples base 9
    for lab,dd in (("a0",d0),("a1",d1)):
        t=[81*dd[i]+9*dd[i+1]+dd[i+2] for i in range(0,len(dd)-2,3)]
        report(f"{nm} triples b9 {lab} (mod256)", bytes(x%256 for x in t))
        t=[dd[i]+9*dd[i+1]+81*dd[i+2] for i in range(0,len(dd)-2,3)]
        report(f"{nm} triples b9 rev {lab} (mod256)", bytes(x%256 for x in t))
        p=[9*dd[i]+dd[i+1] for i in range(0,len(dd)-1,2)]
        report(f"{nm} pairs b9 {lab}+32", bytes(x+32 for x in p))
        report(f"{nm} pairs b9 {lab}+48", bytes((x+48)%256 for x in p))
        p=[dd[i]+9*dd[i+1] for i in range(0,len(dd)-1,2)]
        report(f"{nm} pairs b9 rev {lab}+32", bytes(x+32 for x in p))
    p=[10*d1[i]+d1[i+1] for i in range(0,len(d1)-1,2)]
    report(f"{nm} pairs dec", bytes(p))
    report(f"{nm} pairs dec+32", bytes((x+32)%256 for x in p))
    report(f"{nm} pairs hex-nibble", bytes(16*d1[i]+d1[i+1] for i in range(0,len(d1)-1,2)))
    # zero-out primes then decimal->bytes
    for base in (0,1):
        z=[0 if is_prime(i+base) else x for i,x in enumerate(d1)]
        report(f"{nm} zero@prime(b{base}) dec->bytes", num_to_bytes(int("".join(map(str,z)))))
        z=[x for i,x in enumerate(d1) if not is_prime(i+base)]
        report(f"{nm} drop@prime(b{base}) dec->bytes", num_to_bytes(int("".join(map(str,z)))))
        z=[x for i,x in enumerate(d1) if is_prime(i+base)]
        report(f"{nm} keep@prime(b{base}) dec->bytes", num_to_bytes(int("".join(map(str,z)))))
        report(f"{nm} keep@prime(b{base}) letters", "".join(s[i] for i in range(len(s)) if is_prime(i+base)).encode())
# textarea hashes as passphrases
sal_line=[l for l in open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md",encoding="utf-8").read().splitlines() if l.startswith("> d b b i")][0][2:]
sal_line=sal_line.replace("*","")
texts={"salphaseion_spaced":sal_line,"salphaseion_nospace":sal_line.replace(" ",""),
       "dbbi":dbbi,"faed":faed,"dbbi_faed":dbbi+faed,"DBBI":dbbi.upper(),"FAED":faed.upper()}
for k,v in texts.items():
    for form in (v, v.upper()):
        for pw in (form, hashlib.sha256(form.encode()).hexdigest()):
            h=O.aes_open(pw)
            if h: print("AES HIT",k,h)
print("textarea passphrases: done")
