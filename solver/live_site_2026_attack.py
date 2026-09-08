# -*- coding: utf-8 -*-
"""
Sessao 2026-09-08: gsmg.io foi REVIVIDO pelo criador (Last-Modified 2026-08-15/17).
Hipotese barata: os textos novos da pagina sao a senha/insumo dos blobs.
Testa cada texto como senha crua, sha256 hex (lower/upper) e HASHTHETEXT
(UPPER sem espacos -> sha256) nos 3 blobs (SMALL, COSMIC, TAIL32), 2 KDFs.
Inclui o minikey de Che (#50514) e as variantes de E (#71180/#71197).
"""
import sys, os, hashlib, base64, itertools, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
import base58

TAIL32_B64=("U2FsdGVkX1+0Wl49gnWTyiimluu7V3+vl7st0gUt9sWDzNLxDmlPMsDSiuW2a46z"
            "gKlIi8aaqY5gpJPPEzW1n9n3/26qs4zstWtPKF8Zs/BTNN4IiEh4qu18mdC0NAv4")
raw=base64.b64decode(TAIL32_B64); assert raw[:8]==b"Salted__"
BLOBS=dict(O.blobs()); BLOBS["TAIL32"]=(raw[8:16],raw[16:])
assert BLOBS["TAIL32"][0].hex()=="b45a5e3d827593ca"

def aes_all(pw):
    pw=pw.encode() if isinstance(pw,str) else pw; hits=[]
    for name,(salt,ct) in BLOBS.items():
        for hmod in (SHA256,MD5):
            k,iv=O._evp(pw,salt,hmod); p=AES.new(k,AES.MODE_CBC,iv).decrypt(ct); pad=p[-1]
            if 1<=pad<=16 and p.endswith(bytes([pad])*pad):
                body=p[:-pad]; asc=sum(32<=b<127 for b in body)/max(1,len(body))
                hits.append((name,hmod.__name__,round(asc,2),body[:60]))
    return hits

texts=[
 "The lights are off.","The lights are off","Thelightsareoff","thelightsareoff",
 "Nine years of chaos ended. One mystery remains.","Nine years of chaos ended","One mystery remains","onemysteryremains","nineyearsofchaosended",
 "Follow the white rabbit","followthewhiterabbit","FOLLOWTHEWHITERABBIT",
 "WARNING: carrier anomaly","carrier anomaly","carrieranomaly","Trace program: running","traceprogramrunning","SYSTEM FAILURE","systemfailure",
 "2017 — 2026","2017-2026","20172026","2017 - 2026","2017","2026",
 "A fully automated crypto trading bot","afullyautomatedcryptotradingbot",
 "Hello :-)","Hello ;)","hello",
 "Nice to see you around! Good luck little bunny hunter ;)","You made it to the next step! Good luck little bunny hunter ;)",
 "Good luck little bunny hunter","little bunny hunter","littlebunnyhunter","bunny hunter","bunnyhunter","You made it to the next step","youmadeittothenextstep","Nice to see you around","nicetoseeyouaround",
 "Former GSMG homepage","GSMG shutdown sequence","finalGrid","final-title","Nine years of chaos","The lights are off. Nine years of chaos ended. One mystery remains.",
 "GSMG.IO5BTCPUZZLECHALLENGE","gsmg.io5btcpuzzlechallenge","GSMG | GSMG","GSMG",
 "gsmg.io magic puzzle piece","White Rabbits everywhere","puzzlepiece","GSMG.io Puzzle piece",
 "Iykyk","iykyk","Give yourself yourself and yourself will be given yourself","giveyourselfyourselfandyourselfwillbegivenyourself",
 "Pfff. Coincidence.","Couple hours","couplehours","I rushed it","irushedit","irushedtit",
 "Carrots were originally purple, until the Dutch turned them orange in the 1600s to kiss up to their royal family.","purple","orange","carrot","purplecarrot","orangecarrot","royalfamily","Orange-Nassau",
]
# E #71180/#71197: sha256(title + enter + address) e permutacoes
T="GSMGIO5BTCPUZZLECHALLENGE"; ADDR="1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
for parts in itertools.permutations([T,"enter",ADDR]):
    texts.append("".join(parts)); texts.append(" ".join(parts))
for extra in ("ENTER","matrixsumlist","101","enter\n"):
    texts.append(T+extra+ADDR); texts.append(T+ADDR+extra)
# minikey de Che (#50514): 24 chars da URL, 7 bits cada (sem o 8o bit) = 168 bits -> base58 -> 'S'+...
url=b"gsmg.io/theseedisplanted"
bits="".join(format(b&0x7f,"07b") for b in url); n=int(bits,2); b21=n.to_bytes(21,"big")
mini="S"+base58.b58encode(b21).decode()
texts+= [mini, mini.upper(), base58.b58encode(b21).decode()]
cands=set()
for t in texts:
    cands.add(t)
    cands.add(hashlib.sha256(t.encode()).hexdigest()); cands.add(hashlib.sha256(t.encode()).hexdigest().upper())
    ht=re.sub(r"[^A-Za-z0-9]","",t).upper(); cands.add(ht); cands.add(hashlib.sha256(ht.encode()).hexdigest())
    cands.add(t.lower()); cands.add(t.replace(" ",""))
print("candidatos:",len(cands))
hits=[]; pads=0
for c in sorted(cands):
    h=aes_all(c)
    for x in h:
        pads+=1
        if x[2]>=0.85: hits.append((c,x))
print("paddings validos:",pads,"(esperado ~",round(len(cands)*6/256,1),")")
print("HITS legiveis:",hits if hits else "0")
# minikey -> privkey
for m in (mini,):
    pk=hashlib.sha256(m.encode()).digest(); r=O.check_privkey(pk)
    print("minikey",m,"->",r if r else "nao bate")
