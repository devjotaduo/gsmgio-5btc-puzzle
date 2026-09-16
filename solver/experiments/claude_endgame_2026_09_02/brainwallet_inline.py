# -*- coding: utf-8 -*-
"""Hipótese: a privkey do prêmio (ou a senha de um blob) é sha256 de uma frase VISÍVEL do puzzle
("regular bitcoin private key", "true give away", "in front of your eyes"). Espaço: frases do README
(todas as sentenças dos textos decodificados), tokens, hints do criador, roadmap; formas raw/upper/
lower/sem-espaço/sem-pontuação/+\n; sha256, sha256², sha256(hex). Oráculo: G.priv_hit (comp+uncomp)
+ espelho N-k, e EVP nos 3 blobs."""
import sys, re, hashlib, json
sys.path.insert(0, ".")
import gsmg_common as G
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
txt = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
phr = set()
# frases dos blocos de texto do README (exclui base64/hex longos)
for block in re.findall(r"```(?:text)?\n(.*?)```", txt, re.S):
    if re.search(r"U2FsdGVk|^[0-9a-f]{60,}", block, re.M): continue
    for line in block.splitlines():
        line = line.strip()
        if len(line) < 3 or re.fullmatch(r"[01 ]+", line): continue
        phr.add(line)
        for s in re.split(r"(?<=[.!?])\s+", line):
            if len(s) > 3: phr.add(s.strip())
# linhas de prosa do README com aspas ou hints
for q in re.findall(r"[\"“>]\s*([^\"”\n]{6,200})", txt): phr.add(q.strip())
extra = """yellowblueprimes matrixsumlist lastwordsbeforearchichoice yinyang wewontgiveawaythepassword
itsinfrontofyoureyesbutyourenotseeingit verylaststepisatruegiveaway promised
yellow blue primes|yin yang|ying yang|Roses are White but often Red|Yellow has a number and so does Blue
Go back to the first puzzle piece without further ado|It might have shown you only one door
beware that the rabbits nest may contain a whole lot more|Hush hush|hushhush|rabbits nest|rabbitsnest
GSMG MEGANIGMA|GSMG MEGANIGMA || 5 BTC|MEGANIGMA|follow the white rabbit|followthewhiterabbit
follow_the_white_rabbit|Follow the white rabbit|the seed is planted|theseedisplanted|gsmg.io/theseedisplanted
GSMG Puzzle|SalPhaseIon|Cosmic Duality|SalPhaseIonCosmicDuality|salvation|the source|thesource
Globally supporting my generation|globallysupportingmygeneration|Regular Bitcoin Private key
regularbitcoinprivatekey|purple pill|purplepill|red pill|blue pill|there is no spoon|thereisnospoon
knock knock neo|knockknockneo|wake up neo|wakeupneo|the matrix has you|themadrixhasyou|temet nosce|temetnosce
free your mind|freeyourmind|I know kung fu|choice is an illusion|the problem is choice|theproblemischoice
hope|Hope. It is the quintessential human delusion|we wont|we won't|If I were you I would hope that we dont meet again
the door to your right|the door to your left|the source and the salvation of zion|thesourceandthesalvationofzion
the future is ours|thefutureisours|jacque fresco|the venus project|thevenusproject|the choice is ours|thechoiceisours
hash the text|HASHTHETEXT|hashthetext|press enter and start talking|our first hint is your last command|ans too|answer too
this password|thispassword|last words before archi choice|enter|matrix sum list|BTCSEED|btcseed|btc seed|seed
half and better half|halfandbetterhalf|better half|betterhalf|half|one for one four for one|1141|11110
in case you manage to crack this|Raising the stakes without extra chances of winning|ciao bella|bella ciao
a fubcd-king & oracle-queen, thingky mvps|fubcd king oracle queen thingky mvps|on a sad board but as wide as the first one seen
eps3.5_kill-process.inc|eps3.4_runtime-error.r00|kill-process|Le Miroir de la Vie et de la Mort|life and death|lifeanddeath
11 SEP 2001|11SEP2001|09112001|20010911|first or zero|firstorzero|zeroed out|prime|101|102|163|193|140|hundred fourty
GSMG|gsmg|gsmg.io|1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe|GSMGIO5BTCPUZZLECHALLENGE|GSMG.IO 5 BTC PUZZLE CHALLENGE
5 BTC|5btc|neo|Neo|trinity|morpheus|oracle|architect|keymaker|merovingian|zion|satoshi|nakamoto|satoshinakamoto
d b b i|dbbi|faed|abba|shabef|shabefanstoo|z|o|carrots were originally purple|orange|dutch|tiny hint|<3
""".replace("\n", "|")
for p in extra.split("|"):
    p = p.strip()
    if p: phr.add(p)
phr.add(G.DBBI); phr.add(G.FAED); phr.add(G.bif_full()); phr.add(G.bif_full()[7:]); phr.add("".join(str(d) for d in G.digits(G.FAED)))
phr.add("".join(str(d) for d in G.digits(G.DBBI)))
def forms(p):
    base = {p, p.upper(), p.lower(), p.title()}
    ns = {re.sub(r"\s+", "", x) for x in base}
    np_ = {re.sub(r"[^A-Za-z0-9]", "", x) for x in base}
    out = base | ns | np_
    return {x for x in out if x}
cands = set()
for p in phr:
    for f in forms(p):
        cands.add(f); cands.add(f + "\n")
print("frases", len(phr), "candidatos", len(cands))
n = 0; hard = []; soft = []
import ecdsa
def priv_both(k32):
    r = G.priv_hit(k32)
    if r: return r
    ki = int.from_bytes(k32, "big")
    if 0 < ki < N:
        r = G.priv_hit((N - ki).to_bytes(32, "big"))
        if r: return dict(r, mirror=True)
    return None
for c in sorted(cands):
    b = c.encode("utf-8", "ignore")
    keys = {sha1 := hashlib.sha256(b).digest(), hashlib.sha256(sha1).digest(), hashlib.sha256(sha1.hex().encode()).digest()}
    for k in keys:
        n += 1
        r = priv_both(k)
        if r: hard.append({"phrase": c, "hit": r})
    h, s = G.try_password_all(c); n += 6
    if h: hard += [dict(x, pw=c) for x in h]
    h, s = G.try_password_all(sha1.hex()); n += 6
    if h: hard += [dict(x, pw="sha256hex:" + c) for x in h]
print(json.dumps({"family": "brainwallet_inline", "n_tests": n, "hard_hits": hard, "n_cands": len(cands)}, ensure_ascii=False)[:3000])
G.jsonl("brainwallet_inline.jsonl", {"family": "brainwallet_inline", "n_tests": n, "n_cands": len(cands), "hard": hard})
