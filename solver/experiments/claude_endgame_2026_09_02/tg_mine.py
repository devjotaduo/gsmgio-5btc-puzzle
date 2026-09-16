import json, re, sys
p=r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\result.json"
with open(p,encoding='utf-8') as f: d=json.load(f)
msgs=[m for m in d['messages'] if m.get('type')=='message']
def txt(m):
    t=m.get('text')
    if isinstance(t,list): return ''.join(x if isinstance(x,str) else x.get('text','') for x in t)
    return t or ''
def line(m,n=700): return f"{m['date'][:16]} #{m['id']} [{m.get('from')}] {txt(m)[:n]!r}"
cats={
 'almost': r"\balmost\b.*(decrypt|open|pass|readable|plain|text|crack)|(decrypt|open|pass|readable|plain|crack).*\balmost\b|\bnearly\b.*(decrypt|crack|open)|partial(ly)? (readable|plaintext|decrypt)|readable (text|output|plain)|half readable|looks like (english|text|words)|\bplaintext\b",
 'html': r"textarea|view-source|view source|source code|\bhtml\b|hidden (text|div|element|field|comment)|html comment|<!--|inspect element|dev ?tools|page source",
 'lastwords': r"lastwordsbefore|last words before|archichoice|archi choice|architect.?s? choice",
 'anstoo': r"\bans too\b|answer too|shabef|sha256 answer|first hint is your last command|last command",
 'smallblob': r"\bsmall\b.*(blob|block|aes|cipher)|(blob|block|aes|cipher).*\bsmall\b|80 bytes|5 blocks|two lines|second line|QvX0|U2FsdGVkX1\+0Wl49",
 'dbbifaed': r"\bdbbi|\bfaed|bifid|btcseed|trifid",
 'enter': r"\benter\b.*(binary|a/b|ab|bits|line)|(binary|bits).*\benter\b",
 'yinyang': r"yin.?yang|ying.?yang",
 'primeidx': r"prime (index|indices|position)|prime.{0,20}last words|30 to 31|31 bytes|30 bytes",
 'purple': r"purple|carrot|orange|dutch",
 'door': r"another door|third door|3rd door|2nd door|second door",
}
res={k:[] for k in cats}
for m in msgs:
    t=txt(m)
    if not t: continue
    for k,rx in cats.items():
        if re.search(rx,t,re.I): res[k].append(m)
for k,v in res.items():
    open(f'cat_{k}.txt','w',encoding='utf-8').write('\n'.join(line(m) for m in v))
    print(k,len(v))
# specific users
for name,fn in [('Denis Golovkin','user_denis'),('gnomad','user_gnomad'),('PoW','user_pow'),('Charlie Craig','user_charlie')]:
    v=[m for m in msgs if m.get('from')==name]
    open(f'{fn}.txt','w',encoding='utf-8').write('\n'.join(line(m,1200) for m in v))
    print(name,len(v))
