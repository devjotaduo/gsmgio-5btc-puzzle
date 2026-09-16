import json, urllib.request, urllib.parse, re, sys
NL = ["Nederland","Bitcoin","Cryptografie","Amsterdam","Geschiedenis_van_Nederland","Tweede_Wereldoorlog","Rembrandt_van_Rijn","Koninkrijk_der_Nederlanden","Vincent_van_Gogh","Rotterdam","België","Antwerpen_(stad)","Nederlands","Willem_van_Oranje","Eerste_Wereldoorlog","Europese_Unie","Filosofie","Internet","Wiskunde","Utrecht_(stad)"]
DE = ["Deutschland","Kryptographie","Bitcoin","Berlin","Geschichte_Deutschlands","Zweiter_Weltkrieg","Mathematik","Philosophie","Europäische_Union","Internet","Deutsche_Sprache","Johann_Wolfgang_von_Goethe"]
def fetch(lang, title):
    url = f"https://{lang}.wikipedia.org/w/api.php?" + urllib.parse.urlencode({"action":"query","prop":"extracts","explaintext":1,"format":"json","titles":title,"redirects":1})
    req = urllib.request.Request(url, headers={"User-Agent":"gsmg-research/1.0 (dev@jotaduo.com)"})
    d = json.load(urllib.request.urlopen(req, timeout=60))
    pages = d["query"]["pages"]
    return "\n".join(p.get("extract","") for p in pages.values())
for lang, lst in (("nl",NL),("de",DE)):
    out = []
    for t in lst:
        try:
            x = fetch(lang, t); out.append(x); print(lang, t, len(x), flush=True)
        except Exception as e:
            print(lang, t, "ERR", e, flush=True)
    open(f"corpus/{lang}.txt","w",encoding="utf-8").write("\n".join(out))
