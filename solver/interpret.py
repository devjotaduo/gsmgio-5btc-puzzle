# -*- coding: utf-8 -*-
"""
Ataque INTERPRETATIVO via llama3 local (Ollama). O gargalo do endgame nao e
computacional — e descobrir qual ALFABETO/METODO o "first hint" fixa. Aqui o
modelo local LE a discussao da comunidade (result.json) sobre o "first hint" e
propoe keywords/alfabetos concretos; cada proposta CAI na verificacao por oraculo
(Bifid do faed -> readable + aes_open + priv). O modelo propoe; o oraculo julga.
"""
import os, sys, json, time, re, urllib.request, hashlib
import oracles as O
from scorer import Scorer

HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)
ROOT = os.path.dirname(HERE)
MODEL = os.environ.get("GSMG_MODEL", "llama3:latest")
ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"

CONTEXT = """You are helping crack the final stage of the GSMG.IO 5 BTC puzzle.
Known facts:
- A 570-symbol string "faed" over the 9 letters a-i must be decoded.
- The method family is a Polybius/Bifid/checkerboard cipher (proven in earlier phases).
- We NEED the ALPHABET/KEYWORD that seeds the 5x5 cipher square. The creator said
  the "first hint" tells us how to interpret it: "our first hint is your last command",
  "return to the source code", "reinserting the prime basics".
- Bifid of faed with square "DBIFHCEGA..." already yields the header BTCSEED, but the
  rest is not readable — so the square/keyword is probably slightly different.
Your job: from the community discussion below, extract CONCRETE, TESTABLE guesses."""

INSTR = """Output ONLY JSON:
{"keywords": ["<short keyword or phrase that could seed the cipher square>", ...],
 "alphabets": ["<a 25-letter arrangement A-Z without J, if anyone proposed one>", ...],
 "phrases": ["<candidate password phrase>", ...],
 "notes": "<one line: what the 'first hint' most plausibly means>"}
Only include items actually supported by the text. Empty lists are fine."""

def _txt(m):
    t = m.get("text", "")
    if isinstance(t, list):
        t = " ".join(x if isinstance(x, str) else x.get("text", "") for x in t)
    return t

def extract(max_msgs=400):
    """Mensagens de maior sinal sobre o 'first hint' / alfabeto / metodo."""
    d = json.load(open(os.path.join(ROOT, "result.json"), encoding="utf-8"))
    strong = ["first hint", "last command", "keyword", "alphabet", "return to the source",
              "prime basic", "reinsert", "the source code", "salphase"]
    out = []
    for m in d.get("messages", []):
        t = _txt(m).strip()
        low = t.lower()
        if len(t) < 25:
            continue
        score = sum(3 if k in ("first hint", "keyword", "last command") else 1
                    for k in strong if k in low)
        if score:
            out.append((score, t.replace("\n", " ")[:600]))
    out.sort(key=lambda x: -x[0])
    seen = set(); uniq = []
    for _, t in out:
        k = t[:80]
        if k in seen:
            continue
        seen.add(k); uniq.append(t)
        if len(uniq) >= max_msgs:
            break
    return uniq

def llama(prompt, timeout=180):
    body = json.dumps({"model": MODEL, "prompt": prompt, "format": "json", "stream": False,
                       "options": {"temperature": 0.7, "num_predict": 800}}).encode()
    req = urllib.request.Request("http://localhost:11434/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
        return json.loads(resp["response"])
    except Exception as e:
        return {}

def keyword_to_square(kw):
    """Constroi quadrado Polybius: dedup(keyword) + resto do alfabeto (sem J)."""
    s = re.sub(r"[^A-Z]", "", kw.upper().replace("J", "I"))
    seen = []
    for c in s + ALPHA25:
        if c not in seen and c in ALPHA25:
            seen.append(c)
    return "".join(seen) if len(seen) == 25 else None

def bifid_decrypt(ct, alpha, period):
    p = {c: (i // 5, i % 5) for i, c in enumerate(alpha)}
    out = []
    for off in range(0, len(ct), period):
        blk = ct[off:off + period]; seq = []
        for c in blk:
            r, co = p[c]; seq += [r, co]
        n = len(blk); rows, cols = seq[:n], seq[n:]
        out.append("".join(alpha[rows[i] * 5 + cols[i]] for i in range(n)))
    return "".join(out)

def hard_oracles(pt):
    for s in (pt, pt[7:]):
        for f in {s, s.lower(), hashlib.sha256(s.encode()).hexdigest()}:
            h = O.aes_open(f)
            if h:
                return {"kind": "aes_open", "pw": f[:40], "hits": h}
        for c in (hashlib.sha256(s.encode()).digest(), hashlib.sha256(s.lower().encode()).digest()):
            r = O.check_privkey(c)
            if r:
                return {"kind": "privkey", "hit": r}
    return None

def verify_square(sq, scorer, label):
    """Decodifica faed com o quadrado em varios periodos; score + oraculos duros."""
    ct = O.sources()["faed"].upper()
    best = None
    for period in (570, 285, 190, 114, 95, 57, 38, 30, 19, 15):
        pt = bifid_decrypt(ct, sq, period)
        sc = scorer(pt)
        hit = hard_oracles(pt)
        if hit:
            return {"solve": True, "period": period, "square": sq, "label": label, **hit, "pt": pt[:60]}
        if best is None or sc > best[0]:
            best = (sc, period, pt)
    return {"solve": False, "score": round(best[0], 3), "period": best[1],
            "square": sq, "label": label, "head": best[2][:40]}

def main():
    scorer = Scorer()
    print(f"[{time.strftime('%H:%M:%S')}] interpret via {MODEL} | extraindo discussao...")
    msgs = extract()
    print(f"[{time.strftime('%H:%M:%S')}] {len(msgs)} mensagens de alto sinal. Analisando em lotes...")
    # lotes que cabem no contexto (8192 tokens ~ 6k chars de material)
    CHUNK = 14
    proposals = {"keywords": set(), "alphabets": set(), "phrases": set()}
    notes = []
    for i in range(0, len(msgs), CHUNK):
        batch = msgs[i:i + CHUNK]
        material = "\n---\n".join(batch)
        prompt = f"{CONTEXT}\n\nCOMMUNITY DISCUSSION:\n{material}\n\n{INSTR}"
        data = llama(prompt)
        if not isinstance(data, dict):
            continue
        for k in ("keywords", "alphabets", "phrases"):
            for v in data.get(k, []) or []:
                if isinstance(v, str) and 2 <= len(v) <= 80:
                    proposals[k].add(v.strip())
        if data.get("notes"):
            notes.append(str(data["notes"])[:200])
        print(f"[{time.strftime('%H:%M:%S')}] lote {i//CHUNK+1}/{(len(msgs)+CHUNK-1)//CHUNK}: "
              f"+{len(data.get('keywords',[]) or [])}kw +{len(data.get('alphabets',[]) or [])}alf")

    # dedup -> quadrados a testar
    squares = {}  # square -> label
    for kw in proposals["keywords"] | proposals["phrases"]:
        sq = keyword_to_square(kw)
        if sq:
            squares.setdefault(sq, f"kw:{kw[:30]}")
    for a in proposals["alphabets"]:
        sq = keyword_to_square(a) if len(re.sub(r'[^A-Z]', '', a.upper())) != 25 else a.upper().replace("J", "I")
        if sq and len(set(sq)) == 25:
            squares.setdefault(sq, f"alpha:{a[:30]}")
    squares.setdefault(CANON, "CANON(baseline)")

    print(f"\n[{time.strftime('%H:%M:%S')}] llama propos {len(proposals['keywords'])} keywords, "
          f"{len(proposals['alphabets'])} alfabetos -> {len(squares)} quadrados unicos p/ testar")
    results = []
    for sq, label in squares.items():
        r = verify_square(sq, scorer, label)
        results.append(r)
        if r.get("solve"):
            json.dump(r, open(os.path.join(OUT, "SOLVED.json"), "w"), indent=2)
            print(f"\n!!! SOLVE via '{label}' — out/SOLVED.json"); return
    results.sort(key=lambda r: -r["score"])
    print(f"\n=== TOP quadrados por legibilidade (baseline CANON={next(r['score'] for r in results if 'CANON' in r['label'])}) ===")
    for r in results[:12]:
        print(f"  {r['score']}  per={r['period']:3d}  {r['label']:34s} head={r['head']}")
    json.dump({"notes": notes[:20], "proposals": {k: sorted(v) for k, v in proposals.items()},
               "results": results[:40]},
              open(os.path.join(OUT, "interpret.json"), "w"), ensure_ascii=False, indent=2)
    print(f"\n[{time.strftime('%H:%M:%S')}] gravado out/interpret.json ({len(results)} quadrados testados)")
    if notes:
        print("Notas do llama (o que o 'first hint' significa):")
        for n in notes[:6]:
            print("  -", n)

if __name__ == "__main__":
    main()
