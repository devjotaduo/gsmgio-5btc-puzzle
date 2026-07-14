# -*- coding: utf-8 -*-
"""
Ataque de STRADDLING CHECKERBOARD (familia VIC) ao faed — a cifra COMPROVADA na
fase 3.2.2 do puzzle. Encaixe estrutural: faed = 9 simbolos (a-i -> digitos 1-9,
sem 0). Com a coluna 0 morta, o checkerboard tem 7 (topo) + 9 + 9 = 25 slots =
exatamente as 25 letras (A-Z sem J).

Layout (digitos 1..9; 0 nunca aparece):
  topo[1..9]: 2 colunas sao digitos-de-escape (e1,e2), 7 colunas tem letras
  linha_e1[1..9]: 9 letras (prefixadas pelo digito e1)
  linha_e2[1..9]: 9 letras (prefixadas pelo digito e2)
Decode do fluxo de digitos:
  d==e1 -> consome proximo d2 -> linha_e1[d2]
  d==e2 -> consome proximo d2 -> linha_e2[d2]
  senao -> topo[d]

Busca: permutacao das 25 letras nos 25 slots + escolha de (e1,e2). Hill-climb
com restarts maximizando quadgramas EN. Controle valida a capacidade do motor.
Oraculos DUROS (aes_open/privkey) no melhor plaintext.
"""
import os, sys, json, time, random, argparse, hashlib
import oracles as O
from scorer import Scorer

HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)
ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # 25 letras, sem J

def faed_digits():
    s = O.sources()["faed"]  # a-i
    return [ord(c) - ord('a') + 1 for c in s]  # a=1..i=9

def build_layout(perm25, e1, e2):
    """perm25: 25 letras. Retorna (top[10], row1[10], row2[10]) indexaveis por 1..9.
    Indice 0 = None (coluna morta). e1<e2 esperado."""
    top = [None] * 10; row1 = [None] * 10; row2 = [None] * 10
    letters = list(perm25)
    # topo: colunas 1..9 exceto e1,e2 -> 7 letras
    li = 0
    for c in range(1, 10):
        if c == e1 or c == e2:
            continue
        top[c] = letters[li]; li += 1
    for d in range(1, 10):
        row1[d] = letters[li]; li += 1
    for d in range(1, 10):
        row2[d] = letters[li]; li += 1
    assert li == 25
    return top, row1, row2

def decode(digits, perm25, e1, e2):
    top, row1, row2 = build_layout(perm25, e1, e2)
    out = []; i = 0; n = len(digits)
    while i < n:
        d = digits[i]
        if d == e1 and i + 1 < n:
            out.append(row1[digits[i + 1]] or "?"); i += 2
        elif d == e2 and i + 1 < n:
            out.append(row2[digits[i + 1]] or "?"); i += 2
        else:
            out.append(top[d] if (1 <= d <= 9 and top[d]) else "?"); i += 1
    return "".join(out)

def encode(text, perm25, e1, e2):
    """Para o CONTROLE: texto -> fluxo de digitos 1-9."""
    top, row1, row2 = build_layout(perm25, e1, e2)
    code = {}
    for c in range(1, 10):
        if top[c]: code[top[c]] = [c]
    for d in range(1, 10):
        code[row1[d]] = [e1, d]
        code[row2[d]] = [e2, d]
    out = []
    for ch in text:
        out += code[ch]
    return out

# ---------------- hill-climb ----------------
def climb(digits, scorer, restarts=30, stall_max=1200, seeds=None, deadline=None):
    best_sc = -1e9; best = None
    seeds = seeds or []
    r = 0
    while True:
        r += 1
        if seeds and r <= len(seeds):
            perm = list(seeds[r - 1])
        else:
            perm = list(ALPHA25); random.shuffle(perm)
        e1, e2 = sorted(random.sample(range(1, 10), 2))
        cur = scorer(decode(digits, perm, e1, e2))
        stall = 0
        while stall < stall_max:
            if deadline and time.time() >= deadline:
                if cur > best_sc:
                    best_sc = cur; best = ("".join(perm), e1, e2, decode(digits, perm, e1, e2))
                    yield ("best", best_sc, best)
                return
            move = random.random()
            if move < 0.12:  # troca escapes
                ne1, ne2 = sorted(random.sample(range(1, 10), 2))
                sc = scorer(decode(digits, perm, ne1, ne2))
                if sc >= cur:
                    e1, e2, cur = ne1, ne2, sc; stall = 0
                else:
                    stall += 1
            else:  # troca 2 letras
                a, b = random.sample(range(25), 2)
                perm[a], perm[b] = perm[b], perm[a]
                sc = scorer(decode(digits, perm, e1, e2))
                if sc >= cur:
                    cur = sc; stall = 0
                else:
                    perm[a], perm[b] = perm[b], perm[a]; stall += 1
        if cur > best_sc:
            best_sc = cur; best = ("".join(perm), e1, e2, decode(digits, perm, e1, e2))
            yield ("best", best_sc, best)
        if deadline and time.time() >= deadline:
            return
        if not deadline and r >= restarts:
            return

# ---------------- controle ----------------
def control():
    sc = Scorer()
    import re
    en = re.sub(r"[^A-Z]", "", ("THEQUICKBROWNFOXIUMPSOVERALAZYDOGTHISISATESTOFTHESTRADDLING"
                                "CHECKERBOARDCIPHERHIDDENMESSAGEINSIDETHEPUZZLEPAYLOAD" * 6).upper())
    en = en.replace("J", "I")[:300]
    key = list(ALPHA25); random.seed(11); random.shuffle(key); key = "".join(key)
    e1, e2 = 3, 7
    digits = encode(en, key, e1, e2)
    rec = decode(digits, key, e1, e2)
    assert rec == en, "encode/decode nao casam!"
    print(f"[ok] encode/decode roundtrip ({len(digits)} digitos)")
    best = -9; bestpt = ""
    for kind, s, b in climb(digits, sc, restarts=25, stall_max=1500):
        if s > best:
            best = s; bestpt = b[3]
    match = sum(a == c for a, c in zip(bestpt, en)) / len(en)
    print(f"[controle] best score={best:.3f} match={match:.0%} (ingles ~ -3..-4.5)")
    print(f"           recuperado[:60]={bestpt[:60]}")
    print(f"           original  [:60]={en[:60]}")
    return match

# ---------------- oraculos duros ----------------
def hard_oracles(pt):
    for s in (pt, pt[7:] if len(pt) > 7 else pt):
        for f in {s, s.lower(), hashlib.sha256(s.encode()).hexdigest()}:
            h = O.aes_open(f)
            if h:
                return {"kind": "aes_open", "pw": f[:40], "hits": h}
        for c in (hashlib.sha256(s.encode()).digest(), hashlib.sha256(s.lower().encode()).digest()):
            r = O.check_privkey(c)
            if r:
                return {"kind": "privkey", "hit": r}
    return None

def run(args):
    random.seed()
    sc = Scorer()
    digits = faed_digits()
    print(f"[{time.strftime('%H:%M:%S')}] checkerboard | faed {len(digits)} digitos | "
          f"max_h={args.max_hours} bt={args.breakthrough}")
    deadline = time.time() + args.max_hours * 3600 if args.max_hours else None
    best = -1e9
    for kind, s, b in climb(digits, sc, deadline=deadline, stall_max=2000):
        if s > best:
            best = s
            perm, e1, e2, pt = b
            meta = {"ts": time.strftime('%H:%M:%S'), "score": round(s, 3),
                    "e1": e1, "e2": e2, "square": perm, "head": pt[:40]}
            print(f"[{time.strftime('%H:%M:%S')}] NEW BEST {s:.3f} e=({e1},{e2}) head={pt[:32]}")
            with open(os.path.join(OUT, "cb_candidates.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps({**meta, "plaintext": pt}, ensure_ascii=False) + "\n")
            hit = hard_oracles(pt)
            if hit:
                json.dump({**meta, **hit}, open(os.path.join(OUT, "SOLVED.json"), "w"), indent=2)
                print("\n!!! SOLVE (checkerboard) — out/SOLVED.json"); return
            if s >= args.breakthrough:
                json.dump({**meta, "plaintext": pt, "reason": "readable checkerboard"},
                          open(os.path.join(OUT, "BREAKTHROUGH.json"), "w"), indent=2, ensure_ascii=False)
                print(f"\n*** BREAKTHROUGH checkerboard {s:.3f} ***"); return
    print(f"[fim] best={best:.3f}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", action="store_true")
    ap.add_argument("--max-hours", type=float, default=0)
    ap.add_argument("--breakthrough", type=float, default=-4.8)
    a = ap.parse_args()
    if a.control:
        control()
    else:
        run(a)
