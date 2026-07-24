# -*- coding: utf-8 -*-
"""
joint_attack_v2 — RECONSTRUIDO (o original corrompeu, sem git history).
A frente que NENHUM script combinou: over-encryption (matrixsumlist mod-9)
APLICADA ANTES do straddling-checkerboard, com alfabeto DERIVADO do dbbi.

Por que: checkerboard.py buscou quadrados ALEATORIOS -> platô -5.592 em 620k
gens (log). matrixsum_attack.py aplicou keystream só antes do BIFID, nunca antes
do CHECKERBOARD. Este script fecha essa lacuna com seeds canonicos (nao cego).

Pipeline testado por combinacao:
  faed(a-i) -> digitos 1..9
  -> [remover keystream matrixsumlist mod-9] (add/sub, rowsum/colsum/spiral, per-symbol)
  -> decode straddling-checkerboard (alfabeto do dbbi, e1<e2)
  -> plaintext -> Scorer + oraculos DUROS (aes/priv/bip39)

Log: _work/joint_attack_v2_results.jsonl. Determinístico, segundos.
"""
import os, json, time, hashlib, itertools
import oracles as O
from scorer import Scorer
from checkerboard import build_layout, decode, ALPHA25
from prime_attack import hard_oracles, key_from_symbols

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_work", "joint_attack_v2_results.jsonl")

ROWSUM = [6,10,8,7,6,6,5,4,9,9,7,8,7,9]
COLSUM = [8,10,8,10,8,7,3,6,7,5,9,6,6,8]
# ordem-espiral CCW da matriz (validada: decodifica theseedisplanted)
MATRIX = ["00110100101100","11110011101011","11011101001001","01101000011101",
          "01100011000110","10011000100011","10011100010000","11100000001000",
          "00011101111101","11111100110001","11010000011011","11110010101100",
          "01011101000110","01101101101011"]

def spiral_ccw():
    g = [[int(x) for x in r] for r in MATRIX]; n = 14; seq = []
    top,bot,left,right = 0,n-1,0,n-1
    while top<=bot and left<=right:
        for r in range(top,bot+1): seq.append(g[r][left])
        left+=1
        for c in range(left,right+1): seq.append(g[bot][c])
        bot-=1
        if left<=right:
            for r in range(bot,top-1,-1): seq.append(g[r][right])
            right-=1
        if top<=bot:
            for c in range(right,left-1,-1): seq.append(g[top][c])
            top+=1
    return seq
SPIRAL = spiral_ccw()  # 196 bits

def faed_digits():
    return [ord(c)-ord('a')+1 for c in O.sources()["faed"]]  # 1..9

def dbbi_alphabets():
    """Seeds canonicos de alfabeto-checkerboard DERIVADOS do dbbi (nao aleatorio)."""
    dbbi = O.sources()["dbbi"]
    seeds = {}
    # 1) ordem de 1a ocorrencia do dbbi (a-i) mapeada p/ A-I, + filler alfabetico
    seen = []
    for c in dbbi:
        u = chr(ord('A')+ord(c)-ord('a'))
        if u not in seen: seen.append(u)
    filler = [c for c in ALPHA25 if c not in seen]
    seeds["dbbi_firstocc"] = "".join(seen+filler)[:25]
    # 2) sha256(dbbi) hex -> ordem de 1a ocorrencia das letras hex mapeadas + filler
    h = hashlib.sha256(dbbi.encode()).hexdigest().upper()
    seen2 = []
    for c in h:
        # hex digit -> letra (0->A..F->F, dígitos 0-9 -> mapear p/ letras alfabeto)
        if c in "0123456789": u = chr(ord('A')+int(c))
        else: u = c
        if u in ALPHA25 and u not in seen2: seen2.append(u)
    filler2 = [c for c in ALPHA25 if c not in seen2]
    seeds["sha256_dbbi"] = "".join(seen2+filler2)[:25]
    # 3) CANON (o quadrado Bifid) tambem como checkerboard (controle)
    seeds["canon"] = "DBIFHCEGAKLMNOPQRSTUVWXYZ"
    # 4) fase 3.2.2 (ja negativo sem keystream — testar COM keystream)
    seeds["phase322"] = "FUBCDORALETHINGKYMVPSJQZXW"[:25]
    return seeds

def remove_keystream(digits, klist, direction):
    """Undo over-encryption mod-9 (dígitos 1..9). direction: +1=sub, -1=add."""
    out = []
    L = len(klist)
    for i, d in enumerate(digits):
        k = klist[i % L]
        # d,k em 1..9 -> trabalhar em 0..8, aplicar, voltar a 1..9
        v = ((d-1) + direction*(k-1)) % 9 + 1
        out.append(v)
    return out

def score_and_check(pt, scorer, name, results, log):
    sc = scorer(pt) if pt and set(pt) <= set(ALPHA25) else -9.9
    results.append((round(sc,3), name, pt[:46]))
    log.write(json.dumps({"score":round(sc,3),"name":name,"head":pt[:60]}, ensure_ascii=False)+"\n")
    hit = hard_oracles(pt)
    if hit: return {"solve":True,"construction":name,"pt":pt[:80],**hit}
    return None

def main():
    scorer = Scorer()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    log = open(OUT, "w", encoding="utf-8")
    digits = faed_digits()
    alphabets = dbbi_alphabets()
    print(f"[setup] faed {len(digits)} digitos | {len(alphabets)} alfabetos-seed do dbbi")
    for name, a in alphabets.items():
        ok = len(a)==25 and len(set(a))==25
        print(f"  seed {name:16s} valido={ok} {a}")

    keystreams = {
        "rowsum": ROWSUM, "colsum": COLSUM,
        # spiral bits -> valores 1..9 ciclando (bit+idx heurística determinística)
        "spiral9": [(SPIRAL[i%len(SPIRAL)]*4 + (i%9)) % 9 + 1 for i in range(14)],
        "none": None,
    }
    results = []; t0 = time.time(); tried = 0
    for aname, alpha in alphabets.items():
        if len(set(alpha)) != 25:
            continue
        for e1, e2 in itertools.combinations(range(1,10), 2):
            top, row1, row2 = build_layout(alpha, e1, e2)
            for kname, kl in keystreams.items():
                dirs = (0,) if kl is None else (1, -1)
                for d in dirs:
                    dig = digits if kl is None else remove_keystream(digits, kl, d)
                    pt = decode(dig, alpha, e1, e2)
                    tried += 1
                    tag = f"{aname}|e({e1},{e2})|ks_{kname}{'' if kl is None else ('+' if d>0 else '-')}"
                    hit = score_and_check(pt, scorer, tag, results, log)
                    if hit:
                        json.dump(hit, open(os.path.join(os.path.dirname(OUT),"SOLVED_joint.json"),"w"), indent=2)
                        print(f"\n!!! SOLVE via {tag}\n{json.dumps(hit,indent=2)}")
                        log.close(); return
    log.close()
    results.sort(key=lambda r:-r[0])
    print(f"\n=== JOINT ATTACK v2: {tried} construcoes em {time.time()-t0:.1f}s ===")
    print("(baseline checkerboard GPU platô = -5.592 ; ingles ~ -4.5 ; nenhum oraculo abriu)")
    print("TOP 15 por legibilidade:")
    for s,n,h in results[:15]:
        print(f"  {s:7.3f}  {n:32s} {h}")
    print("\n=== VEREDITO ===")
    top = results[0][0]
    if top > -4.5:
        print(f"POSSIVEL SINAL: top {top} >= limiar ingles. Revisar {results[0][1]}")
    else:
        print(f"NEGATIVO: top {top} << ingles (-4.5). over-encryption+checkerboard(dbbi) nao revela texto.")
        print("A ultima rota computacional conhecida esta fechada. Gargalo = interpretativo.")

if __name__ == "__main__":
    main()
