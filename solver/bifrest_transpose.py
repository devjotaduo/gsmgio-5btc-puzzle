# -*- coding: utf-8 -*-
"""
Ultimo buraco deterministico: transposicao POS-Bifid do BIF_REST com larguras/
chaves TEMATICAS que o matrixsum_attack.py nao cobriu (so tinha rowsum/colsum).
- BIF = Bifid(faed, CANON, 570) -> BTCSEED + BIF_REST(563)
- Transpoe BIF_REST por grade de largura W (temas: 91,13,38,7,15,19,geometrias de 563)
  lendo colunas em ordem natural E na ordem induzida por rowsum/colsum.
- Julga por Scorer (ingles) + oraculos DUROS (aes/priv/bip39).
Determinístico, sem parametro livre alem das larguras temáticas. Segundos.
"""
import os, json, time, hashlib
import oracles as O
from scorer import Scorer
from prime_attack import bifid_decrypt, hard_oracles, key_from_symbols, CANON, ALPHA25

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_work", "bifrest_transpose.jsonl")
ROWSUM = [6,10,8,7,6,6,5,4,9,9,7,8,7,9]
COLSUM = [8,10,8,10,8,7,3,6,7,5,9,6,6,8]

def grid_read(text, W, order):
    """Le por colunas na ordem 'order' (grade largura W, ragged)."""
    out = []
    for c in order:
        r = 0
        while r*W + c < len(text):
            out.append(text[r*W+c]); r += 1
    return "".join(out)

def main():
    scorer = Scorer()
    faed = O.sources()["faed"]
    BIF = bifid_decrypt(faed.upper(), CANON, 570)
    REST = BIF[7:]                       # 563 chars
    print(f"[setup] BIF={BIF[:12]}... REST len={len(REST)} FULL len={len(BIF)}")
    results = []; t0 = time.time()

    # ordem-espiral da matriz 14x14 (fase 1): sequencia de bits lida em espiral
    # (mesma travessia que produz a URL). Usada como chave de coluna.
    MATRIX = [
        "00110100101100","11110011101011","11011101001001","01101000011101",
        "01100011000110","10011000100011","10011100010000","11100000001000",
        "00011101111101","11111100110001","11010000011011","11110010101100",
        "01011101000110","01101101101011",
    ]
    grid = [[int(x) for x in row] for row in MATRIX]
    # espiral counterclockwise a partir do topo-esquerda (como a fase 1)
    def spiral_ccw(g):
        n = len(g); seq = []
        top, bot, left, right = 0, n-1, 0, n-1
        while top <= bot and left <= right:
            for r in range(top, bot+1): seq.append(g[r][left])   # desce col esq
            left += 1
            for c in range(left, right+1): seq.append(g[bot][c]) # anda base
            bot -= 1
            if left <= right:
                for r in range(bot, top-1, -1): seq.append(g[r][right]) # sobe dir
                right -= 1
            if top <= bot:
                for c in range(right, left-1, -1): seq.append(g[top][c]) # topo
                top += 1
        return seq
    spiral_bits = spiral_ccw(grid)   # 196 bits

    def grid_read_local(text, W, order):
        out = []
        for c in order:
            r = 0
            while r*W + c < len(text):
                out.append(text[r*W+c]); r += 1
        return "".join(out)
    global grid_read
    grid_read = grid_read_local

    widths = sorted(set([91,13,38,7,15,19,9,14,10,101,2,3,5,
                         30,570,285,190,114,95,57,141]))
    # alvos: REST (563) E BIF completo (570) — ref: header pode precisar alinhar na grade
    targets = {"REST": REST, "FULL": BIF}
    for tname, TXT in targets.items():
        for W in widths:
            if W < 2 or W > len(TXT):
                continue
            ncol = W
            orders = {"nat": list(range(ncol))}
            rs = (ROWSUM * (ncol//len(ROWSUM)+1))[:ncol]
            orders["rowsum"] = sorted(range(ncol), key=lambda i:(rs[i], i))
            cs = (COLSUM * (ncol//len(COLSUM)+1))[:ncol]
            orders["colsum"] = sorted(range(ncol), key=lambda i:(cs[i], i))
            # ordem-espiral: usa os primeiros W bits da espiral como chave
            sp = (spiral_bits * (ncol//len(spiral_bits)+1))[:ncol]
            orders["spiral"] = sorted(range(ncol), key=lambda i:(sp[i], i))
            for oname, order in orders.items():
                out = grid_read(TXT, W, order)
                sc = scorer(out) if set(out) <= set(ALPHA25) else -9.9
                name = f"{tname}|W{W}|{oname}"
                results.append((round(sc,3), name, out[:46]))
                for oracle in (lambda o=out: hard_oracles(o), lambda o=out: key_from_symbols(o)):
                    hit = oracle()
                    if hit:
                        json.dump({"solve":True,"construction":name,"text":out[:80],**hit},
                                  open(os.path.join(os.path.dirname(OUT),"SOLVED_bifrest.json"),"w"), indent=2)
                        print(f"\n!!! SOLVE via {name}\n{json.dumps(hit,indent=2)}"); return

    results.sort(key=lambda r:-r[0])
    with open(OUT,"w",encoding="utf-8") as f:
        for s,n,h in results:
            f.write(json.dumps({"score":s,"name":n,"head":h},ensure_ascii=False)+"\n")
    print(f"=== BIFREST TRANSPOSE: {len(results)} construcoes em {time.time()-t0:.1f}s ===")
    print("(baseline CANON puro = -5.577 ; ingles ~ -4.5 ; nenhum oraculo abriu)")
    print("TOP 12 por legibilidade:")
    for s,n,h in results[:12]:
        print(f"  {s:7.3f}  {n:20s} {h}")
    print("\n=== VEREDITO ===")
    top = results[0][0]
    if top > -4.5:
        print(f"POSSIVEL SINAL: top score {top} >= limiar ingles. Revisar {results[0][1]}")
    else:
        print(f"NEGATIVO: top {top} << ingles (-4.5). Transposicao pos-Bifid nao revela texto.")

if __name__ == "__main__":
    main()
