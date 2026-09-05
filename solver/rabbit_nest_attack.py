# -*- coding: utf-8 -*-
"""O "ninho do coelho": a segunda porta na primeira peça do puzzle.

Hipótese falsificável
--------------------
A matriz 14x14 tem 196 células mas a URL consome só 192 bits; sobram as 4 últimas da espiral
(192-195). O criador: *"It might have shown you only one door, beware that the rabbits nest may
contain a whole lot more."* Medindo a imagem original em sub-pixels de 15 px (5x5 por célula),
EXATAMENTE 7 células não são uniformes — as 4 do ninho (espiral 192,193,194,195) mais 3 vizinhas
(172,184,187) — e nelas está desenhado um coelho. As outras 189 células são uniformes (controle).
Cada célula do coelho tem uma contagem de tinta que cai em 1..9, o alfabeto do endgame (a=1..i=9).

Espaço finito: as contagens em 6 ordens como dígitos/letras/z-method; o bitmap de 300 bits do
coelho em leituras linha/coluna/espiral, direto e invertido, como bytes/senha/privkey.
"""
import sys, json, hashlib, itertools, random
import numpy as np
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from PIL import Image

a = np.array(Image.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\archive\Puzzle_full.png").convert("RGB")).astype(int)
SUB = 15
sub = np.zeros((70, 70), dtype=int)
for sr in range(70):
    for sc in range(70):
        blk = a[sr*SUB:(sr+1)*SUB, sc*SUB:(sc+1)*SUB]
        sub[sr, sc] = 1 if blk.reshape(-1,3).mean(0).sum() < 200 else 0
RAB = [(6,6),(6,7),(7,6),(7,7),(7,8),(7,9),(8,6)]
bad = sum(1 for r in range(14) for c in range(14)
          if (r,c) not in RAB and sub[r*5:(r+1)*5, c*5:(c+1)*5].min() != sub[r*5:(r+1)*5, c*5:(c+1)*5].max())
assert bad == 0, f"controle falhou: {bad} células não-coelho mistas"
print("CONTROLE OK: só as 7 células do coelho são não-uniformes")
cnt = {rc: int(sub[rc[0]*5:(rc[0]+1)*5, rc[1]*5:(rc[1]+1)*5].sum()) for rc in RAB}
sp = {G.SPIRAL.index(rc): rc for rc in RAB}
print("contagens:", {i: cnt[sp[i]] for i in sorted(sp)})

# ---------- nulo: quão surpreendente é 7 contagens todas em 1..9?
random.seed(3); N = 100000; hit = 0
dens = sum(cnt.values()) / (7*25)
for _ in range(N):
    if all(1 <= sum(1 for _ in range(25) if random.random() < dens) <= 9 for _ in range(7)): hit += 1
print(f"nulo: P(7 células de 5x5 com densidade {dens:.3f} caírem todas em 1..9) = {hit/N:.4f}")

# ---------- materiais
orders = {
 "spiral":       [cnt[sp[i]] for i in sorted(sp)],
 "spiral_rev":   [cnt[sp[i]] for i in sorted(sp, reverse=True)],
 "rowmajor":     [cnt[rc] for rc in sorted(RAB)],
 "rowmajor_rev": [cnt[rc] for rc in sorted(RAB, reverse=True)],
 "nest":         [cnt[sp[i]] for i in (192,193,194,195)],
 "nest_rev":     [cnt[sp[i]] for i in (195,194,193,192)],
 "nest_rowmaj":  [cnt[rc] for rc in sorted([(6,6),(6,7),(7,6),(7,7)])],
}
mats = set()
for name, v in orders.items():
    d = "".join(map(str, v)); L = "".join(chr(96+x) for x in v)
    mats |= {d.encode(), L.encode(), L.upper().encode()}
    try: mats.add(G.z_method(v))
    except Exception: pass
# bitmap do coelho: 300 bits em várias leituras
canvas = np.zeros((15,20), dtype=int)
for (r,c) in RAB: canvas[(r-6)*5:(r-6)*5+5, (c-6)*5:(c-6)*5+5] = sub[r*5:(r+1)*5, c*5:(c+1)*5]
reads = {"row": canvas.flatten(), "col": canvas.T.flatten(),
         "rowrev": canvas.flatten()[::-1], "colrev": canvas.T.flatten()[::-1]}
for rn, bits in list(reads.items()):
    reads[rn+"_inv"] = 1 - bits
for rn, bits in reads.items():
    b = bits.tolist()
    for msb in (True, False):
        by = bytearray()
        for i in range(0, len(b)-7, 8):
            ch = b[i:i+8]
            by.append(int("".join(map(str, ch if msb else ch[::-1])), 2))
        mats.add(bytes(by))
# só os 100 bits do ninho
nb = np.concatenate([sub[r*5:(r+1)*5, c*5:(c+1)*5].flatten() for (r,c) in [sp[i] for i in (192,193,194,195)]])
for v in (nb, nb[::-1], 1-nb):
    s = "".join(map(str, v.tolist()))
    mats.add(s.encode()); mats.add(int(s,2).to_bytes((len(s)+7)//8, "big"))
mats = {m for m in mats if m and len(m) <= 512}
forms = set()
for m in mats:
    forms |= {m, G.shahex(m).encode(), G.shahex(m).upper().encode(), G.sha(m)}
print(f"materiais {len(mats)} -> formas {len(forms)}")

BL = {k: G.BLOBS[k] for k in ("SMALL","COSMIC","TAIL32")}
n=0; pads=[]; hard=[]
for f in forms:
    for bn in BL:
        for kdf,p in G.aes_try(f, bn):
            n+=1; pads.append((bn,kdf,round(G.printable(p),3)))
            if G.semantic(p) or G.printable(p)>0.85: hard.append((bn,kdf,f[:60],p[:150]))
            hard += G.fast_priv_scan(p, bn)
    if len(f)==32: hard += [("priv-direct",f.hex())] if G.priv_hit(f) else []
    hard += [("priv-sha", f[:40])] if G.priv_hit(G.sha(f)) else []
print(f"ORÁCULOS: {len(forms)*3*2} tentativas AES, paddings válidos {len(pads)} (esperado {len(forms)*3*2/256:.1f}), HARD={hard}")
json.dump({"family":"rabbit_nest","counts":{str(i):cnt[sp[i]] for i in sorted(sp)},
           "orders":{k:"".join(map(str,v)) for k,v in orders.items()},
           "null_p_all_1to9": hit/N, "n_materials":len(mats), "n_forms":len(forms),
           "pads":len(pads), "hard":[str(h)[:200] for h in hard]},
          open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\rabbit_nest.json","w"), indent=1)
