# Hipotese: "zeroed out" = os 1s da matriz viram digito 0 e os 91 zeros dos 192 bits da URL recebem os 91 digitos do dbbi (a=1..9);
# o numero decimal de 192 digitos passa pelo z-method da pagina (dec -> hex -> ascii). Variantes de ordem/base/polaridade/matriz.
import sys, itertools
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
D = G.DBBI
orders = {"spiral": G.SPIRAL, "row": [(r, c) for r in range(14) for c in range(14)],
          "col": [(r, c) for c in range(14) for r in range(14)], "spiral_rev": G.SPIRAL[::-1]}
res = []; n = 0
for mname, M in (("img", G.MATRIX_IMG), ("readme", G.MATRIX_README)):
    for oname, order in orders.items():
        bits = [M[r][c] for r, c in order]
        for L in (192, 196):
            b = bits[:L]
            for fill_on in (0, 1):                 # dbbi entra nas celulas com bit == fill_on
                slots = [i for i, x in enumerate(b) if x == fill_on]
                if len(slots) < 91: continue
                for base1 in (True, False):
                    dd = G.digits(D, base1)
                    for dfill in ("0", "1", "", "9"):       # o que vai nas outras celulas
                        for align in ("head", "tail"):
                            use = slots[:91] if align == "head" else slots[-91:]
                            out = []
                            k = 0
                            for i in range(L):
                                if i in use: out.append(str(dd[k])); k += 1
                                elif i in slots: out.append(dfill)   # sobra de slots
                                else: out.append(dfill)
                            s = "".join(out)
                            if not s: continue
                            for rev in (False, True):
                                t = s[::-1] if rev else s
                                if not t or t.strip("0") == "": continue
                                n += 1
                                try: by = G.z_method([int(c) for c in t])
                                except Exception: continue
                                pr = G.printable(by)
                                hard, soft = G.try_password_all(by.hex()); hard2, _ = G.try_password_all(t)
                                res.append((pr, mname, oname, L, fill_on, base1, dfill, align, rev, by[:30]))
                                if pr > 0.8 or hard or hard2: print("!!!", pr, mname, oname, L, fill_on, base1, dfill, align, rev, by[:60], hard, hard2)
res.sort(reverse=True)
print("n", n, "best printable:", [(round(r[0], 2), r[1:9]) for r in res[:5]])
