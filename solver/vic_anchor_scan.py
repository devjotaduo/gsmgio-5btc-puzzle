# -*- coding: utf-8 -*-
"""ANCHOR-SCAN: a receita PROVADA (cosmic = XOR dos sha256 das 7 partes cuja
concat = senha do SMALL) fixa o ALVO do decode: o faed/dbbi devem decodificar
para os tokens literais (matrixsumlist/enter/lastwordsbeforearchichoice/
thispassword/yourlastcommand/secondanswer).
Novo oraculo: em vez de score de ingles, buscar os PADROES DE DIGITOS dos
tokens (encodados pelo checkerboard) dentro da string de digitos mapeada.
Espaco: 9! mapeamentos x 2 universos x {canon, VIC-3.2.2} x 36 pares de escape
(dbbi exaustivo) e faed (cru + 3 destransposicoes colunares pela chave de 38).
CONTROLE: o encoder deve reproduzir o decode provado da fase 3.2.2.
"""
from __future__ import annotations
import itertools, os, sys, time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O

CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"
VIC322 = "FUBCDORALETHINGKYMVPSJQZXW"
D322 = "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"
ANCHOR_TEXTS = [
    "MATRIXSUMLIST", "THISPASSWORD", "ARCHICHOICE", "LASTWORDSBEFORE",
    "ENTERLASTWORDS", "YOURLASTCOMMAND", "SECONDANSWER",
    "MATRIXSUMLISTENTERLASTWORDSBEFOREARCHICHOICETHISPASSWORDMATRIXSUMLIST",
]


def code_table(alpha25: str, U, e1, e2):
    """letter -> tuple de digitos (indices no universo U)."""
    tab = {}
    top = [d for d in U if d != e1 and d != e2]
    for i, d in enumerate(top):
        tab[alpha25[i]] = (d,)
    for i, d in enumerate(U):
        tab[alpha25[7 + i]] = (e1, d)
        tab[alpha25[16 + i]] = (e2, d)
    return tab


def encode(text: str, tab) -> tuple:
    out = []
    for c in text:
        out.extend(tab[c])
    return tuple(out)


def decode_digits(digits, alpha25, U, e1, e2):
    top = {d: alpha25[i] for i, d in enumerate([d for d in U if d != e1 and d != e2])}
    r1 = {d: alpha25[7 + i] for i, d in enumerate(U)}
    r2 = {d: alpha25[16 + i] for i, d in enumerate(U)}
    out, i = [], 0
    while i < len(digits):
        d = digits[i]
        if d == e1:
            i += 1
            if i < len(digits):
                out.append(r1[digits[i]])
        elif d == e2:
            i += 1
            if i < len(digits):
                out.append(r2[digits[i]])
        else:
            out.append(top[d])
        i += 1
    return "".join(out)


def main():
    t0 = time.time()
    src = O.sources()
    dbbi_l, faed_l = src["dbbi"].lower(), src["faed"].lower()

    # ================= CONTROLE: fase 3.2.2 =================
    print("=" * 62)
    print("CONTROLE: decode 3.2.2 provado (INCASEYOUMANAGE...)")
    print("=" * 62)
    U = list(range(1, 10))
    digits322 = [int(c) for c in D322]
    dec = decode_digits(digits322, VIC322, U, 1, 4)
    print(f"   decode: {dec[:60]}")
    if dec.startswith("INCASEYOUMANAGE"):
        print("   CONTROLE OK — encoder/decoder consistentes com a fase 3.2.2")
        ctrl_ok = True
    else:
        # tenta escapes e ordem alternativos rapidamente
        found = None
        for e1 in range(1, 10):
            for e2 in range(e1 + 1, 10):
                d = decode_digits(digits322, VIC322, U, e1, e2)
                if d.startswith("INCASEYOUMANAGE"):
                    found = (e1, e2)
                    print(f"   CONTROLE OK com escapes ({e1},{e2})")
                    break
            if found:
                break
        ctrl_ok = found is not None
        if not ctrl_ok:
            print("   CONTROLE FALHOU — layout divergente; prosseguindo mesmo assim")

    # ================= preparo dos padroes =================
    universes = {"0-8": list(range(0, 9)), "1-9": list(range(1, 10))}
    combos = []  # (alpha, Uname, e1, e2, patterns[(bytes, tag)])
    for uname, U in universes.items():
        for aname, alpha in (("canon", CANON), ("vic322", VIC322)):
            for e1 in U:
                for e2 in U:
                    if e1 >= e2:
                        continue
                    tab = code_table(alpha, U, e1, e2)
                    pats = []
                    for t in ANCHOR_TEXTS:
                        try:
                            enc = encode(t, tab)
                        except KeyError:
                            continue
                        pats.append((bytes(enc), t))
                    combos.append((aname, uname, e1, e2, pats))
    print(f"\n[combos] {len(combos)} (alpha, universo, escapes) com {len(ANCHOR_TEXTS)} ancoras")

    # simbolos -> indices
    def sym_idx(s):
        return np.array([ord(c) - 97 for c in s], dtype=np.int8)

    # destransposicoes do faed (colunar 15x38 pela chave de 38)
    KEY38 = "lastwordsbeforearchichoicethispassword"
    order = sorted(range(38), key=lambda i: (KEY38[i], i))

    def untransp_out(s):
        """leitura por colunas na ordem da chave -> grade 15x38 -> linhas"""
        cols = {c: s[i * 15:(i + 1) * 15] for i, c in enumerate(order)}
        rows = []
        for r in range(15):
            rows.append("".join(cols[c][r] for c in range(38)))
        return "".join(rows)

    def untransp_in(s):
        """linhas -> grade -> ler colunas na ordem da chave"""
        rows = [s[r * 38:(r + 1) * 38] for r in range(15)]
        out = []
        for c in order:
            out.extend(rows[r][c] for r in range(15))
        return "".join(out)

    faed_orders = {
        "raw": faed_l,
        "untr_out": untransp_out(faed_l),
        "untr_in": untransp_in(faed_l),
    }
    # sanity: destransposicao valida
    for nm, s in faed_orders.items():
        assert len(s) == 570, f"{nm}: {len(s)}"

    # ================= varredura =================
    perms = np.array(list(itertools.permutations(range(9))), dtype=np.int8)  # 362880x9

    def scan(name: str, symstr: str, combos_scope, verbose=True):
        S = sym_idx(symstr)
        L = len(S)
        hits = []
        checked = 0
        # por universo: mapa perms -> digitos
        for uname, U in universes.items():
            Uarr = np.array(U, dtype=np.int8)
            # chunks de mappings
            CH = 20000
            combo_u = [c for c in combos_scope if c[1] == uname]
            for c0 in range(0, len(perms), CH):
                Pch = perms[c0:c0 + CH]
                D = Uarr[Pch[:, S]]  # (chunk, L)
                for (aname, _u, e1, e2, pats) in combo_u:
                    for pat, tag in pats:
                        lp = len(pat)
                        if lp < 6 or lp > L:
                            continue
                        # prefixo de 3 bytes vetorizado
                        m0 = (D[:, :-2] == pat[0]) & (D[:, 1:-1] == pat[1]) & (D[:, 2:] == pat[2])
                        rows, cols = np.nonzero(m0)
                        for r, c in zip(rows, cols):
                            if tuple(D[r, c:c + lp]) == tuple(pat):
                                hit = {
                                    "src": name, "alpha": aname, "U": uname,
                                    "escapes": (int(e1), int(e2)),
                                    "anchor": tag, "map": tuple(int(x) for x in Pch[r]),
                                    "pos": int(c),
                                }
                                hits.append(hit)
                                print(f"   !!! ANCORA {tag} em {name}/{aname}/U{uname}/esc{e1}{e2} pos={c}")
                        checked += 1
        if verbose:
            print(f"   [{name}] {checked} (combo,chunk) verificados, {len(hits)} hits")
        return hits

    print()
    print("=" * 62)
    print("DBBI: exaustivo (9! x 2 universos x 2 alfabetos x 36 escapes)")
    print("=" * 62)
    hits_dbbi = scan("dbbi", dbbi_l, combos)

    print()
    print("=" * 62)
    print("FAED: cru + 2 destransposicoes (escapes documentados (1,4) + todos)")
    print("=" * 62)
    hits_faed = []
    for oname, ostring in faed_orders.items():
        h = scan(f"faed_{oname}", ostring, combos)
        hits_faed.extend(h)

    # ================= relatorio =================
    print()
    print("=" * 62)
    print(f"TOTAL: {len(hits_dbbi) + len(hits_faed)} ancoras encontradas | tempo {time.time()-t0:.0f}s")
    print("=" * 62)
    allh = hits_dbbi + hits_faed
    for h in allh[:40]:
        # decodifica o contexto do hit
        U = universes[h["U"]]
        e1, e2 = h["escapes"]
        alpha = CANON if h["alpha"] == "canon" else VIC322
        sym = dbbi_l if h["src"] == "dbbi" else faed_orders[h["src"].replace("faed_", "")]
        m = h["map"]
        digits = [m[ord(c) - 97] for c in sym]
        pt = decode_digits(digits, alpha, U, e1, e2)
        print(f"  {h['anchor']} @ {h['src']}/{h['alpha']}/esc{e1}{e2}/pos{h['pos']}")
        print(f"    decode: {pt[:90]}")
    if not allh:
        print("NEGATIVO — nenhum padra de digito dos tokens aparece em nenhuma")
        print("configuracao (dbbi exaustivo; faed cru+destransposto).")


if __name__ == "__main__":
    main()
