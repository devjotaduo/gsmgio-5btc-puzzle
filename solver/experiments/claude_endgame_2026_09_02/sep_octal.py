# -*- coding: utf-8 -*-
"""Hipótese: 9 = 8+1 — um símbolo é separador e os outros 8 são dígitos octais (3 bits) → bitstream/bytes;
ou os grupos entre separadores são números; ou os GAPS entre ocorrências de um símbolo codificam letras."""
import sys, itertools, collections
sys.path.insert(0, ".")
import gsmg_common as G
srcs = {"dbbi": G.DBBI, "faed": G.FAED, "faed_np": G.FAED[4:]}
n = 0; hits = []; best = []
def judge(tag, b):
    global n
    n += 1
    if not b: return
    pr = G.printable(b)
    best.append((pr, tag, b[:60]))
    if pr >= 0.8 and len(b) >= 8: hits.append(("printable", tag, b[:120].decode("latin-1")))
    if len(b) >= 32:
        h = G.fast_priv_scan(b, tag)
        if h: hits.append(("PRIV", tag, h))
    t = b.decode("latin-1")
    if G.wif_candidates(t) or G.hex64_candidates(t): hits.append(("pattern", tag, t[:120]))
for name, s in srcs.items():
    print(name, "group-length dist per separator:")
    for sep in "abcdefghi":
        groups = s.split(sep)
        lens = collections.Counter(len(g) for g in groups)
        print("  sep", sep, "n_groups", len(groups), "lens", dict(sorted(lens.items())[:8]))
        rest = [c for c in "abcdefghi" if c != sep]
        for order_name, order in (("alpha", rest), ("rev", rest[::-1])):
            code = {c: i for i, c in enumerate(order)}
            # (1) bitstream 3 bits por símbolo (separador removido), 8 bits -> bytes
            bits = "".join(format(code[c], "03b") for c in s if c != sep)
            for off in range(3):
                bb = bits[off:]; bb = bb[:len(bb) // 8 * 8]
                judge(f"{name}|sep{sep}|{order_name}|bits3|off{off}", bytes(int(bb[i:i+8], 2) for i in range(0, len(bb), 8)))
            # (2) grupos como números octais -> byte (mod 256) e -> a1z26/ascii
            vals = []
            for g in groups:
                if not g: continue
                v = 0
                for c in g: v = v * 8 + code[c]
                vals.append(v)
            judge(f"{name}|sep{sep}|{order_name}|grp_oct_mod256", bytes(v % 256 for v in vals))
            judge(f"{name}|sep{sep}|{order_name}|grp_oct_+32", bytes((v % 95) + 32 for v in vals))
            judge(f"{name}|sep{sep}|{order_name}|grp_oct_a1z26", "".join(chr(65 + (v - 1) % 26) for v in vals).encode())
            # (3) grupos: comprimento como número
            L = [len(g) for g in groups]
            judge(f"{name}|sep{sep}|grouplen_a1z26", "".join(chr(65 + (l - 1) % 26) for l in L if l > 0).encode())
            judge(f"{name}|sep{sep}|grouplen_+32", bytes((l % 95) + 32 for l in L))
        # (4) gaps entre ocorrências do símbolo
        pos = [i for i, c in enumerate(s) if c == sep]
        gaps = [b - a for a, b in zip(pos, pos[1:])]
        judge(f"{name}|gaps{sep}|a1z26", "".join(chr(65 + (g - 1) % 26) for g in gaps).encode())
        judge(f"{name}|gaps{sep}|ascii", bytes(g % 256 for g in gaps))
        judge(f"{name}|gaps{sep}|+32", bytes((g % 95) + 32 for g in gaps))
        judge(f"{name}|gaps{sep}|digits->z", G.z_method([g % 10 for g in gaps]) if gaps else b"")
    # (5) contagem: run-length encoding do stream inteiro
    rl = [(c, len(list(g))) for c, g in itertools.groupby(s)]
    judge(f"{name}|runlengths_a1z26", "".join(chr(65 + (l - 1) % 26) for _, l in rl).encode())
best.sort(reverse=True)
print("n", n, "hits", hits[:10])
for pr, tag, b in best[:8]: print(round(pr, 3), tag, b)
G.jsonl("sep_octal.jsonl", {"family": "sep_octal", "n_tests": n, "hits": [str(h) for h in hits], "best": [[p, t] for p, t, _ in best[:20]]})
