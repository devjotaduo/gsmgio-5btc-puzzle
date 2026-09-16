# Patch: memoria enxuta + ranking por z_Hcond (o controle mostrou que |z| max e' seletor ruim).
import io, os
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bifid3x3_exhaustive.py")
s = io.open(p, encoding="utf-8").read()
n = 0
def rep(a, b):
    global s, n
    assert a in s, a[:70]
    s = s.replace(a, b); n += 1

rep("""    K = int(np.prod(out.shape[:-1])); o = out.reshape(K, -1).astype(np.int64)
    codes = o[:, :-1] * 9 + o[:, 1:] + 81 * np.arange(K)[:, None]
    return np.bincount(codes.ravel(), minlength=81 * K).reshape(*out.shape[:-1], 9, 9).astype(np.float64)""",
"""    K = int(np.prod(out.shape[:-1])); o = out.reshape(K, -1).astype(np.int32)
    codes = o[:, :-1] * 9 + o[:, 1:] + (81 * np.arange(K, dtype=np.int32))[:, None]
    del o
    N = np.bincount(codes.ravel(), minlength=81 * K).reshape(*out.shape[:-1], 9, 9).astype(np.float64)
    del codes
    return N""")

rep("    codes = out.astype(np.int64) + 9 * cls[None, :] + 36 * np.arange(K)[:, None]",
    "    codes = out.astype(np.int32) + (9 * cls[None, :]).astype(np.int32) + (36 * np.arange(K, dtype=np.int32))[:, None]")

rep("""    for kind in ("class", "plain"):
        idx = within_class_perms(cls, nsh) if kind == "class" else np.stack([rng.permutation(n) for _ in range(nsh)])
        sh = out[:, idx]                                                  # (K,nsh,n)
        st = np.stack(stats_from_counts(digraph_counts(sh)), -1)         # (K,nsh,3)
        mu, sd = st.mean(1), st.std(1)
        res.append((obs - mu) / np.maximum(sd, 1e-9))""",
"""    for kind in ("class", "plain"):
        idx = within_class_perms(cls, nsh) if kind == "class" else np.stack([rng.permutation(n) for _ in range(nsh)])
        mu = np.empty((K, 3)); sd = np.empty((K, 3))
        for a in range(0, K, 25):                       # sub-lote: pico ~25*nsh*n bytes
            sh = out[a:a + 25][:, idx]
            st = np.stack(stats_from_counts(digraph_counts(sh)), -1)
            mu[a:a + 25], sd[a:a + 25] = st.mean(1), st.std(1)
            del sh, st
        res.append((obs - mu) / np.maximum(sd, 1e-9))""")

rep("def screen(text, label, periods, top_T=4000, chunk=15120):",
    "def screen(text, label, periods, top_T=4000, chunk=4032):")
rep("            gs = np.empty(len(CLASSES))", "            gs = np.empty(len(CLASSES), np.float32)")
rep("""                out = bifid_all(t, CLASSES[a:a + chunk], ir, ic)
                gs[a:a + chunk] = gstat(out, cls)""",
"""                out = bifid_all(t, CLASSES[a:a + chunk], ir, ic)
                gs[a:a + chunk] = gstat(out, cls); del out""")
rep("""        for a in range(0, len(cis), 500):
            obs, zc, zp = empirical_z(out[a:a + 500], cls)""",
"""        for a in range(0, len(cis), 200):
            obs, zc, zp = empirical_z(out[a:a + 200], cls)""")
rep("""                                "absz": float(np.abs(zc[j]).max()), "absz_plain": float(np.abs(zp[j]).max())})
    triples.sort(key=lambda r: -r["absz"])""",
"""                                "absz": float(np.abs(zc[j]).max()), "absz_plain": float(np.abs(zp[j]).max()),
                                "zH": float(zc[j, 0])})
    triples.sort(key=lambda r: r["zH"])   # mais negativo = mais dependencia serial""")

rep("""    rank_plain = None
    if hit:
        rank_plain = 1 + sum(1 for r in tri if r["absz_plain"] > hit["absz_plain"])""",
"""    rank_zH = rank_absz = None
    if hit:
        rank_zH = 1 + sum(1 for r in tri if r["zH"] < hit["zH"])
        rank_absz = 1 + sum(1 for r in tri if r["absz"] > hit["absz"])""")
rep("""           "rank_absz_class": rank, "rank_absz_plain": rank_plain,""",
"""           "rank_in_funnel_zH": rank_zH, "rank_in_funnel_absz": rank_absz, "pos_sorted": rank,
           "funnel_zH_min": float(min(r["zH"] for r in tri)),""")
rep("""           "top1": {kk: tri[0][kk] for kk in ("period", "mode", "class", "absz", "z_class")},""",
"""           "top1": {kk: tri[0][kk] for kk in ("period", "mode", "class", "absz", "zH", "z_class")},""")

rep('"top10": [{k: r[k] for k in ("period", "mode", "square", "G", "absz", "z_class", "z_plain")} for r in tri[:10]]})',
    '"top10": [{k: r[k] for k in ("period", "mode", "square", "G", "zH", "absz", "z_class", "z_plain")} for r in tri[:10]]})')
rep('    print(label, "top5 por |z_class|:", [(r["period"], r["mode"], r["square"], round(r["absz"], 2)) for r in tri[:5]], flush=True)',
    '    print(label, "top5 por z_Hcond:", [(r["period"], r["mode"], r["square"], round(r["zH"], 2)) for r in tri[:5]], flush=True)')
rep('for r in REAL["faed"][:20]],', 'for r in sorted(REAL["faed"], key=lambda x: x["zH"])[:20]],')
rep('for r in REAL["dbbi"][:20]],', 'for r in sorted(REAL["dbbi"], key=lambda x: x["zH"])[:20]],')
rep('''"faed_absz_dist": {"max": REAL["faed"][0]["absz"], "n_ge_4": sum(r["absz"] >= 4 for r in REAL["faed"]), "n_ge_5": sum(r["absz"] >= 5 for r in REAL["faed"])},
           "dbbi_absz_dist": {"max": REAL["dbbi"][0]["absz"], "n_ge_4": sum(r["absz"] >= 4 for r in REAL["dbbi"]), "n_ge_5": sum(r["absz"] >= 5 for r in REAL["dbbi"])},''',
'''"faed_dist": {"zH_min": min(r["zH"] for r in REAL["faed"]), "absz_max": max(r["absz"] for r in REAL["faed"]),
                         "n_zH_le_m6": sum(r["zH"] <= -6 for r in REAL["faed"]), "n_zH_le_m4": sum(r["zH"] <= -4 for r in REAL["faed"])},
           "dbbi_dist": {"zH_min": min(r["zH"] for r in REAL["dbbi"]), "absz_max": max(r["absz"] for r in REAL["dbbi"]),
                         "n_zH_le_m6": sum(r["zH"] <= -6 for r in REAL["dbbi"]), "n_zH_le_m4": sum(r["zH"] <= -4 for r in REAL["dbbi"])},''')
rep('print(json.dumps({k: summary[k] for k in ("n_bifid_outputs", "n_decodes", "faed_absz_dist", "dbbi_absz_dist", "n_soft", "n_readable", "elapsed_s")}))',
    'print(json.dumps({k: summary[k] for k in ("n_bifid_outputs", "n_decodes", "faed_dist", "dbbi_dist", "n_soft", "n_readable", "elapsed_s")}))')

rep("""    t = sym2arr(txt)
    for rank, r in enumerate(REAL[label][:2000]):""",
"""    t = sym2arr(txt)
    byzH = sorted(REAL[label], key=lambda x: x["zH"]); byabs = sorted(REAL[label], key=lambda x: -x["absz"])
    full_ids = {id(x) for x in byzH[:300]} | {id(x) for x in byabs[:300]}
    seen = {id(x) for x in byzH[:1500]}
    sel = byzH[:1500] + [x for x in byabs[:1500] if id(x) not in seen]
    for rank, r in enumerate(sel):""")
rep("        downstream(out, how, full=rank < 300)", "        downstream(out, how, full=id(r) in full_ids)")

io.open(p, "w", encoding="utf-8").write(s)
print("patched", n, "trechos")
