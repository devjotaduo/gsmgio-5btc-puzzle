# -*- coding: utf-8 -*-
"""Familia yinyang_interleave (passe 2 = passe 1 re-verificado + extensoes).

HIPOTESE: "Cosmic Duality / half and better half / yinyang" significa que dois CANAIS de
digitos a-i (A = faed[:285] e B = faed[285:], e tambem impar/par, faed/reverso, dbbi/faed[-91:],
faed[:91]/dbbi) se COMBINAM por INTERCALACAO/CONCATENACAO de digitos (nao por aritmetica modular,
ja fechada): A0B0A1B1, par 10A+B / 16A+B / bits intercalados, soma/produto/|dif| concatenados,
base-19 e base-81 posicionais, ou (linha,coluna) de um quadrado 9x9 keyed por frases do puzzle.
A string resultante deve decodificar (z-method, base9, checkerboard, Bifid, a1z26, ASCII) para
texto semantico, ou hashear (sha256) para a senha de SMALL/COSMIC/TAIL32, ou conter a privkey.

Passe 1 (re-executado aqui) = estatistica conjunta 9x9 + 197 strings x ~340 decodes.
Passe 2 (novo) = (a) estatistica do SIMBOLO-PAR (81 valores): uniformidade e IoC contra nulo
multinomial, com CONTROLE POSITIVO (texto ingles codificado por quadrado 9x9 keyed);
(b) construcoes de intercalacao que faltavam: nibble (x<<4|y), bits intercalados, ordem YX nos
pares ASCII/mod26, empacotamento mod-16 em nibbles, quadrados 9x9 keyed por mais 4 frases.
"""
import sys, os, random, itertools, json, time, math
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
import yinyang_interleave_pass1 as P          # motor do passe 1 (controles ja provados)

LOG = os.path.join(SP, "yinyang_interleave.jsonl")
P.LOG = LOG                                    # redireciona o log do motor
HYP = __doc__.split("HIPOTESE: ")[1].split("\n\nPasse 1")[0].replace("\n", " ")
B81 = P.B81
EXTRA_PHRASES = ["halfandbetterhalf", "lifeanddeath", "lemiroirdelavieetdelamort",
                 "theflowerblossomsthroughwhatseemstobeaconcretesurface"]


# ---------------------------------------------------------------- (a) estatistica do simbolo-par
def pair_stats(name, X, Y, k=200, seed=7):
    """X,Y em 1..9 -> simbolo s=(x-1)*9+(y-1) em 0..80. Testa se o fluxo de 81 simbolos parece
    TEXTO substituido (distribuicao peluda, IoC alto) ou ruido uniforme."""
    S = [(x - 1) * 9 + (y - 1) for x, y in zip(X, Y)]
    n = len(S)
    def chi2_unif(seq):
        f = [0] * 81
        for v in seq: f[v] += 1
        e = n / 81.0
        return sum((c - e) ** 2 / e for c in f)
    def ioc(seq):
        f = [0] * 81
        for v in seq: f[v] += 1
        return sum(c * (c - 1) for c in f) / (n * (n - 1))
    rnd = random.Random(seed)
    nc, ni = [], []
    for _ in range(k):
        r = [rnd.randrange(81) for _ in range(n)]
        nc.append(chi2_unif(r)); ni.append(ioc(r))
    def z(obs, null):
        mu = sum(null) / len(null)
        sd = (sum((v - mu) ** 2 for v in null) / (len(null) - 1)) ** 0.5
        return round((obs - mu) / sd, 2), round(mu, 4), round(sd, 4)
    zc, muc, sdc = z(chi2_unif(S), nc); zi, mui, sdi = z(ioc(S), ni)
    r = {"pairstat": name, "n": n, "chi2_unif": round(chi2_unif(S), 1), "chi2_null_mean": muc,
         "z_chi2": zc, "ioc81": round(ioc(S), 5), "ioc_null_mean": mui, "z_ioc": zi}
    G.jsonl(LOG, r); print(r, flush=True)
    return r


def pairstat_control():
    """Controle positivo: ingles real codificado em (linha,coluna) de um quadrado 9x9 keyed
    TEM de acender os dois detectores (z_chi2 e z_ioc bem positivos)."""
    sq = G.keyed_alphabet("cosmicduality", base=B81, merge_j=False)
    msg = ("the private keys belong to half and better half and they also need funds to live "
           "and prosper in the matrix forever and ever the seed is planted good luck bunny") * 3
    msg = [c for c in msg if c in sq][:285]
    X = [sq.index(c) // 9 + 1 for c in msg]; Y = [sq.index(c) % 9 + 1 for c in msg]
    r = pair_stats("CONTROL_english_via_sq9", X, Y)
    ok = r["z_chi2"] > 8 and r["z_ioc"] > 8
    G.jsonl(LOG, {"control_pairstat": ok, "detail": r}); print("CONTROLE pairstat:", ok)
    assert ok, r
    return r


# ---------------------------------------------------------------- (b) construcoes novas
def bit_interleave(x, y):
    """bits de x (4b) intercalados com bits de y -> 1 byte (yin/yang no nivel do bit)."""
    v = 0
    for i in range(4):
        v |= ((x >> i) & 1) << (2 * i)
        v |= ((y >> i) & 1) << (2 * i + 1)
    return v


def build_new():
    """Somente o que o passe 1 NAO gerou. base=1 (a=1..i=9)."""
    Bt, T = {}, {}
    for pn, (X, Y) in P.pair_sources(1).items():
        p = "n_" + pn
        pairsYX = [10 * y + x for x, y in zip(X, Y)]
        Bt[p + "_pair_ascii_YX"] = bytes(pairsYX)
        T[p + "_pair_mod26_YX"] = "".join(P.AZ[v % 26] for v in pairsYX)
        Bt[p + "_nib_XY"] = bytes(((x - 1) << 4) | (y - 1) for x, y in zip(X, Y))
        Bt[p + "_nib_YX"] = bytes(((y - 1) << 4) | (x - 1) for x, y in zip(X, Y))
        Bt[p + "_bitint_XY"] = bytes(bit_interleave(x - 1, y - 1) for x, y in zip(X, Y))
        Bt[p + "_bitint_YX"] = bytes(bit_interleave(y - 1, x - 1) for x, y in zip(X, Y))
        s81 = [(x - 1) * 9 + (y - 1) for x, y in zip(X, Y)]
        Bt[p + "_s81_raw"] = bytes(s81)
        Bt[p + "_s81_plus32"] = bytes(v + 32 for v in s81)
        nib = [v % 16 for v in s81]
        Bt[p + "_s81mod16_pack"] = bytes((nib[i] << 4) | nib[i + 1] for i in range(0, len(nib) - 1, 2))
        T[p + "_s81mod16_hex"] = "".join("0123456789abcdef"[v] for v in nib)
        for ph in EXTRA_PHRASES:
            sq = G.keyed_alphabet(ph, base=B81, merge_j=False)
            T[p + f"_sq9_{ph[:12]}_rowXcolY"] = "".join(sq[(x - 1) * 9 + (y - 1)] for x, y in zip(X, Y))
            T[p + f"_sq9_{ph[:12]}_rowYcolX"] = "".join(sq[(y - 1) * 9 + (x - 1)] for x, y in zip(X, Y))
    return Bt, T


# ---------------------------------------------------------------- adendo (roda com: py yinyang_interleave.py addendum)
def addendum():
    """(1) nulo que PRESERVA as marginais para o chi2 dos 81 simbolos-par: separa 'distribuicao
    peluda porque o unigrama do faed e enviesado' de 'peluda por estrutura de par'.
    (2) empacotamento de nibbles com deslocamento impar (as janelas de 32 B que o pack alinhado
    a byte nao cobre) -> fast_priv_scan."""
    out = []
    for pn, (X, Y) in P.pair_sources(1).items():
        S = [(x - 1) * 9 + (y - 1) for x, y in zip(X, Y)]
        n = len(S)
        def chi2(seq):
            f = [0] * 81
            for v in seq: f[v] += 1
            e = n / 81.0
            return sum((c - e) ** 2 / e for c in f)
        obs = chi2(S); rnd = random.Random(1327); Y2 = list(Y); null = []
        for _ in range(200):
            rnd.shuffle(Y2); null.append(chi2([(x - 1) * 9 + (y - 1) for x, y in zip(X, Y2)]))
        mu = sum(null) / len(null); sd = (sum((v - mu) ** 2 for v in null) / (len(null) - 1)) ** 0.5
        r = {"pairstat_marginal_null": pn, "n": n, "chi2": round(obs, 1), "null_mean": round(mu, 1),
             "null_sd": round(sd, 1), "z": round((obs - mu) / sd, 2)}
        G.jsonl(LOG, r); print(r, flush=True); out.append(r)
        nib = [v % 16 for v in S]
        for off in (1,):
            b = bytes((nib[i] << 4) | nib[i + 1] for i in range(off, len(nib) - 1, 2))
            P.STATS["n"] += 1
            for h in G.fast_priv_scan(b, f"nibshift{off}"):
                P.RES["hard"].append({"kind": "privkey_raw", "src": pn, "how": f"nibshift{off}", "hit": str(h)})
    G.jsonl(LOG, {"addendum": {"marginal_nulls": out, "hard": P.RES["hard"], "n_tests": P.STATS["n"]}})
    print("ADENDO hard:", P.RES["hard"], "n_tests_extra:", P.STATS["n"])


# ---------------------------------------------------------------- main
if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "addendum":
    addendum(); sys.exit()

if __name__ == "__main__":
    t0 = time.time(); open(LOG, "w").close()
    G.jsonl(LOG, {"family": "yinyang_interleave", "pass": 2, "hypothesis": HYP})

    f0 = [ord(c) - 97 for c in G.FAED]; d0 = [ord(c) - 97 for c in G.DBBI]
    joints = [P.joint_test("A[i],B[i] halves", f0[:285], f0[285:]),
              P.joint_test("faed[2i],faed[2i+1]", f0[0::2], f0[1::2]),
              P.joint_test("dbbi[i],faed[i]", d0, f0[:91]),
              P.joint_test("dbbi[i],faed[-91+i]", d0, f0[-91:]),
              P.joint_test("faed[i],faed[569-i]", f0[:285], f0[::-1][:285])]

    ctl_pair = pairstat_control()
    pairstats = [pair_stats(f"{pn}_XY", X, Y) for pn, (X, Y) in P.pair_sources(1).items()]
    pairstats += [pair_stats(f"{pn}_YX", Y, X) for pn, (X, Y) in P.pair_sources(1).items()]

    n_ctrl = P.control(); null = P.null_model()
    n_null = P.STATS["n"]

    bests = []; seen = set()
    for base in (0, 1):                                  # bateria do passe 1 (re-verificacao)
        D, Bt, T = P.build(base)
        for name, digs in D.items():
            key = tuple(digs)
            if key in seen: continue
            seen.add(key); b = P.run_digits(name, digs); bests.append(b)
            G.jsonl(LOG, {"string": name, "len": len(digs), "best": b})
        for name, val in list(Bt.items()) + list(T.items()):
            key = val if isinstance(val, bytes) else val.encode()
            if key in seen: continue
            seen.add(key); bests.append(P.check(val, "direct", name, deep=True))
    n_pass1 = P.STATS["n"]
    print(f"passe1 refeito: {n_pass1} testes, {len(seen)} strings, {time.time()-t0:.0f}s", flush=True)

    nBt, nT = build_new()                                 # bateria NOVA
    n_new_strings = 0
    for name, val in list(nBt.items()) + list(nT.items()):
        key = val if isinstance(val, bytes) else val.encode()
        if key in seen: continue
        seen.add(key); n_new_strings += 1
        b = P.check(val, "direct", name, deep=True); bests.append(b)
        G.jsonl(LOG, {"string": name, "len": len(val), "best": b, "pass": 2})
        if isinstance(val, bytes):                        # e tambem como fluxo de digitos decimais
            digs = [int(c) for c in "".join(str(v) for v in val)]
            b2 = P.run_digits(name + "_asdigits", digs); bests.append(b2)
            G.jsonl(LOG, {"string": name + "_asdigits", "len": len(digs), "best": b2, "pass": 2})

    bests.sort(key=lambda x: -x["score"])
    summary = {"n_tests": P.STATS["n"], "n_pass1": n_pass1, "n_new_strings": n_new_strings,
               "n_control": n_ctrl, "n_null": n_null, "n_strings": len(seen),
               "joints": joints, "pairstat_control": ctl_pair, "pairstats": pairstats, "null": null,
               "hard": P.RES["hard"], "n_soft": len(P.RES["soft"]), "soft": P.RES["soft"][:5],
               "n_readable": len(P.RES["readable"]),
               "readable": sorted(P.RES["readable"], key=lambda x: -x.get("score", -99))[:10],
               "top5": bests[:5], "secs": round(time.time() - t0)}
    G.jsonl(LOG, {"summary": summary})
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:9000])
