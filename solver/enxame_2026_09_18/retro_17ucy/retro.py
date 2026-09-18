# -*- coding: utf-8 -*-
"""Frente retro_17ucy (campanha enxame_2026-09-18): braço de chave, sem AES.

HIPÓTESE (finita, falsificável). Algum escalar direto já gerado por uma família que rodou antes
do commit 0ce4185 (2026-09-17 23:21), quando G.priv_hit / O.check_privkey / os TGT próprios dos
scripts só comparavam com 1GSMG, é a privkey de 17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa (ou de 1GSMG,
regressão). Refutação: regenerar exatamente esses escalares, deduplicar por bytes e comparar o
h160 das pubkeys comprimida e não comprimida com os dois alvos dá zero correspondências.

Fontes (ver FONTES): F6 inteira (gerar, T3_low, T3_verbatim até o índice 654.889 e o resto,
separadores, extras), brainwallet.py / brainwallet_inline.py / brainwallet2.py, as 466.310 bases
do corpus histórico, as 6 famílias .cjs com oracles.json, os materiais de prime_host_delta/run1,
prime_host_l84/run1 e rabbit_delta, os inteiros de faed_keys/keys.json, e os braços de chave de
select256.py e cores163.py regenerados pelos próprios scripts.

Controles: positivo público (sha256('correct horse battery staple') -> 1JwSSubhmg…); em cada fonte,
dois escalares do próprio fluxo têm o h160 (um não comprimido, um comprimido) injetado no conjunto de
alvos só durante a varredura e têm de ser recuperados; amostra de 200 escalares por fonte conferida
com python-ecdsa (implementação independente); reconciliação com as contagens e os
scalarStreamSHA256 guardados. Nulo: N/A (cobertura determinística finita).

Uso: python retro.py            -> campanha completa (Pool de 4, uma fonte por processo)
     python retro.py NOME ...   -> só as fontes pedidas, sem escrever saídas (teste)
"""
import sys, os, io, re, json, time, hashlib, random, builtins, itertools, subprocess, importlib.util
from collections import Counter
from multiprocessing import Pool

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(AQUI))
import comum as C          # importa o kit da worktree pelo caminho relativo
import numpy as np
from coincurve import PublicKey

G = C.G
O = G.O
SOLVER = G.SOLVER
PRINCIPAL = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
SAIDA = os.path.abspath(os.path.join(SOLVER, "..", "_work", "enxame_2026-09-18", "retro_17ucy"))
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
NB = N.to_bytes(32, "big")
ZERO = bytes(32)
REAIS = {bytes.fromhex(h): a for h, a in zip(O.TARGET_H160S, O.PRIZE_ADDRS)}
assert len(REAIS) == 2 and O.PRIZE_ADDRS[1].startswith("17ucy")
WORKERS = 4


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def s256(b):
    return hashlib.sha256(b).digest()


def tres(b):
    """sha256, sha256² (sobre o digest cru) e sha256(sha256hex) — o gesto brainwallet."""
    d = s256(b)
    return d, s256(d), s256(d.hex().encode())


def int32(v):
    return v.to_bytes(32, "big") if 0 <= v < 2 ** 256 else None


def carregar(caminho, nome):
    spec = importlib.util.spec_from_file_location(nome, caminho)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha_arquivo(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


class Coletor:
    """Acumula escalares de 32 B num bytearray (sem objeto por escalar) com contagem por subfonte."""

    def __init__(self):
        self.buf = bytearray()
        self.por_sub = Counter()
        self.fora = Counter()      # itens que não viram 32 B (inteiro >= 2^256, tamanho errado)

    def add(self, sub, k):
        if k is None or len(k) != 32:
            self.fora[sub] += 1
            return
        self.buf += k
        self.por_sub[sub] += 1

    def tres(self, sub, b):
        for tag, k in zip(("sha256", "sha256d", "sha256_hex"), tres(b)):
            self.add(f"{sub}/{tag}", k)


# =============================================================== (1) família 6
def _f6():
    sys.path.insert(0, os.path.join(SOLVER, "operador_ensinado_2026_09_17"))
    import familia6_referencia_pessoal as F      # efeito de import: controle da fase 2 (só leitura)
    import critico_familia6 as K
    return F, K


def f6_gerar(c):
    F, _K = _f6()
    cands = F.gerar()
    nao_f3 = 0
    for s, fam in cands.items():
        b = s.encode("utf-8")
        c.tres("gerar", b)
        if not fam.startswith("F3_"):             # extras do crítico: sha256² e sha256(raw+LF)
            nao_f3 += 1
            c.add("gerar/sha256_lf", s256(b + b"\n"))
    hist = len(cands) + 2 * nao_f3 + len(cands)
    assert (len(cands), nao_f3, hist) == (198345, 29121, 454932), (len(cands), nao_f3, hist)
    return {"candidatos": len(cands), "nao_F3": nao_f3, "brainwallets_historicos_reconciliados": hist,
            "fontes": {"familia6": sha_arquivo(F.__file__), "critico_familia6": sha_arquivo(_K.__file__)}}


def f6_t3_low(c):
    _F, K = _f6()
    n = 0
    for s, _fam in K._gen_triplas("low"):
        c.tres("T3_low", s.encode("utf-8"))
        n += 1
    assert n == 777816, n
    return {"triplas": n}


def f6_t3_vb(c, parte):
    _F, K = _f6()
    n = 0
    for i, (s, _fam) in enumerate(K._gen_triplas("vb")):
        if (i <= 654889) == (parte == "ate_654889"):
            c.tres("T3_vb_" + parte, s.encode("utf-8"))
            n += 1
    assert n == (654890 if parte == "ate_654889" else 970026 - 654890), n
    return {"triplas": n, "indice_corte": 654889}


def f6_separadores(c):
    _F, K = _f6()
    _F, base_low, base_vb, _pl, _pv = K._inventario()
    n = 0
    # cópia do gerador de critico_familia6.etapa_separadores (aninhado lá, não importável)
    for a, b in itertools.permutations(base_low, 2):
        for sp in (" ", "-", "and", "_", "."):
            c.tres("separadores_low", (a + sp + b).encode("utf-8")); n += 1
    for a, b in itertools.permutations(base_vb, 2):
        for sp in (" ", "-", " and "):
            c.tres("separadores_vb", (a + sp + b).encode("utf-8")); n += 1
    assert n == 77118, n
    return {"candidatos_gerados": n}


# =============================================================== (2A) brainwallets de 2026-09-02
BW_DIR = os.path.join(PRINCIPAL, r"solver\experiments\claude_endgame_2026_09_02")   # creator_all.txt só lá
README_0902 = "2d2ec8f"   # último commit do README antes das execuções de 2026-09-02 13:26-13:41


def open_readme_antigo():
    """open() que serve o README.md do commit README_0902 (os dois scripts leem o README vivo)."""
    txt = subprocess.run(["git", "-C", SOLVER, "show", README_0902 + ":README.md"], capture_output=True,
                         encoding="utf-8").stdout
    assert len(txt) > 10000

    def aberto(path, mode="r", *a, **k):
        if os.path.basename(str(path)) == "README.md" and "r" in mode and "b" not in mode:
            return io.StringIO(txt)
        return builtins.open(path, mode, *a, **k)
    return aberto, hashlib.sha256(txt.encode("utf-8")).hexdigest()


def bw_frases(c):
    B = carregar(os.path.join(BW_DIR, "brainwallet.py"), "brainwallet_hist")
    B.open, readme = open_readme_antigo()
    corpus = B.build_corpus()
    assert len(corpus) == 3246, len(corpus)
    n_keys = 0
    for p in corpus:
        for f in B.forms(p):
            for kname, k in B.keys_of(f.encode("utf-8", "replace")):
                c.add("brainwallet/" + kname, k); n_keys += 1
    assert n_keys == 96450, n_keys
    # brainwallet2.py (bytes crus como chave): cópia do gerador de main(), sem o oráculo antigo
    n2 = 0
    for p in corpus:
        for f in B.forms(p):
            bs = f.encode("utf-8", "replace")
            ks = [bs[:32], bs[-32:]] if len(bs) >= 32 else [bs.rjust(32, b"\x00"), bs.ljust(32, b"\x00"),
                                                            bs.rjust(32, b" "), bs.ljust(32, b" ")]
            if re.fullmatch(r"[0-9a-fA-F]{64}", f.strip()):
                ks.append(bytes.fromhex(f.strip()))
            if len(bs) >= 32:
                ks.append(hashlib.sha256(bs).digest()[::-1])
            for k in ks:
                c.add("brainwallet2/rawbytes", k); n2 += 1
    assert n2 == 57965, n2
    return {"frases": len(corpus), "chaves_brainwallet_py": n_keys, "chaves_brainwallet2_py": n2,
            "fonte": sha_arquivo(os.path.join(BW_DIR, "brainwallet.py")), "readme": [README_0902, readme]}


def bw_inline(c):
    p = os.path.join(BW_DIR, "brainwallet_inline.py")
    src = open(p, encoding="utf-8").read()
    corte = src.index("n = 0; hard = []")          # só o gerador de frases; o resto roda AES e grava log
    ns = {"__name__": "bw_inline_hist", "__file__": p}
    ns["open"], readme = open_readme_antigo()
    exec(compile(src[:corte], p, "exec"), ns)
    cands = ns["cands"]
    assert len(cands) == 6434, len(cands)
    for cand in sorted(cands):
        b = cand.encode("utf-8", "ignore")
        for tag, k in zip(("sha256", "sha256d", "sha256_hex"), tres(b)):
            c.add("inline/" + tag, k)
            v = int.from_bytes(k, "big")
            if 0 < v < N:
                c.add("inline/" + tag + "|N-k", int32(N - v))   # espelho que o script também testava
    return {"candidatos": len(cands), "fonte": sha_arquivo(p), "readme": [README_0902, readme]}


# =============================================================== (2A) corpus histórico (466.310)
def corpus_hist(c):
    """Executa o coletor ct_montage_corpus_collect.py (o mesmo que deu 466.310 em 17/09) com toda
    escrita em disco neutralizada; roda num processo próprio (maxtasksperchild=1)."""
    col = os.path.join(SOLVER, "ct_montage_corpus_collect.py")
    real_open = builtins.open

    def guarda(path, mode="r", *a, **k):
        if any(x in mode for x in "wax+"):
            return io.BytesIO() if "b" in mode else io.StringIO()
        return real_open(path, mode, *a, **k)
    salvo = (G.SOLVER, O.aes_open, O.check_privkey)
    ns = {"__name__": "coletor_hist", "__file__": col}
    builtins.open = guarda
    G.SOLVER = os.path.join(PRINCIPAL, "solver")    # onde a coleta de 17/09 rodou (dados locais)
    try:
        exec(compile(real_open(col, encoding="utf-8").read(), col, "exec"), ns)
    finally:
        builtins.open = real_open
        G.SOLVER, O.aes_open, O.check_privkey = salvo
    pws = list(ns["CANDS"].keys())
    assert len(pws) == 466310, len(pws)
    fluxo = hashlib.sha256(b"\n".join(sorted(pws))).hexdigest()
    for pw in pws:
        c.tres("corpus", pw)
    return {"bases": len(pws), "por_fonte": ns["SRC_COUNT"], "sha256_bases_ordenadas": fluxo,
            "historico_privkeys": 2 * len(pws), "fonte": sha_arquivo(col)}


# =============================================================== (2B) famílias .cjs com oracles.json
CJS = {
    "zero_cells": "zero_cells_prime_sums_2026-09-16",
    "color_factor": "color_factor_sums_2026-09-16",
    "count_prime": "count_prime_matrix_2026-09-16",
    "wavelength": "wavelength_primes_2026-09-16",
    "frequency": "frequency_primes_2026-09-16",
    "url_prime": "url_prime_reinsertion_2026-09-16",
}
HEX64 = re.compile(rb"^[0-9a-fA-F]{64}$")


def _corpo(p):
    return bytes.fromhex(p.get("plaintextHex") or p["hex"])


def _regra_original(fam, d):
    """Conjunto de escalares (hex minúsculo) exatamente como o .cjs da família montou."""
    S = set()
    pws = [bytes.fromhex(p["hex"]) for p in d["passwords"]]
    corpos = [_corpo(p) for p in d["padding"]]
    if fam == "zero_cells" or fam == "url_prime":
        S |= {s256(b).hex() for b in pws}
        for b in corpos:
            if fam == "zero_cells":
                S.add(s256(b).hex())
            if len(b) == 32:
                S.add(b.hex())
            if HEX64.match(b):
                S.add(b.decode("latin-1").lower())
    elif fam == "color_factor":
        def esc(k):
            S.add(k.hex()); S.add(k[::-1].hex())
        for b in pws:
            esc(s256(b))
        for b in corpos:
            esc(s256(b))
            for j in range(len(b) - 31):
                esc(b[j:j + 32])
    else:   # count_prime, frequency, wavelength: só sha256(material) = sha256(senha 'direct')
        S |= {s256(bytes.fromhex(p["hex"])).hex() for p in d["passwords"] if p["form"] == "direct"}
    return {h for h in S if 0 < int(h, 16) < N}


def cjs(c, fam):
    arq = os.path.join(PRINCIPAL, "_work", CJS[fam], "oracles.json")
    d = json.load(open(arq, encoding="utf-8"))
    orig = sorted(_regra_original(fam, d))
    fluxo = hashlib.sha256(b"".join(bytes.fromhex(h) for h in orig)).hexdigest()
    ref = {"zero_cells": (d.get("scalarCount"), d.get("scalarStreamSHA256")),
           "color_factor": (d.get("scalars"), d.get("scalarStreamSHA256")),
           "url_prime": (d.get("scalars"), d.get("scalarStreamSHA256")),
           "count_prime": (d.get("scalarChecks"), None)}.get(fam)
    if fam in ("frequency", "wavelength"):
        guardado = sorted(s["hex"] for s in d["scalars"])
        ok = guardado == orig
        ref = (len(guardado), None)
    else:
        ok = ref[0] == len(orig) and (ref[1] is None or ref[1] == fluxo)
    assert ok, (fam, ref, len(orig), fluxo)
    for h in orig:
        c.add("original", bytes.fromhex(h))
    # extensão pedida pelo gate: sha256 de toda senha (inclui sha256(sha256hex(material))) e do corpo
    for p in d["passwords"]:
        c.add("ext/sha256(senha)", s256(bytes.fromhex(p["hex"])))
    for p in d["padding"]:
        c.add("ext/sha256(corpo)", s256(_corpo(p)))
    return {"arquivo": arq, "sha256_arquivo": sha_arquivo(arq), "senhas": len(d["passwords"]),
            "paddings": len(d["padding"]), "escalares_originais": len(orig),
            "scalarStream_recomputado": fluxo, "guardado": ref, "reconciliado": ok}


# =============================================================== (2C) prime_host e faed_keys
PH = {"ph_delta_run1": r"_work\prime_host_delta_2026-09-17\run1\materials.json",
      "ph_l84_run1": r"_work\prime_host_l84_2026-09-17\run1\materials.json",
      "rabbit_delta": r"_work\prime_host_delta_2026-09-17\rabbit_delta\materials.json"}


def prime_host(c):
    meta = {}
    for nome, rel in PH.items():
        arq = os.path.join(PRINCIPAL, rel)
        mats = json.load(open(arq, encoding="utf-8"))
        for m in mats:
            c.tres(nome, bytes.fromhex(m["hex"]))
        meta[nome] = {"materiais": len(mats), "sha256_arquivo": sha_arquivo(arq)}
    assert sum(v["materiais"] for v in meta.values()) == 30826, meta
    arq = os.path.join(PRINCIPAL, r"_work\prime_host_delta_2026-09-17\faed_keys\keys.json")
    keys = json.load(open(arq, encoding="utf-8"))
    for k in keys:
        s = "".join(str(v) for v in k["values"])       # decimal-concat e mod10: dígitos concatenados
        c.add("faed_keys/inteiro", int32(int(s)))
        c.tres("faed_keys/texto", s.encode())
    meta["faed_keys"] = {"chaves": len(keys), "formatos": dict(Counter(k["format"] for k in keys)),
                         "sha256_arquivo": sha_arquivo(arq)}
    return meta


# =============================================================== (3) select256 e cores163
FRONT = os.path.join(PRINCIPAL, r"_work\frontier_2026-09-17")


def select256(c):
    S = carregar(os.path.join(FRONT, r"rodada1_scripts\selection\select256.py"), "select256_hist")
    coleta = [True]

    def pcheck(sec, where):
        S.NT += 1
        if len(sec) == 32 and coleta[0]:
            c.add("pcheck", sec)
        return False

    def try_pw(pw, where, blobs=("SMALL", "COSMIC", "TAIL32")):
        S.NT += len(blobs)                                 # braço AES fora; só a contagem
    S.pcheck, S.try_pw, S.note_text = pcheck, try_pw, (lambda *a, **k: None)
    # --- controles do original só para reconciliar NT (escalares sintéticos não entram)
    coleta[0] = False
    S.control_privkey(); S.control_aes()
    nt_ctrl = S.NT
    coleta[0] = True
    # --- cópia do laço de main() (fontes, interseções, par i<->i+285, p24)
    sources = {"faed": G.FAED, "dbbi": G.DBBI, "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:]}
    seen = set()
    for sname, src in sources.items():
        cat = S.catalogo(src, sname)
        S.N_SEL += len(cat)
        dsrc = G.digits(src, False)
        for lbl, idx in cat.items():
            sub = "".join(src[i] for i in idx)
            key = (len(sub), hash(sub)); dup = key in seen; seen.add(key)
            do_pw = not lbl.startswith("mod") or lbl.endswith("_0")
            S.materialize(sub, f"{sname}/{lbl}", do_bits=True, do_pw=do_pw and not dup)
            S.head_tail_256(sub, f"{sname}/{lbl}")
            st = set(idx)
            zin = [0 if i in st else x for i, x in enumerate(dsrc)]
            zout = [x if i in st else 0 for i, x in enumerate(dsrc)]
            S.materialize_digits(zin, f"{sname}/{lbl}/ZERO_sel", do_pw=do_pw and not dup)
            S.materialize_digits(zout, f"{sname}/{lbl}/ZERO_comp", do_pw=False)
    cat = S.catalogo(G.FAED, "faed")
    fc = [(l, set(cat[l])) for l in S.FIRST_CLASS if l in cat]
    for a in range(len(fc)):
        for b in range(a + 1, len(fc)):
            la, sa = fc[a]; lb, sb = fc[b]
            for op, s in (("and", sa & sb), ("or", sa | sb), ("xor", sa ^ sb)):
                if len(s) < 8:
                    continue
                S.N_SEL += 1
                sub = "".join(G.FAED[i] for i in sorted(s))
                S.materialize(sub, f"faed/{la}_{op}_{lb}", do_bits=True, do_pw=False)
                S.head_tail_256(sub, f"faed/{la}_{op}_{lb}")
    S.pair_block(G.FAED, "faed")
    idx24 = [p for p in S.PR if p < 91]
    for tag, base in (("b0", 0), ("b1", 1)):
        sub = "".join(G.DBBI[p - base] for p in idx24 if 0 <= p - base < 91)
        S.materialize(sub, f"dbbi/p24_{tag}")
        for mul in (2, 3, 6, 7):
            S.materialize("".join(G.FAED[(p - base) * mul % 570] for p in idx24), f"faed/p24x{mul}_{tag}")
    nt_real = S.NT - nt_ctrl
    coleta[0] = False
    S.null_model(200)                                  # só conta os try_pw do nulo, como o original
    nt_total = S.NT
    assert (S.N_SEL, nt_total) == (2038, 3773974), (S.N_SEL, nt_total)
    return {"selecoes": S.N_SEL, "NT_total_reconciliado": nt_total, "NT_controles": nt_ctrl,
            "NT_laco_principal": nt_real, "NT_nulo": nt_total - nt_ctrl - nt_real,
            "fonte": sha_arquivo(S.__file__)}


def cores163(c):
    M = carregar(os.path.join(FRONT, r"rodada2_scripts\cores_parametro_163\cores163.py"), "cores163_hist")
    jan = Counter()

    def priv32(b):
        M.CNT["priv"] += 1
        c.add("priv32", b)
        return False

    def probe_pw(pw, label, log):
        M.CNT["pw"] += 1
        pb = pw.encode() if isinstance(pw, str) else pw
        priv32(hashlib.sha256(pb).digest())             # único braço de chave de probe_pw

    def fps(buf, where=""):
        for j in range(len(buf) - 31):
            c.add("janelas_formas_bytes", buf[j:j + 32]); jan["n"] += 1
        return []
    salvo = (G.fast_priv_scan, G.aes_rawkey)
    M.priv32, M.probe_pw = priv32, probe_pw
    G.fast_priv_scan, G.aes_rawkey = fps, (lambda *a, **k: None)
    try:
        M.reset_stats()
        M.battery(G.DBBI, G.FAED, log=True)
        M.run_url(log=True)
    finally:
        G.fast_priv_scan, G.aes_rawkey = salvo
    assert M.CNT["pw"] == 21997, M.CNT
    return {"senhas_reconciliadas": M.CNT["pw"], "priv32": M.CNT["priv"] - jan["n"],
            "janelas_formas_bytes": jan["n"], "CNT_priv_sem_plaintexts": M.CNT["priv"],
            "CNT_priv_original": 986874,
            "diferenca_janelas_de_plaintexts_AES": 986874 - M.CNT["priv"],
            "fonte": sha_arquivo(M.__file__)}


# ponytail: ordem intercala fontes grandes e pequenas para não ter 4 grandes na memória ao mesmo tempo
FONTES = {
    "select256": select256,
    "cjs_color_factor": lambda c: cjs(c, "color_factor"),
    "brainwallet_py_e_2": bw_frases,
    "F6_T3_low": f6_t3_low,
    "F6_gerar": f6_gerar,
    "cores163": cores163,
    "F6_T3_vb_ate_654889": lambda c: f6_t3_vb(c, "ate_654889"),
    "prime_host_faed_keys": prime_host,
    "corpus_466310": corpus_hist,
    "F6_separadores": f6_separadores,
    "F6_T3_vb_resto": lambda c: f6_t3_vb(c, "resto"),
    "brainwallet_inline": bw_inline,
    "cjs_zero_cells": lambda c: cjs(c, "zero_cells"),
    "cjs_frequency": lambda c: cjs(c, "frequency"),
    "cjs_wavelength": lambda c: cjs(c, "wavelength"),
    "cjs_url_prime": lambda c: cjs(c, "url_prime"),
    "cjs_count_prime": lambda c: cjs(c, "count_prime"),
}


# =============================================================== oráculo e processamento de uma fonte
def varrer(arr, plantados):
    """arr: np.ndarray V32 ordenado e único. Devolve contagens, sha256 do fluxo válido e acertos."""
    alvos = {**{h: ("REAL", a) for h, a in REAIS.items()}, **plantados}
    fluxo = hashlib.sha256()
    validos = invalidos = 0
    acertos = []
    for v in arr:
        k = v.tobytes()
        if k == ZERO or k >= NB:
            invalidos += 1
            continue
        validos += 1
        fluxo.update(k)
        pk = PublicKey.from_valid_secret(k)
        for comp in (False, True):
            h = h160(pk.format(comp))
            if h in alvos:
                acertos.append({"k": k.hex(), "comprimida": comp, "h160": h.hex(), "alvo": alvos[h]})
    return validos, invalidos, fluxo.hexdigest(), acertos


def processar(nome):
    t0 = time.time()
    c = Coletor()
    meta = FONTES[nome](c)
    t_ger = time.time() - t0
    gerados = len(c.buf) // 32
    arr = np.unique(np.frombuffer(c.buf, dtype="V32"))
    c.buf = None
    validos_idx = [i for i in (len(arr) // 3, 2 * len(arr) // 3)]
    plantados = {}
    for i, comp in zip(validos_idx, (False, True)):
        k = arr[i].tobytes()
        if k != ZERO and k < NB:
            plantados[h160(PublicKey.from_valid_secret(k).format(comp))] = ("PLANTADO", k.hex(), comp)
    validos, invalidos, fluxo, acertos = varrer(arr, plantados)
    reais = [a for a in acertos if a["alvo"][0] == "REAL"]
    recup = {(a["k"], a["comprimida"]) for a in acertos if a["alvo"][0] == "PLANTADO"}
    esperado = {(v[1], v[2]) for v in plantados.values()}
    # implementação independente (python-ecdsa, oracles.priv_to_addresses) numa amostra
    rnd = random.Random(nome)
    amostra = [arr[i].tobytes() for i in rnd.sample(range(len(arr)), min(200, len(arr)))]
    amostra = [k for k in amostra if k != ZERO and k < NB]
    diverg = 0
    for k in amostra:
        _au, _ac, hu, hc = O.priv_to_addresses(k)
        pk = PublicKey.from_valid_secret(k)
        diverg += (h160(pk.format(False)).hex(), h160(pk.format(True)).hex()) != (hu, hc)
    pref = np.frombuffer(arr.tobytes(), dtype=np.uint8).reshape(-1, 32)[:, :8].copy().view(">u8").ravel()
    return {"fonte": nome, "meta": meta, "por_subfonte": dict(c.por_sub), "fora_de_32B": dict(c.fora),
            "gerados": gerados, "unicos": int(len(arr)), "validos": validos, "invalidos_0_ou_ge_n": invalidos,
            "sha256_fluxo_ordenado": fluxo, "verificacoes_h160": 2 * validos,
            "hits_reais": reais, "plantados": len(esperado), "plantados_recuperados": len(recup & esperado),
            "controle_plantado_ok": recup == esperado and len(esperado) == 2,
            "ecdsa_amostra": len(amostra), "ecdsa_divergencias": diverg,
            "seg_geracao": round(t_ger, 1), "seg_total": round(time.time() - t0, 1)}, pref.tobytes()


# =============================================================== controles globais
def controles():
    k = s256(b"correct horse battery staple")
    au, _ac, hu, _hc = O.priv_to_addresses(k)
    pk = PublicKey.from_valid_secret(k)
    ok_pub = au == "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T" and h160(pk.format(False)).hex() == hu
    # o kit atual enxerga um segundo alvo plantado; restaura depois
    ks = s256(b"retro_17ucy/controle-kit")
    hs = h160(PublicKey.from_valid_secret(ks).format(True)).hex()
    antes = (O.TARGET_H160S, G.TARGET_H160S)
    assert G.priv_hit(ks) is None
    O.TARGET_H160S = O.TARGET_H160S + (hs,); G.TARGET_H160S = O.TARGET_H160S
    try:
        ok_kit = bool(G.priv_hit(ks)) and bool(G.fast_priv_scan(b"\x00" * 5 + ks))
    finally:
        O.TARGET_H160S, G.TARGET_H160S = antes
    assert O.TARGET_H160S == antes[0] and len(O.TARGET_H160S) == 2
    # a lacuna: o oráculo anterior ao 0ce4185 não tem segunda vaga; o mesmo escalar passa em branco
    src_old = subprocess.run(["git", "-C", SOLVER, "show", "0ce4185^:solver/oracles.py"],
                             capture_output=True, text=True, encoding="utf-8").stdout
    ns = {"__name__": "oracles_antigo", "__file__": os.path.join(SOLVER, "oracles.py")}
    exec(compile(src_old, "oracles_antigo.py", "exec"), ns)
    old_cego = ns["check_privkey"](ks) is None and "TARGET_H160S" not in ns \
        and "17ucy" not in src_old and O.TARGET_H160S[1] not in src_old
    return {"positivo_publico_correct_horse": ok_pub, "endereco": au,
            "kit_atual_ve_segundo_alvo_plantado": ok_kit,
            "oraculo_pre_0ce4185_sem_17ucy": old_cego,
            "oraculo_pre_0ce4185_alvos": [ns["PRIZE_ADDR"], ns["TARGET_H160"]]}


def main(nomes):
    teste = bool(nomes)
    nomes = nomes or list(FONTES)
    t0 = time.time()
    ctrl = controles()
    assert all(v for k, v in ctrl.items() if k.startswith(("positivo", "kit", "oraculo_pre_0ce4185_sem"))), ctrl
    print("[controles]", ctrl, flush=True)
    res, prefs = [], []
    with Pool(WORKERS, maxtasksperchild=1) as pool:
        for r, pref in pool.imap_unordered(processar, nomes):
            res.append(r); prefs.append(pref)
            print("[fonte] %-22s gerados=%9d unicos=%9d validos=%9d reais=%d plantado=%s ecdsa_div=%d %.0fs"
                  % (r["fonte"], r["gerados"], r["unicos"], r["validos"], len(r["hits_reais"]),
                     r["controle_plantado_ok"], r["ecdsa_divergencias"], r["seg_total"]), flush=True)
    todos = np.unique(np.frombuffer(b"".join(prefs), dtype=">u8"))
    soma = sum(r["unicos"] for r in res)
    resumo = {"frente": "retro_17ucy", "alvos": dict(zip(O.PRIZE_ADDRS, O.TARGET_H160S)),
              "kit": C.commit_do_kit(), "script_sha256": sha_arquivo(os.path.abspath(__file__)),
              "comum_sha256": sha_arquivo(C.__file__),
              "fontes": len(res), "gerados": sum(r["gerados"] for r in res), "unicos_soma_por_fonte": soma,
              "unicos_uniao_prefixo64": int(len(todos)), "sobreposicao_entre_fontes": soma - int(len(todos)),
              "validos": sum(r["validos"] for r in res), "verificacoes_h160": sum(r["verificacoes_h160"] for r in res),
              "hits_reais": [h for r in res for h in r["hits_reais"]], "aes": 0,
              "seg_parede": round(time.time() - t0, 1)}
    print(json.dumps(resumo, ensure_ascii=False, indent=1), flush=True)
    if teste:
        return
    ordem = {n: i for i, n in enumerate(FONTES)}
    res.sort(key=lambda r: ordem[r["fonte"]])
    json.dump({**resumo, "por_fonte": res}, open(os.path.join(SAIDA, "summary.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    json.dump({"globais": ctrl, "por_fonte": {r["fonte"]: {k: r[k] for k in (
        "plantados", "plantados_recuperados", "controle_plantado_ok", "ecdsa_amostra", "ecdsa_divergencias")}
        for r in res}, "nulo": "N/A: cobertura determinística finita; vale a contagem reconciliada"},
        open(os.path.join(SAIDA, "controls.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main(sys.argv[1:])
