# -*- coding: utf-8 -*-
"""
Running key EXTERNA ao corpus da página: o texto do livro *Looking Forward* (Keyes & Fresco 1969) — o "Bingo" do criador em 2026-03-03 (OCR em
_work/cosmic_duality.txt, ~250 k letras), lead do R6. Hipótese: faed = checkerboard/dígitos de um
texto somado (mod 9/10) a uma chave corrente tirada do livro a partir de algum ponto (p. ex. p. 39).
Varre TODOS os alinhamentos (offset da chave) × 4 configurações × 3 modos com um pré-filtro
vetorizado de entropia condicional H(X_{i+1}|X_i); os 150 streams de menor H por (config, modo)
passam pelo gate completo (z vs 30 embaralhados). O mesmo pipeline roda sobre um faed embaralhado
(nulo casado). Controle: checkerboard 3.2.2 de inglês + chave = trecho do livro no offset 12345.
Oráculo: |z| ≥ 10 → decode checkerboard/Bifid (só se algo passar).
"""
import sys, os, io, re, json, time
import numpy as np
SCR = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, SCR)
import gsmg_common as G
rng = np.random.default_rng(42)
LOG = os.path.join(SCR, "lf_running_key.jsonl"); open(LOG, "w").close()

txt = io.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\looking_forward.txt", encoding="utf-8", errors="ignore").read()
LET = np.array([ord(c) - 96 for c in txt.lower() if "a" <= c <= "z"], dtype=np.int64)
print("letras do livro:", len(LET))
FD = np.array(G.digits(G.FAED), dtype=np.int64)
N = 570
CONFIGS = {
    "m9":    dict(n=9,  c=(FD - 1)),
    "m10a":  dict(n=10, c=FD.copy()),
    "m10i0": dict(n=10, c=np.where(FD == 9, 0, FD)),
    "m10a0": dict(n=10, c=(FD - 1)),
}
KEYS = {"a1z26": LET, "a0z25": LET - 1}

def hcond_batch(S, n):
    """S: (m, N) streams inteiros em 0..n-1 → H(X_{i+1}|X_i) por linha (bits)."""
    m = S.shape[0]
    pair = S[:, :-1] * n + S[:, 1:]                                   # (m, N-1)
    bg = np.zeros((m, n * n), dtype=np.float64)
    np.add.at(bg, (np.repeat(np.arange(m), N - 1), pair.ravel()), 1.0)
    bg = bg.reshape(m, n, n); rows = bg.sum(2, keepdims=True)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(bg > 0, bg * np.log2(bg / rows), 0.0)
    return -t.sum((1, 2)) / (N - 1)

def bigram_stats(a, n):
    bg = np.bincount(a[:-1] * n + a[1:], minlength=n * n).astype(float)
    Mn = bg.sum(); ioc = (bg * (bg - 1)).sum() / (Mn * (Mn - 1))
    b2 = bg.reshape(n, n); rows = b2.sum(1, keepdims=True)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(b2 > 0, b2 * np.log2(b2 / rows), 0.0)
    return -t.sum() / Mn, ioc
def gate_z(a, n, nshuf=30):
    H, I = bigram_stats(a, n)
    nul = np.array([bigram_stats(rng.permutation(a), n) for _ in range(nshuf)])
    return (H - nul[:, 0].mean()) / (nul[:, 0].std() or 1e-9), (I - nul[:, 1].mean()) / (nul[:, 1].std() or 1e-9)

def rekey(c, K, mode, n):      # c: (N,), K: (m, N)
    if mode == "add": return (c[None, :] - K) % n
    if mode == "sub": return (c[None, :] + K) % n
    return (K - c[None, :]) % n

def scan(cvec_by_cfg, label, topk=150, chunk=20000):
    """Para cada (chave, config, modo): H para todos os offsets; gate completo nos topk menores."""
    out = []
    for kn, key in KEYS.items():
        noff = len(key) - N + 1
        win = np.lib.stride_tricks.sliding_window_view(key, N)      # (noff, N) view
        for cn, cfg in CONFIGS.items():
            n = cfg["n"]; c = cvec_by_cfg[cn]
            for mode in ("add", "sub", "beau"):
                Hs = np.empty(noff)
                for s in range(0, noff, chunk):
                    K = win[s:s + chunk] % n
                    Hs[s:s + chunk] = hcond_batch(rekey(c, K, mode, n), n)
                idx = np.argpartition(Hs, topk)[:topk]
                best = None
                for o in idx:
                    a = rekey(c, win[o:o + 1] % n, mode, n)[0]
                    zH, zI = gate_z(a, n)
                    if best is None or zH < best[0]: best = (float(zH), float(zI), int(o), float(Hs[o]))
                rec = {"label": label, "key": kn, "cfg": cn, "mode": mode, "noff": int(noff), "H_min": float(Hs.min()),
                       "H_mean": float(Hs.mean()), "H_sd": float(Hs.std()), "best_zH": best[0], "best_zI": best[1], "best_off": best[2]}
                out.append(rec); G.jsonl(LOG, rec)
                print(f"{label:8s} {kn:6s} {cn:6s} {mode:4s} noff={noff:7d} Hmin={Hs.min():.3f} (mean {Hs.mean():.3f} sd {Hs.std():.4f})  best zH={best[0]:+.2f} zI={best[1]:+.2f} @off {best[2]}"); sys.stdout.flush()
    return out

t0 = time.time()
# ---- controle: inglês (monólogo do Arquiteto) → checkerboard 3.2.2 → + chave do livro no offset 12345 (m10a, add)
README = io.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
arch = re.search(r"NOW TO RETURN TO THE SOURCE[^\n]*", README)
eng = re.sub(r"[^A-Z]", "", (arch.group() if arch else "NOWTORETURNTOTHESOURCECODES" * 30).upper())
try:
    AL322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
    digs = []
    # checkerboard 3.2.2: linha 0 = 8 letras sem escapes (escapes 1,4), linhas 1x/4x
    top = [c for c in AL322[:10]]  # posições 0..9, '.' nos escapes 1 e 4? usar G.checkerboard_encode se existir
    if hasattr(G, "checkerboard_encode"):
        digs = G.checkerboard_encode(eng, AL322, (1, 4))
    else:
        # codificação simples: alfabeto de 10 colunas com escapes nas colunas 1 e 4
        cols = "0123456789"; table = {}
        row0 = AL322.replace(".", "")[:8]; rest = AL322.replace(".", "")[8:]
        r0cols = [i for i in range(10) if i not in (1, 4)]
        for ch, col in zip(row0, r0cols): table[ch] = str(col)
        for j, ch in enumerate(rest): table[ch] = ("1" if j < 10 else "4") + str(j % 10)
        digs = [int(d) for ch in eng if ch in table for d in table[ch]]
    ctrl = np.array(digs[:N], dtype=np.int64)
    if len(ctrl) < N: ctrl = np.resize(ctrl, N)
    kc = (LET[12345:12345 + N]) % 10
    ctrl_c = (ctrl + kc) % 10           # cifrado com add em m10a ⇒ rekey 'add' recupera
    cv = {cn: ctrl_c.copy() for cn in CONFIGS}
    print("controle (chave certa deve aparecer em m10a/add @12345):")
    scan(cv, "ctrl", topk=60)
except Exception as e:
    print("controle falhou:", e)
print("t=%.0fs" % (time.time() - t0))
# ---- faed real
real = scan({cn: cfg["c"] for cn, cfg in CONFIGS.items()}, "faed")
print("t=%.0fs" % (time.time() - t0))
# ---- nulo casado: faed embaralhado, mesmo pipeline
perm = rng.permutation(N)
null = scan({cn: cfg["c"][perm] for cn, cfg in CONFIGS.items()}, "null")
zr = min(r["best_zH"] for r in real); zn = min(r["best_zH"] for r in null)
summary = {"n_streams_real": sum(r["noff"] for r in real), "min_zH_real": zr, "min_zH_null": zn,
           "passers_real": [r for r in real if r["best_zH"] <= -10], "elapsed_s": round(time.time() - t0)}
G.jsonl(LOG, {"summary": summary}); print(json.dumps(summary, ensure_ascii=False)[:1500])
