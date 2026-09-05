# -*- coding: utf-8 -*-
"""Roadmap do criador, passos 1-2: `yellowblueprimes` -> `matrixsumlist`.

Hipótese falsificável
--------------------
O roadmap (binário revertido, 2023-02-25) é SEQUENCIAL. Passo 1 `yellowblueprimes`: as 24
células coloridas ocupam os índices espirais 7,15,...,191 e são exatamente 24 = a quantidade
de primos < 91 = len(dbbi); a ordem espiral BBBBYBBBYYBBBBYBBYYBYYBY marca cada primo como
azul (15) ou amarelo (9). Isso particiona as posições primas de `dbbi` em dois grupos, e
15 é a largura da grade de `faed` (15x38) enquanto 9 é o tamanho do alfabeto. Passo 2
`matrixsumlist`: o resultado é operado pela LISTA de somas da matriz (linhas/colunas) ou por
101, produzindo a senha.

Espaço finito: 2 bases x {azul, amarelo, todos, complementos} como chave colunar sobre as
grades 15x38 e 38x15 de `faed` (direta e inversa, leitura por linha e coluna), depois a lista
de somas como deslocamento/seleção, materializado em dígitos, z-method e sha256.
Nulo casado: 300 reatribuições aleatórias de 15 azuis entre os 24 primos, mesmo pipeline.
"""
import sys, random, json, hashlib
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from Crypto.Cipher import AES

D, F = G.DBBI, G.FAED
PRIMES = [p for p in range(2, 91) if G.is_prime(p)]
ROWS = G.row_sums(G.MATRIX_README); COLS = G.col_sums(G.MATRIX_README)

# ---------- oráculo rápido (1 AES-ECB no último bloco), com controle positivo
def evp(pw, salt):
    d = b""; prev = b""
    while len(d) < 48:
        prev = hashlib.sha256(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]
def pad_ok(pw, salt, ct):
    k, _ = evp(pw, salt)
    p = bytes(a ^ b for a, b in zip(AES.new(k, AES.MODE_ECB).decrypt(ct[-16:]), ct[-32:-16]))
    n = p[-1]; return 1 <= n <= 16 and all(x == n for x in p[-n:])
def full(pw, salt, ct):
    k, iv = evp(pw, salt); return G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
s2, c2 = G._parse(G.PHASE2_B64)
assert pad_ok(G.shahex("causality").encode(), s2, c2) and b"keymaker" in full(G.shahex("causality").encode(), s2, c2).lower()
print("CONTROLE OK (fase 2 abre)")

def colkey(word):
    """Chave de transposição colunar: ordem estável dos caracteres (letras repetidas OK)."""
    return [i for i, _ in sorted(enumerate(word), key=lambda t: (t[1], t[0]))]

def transpose(text, key, by_col_out):
    w = len(key)
    if w == 0 or len(text) % w: return None
    rows = [text[i:i + w] for i in range(0, len(text), w)]
    cols = ["".join(r[k] for r in rows) for k in key]
    return "".join(cols) if by_col_out else "".join("".join(c[i] for c in cols) for i in range(len(rows)))

def pipeline(colorseq, collect):
    """Gera todos os textos candidatos para uma atribuição de cores."""
    blue = [p for p, c in zip(PRIMES, colorseq) if c == "B"]
    yell = [p for p, c in zip(PRIMES, colorseq) if c == "Y"]
    out = []
    for base in (0, 1):
        sel = {"blue": blue, "yellow": yell, "all": PRIMES}
        for name, ps in sel.items():
            word = "".join(D[p - base] for p in ps if 0 <= p - base < 91)
            if not word: continue
            for rev in (False, True):
                w = word[::-1] if rev else word
                key = colkey(w); inv = [0] * len(key)
                for i, k in enumerate(key): inv[k] = i
                for kk, kn in ((key, "k"), (inv, "ki")):
                    if len(F) % len(kk): continue
                    for bycol in (False, True):
                        t = transpose(F, kk, bycol)
                        if not t: continue
                        out.append((f"{name}{base}{'r' if rev else ''}{kn}{'c' if bycol else 'l'}", t))
    # passo 2: matrixsumlist sobre cada saída
    final = []
    for lab, t in out:
        digs = G.digits(t)
        final.append((lab + ":raw", t))
        for sums, sn in ((ROWS, "rows"), (COLS, "cols"), ([101], "101")):
            sh = "".join(str((d + sums[i % len(sums)]) % 9 + 1) for i, d in enumerate(digs))
            final.append((lab + ":+" + sn, sh))
            pick = "".join(t[i] for i in range(0, len(t), max(1, sums[0])) )
            if len(pick) > 8: final.append((lab + ":step" + sn, pick))
        if collect: final.append((lab + ":sel101", "".join(t[i] for i in range(len(t)) if (i % 101) < 9)))
    return final

def score_best(cands):
    b = (-99, None)
    for lab, t in cands:
        s = G.english_score(t.upper())
        if s > b[0]: b = (s, lab)
    return b[0]

real = pipeline(G.COLOR_SEQ, True)
print("candidatos reais:", len(real), " melhor score:", round(score_best(real), 3))

# ---------- nulo casado
random.seed(11); nulls = []
for _ in range(300):
    cs = ["B"] * 15 + ["Y"] * 9; random.shuffle(cs)
    nulls.append(score_best(pipeline("".join(cs), True)))
import statistics as st
mu, sd = st.mean(nulls), st.pstdev(nulls)
zr = (score_best(real) - mu) / (sd or 1e-9)
print(f"nulo(300): média {mu:.3f} sd {sd:.3f} máx {max(nulls):.3f}  ->  z real = {zr:+.2f}, "
      f"p = {sum(1 for x in nulls if x >= score_best(real))/len(nulls):.3f}")

# ---------- oráculos duros em TODOS os candidatos reais
BL = {k: G.BLOBS[k] for k in ("SMALL", "COSMIC", "TAIL32")}
n_aes = 0; pads = 0; hard = []
for lab, t in real:
    forms = {t.encode(), t.upper().encode(), G.shahex(t).encode(), G.shahex(t).upper().encode()}
    try:
        z = G.z_method(G.digits(t))
        forms |= {z, z.hex().encode(), G.shahex(z).encode()}
        for h in G.fast_priv_scan(z, lab): hard.append(h)
    except Exception: pass
    for f in forms:
        for bn, (salt, ct) in BL.items():
            n_aes += 1
            if pad_ok(f, salt, ct):
                p = full(f, salt, ct); pads += 1
                if p and (G.semantic(p) or G.printable(p) > 0.85):
                    hard.append((bn, lab, p[:120].decode("latin-1"))); print("!!! HARD", bn, lab, p[:100])
                if p:
                    for h in G.fast_priv_scan(p, f"{bn}:{lab}"): hard.append(h)
print(f"oráculos: {n_aes} AES, paddings {pads} (esperado {n_aes/256:.1f}), HARD={hard}")
json.dump({"family": "roadmap_yellowblue_matrixsum", "n_cands": len(real), "n_aes": n_aes,
           "pads": pads, "expected_pads": n_aes / 256, "z": zr, "hard": hard},
          open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\roadmap_yb_matrixsum.json", "w"), indent=1)
