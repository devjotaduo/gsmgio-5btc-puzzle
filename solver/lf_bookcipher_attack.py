# -*- coding: utf-8 -*-
"""*Looking Forward* como CIFRA DE LIVRO indexada por `faed`.

Hipótese falsificável
--------------------
`faed` tem 570 símbolos a-i (dígitos 1..9, nunca 0) e comporta-se como i.i.d. — exatamente
o que se espera de um fluxo de ÍNDICES, não de texto cifrado. 570 = 3x190 = 2x285.
Se o livro apontado pelo "Bingo" do criador (2026-03-03) é a fonte, então os grupos de
2 ou 3 dígitos de `faed` indexam palavras/linhas/sentenças e a mensagem sai das iniciais.

Espaço: grupos de 2 e 3 dígitos, lidos em decimal e em base 9, base 0 e 1, ordem direta e
reversa, sobre 4 universos do livro (palavras, linhas, sentenças, letras), pegando a inicial
ou a palavra inteira. Cada saída passa por quadgramas com NULO casado (as mesmas leituras
sobre um `faed` embaralhado) e pelos oráculos duros AES/privkey.
"""
import sys, re, io, random, hashlib
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G

txt = io.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\looking_forward.txt", encoding="utf-8", errors="ignore").read()
UNIV = {
    "words": [w for w in re.findall(r"[A-Za-z']+", txt)],
    "lines": [l for l in txt.split("\n") if l.strip()],
    "sents": [s for s in re.split(r"(?<=[.!?])\s+", txt.replace("\n", " ")) if s.strip()],
    "letters": list(re.sub(r"[^A-Za-z]", "", txt)),
}
print({k: len(v) for k, v in UNIV.items()})

def groups(digs, k):
    return [digs[i:i + k] for i in range(0, len(digs) - k + 1, k)]
def val(g, base, off):
    v = 0
    for d in g: v = v * base + (d - off)
    return v

def readings(faed_digits):
    """Todas as leituras principiadas: (rótulo, lista de índices)."""
    out = []
    for k in (2, 3):
        for rev in (False, True):
            ds = faed_digits[::-1] if rev else faed_digits
            for gr in (groups(ds, k),):
                for base, off, bn in ((10, 0, "dec"), (9, 1, "b9"), (10, 1, "dec-1")):
                    idx = [val(g, base, off) for g in gr]
                    out.append((f"k{k}{'r' if rev else ''}:{bn}", idx))
    return out

def materialize(idx, uname, mode):
    U = UNIV[uname]; n = len(U)
    picks = []
    for i in idx:
        j = i % n if mode.endswith("mod") else i
        if not (0 <= j < n): return None
        picks.append(U[j])
    if uname == "letters": return "".join(picks).upper()
    if mode.startswith("init"): return "".join(p.strip()[0] for p in picks if p.strip()).upper()
    return re.sub(r"[^A-Z]", "", " ".join(picks).upper())[:2000]

def sweep(faed_digits, tag):
    best = (-99, None); n = 0; texts = []
    for label, idx in readings(faed_digits):
        for uname in UNIV:
            for mode in ("init", "initmod", "full", "fullmod"):
                if uname == "letters" and mode.startswith("init"): continue
                t = materialize(idx, uname, mode)
                if not t or len(t) < 40: continue
                n += 1
                s = G.english_score(t)
                if s > best[0]: best = (s, f"{tag}|{label}|{uname}|{mode}", t[:120])
                texts.append((s, f"{label}|{uname}|{mode}", t))
    return best, n, texts

FD = G.digits(G.FAED)                      # a=1..i=9
best, n, texts = sweep(FD, "faed")
print(f"leituras válidas: {n}; melhor score {best[0]:.2f} em {best[1]}")
print("  texto:", best[2])

# ---- nulo casado: 200 embaralhamentos de faed, mesmo pipeline
random.seed(7); nulls = []
for _ in range(200):
    d2 = FD[:]; random.shuffle(d2)
    b, _, _ = sweep(d2, "null"); nulls.append(b[0])
nulls.sort()
import statistics as st
mu, sd = st.mean(nulls), st.pstdev(nulls)
z = (best[0] - mu) / (sd or 1e-9)
print(f"nulo (200 embaralhamentos): média {mu:.2f} sd {sd:.2f} máx {nulls[-1]:.2f} -> z do real = {z:+.2f}")
print(f"p empírico = {sum(1 for x in nulls if x >= best[0]) / len(nulls):.3f}")

# ---- oráculos duros nos 40 melhores textos
texts.sort(reverse=True, key=lambda x: x[0])
hard = []; n_aes = 0
for s, how, t in texts[:40]:
    for form in (t, t.lower(), G.shahex(t), G.shahex(t.lower())):
        h, _ = G.try_password_all(form); n_aes += 3; hard += h
        hard += [(how, r) for r in G.phrase_priv(form)]
print(f"oráculos: {n_aes} AES nos 40 melhores textos, HARD={hard}")
print("top 5 textos:")
for s, how, t in texts[:5]: print(f"  {s:6.2f} {how:28s} {t[:90]}")
