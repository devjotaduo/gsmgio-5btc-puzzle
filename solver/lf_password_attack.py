# -*- coding: utf-8 -*-
"""Looking Forward (Keyes & Fresco, 1969) como FONTE DE SENHA.

Hipótese (gramática provada do puzzle): a senha da fase 1 é uma frase VERBATIM de uma obra
(letra de "The Warning") em minúsculas e sem espaços -> sha256. O criador respondeu "Bingo"
quando gnomad apontou o comentário de Denis Golovkin de que "it's in front of your eyes but
you're not seeing it" era recomendação de ler este livro. Logo: alguma frase/sequência de
palavras do livro, normalizada da mesma forma, é a senha de SMALL/COSMIC/TAIL32.

Espaço: todas as sentenças, todos os títulos e todos os n-gramas de 2..12 palavras.
Oráculo rápido: só o último bloco (padding PKCS7) via 1 AES-ECB; padding válido -> decifra tudo
e roda o oráculo semântico + varredura de privkey.
"""
import sys, re, io, hashlib, itertools, json, time
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from Crypto.Cipher import AES

BLOBS = {k: G.BLOBS[k] for k in ("SMALL", "COSMIC", "TAIL32")}

def evp_sha256(pw, salt):
    d = b""; prev = b""
    while len(d) < 48:
        prev = hashlib.sha256(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]

def fast_pad_ok(pw, salt, ct):
    """1 AES-ECB: plaintext do último bloco = D(ct[-16:]) XOR ct[-32:-16]."""
    key, _ = evp_sha256(pw, salt)
    last = AES.new(key, AES.MODE_ECB).decrypt(ct[-16:])
    prev = ct[-32:-16]
    p = bytes(a ^ b for a, b in zip(last, prev))
    n = p[-1]
    return 1 <= n <= 16 and all(x == n for x in p[-n:])

def full(pw, salt, ct):
    key, iv = evp_sha256(pw, salt)
    p = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    return G.unpad(p)

# ---------------- controle positivo: a fase 2 abre com sha256hex("causality")
s2, c2 = G._parse(G.PHASE2_B64)
ctrl = G.shahex("causality").encode()
assert fast_pad_ok(ctrl, s2, c2), "oráculo rápido quebrado"
pt = full(ctrl, s2, c2); assert b"keymaker" in pt.lower(), "controle não abriu"
print("CONTROLE OK: fase 2 aberta, printable", round(G.printable(pt), 3))

# ---------------- corpus
txt = io.open(r"C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle\e6b07645-ce08-4b50-be07-c055b0360d9d\scratchpad\lf.txt", encoding="utf-8", errors="ignore").read()
txt = txt.replace("-\n", "").replace("\n", " ")
norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", txt) if 8 <= len(s.strip()) <= 400]
words = [w for w in re.findall(r"[A-Za-z0-9']+", txt)]
print("sentenças", len(sentences), "palavras", len(words))

cands = set()
for s in sentences:
    n = norm(s)
    if 8 <= len(n) <= 200: cands.add(n)
# n-gramas de palavras
for n in range(2, 13):
    for i in range(len(words) - n + 1):
        c = norm(" ".join(words[i:i + n]))
        if 8 <= len(c) <= 120: cands.add(c)
# títulos/capítulos e tokens do livro combinados com o vocabulário do puzzle
extra = ["lookingforward", "kennethskeyesjr", "jacquefresco", "thingsthatshapeourfuture",
         "aprojectionofourfuture", "theleapfromthejungle", "theconfusionofourtimes",
         "predictingthefuture", "ourvalueschartourcourse", "thescientificmethod",
         "cybernatedtechnology", "awaywego", "athomeinthetwentyfirstcentury"]
for e in extra:
    cands.add(e); cands.add(e + "lookingforward"); cands.add("lookingforward" + e)
    cands.add("jacquefresco" + e); cands.add(e + "jacquefresco")
print("candidatos únicos:", len(cands))

t0 = time.time(); n_tests = 0; pads = []; hard = []
for i, c in enumerate(cands):
    for form in (G.shahex(c).encode(), c.encode(), G.shahex(c).upper().encode()):
        for bn, (salt, ct) in BLOBS.items():
            n_tests += 1
            if fast_pad_ok(form, salt, ct):
                p = full(form, salt, ct)
                if p is None: continue
                pr = G.printable(p)
                pads.append((bn, c[:60], form[:20].decode("latin-1"), round(pr, 3), p[:40].decode("latin-1")))
                if G.semantic(p) or pr > 0.85:
                    hard.append((bn, c, form.decode("latin-1"), pr, p[:200].decode("latin-1")))
                    print("!!! HARD", bn, c[:80], pr, p[:120])
                for h in G.fast_priv_scan(p, f"{bn}:{c[:40]}"): hard.append(h)
    if i % 20000 == 0 and i:
        print(f"  {i}/{len(cands)} cands, {n_tests} AES, {len(pads)} pads, {time.time()-t0:.0f}s"); sys.stdout.flush()
print(f"FIM: {len(cands)} candidatos, {n_tests} testes AES, {len(pads)} paddings válidos "
      f"(esperado ~{n_tests/256:.0f}), HARD={len(hard)}, {time.time()-t0:.0f}s")
for p in sorted(pads, key=lambda x: -x[3])[:12]: print("  pad", p)
json.dump({"family": "looking_forward_password", "n_cands": len(cands), "n_tests": n_tests,
           "pads": len(pads), "expected_pads": n_tests / 256, "hard": hard[:20],
           "top_pads": sorted(pads, key=lambda x: -x[3])[:20]},
          open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\looking_forward_password.json", "w"), indent=1)
