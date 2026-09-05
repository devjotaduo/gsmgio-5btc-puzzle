# -*- coding: utf-8 -*-
"""Bytes EXATOS dos plaintexts das fases 2/3/3.2 como material de senha do TAIL32.

Hipótese falsificável
--------------------
A gramática do puzzle é sha256(texto) -> senha do próximo blob. O blob TAIL32 fica no FIM do
plaintext da fase 3.2, logo sua senha deve sair desse mesmo plaintext. A rodada anterior
(`raising_variants`) precisou ADIVINHAR 31 variantes de whitespace porque só tinha a transcrição
do README; aqui os plaintexts são decifrados na hora, com os CRLF verdadeiros, e usados verbatim:
o texto inteiro, cada bloco separado por CRLFCRLF, cada linha, cada sentença, os prefixos e
sufixos cumulativos, e as concatenações encadeadas entre fases.
"""
import sys, re, hashlib, itertools, json
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from Crypto.Cipher import AES

def evp(pw, salt, h):
    d = b""; p = b""
    while len(d) < 48: p = h(p + pw + salt).digest(); d += p
    return d[:32], d[32:48]
def pad_ok(pw, salt, ct, h):
    k, _ = evp(pw, salt, h)
    p = bytes(a ^ b for a, b in zip(AES.new(k, AES.MODE_ECB).decrypt(ct[-16:]), ct[-32:-16]))
    n = p[-1]; return 1 <= n <= 16 and all(x == n for x in p[-n:])
def dec(pw, salt, ct, h=hashlib.sha256):
    k, iv = evp(pw, salt, h); return G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))

# ---- decifra as três fases e guarda os BYTES EXATOS
PW = {"p2": G.shahex("causality"),
      "p3": None,
      "p32": G.shahex("jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple")}
PT = {}
for tag, b64 in (("p2", G.PHASE2_B64), ("p32", G.PHASE32_B64)):
    s, c = G._parse(b64); p = dec(PW[tag].encode(), s, c)
    assert p, f"{tag} não abriu"; PT[tag] = p
    print(f"{tag}: {len(p)} bytes exatos, sha256 {G.shahex(p)}")

# ---- material verbatim
mats = set()
for tag, p in PT.items():
    mats.add(p)
    for blk in p.split(b"\r\n\r\n"):
        if blk: mats.add(blk); mats.add(blk.strip())
    for ln in p.replace(b"\r\n", b"\n").split(b"\n"):
        if ln.strip(): mats.add(ln); mats.add(ln.strip())
    for m in re.finditer(rb"[ -~]{25,}", p):
        mats.add(m.group())
    # prefixos/sufixos cumulativos por bloco
    blks = [b for b in p.split(b"\r\n\r\n") if b]
    for i in range(1, len(blks) + 1):
        mats.add(b"\r\n\r\n".join(blks[:i])); mats.add(b"\r\n\r\n".join(blks[-i:]))
# encadeamento entre fases (verbatim, nas duas ordens)
for a, b in itertools.permutations(PT.values(), 2):
    mats.add(a + b); mats.add(G.sha(a) + G.sha(b)); mats.add((G.shahex(a) + G.shahex(b)).encode())
mats = {m for m in mats if 4 <= len(m) <= 4000}
print("materiais verbatim únicos:", len(mats))

forms = set()
for m in mats:
    forms |= {m, G.shahex(m).encode(), G.shahex(m).upper().encode(), G.sha(m)}
    try:
        t = m.decode("ascii")
        forms |= {t.lower().encode(), re.sub(rb"\s+", b"", m), re.sub(rb"[^A-Za-z0-9]", b"", m)}
    except Exception: pass
forms = {f for f in forms if f}
print("formas de senha:", len(forms))

BL = {k: G.BLOBS[k] for k in ("TAIL32", "SMALL", "COSMIC")}
s2, c2 = G._parse(G.PHASE2_B64)
assert pad_ok(G.shahex("causality").encode(), s2, c2, hashlib.sha256), "controle quebrado"
print("CONTROLE OK")
n = 0; pads = []; hard = []
for f in forms:
    for bn, (salt, ct) in BL.items():
        for h, hn in ((hashlib.sha256, "sha256"), (hashlib.md5, "md5")):
            n += 1
            if pad_ok(f, salt, ct, h):
                p = dec(f, salt, ct, h)
                if not p: continue
                pads.append((bn, hn, round(G.printable(p), 3), f[:50]))
                if G.semantic(p) or G.printable(p) > 0.85:
                    hard.append((bn, hn, f[:80].decode("latin-1", "replace"), p[:200].decode("latin-1", "replace")))
                    print("!!! HARD", bn, hn, f[:60], p[:150])
                for x in G.fast_priv_scan(p, bn): hard.append(x)
print(f"RESULTADO: {n} testes AES; paddings {len(pads)} (esperado {n/256:.1f}); HARD={hard}")
for p in sorted(pads, key=lambda x: -x[2])[:8]: print("  pad", p)
json.dump({"family": "exact_plaintext_tail32", "n_materials": len(mats), "n_forms": len(forms),
           "n_aes": n, "pads": len(pads), "expected": n / 256, "hard": hard},
          open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\exact_plaintext_tail32.json", "w"), indent=1)
