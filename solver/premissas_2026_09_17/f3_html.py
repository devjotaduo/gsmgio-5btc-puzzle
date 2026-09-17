# -*- coding: utf-8 -*-
"""Forense byte a byte dos HTMLs vivos (endgame, fase2, theseed, root, robots): nao-ASCII, tabs, trailing ws,
CRLF/LF, comentarios, atributos/ids, ordem de scripts; e conferencia byte-exata dos blobs/strings contra o kit."""
import sys, os, re, collections, hashlib, base64
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
D = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\gsmg_live_2026-09"
FILES = {"endgame": "body_89727c598b9cd1cf8873f27cb7057f050645ddb6",
         "fase2": "body_choiceisanillusioncreatedbetweenthosewit",
         "theseed": "body_theseedisplanted", "root": "body_gsmg.io_root",
         "robots": "body_gsmg.io_robots.txt", "puzzle": "body_puzzle"}
for name, fn in FILES.items():
    b = open(os.path.join(D, fn), "rb").read()
    print("=" * 78); print(f"{name}: {len(b)} B sha256={hashlib.sha256(b).hexdigest()[:16]}")
    crlf = b.count(b"\r\n"); lf = b.count(b"\n") - crlf; cr = b.count(b"\r") - crlf
    print(f"  CRLF={crlf} LF={lf} CR={cr} TAB={b.count(b'\t')} NUL={b.count(b'\x00')} termina-com-newline={b.endswith(b'\n')}")
    non = [(i, x) for i, x in enumerate(b) if x >= 0x80 or (x < 0x20 and x not in (9, 10, 13))]
    print(f"  bytes nao-ASCII/controle: {len(non)}")
    if non and len(non) < 60:
        # agrupar em sequencias utf-8
        s = b.decode("utf-8", "replace")
        for m in re.finditer(r"[^\x00-\x7f]+", s):
            print(f"    @char{m.start()} {m.group()!r} U+{' U+'.join(f'{ord(c):04X}' for c in m.group())}  ctx={s[max(0,m.start()-25):m.end()+25]!r}")
    lines = b.split(b"\n")
    trail = [(i, len(l) - len(l.rstrip(b" \t\r"))) for i, l in enumerate(lines) if l.rstrip(b"\r") != l.rstrip(b" \t\r")]
    print(f"  linhas={len(lines)} trailing-ws em: {trail[:20]}")
    dbl = [(i, l.count(b"  ")) for i, l in enumerate(lines) if b"  " in l.lstrip()]
    print(f"  espacos-duplos internos: {dbl[:20]}")
    lead = collections.Counter(len(l) - len(l.lstrip(b" ")) for l in lines if l.strip())
    print(f"  indentacao (espacos iniciais -> n linhas): {dict(lead)}")
    print(f"  comentarios: {re.findall(rb'<!--.*?-->', b, re.S)}")
    tags = re.findall(rb"<([a-zA-Z0-9]+)([^>]*)>", b)
    attrs = collections.Counter()
    for t, a in tags:
        for k, v in re.findall(rb'([a-zA-Z\-]+)\s*=\s*"([^"]*)"', a): attrs[(t.lower(), k.lower(), v)] += 1
    print(f"  tags ({len(tags)}): {collections.Counter(t.lower() for t, _ in tags)}")
    for (t, k, v), n in attrs.items():
        if k in (b"id", b"class", b"name", b"style", b"href", b"src", b"action", b"content", b"lang", b"charset", b"type", b"method", b"rel"):
            print(f"    <{t.decode()} {k.decode()}={v.decode('utf-8','replace')!r}> x{n}")
    scripts = re.findall(rb"<script[^>]*>.*?</script>", b, re.S)
    print(f"  scripts: {len(scripts)}")
    for s in scripts: print("    ", s[:200])
    # textareas: conteudo exato
    for i, ta in enumerate(re.findall(rb"<textarea[^>]*>(.*?)</textarea>", b, re.S)):
        print(f"  textarea[{i}] {len(ta)} B  comeca={ta[:20]!r} termina={ta[-20:]!r} linhas={ta.count(b'\n')}")
        open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{name}_textarea{i}.bin"), "wb").write(ta)

# ---- conferencia byte-exata do endgame vs kit
b = open(os.path.join(D, FILES["endgame"]), "rb").read()
tas = re.findall(rb"<textarea[^>]*>(.*?)</textarea>", b, re.S)
t0 = tas[0].decode()
print("\n=== endgame textarea[0] (SalPhaseIon) ===")
for i, l in enumerate(t0.split("\n")):
    print(f"  L{i:02d} len={len(l):4d} {'CR' if l.endswith(chr(13)) else '  '} | {l[:100]!r}")
flat = t0.replace(" ", "").replace("\r", "").replace("\n", "")
print("  flat len", len(flat))
# tokens do kit
assert G.DBBI in flat and G.FAED in flat
print("  dbbi @", flat.index(G.DBBI), " faed @", flat.index(G.FAED))
# blob SMALL exato no textarea?
sm = re.search(r"U2FsdGVkX18[A-Za-z0-9+/=]+", t0)
print("  primeira linha base64 SMALL:", sm.group() if sm else None, "== kit:", (sm.group() == G.SMALL_B64[:64]) if sm else None)
t1 = tas[1].decode()
cos = t1.replace("\r", "").replace("\n", "").strip()
print("=== COSMIC textarea: len", len(cos), "== kit:", base64.b64decode(cos) == b"Salted__" + G.BLOBS["COSMIC"][0] + G.BLOBS["COSMIC"][1])
# base64 canonicidade: bits sobrando no ultimo char
def spare_bits(s):
    s = s.rstrip("="); n = len(s) % 4
    if n == 0: return 0, None
    last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".index(s[-1])
    return {2: 4, 3: 2}[n], last & ({2: 0xF, 3: 0x3}[n])
print("  COSMIC spare bits:", spare_bits(cos))
# fase 2 / fase 3 textareas vs kit
b2 = open(os.path.join(D, FILES["fase2"]), "rb").read()
t2 = [x.decode().replace("\n", "").replace("\r", "").strip() for x in re.findall(rb"<textarea[^>]*>(.*?)</textarea>", b2, re.S)]
print("=== fase2 page: textarea0 == PHASE2_B64:", t2[0] == G.PHASE2_B64, "| textarea1 == PHASE3_B64:", t2[1] == G.PHASE3_B64)
for nm, s in (("PHASE2", G.PHASE2_B64), ("PHASE3", G.PHASE3_B64), ("PHASE32", G.PHASE32_B64), ("SMALL", G.SMALL_B64), ("TAIL32", G.TAIL32_B64)):
    print(f"  {nm}: len={len(s)} spare_bits={spare_bits(s)} ct_len={len(base64.b64decode(s))-16}")
