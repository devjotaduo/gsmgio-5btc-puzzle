# -*- coding: utf-8 -*-
"""
Extensao da familia -kfile: o "arquivo" pode ser o CIPHERTEXT da fase anterior (o `-in` do ultimo
comando) ou qualquer arquivo de texto do puzzle, e a "linha" qualquer linha (nao so a 1a).
Testa TODA linha (<=1023 B, semantica -pass file:) de: HTML/txt/xml/json/js do site, README.md,
blobs base64 das fases (linhas de 64 como no README) e SMALL/TAIL32/COSMIC como aparecem na pagina.
"""
import sys, os, re, hashlib, json, time, base64
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from coincurve import PublicKey
REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "soft_hits_lines.jsonl"); open(LOG, "w").close()
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
def priv(b32):
    try: return PublicKey.from_valid_secret(b32).format(False) == TGT
    except Exception: return False

TEXT_EXT = (".html", ".txt", ".xml", ".json", ".js")
files = [os.path.join(REPO, "README.md")]
for r in ("_work/gsmg_live_2026-09", "_work/archive", "_work/decentraland"):
    for dp, dn, fn in os.walk(os.path.join(REPO, r)):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            if f.startswith("hdr_") or f in ("cdx_all.json",) or f.startswith("reddit_"): continue
            if f.lower().endswith(TEXT_EXT) or f.startswith("body_") and not f.endswith((".png", ".ttf")):
                files.append(p)
materials = {}
def add(label, b):
    if b and len(b) <= 1023: materials.setdefault(b, label)
n_lines = 0
for f in files:
    data = open(f, "rb").read(); rel = os.path.relpath(f, REPO)
    for i, line in enumerate(data.split(b"\n")):
        n_lines += 1
        l = line[:-1] if line.endswith(b"\r") else line
        z = l.find(b"\x00"); l = l if z < 0 else l[:z]
        add(f"{rel}:{i+1}", l); add(f"{rel}:{i+1}|strip", l.strip())
        # linhas base64 (blobs): tambem os bytes decodificados
        if re.fullmatch(rb"[A-Za-z0-9+/]{16,}={0,2}", l.strip()):
            try: add(f"{rel}:{i+1}|b64dec", base64.b64decode(l.strip() + b"=" * (-len(l.strip()) % 4)))
            except Exception: pass
# blobs das fases como no README (linhas de 64) e blobs finais como strings inteiras
for name, b64 in (("PHASE2", G.PHASE2_B64), ("PHASE3", G.PHASE3_B64), ("PHASE32", G.PHASE32_B64),
                  ("SMALL", G.SMALL_B64), ("TAIL32", G.TAIL32_B64)):
    add(f"blob:{name}|b64", b64.encode()); add(f"blob:{name}|raw", base64.b64decode(b64))
    for j in range(0, len(b64), 64): add(f"blob:{name}|line{j//64}", b64[j:j+64].encode())
salt, ct = G.BLOBS["COSMIC"]; cos = b"Salted__" + salt + ct
add("blob:COSMIC|raw", cos); add("blob:COSMIC|b64", base64.b64encode(cos))
for nm, (s, c) in G.BLOBS.items():
    add(f"blob:{nm}|salt", s); add(f"blob:{nm}|salthex", s.hex().encode()); add(f"blob:{nm}|ct16", c[:16]); add(f"blob:{nm}|ct32", c[:32])

def pw_forms(m):
    yield "raw", m
    h = hashlib.sha256(m).digest()
    yield "sha256hex", h.hex().encode(); yield "SHA256HEX", h.hex().upper().encode(); yield "sha256raw", h

raw2 = base64.b64decode(G.PHASE2_B64); G.BLOBS["PHASE2"] = (raw2[8:16], raw2[16:])
hard, soft = G.try_password_all(G.shahex("causality").encode(), blobs=("PHASE2",))
assert hard and hard[0]["head"].startswith("The ironic"); del G.BLOBS["PHASE2"]

t0 = time.time(); n_tests = n_priv = 0; hard_hits = []; soft_hits = []; best = None
for m, label in materials.items():
    for fk, pw in pw_forms(m):
        n_tests += 1
        h, s = G.try_password_all(pw)
        for r in h: r.update(material=label, form=fk); hard_hits.append(r)
        for r in s:
            r.update(material=label, form=fk); soft_hits.append(r); G.jsonl(LOG, r)
            if best is None or r["printable"] > best["printable"]: best = r
    h = hashlib.sha256(m).digest(); n_priv += 2
    if priv(h): hard_hits.append({"privkey": h.hex(), "material": label, "form": "sha256"})
    if priv(hashlib.sha256(h).digest()): hard_hits.append({"privkey": h.hex(), "material": label, "form": "sha256d"})
    if len(m) == 32 and priv(m): hard_hits.append({"privkey": m.hex(), "material": label, "form": "raw32"})
res = {"n_files": len(files), "n_lines_read": n_lines, "n_materials_unique": len(materials),
       "n_password_forms": n_tests, "n_aes_decrypts": n_tests * 6, "n_privkey_checks": n_priv,
       "expected_padding_hits_null": round(n_tests * 6 / 256, 1), "soft_hits": len(soft_hits),
       "hard_hits": hard_hits, "best_soft": best, "secs": round(time.time() - t0, 1),
       "soft_printable_max": max((r["printable"] for r in soft_hits), default=0)}
json.dump(res, open(os.path.join(OUT, "summary_lines.json"), "w"), indent=1, ensure_ascii=False)
print(json.dumps(res, ensure_ascii=False, indent=1))
