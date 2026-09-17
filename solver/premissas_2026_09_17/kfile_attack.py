# -*- coding: utf-8 -*-
"""
Familia: a senha NAO e texto digitado — e o que `openssl enc -kfile <arq>` / `-pass file:<arq>`
extrairia de um ARQUIVO do puzzle (1a linha), ou o digest dos BYTES do arquivo.
Semantica verificada com openssl 3.5.7 real (ctl/semantics.py):
  -kfile      : 1a linha ate '\n', tira '\r\n' final, corta no NUL, max 127 B
  -pass file: : 1a linha ate '\n', tira '\n' (Windows text-mode tambem tira '\r'), corta no NUL, max 1023 B
  '\r' sozinho NAO termina linha.
"""
import sys, os, re, hashlib, json, struct, time, base64
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from coincurve import PublicKey
REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "soft_hits.jsonl")
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
open(LOG, "w").close()

def priv(b32):
    try: return PublicKey.from_valid_secret(b32).format(False) == TGT
    except Exception: return False

# ---------------------------------------------------------------- arquivos
ROOTS = [os.path.join(REPO, "_work", "gsmg_live_2026-09"), os.path.join(REPO, "_work", "archive"),
         os.path.join(REPO, "_work", "decentraland")]
EXTRA = [os.path.join(REPO, "_work", "review_2026-09-11", "creator_endorsed_cosmic_cover.png")]
# ponytail: exclui so' os artefatos gerados por nos (headers HTTP, espectrogramas, mascaras, dumps)
DERIVED = re.compile(r"(^hdr_|^py_|^spec_|^wave\.png$|^logo_diffmask|^logos_side_by_side|^cdx_all|^reddit_|^PROVENANCE|^cover_provenance)")
files = []
for r in ROOTS:
    for dp, dn, fn in os.walk(r):
        for f in sorted(fn):
            if DERIVED.search(f): continue
            files.append(os.path.join(dp, f))
files += EXTRA
files = [f for f in files if os.path.getsize(f) > 0]

# ---------------------------------------------------------------- semantica de linha
def first_line_forms(data):
    """Todas as leituras de '1a linha' — a real do openssl e as hipoteticas."""
    forms = {}
    nl = data.find(b"\n"); line = data if nl < 0 else data[:nl]
    def cut_nul(b):
        z = b.find(b"\x00"); return b if z < 0 else b[:z]
    l_win = line[:-1] if line.endswith(b"\r") else line           # \r\n -> \n (text mode)
    forms["kfile"] = cut_nul(l_win)[:127]                         # openssl -kfile (verificado)
    forms["passfile_win"] = cut_nul(l_win)[:1023]                 # -pass file: no Windows (verificado)
    forms["passfile_linux"] = cut_nul(line)[:1023]                # -pass file: no Linux (mantem \r)
    cr = data.find(b"\r"); forms["to_cr"] = cut_nul(data if cr < 0 else data[:cr])[:1023]
    forms["line_keep_nul"] = l_win                                # hipotetico: sem truncar no NUL
    forms["line_keep_nul_cr"] = line
    forms["whole"] = data                                         # arquivo inteiro como senha
    return forms

def png_chunks(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n": return []
    out = []; i = 8
    while i + 8 <= len(data):
        ln, typ = struct.unpack(">I4s", data[i:i + 8]); body = data[i + 8:i + 8 + ln]
        out.append((typ.decode("latin-1"), body)); i += 12 + ln
        if typ == b"IEND": break
    return out

def id3_frames(data):
    if data[:3] != b"ID3": return []
    ver = data[3]; sz = 0
    for b in data[6:10]: sz = (sz << 7) | (b & 0x7f)
    i = 10; out = []
    while i < 10 + sz:
        if ver >= 3:
            fid = data[i:i + 4]
            if not fid.strip(b"\x00"): break
            fl = struct.unpack(">I", data[i + 4:i + 8])[0]
            if ver == 4:
                fl = ((fl >> 24 & 0x7f) << 21) | ((fl >> 16 & 0x7f) << 14) | ((fl >> 8 & 0x7f) << 7) | (fl & 0x7f)
            body = data[i + 10:i + 10 + fl]; i += 10 + fl
        else:
            fid = data[i:i + 3]
            if not fid.strip(b"\x00"): break
            fl = int.from_bytes(data[i + 3:i + 6], "big"); body = data[i + 6:i + 6 + fl]; i += 6 + fl
        out.append((fid.decode("latin-1"), body))
    return out

# ---------------------------------------------------------------- materiais
materials = {}   # bytes -> label (dedupe global por conteudo)
def add(label, b):
    if b is None or len(b) == 0: return
    materials.setdefault(b, label)
n_files = 0; chunk_count = 0
for f in files:
    data = open(f, "rb").read(); n_files += 1
    rel = os.path.relpath(f, REPO)
    for k, v in first_line_forms(data).items(): add(f"{rel}|{k}", v)
    for typ, body in png_chunks(data):
        chunk_count += 1
        for k, v in first_line_forms(body).items():
            if k in ("kfile", "passfile_linux", "line_keep_nul"): add(f"{rel}|png:{typ}|{k}", v)
        add(f"{rel}|png:{typ}|data", body); add(f"{rel}|png:{typ}|type+data", typ.encode() + body)
    for fid, body in id3_frames(data):
        chunk_count += 1
        for k, v in first_line_forms(body).items():
            if k in ("kfile", "passfile_linux", "line_keep_nul"): add(f"{rel}|id3:{fid}|{k}", v)
        add(f"{rel}|id3:{fid}|data", body)
        if body[:1] in (b"\x00", b"\x01", b"\x03"): add(f"{rel}|id3:{fid}|text", body[1:].rstrip(b"\x00"))
    for hname in ("sha256", "sha1", "md5"):
        d = hashlib.new(hname, data).digest()
        add(f"{rel}|{hname}_hex", d.hex().encode()); add(f"{rel}|{hname}_HEX", d.hex().upper().encode()); add(f"{rel}|{hname}_raw", d)
add("empty", b"")  # ttf/whole-NUL: openssl -pass file: daria senha vazia

# ---------------------------------------------------------------- formas de senha por material
def pw_forms(m):
    yield "raw", m
    h = hashlib.sha256(m).digest()
    yield "sha256hex", h.hex().encode(); yield "SHA256HEX", h.hex().upper().encode(); yield "sha256raw", h
    if len(m) <= 1023 and m and not m.endswith(b"\n"): yield "raw+nl", m + b"\n"

# controle positivo: fase 2 abre no pipeline
raw2 = base64.b64decode(G.PHASE2_B64); G.BLOBS["PHASE2"] = (raw2[8:16], raw2[16:])
hard, soft = G.try_password_all(G.shahex("causality").encode(), blobs=("PHASE2",))
assert hard and hard[0]["head"].startswith("The ironic"), hard
del G.BLOBS["PHASE2"]
# controle negativo: material lixo
assert not G.try_password_all(b"\x89PNGxx")[0]
# controle da semantica -kfile (mesmos casos de ctl/semantics.py, aqui como assert)
assert first_line_forms(b"abc\r\ndef")["kfile"] == b"abc" and first_line_forms(b"ab\x00c\ndef")["kfile"] == b"ab"
assert first_line_forms(b"X" * 200)["kfile"] == b"X" * 127 and first_line_forms(b"X" * 200)["passfile_win"] == b"X" * 200
assert first_line_forms(b"abc\rdef\n")["kfile"] == b"abc\rdef" and first_line_forms(b"\x89PNG\r\n\x1a\n")["kfile"] == b"\x89PNG"

# ---------------------------------------------------------------- ataque
t0 = time.time(); n_tests = 0; n_priv = 0; hard_hits = []; soft_hits = []; best = None
for m, label in materials.items():
    for fk, pw in pw_forms(m):
        n_tests += 1
        h, s = G.try_password_all(pw)
        for r in h: r.update(material=label, form=fk); hard_hits.append(r)
        for r in s:
            r.update(material=label, form=fk); soft_hits.append(r); G.jsonl(LOG, r)
            if best is None or r["printable"] > best["printable"]: best = r
    # privkey: sha256(m), sha256(sha256(m)), sha256(hex), m se 32 B
    h = hashlib.sha256(m).digest()
    cands = [("sha256", h), ("sha256d", hashlib.sha256(h).digest()), ("sha256(hex)", hashlib.sha256(h.hex().encode()).digest())]
    if len(m) == 32: cands.append(("raw32", m))
    for pk, b in cands:
        n_priv += 1
        if priv(b): hard_hits.append({"privkey": b.hex(), "material": label, "form": pk})
res = {"n_files": n_files, "n_chunks_frames": chunk_count, "n_materials_unique": len(materials),
       "n_password_forms": n_tests, "n_aes_decrypts": n_tests * 6, "n_privkey_checks": n_priv,
       "expected_padding_hits_null": round(n_tests * 6 / 256, 1), "soft_hits": len(soft_hits),
       "hard_hits": hard_hits, "best_soft": best, "secs": round(time.time() - t0, 1),
       "soft_printable_max": max((r["printable"] for r in soft_hits), default=0),
       "files": [os.path.relpath(f, REPO) for f in files]}
json.dump(res, open(os.path.join(OUT, "summary.json"), "w"), indent=1, ensure_ascii=False)
print(json.dumps({k: v for k, v in res.items() if k != "files"}, ensure_ascii=False, indent=1))
