# -*- coding: utf-8 -*-
"""
Familia ans_too_ct_text.
Hipotese: "sha256 ans too" + "our first hint is your last command" (=HASHTHETEXT) mandam hashear o que esta
VISIVEL, inclusive o proprio blob (texto base64 ou seus bytes decodificados), e encadear entre blobs; e a senha
e' o que um shell real entregaria (sufixo CR/LF, espaco, BOM, UTF-16-LE do PowerShell, sha256hex + newline).
So cobre o que hashthetext NAO cobriu: formas binarias dos blobs, CRLF/por-linha/espacado, H1+textarea,
sufixos de shell sobre tokens E sobre os proprios digests hex, BOM, UTF-16-LE.
"""
import sys, os, re, hashlib, base64, json, time, itertools
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
LOG = os.path.join(SP, "ans_too_ct_text.jsonl")
open(LOG, "w").close()
HYP = ("senha = forma de shell (raw/sha256hex/SHA256HEX/dsha/digest/-K) de: bytes decodificados dos blobs "
       "(CT raw/hex, salt||CT, Salted__||salt||CT), base64 com CRLF/por-linha/espacado, H1+textarea; e "
       "entradas de shell (sufixos \\r\\n, \\n, ' ', BOM, UTF-16-LE) sobre tokens, linhas e os 30 sha256hex "
       "mais naturais — cruzado contra SMALL/COSMIC/TAIL32, KDF SHA256 (MD5 de sobra) + priv_hit dos digests.")
G.jsonl(LOG, {"hypothesis": HYP})

PAGE = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\archive\endgame\endgame_20230601222752.html", encoding="utf-8").read()
TA1, TA2 = re.findall(r"<textarea[^>]*>(.*?)</textarea>", PAGE, re.S)
ta1_ns = TA1.replace(" ", "")
assert TA2.replace("\n", "") == "".join(TA2.split()) and len(TA2.split("\n")) == 28
COSMIC_B64 = TA2.replace("\n", "")
COS_LINES = TA2.split("\n")
SM1, SM2 = G.SMALL_B64[:64], G.SMALL_B64[64:]
TL1, TL2 = G.TAIL32_B64[:64], G.TAIL32_B64[64:]
i_small = ta1_ns.index("U2FsdGVk")
ENTER_ABBA = ta1_ns[i_small + 64: i_small + 64 + 40]
assert set(ENTER_ABBA) <= set("ab") and len(ENTER_ABBA) == 40
i_z1 = ta1_ns.index("z"); i_zl = ta1_ns.rindex("z")

# ------------------------------------------------------------------ Parte 1: textos/bytes dos blobs
T = {}   # label -> str|bytes
def add(lbl, s):
    if s and s not in T.values(): T[lbl] = s
for name, b64, l1, l2 in (("SMALL", G.SMALL_B64, SM1, SM2), ("TAIL32", G.TAIL32_B64, TL1, TL2)):
    salt, ct = G.BLOBS[name]
    full = base64.b64decode(b64)
    add(f"{name}:b64_crlf", l1 + "\r\n" + l2)
    add(f"{name}:b64_lf_tail", l1 + "\n" + l2 + "\n")
    add(f"{name}:b64_crlf_tail", l1 + "\r\n" + l2 + "\r\n")
    add(f"{name}:b64_spaced", " ".join(b64))
    add(f"{name}:ct_hex", ct.hex()); add(f"{name}:CT_HEX", ct.hex().upper())
    add(f"{name}:ct_raw", ct); add(f"{name}:salt_ct", salt + ct); add(f"{name}:full_raw", full)
    add(f"{name}:full_hex", full.hex()); add(f"{name}:FULL_HEX", full.hex().upper())
    add(f"{name}:salt_hex", salt.hex()); add(f"{name}:SALT_HEX", salt.hex().upper()); add(f"{name}:salt_raw", salt)
    add(f"{name}:salt_b64", base64.b64encode(salt).decode())
    add(f"{name}:ct_b64", base64.b64encode(ct).decode())
    add(f"{name}:saltct_b64", base64.b64encode(salt + ct).decode())
    add(f"{name}:l1_raw", base64.b64decode(l1)); add(f"{name}:l1_hex", base64.b64decode(l1).hex())
    add(f"{name}:l2_raw", base64.b64decode(l2 + "==")[:48] if len(l2) % 4 else base64.b64decode(l2))
add("SMALL:b64_abba_crlf", SM1 + "\r\n" + ENTER_ABBA + "\r\n" + SM2)
add("SMALL:b64_abba_lf", SM1 + "\n" + ENTER_ABBA + "\n" + SM2)
add("SMALL:b64_enter_crlf", SM1 + "\r\nenter\r\n" + SM2)
add("SMALL:b64_ENTER", SM1 + "ENTER" + SM2)
add("SMALL:b64_spaced_abba", " ".join(SM1 + ENTER_ABBA + SM2))
add("SMALL:b64_spaced_l1", " ".join(SM1)); add("SMALL:b64_spaced_l2", " ".join(SM2))
salt, ct = G.BLOBS["COSMIC"]; full = base64.b64decode(COSMIC_B64)
add("COSMIC:b64_crlf", "\r\n".join(COS_LINES)); add("COSMIC:b64_lf_tail", TA2 + "\n")
add("COSMIC:b64_crlf_tail", "\r\n".join(COS_LINES) + "\r\n")
add("COSMIC:b64_spaced_1line", " ".join(COSMIC_B64))
add("COSMIC:b64_spaced_lines", "\n".join(" ".join(l) for l in COS_LINES))
add("COSMIC:b64_spaced_flat", " ".join(" ".join(l) for l in COS_LINES))
for i, l in enumerate(COS_LINES): add(f"COSMIC:line{i:02d}", l)
add("COSMIC:line00_raw", base64.b64decode(COS_LINES[0])); add("COSMIC:line00_hex", base64.b64decode(COS_LINES[0]).hex())
add("COSMIC:ct_hex", ct.hex()); add("COSMIC:CT_HEX", ct.hex().upper())
add("COSMIC:ct_raw", ct); add("COSMIC:salt_ct", salt + ct); add("COSMIC:full_raw", full)
add("COSMIC:full_hex", full.hex()); add("COSMIC:FULL_HEX", full.hex().upper())
add("COSMIC:salt_hex", salt.hex()); add("COSMIC:SALT_HEX", salt.hex().upper()); add("COSMIC:salt_raw", salt)
add("COSMIC:salt_b64", base64.b64encode(salt).decode()); add("COSMIC:ct_b64", base64.b64encode(ct).decode())
add("COSMIC:saltct_b64", base64.b64encode(salt + ct).decode())
# concatenacoes binarias entre blobs (encadear)
cs = {n: G.BLOBS[n][1] for n in ("SMALL", "COSMIC", "TAIL32")}
for a, b in itertools.permutations(cs, 2): add(f"CT:{a}+{b}", cs[a] + cs[b])
add("CT:SMALL+COSMIC+TAIL32", cs["SMALL"] + cs["COSMIC"] + cs["TAIL32"])
add("CT:SMALL^TAIL32", bytes(x ^ y for x, y in zip(cs["SMALL"], cs["TAIL32"])))
add("SALT:SMALL+COSMIC", G.BLOBS["SMALL"][0] + G.BLOBS["COSMIC"][0])
add("SALT:SMALL+COSMIC+TAIL32", G.BLOBS["SMALL"][0] + G.BLOBS["COSMIC"][0] + G.BLOBS["TAIL32"][0])
add("SALT:SMALL^COSMIC", bytes(x ^ y for x, y in zip(G.BLOBS["SMALL"][0], G.BLOBS["COSMIC"][0])))
# textarea 1 / H1
add("TA1:h1_spaced", "SalPhaseIon" + TA1); add("TA1:h1_sp_spaced", " SalPhaseIon " + TA1)
add("TA1:h1_nl_spaced", "SalPhaseIon\n" + TA1); add("TA1:h1_ns", "SalPhaseIon" + ta1_ns)
add("TA1:h1_lower_ns", "salphaseion" + ta1_ns); add("TA1:h1_spacedchars", " ".join("SalPhaseIon") + " " + TA1)
add("TA2:h1", "Cosmic Duality" + TA2); add("TA2:h1_nl", "Cosmic Duality\n" + TA2); add("TA2:h1_ns", "CosmicDuality" + COSMIC_B64)
add("TA2:h1_nl_crlf", "Cosmic Duality\r\n" + "\r\n".join(COS_LINES))
add("PAGE:h1s_ta", "SalPhaseIon" + TA1 + "Cosmic Duality" + TA2)
add("PAGE:h1s_ta_ns", "SalPhaseIon" + ta1_ns + "CosmicDuality" + COSMIC_B64)
add("PAGE:visible_crlf", "GSMG Puzzle\r\nSalPhaseIon\r\n" + TA1 + "\r\nCosmic Duality\r\n" + "\r\n".join(COS_LINES))
add("PAGE:html_crlf", PAGE.replace("\n", "\r\n"))
add("TA1:upto_z_incl", ta1_ns[:i_z1 + 1]); add("TA1:lastz_to_end", ta1_ns[i_zl:])
add("TA1:lastz_to_end_spaced", " ".join(ta1_ns[i_zl:])); add("TA1:upto_z_incl_spaced", " ".join(ta1_ns[:i_z1 + 1]))
add("TA1:ai_upto_smallblob", "".join(c for c in ta1_ns[:i_small] if c in "abcdefghi"))
add("TA1:ai_o_z_upto_blob", "".join(c for c in ta1_ns[:i_small] if c in "abcdefghioz"))
print("parte1 strings:", len(T))

# ------------------------------------------------------------------ Parte 2: entradas de shell
TOK = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "sha256", "enter", "ans too", "anstoo",
       "our first hint is your last command", "ourfirsthintisyourlastcommand", "shabef", "shabefanstoo",
       "sha256anstoo", "sha256 ans too", "sha256 answer too", "yellowblueprimes", "yinyang", "HASHTHETEXT",
       "SalPhaseIon", "Cosmic Duality", "CosmicDuality", "SalPhaseIonCosmicDuality", "GSMG Puzzle",
       "matrixsumlistlastwordsbeforearchichoicethispassword", "lastwordsbeforearchichoicethispassword",
       "thispasswordenter", "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang"]
NAT = {"matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "our first hint is your last command",
       "ourfirsthintisyourlastcommand", "ans too", "anstoo", "sha256", "enter", "shabefanstoo", "SalPhaseIon",
       "Cosmic Duality", "SalPhaseIonCosmicDuality", "GSMG Puzzle", "yellowblueprimes", "yinyang", "HASHTHETEXT",
       "matrixsumlistlastwordsbeforearchichoicethispassword", "lastwordsbeforearchichoicethispassword",
       "thispasswordenter", G.DBBI, G.FAED, G.DBBI + G.FAED, TA1, ta1_ns, COSMIC_B64, TA2, G.SMALL_B64,
       G.TAIL32_B64, "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"}
HEXES = {G.shahex(s): s for s in NAT}
assert len(HEXES) == 30, len(HEXES)
SUF = ["", " \r\n", " \n", "\r\n", "\n", " ", "\r"]
BOM = b"\xef\xbb\xbf"
S2 = {}   # label -> (bytes senha, "tok"|"hex")
def add2(lbl, b, kind):
    if b not in S2.values(): S2[lbl] = (b, kind)
for kind, bases in (("tok", TOK), ("hex", list(HEXES) + [h.upper() for h in HEXES])):
    for s in bases:
        for suf in SUF:
            u = (s + suf).encode("utf-8")
            add2(f"{kind}:{s[:20]}:{suf!r}", u, kind)
            add2(f"{kind}:BOM:{s[:20]}:{suf!r}", BOM + u, kind)
            add2(f"{kind}:U16:{s[:20]}:{suf!r}", (s + suf).encode("utf-16-le"), kind)
            add2(f"{kind}:U16BOM:{s[:20]}:{suf!r}", (s + suf).encode("utf-16"), kind)
print("parte2 senhas:", len(S2))

# ------------------------------------------------------------------ motor
n_aes = n_priv = 0; HARD = []; SOFT = []; DIGESTS = set()
def as_bytes(s): return s if isinstance(s, bytes) else s.encode("utf-8")
def pw_forms(b):
    d = hashlib.sha256(b).digest(); h = d.hex()
    DIGESTS.add(d); DIGESTS.add(hashlib.sha256(d).digest()); DIGESTS.add(hashlib.sha256(h.encode()).digest())
    return {"raw": b, "sha": h.encode(), "SHA": h.upper().encode(),
            "dsha_hex": hashlib.sha256(h.encode()).hexdigest().encode(), "digest": d}, d
def test_pw(pw, lbl, form, blobs=("SMALL", "COSMIC", "TAIL32"), kdfs=("sha256", "md5")):
    global n_aes
    for blob in blobs:
        for kdf in kdfs:
            n_aes += 1
            for kname, p in G.aes_try(pw, blob, kdf=kdf):
                rec = {"label": lbl, "form": form, "blob": blob, "kdf": kdf, "len": len(p),
                       "printable": round(G.printable(p), 3), "head": p[:40].decode("latin-1")}
                if G.semantic(p):
                    rec["plaintext_hex"] = p.hex(); rec["pw_hex"] = pw.hex(); HARD.append(rec)
                    G.jsonl(LOG, {"HARD": rec}); print("HARD HIT", rec)
                else:
                    SOFT.append(rec); G.jsonl(LOG, {"soft": rec})
def test_rawkey(d, lbl, blobs=("SMALL", "COSMIC", "TAIL32")):
    global n_aes
    for blob in blobs:
        salt = G.BLOBS[blob][0]
        for ivn, iv in (("iv0", b"\x00" * 16), ("iv_saltsalt", salt + salt)):
            n_aes += 1
            p = G.aes_rawkey(d, blob, iv)
            if p is None: continue
            rec = {"label": lbl, "form": "K:" + ivn, "blob": blob, "kdf": "-K", "len": len(p),
                   "printable": round(G.printable(p), 3), "head": p[:40].decode("latin-1")}
            if G.semantic(p):
                rec["plaintext_hex"] = p.hex(); rec["key_hex"] = d.hex(); HARD.append(rec)
                G.jsonl(LOG, {"HARD": rec}); print("HARD HIT", rec)
            else:
                SOFT.append(rec); G.jsonl(LOG, {"soft": rec})

def run_part1(blobs=("SMALL", "COSMIC", "TAIL32")):
    for lbl, s in T.items():
        forms, d = pw_forms(as_bytes(s))
        for fn, pw in forms.items(): test_pw(pw, lbl, fn, blobs)
        test_rawkey(d, lbl, blobs); test_rawkey(hashlib.sha256(d).digest(), lbl + ":dsha", blobs)
def run_part2(blobs=("SMALL", "COSMIC", "TAIL32")):
    for lbl, (b, kind) in S2.items():
        forms, d = pw_forms(b)
        test_pw(b, lbl, "raw", blobs)
        test_pw(forms["sha"], lbl, "sha", blobs); test_pw(forms["SHA"], lbl, "SHA", blobs)
        if kind == "tok": test_pw(forms["dsha_hex"], lbl, "dsha_hex", blobs); test_pw(d, lbl, "digest", blobs)

# ------------------------------------------------------------------ controle positivo: blob sintetico, senha "abc\r\n"
def make_blob(pw, plaintext, salt=b"\x01\x23\x45\x67\x89\xab\xcd\xef"):
    k, iv = G.evp(pw, salt, SHA256)
    pad = 16 - len(plaintext) % 16
    return salt, AES.new(k, AES.MODE_CBC, iv).encrypt(plaintext + bytes([pad]) * pad)
G.BLOBS["CTRL"] = make_blob(b"abc\r\n", b"the private key is 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ ok")
S2_backup = dict(S2); S2.clear()
for suf in SUF: add2(f"ctrl:abc:{suf!r}", ("abc" + suf).encode(), "tok")
run_part2(blobs=("CTRL",))
assert HARD and HARD[0]["form"] == "raw" and HARD[0]["label"] == "ctrl:abc:'\\r\\n'", HARD
print("controle positivo OK:", HARD[0]["label"], HARD[0]["head"])
G.jsonl(LOG, {"control": "blob sintetico EVP-SHA256 com senha 'abc\\r\\n' reaberto pela maquinaria de sufixos", "hit": HARD[0]})
HARD.clear(); SOFT.clear(); n_aes = 0; DIGESTS.clear(); del G.BLOBS["CTRL"]
S2.clear(); S2.update(S2_backup)

# ------------------------------------------------------------------ rodada real
t0 = time.time()
run_part1(); print("parte1 feita: n_aes", n_aes, round(time.time() - t0, 1), "s")
run_part2(); print("parte2 feita: n_aes", n_aes, round(time.time() - t0, 1), "s")
# priv_hit de todos os digests (sha, dsha, sha(hex)) das duas partes
PRIV = []
for d in DIGESTS:
    n_priv += 1
    r = G.priv_hit(d)
    if r: PRIV.append({"key_hex": d.hex(), "res": r}); G.jsonl(LOG, {"PRIV_HIT": PRIV[-1]}); print("PRIV HIT", d.hex(), r)
n_tests = n_aes + n_priv
SOFT.sort(key=lambda r: -r["printable"])
summary = {"family": "ans_too_ct_text", "n_strings_p1": len(T), "n_pw_p2": len(S2), "n_aes": n_aes, "n_priv": n_priv,
           "n_tests": n_tests, "pad_valid": len(SOFT), "hard": len(HARD) + len(PRIV), "best_soft": SOFT[:5],
           "elapsed_s": round(time.time() - t0, 1)}
G.jsonl(LOG, {"summary": summary, "hard_hits": HARD, "priv_hits": PRIV})
print(json.dumps(summary, ensure_ascii=False, indent=1)[:3000])
