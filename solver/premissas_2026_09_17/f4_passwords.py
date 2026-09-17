# -*- coding: utf-8 -*-
"""Testa como senha (crua, sha256hex, SHA256HEX, digest cru, sha256 dupla, raw+LF) nos 3 blobs
(SMALL/COSMIC/TAIL32, EVP md5+sha256):
(a) letras/palavras-desvio do Arquiteto e das outras fases; (b) material de BYTES crus (segmento EBCDIC
latin-1, glifos cp866/cp437, linhas dos plaintexts, ciphertexts, textareas HTML, comentarios HTML).
Tambem sha256(cand) como privkey (brainwallet) e cand de 32 B como privkey.
Controle positivo: fases 2 e 3.2 abrem no MESMO pipeline. Nulo: 20k senhas aleatorias -> taxa de padding."""
import sys, os, re, json, hashlib, base64, pickle, random, itertools, collections, time
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "f4_passwords.jsonl"); open(LOG, "w").close()
D = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\gsmg_live_2026-09"

# ---------- controle positivo: fase 2/3.2 abrem no pipeline try_password_all
def parse(b64):
    raw = base64.b64decode(b64); return raw[8:16], raw[16:]
G.BLOBS["FASE2"] = parse(G.PHASE2_B64); G.BLOBS["FASE32"] = parse(G.PHASE32_B64)
h, s = G.try_password_all(G.shahex("causality"), blobs=("FASE2",))
assert h and h[0]["kdf"].endswith("SHA256") and h[0]["head"].startswith("The ironic"), (h, s)
h, s = G.try_password_all("250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c", blobs=("FASE32",))
# ACHADO: o plaintext AUTENTICO da 3.2 tem printable=0.589 (segmento EBCDIC) -> G.semantic o classifica como SOFT!
assert (h + s)[0]["head"].startswith("I've been") and (h + s)[0]["printable"] < 0.85, (h, s)
print("[achado] plaintext real da fase 3.2: printable =", (h + s)[0]["printable"], "-> semantic() o descartaria como ruido")
h, s = G.try_password_all("xyz_wrong_control", blobs=("FASE2", "SMALL"))
assert not h
print("[controle] fase2/fase3.2 abrem no pipeline; senha lixo nao abre")

# ---------- material
P2 = open(os.path.join(OUT, "fase2_plain.bin"), "rb").read()
P3 = open(os.path.join(OUT, "fase3_plain.bin"), "rb").read()
P32 = open(os.path.join(OUT, "fase32_plain.bin"), "rb").read()
L32 = P32.split(b"\r\n"); SEG = L32[4]; assert len(SEG) == 1539
J = json.load(open(os.path.join(OUT, "f2_segment.json")))
PT, LETTERS = J["pt"], J["letters"]
readme = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
i3 = readme.index("YOUR LIFE IS THE SUM"); RT = readme[i3:readme.index("```", i3)].strip()
CB = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE"
CB_SP = "IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE"

C = collections.OrderedDict()   # label -> bytes
def add(label, v):
    if isinstance(v, str): v = v.encode("utf-8")
    if v and label not in C: C[label] = v

# (a) desvios do Arquiteto (palavras) — grafias erradas, corretas, e inseridas
DEV_WORDS = ["FOURTY", "FORTY", "WAISTING", "WASTING", "THROPHIES", "TROPHIES", "PRICES", "PRIZES", "ENTIRENESS",
             "ENTIRETY", "ENTIRE", "YOURSELFSELF", "SELF", "CIAOBELLAO", "CIAOBELLA", "BELLAO", "THEYOU", "YOUYOU",
             "ME", "KEYNOTE", "NOTE", "SOURCECODES", "CODES", "PRIMEBASICS", "BASICS", "HOPEFULLY", "NEVERTHELESS",
             "GOODLUCK", "WISEMAN", "RESTLESSSOUL", "THINGKY", "THINKY", "FUBCD", "MVPS", "SADBOARD", "WILLPOWER",
             "HUNDREDFOURTY", "140", "ONEHUNDREDFORTY", "THEREFOR", "THEREFORE", "KNOW", "KNOWN", "LETPUT", "LETSPUT",
             "WORSTGEAR", "IRRELEVANT", "THEMOST", "PUZZLE", "THISPUZZLE", "LAST", "NOT", "WELL", "I", "ARESTLESSSOUL",
             "OVERTWENTYTHREECIPHERS", "SIXTEENENCRYPTIONS", "SEVENINTERTWINEDPASSWORDS", "PRIVATEKEYNOTE",
             "ACTUALPRIVATEKEYNOTE", "BRUTEFORCING", "YOURWILLTOLIVE", "IREALLYHOPEYOURETHEONE", "HOPEYOURETHEONE",
             "YOURETHEONE", "CIAO", "BELLA", "O", "SELFSELF", "YOURSELF"]
for w in DEV_WORDS:
    for f in (w, w.lower(), w.capitalize()): add(f"dev:{f}", f)
for combo in (["FOURTY", "WAISTING", "PRICES", "THROPHIES"], ["FOURTY", "WAISTING", "PRICES", "THROPHIES", "ENTIRENESS"],
              ["FOURTY", "WAISTING", "PRICES", "THROPHIES", "ENTIRENESS", "SELF", "O"],
              ["WAISTING", "PRICES", "THROPHIES"], ["FOURTY", "WAISTING", "THROPHIES", "THINGKY"],
              ["FOURTY", "WAISTING", "PRICES", "THROPHIES", "THINGKY"], ["YOU", "ME", "SELF", "O"],
              ["YOU", "ME", "CODES", "HOPEFULLY", "BASICS", "SELF", "O"]):
    s = "".join(combo); add(f"devseq:{s}", s); add(f"devseq:{s.lower()}", s.lower()); add(f"devseq:{'_'.join(combo)}", " ".join(combo))
LET = ["UICH", "UICHG", "UIHG", "UICHGENS", "ENSUICHG", "HCIU", "GHCIU", "UIZCH", "UICHO", "UICHSO", "UICHGO"]
for l in LET:
    add(f"letras:{l}", l); add(f"letras:{l.lower()}", l.lower())
for perm in itertools.permutations("UICH"):
    s = "".join(perm); add(f"perm:{s}", s); add(f"perm:{s.lower()}", s.lower())
for perm in itertools.permutations("UICHG"):
    s = "".join(perm); add(f"perm5:{s}", s); add(f"perm5:{s.lower()}", s.lower())
words = re.sub(r"[^A-Z0-9' ]", " ", RT.upper()).split()
pos = {w: [i for i, x in enumerate(words) if x == w] for w in ("FOURTY", "WAISTING", "PRICES", "THROPHIES", "ENTIRENESS", "SELF", "O", "ME")}
add("devpos:idx", "".join(str(pos[w][0]) for w in ("FOURTY", "WAISTING", "PRICES", "THROPHIES")))
add("devpos:idx1", "".join(str(pos[w][0] + 1) for w in ("FOURTY", "WAISTING", "PRICES", "THROPHIES")))
print("posicoes (0-based) das palavras-desvio:", pos)

# (b) bytes crus
add("seg:raw_latin1_bytes", SEG)
add("seg:cp866_glyphs_utf8", SEG.decode("cp866"))
add("seg:cp437_glyphs_utf8", SEG.decode("cp437"))
add("seg:letters", LETTERS); add("seg:LETTERS", LETTERS.upper())
add("seg:beaufort_pt", PT); add("seg:beaufort_pt_lower", PT.lower())
add("seg:readme_formatted", RT); add("seg:readme_formatted_crlf", RT.replace("\n", "\r\n"))
add("seg:readme_oneline", " ".join(RT.split()))
for i, l in enumerate(L32):
    if l: add(f"p32:line{i}", l); add(f"p32:line{i}_crlf", l + b"\r\n")
add("p32:whole", P32); add("p32:before_tail32", P32[:2292]); add("p32:text_before_seg", P32[:447])
add("p32:seg+digits", SEG + b"\r\n\r\n" + L32[6]); add("p32:digits+raising", L32[6] + b"\r\n\r\n" + L32[8])
add("p32:tail32_b64_2lines", L32[10] + b"\r\n" + L32[11]); add("p32:tail32_b64_joined", L32[10] + L32[11])
add("p32:tail32_raw", base64.b64decode(L32[10] + L32[11]))
add("p2:whole", P2); add("p3:whole", P3)
for i, l in enumerate(P2.split(b"\r\n")): add(f"p2:line{i}", l)
for i, l in enumerate(P3.split(b"\r\n")[:7]):
    if l: add(f"p3:line{i}", l)
add("p3:blob32_b64", b"".join(P3.split(b"\r\n")[8:])); add("p3:blob32_raw", base64.b64decode(b"".join(P3.split(b"\r\n")[8:])))
add("cb:plain", CB); add("cb:plain_sp", CB_SP); add("cb:plain_lower", CB.lower())
for nm, b64 in (("SMALL", G.SMALL_B64), ("TAIL32", G.TAIL32_B64), ("PHASE2", G.PHASE2_B64), ("PHASE3", G.PHASE3_B64), ("PHASE32", G.PHASE32_B64)):
    raw = base64.b64decode(b64)
    add(f"ct:{nm}_b64", b64); add(f"ct:{nm}_raw", raw); add(f"ct:{nm}_ctonly", raw[16:])
    add(f"ct:{nm}_salt", raw[8:16]); add(f"ct:{nm}_salthex", raw[8:16].hex())
cs, cc = G.BLOBS["COSMIC"]; add("ct:COSMIC_raw", b"Salted__" + cs + cc); add("ct:COSMIC_salthex", cs.hex()); add("ct:COSMIC_b64", base64.b64encode(b"Salted__" + cs + cc))
# HTML
for nm, fn in (("endgame", "body_89727c598b9cd1cf8873f27cb7057f050645ddb6"), ("fase2", "body_choiceisanillusioncreatedbetweenthosewit"), ("theseed", "body_theseedisplanted")):
    b = open(os.path.join(D, fn), "rb").read(); add(f"html:{nm}_whole", b)
    for j, ta in enumerate(re.findall(rb"<textarea[^>]*>(.*?)</textarea>", b, re.S)):
        add(f"html:{nm}_textarea{j}", ta); add(f"html:{nm}_textarea{j}_strip", ta.strip())
    for cm in re.findall(rb"<!--\s*(.*?)\s*-->", b, re.S): add(f"html:{nm}_comment", cm)
STRS = ["Good luck little bunny hunter ;)", "Good luck little bunny hunter", "little bunny hunter", "bunny hunter", "bunnyhunter",
        "littlebunnyhunter", "Nice to see you around!", "You made it to the next step!", "Hello :-)", "Hello", "no-js", "GSMG Puzzle",
        "SalPhaseIon", "Cosmic Duality", "SalPhaseIonCosmicDuality", "salphaseion", "cosmicduality", "89727c598b9cd1cf8873f27cb7057f050645ddb6",
        "choiceisanillusioncreatedbetweenthosewithpowerandthosewithout", "theseedisplanted", "phase1verification", "A\u2013B", "AB",
        "openssl enc -aes-256-cbc -d -a -in phase3.2.txt -pass pass:250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
        "openssl enc -aes-256-cbc -d -a", "openssl", "enc", "-pass pass:", "dgst", "sha256sum", "echo -n", "sha256",
        "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c", "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
        G.shahex("causality"), "causality"]
for s in STRS: add(f"str:{s[:40]}", s)
for nm, b in (("p2", P2), ("p3", P3), ("p32", P32), ("seg", SEG), ("pt", PT.encode()), ("letters", LETTERS.encode())):
    add(f"sha:{nm}_hex", hashlib.sha256(b).hexdigest())

print("candidatos-base:", len(C))
corpus = None
cp = os.path.join(OUT, "corpus.pkl")
if os.path.exists(cp):
    corpus = set(pickle.load(open(cp, "rb"))["pws"]); print("corpus historico:", len(corpus))

def forms(v):
    return [("raw", v), ("sha256hex", hashlib.sha256(v).hexdigest().encode()), ("SHA256HEX", hashlib.sha256(v).hexdigest().upper().encode()),
            ("sha256raw", hashlib.sha256(v).digest()), ("sha256x2hex", hashlib.sha256(hashlib.sha256(v).digest()).hexdigest().encode()),
            ("raw_lf", v + b"\n")]
BLOBS = ("SMALL", "COSMIC", "TAIL32")
n_tests = 0; hard = []; soft = []; new_base = 0; priv_hits = []; overlap = []
t0 = time.time()
for label, v in C.items():
    is_new = corpus is None or v not in corpus
    new_base += is_new
    if not is_new: overlap.append(label)
    for fname, pw in forms(v):
        for k in (hashlib.sha256(v).digest(), v if len(v) == 32 else None):
            if k and G.priv_hit(k): priv_hits.append({"label": label, "form": fname, "priv": k.hex()})
        h, s = G.try_password_all(pw, blobs=BLOBS, kdf="both")
        n_tests += len(BLOBS) * 2
        for r in h: r.update(label=label, form=fname); hard.append(r); G.jsonl(LOG, {"HARD": r})
        for r in s: r.update(label=label, form=fname); soft.append(r); G.jsonl(LOG, {"soft": r})
print(f"testes AES: {n_tests}  (bases {len(C)}, novas vs corpus: {new_base})  t={time.time()-t0:.0f}s")
print("bases ja no corpus:", overlap)
print("HARD:", hard); print("priv_hits:", priv_hits)
print("soft (padding valido):", len(soft), "esperado ~", round(n_tests / 256, 1))
for r in soft: print("  ", r["label"], r["form"], r["blob"], r["kdf"], "printable", r["printable"], r["hex"][:32])
rng = random.Random(1); nn = 0; ns = 0
for _ in range(20000):
    pw = bytes(rng.getrandbits(8) for _ in range(12)); h, s = G.try_password_all(pw, blobs=BLOBS, kdf="both"); nn += 6; ns += len(s) + len(h)
    assert not h
print(f"nulo: {nn} testes aleatorios -> {ns} paddings validos ({ns/nn*256:.2f} x 1/256)")
json.dump({"n_tests": n_tests, "bases": len(C), "new_bases": new_base, "overlap": overlap, "hard": hard, "priv_hits": priv_hits,
           "soft": soft, "null": {"n": nn, "pad_ok": ns}}, open(os.path.join(OUT, "f4_passwords.json"), "w"), indent=1)
