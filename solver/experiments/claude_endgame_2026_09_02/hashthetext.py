# -*- coding: utf-8 -*-
"""
Familia HASHTHETEXT — "our first hint is your last command".
Hipotese: a senha do SMALL/COSMIC/TAIL32 e' sha256 de um TEXTO VISIVEL das paginas
(definicao picky do autor: so [A-Za-z0-9], caixa preservada — como GSMGIO5BTCPUZZLECHALLENGE+addr).
Enumera textos do endgame e das fases 1-3.2, varias normalizacoes e ordens de leitura,
e testa cada um como: senha crua, sha256hex, SHA256HEX, double-sha (2 formas), digest cru
(EVP MD5+SHA256) nos 3 blobs; e sha256 como chave -K crua com 4 IVs; e como privkey.
"""
import sys, os, re, hashlib, itertools, base64, json, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
LOG = os.path.join(SP, "hashthetext.jsonl")
open(LOG, "w").close()
G.jsonl(LOG, {"hypothesis": "senha = sha256(texto visivel picky) das paginas (endgame + fases 1-3.2), "
              "ordens de leitura e separadores; formas raw/sha/SHA/double/digest + -K cru; blobs SMALL/COSMIC/TAIL32"})
README = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
PAGE = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\archive\endgame\endgame_20230601222752.html", encoding="utf-8").read()

# ------------------------------------------------------------------ textos-fonte
ta = re.findall(r"<textarea[^>]*>(.*?)</textarea>", PAGE, re.S)
TA1, TA2 = ta[0], ta[1]
assert TA1.startswith("d b b i") and TA2.startswith("U2FsdGVk") and "\n" in TA2
ta1_ns = TA1.replace(" ", "")
i_z1 = ta1_ns.index("z"); zsegs = ta1_ns[i_z1 + 1:].split("z", 2)
assert len(zsegs) == 3
seg1, seg2, seg3 = zsegs                     # seg3 = shabef...U2Fs...(enter)...jJshabefanstoo
i_blob = seg3.index("U2FsdGVk")
line_before = seg3[:i_blob]                  # shabefourfirsthintisyourlastcommand
blob_and_after = seg3[i_blob:]
i_ans = blob_and_after.index("shabefanstoo")
blob_raw = blob_and_after[:i_ans]            # U2F...rd9z[abba]QvX0...jJ
b64_1 = blob_raw[:blob_raw.index("z") + 1]   # inclui o 'z' final (necessario p/ base64 fechar)
rest = blob_raw[len(b64_1):]
abba2 = rest[:40]; b64_2 = rest[40:]
assert abba2 == "abbaabababbabbbaabbbabaaabbaababbbaaba" [:40] or set(abba2) <= set("ab")
assert base64.b64decode(b64_1 + b64_2)[:8] == b"Salted__"
DBBI, FAED = G.DBBI, G.FAED
abba1 = ta1_ns[91:195]
assert set(abba1) <= set("ab") and len(abba1) == 104
upto_z = ta1_ns[:i_z1]

PHASE2_TEXT = ('"1... are you looking for the private keymaker?" You come to me, without it. Come to me with it and '
               "you'll have the power to continue. It'll grant the first part. /(aaa, connected enf)")
def block(after, n=1):
    i = README.index(after); m = re.search(r"```text?\n(.*?)```", README[i:], re.S); return m.group(1)
PHASE3_RIDDLE = README[README.index("There's a guy who theorised the idea that 'Any linear"):README.index("--> parts 1..7")]
PHASE3_RIDDLE = PHASE3_RIDDLE[:PHASE3_RIDDLE.rindex("/(aBa, connected not enf)") + len("/(aBa, connected not enf)")]
PHASE2_DECR = README[README.index("The ironic 2name"):README.index("Ok kid, on the highway, let put it in the worst gear.") + len("Ok kid, on the highway, let put it in the worst gear.")]
PHASE3_DECR = README[README.index("What if the merovingian is wrong"):README.index("Phase 3.2 is ciphered with aes-256-cbc base64 and a sha256 pw, yet again.") + len("Phase 3.2 is ciphered with aes-256-cbc base64 and a sha256 pw, yet again.")]
P32_INTRO = README[README.index("I've been waiting for you. You have many questions"):README.index("╬╚,╬°%")].strip()
P32_CIPH = README[README.index("╬╚,╬°%"):].split("\n")[0]
P322_DIGITS = "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"
RAISING = "Raising the stakes without extra chances of winning. A fubcd-king & oracle-queen, thingky mvps, on a sad board but as wide as the first one seen."
ARCH = README[README.index("YOUR LIFE IS THE SUM OF A REMAINDER"):README.index("HOPE YOURE THE ONE CIAO BELLA O") + len("HOPE YOURE THE ONE CIAO BELLA O")]
VIC = "IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE"
ROSES = ("Roses are White but often Red.\nYellow has a number and so does Blue.\nGo back to the first puzzle piece without further ado.\n\n"
         "It might have shown you only one door, beware that the rabbits nest may contain a whole lot more.\n\nHush hush.")
ADDR = G.PRIZE_ADDR
H89 = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
assert G.shahex("GSMGIO5BTCPUZZLECHALLENGE" + ADDR) == H89
LONGURL = "choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself"
MAT_ROWS = "".join("".join(map(str, r)) for r in G.MATRIX_IMG)
MAT_ROWS_R = "".join("".join(map(str, r)) for r in G.MATRIX_README)
MAT_SPIRAL = "".join(str(G.MATRIX_IMG[r][c]) for r, c in G.SPIRAL)
MAT_SPACED = "\n".join(" ".join(map(str, r)) for r in G.MATRIX_README)
PW7 = ("causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"
       "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1")
PW32 = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
PW2 = "theflowerblossomsthroughwhatseemstobeaconcretesurface"

T = {}   # label -> texto
def add(lbl, s):
    if s: T.setdefault(lbl, s)
# --- endgame
add("title", "GSMG Puzzle"); add("h1a", "SalPhaseIon"); add("h1b", "Cosmic Duality")
add("h1ab", "SalPhaseIon Cosmic Duality"); add("title_h1ab", "GSMG Puzzle SalPhaseIon Cosmic Duality")
add("ta1", TA1); add("ta2", TA2); add("ta2_nonl", TA2.replace("\n", ""))
add("page_visible", "GSMG Puzzle\nSalPhaseIon\n" + TA1 + "\nCosmic Duality\n" + TA2)
add("page_visible_noTitle", "SalPhaseIon\n" + TA1 + "\nCosmic Duality\n" + TA2)
add("ta1_ta2", TA1 + "\n" + TA2); add("ta1_ta2_ns", ta1_ns + TA2.replace("\n", ""))
add("ta1_ai_only", "".join(c for c in ta1_ns if c in "abcdefghi"))
add("ta1_ai_o_only", "".join(c for c in ta1_ns if c in "abcdefghio"))
add("dbbi", DBBI); add("faed", FAED); add("dbbi_faed", DBBI + FAED); add("faed_dbbi", FAED + DBBI)
add("upto_z", upto_z); add("upto_z_spaced", " ".join(upto_z))
add("seg1", seg1); add("seg2", seg2); add("seg3", seg3); add("seg1seg2", seg1 + seg2)
add("zseg1", "z" + seg1); add("zseg2", "z" + seg2); add("zsegs_all", ta1_ns[i_z1:])
add("abba1", abba1); add("abba2", abba2); add("abba12", abba1 + abba2)
add("line_before", line_before); add("line_before_sp", "s h a b e f o u r f i r s t h i n t i s y o u r l a s t c o m m a n d")
add("blob_raw", blob_raw); add("b64_1", b64_1); add("b64_2", b64_2); add("b64_1_nz", b64_1[:-1]); add("small_b64", b64_1 + b64_2)
add("small_b64_nl", b64_1 + "\n" + b64_2); add("small_b64_enter", b64_1 + "enter" + b64_2)
add("ta1_noblob", TA1.replace(" ".join(blob_raw), "").replace("  ", " "))
add("ta1_upto_blob", TA1[:TA1.index("U 2 F")])
add("ta1_after_blob", "s h a b e f a n s t o o"); add("shabefanstoo", "shabefanstoo"); add("anstoo", "ans too")
add("sha256anstoo", "sha256 ans too"); add("sha256answertoo", "sha256 answer too"); add("answertoo", "answer too")
add("ofh", "our first hint is your last command"); add("sha256ofh", "sha256 our first hint is your last command")
add("shabefofh", "shabef our first hint is your last command"); add("ofh_upper", "OUR FIRST HINT IS YOUR LAST COMMAND")
add("firsthint", "our first hint"); add("lastcommand", "your last command"); add("hashthetext", "HASHTHETEXT")
add("hashthetext_l", "hashthetext"); add("hash the text", "hash the text"); add("HASH THE TEXT", "HASH THE TEXT")
add("h89", H89); add("H89", H89.upper()); add("h89x2", H89 + H89); add("url89", "https://gsmg.io/" + H89)
add("url89_ns", "gsmg.io/" + H89); add("h89_sha", G.shahex(H89)); add("gsmgio_5btc_pw", "GSMGIO5BTCPUZZLECHALLENGE" + ADDR)
add("gsmgio_5btc", "GSMG.IO 5 BTC PUZZLE CHALLENGE"); add("gsmgio_5btc_addr", "GSMG.IO 5 BTC PUZZLE CHALLENGE " + ADDR)
add("addr", ADDR); add("GSMG", "GSMG"); add("gsmg.io", "gsmg.io"); add("GSMG Puzzle piece", "GSMG.io Puzzle piece")
add("decentraland", "GSMG.io Puzzle piece — coords -41,-17\nGSMG.IO 5 BTC PUZZLE CHALLENGE\nDecentraland: Type /help for info about controls\nPress enter and start talking…")
add("coords", "-41,-17"); add("globally", "Globally supporting my generation"); add("roses", ROSES)
add("salvation", "Salvation"); add("salphaseion_l", "salphaseion"); add("cosmicduality_l", "cosmic duality")
add("yinyang", "yinyang"); add("yin yang", "yin yang"); add("ying yang", "ying yang"); add("purple pill", "purple pill")
add("matrix_rows", MAT_ROWS); add("matrix_rows_readme", MAT_ROWS_R); add("matrix_spiral", MAT_SPIRAL); add("matrix_spaced", MAT_SPACED)
add("matrix_rows_nl", "\n".join("".join(map(str, r)) for r in G.MATRIX_IMG))
add("url_seed", "gsmg.io/theseedisplanted"); add("url_seed_https", "https://gsmg.io/theseedisplanted"); add("theseedisplanted", "theseedisplanted")
add("the seed is planted", "the seed is planted"); add("url_puzzle", "https://gsmg.io/puzzle"); add("gsmg.io/puzzle", "gsmg.io/puzzle")
add("longurl", LONGURL); add("longurl_https", "https://gsmg.io/" + LONGURL); add("phase1verification", "phase1verification")
add("url_p1v", "https://gsmg.io/phase1verification"); add("pw2", PW2); add("thewarning", "The Warning"); add("logic", "Logic")
add("warning logic", "the warning logic"); add("phase2_text", PHASE2_TEXT); add("phase2_hdr", "PHASE 2"); add("phase3_hdr", "PHASE 3")
add("phase2_page", "PHASE 2\n\n" + PHASE2_TEXT + "\n\nCiphered with aes-256-cbc /w base64 sha-256(password)")
add("causality", "causality"); add("phase2_decr", PHASE2_DECR); add("phase3_riddle", PHASE3_RIDDLE); add("phase3_decr", PHASE3_DECR)
add("pw7", PW7); add("pw32", PW32); add("p32_intro", P32_INTRO); add("p32_ciph", P32_CIPH); add("p322_digits", P322_DIGITS)
add("raising", RAISING); add("arch", ARCH); add("arch_1line", " ".join(ARCH.split())); add("vic", VIC); add("vic_ns", VIC.replace(" ", ""))
add("themaxtrixhasyou", "THEMATRIXHASYOU"); add("beaufort", "beaufort"); add("fubcd", "FUBCDORA.LETHINGKYMVPS.JQZXW")
add("p32_full", P32_INTRO + "\n\n" + P32_CIPH + "\n\n" + P322_DIGITS + "\n\n" + RAISING)
add("tail32_b64", G.TAIL32_B64); add("half", "half and better half"); add("halfbetterhalf", "HALF AND BETTER HALF")
add("architect_hint", "the door to your right leads to the source and the salvation of Zion")
add("cosmic_book", "Cosmic Duality Book Page — Life and Death"); add("miroir", "Le Miroir de la Vie et de la Mort")
add("eps35", "eps3.5_kill-process.inc"); add("eps34", "eps3.4_runtime-error.r00"); add("matrixsumlist_v", "matrixsumlist")
add("neo_date", "11 SEP 2001"); add("11092001", "11092001"); add("09112001", "09112001"); add("20010911", "20010911")
add("yellowblueprimes", "yellowblueprimes"); add("roadmap", "yellowblueprimes matrixsumlist lastwordsbeforearchichoice yinyang")
add("roadmap_arrow", "yellowblueprimes -> matrixsumlist -> lastwordsbeforearchichoice -> yinyang")
add("infront", "it's in front of your eyes but you're not seeing it"); add("bingo", "Bingo")
add("readme_salph", README[README.index("> d b b i"):README.index("> s h a b e f a n s t o o") + len("> s h a b e f a n s t o o")].replace("> ", "").replace("*", ""))
add("html_page", PAGE)

# --- tokens decodificados em ordens de leitura / permutacoes
TOK = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "sha256", "our first hint is your last command", "enter", "ans too"]
SEPS = ["", " ", "\n"]
combos = set()
for k in range(1, 4):
    for p in itertools.permutations(TOK, k): combos.add(p)
for p in itertools.permutations(TOK[:3] + ["enter"]): combos.add(p)
combos.add(tuple(TOK)); combos.add(tuple(TOK[:5])); combos.add(("matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "sha256", "our first hint is your last command", "enter", "sha256", "ans too"))
combos.add(("yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang"))
combos.add(("matrixsumlist", "enter", "lastwordsbeforearchichoice", "enter", "thispassword", "enter"))
combos.add(("thispassword", "enter")); combos.add(("lastwordsbeforearchichoice", "thispassword", "enter"))
for p in sorted(combos):
    for sep in SEPS:
        s = sep.join(p)
        add("tok:" + sep.encode("unicode_escape").decode() + ":" + "|".join(x.replace(" ", "_") for x in p), s)
        add("tok_nl:" + sep.encode("unicode_escape").decode() + ":" + "|".join(x.replace(" ", "_") for x in p), s + "\n")

# ------------------------------------------------------------------ normalizacoes
def picky(s): return re.sub(r"[^A-Za-z0-9]", "", s)
def nows(s): return re.sub(r"\s+", "", s)
def variants(s):
    v = {s, picky(s), picky(s).upper(), picky(s).lower(), nows(s), s.upper(), s.lower(), s.strip(), s.rstrip("\n") + "\n"}
    return [x for x in v if x]
CANDS = {}   # string -> label
for lbl, s in T.items():
    for v in variants(s): CANDS.setdefault(v, lbl)
print("textos-fonte:", len(T), " strings unicas:", len(CANDS))

# ------------------------------------------------------------------ motor de teste
PADHITS = []; HARD = []; n_aes = 0; n_priv = 0
def pw_forms(s):
    b = s.encode("utf-8")
    d = hashlib.sha256(b).digest(); h = d.hex()
    return {"raw": b, "sha": h.encode(), "SHA": h.upper().encode(), "dsha_hex": hashlib.sha256(h.encode()).hexdigest().encode(),
            "dsha_raw": hashlib.sha256(d).hexdigest().encode(), "digest": d}
def keys_for(s):
    d = hashlib.sha256(s.encode()).digest()
    return {"k_sha": d, "k_dsha": hashlib.sha256(d).digest()}
def ivs_for(blob):
    salt = G.BLOBS[blob][0]
    return {"iv0": b"\x00" * 16, "iv_salt00": salt + b"\x00" * 8, "iv_saltsalt": salt + salt,
            "iv_md5salt": hashlib.md5(salt).digest(), "iv_sha_salt": hashlib.sha256(salt).digest()[:16]}
def check_plain(p, how, s, lbl):
    pr = G.printable(p)
    rec = {"how": how, "label": lbl, "text": s[:80], "printable": round(pr, 3), "head": p[:48].decode("latin-1")}
    if G.semantic(p):
        rec["plaintext_hex"] = p.hex(); HARD.append(rec); G.jsonl(LOG, {"HARD": rec}); print("HARD HIT", rec)
    else:
        PADHITS.append(rec)
        if pr >= 0.6: G.jsonl(LOG, {"soft": rec})
    # privkey dentro do plaintext
    for h in G.scan_priv(p, how): HARD.append({"how": how, "priv": h}); print("PRIV IN PLAIN", h)
BLOBS = ("SMALL", "COSMIC", "TAIL32")
t0 = time.time()
for s, lbl in CANDS.items():
    for fname, pw in pw_forms(s).items():
        for blob in BLOBS:
            for kdf, p in G.aes_try(pw, blob): check_plain(p, f"pass:{fname}/{kdf}/{blob}", s, lbl)
            n_aes += 2
    for kname, key in keys_for(s).items():
        for blob in BLOBS:
            for ivn, iv in ivs_for(blob).items():
                p = G.aes_rawkey(key, blob, iv); n_aes += 1
                if p is not None: check_plain(p, f"K:{kname}/{ivn}/{blob}", s, lbl)
        r = G.priv_hit(key); n_priv += 1
        if r: HARD.append({"how": f"priv:{kname}", "label": lbl, "text": s, "hit": r}); print("PRIV HIT", lbl, r)
print(f"tempo {time.time()-t0:.1f}s  strings={len(CANDS)} aes={n_aes} priv={n_priv} pad_valid={len(PADHITS)} hard={len(HARD)}")

# ------------------------------------------------------------------ controle positivo: fase 2 abre com sha256('causality')
m = re.search(r"Ciphered with aes-256-cbc /w base64 sha-256\(password\)\n```\n\n```text\n(.*?)```", README, re.S)
p2 = base64.b64decode(m.group(1).replace("\n", "")); assert p2[:8] == b"Salted__"
G.BLOBS["PHASE2"] = (p2[8:16], p2[16:])
ctrl = G.aes_try(G.shahex("causality").encode(), "PHASE2")
assert ctrl and any(G.semantic(p) and b"keymaker" in p for _, p in ctrl), "controle positivo falhou"
ctrl_kdf = [k for k, p in ctrl if G.semantic(p)]
# controle -K: a mesma chave/iv EVP-MD5 da fase 2 via aes_rawkey deve abrir
k, iv = G.evp(G.shahex("causality").encode(), p2[8:16], G.SHA256 if "SHA256" in ctrl_kdf[0] else G.MD5)
assert G.semantic(G.aes_rawkey(k, "PHASE2", iv)), "controle -K falhou"
print("controle positivo OK (fase 2 abre; kdf:", ctrl_kdf, ")")

best = max(PADHITS, key=lambda r: r["printable"]) if PADHITS else None
summary = {"family": "hashthetext", "n_strings": len(CANDS), "n_aes": n_aes, "n_priv": n_priv, "n_tests": n_aes + n_priv,
           "pad_valid": len(PADHITS), "hard": len(HARD), "best_soft": best, "control_kdf": ctrl_kdf}
G.jsonl(LOG, {"summary": summary, "hard_hits": HARD, "pad_hits": PADHITS})
print(json.dumps(summary, ensure_ascii=False, indent=1))
