# -*- coding: utf-8 -*-
"""
FAMÍLIA kdf_variants — o criador (openssl >= 1.1.0, EVP-SHA256 provado nas fases 2/3/3.2) pode
ter mudado a derivação de chave no endgame: -pbkdf2/-iter (1.1.1+), -md <digest>, aes-128/192,
ou chave crua -K/-iv. Testa ~2-4k senhas-núcleo × 3 blobs (SMALL/COSMIC/TAIL32) × ~50 derivações.
Oráculo duro: G.semantic(plaintext AES) ou sha256(pw) -> privkey do prêmio. Padding válido = soft.
"""
import sys, os, json, time, hashlib, base64, itertools, re
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160
from coincurve import PublicKey

LOG = os.path.join(SP, "kdf_variants.jsonl")
open(LOG, "w").close()
G.jsonl(LOG, {"hypothesis": "criador usou openssl>=1.1.0; no endgame pode ter trocado KDF para -pbkdf2/-iter, "
              "-md sha1/224/384/512/ripemd160, aes-128/192 ou -K/-iv; senhas-núcleo × 3 blobs × ~50 derivações."})

TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
N = {"aes": 0, "priv": 0}
HARD, SOFT = [], []

# ------------------------------------------------------------------ blobs
def parse_b64(b64):
    raw = base64.b64decode("".join(b64.split())); assert raw[:8] == b"Salted__"; return raw[8:16], raw[16:]
BLOBS = dict(G.BLOBS)
BLOBS["PHASE2"] = parse_b64(G.PHASE2_B64)

# ------------------------------------------------------------------ derivações
MDS = {"md5": MD5, "sha1": SHA1, "sha224": SHA224, "sha256": SHA256, "sha384": SHA384, "sha512": SHA512, "ripemd160": RIPEMD160}
PBK = [("sha256", 1000), ("sha256", 2048), ("sha256", 10000), ("sha256", 100000), ("sha1", 10000), ("sha512", 10000)]
SIZES = ((32, "aes256"), (16, "aes128"), (24, "aes192"))   # key||iv = d[:k]||d[k:k+16] — mesma stream, custo zero

def evp_stream(pw, salt, hm, need=48):
    d = b""; prev = b""
    while len(d) < need:
        prev = hm.new(prev + pw + salt).digest(); d += prev
    return d

def derivations(pw, salt, ct):
    """gera (label, key, iv, ct) para todas as variantes"""
    # (b) EVP_BytesToKey com 7 digests (+ variante senha com '\n')
    for pwv, tag in ((pw, ""), (pw + b"\n", "+nl")):
        for name, hm in MDS.items():
            d = evp_stream(pwv, salt, hm)
            for k, sz in SIZES:
                yield f"evp-{name}-{sz}{tag}", d[:k], d[k:k + 16], ct
    # (a) PBKDF2-HMAC
    for name, it in PBK:
        d = hashlib.pbkdf2_hmac(name, pw, salt, it, 48)
        for k, sz in SIZES:
            yield f"pbkdf2-{name}-{it}-{sz}", d[:k], d[k:k + 16], ct
    # (c) chave crua -K (com Salted__ ignorado) — prior baixa: -K não escreve header Salted__
    h = hashlib.sha256(pw).digest()
    keys = {"sha256": h, "sha256d": hashlib.sha256(h).digest(),
            "sha256-utf16": hashlib.sha256(pw.decode("latin-1").encode("utf-16-le")).digest()}
    try:
        t = pw.decode()
        if re.fullmatch(r"[0-9a-fA-F]{64}", t): keys["hexpw"] = bytes.fromhex(t)
    except Exception: pass
    ivs = {"iv0": b"\x00" * 16, "salt2": salt * 2, "salt0": salt + b"\x00" * 8, "h16": h[16:], "h0": h[:16],
           "h16rev": h[16:][::-1], "md5": hashlib.md5(pw).digest()}
    for kn, k in keys.items():
        for ivn, iv in ivs.items():
            yield f"rawK-{kn}-{ivn}", k, iv, ct
        yield f"rawK-{kn}-ctshift", k, ct[:16], ct[16:]   # CBC deslocado: 1º bloco de CT vira IV

def test_pw(pw, label, blobs=("SMALL", "COSMIC", "TAIL32")):
    pwb = pw.encode("utf-8") if isinstance(pw, str) else pw
    # privkey de graça
    for kn, k in (("sha256", hashlib.sha256(pwb).digest()), ("sha256d", hashlib.sha256(hashlib.sha256(pwb).digest()).digest())):
        N["priv"] += 1
        try:
            if PublicKey.from_valid_secret(k).format(False) == TGT:
                HARD.append({"kind": "privkey", "pw": pw, "how": kn, "priv_hex": k.hex()}); print("!!! PRIV HIT", pw, kn)
        except Exception: pass
    for b in blobs:
        salt, ct = BLOBS[b]
        for dlab, k, iv, c in derivations(pwb, salt, ct):
            N["aes"] += 1
            p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c))
            if p is None: continue
            rec = {"pw": pw, "label": label, "blob": b, "kdf": dlab, "len": len(p), "printable": round(G.printable(p), 3),
                   "head_hex": p[:32].hex()}
            if G.semantic(p):
                rec.update({"kind": "aes", "key_hex": k.hex(), "iv_hex": iv.hex(), "plaintext_hex": p.hex()})
                HARD.append(rec); print("!!! HARD HIT", rec)
            else:
                # priv scan no plaintext binário (SMALL/TAIL32 têm 80B — poderia ser privkey crua)
                hits = G.fast_priv_scan(p, f"{b}/{dlab}")
                N["priv"] += max(0, len(p) - 31)
                if hits:
                    rec.update({"kind": "priv-in-plaintext", "hits": hits, "plaintext_hex": p.hex()}); HARD.append(rec); print("!!! PRIV IN PT", rec)
                else:
                    SOFT.append(rec)
            G.jsonl(LOG, rec)

# ------------------------------------------------------------------ controles positivos
def control():
    ok = {}
    # fase 2: EVP-SHA256 aes256
    s, c = BLOBS["PHASE2"]; pw = G.shahex("causality").encode()
    found = {lab for lab, k, iv, cc in derivations(pw, s, c)
             if (p := G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(cc))) and p.startswith(b"The ironic")}
    ok["phase2"] = found == {"evp-sha256-aes256"}
    # blobs gerados pelo openssl 3.5.7 real (ctl_*.b64) com senha 'controlpw'
    exp = {"ctl_pbkdf2.b64": "pbkdf2-sha256-10000-aes256", "ctl_pbkdf2_sha512_2048.b64": "pbkdf2-sha512-10000-aes256",
           "ctl_evp_sha512.b64": "evp-sha512-aes256", "ctl_evp_aes128.b64": "evp-sha256-aes128",
           "ctl_pbkdf2_aes192_sha1.b64": "pbkdf2-sha1-10000-aes192", "ctl_evp_ripemd.b64": "evp-ripemd160-aes256"}
    msg = open(os.path.join(SP, "ctl.txt"), "rb").read()
    for fn, want in exp.items():
        s, c = parse_b64(open(os.path.join(SP, fn)).read())
        found = {lab for lab, k, iv, cc in derivations(b"controlpw", s, c)
                 if G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(cc)) == msg}
        ok[fn] = found == {want}
        if not ok[fn]: print("CONTROLE FALHOU", fn, found, want)
    # -K sintético: key=sha256(pw), iv=salt*2, header Salted__ artificial
    s = b"12345678"; k = hashlib.sha256(b"controlpw").digest(); iv = s * 2
    pad = 16 - len(msg) % 16; c = AES.new(k, AES.MODE_CBC, iv).encrypt(msg + bytes([pad]) * pad)
    found = {lab for lab, kk, ii, cc in derivations(b"controlpw", s, c) if G.unpad(AES.new(kk, AES.MODE_CBC, ii).decrypt(cc)) == msg}
    ok["rawK"] = "rawK-sha256-salt2" in found
    # controle de oráculo: senha correta da fase 2 via test_pw acha hard hit semântico
    before = len(HARD); test_pw(G.shahex("causality"), "ctl", blobs=("PHASE2",))
    ok["oracle"] = len(HARD) == before + 1 and HARD[-1]["kdf"] == "evp-sha256-aes256"
    HARD.pop()
    G.jsonl(LOG, {"controls": ok}); print("controles:", ok)
    assert all(ok.values()), ok
    return sum(1 for _ in derivations(b"x", b"12345678", b"\0" * 32))

# ------------------------------------------------------------------ senhas-núcleo
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def build_passwords():
    P = {}   # pw -> label (primeira origem)
    def add(lab, *ss):
        for s in ss:
            if s and s not in P: P[s] = lab
    T7 = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "sha256", "shabef",
          "ourfirsthintisyourlastcommand", "anstoo"]
    items = T7 + ["matrixsumlist"]           # matrixsumlist duplicado (aparece 2× na leitura da página)
    for r in (1, 2, 3):
        for combo in itertools.permutations(items, r):
            s = "".join(combo); add("tok%d" % r, s, sha(s))
    # tokens com espaços (como aparecem)
    for s in ["our first hint is your last command", "ans too", "shabef ans too", "shabef our first hint is your last command",
              "sha256 answer too", "answer too", "answer", "ans", "z", "zshabef", "SalPhaseIon", "salphaseion", "SALPHASEION",
              "Cosmic Duality", "cosmicduality", "CosmicDuality", "COSMICDUALITY", "GSMG Puzzle", "GSMGPuzzle", "gsmg", "GSMG"]:
        add("page", s, sha(s), sha(s.replace(" ", "")), s.replace(" ", ""))
    # fases anteriores: senhas cruas + hashes
    PH = {"p1": "theflowerblossomsthroughwhatseemstobeaconcretesurface", "p2": "causality",
          "p3": "causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
          "p32": "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
          "ht": "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"}
    for k, v in PH.items():
        add("phase-" + k, v, sha(v), sha(v).upper(), sha(sha(v)))
    add("url", "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
        "89727C598B9CD1CF8873F27CB7057F050645DDB6A7A157A110239AC0152F6A32", sha("89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"),
        "gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32", "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
    # hints do criador / temas
    for s in ["BTCSEED", "btcseed", "BTC SEED", "btc seed", "halfandbetterhalf", "half and better half", "betterhalf", "better half",
              "HALFANDBETTERHALF", "yinyang", "yin yang", "YinYang", "YINYANG", "yingyang", "salvation", "Salvation", "SALVATION",
              "yellowblueprimes", "yellow blue primes", "purplepill", "purple pill", "thepurplepill", "infrared", "Infrared", "INFRARED",
              "theseedisplanted", "the seed is planted", "gsmg.io/theseedisplanted", "HASHTHETEXT", "hashthetext", "hash the text",
              "thematrixhasyou", "THEMATRIXHASYOU", "The Matrix has you", "42", "zion", "Zion", "architect", "Architect", "thearchitect",
              "neo", "Neo", "trinity", "morpheus", "11092001", "11SEP2001", "11 SEP 2001", "09112001", "20010911", "kill-process",
              "eps3.5_kill-process.inc", "killprocess", "lemiroirdelavieetdelamort", "Le Miroir de la Vie et de la Mort", "lifeanddeath",
              "Life and Death", "life and death", "cosmicdualitybookpage", "globallysupportingmygeneration", "Globally supporting my generation",
              "GloballySupportingMyGeneration", "bingo", "Bingo", "littlebunnyhunter", "little bunny hunter", "goodlucklittlebunnyhunter",
              "rabbitsnest", "rabbits nest", "hushhush", "hush hush", "rosesarewhite", "primebasics", "prime basics", "sourcecodes",
              "returntothesource", "return to the source", "thesource", "privatekeynote", "private keynote", "keynote", "thispasswordisthepassword",
              "matrixsumlistenter", "lastcommand", "last command", "firsthint", "first hint", "ourfirsthint", "yourlastcommand", "your last command",
              "1327", "193", "163", "101", "102", "91", "570", "285", "24", "15", "9", "7", "23", "16", "140", "hundredfourty",
              "worthhundredfourty", G.DBBI, G.FAED, G.FAED[:285], G.FAED[285:], G.DBBI + G.FAED, "dbbi", "faed", "aied",
              "R=18", "1812", "21", "firstorzero", "first or zero", "0", "1", "SalPhaseIonCosmicDuality", "salphaseioncosmicduality",
              "salvationphase", "phase", "vat", "SalvationPhaseIon", "ion", "Ion", "salphase", "sal", "Sal",
              G.bif_full()[:7], G.bif_full(), G.bif_full()[7:], "TheIronic", "sha256", "SHA256", "openssl", "aes-256-cbc", "aes256cbc"]:
        add("hint", s, sha(s), sha(s.replace(" ", "")))
    # focused_aes (script antigo, só SMALL/COSMIC + MD5/SHA256 aes256)
    sys.path.insert(0, G.SOLVER)
    import focused_aes as FA
    for p in FA.PHRASES:
        for v in FA.variants(p): add("focused", v)
    kp = ["lastwordsbeforearchichoice", "thispassword", "our first hint is your last command", "enter", "matrixsumlist"]
    for a, b in itertools.permutations(kp, 2):
        for j in ("", " "):
            s = a + j + b; add("focused2", s, s.replace(" ", ""), sha(s.replace(" ", "")))
    # roadmap_sweep (replicado; o módulo executa ao importar)
    ROAD = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang"]
    T1 = "wewontgiveawaythepassworditsinfrontofyoureyesbutyourenotseeingit"; T2 = "verylaststepisatruegiveawaypromised"
    cs = []
    for r in range(1, 5):
        for combo in itertools.permutations(ROAD, r): cs.append("".join(combo))
    base = "".join(ROAD)
    for extra in ["", T1, T1 + T2, T2]: cs += [base + extra, base + "yinyang" + extra]
    for mid in ["enter", "shabef", "matrixsumlistenter"]: cs.append("yellowblueprimes" + mid + "lastwordsbeforearchichoicethispasswordyinyang")
    D = "ncsyangcahiriasogaleafayanestve"; cs += [D, "yinyang" + D, D + "yinyang"]
    cs += ["makethebestofeverything", "tinyhint", "happynewyearmakethebestofeverything", "ohandheresatinyhint", "makethebestofeverythingyinyang",
           "yinyangmakethebestofeverything", "12345", "salvation", "yinyangsalvation", "salvationyinyang",
           "itsinfrontofyoureyesbutyourenotseeingit", "infrontofyoureyes", "itsinfrontofyoureyes", base + T1 + T2, T1, T2]
    for s in cs: add("roadmap", s, sha(s), sha(s.upper()), sha(sha(s)))
    return P

if __name__ == "__main__":
    t0 = time.time()
    nvar = control()
    P = build_passwords()
    print(f"senhas-núcleo: {len(P)}; derivações por (pw,blob): {nvar}")
    G.jsonl(LOG, {"n_passwords": len(P), "derivations_per_pw_blob": nvar})
    for i, (pw, lab) in enumerate(P.items()):
        test_pw(pw, lab)
        if i % 200 == 0: print(f"[{i}/{len(P)}] aes={N['aes']} priv={N['priv']} soft={len(SOFT)} hard={len(HARD)} {time.time()-t0:.0f}s", flush=True)
    # soft: ordena por printable
    SOFT.sort(key=lambda r: -r["printable"])
    summ = {"summary": True, "n_aes": N["aes"], "n_priv": N["priv"], "n_soft": len(SOFT), "n_hard": len(HARD),
            "expected_soft": round(N["aes"] / 256 * (1 + 1/256 + 1/65536), 1), "best_soft": SOFT[:10], "hard": HARD, "secs": round(time.time() - t0)}
    G.jsonl(LOG, summ); print(json.dumps(summ, ensure_ascii=False, indent=1)[:4000])
