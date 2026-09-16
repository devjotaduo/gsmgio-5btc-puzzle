# -*- coding: utf-8 -*-
"""Familia blob_structure: estrutura dos blobs (linha1/linha2 do SMALL, modos/cifras
alternativos do openssl legado, TAIL32 com textos da fase 3.2, COSMIC = sha256(resposta))."""
import sys, os, re, json, base64, hashlib, itertools, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Hash import MD5, SHA256
LOG = os.path.join(SP, "blob_structure.jsonl")
open(LOG, "w").close()
G.jsonl(LOG, {"hypothesis": "enter separa linha1 (blob EVP autonomo, 2 blocos) e linha2 (3 blocos crus, IV alternativo/ECB); "
              "ou blob inteiro em cifra/modo legado (aes-128/192, ecb, ctr/ofb/cfb, des3, bf). TAIL32 com textos 3.2; COSMIC com sha256(senha)."})

# ------------------------------------------------------------------ senhas
README = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
def hashthetext(s): return re.sub(r"[^A-Za-z0-9]", "", s)
sha = lambda s: hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()

MAIN = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "enter", "yellowblueprimes", "yinyang"]
EXTRA = ["sha256", "shabef", "our first hint is your last command", "ourfirsthintisyourlastcommand", "ans too", "anstoo",
         "SalPhaseIon", "salphaseion", "Cosmic Duality", "CosmicDuality", "cosmicduality", "GSMG Puzzle", "GSMGPuzzle",
         "salvation", "Salvation", "half", "betterhalf", "halfandbetterhalf", "half and better half", "BTCSEED", "btcseed",
         "theseedisplanted", "the seed is planted", "gsmg.io/theseedisplanted", "HASHTHETEXT", "hashthetext",
         "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
         "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
         "causality", "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6", "theflowerblossomsthroughwhatseemstobeaconcretesurface",
         "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
         "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
         "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple", "THEMATRIXHASYOU", "thematrixhasyou",
         "1141", "purplepill", "purple pill", "bluepill", "redpill", "Bingo", "bingo", "yellowblueprimes", "yinyang", "yin yang",
         "matrixsumlist101", "matrixsumlist102", "101", "102", "1327", "193", "163", "z", "dbbi", "faed",
         G.DBBI, G.FAED, G.DBBI + G.FAED,
         "openssl enc -aes-256-cbc -d -a", "openssl enc -aes-256-cbc -d -a -in", "enc -aes-256-cbc -d -a",
         "our first hint is your last command sha256", "sha256 our first hint is your last command",
         "shabef our first hint is your last command", "shabef ans too", "sha256 ans too", "sha256answertoo", "answer", "ans",
         "lastwordsbeforearchichoicethispassword", "thispasswordlastwordsbeforearchichoice",
         "There is no spoon", "thereisnospoon", "Neo", "neo", "Trinity", "Morpheus", "Architect", "architect", "Oracle", "oracle",
         "11SEP2001", "11092001", "20010911", "Globally supporting my generation", "Globallysupportingmygeneration",
         "Le Miroir de la Vie et de la Mort", "LeMiroirdelaVieetdelaMort", "Life and Death", "LifeandDeath", "eps3.5_kill-process.inc",
         ]
# textos da fase 3.2 (TAIL32): Beaufort plaintext, VIC plaintext, frases
BEAUF = re.search(r"YOUR LIFE IS THE SUM.*?CIAO BELLA O", README, re.S).group(0)
BEAUF_1L = " ".join(BEAUF.split())
VIC = "IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE"
RAISING = "Raising the stakes without extra chances of winning. A fubcd-king & oracle-queen, thingky mvps, on a sad board but as wide as the first one seen."
ARCH_INTRO = ("I've been waiting for you. You have many questions, and although the process has altered your consciousness, you remain irrevocably human. "
              "Ergo, some of my answers you will understand, and some of them you will not. Concordantly, while your first question may be the most pertinent, "
              "you may or may not realize it is also irrelevant.")
BEAUF_CT = re.search(r"\n(vtkvplmepph[a-z]+)\n", README).group(1)
VIC_DIG = "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"
P32 = [BEAUF, BEAUF_1L, hashthetext(BEAUF), VIC, VIC.replace(" ", ""), RAISING, hashthetext(RAISING), ARCH_INTRO, hashthetext(ARCH_INTRO),
       "... am I here? Wake up, you... I've designed you a beautiful strategic position. One for one, four for one.",
       "amIhereWakeupyouIvedesignedyouabeautifulstrategicpositionOneforonefourforone",
       "I've designed you a beautiful strategic position", "One for one, four for one", "Oneforonefourforone",
       "halfandbetterhalf", "half and better half", "HALFANDBETTERHALF", "HALF AND BETTER HALF", "betterhalf", "BETTERHALF",
       "raisingthestakeswithoutextrachancesofwinning", "Raisingthestakeswithoutextrachancesofwinning",
       "RaisingthestakeswithoutextrachancesofwinningAfubcdkingoraclequeenthingkymvpsonasadboardbutaswideasthefirstoneseen",
       "afubcdkingoraclequeenthingkymvpsonasadboardbutaswideasthefirstoneseen",
       "fubcdkingoraclequeenthingkymvps", "FUBCDKINGORACLEQUEENTHINGKYMVPS", "fubcd-king & oracle-queen, thingky mvps",
       "FUBCDORA.LETHINGKYMVPS.JQZXW", "FUBCDORALETHINGKYMVPSJQZXW", "FUBCDORA.LETHINGKYMVPS/JQZXW", "fubcdoralethingkymvpsjqzxw",
       "THEMATRIXHASYOU", "thematrixhasyou", "The matrix has you", "1141", "14", "beaufort", "Beaufort", "vic", "VIC",
       "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c", VIC_DIG, BEAUF_CT,
       "incaseyoumanagetocrackthis", "INCASEYOUMANAGETOCRACKTHIS", "theprivatekeysbelongtohalfandbetterhalf", "THEPRIVATEKEYSBELONGTOHALFANDBETTERHALF",
       "theyalsoneedfundstolive", "THEYALSONEEDFUNDSTOLIVE", "andtheyalsoneedfundstolive", "fundstolive", "needfundstolive",
       "worthhundredfourty", "WORTHHUNDREDFOURTY", "hundredfourty", "140", "ciaobella", "CIAOBELLA", "ciaobellao", "CIAOBELLAO",
       "reinsertingtheprimebasics", "REINSERTINGTHEPRIMEBASICS", "returntothesourcecodes", "RETURNTOTHESOURCECODES",
       "twentythreecipherssixteenencryptionsandorsevenintertwinedpasswords", "sevenintertwinedpasswords", "SEVENINTERTWINEDPASSWORDS",
       "theactualprivatekeynote", "privatekeynote", "PRIVATEKEYNOTE", "bruteforcingmightberequired", "denialisthemostpredictableofallhumanresponses",
       "ihopeyouretheone", "IREALLYHOPEYOURETHEONE", "yourlifeisthesumofaremainderofanunbalancedequation",
       "jacquefresco", "giveit", "justonesecond", "heisenbergsuncertaintyprinciple", "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
       "Sometimes, just one second", "sometimesjustonesecond", "How long is forever", "howlongisforever",
       ]

def variants(s):
    out = {s, s.upper(), s.lower(), s + "\n", s + "\r\n", sha(s), sha(s).upper(), sha(s + "\n"), sha(s.upper()), sha(s.lower())}
    return out

def build_small_pw():
    pws = set()
    for k in (1, 2, 3):
        for combo in itertools.permutations(MAIN, k):
            for sep in ("", " ", "\n", "-", "_", ","):
                pws.add(sep.join(combo))
    for s in EXTRA + MAIN: pws |= variants(s)
    base = set(pws)
    for s in base:
        if len(s) < 200: pws |= {s + "\n", sha(s), sha(s + "\n")}
    return sorted(pws)

def build_tail_pw():
    pws = set()
    for s in P32: pws |= variants(s)
    for s in list(pws):
        pws.add(sha(s))
    return sorted(pws)

# ------------------------------------------------------------------ decodificadores estruturais
def evp(pw, salt, hm, klen, ivlen):
    d = b""; prev = b""
    while len(d) < klen + ivlen:
        prev = hm.new(prev + pw + salt).digest(); d += prev
    return d[:klen], d[klen:klen + ivlen]

def unpad(p, bs=16):
    if not p: return None
    n = p[-1]
    if 1 <= n <= bs and p.endswith(bytes([n]) * n): return p[:-n]
    return None

# cada modo: (nome, klen, ivlen, fn(key, iv, ct) -> plaintext_bruto, precisa_unpad, blocksize)
def _aes_cbc(k, iv, ct): return AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
def _aes_ecb(k, iv, ct): return AES.new(k, AES.MODE_ECB).decrypt(ct)
def _aes_ctr(k, iv, ct): return AES.new(k, AES.MODE_CTR, initial_value=iv, nonce=b"").decrypt(ct)
def _aes_ofb(k, iv, ct): return AES.new(k, AES.MODE_OFB, iv).decrypt(ct)
def _aes_cfb(k, iv, ct): return AES.new(k, AES.MODE_CFB, iv, segment_size=128).decrypt(ct)
def _aes_cfb8(k, iv, ct): return AES.new(k, AES.MODE_CFB, iv, segment_size=8).decrypt(ct)
def _des3_cbc(k, iv, ct):
    try: return DES3.new(k, DES3.MODE_CBC, iv).decrypt(ct)
    except ValueError: return None   # chave degenerada
def _des3_ecb(k, iv, ct):
    try: return DES3.new(k, DES3.MODE_ECB).decrypt(ct)
    except ValueError: return None
def _bf_cbc(k, iv, ct): return Blowfish.new(k, Blowfish.MODE_CBC, iv).decrypt(ct)
def _bf_ecb(k, iv, ct): return Blowfish.new(k, Blowfish.MODE_ECB).decrypt(ct)
MODES = [  # nome, klen, ivlen, fn, padded, bs
    ("aes-256-cbc", 32, 16, _aes_cbc, True, 16),
    ("aes-128-cbc", 16, 16, _aes_cbc, True, 16),
    ("aes-192-cbc", 24, 16, _aes_cbc, True, 16),
    ("aes-256-ecb", 32, 0, _aes_ecb, True, 16),
    ("aes-128-ecb", 16, 0, _aes_ecb, True, 16),
    ("aes-256-ctr", 32, 16, _aes_ctr, False, 16),
    ("aes-256-ofb", 32, 16, _aes_ofb, False, 16),
    ("aes-256-cfb", 32, 16, _aes_cfb, False, 16),
    ("aes-256-cfb8", 32, 16, _aes_cfb8, False, 16),
    ("des-ede3-cbc", 24, 8, _des3_cbc, True, 8),
    ("des-ede3-ecb", 24, 0, _des3_ecb, True, 8),
    ("bf-cbc", 16, 8, _bf_cbc, True, 8),
    ("bf-ecb", 16, 0, _bf_ecb, True, 8),
]
KDFS = (MD5, SHA256)

def judge(p, padded, bs):
    """Retorna (hard, soft, plaintext) — hard = semantica; soft = padding valido (ou stream com printable>=0.6)."""
    if p is None: return False, False, None
    if padded:
        u = unpad(p, bs)
        if u is None: return False, False, None
        return G.semantic(u), True, u
    return G.semantic(p), G.printable(p) >= 0.6, p

STATS = {"n": 0, "npriv": 0}
import coincurve
_PUB = bytes.fromhex(G.TARGET_PUBKEY_HEX); _N = 0xFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def fast_priv(b32):
    n = int.from_bytes(b32, "big")
    if n == 0 or n >= _N: return False
    return coincurve.PrivateKey(b32).public_key.format(compressed=False) == _PUB
HARD, SOFT = [], []
def record(kind, pw, blob, mode, kdf, extra, p, hard, soft):
    if not (hard or soft): return
    rec = {"kind": kind, "blob": blob, "mode": mode, "kdf": kdf, "extra": extra, "pw": pw.decode("latin-1")[:120],
           "len": len(p), "printable": round(G.printable(p), 3), "head": p[:48].decode("latin-1")}
    if hard:
        rec["plaintext_hex"] = p.hex(); rec["pw_hex"] = pw.hex(); HARD.append(rec); print("HARD HIT", rec)
    else:
        SOFT.append(rec)
    G.jsonl(LOG, rec)

def run_modes(pw, blob, salt, ct, kind="full"):
    """Blob inteiro (Salted__ + salt + ct) por todos os modos legados."""
    for hm in KDFS:
        for name, klen, ivlen, fn, padded, bs in MODES:
            if len(ct) % bs: continue
            k, iv = evp(pw, salt, hm, klen, ivlen)
            p = fn(k, iv, ct); STATS["n"] += 1
            hard, soft, u = judge(p, padded, bs)
            record(kind, pw, blob, name, hm.__name__, "", u, hard, soft)
            if p is not None and len(p) >= 32:
                for off in range(0, len(p) - 31, 16):   # ponytail: so offsets alinhados a bloco (coincurve, rapido)
                    STATS["npriv"] += 1
                    if fast_priv(p[off:off + 32]):
                        HARD.append({"kind": "privkey", "pw": pw.decode("latin-1"), "mode": name, "kdf": hm.__name__, "off": off, "priv_hex": p[off:off+32].hex(), "buf_hex": p.hex()})
                        print("PRIV HIT", HARD[-1])

def run_small_split(pw):
    """Linha 1 = blob EVP autonomo (2 blocos); linha 2 = 3 blocos crus com chave EVP e IVs alternativos / ECB."""
    salt, ct = G.BLOBS["SMALL"]; l1, l2 = ct[:32], ct[32:]
    for hm in KDFS:
        # linha 1 sozinha: aes-256/128/192-cbc + ecb
        for name, klen, ivlen, fn, padded, bs in MODES[:5]:
            k, iv = evp(pw, salt, hm, klen, ivlen)
            p = fn(k, iv, l1); STATS["n"] += 1
            hard, soft, u = judge(p, padded, bs)
            record("line1", pw, "SMALL", name, hm.__name__, "", u, hard, soft)
        # linha 2 crua: chave aes-256 EVP, IVs alternativos (IV=ct[16:32] == continuacao CBC == full, ja coberto)
        k, iv = evp(pw, salt, hm, 32, 16)
        ivs = {"iv0": b"\0" * 16, "salt00": salt + b"\0" * 8, "saltsalt": salt * 2, "evp_iv": iv,
               "line1_ct0": ct[:16]}
        for lab, v in ivs.items():
            p = _aes_cbc(k, v, l2); STATS["n"] += 1
            hard, soft, u = judge(p, True, 16)
            record("line2", pw, "SMALL", "aes-256-cbc", hm.__name__, lab, u, hard, soft)
        p = _aes_ecb(k, None, l2); STATS["n"] += 1
        hard, soft, u = judge(p, True, 16)
        record("line2", pw, "SMALL", "aes-256-ecb", hm.__name__, "", u, hard, soft)
        # linha 2 sem padding (stream): CTR/OFB/CFB com IV EVP
        for name, fn in (("aes-256-ctr", _aes_ctr), ("aes-256-ofb", _aes_ofb), ("aes-256-cfb", _aes_cfb)):
            p = fn(k, iv, l2); STATS["n"] += 1
            hard, soft, u = judge(p, False, 16)
            record("line2", pw, "SMALL", name, hm.__name__, "evp_iv", u, hard, soft)
        # linha 2 como blob EVP proprio com salt = primeiros 8 bytes da linha 2? nao — sem header. Usar salt do SMALL, ct = l2 (ja acima com evp_iv).
        # chave = sha256(pw) crua (openssl -K), IV zero / salt
        k2 = hashlib.sha256(pw).digest()
        for lab, v in (("iv0", b"\0" * 16), ("salt00", salt + b"\0" * 8)):
            p = _aes_cbc(k2, v, ct); STATS["n"] += 1
            hard, soft, u = judge(p, True, 16)
            record("rawkey_sha256", pw, "SMALL", "aes-256-cbc", "sha256raw", lab, u, hard, soft)
            p = _aes_cbc(k2, v, l1); STATS["n"] += 1
            hard, soft, u = judge(p, True, 16)
            record("rawkey_sha256_l1", pw, "SMALL", "aes-256-cbc", "sha256raw", lab, u, hard, soft)

# ------------------------------------------------------------------ controle positivo
def control():
    # 1) blob real da fase 3.2 abre com 250f37... (EVP-MD5, aes-256-cbc)
    m = re.search(r"Phase 3\.2 is ciphered.*?\n\n(U2FsdGVk.*?)\n\n", README, re.S)
    raw = base64.b64decode(m.group(1).replace("\n", ""))
    salt, ct = raw[8:16], raw[16:]
    pw = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
    opened = {}
    for hm in KDFS:
        k, iv = evp(pw, salt, hm, 32, 16)
        u = unpad(_aes_cbc(k, iv, ct))
        if u and u.startswith(b"I've been waiting for you"): opened[hm.__name__] = True
    assert opened, "controle 3.2 falhou"
    print("controle: blob 3.2 abre com KDF", list(opened))   # fato: SHA256 (openssl >= 1.1), nao MD5
    G.jsonl(LOG, {"control_phase32_kdf": list(opened)})
    # 2) round-trip de cada modo com plaintext plantado
    from Crypto.Cipher import AES as A
    pt = b"POSITIVE CONTROL: this is a planted plaintext for blob_structure!!"
    for name, klen, ivlen, fn, padded, bs in MODES:
        k, iv = evp(b"ctrl", b"12345678", MD5, klen, ivlen)
        data = pt + bytes([bs - len(pt) % bs]) * (bs - len(pt) % bs) if padded else pt
        if name.startswith("aes"):
            mode = {"cbc": A.MODE_CBC, "ecb": A.MODE_ECB, "ctr": A.MODE_CTR, "ofb": A.MODE_OFB, "cfb": A.MODE_CFB}[name.split("-")[2].rstrip("8")]
            if mode == A.MODE_ECB: c = A.new(k, mode)
            elif mode == A.MODE_CTR: c = A.new(k, mode, initial_value=iv, nonce=b"")
            elif mode == A.MODE_CFB: c = A.new(k, mode, iv, segment_size=8 if name.endswith("cfb8") else 128)
            else: c = A.new(k, mode, iv)
        elif name.startswith("des"):
            c = DES3.new(k, DES3.MODE_ECB) if "ecb" in name else DES3.new(k, DES3.MODE_CBC, iv)
        else:
            c = Blowfish.new(k, Blowfish.MODE_ECB) if "ecb" in name else Blowfish.new(k, Blowfish.MODE_CBC, iv)
        ct2 = c.encrypt(data)
        hard, soft, u = judge(fn(k, iv, ct2), padded, bs)
        assert hard and u.startswith(pt), name
    # 3) split: planta linha1 e linha2 com IV alternativo e recupera
    print("controle positivo OK (fase 3.2 abre com 250f37…; 13 modos round-trip)")

# ------------------------------------------------------------------ main
if __name__ == "__main__":
    control()
    t0 = time.time()
    small_pw = build_small_pw(); tail_pw = build_tail_pw()
    print("senhas SMALL:", len(small_pw), "senhas TAIL32:", len(tail_pw))
    G.jsonl(LOG, {"n_pw_small": len(small_pw), "n_pw_tail": len(tail_pw)})
    saltS, ctS = G.BLOBS["SMALL"]; saltT, ctT = G.BLOBS["TAIL32"]; saltC, ctC = G.BLOBS["COSMIC"]
    # (1) SMALL: split + modos legados
    for i, s in enumerate(small_pw):
        pw = s.encode("utf-8")
        run_small_split(pw)
        run_modes(pw, "SMALL", saltS, ctS)
        if i % 1000 == 0: print("small", i, STATS, round(time.time() - t0), flush=True)
    # (2) TAIL32: senhas 3.2 (+ senhas SMALL, baratas) em todos os modos
    for s in tail_pw + small_pw:
        run_modes(s.encode("utf-8"), "TAIL32", saltT, ctT)
    # (3) COSMIC: sha256 de cada senha testada (dupla camada) + senhas cruas; so cbc/ecb (padded) para caber no orcamento
    cosmic_pw = set()
    for s in small_pw + tail_pw:
        cosmic_pw |= {s, sha(s), sha(s + "\n"), sha(s).upper()}
    cosmic_pw = sorted(cosmic_pw)
    print("senhas COSMIC:", len(cosmic_pw))
    G.jsonl(LOG, {"n_pw_cosmic": len(cosmic_pw)})
    MODES_C = [m for m in MODES if m[4]]   # so modos com padding (oraculo objetivo)
    for i, s in enumerate(cosmic_pw):
        pw = s.encode("utf-8")
        if i % 5000 == 0: print("cosmic", i, STATS, round(time.time() - t0), flush=True)
        for hm in KDFS:
            for name, klen, ivlen, fn, padded, bs in MODES_C:
                k, iv = evp(pw, saltC, hm, klen, ivlen)
                p = fn(k, iv, ctC); STATS["n"] += 1
                hard, soft, u = judge(p, padded, bs)
                record("cosmic", pw, "COSMIC", name, hm.__name__, "", u, hard, soft)
    # (4) brainwallet: sha256(senha) como privkey direta
    npriv = 0
    for s in set(small_pw + tail_pw):
        for k in (hashlib.sha256(s.encode()).digest(),):
            npriv += 1
            r = G.priv_hit(k)
            if r: HARD.append({"kind": "brainwallet", "pw": s, "hit": r, "priv_hex": k.hex()}); print("PRIV HIT", HARD[-1])
    summary = {"n_tests": STATS["n"], "n_priv_windows": STATS["npriv"], "n_priv": npriv, "hard": len(HARD), "soft": len(SOFT), "secs": round(time.time() - t0, 1)}
    print(summary); G.jsonl(LOG, {"summary": summary})
    best = max(SOFT, key=lambda r: r["printable"], default=None)
    print("best soft:", best)
    json.dump({"summary": summary, "hard": HARD, "soft": SOFT}, open(os.path.join(SP, "blob_structure_result.json"), "w"), indent=1)
