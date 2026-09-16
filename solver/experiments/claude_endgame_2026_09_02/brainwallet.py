# -*- coding: utf-8 -*-
"""
FAMILIA: brainwallet
Hipotese: "Regular Bitcoin Private key" + "the password is in front of your eyes but
you're not seeing it" + "very last step is a true give away" => a privkey do premio e
simplesmente sha256 de uma frase VISIVEL do puzzle (brainwallet), na mesma gramatica ja
provada nas fases 1-3 (concatenacao/caixa preservada). Espaco finito: todo o texto
visivel do puzzle (paginas, textos decodificados, poema, tokens, hashes, saidas Bifid)
x formas de normalizacao x {sha256, dsha256, sha256(hex)} x {k, N-k}.
Oraculo duro: privkey -> h160 do endereco-premio; e cada frase tambem como passphrase
EVP nos 3 blobs (SMALL/COSMIC/TAIL32) com plaintext semantico.
"""
import sys, os, re, json, hashlib, itertools, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gsmg_common as G
import base58
from coincurve import PrivateKey
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

LOG = os.path.join(HERE, "brainwallet.jsonl")
REPO = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ------------------------------------------------------------------ oraculo rapido
def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

TARGETS = {
    base58.b58decode_check(G.PRIZE_ADDR)[1:],   # h160 do endereco-premio
    bytes.fromhex(G.TARGET_H160),
}

def key_hits(k32, extra=None):
    """Testa privkey (comprimida e nao-comprimida). extra = set de h160 do controle."""
    n = int.from_bytes(k32, "big")
    if n == 0 or n >= N_ORDER:
        return None
    pk = PrivateKey(k32).public_key
    tgt = TARGETS if extra is None else (TARGETS | extra)
    for comp in (True, False):
        h = h160(pk.format(compressed=comp))
        if h in tgt:
            return {"priv_hex": k32.hex(), "compressed": comp, "h160": h.hex()}
    return None

# ------------------------------------------------------------------ corpus de frases
def clean(s):
    return " ".join(s.split()).strip()

BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")
BIN_RE = re.compile(r"^[01\s()a-z.0-9]+$")

def readme_lines():
    txt = open(os.path.join(REPO, "README.md"), encoding="utf-8", errors="replace").read()
    out = []
    for ln in txt.splitlines():
        s = clean(ln.lstrip("> ").lstrip("#").replace("**", "").replace("`", ""))
        if not (3 <= len(s) <= 300):
            continue
        if BASE64_RE.match(s.replace(" ", "")):
            continue
        if not all(32 <= ord(c) < 127 for c in s):
            continue
        if s.count("0") + s.count("1") > len(s) * 0.6:
            continue
        if s.startswith("http") or s.startswith("[") or s.startswith("|"):
            out.append(s)
            continue
        out.append(s)
    return out

def creator_lines():
    p = os.path.join(HERE, "creator_all.txt")
    if not os.path.exists(p):
        return []
    out = []
    for ln in open(p, encoding="utf-8", errors="replace"):
        m = re.search(r"#\d+ (['\"])(.*?)\1(\s+\[reply|$)", ln.strip())
        if not m:
            continue
        s = clean(m.group(2).replace("\\n", " "))
        if 4 <= len(s) <= 200 and all(32 <= ord(c) < 127 for c in s):
            out.append(s)
    return out

def segments(text):
    """Frase inteira + sentencas + clausulas (virgula) + palavras longas."""
    out = {text}
    for sent in re.split(r"(?<=[.!?])\s+", text):
        sent = clean(sent).strip(".!?")
        if 3 <= len(sent) <= 200:
            out.add(sent)
            for cl in sent.split(","):
                cl = clean(cl)
                if 4 <= len(cl) <= 200:
                    out.add(cl)
    return out

# --- material canonico embutido (visivel no puzzle / dado pelo criador)
CANON_PHRASES = [
    # tokens da pagina endgame
    "matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "sha256",
    "shabef", "our first hint is your last command", "sha256 ans too", "ans too",
    "SalPhaseIon", "Cosmic Duality", "GSMG Puzzle", "salphaseion", "cosmicduality",
    "Salvation", "salvation", "SalPhaseIonCosmicDuality", "yinyang", "yellowblueprimes",
    "yin yang", "yellow blue primes", "purple pill", "thepurplepill",
    # roadmap do criador
    "yellowblueprimes matrixsumlist lastwordsbeforearchichoice yinyang",
    "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang",
    # frases-mote
    "the seed is planted", "theseedisplanted", "gsmg.io/theseedisplanted",
    "follow the white rabbit", "followthewhiterabbit", "GSMG MEGANIGMA", "MEGANIGMA",
    "GSMG", "Globally supporting my generation", "GSMGIO", "gsmg.io",
    "in front of your eyes", "infrontofyoureyes", "its in front of your eyes but youre not seeing it",
    "very last step is a true give away", "true give away", "truegiveaway",
    "Regular Bitcoin Private key", "regularbitcoinprivatekey",
    "Have you tried the purple pill already?",
    "At least a prime number is very important to get any further",
    "Some characters need to be zeroed out", "prime positions", "First or zero",
    "rewatch episode 3.5 with the better half", "eps3.5_kill-process.inc",
    "eps3.4_runtime-error.r00", "half and better half", "halfandbetterhalf",
    "the private keys belong to half and better half",
    # endereco / hashes visiveis
    G.PRIZE_ADDR, "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "GSMG.IO 5 BTC PUZZLE CHALLENGE",
    "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
    "https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
    "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",
    "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
    "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
    "5ac407837447fba24ba2802e4d1e9aecb4580aa29fef1088cc387c180b746f75",
    # senhas anteriores e partes
    "causality", "Safenet", "Luna", "HSM", "11110", "causalitySafenetLunaHSM11110",
    "theflowerblossomsthroughwhatseemstobeaconcretesurface",
    "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
    "jacquefresco", "giveit", "givetit", "justonesecond",
    "heisenbergsuncertaintyprinciple", "HASHTHETEXT", "hashthetext",
    "THEMATRIXHASYOU", "thematrixhasyou", "the matrix has you",
    "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
    "B5KR/1r5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 w - - 0 1",
    "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
    "choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself",
    # Matrix / Arquiteto / Neo (transcricoes exatas)
    "the door to your right leads to the source and the salvation of Zion",
    "the door to your left leads back to the matrix",
    "Choice is an illusion created between those with power and those without",
    "Everything begins with choice", "There is only one constant one universal causality",
    "cause and effect", "Wake up Neo", "Wake up you", "The Matrix has you",
    "Why am I here", "Follow the white rabbit", "Knock knock Neo",
    "hope it is the quintessential human delusion simultaneously the source of your greatest strength and your greatest weakness",
    "denial is the most predictable of all human responses",
    "I know why you are here Neo", "There is no spoon", "Free your mind",
    "Ergo vis a vis concordantly", "Ergo", "Vis a vis", "Concordantly",
    "the problem is choice", "It is the sum of a remainder of an unbalanced equation",
    "the function of the one is now to return to the source",
    "You are the eventuality of an anomaly",
    # poema Roses (linhas + variacoes)
    "Roses are White but often Red.",
    "Yellow has a number and so does Blue.",
    "Go back to the first puzzle piece without further ado.",
    "It might have shown you only one door, beware that the rabbits nest may contain a whole lot more.",
    "Hush hush.",
    "Roses are White but often Red Yellow has a number and so does Blue Go back to the first puzzle piece without further ado It might have shown you only one door beware that the rabbits nest may contain a whole lot more Hush hush",
    "RosesareWhitebutoftenRedYellowhasanumberandsodoesBlueGobacktothefirstpuzzlepiecewithoutfurtheradoItmighthaveshownyouonlyonedoorbewarethattherabbitsnestmaycontainawholelotmoreHushhush",
    # cores / numeros da matriz
    "3F48CC", "FFF200", "#3F48CC", "#FFF200", "FEFEFE", "101", "102", "163", "193",
    "yellow", "blue", "Yellow", "Blue", "yellowblue", "blueyellow",
    # BTCSEED
    "BTCSEED", "btcseed", "BTC SEED",
]

def build_corpus():
    phr = set()
    for s in CANON_PHRASES:
        phr |= segments(clean(s))
    for ln in readme_lines():
        phr |= segments(ln)
    for ln in creator_lines():
        phr |= segments(ln)
    # material bruto do puzzle
    bif = G.bif_full()
    phr |= {
        G.DBBI, G.FAED, G.DBBI + G.FAED, G.FAED[4:],
        "".join(str(d) for d in G.digits(G.DBBI)),
        "".join(str(d) for d in G.digits(G.FAED)),
        bif, bif[7:], bif[:64], bif[0::2], bif[1::2],
        G.CANON, "DBIFHCEGA", "dbifhcega",
        "".join(sorted(set(G.DBBI))),
        G.COLOR_SEQ,
        "".join(str(b) for row in G.MATRIX_IMG for b in row),
        "".join(str(b) for row in G.MATRIX_README for b in row),
        "".join(str(G.MATRIX_IMG[r][c]) for r, c in G.SPIRAL),
        ",".join(map(str, G.row_sums(G.MATRIX_IMG))),
        ",".join(map(str, G.col_sums(G.MATRIX_IMG))),
        "".join(map(str, G.row_sums(G.MATRIX_IMG))),
        "".join(map(str, G.col_sums(G.MATRIX_IMG))),
    }
    # concatenacoes do roadmap (gramatica provada: concatenar sem espaco)
    road = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang"]
    for r in range(2, 5):
        for p in itertools.permutations(road, r):
            phr.add("".join(p))
    parts7 = ["causality", "Safenet", "Luna", "HSM", "11110"]
    for r in range(2, 6):
        phr.add("".join(parts7[:r]))
    # gramatica provada do puzzle: concatenar keywords sem espaco (pares e triplas)
    core = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "enter",
            "sha256", "yinyang", "yellowblueprimes", "BTCSEED", "salphaseion",
            "cosmicduality", "theseedisplanted", "hashthetext", "causality",
            "halfandbetterhalf", "thematrixhasyou", "salvation"]
    for a, b in itertools.permutations(core, 2):
        phr.add(a + b)
    core8 = core[:8]
    for t in itertools.permutations(core8, 3):
        phr.add("".join(t))
    # textos longos decodificados, juntados em bloco unico (gramatica "connected enf")
    for blk in big_blocks():
        phr.add(blk)
        phr.add(re.sub(r"[^A-Za-z0-9]", "", blk))
    # palavras do vocabulario visivel
    vocab = set()
    for s in list(phr):
        for w in re.findall(r"[A-Za-z]{4,}", s):
            vocab.add(w)
    phr |= vocab
    return sorted(p for p in phr if 3 <= len(p) <= 4000)

def big_blocks():
    """Blocos completos dos textos decodificados (Arquiteto/Beaufort, VIC, phase2/3)."""
    txt = open(os.path.join(REPO, "README.md"), encoding="utf-8", errors="replace").read()
    out = []
    for m in re.finditer(r"```(?:text|c)?\n(.*?)```", txt, re.S):
        b = m.group(1)
        if BASE64_RE.match(clean(b).replace(" ", "")[:80]) or "U2FsdGVk" in b:
            continue
        s = clean(b)
        if 60 <= len(s) <= 4000 and all(32 <= ord(c) < 127 for c in s):
            out.append(s)
            out.append(s.replace(" ", ""))
    return out

# ------------------------------------------------------------------ formas e chaves
def forms(p):
    alnum = re.sub(r"[^A-Za-z0-9]", "", p)   # regra HASHTHETEXT (autor "picky" com texto)
    f = [p, p.replace(" ", ""), p.lower(), p.upper(),
         p.lower().replace(" ", ""), p.upper().replace(" ", ""), p + "\n",
         alnum, alnum.upper(), alnum.lower()]
    seen, out = set(), []
    for x in f:
        if x and x not in seen:
            seen.add(x); out.append(x)
    return out

def keys_of(bs):
    h1 = hashlib.sha256(bs).digest()
    h2 = hashlib.sha256(h1).digest()
    h3 = hashlib.sha256(h1.hex().encode()).digest()
    out = []
    for name, k in (("sha256", h1), ("dsha256", h2), ("sha256hex", h3)):
        out.append((name, k))
        n = int.from_bytes(k, "big")
        if 0 < n < N_ORDER:
            out.append((name + "|N-k", (N_ORDER - n).to_bytes(32, "big")))
    return out

# ------------------------------------------------------------------ AES (3 blobs)
def evp_open(pw, salt, ct, hm):
    d = b""; prev = b""
    while len(d) < 48:
        prev = hm.new(prev + pw + salt).digest(); d += prev
    p = AES.new(d[:32], AES.MODE_CBC, d[32:48]).decrypt(ct)
    pad = p[-1]
    if 1 <= pad <= 16 and p.endswith(bytes([pad]) * pad):
        return p[:-pad]
    return None

BLOBS = [(n, ) + G.BLOBS[n] for n in ("SMALL", "COSMIC", "TAIL32")]

# ------------------------------------------------------------------ controles
def controls():
    # controle positivo privkey: frase plantada deve ser detectada
    seed = hashlib.sha256(b"CONTROLE-POSITIVO-brainwallet").digest()
    planted = {h160(PrivateKey(seed).public_key.format(compressed=True))}
    assert key_hits(seed, extra=planted), "controle privkey FALHOU"
    assert key_hits(seed) is None, "falso positivo no alvo real"
    # controle positivo AES: blob sintetico com senha conhecida abre e e semantico
    import os as _os
    pw = b"senha-de-controle"; salt = _os.urandom(8)
    msg = b"IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEY IS HERE. " * 2
    d = b""; prev = b""
    while len(d) < 48:
        prev = MD5.new(prev + pw + salt).digest(); d += prev
    pad = 16 - len(msg) % 16
    ct = AES.new(d[:32], AES.MODE_CBC, d[32:48]).encrypt(msg + bytes([pad]) * pad)
    got = evp_open(pw, salt, ct, MD5)
    assert got == msg and G.semantic(got), "controle AES FALHOU"
    assert evp_open(b"errada", salt, ct, MD5) in (None,) or not G.semantic(evp_open(b"errada", salt, ct, MD5) or b"\x00")
    return True

# ------------------------------------------------------------------ main
def main():
    assert controls()
    hyp = ("brainwallet: privkey do premio = sha256/dsha256/sha256(hex) de uma frase "
           "VISIVEL do puzzle (paginas, textos decodificados, poema Roses, tokens, "
           "hashes, saidas Bifid, material do criador), em 7 formas de normalizacao, "
           "mais espelho N-k; cada forma tambem como passphrase EVP nos 3 blobs.")
    G.jsonl(LOG, {"family": "brainwallet", "hypothesis": hyp, "ts": time.time()})

    corpus = build_corpus()
    print("frases base:", len(corpus))
    n_priv = n_aes = 0
    hard, soft = [], []
    best_soft = None
    t0 = time.time()
    for i, phrase in enumerate(corpus):
        for f in forms(phrase):
            bs = f.encode("utf-8", "replace")
            # --- oraculo 1: brainwallet privkey
            for kname, k in keys_of(bs):
                n_priv += 1
                r = key_hits(k)
                if r:
                    r.update({"phrase": phrase, "form": f, "kdf": kname})
                    hard.append({"kind": "privkey", **r})
                    G.jsonl(LOG, {"HARD": r})
                    print("HARD PRIVKEY", r)
            # --- oraculo 2: passphrase EVP nos blobs
            for name, salt, ct in BLOBS:
                for hm in (MD5, SHA256):
                    n_aes += 1
                    p = evp_open(bs, salt, ct, hm)
                    if p is None:
                        continue
                    pr = G.printable(p)
                    rec = {"blob": name, "kdf": hm.__name__, "phrase": phrase,
                           "form": f, "printable": round(pr, 3),
                           "head": p[:48].hex()}
                    if G.semantic(p):
                        rec["plain_hex"] = p.hex()
                        hard.append({"kind": "aes", **rec})
                        G.jsonl(LOG, {"HARD": rec})
                        print("HARD AES", rec)
                    else:
                        soft.append(rec)
                        if best_soft is None or pr > best_soft["printable"]:
                            best_soft = rec
                        # varre privkey embutida no plaintext (padding valido)
                        for h in G.scan_priv(p, f"{name}/{hm.__name__}"):
                            hard.append({"kind": "priv_in_plain", "hit": str(h),
                                         "phrase": phrase, "form": f})
                            G.jsonl(LOG, {"HARD": {"scan": str(h), "phrase": phrase}})
        if i % 500 == 0:
            print(f"{i}/{len(corpus)} priv={n_priv} aes={n_aes} soft={len(soft)} "
                  f"{time.time()-t0:.0f}s", flush=True)

    summary = {"family": "brainwallet", "n_phrases": len(corpus),
               "n_priv_tests": n_priv, "n_aes_tests": n_aes,
               "n_tests": n_priv + n_aes, "n_hard": len(hard),
               "n_soft_padding": len(soft), "best_soft": best_soft,
               "elapsed_s": round(time.time() - t0, 1)}
    G.jsonl(LOG, {"SUMMARY": summary})
    print(json.dumps(summary, indent=2))
    # top 10 softs por printable
    top = sorted(soft, key=lambda r: -r["printable"])[:10]
    G.jsonl(LOG, {"TOP_SOFT": top})
    for t in top:
        print("soft", t["printable"], t["blob"], t["kdf"], repr(t["phrase"][:60]))

if __name__ == "__main__":
    main()
