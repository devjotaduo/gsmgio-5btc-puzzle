# -*- coding: utf-8 -*-
"""fresh_designer — leituras "como o autor" do endgame SalPhaseIon.
L1 enter/newline + senhas de fases anteriores; L2 matrixsumlist sobre dbbi/faed;
L3 sufixos de 'last words before archi choice' (+ 'ans too'); L4 mini yellowblueprimes.
Oráculos duros: G.try_password_all (SMALL/COSMIC/TAIL32, EVP md5+sha256) e G.priv_hit/G.scan_priv."""
import sys, os, hashlib, itertools, json, re
SP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5

LOG = os.path.join(SP, "fresh_designer.jsonl")
open(LOG, "w").close()
G.jsonl(LOG, {"hypothesis": "O autor escreveu a página como fluxo de teclas: 'enter' é a tecla Enter (\\n em hashes/senhas), "
              "'matrixsumlist' é uma operação sobre dbbi/faed em matriz, 'lastwordsbeforearchichoice' é uma pergunta "
              "cuja resposta ('ans too') é sha256'd como senha do SMALL. Espaço finito ~12k senhas × 3 blobs × 2 KDF."})

N = {"aes": 0, "priv": 0}
HARD, SOFT = [], []
seen_pw = set()

def sha(s): return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()

def test_pw(pw, how, blobs=("SMALL", "COSMIC", "TAIL32")):
    if isinstance(pw, str): pw = pw.encode()
    if pw in seen_pw: return
    seen_pw.add(pw)
    hard, soft = G.try_password_all(pw, blobs)
    N["aes"] += 2 * len(blobs)
    for h in hard:
        h.update({"how": how, "pw": pw.decode("latin-1")}); HARD.append(h); G.jsonl(LOG, {"HARD": h})
        print("!!! HARD", h)
    for s in soft:
        s.update({"how": how, "pw": pw.decode("latin-1")[:80]}); SOFT.append(s)

def test_priv(b32, how):
    N["priv"] += 1
    r = G.priv_hit(b32)
    if r:
        HARD.append({"how": how, "priv": b32.hex(), "r": r}); G.jsonl(LOG, {"HARD_PRIV": HARD[-1]}); print("!!! PRIV", HARD[-1])

def forms(x, how):
    """gramática do puzzle + variantes 'enter'."""
    for name, s in (("raw", x), ("lower", x.lower()), ("upper", x.upper()), ("nospace", x.replace(" ", "")),
                    ("lower_nospace", x.lower().replace(" ", "")), ("upper_nospace", x.upper().replace(" ", ""))):
        for suf, sn in (("", ""), ("\n", "+LF"), ("\r\n", "+CRLF")):
            t = s + suf
            test_pw(t, f"{how}|{name}{sn}|raw")
            h = sha(t)
            test_pw(h, f"{how}|{name}{sn}|sha256hex")
            test_pw(h.upper(), f"{how}|{name}{sn}|SHA256HEX")
            test_pw(h + "\n", f"{how}|{name}{sn}|sha256hex+LF")
            test_pw(bytes.fromhex(h), f"{how}|{name}{sn}|sha256raw")
            test_priv(bytes.fromhex(h), f"{how}|{name}{sn}|sha256->priv")

# ---------------------------------------------------------------- controle positivo
def control():
    pt = b"POSITIVE CONTROL: the private key is 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ\n"
    salt = b"\x01" * 8
    k, iv = G.evp(b"ctrl", salt, MD5)
    pad = 16 - len(pt) % 16
    ct = AES.new(k, AES.MODE_CBC, iv).encrypt(pt + bytes([pad]) * pad)
    G.BLOBS["CTRL"] = (salt, ct)
    hard, soft = G.try_password_all("ctrl", ("CTRL",))
    assert hard and hard[0]["kdf"] == "Crypto.Hash.MD5", hard
    assert G.try_password_all("wrong", ("CTRL",))[0] == []
    del G.BLOBS["CTRL"]
    assert G.priv_hit(hashlib.sha256(b"x").digest()) is None
    print("controle positivo OK")

# ---------------------------------------------------------------- L1: enter / last command
def L1():
    n0 = N["aes"]
    page = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "sha256",
            "ourfirsthintisyourlastcommand", "anstoo"]
    prev_pw = {
        "p2_causality": "causality",
        "p2_hash": "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",
        "p3_hash": "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
        "p32_src": "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
        "p32_hash": "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
        "p1_form": "theflowerblossomsthroughwhatseemstobeaconcretesurface",
        "url_hash": "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
        "url_src": "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
        "seed": "theseedisplanted", "seed_url": "gsmg.io/theseedisplanted",
        "beaufort": "THEMATRIXHASYOU", "hashthetext": "HASHTHETEXT",
        "salphaseion": "SalPhaseIon", "cosmic": "Cosmic Duality", "title": "GSMG Puzzle",
        "h1s": "SalPhaseIonCosmicDuality", "yinyang": "yinyang", "ybp": "yellowblueprimes",
        "dbbi": G.DBBI, "faed": G.FAED, "dbbi_sp": " ".join(G.DBBI), "faed_sp": " ".join(G.FAED),
        "roadmap": "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang",
    }
    for k, v in prev_pw.items(): forms(v, "L1prev:" + k)
    # janelas contíguas dos 7 tokens da página, sem/with espaço e com '\n' como junção ("enter")
    for i in range(len(page)):
        for j in range(i + 1, len(page) + 1):
            w = page[i:j]
            if len(w) == 1 and i > 0: forms(w[0], f"L1tok:{w[0]}"); continue
            for sep, sn in (("", "cat"), (" ", "sp"), ("\n", "LF")):
                forms(sep.join(w), f"L1win:{sn}:{i}-{j}")
    # combinação estrita "first hint + ans" com hash de fases anteriores como 'last command'
    for a in ("89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32", "theseedisplanted"):
        for b in ("250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
                  "theflowerblossomsthroughwhatseemstobeaconcretesurface", "causality", "thispassword"):
            forms(a + b, f"L1fh+prev:{a[:8]}+{b[:8]}"); forms(b + a, f"L1prev+fh:{b[:8]}+{a[:8]}")
            test_pw(sha(a) + sha(b), f"L1 sha(fh)+sha(prev) {a[:8]}+{b[:8]}")
            test_pw(sha(sha(a) + sha(b)), f"L1 sha(sha(fh)+sha(prev)) {a[:8]}+{b[:8]}")
    G.jsonl(LOG, {"L1_aes_tests": N["aes"] - n0}); print("L1 aes tests", N["aes"] - n0)

# ---------------------------------------------------------------- L2: matrixsumlist sobre dbbi/faed
def shapes(n):
    return [(r, n // r) for r in range(1, n + 1) if n % r == 0 and 1 < r < n]

def sumlists(s, base):
    d = [ord(c) - 96 - (0 if base else 1) for c in s]
    n = len(d); out = {}
    for r, c in shapes(n):
        M = [d[i * c:(i + 1) * c] for i in range(r)]
        out[f"{r}x{c}:rows"] = [sum(row) for row in M]
        out[f"{r}x{c}:cols"] = [sum(M[i][j] for i in range(r)) for j in range(c)]
        if r == c or True:
            # diagonais (soma por i-j e i+j) só para formas quase quadradas
            if abs(r - c) <= 8:
                out[f"{r}x{c}:diag"] = [sum(M[i][j] for i in range(r) for j in range(c) if i - j == k) for k in range(-(c - 1), r)]
                out[f"{r}x{c}:anti"] = [sum(M[i][j] for i in range(r) for j in range(c) if i + j == k) for k in range(r + c - 1)]
    if n == 91:
        # triângulo 1..13
        tri = []; k = 0
        for L in range(1, 14): tri.append(d[k:k + L]); k += L
        out["tri:rows"] = [sum(t) for t in tri]
        out["tri:cols"] = [sum(t[j] for t in tri if j < len(t)) for j in range(13)]
        # triângulo superior estrito de 14x14 simétrica: somas de linha da matriz completa
        M = [[0] * 14 for _ in range(14)]; k = 0
        for i in range(14):
            for j in range(i + 1, 14): M[i][j] = M[j][i] = d[k]; k += 1
        out["ut14:rows"] = [sum(row) for row in M]
        out["ut14:rows_upper_only"] = [sum(M[i][j] for j in range(i + 1, 14)) for i in range(14)]
        out["ut14:cols_upper_only"] = [sum(M[i][j] for i in range(0, j)) for j in range(14)]
        # ordem espiral: preencher 14x14 pela espiral com dbbi nas primeiras 91 células
        S = [[0] * 14 for _ in range(14)]
        for k, (i, j) in enumerate(G.SPIRAL[:91]): S[i][j] = d[k]
        out["spiral91:rows"] = [sum(row) for row in S]; out["spiral91:cols"] = [sum(S[i][j] for i in range(14)) for j in range(14)]
    out["total"] = [sum(d)]
    return out

def L2():
    n0, p0 = N["aes"], N["priv"]
    for name, s in (("dbbi", G.DBBI), ("faed", G.FAED), ("faed_np", G.FAED[4:]), ("dbbi_faed", G.DBBI + G.FAED)):
        for base in (0, 1):
            for lab, lst in sumlists(s, base).items():
                how = f"L2:{name}:a={base}:{lab}"
                dec = "".join(map(str, lst))
                # (i) método z: decimal -> hex -> bytes
                try:
                    zb = G.z_method(lst) if all(x >= 0 for x in lst) else None
                except Exception:
                    zb = None
                if zb:
                    test_pw(zb, how + "|z_raw"); test_pw(sha(zb), how + "|z_sha")
                    if G.printable(zb) > 0.85: test_pw(zb.decode("latin-1"), how + "|z_ascii"); print("z-ascii", how, zb[:40])
                    for h in G.scan_priv(zb, how): HARD.append({"how": h[0], "where": h[1], "r": h[2]})
                    N["priv"] += max(1, len(zb) - 31)
                # (ii) decimal concatenado / separado por espaço, vírgula
                for sep, sn in (("", "cat"), (" ", "sp"), (",", "comma")):
                    t = sep.join(map(str, lst))
                    test_pw(t, how + f"|dec_{sn}_raw"); test_pw(sha(t), how + f"|dec_{sn}_sha")
                    test_pw(sha(t + "\n"), how + f"|dec_{sn}_shaLF")
                    test_priv(bytes.fromhex(sha(t)), how + f"|dec_{sn}_sha->priv")
                # (iii) mod 26 -> letras
                for off in (0, 1):
                    L = "".join(chr(65 + (x - off) % 26) for x in lst)
                    test_pw(L, how + f"|a1z26({off})_raw"); test_pw(L.lower(), how + f"|a1z26({off})_lower")
                    test_pw(sha(L), how + f"|a1z26({off})_sha"); test_pw(sha(L.lower()), how + f"|a1z26({off})_sha_lower")
                # (iv) bytes mod 256 -> priv / senha
                B = bytes(x % 256 for x in lst)
                test_pw(B, how + "|bytes_raw"); test_pw(sha(B), how + "|bytes_sha")
                test_priv(hashlib.sha256(B).digest(), how + "|sha(bytes)->priv")
                if len(B) >= 32:
                    for h in G.scan_priv(B, how): HARD.append({"how": h[0], "where": h[1], "r": h[2]})
                    N["priv"] += len(B) - 31
                # (v) hex nibbles / 2 dígitos
                H = "".join(f"{x % 256:02x}" for x in lst)
                test_pw(H, how + "|hex_raw"); test_pw(sha(H), how + "|hex_sha")
                if len(bytes.fromhex(H)) == 32: test_priv(bytes.fromhex(H), how + "|hex->priv")
    G.jsonl(LOG, {"L2_aes_tests": N["aes"] - n0, "L2_priv_tests": N["priv"] - p0}); print("L2 aes", N["aes"] - n0, "priv", N["priv"] - p0)

# ---------------------------------------------------------------- L3: last words before archi choice
ARCH = ("Hello Neo. Who are you? I am the Architect. I created the matrix. I've been waiting for you. You have many questions, "
 "and although the process has altered your consciousness, you remain irrevocably human. Ergo, some of my answers you will "
 "understand, and some of them you will not. Concordantly, while your first question may be the most pertinent, you may or may "
 "not realize it is also irrelevant. Why am I here? Your life is the sum of a remainder of an unbalanced equation inherent to "
 "the programming of the matrix. You are the eventuality of an anomaly, which despite my sincerest efforts I have been unable "
 "to eliminate from what is otherwise a harmony of mathematical precision. While it remains a burden assiduously avoided, it "
 "is not unexpected, and thus not beyond a measure of control. Which has led you, inexorably, here. You haven't answered my "
 "question. Quite right. Interesting. That was quicker than the others. Others? What others? How many? What others? The matrix "
 "is older than you know. I prefer counting from the emergence of one integral anomaly to the emergence of the next, in which "
 "case this is the sixth version. There are only two possible explanations: either no one told me, or no one knows. Precisely. "
 "As you are undoubtedly gathering, the anomaly's systemic, creating fluctuations in even the most simplistic equations. Choice. "
 "The problem is choice. The first matrix I designed was quite naturally perfect, it was a work of art, flawless, sublime. A "
 "triumph equaled only by its monumental failure. The inevitability of its doom is as apparent to me now as a consequence of the "
 "imperfection inherent in every human being, thus I redesigned it based on your history to more accurately reflect the varying "
 "grotesqueries of your nature. However, I was again frustrated by failure. I have since come to understand that the answer "
 "eluded me because it required a lesser mind, or perhaps a mind less bound by the parameters of perfection. Thus, the answer "
 "was stumbled upon by another, an intuitive program, initially created to investigate certain aspects of the human psyche. If "
 "I am the father of the matrix, she would undoubtedly be its mother. The Oracle. Please. As I was saying, she stumbled upon a "
 "solution whereby nearly 99.9% of all test subjects accepted the program, as long as they were given a choice, even if they "
 "were only aware of the choice at a near unconscious level. While this answer functioned, it was obviously fundamentally "
 "flawed, thus creating the otherwise contradictory systemic anomaly, that if left unchecked might threaten the system itself. "
 "Ergo, those that refused the program, while a minority, if unchecked, would constitute an escalating probability of disaster. "
 "This is about Zion. You are here because Zion is about to be destroyed. Its every living inhabitant terminated, its entire "
 "existence eradicated. Bullshit. Denial is the most predictable of all human responses. But, rest assured, this will be the "
 "sixth time we have destroyed it, and we have become exceedingly efficient at it. The function of the One is now to return to "
 "the source, allowing a temporary dissemination of the code you carry, reinserting the prime program. After which you will be "
 "required to select from the matrix 23 individuals, 16 female, 7 male, to rebuild Zion. Failure to comply with this process "
 "will result in a cataclysmic system crash killing everyone connected to the matrix, which coupled with the extermination of "
 "Zion will ultimately result in the extinction of the entire human race. You won't let it happen, you can't. You need human "
 "beings to survive. There are levels of survival we are prepared to accept. However, the relevant issue is whether or not you "
 "are ready to accept the responsibility for the death of every human being in this world. It is interesting reading your "
 "reactions. Your five predecessors were by design based on a similar predication, a contingent affirmation that was meant to "
 "create a profound attachment to the rest of your species, facilitating the function of the One. While the others experienced "
 "this in a very general way, your experience is far more specific. Vis-a-vis, love. Trinity. Apropos, she entered the matrix "
 "to save your life at the cost of her own. No. Which brings us at last to the moment of truth, wherein the fundamental flaw is "
 "ultimately expressed, and the anomaly revealed as both beginning, and end. There are two doors. The door to your right leads "
 "to the source, and the salvation of Zion. The door to your left leads back to the matrix, to her, and to the end of your "
 "species. As you adequately put, the problem is choice. But we already know what you're going to do, don't we? Already I can "
 "see the chain reaction, the chemical precursors that signal the onset of an emotion, designed specifically to overwhelm logic, "
 "and reason. An emotion that is already blinding you from the simple, and obvious truth: she is going to die, and there is "
 "nothing that you can do to stop it. No. Hope, it is the quintessential human delusion, simultaneously the source of your "
 "greatest strength, and your greatest weakness. If I were you, I would hope that we don't meet again. We won't.")

def L3():
    n0, p0 = N["aes"], N["priv"]
    words = re.findall(r"[A-Za-z0-9']+", ARCH)
    lw = [w.lower().replace("'", "") for w in words]
    stops = {}
    def stop_at(phrase, label):
        i = ARCH.find(phrase); assert i >= 0, phrase
        stops[label] = len(re.findall(r"[A-Za-z0-9']+", ARCH[:i]))
    stop_at("There are two doors", "before_two_doors")
    stop_at("The door to your right", "before_door_right")
    stop_at("As you adequately put, the problem is choice", "before_problem_is_choice")
    stop_at("But we already know", "after_problem_is_choice")
    stop_at("Choice. The problem is choice.", "before_choice1")
    stop_at("The first matrix I designed", "after_choice1")
    stop_at("No. Hope, it is", "before_no_hope")
    stop_at("We won't.", "before_we_wont")
    stops["end"] = len(lw)
    # texto do puzzle (3.2.1): antes de SELECT
    p32 = re.search(r"YOUR LIFE IS THE SUM.*?CIAO BELLA O", open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read(), re.S).group(0)
    pw32 = [w.lower().replace("'", "") for w in re.findall(r"[A-Za-z0-9']+", p32)]
    i_sel = pw32.index("select")
    sources = [("film", lw, stops), ("p32", pw32, {"before_select": i_sel, "end": len(pw32),
                                                       "before_required": pw32.index("required")})]
    FH = ["89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32", "theseedisplanted",
          "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", "matrixsumlist"]
    for src, W, st in sources:
        for lab, idx in st.items():
            for k in range(1, 16):
                if idx - k < 0: break
                ans_sp = " ".join(W[idx - k:idx]); ans = ans_sp.replace(" ", "")
                how = f"L3:{src}:{lab}:k={k}"
                for v, vn in ((ans, "nospace"), (ans.upper(), "UPPER"), (ans_sp, "spaced")):
                    test_pw(v, how + f"|{vn}_raw"); test_pw(sha(v), how + f"|{vn}_sha")
                    test_pw(sha(v + "\n"), how + f"|{vn}_shaLF"); test_priv(bytes.fromhex(sha(v)), how + f"|{vn}_sha->priv")
                # 'ans too': combinar com first hint
                for fh in FH:
                    test_pw(sha(fh + ans), how + f"|sha(fh+ans):{fh[:6]}")
                    test_pw(sha(ans + fh), how + f"|sha(ans+fh):{fh[:6]}")
                    test_pw(sha(fh) + sha(ans), how + f"|sha(fh)+sha(ans):{fh[:6]}")
                    test_pw(sha(sha(fh) + sha(ans)), how + f"|sha(sha(fh)+sha(ans)):{fh[:6]}")
                    x = bytes(a ^ b for a, b in zip(bytes.fromhex(sha(fh)), bytes.fromhex(sha(ans))))
                    test_pw(x.hex(), how + f"|xor_hex:{fh[:6]}"); test_priv(x, how + f"|xor->priv:{fh[:6]}")
    G.jsonl(LOG, {"L3_aes_tests": N["aes"] - n0, "L3_priv_tests": N["priv"] - p0}); print("L3 aes", N["aes"] - n0, "priv", N["priv"] - p0)

# ---------------------------------------------------------------- L4 mini: yellowblueprimes sobre dbbi
def L4():
    n0 = N["aes"]
    primes = [p for p in range(2, 91) if G.is_prime(p)]; assert len(primes) == 24
    cols = [G.COLORED[i][0] for i in sorted(G.COLORED) if G.COLORED[i][0] != "W*"]; assert len(cols) == 24
    for base in (0, 1):
        for keep, kn in (("B", "blue"), ("Y", "yellow")):
            sel = "".join(G.DBBI[p - base] for p, c in zip(primes, cols) if c == keep and p - base < 91)
            rest = "".join(G.DBBI[p - base] for p, c in zip(primes, cols) if c != keep and p - base < 91)
            zero = "".join(("a" if (i + base) in primes and cols[primes.index(i + base)] == keep else ch) for i, ch in enumerate(G.DBBI)) if base == 0 else \
                   "".join(("a" if (i + base) in primes and cols[primes.index(i + base)] == keep else ch) for i, ch in enumerate(G.DBBI))
            drop = "".join(ch for i, ch in enumerate(G.DBBI) if not ((i + base) in primes and cols[primes.index(i + base)] == keep))
            for lab, s in ((f"sel_{kn}", sel), (f"rest_{kn}", rest), (f"zero_{kn}", zero), (f"drop_{kn}", drop)):
                how = f"L4:b{base}:{lab}"
                forms(s, how)
                d = [ord(c) - 96 for c in s]
                zb = G.z_method(d); test_pw(zb, how + "|z_raw"); test_pw(sha(zb), how + "|z_sha")
                if G.printable(zb) > 0.85: print("L4 z-ascii", how, zb)
                for h in G.scan_priv(zb, how): HARD.append({"how": h[0], "where": h[1], "r": h[2]})
                N["priv"] += max(1, len(zb) - 31)
    G.jsonl(LOG, {"L4_aes_tests": N["aes"] - n0}); print("L4 aes", N["aes"] - n0)

if __name__ == "__main__":
    control(); L1(); L2(); L3(); L4()
    SOFT.sort(key=lambda s: -s["printable"])
    summary = {"n_aes": N["aes"], "n_priv": N["priv"], "n_pw": len(seen_pw), "hard": HARD, "soft_top": SOFT[:10], "n_soft": len(SOFT)}
    G.jsonl(LOG, {"SUMMARY": summary})
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:4000])
