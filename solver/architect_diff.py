# -*- coding: utf-8 -*-
"""Diff sistematico: monologo do puzzle (fase 3.2, Beaufort/THEMATRIXHASYOU) vs
discurso ORIGINAL do Arquiteto (Matrix Reloaded, transcript publico). Hipotese:
'its in front of your eyes but you're not seeing it' = as DIFERENCAS sao o sinal.
Extrai: palavras inseridas/duplicadas, grafias 'erradas' (letras extras), mapa de
letras ONE->YOU, posicoes como indices; testa tudo em oraculo duro.
Fontes do original: matrixfans.net / scottmanning.com transcripts (concordantes).
"""
from __future__ import annotations
import difflib, hashlib, itertools, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
from search import bifid_decrypt

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"

PUZZLE = """YOUR LIFE IS THE SUM OF A REMAINDER OF AN UNBALANCED EQUATION INHERENT TO THE PROGRAMMING OF THIS PUZZLE
YOU ARE THE EVENTUALITY OF AN ANOMALY WHICH DESPITE MY SINCEREST EFFORTS I HAVE BEEN UNABLE TO ELIMINATE
FROM WHAT IS OTHERWISE A HARMONY OF MATHEMATICAL PRECISION WHILE IT REMAINS A BURDEN TO SEDULOUSLY AVOID IT
IT IS NOT UNEXPECTED AND THUS NOT BEYOND A MEASURE OF CONTROL WHICH HAS LED YOU INEXORABLY HERE YOU
YOU HAVEN'T ANSWERED MY QUESTION ME QUITE RIGHT INTERESTING THAT WAS QUICKER THAN THE OTHERS PLEASE IF YOU
FIND A WAY TO COMPLETE THE LAST PART OF THE PUZZLE TAKE THE PRIVATE KEY YOUVE EARNED IT BUT PLEASE TAKE
THIS TO HEART THAT WHAT A WISEMAN ABOVE HINTED AT IS WORTH HUNDRED FOURTY OF THE INVESTMENT THAT'S
WHAT US GUYS AT GSMG ARE TRYING TO ACCOMPLISH IN THE END PLEASE JUST HELP US BUILD IT INSTEAD OF JUST
WAISTING YOUR LIFETIME BY HUNTING FOR WORTHLESS PRICES AND THROPHIES LIKE THIS I'M SORRY TO
TELL YOU THAT YOUVE COME THIS FAR BUT YOU'LL NEVER FINISH THE LAST TASK I EXPECT YOU TO SAY BULLSHIT
WELL DENIAL IS THE MOST PREDICTABLE OF ALL HUMAN RESPONSES BUT REST ASSURED THIS WILL NOT BE THE LAST TIME
I HAVE DESTROYED A RESTLESS SOUL AND I HAVE BECOME EXCEEDINGLY EFFICIENT AT IT THE FUNCTION OF THE YOU IS
NOW TO RETURN TO THE SOURCE CODES ALLOWING A TEMPORARY DISSEMINATION OF THE CODE YOU HOPEFULLY CARRY
REINSERTING THE PRIME BASICS AFTER WHICH YOU WILL BE REQUIRED TO SELECT FROM OVER TWENTY-THREE CIPHERS
SIXTEEN ENCRYPTIONS AND OR SEVEN INTERTWINED PASSWORDS TO FIND THE ACTUAL PRIVATE KEYNOTE THAT ALSO
BRUTE FORCING MIGHT BE REQUIRED FAILURE TO COMPLY WITH THIS PROCESS WILL RESULT IN A CATACLYSMIC
SYSTEM CRASH KILLING YOUR WILLPOWER WHICH COUPLED WITH THE EXTERMINATION OF YOUR WILL TO LIVE AND WILL
ULTIMATELY RESULT IN THE EXTINCTION OF THE ENTIRENESS OF YOURSELF SELF GOOD LUCK NEVERTHELESS I REALLY
HOPE YOURE THE ONE CIAO BELLA O"""

# Segmentos cobertos pelo puzzle, na ordem do filme (Neo incluso onde o puzzle fundiu)
ORIGINAL = """Your life is the sum of a remainder of an unbalanced equation inherent to the programming of the matrix.
You are the eventuality of an anomaly, which, despite my sincerest efforts, I have been unable to eliminate
from what is otherwise a harmony of mathematical precision. While it remains a burden to sedulously avoid
it, it is not unexpected, and thus not beyond a measure of control. Which has led you, inexorably, here.
You haven't answered my question. Quite right. Interesting. That was quicker than the others.
Bullshit. Denial is the most predictable of all human responses, but rest assured, this will be the sixth
time we have destroyed it, and we have become exceedingly efficient at it.
The function of the One is now to return to the source, allowing a temporary dissemination of the code you
carry, reinserting the prime program. After which, you will be required to select from the matrix 23
individuals, 16 female, 7 male, to rebuild Zion. Failure to comply with this process will result in a
cataclysmic system crash, killing everyone connected to the matrix, which, coupled with the extermination
of Zion, will ultimately result in the extinction of the entire human race."""


def matches_pubkey(s: bytes) -> bool:
    if len(s) != 32 or not any(s):
        return False
    try:
        return PublicKey.from_valid_secret(s).format(compressed=False) == TARGET_PUBKEY
    except ValueError:
        return False


def pr(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data)


def valid_pt(d: bytes) -> bool:
    if not d or len(d) % 16:
        return False
    p = d[-1]
    if not 1 <= p <= 16 or not d.endswith(bytes([p]) * p):
        return False
    return pr(d[:-p]) >= 0.80


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def evp_kdf(pw: bytes, salt: bytes):
    d = d_i = b""
    while len(d) < 48:
        d_i = hashlib.md5(d_i + pw + salt).digest()
        d += d_i
    return d[:32], d[32:48]


def evp_open(salt: bytes, ct: bytes, pw: bytes):
    key, iv = evp_kdf(pw, salt)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if not pt or len(pt) % 16:
        return None
    p = pt[-1]
    if not 1 <= p <= 16 or not pt.endswith(bytes([p]) * p):
        return None
    return pt[:-p]


def words(text: str):
    return re.sub(r"[^A-Z0-9'\- ]", " ", text.upper()).split()


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    blocks = [body[i * 32:(i + 1) * 32] for i in range(35)]
    small_salt, small_ct = O.blobs()["SMALL"]
    cosmic_salt, cosmic_ct = O.blobs()["COSMIC"]
    src = O.sources()
    faed = src["faed"].upper().replace("J", "I")
    hard, soft = [], []

    pw_list, key_list = [], {}

    def add_pw(label: str, pw: bytes):
        sha = hashlib.sha256(pw).digest()
        if matches_pubkey(sha):
            hard.append({"label": f"sha256({label})", "priv": sha.hex()})
        if len(pw) == 32 and matches_pubkey(pw):
            hard.append({"label": f"raw({label})", "priv": pw.hex()})
        for ivn, iv in (("zero", b"\x00" * 16), ("hdr", header28[:16])):
            key = sha
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            if valid_pt(pt) or b"Salted__" in pt:
                soft.append({"label": f"{label}_aes_{ivn}", "head": pt[:60].hex()})
            for j in range(0, len(pt) - 31, 16):
                if matches_pubkey(pt[j:j + 32]):
                    hard.append({"label": f"{label}_aes_{ivn}_off{j}", "priv": pt[j:j + 32].hex()})
        for nm, salt, ct in (("SMALL", small_salt, small_ct), ("COSMIC", cosmic_salt, cosmic_ct)):
            pt = evp_open(salt, ct, pw)
            if pt and pr(pt) >= 0.85:
                soft.append({"label": f"{label}_{nm}", "ascii": round(pr(pt), 3)})
            pt = evp_open(salt, ct, sha.hex().encode())
            if pt and pr(pt) >= 0.85:
                soft.append({"label": f"{label}_{nm}_sha", "ascii": round(pr(pt), 3)})

    # ================= diff palavra-a-palavra =================
    p_w, o_w = words(PUZZLE), words(ORIGINAL)
    print(f"[diff] puzzle {len(p_w)} palavras | original {len(o_w)} palavras")
    sm = difflib.SequenceMatcher(a=o_w, b=p_w, autojunk=False)
    deviations = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        ctx_pre = " ".join(o_w[max(0, i1 - 2):i1])
        ctx_pos = " ".join(o_w[i2:i2 + 2])
        deviations.append({
            "tag": tag, "original": " ".join(o_w[i1:i2]), "puzzle": " ".join(p_w[j1:j2]),
            "antes": ctx_pre, "depois": ctx_pos, "pos_puzzle": j1,
        })
    print("\n===== DESVIOS (original -> puzzle) =====")
    for d in deviations:
        print(f"[{d['tag']:7s}] {d['antes']!r} >> {d['original']!r} -> {d['puzzle']!r}")
    # palavras duplicadas no puzzle (w[k] == w[k-1])
    dup = [(i, w) for i, w in enumerate(p_w) if i and w == p_w[i - 1]]
    print(f"\nduplicadas: {dup}")

    # ================= extracoes concretas =================
    inserted = ["YOU", "ME", "SELF", "HOPEFULLY", "NEVERTHELESS", "CIAOBELLA", "CIAOBELLAO",
                "YOUMESELF", "YOUMESELFANDWILL", "WILLTO LIVE".replace(" ", ""), "ANDWILL"]
    add_pw("you", b"YOU"); add_pw("me", b"ME"); add_pw("self", b"SELF")
    add_pw("yomeself", b"YOUMESELF"); add_pw("you_me_self", b"YOU ME SELF")
    add_pw("hopefully", b"HOPEFULLY"); add_pw("nevertheless", b"NEVERTHELESS")
    add_pw("ciaobella", b"CIAOBELLA"); add_pw("ciaobellao", b"CIAOBELLAO")
    add_pw("goodluck", b"GOODLUCK"); add_pw("wiseman", b"WISEMAN")
    add_pw("restlesssoul", b"RESTLESSSOUL"); add_pw("keynote", b"KEYNOTE")
    add_pw("privatekeynote", b"PRIVATEKEYNOTE")
    add_pw("sourcecodes", b"SOURCECODES"); add_pw("primebasics", b"PRIMEBASICS")

    # letras extras das grafias 'erradas': FOURTY(U) WAISTING(I) THROPHIES(H) THINGKY(G)
    for perm in itertools.permutations("UIHG"):
        s = "".join(perm)
        add_pw(f"letras_{s}", s.encode())
    # grafias erradas em si
    for s in ("FOURTY", "WAISTING", "THROPHIES", "THINGKY", "FOURTYWAISTINGTHROPHIES"):
        add_pw(s, s.encode())
    add_pw("letras_bytes", bytes([0x55, 0x49, 0x48, 0x47]) * 8)

    # mapa de letras ONE->YOU (O->Y, N->O, E->U) aplicado ao Bifid output
    bif = bifid_decrypt(faed, CANON, 570)
    m = str.maketrans("ONE", "YOU")
    mapped = bif.translate(m)
    add_pw("bif_onemap", mapped.encode())
    add_pw("bifrest_onemap", mapped[7:].encode())
    # inverso YOU->ONE sobre o bif
    m2 = str.maketrans("YOU", "ONE")
    add_pw("bif_youmap", bif.translate(m2).encode())
    add_pw("bifrest_youmap", bif.translate(m2)[7:].encode())

    # posicoes das duplicadas como indices
    hdr7 = [int.from_bytes(header28[i * 4:(i + 1) * 4], "big") for i in range(7)]
    idxs = set()
    for i, w in dup:
        idxs.add(i % 35); idxs.add((i + 1) % 35)
    for i in hdr7:
        idxs.add(i % 35)
    # 7(header-words) + 16 = 23 blocos selecionados
    sel_a = sorted(set([h % 35 for h in hdr7]) | set(range(16)))
    sel_b = sorted(set([h % 35 for h in hdr7]) | set(range(19, 35)))
    sel_c = sorted(set([h % 35 for h in hdr7]) | set(range(35 - 16, 35)))
    for nm, sel in (("7w+16first", sel_a), ("7w+16last", sel_c), ("7w+16mid", sel_b)):
        if len(sel) < 2:
            continue
        x = bytes(32)
        t = 0
        for i in sel:
            x = xor_bytes(x, blocks[i])
            t = (t + int.from_bytes(blocks[i], "big")) % (1 << 256)
        add_pw(f"sel_{nm}_xor", x)
        add_pw(f"sel_{nm}_add", t.to_bytes(32, "big"))
    # exatamente 23 blocos: 7 do header + 16 seguintes/depois
    for base_mode in ("first", "skip7"):
        sel = set([h % 35 for h in hdr7])
        if base_mode == "first":
            for i in range(35):
                if len(sel) >= 23:
                    break
                sel.add(i)
        else:
            for i in range(34, -1, -1):
                if len(sel) >= 23:
                    break
                sel.add(i)
        sel = sorted(sel)[:23]
        x = bytes(32)
        t = 0
        for i in sel:
            x = xor_bytes(x, blocks[i])
            t = (t + int.from_bytes(blocks[i], "big")) % (1 << 256)
        add_pw(f"23sel_{base_mode}_xor", x)
        add_pw(f"23sel_{base_mode}_add", t.to_bytes(32, "big"))

    # 'hundred fourty' = 140: char/word 140 do monologo e do faed
    flat = re.sub(r"\s+", " ", PUZZLE.upper())
    add_pw("mono_char140_32", flat[140:172].encode())
    add_pw("mono_word140", " ".join(words(flat)[139:140]).encode())
    add_pw("faed_140_172", faed[140:172].encode())
    add_pw("faed_140_172_lower", faed[140:172].lower().encode())
    add_pw("mono_words139to171", " ".join(words(flat)[139:171]).encode())

    # ================= relatorio =================
    print()
    print("=" * 60)
    print("DIFF ARQUITETO - oraculo duro")
    print("=" * 60)
    print(f"HARD hits: {len(hard)}")
    print(f"SOFT hits: {len(soft)}")
    if hard:
        print("\n!!! SOLVE !!!")
        for h in hard:
            print(f"  {h}")
    if soft:
        print("\n--- soft hits ---")
        for s in soft[:20]:
            print(f"  {s}")
    if not hard and not soft:
        print("NEGATIVO — nenhum candidato do diff fecha o oraculo.")


if __name__ == "__main__":
    main()
