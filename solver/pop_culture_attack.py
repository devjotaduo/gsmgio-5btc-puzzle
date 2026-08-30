# -*- coding: utf-8 -*-
"""Ataque pop-cultura (nao obvio):
A. titulos/nomes como keyword do quadrado Bifid (SALPHASEION = anagrama de ALPHA+NOESIS);
B. o mapeamento do discurso ORIGINAL do Arquiteto: 'select 23 individuals -- 16 female,
   7 male' -> chave das 7 palavras do header28 x IV de 16 bytes (a combinacao nunca testada);
C. frases canonicas de Matrix/2001/Mr.Robot/Alice/Bitcoin como senha (35 blocos, SMALL, COSMIC);
D. formas raw (com pontuacao/caixa original) no EVP do SMALL, frontier da retratacao #104.
"""
from __future__ import annotations
import hashlib, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
from search import bifid_decrypt
from scorer import Scorer

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"
FILLER = "ABCDEFGHIJKLMNOPRSTUVWXYZ"  # A-Z sem Q? nao: sem J (I=J)


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


def keyed(text: str) -> str:
    """Quadrado Polybius: 1as ocorrencias (J->I) + filler A-Z sem J."""
    t = re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")
    seen = "".join(dict.fromkeys(t))
    filler = "".join(c for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ" if c not in seen)
    sq = (seen + filler)[:25]
    return sq if len(set(sq)) == 25 else ""


def try_aes(label, key, iv, body, hard, soft):
    if len(key) != 32 or len(iv) != 16:
        return
    try:
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
    except ValueError:
        return
    if valid_pt(pt) or b"Salted__" in pt:
        soft.append({"label": label, "head": pt[:80].hex()})
    for j in range(0, len(pt) - 31, 16):
        if matches_pubkey(pt[j:j + 32]):
            hard.append({"label": f"{label}_off{j}", "priv": pt[j:j + 32].hex()})


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    blocks = [body[i * 32:(i + 1) * 32] for i in range(35)]
    half, bh, cosmic = R["half"], R["better_half"], R["cosmic"]
    chain1, chain2, mt = R["chain1"], R["chain2"], R["matrix_tail"]
    small_salt, small_ct = O.blobs()["SMALL"]
    cosmic_salt, cosmic_ct = O.blobs()["COSMIC"]
    src = O.sources()
    faed = src["faed"].upper().replace("J", "I")
    dbbi = src["dbbi"].upper().replace("J", "I")
    sc = Scorer()
    hard, soft = [], []

    # ================= A. quadrados keyed por titulos/nomes =================
    keywords = [
        "SALPHASEION", "COSMICDUALITY", "ALPHANOESIS", "NOESIS", "THEKEYMAKER",
        "KEYMAKER", "TEMETNOSCE", "KNOWTHYSELF", "MEROVINGIAN", "PERSEPHONE",
        "SERAPH", "MOBILAVE", "MOBILAVENUE", "ZION", "ZIONMAINFRAME",
        "NEBUCHADNEZZAR", "METACORTEX", "DUJOUR", "FOLLOWTHEWHITERABBIT",
        "WHITERABBIT", "GOASKALICE", "FEEDYOURHEAD", "JABBERWOCKY", "CHESHIRECAT",
        "MADHATTER", "RABBITHOLE", "HALFINNEY", "SAL9000", "HAL9000", "DAISYBELL",
        "MONOLITH", "YINGYANG", "YINYANG", "THEORACLE", "ORACLE", "THEARCHITECT",
        "ARCHITECT", "THEMATRIX", "MORPHEUS", "TRINITY", "NEO", "THEONE", "CYPHER",
        "AGENTSMITH", "SMITH", "RELOADED", "REVOLUTIONS", "ANIMATRIX",
        "HEARTOTHECITY", "WABASHANDLAKE", "DORMOUSE", "THETRAINMAN", "RAMAKANDRA",
        "SATI", "EPS35QU4RTZDECR1P7ND4C0DEPERL", "QU4RTZ", "REDWHEELBARROW",
        "FSOCIETY", "WHITEROSE", "BONSOIRELLIOT", "THEVENUSPROJECT",
        "THECHOICEISOURS", "LOOKINGFORWARD", "CHANCELLORONBRINKOFSECONDBAILOUT",
    ]
    base_out = bifid_decrypt(faed, CANON, 570)
    base_score = sc(base_out)
    print(f"[A] baseline canon p570: {base_score:.3f} | {base_out[:20]}")
    results = []
    for kw in keywords:
        sq = keyed(kw)
        if not sq:
            continue
        for period in (570, 91, 38, 13, 7):
            out = bifid_decrypt(faed, sq, period)
            s = sc(out)
            results.append((s, kw, period, out))
            if "BTCSEED" in out or s > -4.6:
                soft.append({"label": f"sq_{kw}_p{period}", "score": round(s, 3), "head": out[:48]})
        for period in (91, 13, 7):
            out = bifid_decrypt(dbbi, sq, period)
            s = sc(out)
            results.append((s, kw + ":dbbi", period, out))
            if s > -4.6:
                soft.append({"label": f"sqdbbi_{kw}_p{period}", "score": round(s, 3), "head": out[:48]})
    results.sort(key=lambda r: -r[0])
    print("[A] top 8 quadrados-keyword (faed|dbbi):")
    for s, kw, period, out in results[:8]:
        print(f"  {s:8.3f}  {kw:34s} p={period:3d}  {out[:36]}")
    # melhores saidas como material de chave
    for s, kw, period, out in results[:5]:
        sha = hashlib.sha256(out.encode("latin-1")).digest()
        if matches_pubkey(sha):
            hard.append({"label": f"sha256(sq_{kw}_p{period})", "priv": sha.hex()})
        try_aes(f"sq_{kw}_p{period}", sha, b"\x00" * 16, body, hard, soft)
        pt = evp_open(small_salt, small_ct, out.encode("latin-1"))
        if pt and pr(pt) >= 0.85:
            soft.append({"label": f"sq_{kw}_p{period}_SMALL", "ascii": round(pr(pt), 3), "head": pt[:60].hex()})
    # null-check se algo prometer
    best = results[0]
    if best[0] > -5.0:
        import random
        sq = keyed(best[1].split(":")[0])
        hits = 0
        for _ in range(2000):
            shuffled = list(sq)
            random.shuffle(shuffled)
            out = bifid_decrypt(faed, "".join(shuffled), best[2])
            if sc(out) >= best[0]:
                hits += 1
        print(f"[A] null-check: {hits}/2000 shuffles >= {best[0]:.3f}")

    # ================= B. 16 female x 7 male: chave de 7 palavras x IV 16B =================
    words = [header28[i * 4:(i + 1) * 4] for i in range(7)]
    w_concat = b"".join(words)
    sha_words = [hashlib.sha256(w).digest() for w in words]
    k7 = {
        "sha_hdr28": hashlib.sha256(header28).digest(),
        "sha_hdr28hex": hashlib.sha256(header28.hex().encode()).digest(),
        "sha_dec7": hashlib.sha256("".join(str(int.from_bytes(w, "big")) for w in words).encode()).digest(),
        "sha_wcat": hashlib.sha256(w_concat).digest(),
        "evp_hdr28": evp_kdf(header28, R["chain4_blob"][8:16])[0],
        "evp_wcat": evp_kdf(w_concat, R["chain4_blob"][8:16])[0],
        "sha4of7+7pad": b"".join(s[:4] for s in sha_words) + b"\x07" * 4,
        "interleave7+pad4": bytes(w[j] for j in range(4) for w in words) + w_concat[:4],
    }
    iv16 = {
        "half_lo": half[:16], "half_hi": half[16:], "bh_lo": bh[:16], "bh_hi": bh[16:],
        "xor_lo": xor_bytes(half, bh)[:16], "h8bh8": half[:8] + bh[:8],
        "blk0": blocks[0][:16], "blk34": blocks[34][:16], "hdr_lo": header28[:16],
        "hdr_hi": header28[12:28], "cosmic": cosmic[16:32], "c1_64": chain1[64:80],
        "c2_64": chain2[64:80], "mt_lo": mt[:16], "c4pw": F.CHAIN4_PASSWORD[:16],
    }
    for kn, key in k7.items():
        for ivn, iv in iv16.items():
            try_aes(f"B_{kn}x{ivn}", key, iv, body, hard, soft)
    # direcao inversa: chave = dualidade, IV = 7 palavras
    keys_d = {
        "half": half, "bh": bh, "xor": xor_bytes(half, bh),
        "sha_hbh": hashlib.sha256(half + bh).digest(),
        "sha_bhh": hashlib.sha256(bh + half).digest(),
        "c4pw": F.CHAIN4_PASSWORD, "sha_c4pw": hashlib.sha256(F.CHAIN4_PASSWORD).digest(),
    }
    ivs_w = {
        "w1-4": w_concat[:16], "w4-7": w_concat[12:28],
        "ilv16": bytes(w[j] for j in range(4) for w in words)[:16],
        "sha_w1": sha_words[0][:16],
    }
    for kn, key in keys_d.items():
        for ivn, iv in ivs_w.items():
            try_aes(f"B2_{kn}x{ivn}", key, iv, body, hard, soft)

    # ================= C. frases pop como senha =================
    quotes = [
        # Matrix (as que espelham os hints)
        "NOONECANBETOLDWHATTHEMATRIXIS", "YOUHAVETOSEEITFORYOURSELF",
        "ICANONLYSHOWYOUTHEDOOR", "ICANONLYSHOWYOUTHEDOORYOUHAVETOWALKTHROUGHIT",
        "THEREISNOSPOON", "ITISNOTTHESPOONTHATBENDSITISONLYYOURSELF",
        "IGNORANCEISBLISS", "FREEMYOURMIND", "KNOCKKNOCKNEO",
        "WAKEUPNEOTHEMATRIXHASYOUFOLLOWTHEWHITERABBIT", "THEMATRIXHASYOU",
        "TEMETNOSCE", "KNOWTHYSELF", "YOUVEALREADYMADETHECHOICE",
        "EVERYTHINGTHATHASABEGINNINGHASANEND", "THEPROBLEMISCHOICE",
        "CHOICEISANILLUSION", "METACORTEX", "HEARTOTHECITY", "WABASHANDLAKE",
        "MARK3NO11", "ZIONMAINFRAME", "MOBILAVENUE", "RAMAKANDRA", "KAMALA", "SATI",
        "THEKEYMAKER", "MEROVINGIAN", "PERSEPHONE", "SERAPH", "THETRAINMAN",
        "CYPHER", "DUJOUR", "OFTHEDAY", "MYOWNPERSONALJESUSCHRIST", "MRREAGAN",
        "WOMANINREDDRESS", "DIGITALRAIN", "THEREARETWODOORS",
        "THEDOORTOTHELEFT", "THEDOORTOTHERIGHT", "THEDOORTOTHERIGHTLEADSTOTHESOURCE",
        "THEANOMALYREVEALEDASBOTHBEGINNINGANDEND", "RIGHTASRAIN",
        "AWORLDWHEREANYTHINGISPOSSIBLE", "WHEREWEGOFROMTHEREISACHOICEILEAVETOFYOU",
        "HOWDOYOUDEFINEREAL", "THEMATRIXISCONTROL", "THEMATRIXISASYSTEM",
        "THEREISADIFFERENCEBETWEENKNOWINGTHEPATHANDWALKINGTHEPATH",
        "SHEISGOINGTODIEANDTHEREISNOTHINGYOUCANDOTOSTOPIT",
        "DENIALISTHEMOSTPREDICTABLEOFALLHUMANRESPONSES",
        "TRINITY", "THEONE", "SIXTHVERSION", "ROOM101", "ROOM303", "303", "101",
        # 2001 / HAL / SAL
        "HAL9000", "SAL9000", "DAISYBELL", "DAISYDAISYGIVEMEYOURANSWERDO",
        "ABICYCLEBUILTFORTWO", "OPENTHEPODBAYDOORSHAL", "TMA1", "MONOLITH",
        "TYCHOMAGNETICANOMALY",
        # Mr. Robot (eps3.5 dupla + poema + saudacao)
        "EPS35QU4RTZDECR1P7ND4C0DEPERL", "QU4RTZ", "QUARTZ", "KILLPR0CESSINC",
        "KILLPROCESS", "REDWHEELBARROW",
        "SOMUCHDEPENDSUPONAREDWHEELBARROWGLAZEDWITHRAINWATERBESIDETHEWHITECHICKENS",
        "BONSOIRELLIOT", "FSOCIETY", "FSOCIETY00DAT", "WHITEROSE", "DARKARMY",
        "HELLOFRIEND", "SHREDUZN3", "M4STERSL4VE", "EPS34M4STERSL4VEAXSX",
        # Venus Project / Bitcoin
        "THEVENUSPROJECT", "THECHOICEISOURS", "LOOKINGFORWARD", "JACQUEFRESCO",
        "HALFINNEY", "SATOSHINAKAMOTO", "CHANCELLORONBRINKOFSECONDBAILOUTFORBANKS",
        "THETIMES03JAN2009",
        # grafias 'erradas' do proprio puzzle + anagrama
        "YINGYANG", "FOURTY", "WAISTING", "THROPHIES", "PRIVATEKEYNOTE",
        "ARCHICHOICE", "CIAOBELLA", "CIAOBELLAO", "ALPHANOESIS", "NOESIS",
    ]
    for q in quotes:
        pw = q.encode()
        sha = hashlib.sha256(pw).digest()
        if matches_pubkey(sha):
            hard.append({"label": f"sha256({q})", "priv": sha.hex()})
        try_aes(f"q_{q[:24]}", sha, b"\x00" * 16, body, hard, soft)
        try_aes(f"q_{q[:24]}", sha, header28[:16], body, hard, soft)
        try_aes(f"q_{q[:24]}", sha, half[:16], body, hard, soft)
        # frontier da retratacao: SMALL com plaintext semantico
        pt = evp_open(small_salt, small_ct, pw)
        if pt and pr(pt) >= 0.85:
            soft.append({"label": f"SMALL_{q[:24]}", "ascii": round(pr(pt), 3), "head": pt[:60].hex()})
        pt2 = evp_open(small_salt, small_ct, sha.hex().encode())
        if pt2 and pr(pt2) >= 0.85:
            soft.append({"label": f"SMALLsha_{q[:24]}", "ascii": round(pr(pt2), 3)})

    # ================= D. formas raw (pontuacao/caixa original) no EVP =================
    raws = [
        b"so much depends upon\n\na red wheel\n\nbarrow\n\nglazed with rain\n\nwater\n\nbeside the white\n\nchickens",
        b"so much depends upon a red wheel barrow glazed with rain water beside the white chickens",
        b"Daisy, Daisy, give me your answer do",
        b"ciao bella o", b"Ciao bella O", b"ying yang", b"yin yang",
        b"qu4rtz.decr1p7.nd4c0de.perl", b"eps3.5_kill-pr0cess.inc",
        b"eps3.4_m4ster-sl4ve.axsx", b"shred -uzn 3", b"shred -uzn3",
        b"fsociety00.dat", b"hello friend.", b"bonsoir, elliot",
        b"Mark 3 No. 11", b"MARK 3 No. 11", b"temet nosce",
        b"No one can be told what the Matrix is. You have to see it for yourself.",
        b"the seed is planted", b"theseedisplanted", b"gsmg.io/theseedisplanted",
        b"Salphaseion", b"salphaseion", b"Cosmic Duality", b"cosmicduality",
        b"alpha noesis", b"Alpha Noesis",
    ]
    for raw in raws:
        for pw in (raw, raw.upper().replace(b" ", b"")):
            pt = evp_open(small_salt, small_ct, pw)
            if pt and pr(pt) >= 0.85:
                soft.append({"label": f"SMALLraw_{pw[:24]!r}", "ascii": round(pr(pt), 3)})
            pt = evp_open(cosmic_salt, cosmic_ct, pw)
            if pt and pr(pt) >= 0.85:
                soft.append({"label": f"COSMICraw_{pw[:24]!r}", "ascii": round(pr(pt), 3)})
            sha = hashlib.sha256(pw).digest()
            if matches_pubkey(sha):
                hard.append({"label": f"sha256({pw[:24]!r})", "priv": sha.hex()})
            try_aes(f"raw_{pw[:20]!r}", sha, b"\x00" * 16, body, hard, soft)

    # ================= relatorio =================
    print("=" * 60)
    print("ATAQUE POP-CULTURA - oraculo duro")
    print("=" * 60)
    print(f"HARD hits: {len(hard)}")
    print(f"SOFT hits: {len(soft)}")
    if hard:
        print("\n!!! SOLVE !!!")
        for h in hard:
            print(f"  {h}")
    if soft:
        print("\n--- soft hits ---")
        for s in soft[:30]:
            print(f"  {s}")
    if not hard and not soft:
        print("NEGATIVO — pop-cultura nas leituras naturais nao fecha o oraculo.")


if __name__ == "__main__":
    main()
