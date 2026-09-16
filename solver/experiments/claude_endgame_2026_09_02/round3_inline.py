# -*- coding: utf-8 -*-
"""
Rodada 3 inline — fecha as leituras R1, R2, R3 e R5 do crítico com o oráculo rápido de padding
(1 AES-ECB no último bloco CBC; decifra tudo só se o padding fechar).

R1  "lastwordsbeforearchichoice": frases curtas (< 15 palavras cada) das falas finais da cena do
    Arquiteto e de Neo antes da escolha das portas, em várias grafias, + composição do roadmap.
R2  TAIL32 × componentes da senha da fase 3 (causality, Safenet, Luna, HSM, 11110, genesis-hex, FEN e
    seus campos) × tokens da 3.2 × tokens de xadrez, concatenações de 2–3 partes (4 partes só no núcleo).
R3  "our first hint is your last command" = a LINHA DE COMANDO openssl literal, em ~1.500 variantes.
R5  g como zero SELETIVO: seletores finitos de quais g's viram 0, depois z-method da página.
Oráculos: padding+G.semantic nos 3 blobs (EVP-SHA256), sha256(senha)→privkey, printable do z-method.
"""
import sys, os, re, io, json, itertools, hashlib, time
SCR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCR)
import gsmg_common as G
from Crypto.Cipher import AES
from coincurve import PublicKey
sys.set_int_max_str_digits(0)

LOG = os.path.join(SCR, "round3_inline.jsonl"); open(LOG, "w").close()
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
N = {"aes": 0, "priv": 0, "z": 0}; HARD = []; SOFT = 0; BEST = []
BL = {}
for name, (salt, ct) in G.BLOBS.items():
    BL[name] = (salt, ct, ct[-32:-16], ct[-16:])

def evp_key(pw, salt):
    d = b""; prev = b""
    while len(d) < 48:
        prev = hashlib.sha256(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]
def pad_ok(b):
    p = b[-1]; return 1 <= p <= 16 and b.endswith(bytes([p]) * p)
SEEN = set()
def try_pw(pw, how):
    global SOFT
    if isinstance(pw, str): pw = pw.encode("utf-8", "replace")
    if pw in SEEN: return
    SEEN.add(pw)
    for name, (salt, ct, cprev, clast) in BL.items():
        N["aes"] += 1
        k, iv = evp_key(pw, salt)
        last = bytes(a ^ b for a, b in zip(AES.new(k, AES.MODE_ECB).decrypt(clast), cprev))
        if not pad_ok(last): continue
        pt = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        if pt is None: continue
        if G.semantic(pt):
            rec = {"how": how, "blob": name, "pw": pw.decode("latin-1"), "pt_hex": pt.hex()}
            HARD.append(rec); G.jsonl(LOG, {"HARD": rec}); print("### HARD", rec)
        else:
            SOFT += 1
    # sha256(senha) como privkey
    N["priv"] += 1
    try:
        if PublicKey.from_valid_secret(hashlib.sha256(pw).digest()).format(False) == TGT:
            rec = {"how": how, "priv": hashlib.sha256(pw).hexdigest()}; HARD.append(rec); G.jsonl(LOG, {"HARD": rec}); print("### HARD", rec)
    except Exception:
        pass
def forms(p):
    """formas de senha: crua, sha256hex, SHA256HEX, sha256²"""
    h = G.shahex(p)
    return [p, h, h.upper(), G.shahex(h)]
def spell(phrase):
    """grafias de uma frase: lower sem espaço/pontuação, lower com espaços, sem pontuação, original, UPPER, Title"""
    base = phrase.strip()
    nop = re.sub(r"[^\w\s']", "", base)
    lo = nop.lower()
    out = {base, nop, lo, lo.replace(" ", ""), lo.replace("'", ""), lo.replace("'", "").replace(" ", ""),
           nop.replace(" ", ""), lo.upper().replace(" ", ""), base.upper(), lo.replace(" ", "_"), lo.replace(" ", "-")}
    return [x for x in out if x]

t0 = time.time()
README = io.open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()

# ---------------------------------------------------------------- R1: últimas palavras antes da escolha
R1 = [
 "we won't", "we wont", "we will not", "hope",
 "if i were you i would hope that we don't meet again", "i would hope that we don't meet again",
 "hope that we don't meet again", "that we don't meet again", "we don't meet again", "don't meet again", "meet again",
 "the problem is choice", "as you adequately put the problem is choice", "the problem is choice but we already know what you're going to do",
 "but we already know what you're going to do don't we", "we already know what you're going to do", "what you're going to do",
 "already i can see the chain reaction", "the chain reaction", "the chemical precursors that signal the onset of an emotion",
 "an emotion designed specifically to overwhelm logic and reason", "overwhelm logic and reason", "logic and reason",
 "an emotion that is already blinding you from the simple and obvious truth", "the simple and obvious truth", "simple and obvious truth",
 "she is going to die and there is nothing you can do to stop it", "there is nothing you can do to stop it", "nothing you can do to stop it",
 "she is going to die", "hope it is the quintessential human delusion", "the quintessential human delusion", "quintessential human delusion",
 "simultaneously the source of your greatest strength and your greatest weakness", "your greatest strength and your greatest weakness",
 "greatest strength and greatest weakness", "the source of your greatest strength",
 "there are two doors", "two doors", "the door to your right leads to the source and the salvation of zion",
 "the door to your right", "the door to your left", "leads to the source and the salvation of zion", "the source and the salvation of zion",
 "the salvation of zion", "salvation of zion", "the door to your left leads back to the matrix to her and to the end of your species",
 "leads back to the matrix", "to her and to the end of your species", "the end of your species", "end of your species",
 "which brings us at last to the moment of truth", "the moment of truth", "moment of truth",
 "wherein the fundamental flaw is ultimately expressed", "the fundamental flaw", "the anomaly revealed as both beginning and end",
 "both beginning and end", "beginning and end", "denial is the most predictable of all human responses", "the most predictable of all human responses",
 "hello neo", "you are the one", "ergo", "concordantly", "vis-a-vis", "vis a vis", "the function of the one", "the eventuality of an anomaly",
 "you have many questions", "the answer", "why am i here", "your life is the sum of a remainder of an unbalanced equation",
 "an unbalanced equation", "the sum of a remainder", "choice", "the choice", "choose", "the door", "door", "right door", "left door",
 "thank you", "goodbye", "the source", "source", "zion", "her", "trinity", "the matrix", "the end", "the beginning",
]
n_r1 = 0
for ph in (R1 if "--r2" not in sys.argv else []):
    for sp in spell(ph):
        for f in forms(sp): try_pw(f, f"R1|{ph}")
        # gramática 3.2: prefixo giveit / sufixos; composição do roadmap
        for extra in ("giveit" + sp, sp + "thispassword", sp + "matrixsumlist", sp + "enter",
                      "yellowblueprimes" + "matrixsumlist" + sp + "yinyang", "yellowblueprimesmatrixsumlist" + sp,
                      sp + "yinyang", "lastwordsbeforearchichoice" + sp, sp + "lastwordsbeforearchichoice"):
            for f in forms(extra): try_pw(f, f"R1x|{ph}")
        n_r1 += 1
print("R1 frases/grafias:", n_r1, "| AES:", N["aes"], "| t=%.0fs" % (time.time() - t0)); sys.stdout.flush()

# ---------------------------------------------------------------- R3: a linha de comando openssl
sha2 = G.shahex("causality")
m3 = re.search(r"causalitySafenet[^ )`\n]*", README)
pw3_plain = m3.group(0) if m3 else None
ONLY_R2 = "--r2" in sys.argv
sha3 = G.shahex(pw3_plain) if pw3_plain else None
m32 = re.search(r"sha256\((jacquefresco[^)]*)\)|SHA256\((jacquefresco[^)]*)\)", README, flags=re.I)
pw32_plain = (m32.group(1) or m32.group(2)) if m32 else "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
sha32 = G.shahex(pw32_plain)
url = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
hexes = {"sha2": sha2, "sha3": sha3, "sha32": sha32, "url": url, "": ""}
print("fase3 plain:", (pw3_plain or "?")[:60], "| fase3.2 plain:", pw32_plain[:60])
files = ["", "phase.txt", "phase2.txt", "phase3.txt", "phase32.txt", "phase3.2.txt", "salphaseion.txt", "in.txt", "file.txt", "text.txt", "cipher.txt", "puzzle.txt"]
cmds = set()
for fn in files:
    for hk, hv in hexes.items():
        for flags in ("-d -a", "-a -d", "-d -a -in {f}", "-a -d -in {f}", "-d -in {f} -a", "-in {f} -d -a"):
            if "{f}" in flags and not fn: continue
            if "{f}" not in flags and fn: continue
            fl = flags.replace("{f}", fn)
            for pf in ("-pass pass:{h}", "-k {h}", "-pass pass:", "-k", ""):
                if "{h}" in pf and not hv: continue
                if "{h}" not in pf and hv: continue
                p = pf.replace("{h}", hv)
                for c in ("openssl enc -aes-256-cbc", "openssl aes-256-cbc", "openssl enc -aes256"):
                    cmd = " ".join(x for x in (c, fl, p) if x).strip()
                    cmds.add(cmd)
                    cmds.add(cmd.replace(" ", "")); cmds.add(re.sub(r"[^A-Za-z0-9]", "", cmd))
for extra in ("openssl", "enc", "aes-256-cbc", "aes256cbc", "openssl enc", "opensslenc", "-aes-256-cbc", "openssl enc -aes-256-cbc -d -a",
              "opensslencaes256cbcda", "OPENSSL", "sha256sum", "echo -n", "shasum -a 256", "cat", "ls", "cd", "exit", "enter", "return", "the last command", "lastcommand", "last command"):
    cmds.add(extra)
for cmd in (sorted(cmds) if not ONLY_R2 else []):
    for f in forms(cmd): try_pw(f, "R3")
print("R3 comandos:", len(cmds), "| AES:", N["aes"], "| t=%.0fs" % (time.time() - t0)); sys.stdout.flush()

# ---------------------------------------------------------------- R2: TAIL32 × fase 3 × xadrez × 3.2
fen = None
mfen = re.search(r"\b([1-8BKNPQRbknpqr]{1,8}(?:/[1-8BKNPQRbknpqr]{1,8}){7})\b", README)
if mfen: fen = mfen.group(1)
print("FEN:", fen)
parts3 = ["causality", "Safenet", "safenet", "SafeNet", "Luna", "luna", "HSM", "hsm", "SafenetLunaHSM", "safenetlunahsm", "11110"]
if pw3_plain:
    # o hex do genesis é o trecho longo hexadecimal dentro da senha da fase 3 (com prefixo 0x no README)
    mh = re.search(r"0x([0-9A-Fa-f]{32,})", pw3_plain)
    if mh:
        hx = mh.group(1)
        parts3 += ["0x" + hx, hx, hx.lower(), hx[:16], hx[-16:], bytes.fromhex(hx).decode("latin-1")]
    mf = re.search(r"B5KR/[^ )`\n]*", pw3_plain)
    if mf: parts3 += [mf.group(), mf.group().replace("/", "")]
    parts3 += [pw3_plain, G.shahex(pw3_plain)]
if fen:
    parts3 += [fen, fen.split("/")[0], fen.replace("/", ""), fen.split("/")[-1]]
    # peças e casas do FEN
    rows = fen.split("/")
    sq = []
    for ri, row in enumerate(rows):
        rank = 8 - ri; file = 0
        for ch in row:
            if ch.isdigit(): file += int(ch)
            else:
                sq.append(f"{ch}{'abcdefgh'[file]}{rank}"); sq.append(f"{'abcdefgh'[file]}{rank}"); file += 1
    parts3 += sq
chess = ["king", "queen", "King", "Queen", "bishop", "rook", "knight", "pawn", "fubcd", "fubcdking", "oracle", "oraclequeen", "thingky", "mvps",
         "sad", "board", "sadboard", "wide", "first", "seen", "aswideasthefirstoneseen", "thefirstoneseen", "raisingthestakes",
         "raisingthestakeswithoutextrachancesofwinning", "mostvaluablepieces", "mvp", "checkmate", "check", "mate", "chess", "chessboard", "kingandqueen",
         "fubcdkingoraclequeen", "thingkymvps", "KQ", "K", "Q", "B", "R", "N", "P", "white", "black", "e4", "e5", "d4", "d5", "Kg1", "Qd1"]
t32 = ["jacquefresco", "giveit", "justonesecond", "heisenbergsuncertaintyprinciple", "THEMATRIXHASYOU", "thematrixhasyou", "1141", "FUBCDORA.LETHINGKYMVPS.JQZXW",
       "halfandbetterhalf", "half", "betterhalf", "incaseyoumanagetocrackthis", "theprivatekeysbelongtohalfandbetterhalf", "theyalsoneedfundstolive"]
toks = list(dict.fromkeys(parts3 + chess + t32))
core = ["causality", "Safenet", "Luna", "HSM", "11110", "king", "queen", "fubcd", "oracle", "thingky", "mvps", "sadboard", "aswideasthefirstoneseen", "jacquefresco", "giveit", "THEMATRIXHASYOU"] + ([fen] if fen else [])
print("R2 tokens:", len(toks), "core:", len(core)); sys.stdout.flush()
cnt2 = 0
def emit2(s):
    global cnt2
    cnt2 += 1
    for f in forms(s): try_pw(f, "R2")
for t in toks: emit2(t)
for a, b in itertools.permutations(toks, 2):
    emit2(a + b); emit2(a + "." + b)
for a, b, c in itertools.permutations(core, 3):
    emit2(a + b + c)
for a, b, c, d in itertools.permutations(core[:12], 4):
    emit2(a + b + c + d)
print("R2 concatenações:", cnt2, "| AES:", N["aes"], "| t=%.0fs" % (time.time() - t0)); sys.stdout.flush()

# ---------------------------------------------------------------- R5: g como zero seletivo → z-method
F = G.FAED
gpos = [i for i, c in enumerate(F) if c == "g"]
spiral_bits = [G.MATRIX_README[r][c] for r, c in G.SPIRAL]
rowmajor_bits = [G.MATRIX_README[r][c] for r in range(14) for c in range(14)]
colored = set(G.COLORED.keys()); blue = set(G.BLUE_IDX); yellow = set(G.YELLOW_IDX)
sels = {}
for base in (0, 1):
    P = {i for i in gpos if G.is_prime(i + base)}
    sels[f"g@primes_b{base}"] = P; sels[f"g@nonprimes_b{base}"] = set(gpos) - P
ordp = {gpos[k] for k in range(len(gpos)) if G.is_prime(k + 1)}
sels["g_ordinal_prime"] = ordp; sels["g_ordinal_nonprime"] = set(gpos) - ordp
sels["g@blue"] = {i for i in gpos if i in blue}; sels["g@yellow"] = {i for i in gpos if i in yellow}; sels["g@colored"] = {i for i in gpos if i in colored}
sels["g@colored_mod196"] = {i for i in gpos if (i % 196) in colored}
sels["g@matrix1_spiral"] = {i for i in gpos if spiral_bits[i % 196] == 1}; sels["g@matrix0_spiral"] = {i for i in gpos if spiral_bits[i % 196] == 0}
sels["g@matrix1_row"] = {i for i in gpos if rowmajor_bits[i % 196] == 1}; sels["g@matrix0_row"] = {i for i in gpos if rowmajor_bits[i % 196] == 0}
sels["g_even_ord"] = set(gpos[0::2]); sels["g_odd_ord"] = set(gpos[1::2])
sels["g_even_idx"] = {i for i in gpos if i % 2 == 0}; sels["g_odd_idx"] = {i for i in gpos if i % 2 == 1}
for k in range(2, 10):
    for r in range(k): sels[f"g_idx_mod{k}={r}"] = {i for i in gpos if i % k == r}
for k in (10, 20, 30, 40, 50, 57, 60, 70, 80, 90, 100):
    sels[f"g_first{k}"] = set(gpos[:k]); sels[f"g_last{k}"] = set(gpos[-k:])
sels["g_all"] = set(gpos); sels["g_none"] = set()
sels["g_firsthalf"] = {i for i in gpos if i < 285}; sels["g_secondhalf"] = {i for i in gpos if i >= 285}
def zm(digs):
    n = int("".join(map(str, digs))); h = format(n, "x")
    if len(h) % 2: h = "0" + h
    return bytes.fromhex(h)
best5 = []
for name, S in (sels.items() if not ONLY_R2 else []):
    for pol in ("sel0", "sel7"):   # sel0: selecionados viram 0, resto 7 ; sel7: selecionados ficam 7, resto vira 0
        digs = []
        for i, c in enumerate(F):
            if c == "g": digs.append(0 if ((i in S) == (pol == "sel0")) else 7)
            else: digs.append(ord(c) - 96)
        for vname, v in (("full", digs), ("A", digs[:285]), ("B", digs[285:]), ("rev", digs[::-1])):
            if v and v[0] == 0: v = v[:]  # int() lida com zeros à esquerda
            s = "".join(map(str, v)); b = zm(v); N["z"] += 1
            pr = G.printable(b); best5.append((pr, f"R5|{name}|{pol}|{vname}", b[:40]))
            if pr >= 0.85 and len(b) >= 8:
                rec = {"how": f"R5|{name}|{pol}|{vname}", "text": b.decode("latin-1")[:200]}; HARD.append(rec); G.jsonl(LOG, {"HARD_TEXT": rec}); print("### TEXT", rec)
            h = G.fast_priv_scan(b)
            if h: rec = {"how": f"R5|{name}|{pol}|{vname}", "priv": str(h)}; HARD.append(rec); G.jsonl(LOG, {"HARD": rec}); print("### HARD", rec)
            for f in (s, b.hex(), b, G.shahex(s)): try_pw(f, f"R5|{name}|{pol}|{vname}")
best5.sort(reverse=True)
print("R5 seletores:", len(sels), "| z-methods:", N["z"], "| melhor printable:", [(round(p, 2), h) for p, h, _ in best5[:5]])
summary = {"n_aes": N["aes"], "n_priv": N["priv"], "n_zmethod": N["z"], "soft_pads": SOFT, "hard": HARD, "elapsed_s": round(time.time() - t0)}
G.jsonl(LOG, {"summary": summary}); print(json.dumps(summary, ensure_ascii=False)[:1500])
