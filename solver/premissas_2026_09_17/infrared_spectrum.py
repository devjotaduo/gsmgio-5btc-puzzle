# -*- coding: utf-8 -*-
"""
FAMILIA "Infrared": a-i como as 9 bandas do espectro (IR, R, O, Y, G, B, I, V, UV).
Cada simbolo vale o NUMERO da sua cor (nm ou THz); "zeroed out" = IR/UV -> 0.
Materializa dbbi/faed como listas de numeros e testa senha (raw/sha256hex/SHA256HEX),
privkey (sha256 da string; bytes diretos mod 256 e big-endian 16 bits), z-method da pagina.
Nulo: 100 embaralhamentos preservando contagens, mesmo pipeline (tabelas nomeadas).

CONVENCOES NUMERICAS (nm), ordem [IR, R, O, Y, G, B, I, V, UV]:
  wiki_low   : 750 625 590 565 500 450 420 380 100   (limites inferiores da tabela da Wikipedia; UV=100 = limite EUV)
  typical    : 800 700 620 580 530 470 445 420 350   ("valores tipicos" Wikipedia; indigo 445; UV-A ~350)
  classic    :1000 650 600 570 510 475 445 400 300   (tabela escolar ROYGBIV; Y=570 = len(faed))
  classic2   : 750 650 590 570 510 475 445 400 380   (variante com O=590 e UV no limite do visivel)
  hi_bounds  :1000 750 625 590 565 485 450 450 380   (limites superiores Wikipedia; I=V=450 colide de proposito)
  round100   :1000 700 600 600 500 500 400 400 300   (arredondado a 100 nm)
  ordinal    :   0   1   2   3   4   5   6   7   0   (posicao no arco-iris, invisiveis = 0)
  THz        : round(299792.458 / nm) para cada tabela em nm (ordinal nao tem THz)
  produto    : IR{750,800,1000} R{700,650,620} O{600,590} Y{580,570} G{530,510} B{470,450}
               I{445,425} V{400,380} UV{350,300} = 1152 tabelas (so formas primarias, sem somas de linha)
ORDENS de leitura a..i: desc = IR..UV ; asc = UV..IR ; vis_first = R O Y G B I V IR UV ; vis_first2 = R..V UV IR
ZERAGEM: none ; both (IR,UV=0) ; ir ; uv
"""
import sys, os, json, random, hashlib, time, itertools
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from coincurve import PublicKey
import base64

OUT = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(OUT, "paddings.jsonl")
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
BANDS = ["IR", "R", "O", "Y", "G", "B", "I", "V", "UV"]
NM = {
    "wiki_low":  [750, 625, 590, 565, 500, 450, 420, 380, 100],
    "typical":   [800, 700, 620, 580, 530, 470, 445, 420, 350],
    "classic":   [1000, 650, 600, 570, 510, 475, 445, 400, 300],
    "classic2":  [750, 650, 590, 570, 510, 475, 445, 400, 380],
    "hi_bounds": [1000, 750, 625, 590, 565, 485, 450, 450, 380],
    "round100":  [1000, 700, 600, 600, 500, 500, 400, 400, 300],
}
ORDINAL = [0, 1, 2, 3, 4, 5, 6, 7, 0]
ORDERS = {  # posicao no vetor BANDS para cada letra a..i
    "desc": [0, 1, 2, 3, 4, 5, 6, 7, 8],
    "asc": [8, 7, 6, 5, 4, 3, 2, 1, 0],
    "vis_first": [1, 2, 3, 4, 5, 6, 7, 0, 8],
    "vis_first2": [1, 2, 3, 4, 5, 6, 7, 8, 0],
}
ZERO = {"none": (), "both": (0, 8), "ir": (0,), "uv": (8,)}

def thz(tab): return [round(299792.458 / v) if v else 0 for v in tab]

def tables_named():
    t = dict(NM); t.update({k + "_THz": thz(v) for k, v in NM.items()}); t["ordinal"] = ORDINAL
    return t

def make_map(tab, order, zero):
    vals = list(tab)
    for z in ZERO[zero]: vals[z] = 0
    return {c: vals[ORDERS[order][i]] for i, c in enumerate("abcdefghi")}

def divisors(n): return [w for w in range(2, n) if n % w == 0]

def forms(L, full=True, extra_widths=()):
    """Strings derivadas de uma lista de numeros."""
    out = {}
    for sep, tag in (("", "cat"), (" ", "sp"), (",", "com")):
        out[tag] = sep.join(map(str, L))
    out["sum"] = str(sum(L))
    d = [L[i + 1] - L[i] for i in range(len(L) - 1)]
    for sep, tag in (("", "cat"), (" ", "sp"), (",", "com")):
        out["diff_" + tag] = sep.join(map(str, d))
        out["adiff_" + tag] = sep.join(str(abs(x)) for x in d)
    if full:
        n = len(L)
        for w in list(divisors(n)) + list(extra_widths):
            rows = [sum(L[i:i + w]) for i in range(0, n, w)]
            cols = [sum(L[i::w]) for i in range(w)]
            for sep, tag in (("", "cat"), (" ", "sp"), (",", "com")):
                out[f"row{w}_{tag}"] = sep.join(map(str, rows))
                out[f"col{w}_{tag}"] = sep.join(map(str, cols))
    return out

# ---------------- pipeline lean de AES (3 blobs x 2 KDF) + privkey ----------------
def evp(pw, salt, hm):
    d = b""; prev = b""
    while len(d) < 48:
        prev = hm.new(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]

def aes_all(pw, stats, tag):
    """Devolve hits duros; registra paddings validos no log e em stats."""
    pwb = pw.encode() if isinstance(pw, str) else pw
    hard = []
    for b, (salt, ct) in G.BLOBS.items():
        for hm in (MD5, SHA256):
            k, iv = evp(pwb, salt, hm)
            p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
            if p is None: continue
            pr = G.printable(p)
            stats["n_pad"] += 1; stats["max_pr"] = max(stats["max_pr"], pr)
            rec = {"tag": tag, "pw": pw if len(pw) < 200 else pw[:200] + "...", "blob": b,
                   "kdf": hm.__name__.split(".")[-1], "printable": round(pr, 3), "plain_hex": p.hex()}
            priv = scan32(p) if len(p) >= 32 else []
            if priv or G.semantic(p):
                rec["HARD"] = True; rec["priv"] = priv; hard.append(rec)
            if stats.get("log", True): G.jsonl(LOG, rec)
    return hard

def scan32(buf, tgt=TGT):
    hits = []
    for j in range(0, len(buf) - 31):
        try:
            if PublicKey.from_valid_secret(buf[j:j + 32]).format(False) == tgt: hits.append((j, buf[j:j + 32].hex()))
        except Exception: pass
    return hits

def priv_forms(s):
    """sha256(s), sha256(sha256(s)) como privkey."""
    b = s.encode(); h = hashlib.sha256(b).digest()
    return [k for k in (h, hashlib.sha256(h).digest()) if scan32(k)]

def zmethod(L):
    n = int("".join(map(str, L))); h = format(n, "x")
    if len(h) % 2: h = "0" + h
    return bytes.fromhex(h)

def test_string(s, tag, stats, seen):
    hard = []
    for pw in (s, G.shahex(s), G.shahex(s).upper()):
        if pw in seen: continue
        seen.add(pw); stats["n_pw"] += 1
        hard += aes_all(pw, stats, tag)
    ph = priv_forms(s)
    if ph: hard.append({"tag": tag, "HARD": True, "priv_sha": [k.hex() for k in ph]})
    return hard

def run_map(M, name, stats, seen, full=True, sources=None, windows=True, zscan="all"):
    hard = []
    srcs = sources or {"dbbi": G.DBBI, "faed": G.FAED, "both": G.DBBI + G.FAED}
    for sname, s in srcs.items():
        L = [M[c] for c in s]
        extra = (91,) if sname == "faed" else ()
        for ftag, st in forms(L, full, extra).items():
            hard += test_string(st, f"{name}/{sname}/{ftag}", stats, seen)
        # bytes diretos: mod 256 e big-endian 16 bits -> varredura de janelas de 32 B
        b1 = bytes(v % 256 for v in L); b2 = b"".join(v.to_bytes(2, "big") for v in L)
        for bb, bt in (((b1, "mod256"), (b2, "be16")) if windows else ()):
            stats["n_win"] += max(0, len(bb) - 31)
            h = scan32(bb)
            if h: hard.append({"tag": f"{name}/{sname}/{bt}", "HARD": True, "priv": h})
        # z-method da pagina
        z = zmethod(L); pr = G.printable(z); stats["z_max_pr"] = max(stats["z_max_pr"], pr)
        stats["n_z"] += 1
        if pr > stats.get("z_best", (0,))[0]: stats["z_best"] = (round(pr, 3), f"{name}/{sname}", z[:40].decode("latin-1"))
        h = scan32(z) if zscan == "all" else (scan32(z[:32]) + scan32(z[-32:]))  # ends: so 1o/ultimo 32 B
        if h: hard.append({"tag": f"{name}/{sname}/z", "HARD": True, "priv": h})
        if G.semantic(z): hard.append({"tag": f"{name}/{sname}/z", "HARD": True, "z_hex": z.hex()})
    return hard

def new_stats(log=True): return {"n_pw": 0, "n_pad": 0, "max_pr": 0.0, "n_win": 0, "n_z": 0, "z_max_pr": 0.0, "log": log}

def all_maps(named=True):
    out = {}
    tabs = tables_named() if named else {}
    for tn, tab in tabs.items():
        for on in ORDERS:
            for zn in ZERO:
                if tn == "ordinal" and zn != "none": continue
                out[f"{tn}/{on}/{zn}"] = make_map(tab, on, zn)
    return out

def product_maps():
    grid = [(750, 800, 1000), (700, 650, 620), (600, 590), (580, 570), (530, 510), (470, 450), (445, 425), (400, 380), (350, 300)]
    for combo in itertools.product(*grid):
        for unit, tab in (("nm", list(combo)), ("THz", thz(combo))):
            for on in ORDERS:
                for zn in ZERO:
                    yield f"prod_{unit}_{'-'.join(map(str, combo))}/{on}/{zn}", make_map(tab, on, zn)

# ---------------- controles ----------------
def controls():
    # 1) fase 2 abre com sha256hex('causality') via EVP-SHA256 no MEU evp/unpad
    raw = base64.b64decode(G.PHASE2_B64); s2, c2 = raw[8:16], raw[16:]
    k, iv = evp(G.shahex("causality").encode(), s2, SHA256)
    p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c2)); assert p and p.startswith(b"The ironic"), "controle fase 2"
    # 2) cifra texto conhecido com salt do SMALL e reabre pelo aes_all (via BLOBS temporario)
    msg = b"controle positivo infrared " * 3; pad = 16 - len(msg) % 16; m = msg + bytes([pad]) * pad
    salt = G.BLOBS["SMALL"][0]; k, iv = evp(b"senha-teste", salt, SHA256)
    ct = AES.new(k, AES.MODE_CBC, iv).encrypt(m)
    bak = dict(G.BLOBS); G.BLOBS.clear(); G.BLOBS["CTRL"] = (salt, ct)
    st = new_stats(log=False); h = aes_all("senha-teste", st, "ctrl")
    G.BLOBS.clear(); G.BLOBS.update(bak)
    assert h and h[0]["plain_hex"] == msg.hex(), "controle cifra/decifra"
    # 3) z-method reproduz lastwordsbeforearchichoice
    seg = "agdafaoaheiecggchgicbbhcgbehcfcoabicfdhhcdbbcagbdaiobbgbeadedde"
    assert zmethod([0 if c == "o" else ord(c) - 96 for c in seg]) == b"lastwordsbeforearchichoice"
    # 4) scan32 acha chave plantada contra a propria pubkey e nao contra o alvo
    sec = hashlib.sha256(b"planted").digest(); pub = PublicKey.from_valid_secret(sec).format(False)
    buf = os.urandom(40) + sec + os.urandom(20)
    assert scan32(buf, pub) == [(40, sec.hex())] and scan32(buf) == []
    return "fase2 abre via EVP-SHA256 no pipeline; cifra/decifra round-trip com salt do SMALL OK; z-method reproduz lastwordsbeforearchichoice; scan32 acha chave plantada (offset 40) e nao dispara no alvo"

# ---------------- 570 / 91 = amarelo / azul ----------------
def yellow_blue(stats, seen):
    hard = []
    ws = ["570", "91", "57091", "91570", "570 91", "91 570", "570,91", "yellow570blue91", "Yellow570Blue91",
          "yellow570", "blue91", "blue570yellow91", "570nm", "91nm", "526", "526THz", "570nm91", "yellowblue57091",
          "infrared", "Infrared", "INFRARED", "infrared570", "infrared91", "570infrared", "750", "1000", "0", "00",
          "yellow570blue450", "yellow580blue470", "570450", "580470", "570475", "570470", "450570", "470580",
          "yellowblueprimes57091", "57091primes", "7x13", "7*13", "713", "137", "91=7x13", "570=2x3x5x19"]
    for w in ws: hard += test_string(w, f"yb/{w}", stats, seen)
    return hard

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "real"
    t0 = time.time(); ctrl = controls(); print("controles OK"); maps = all_maps()
    if mode == "real":
        if os.path.exists(LOG): os.remove(LOG)
        stats = new_stats(); seen = set(); hard = []
        hard += yellow_blue(stats, seen)
        print("mapas nomeados:", len(maps))
        for name, M in maps.items(): hard += run_map(M, name, stats, seen)
        real_named = dict(stats); print("nomeados:", {k: v for k, v in real_named.items() if k != "log"}, "hard:", len(hard), f"{time.time()-t0:.0f}s", flush=True)
        n_prod = 0   # produto cartesiano: so formas primarias, sem janelas de bytes (ponytail: 36 864 mapas)
        for name, M in product_maps():
            hard += run_map(M, name, stats, seen, full=False, windows=False); n_prod += 1
            if n_prod % 5000 == 0: print("produto", n_prod, f"{time.time()-t0:.0f}s", flush=True)
        print("produto:", n_prod, "mapas;", {k: v for k, v in stats.items() if k != "log"}, "hard:", len(hard), f"{time.time()-t0:.0f}s", flush=True)
        json.dump({"stats": {k: v for k, v in stats.items() if k != "log"}, "real_named": {k: v for k, v in real_named.items() if k != "log"},
                   "hard": hard, "controls": ctrl, "n_maps_named": len(maps), "n_maps_prod": n_prod}, open(os.path.join(OUT, "result_real.json"), "w"), indent=1)
    elif mode == "prod":  # prod <k> <n>: shard k de n do produto cartesiano, mapas DEDUPLICADOS por tupla de valores
        k, n = int(sys.argv[2]), int(sys.argv[3]); LOG = os.path.join(OUT, f"paddings_prod_{k}.jsonl")
        if os.path.exists(LOG): os.remove(LOG)
        globals()["LOG"] = LOG
        uniq = {}
        for name, M in product_maps(): uniq.setdefault(tuple(M[c] for c in "abcdefghi"), name)
        items = [(nm, dict(zip("abcdefghi", t))) for i, (t, nm) in enumerate(uniq.items()) if i % n == k]
        stats = new_stats(); seen = set(); hard = []
        for j, (name, M) in enumerate(items):
            hard += run_map(M, name, stats, seen, full=False, windows=False, zscan="ends")
            if j % 500 == 0: print("prod", k, j, len(items), f"{time.time()-t0:.0f}s", flush=True)
        json.dump({"stats": {kk: v for kk, v in stats.items() if kk != "log"}, "hard": hard, "n_maps": len(items), "n_uniq_total": len(uniq)},
                  open(os.path.join(OUT, f"result_prod_{k}.json"), "w"), indent=1)
    else:  # null <seed> <n>: embaralhamentos preservando contagens, pipeline dos mapas nomeados (sem janelas)
        seed, n = int(sys.argv[2]), int(sys.argv[3]); rng = random.Random(seed); null = []
        for i in range(n):
            d = list(G.DBBI); f = list(G.FAED); rng.shuffle(d); rng.shuffle(f); d = "".join(d); f = "".join(f)
            st = new_stats(log=False); sn = set(); hh = []
            for name, M in maps.items(): hh += run_map(M, name, st, sn, sources={"dbbi": d, "faed": f, "both": d + f}, windows=False)
            null.append({k: v for k, v in st.items() if k != "log"} | {"hard": len(hh), "seed": seed, "i": i})
            print("null", seed, i, null[-1], f"{time.time()-t0:.0f}s", flush=True)
        json.dump(null, open(os.path.join(OUT, f"result_null_{seed}.json"), "w"), indent=1)
    print("FIM", f"{time.time()-t0:.0f}s")
