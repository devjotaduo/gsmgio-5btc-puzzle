# -*- coding: utf-8 -*-
"""
FAMÍLIA seed_encoding_in_bif

Hipótese (prosa): se BTCSEED é um header real, os 563 símbolos seguintes no mesmo
quadrado de 25 letras não podem ser inglês (sem dígitos): devem ser uma seed
codificada só com letras — hex com dígitos mapeados a uma janela de 10/16 letras,
inteiro em base-25/26 numa janela de 44–60 letras (~256 bits), ou mnemonic BIP39
com palavras abreviadas (prefixos únicos de 4 letras; grupos de 3/2 letras como
índice). Espaço finito; falsificável por oráculo duro (privkey → endereço-prêmio).

Cobre o que é NOVO em relação ao já fechado (base-25/26 do REST inteiro a partir
de offsets 0-55, A1Z26→BIP39 direto, nibble→hex, WIF): janelas de comprimento
fixo, mapeamentos por janela de letras, prefixos BIP39 de 4 letras com derivação
própria (sem filtro de diversidade), grupos 3/2, decimações por k primo.
"""
import sys, os, json, hashlib, math, time, random
from collections import Counter
SP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SP)
import gsmg_common as G
import oracles as O
import coincurve, base58
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip32Secp256k1

LOG = os.path.join(SP, "seed_encoding_in_bif.jsonl")
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PRIZE = O.PRIZE_ADDR
TARGET_H160 = O.TARGET_H160
STATS = Counter()          # n_tests por sub-família
HARD = []; SOFT = []

# ------------------------------------------------------------ oráculo rápido (coincurve)
def _h160(b): return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
def _addr(h): return base58.b58encode_check(b"\x00" + h).decode()
def addrs_of(priv32):
    n = int.from_bytes(priv32, "big")
    if n == 0 or n >= N_ORDER: return None
    pk = coincurve.PrivateKey(priv32).public_key
    hu = _h160(pk.format(compressed=False)); hc = _h160(pk.format(compressed=True))
    return hu, hc
def priv_hit(priv32, targets=None):
    """Oráculo duro: priv → h160 comprimido/não. targets: set de h160 (default = prêmio)."""
    STATS["priv_checks"] += 1
    r = addrs_of(priv32)
    if r is None: return None
    hu, hc = r
    tg = targets or {TARGET_H160}
    if hu in tg or hc in tg:
        return {"priv": priv32.hex(), "addr_unc": _addr(hu), "addr_comp": _addr(hc)}
    return None

# ------------------------------------------------------------ textos
BIF = G.bif_full()
REST = BIF[7:]
assert BIF.startswith("BTCSEED") and len(REST) == 563
TEXTS = {"BIF": BIF, "REST": REST, "REST_odd": REST[0::2], "REST_even": REST[1::2]}
AZ25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
AZ26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ORDERS = {"CANON": G.CANON, "AZ25": AZ25, "AZ26": AZ26}
PRIMES_E = [2, 3, 5, 7, 11, 13]

def decimations(text):
    """(e) leitura a cada k-ésima letra, k primo, todos os inícios."""
    for k in PRIMES_E:
        for s in range(k):
            yield f"k{k}s{s}", text[s::k]

# ------------------------------------------------------------ (a) hex por janela de letras
def hex_windows(text, name, targets=None):
    """Toda janela circular de 16 letras de uma ordem → 0..f; runs ≥64 → hex64 → priv.
    Mais: 10-janela (dígitos) + ABCDEF fixos (quando disjuntos)."""
    hits = []
    for oname, order in ORDERS.items():
        L = len(order)
        maps = []
        for st in range(L):
            win = [order[(st + i) % L] for i in range(16)]
            maps.append((f"{oname}+{st}/16", {c: "0123456789abcdef"[i] for i, c in enumerate(win)}))
            win10 = [order[(st + i) % L] for i in range(10)]
            if not set(win10) & set("ABCDEF"):
                m = {c: str(i) for i, c in enumerate(win10)}; m.update({c: c.lower() for c in "ABCDEF"})
                maps.append((f"{oname}+{st}/10+AF", m))
        for mname, m in maps:
            s = "".join(m.get(c, " ") for c in text)
            for run in s.split():
                if len(run) < 64: continue
                for j in range(len(run) - 63):
                    STATS["a_hex64"] += 1
                    r = priv_hit(bytes.fromhex(run[j:j + 64]), targets)
                    if r: hits.append({"sub": "a_hex", "text": name, "map": mname, "off": j, **r})
    return hits

# ------------------------------------------------------------ (b) base-25/26 janelas fixas
def base_windows(text, name, lengths=range(44, 61), targets=None):
    hits = []
    for oname, order in ORDERS.items():
        idx = {c: i for i, c in enumerate(order)}
        if any(c not in idx for c in text): continue   # AZ26 tem J que não ocorre; ok
        B = len(order)
        digs = [idx[c] for c in text]
        for Ln in lengths:
            for off in range(0, len(digs) - Ln + 1):
                w = digs[off:off + Ln]
                for endian, ww in (("big", w), ("little", w[::-1])):
                    v = 0
                    for d in ww: v = v * B + d
                    cands = {v % N_ORDER, v & ((1 << 256) - 1)}
                    if v >= (1 << 256): cands.add(v >> (v.bit_length() - 256))
                    for c in cands:
                        STATS["b_base"] += 1
                        r = priv_hit(c.to_bytes(32, "big"), targets)
                        if r: hits.append({"sub": "b_base", "text": name, "order": oname, "len": Ln,
                                           "off": off, "endian": endian, **r})
    return hits

# ------------------------------------------------------------ (c)(d) BIP39
MN = Mnemonic("english"); WL = MN.wordlist
def _col(w): return w.upper().replace("J", "I")
PREF4 = {}
for w in WL:
    PREF4.setdefault(_col(w[:4]), []).append(w)
PREF4 = {k: v[0] for k, v in PREF4.items() if len(v) == 1}   # prefixos únicos (I/J colapsados)
assert len(PREF4) >= 2040, len(PREF4)
PREF3 = {}
for w in WL: PREF3.setdefault(_col(w[:3]), []).append(w)
PREF3 = {k: v[0] for k, v in PREF3.items() if len(v) == 1}
WORDSET = set(WL)

def derive_check(words, targets=None):
    """Sem filtro de diversidade. Checksum → seed → master, m/0/i, m/0'/i, m/44'/0'/0'/0|1/i."""
    STATS["c_checksum"] += 1
    mnem = " ".join(words)
    if not MN.check(mnem): return None
    STATS["c_valid"] += 1
    seed = Bip39SeedGenerator(mnem).Generate()
    root = Bip32Secp256k1.FromSeed(seed)
    tg = targets or {TARGET_H160}
    cands = {"m": root.PrivateKey().Raw().ToBytes(), "seed[:32]": seed[:32], "seed[32:]": seed[32:]}
    for i in range(5):
        cands[f"m/0/{i}"] = root.ChildKey(0).ChildKey(i).PrivateKey().Raw().ToBytes()
        cands[f"m/0'/{i}"] = root.ChildKey(0x80000000).ChildKey(i).PrivateKey().Raw().ToBytes()
        acct = root.ChildKey(0x80000000 + 44).ChildKey(0x80000000).ChildKey(0x80000000)
        cands[f"m/44'/0'/0'/0/{i}"] = acct.ChildKey(0).ChildKey(i).PrivateKey().Raw().ToBytes()
        cands[f"m/44'/0'/0'/1/{i}"] = acct.ChildKey(1).ChildKey(i).PrivateKey().Raw().ToBytes()
    for path, p in cands.items():
        r = priv_hit(p, tg)
        if r: return {"mnemonic": mnem, "path": path, **r}
    return {"mnemonic": mnem, "valid_only": True}

def bip39_prefix4(text, name, targets=None):
    """(c) grupos de 4 letras = prefixo único BIP39; janelas de 12..24 palavras."""
    hits = []; valids = 0
    for o in range(4):
        words = []
        for j in range(o, len(text) - 3, 4):
            words.append(PREF4.get(text[j:j + 4]))
        for n in (12, 15, 18, 21, 24):
            for s in range(len(words) - n + 1):
                w = words[s:s + n]
                if None in w: continue
                r = derive_check(w, targets)
                if r is None: continue
                valids += 1
                if "priv" in r: hits.append({"sub": "c_pref4", "text": name, "off": o, "start": s, "n": n, **r})
                else: SOFT.append({"sub": "c_pref4", "text": name, "off": o, "start": s, "n": n, "mnemonic": r["mnemonic"]})
    return hits, valids

def bip39_groups(text, name, targets=None):
    """(d) grupos de 3 letras (base-26/25 → mod 2048) e 2 letras (base-26 → 0..675) → índice BIP39."""
    hits = []; valids = 0
    for oname, order in ORDERS.items():
        idx = {c: i for i, c in enumerate(order)}; B = len(order)
        for g in (2, 3):
            for o in range(g):
                words = []
                for j in range(o, len(text) - g + 1, g):
                    v = 0
                    for c in text[j:j + g]: v = v * B + idx[c]
                    words.append(WL[v % 2048])
                for n in (12, 15, 18, 21, 24):
                    for s in range(len(words) - n + 1):
                        r = derive_check(words[s:s + n], targets)
                        if r is None: continue
                        valids += 1
                        if "priv" in r: hits.append({"sub": f"d_grp{g}", "text": name, "order": oname, "off": o, "start": s, "n": n, **r})
        # prefixo de 3 letras único (quando existe)
        if oname == "CANON":
            for o in range(3):
                words = [PREF3.get(text[j:j + 3]) for j in range(o, len(text) - 2, 3)]
                for n in (12, 15, 18, 21, 24):
                    for s in range(len(words) - n + 1):
                        w = words[s:s + n]
                        if None in w: continue
                        r = derive_check(w, targets)
                        if r is None: continue
                        valids += 1
                        if "priv" in r: hits.append({"sub": "d_pref3", "text": name, "off": o, "start": s, "n": n, **r})
    return hits, valids

# ------------------------------------------------------------ estatística
def stats(text):
    c = Counter(text); n = len(text)
    ent = -sum(v / n * math.log2(v / n) for v in c.values())
    ranked = c.most_common()
    cum = 0; k90 = 0
    for _, v in ranked:
        cum += v; k90 += 1
        if cum >= 0.9 * n: break
    return {"len": n, "distinct": len(c), "entropy_bits": round(ent, 3), "symbols_for_90pct": k90,
            "top": ranked[:8]}

# ------------------------------------------------------------ controles positivos
def controls():
    rng = random.Random(1327)
    # (b) privkey conhecida embutida em base-25 CANON
    priv = G.sha(b"controle-b"); tg = {addrs_of(priv)[1]}
    v = int.from_bytes(priv, "big"); digs = []
    while v: digs.append(v % 25); v //= 25
    enc = "".join(G.CANON[d] for d in digs[::-1])
    fake = "".join(rng.choice(G.CANON) for _ in range(40)) + enc + "".join(rng.choice(G.CANON) for _ in range(40))
    h = base_windows(fake, "ctrl", lengths=[len(enc)], targets=tg)
    assert h and h[0]["priv"] == priv.hex(), "controle (b) falhou"
    # (a) hex por janela: hex de priv com dígitos → CANON[st..st+16]
    m = {"0123456789abcdef"[i]: G.CANON[(3 + i) % 25] for i in range(16)}
    fake = "".join(rng.choice(G.CANON) for _ in range(20)) + "".join(m[c] for c in priv.hex()) + "".join(rng.choice(G.CANON) for _ in range(20))
    h = hex_windows(fake, "ctrl", targets=tg)
    assert h and h[0]["priv"] == priv.hex(), "controle (a) falhou"
    # (c) mnemonic conhecida em prefixos de 4 letras → m/44'/0'/0'/0/0
    mnem = MN.to_mnemonic(G.sha(b"controle-c")[:16]).split()
    root = Bip32Secp256k1.FromSeed(Bip39SeedGenerator(" ".join(mnem)).Generate())
    p = root.ChildKey(0x80000000 + 44).ChildKey(0x80000000).ChildKey(0x80000000).ChildKey(0).ChildKey(0).PrivateKey().Raw().ToBytes()
    tg = {addrs_of(p)[1]}
    fake = "".join((w[:4] + "XXXX")[:4].upper().replace("J", "I") for w in mnem)   # palavras <4 letras: padding
    # ponytail: só palavras ≥4 letras no controle (palavras curtas de 3 letras não têm prefixo de 4)
    if all(len(w) >= 4 for w in mnem):
        h, _ = bip39_prefix4("QQ" + fake, "ctrl", targets=tg)
        assert h and h[0]["priv"] == p.hex(), "controle (c) falhou"
    else:
        # (d) via grupos de 3: índices → base-26 de 3 letras
        enc = ""
        for w in mnem:
            i = WL.index(w); enc += AZ26[i // 676] + AZ26[(i // 26) % 26] + AZ26[i % 26]
        h, _ = bip39_groups(enc, "ctrl", targets=tg)
        assert h and h[0]["priv"] == p.hex(), "controle (d) falhou"
    STATS["controls_ok"] = 3
    for k in ("priv_checks", "a_hex64", "b_base", "c_checksum", "c_valid"): STATS[k] = 0
    G.jsonl(LOG, {"event": "controls", "ok": True})

# ------------------------------------------------------------ main
if __name__ == "__main__":
    if os.path.exists(LOG): os.remove(LOG)
    G.jsonl(LOG, {"event": "hypothesis", "family": "seed_encoding_in_bif", "text": __doc__.strip()})
    t0 = time.time()
    controls(); print("controles OK", round(time.time() - t0, 1), "s")
    # estatística
    st = {k: stats(v) for k, v in TEXTS.items()}
    G.jsonl(LOG, {"event": "stats", "stats": st}); print(json.dumps(st, indent=1))
    valids_total = 0
    for name, text in TEXTS.items():
        t1 = time.time()
        HARD += hex_windows(text, name)
        HARD += base_windows(text, name)
        h, v = bip39_prefix4(text, name); HARD += h; valids_total += v
        h, v = bip39_groups(text, name); HARD += h; valids_total += v
        for dn, dt in decimations(text):
            HARD += hex_windows(dt, f"{name}/{dn}")
            h, v = bip39_prefix4(dt, f"{name}/{dn}"); HARD += h; valids_total += v
            h, v = bip39_groups(dt, f"{name}/{dn}"); HARD += h; valids_total += v
            if len(dt) >= 60: HARD += base_windows(dt, f"{name}/{dn}", lengths=(55, 56))
        print(name, dict(STATS), "hard", len(HARD), round(time.time() - t1, 1), "s")
        G.jsonl(LOG, {"event": "progress", "text": name, "stats": dict(STATS), "hard": len(HARD)})
    # confirmação independente de qualquer hit duro via G.priv_hit
    for h in HARD: h["G_confirm"] = G.priv_hit(bytes.fromhex(h["priv"]))
    out = {"n_tests": dict(STATS), "hard": HARD, "soft_valid_mnemonics": valids_total,
           "soft_sample": SOFT[:20], "elapsed_s": round(time.time() - t0, 1)}
    G.jsonl(LOG, {"event": "final", **out})
    print(json.dumps({k: v for k, v in out.items() if k != "soft_sample"}, indent=1))
