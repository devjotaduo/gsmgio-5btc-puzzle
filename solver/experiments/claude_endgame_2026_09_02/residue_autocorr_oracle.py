# -*- coding: utf-8 -*-
"""
COMPLEMENTO 4 — oraculo DURO incondicional sobre os decodes dos 40 melhores streams do bloco B.

Na varredura principal o oraculo (sha256(pt) como senha nos 3 blobs / como privkey) so era chamado
quando o texto passava em semantic_text — e NENHUM passou (0/71k). Aqui removo o gate: reconstruo
os 40 streams de maior |z| a partir do log e rodo sha256(pt) e sha256(pt.lower()) como senha
EVP-SHA256 em SMALL/COSMIC/TAIL32 e como privkey, para TODO decode (22 alfabetos x 72/90 escapes).
Reporta a taxa de padding valido (esperada 1/256 se for ruido).
"""
import sys, json, time, collections
import numpy as np
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from coincurve import PublicKey
LOG = SP + r"\residue_autocorr.jsonl"
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
T0 = time.time()

def a1z26(s): return [ord(c) - 96 for c in s.lower() if 'a' <= c <= 'z']
def ascii_bits(s): return [int(b) for ch in s for b in format(ord(ch), "08b")]
KEYS = {}
KEYS["bin(enter)"] = ascii_bits("enter"); KEYS["bin(matrixsumlist)"] = ascii_bits("matrixsumlist")
for w in ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword",
          "yellowblueprimes", "hashthetext", "enter"]:
    v = a1z26(w); KEYS[f"{w}:a1z26m2"] = [x % 2 for x in v]; KEYS[f"{w}:a1z26m3"] = [x % 3 for x in v]
MR = G.MATRIX_README
KEYS["matrixREADME:spiral"] = [MR[r][c] for r, c in G.SPIRAL]
KEYS["matrixREADME:rowmajor"] = [MR[r][c] for r in range(14) for c in range(14)]
KEYS["url_bits192"] = KEYS["matrixREADME:spiral"][:192]
KEYS["dbbi:m2"] = [d % 2 for d in G.digits(G.DBBI)]; KEYS["dbbi:m3"] = [d % 3 for d in G.digits(G.DBBI)]
KEYS["primeind570"] = [1 if G.is_prime(i) else 0 for i in range(570)]
KEYS["primeind570_b1"] = [1 if G.is_prime(i + 1) else 0 for i in range(570)]
KEYS["thuemorse"] = [bin(i).count("1") % 2 for i in range(570)]
fib = [0, 1]
while len(fib) < 570: fib.append(fib[-1] + fib[-2])
KEYS["fib:m2"] = [x % 2 for x in fib[:570]]; KEYS["fib:m3"] = [x % 3 for x in fib[:570]]
fw = "0"
while len(fw) < 570: fw = "".join("01" if c == "0" else "0" for c in fw)
KEYS["fibword"] = [int(c) for c in fw[:570]]

FD = G.digits(G.FAED); DD = G.digits(G.DBBI)
def cfgs(digs):
    return {"m9": dict(n=9, c=np.array([d - 1 for d in digs]), uni="123456789", back=1),
            "m10a1": dict(n=10, c=np.array(digs), uni="0123456789", back=0),
            "m10a0": dict(n=10, c=np.array([d - 1 for d in digs]), uni="0123456789", back=0),
            "m10i0": dict(n=10, c=np.array([0 if d == 9 else d for d in digs]), uni="0123456789", back=0)}
SEQ = {"faed": cfgs(FD), "dbbi": cfgs(DD)}

AL322_25 = "FUBCDORALETHINGKYMVPSJQZXW"[:25]
PHR = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "yellowblueprimes",
       "hashthetext", "thematrixhasyou", "salphaseion", "cosmicduality", "yinyang",
       "halfandbetterhalf", "theseedisplanted", "followthewhiterabbit", "salvation",
       "enter", "anstoo", "ourfirsthintisyourlastcommand", "purplepill", "primebasics",
       "fubcdkingoraclequeenthingkymvps", "lifeanddeath"]
ALPHS = {"al322_25": AL322_25, "CANON": G.CANON}
for p in PHR: ALPHS[f"kw:{p}"] = G.keyed_alphabet(p)
ALPHS = {k: v for k, v in ALPHS.items() if len(v) == 25}
_s = {}
for k, v in list(ALPHS.items()):
    if v in _s: del ALPHS[k]
    else: _s[v] = k
ESC9 = [(x, y) for x in range(1, 10) for y in range(1, 10) if x != y]
ESC10 = [(x, y) for x in range(10) for y in range(10) if x != y]

rows = [json.loads(l) for l in open(LOG, encoding="utf-8")]
fp = [r for r in rows if r.get("event") == "filter_pass" and r["how"].startswith("B|")]
fp.sort(key=lambda r: -max(abs(r["hcond_z"]), abs(r["digIoC_z"])))
TOP = fp[:40]

n_dec = 0; n_aes = 0; n_pad = 0; n_priv = 0
HARD = []; SOFT = []
for r in TOP:
    _, sq, cn, kname, rots, mode = r["how"].split("|")
    rot = int(rots[3:])
    kraw = KEYS[kname] if kname in KEYS else [int(c) for c in kname.split(":")[1]]
    cfg = SEQ[sq][cn]; n = cfg["n"]; c = cfg["c"]
    k = [x % n for x in (list(kraw[rot:]) + list(kraw[:rot]))]
    K = np.resize(np.array(k), len(c))
    a = (c - K) % n if mode == "add" else (c + K) % n
    digs = [int(x) + cfg["back"] for x in a]
    escs = ESC9 if n == 9 else ESC10[:90]
    uni = cfg["uni"]
    for an, al in ALPHS.items():
        for e in escs:
            pt = G.checkerboard_decode(digs, al, e, uni); n_dec += 1
            for f in (pt, pt.lower()):
                h = G.shahex(f)
                for b in ("SMALL", "COSMIC", "TAIL32"):
                    n_aes += 1
                    for kdf, p in G.aes_try(h, b, kdf="sha256"):
                        n_pad += 1
                        rec = {"how": f"{r['how']}|{an}|esc{e}", "pw": h, "blob": b,
                               "printable": round(G.printable(p), 3), "head": p[:40].decode("latin-1")}
                        if G.semantic(p): HARD.append({**rec, "plaintext_hex": p.hex()})
                        else: SOFT.append(rec)
                kk = G.sha(f.encode()); n_priv += 1
                try:
                    if PublicKey.from_valid_secret(kk).format(False) == TGT:
                        HARD.append({"how": r["how"], "privkey_hex": kk.hex(), "src": f[:100]})
                except Exception:
                    pass
    print(r["how"], "dec", n_dec, "aes", n_aes, "pad", n_pad, round(time.time() - T0), "s", flush=True)

summ = {"event": "oracle_ungated", "n_streams": len(TOP), "n_decodes": n_dec, "n_aes_tries": n_aes,
        "n_valid_padding": n_pad, "padding_rate": round(n_pad / max(1, n_aes), 5),
        "expected_rate_1_256": round(1 / 256, 5), "n_privkey_tries": n_priv,
        "hard_hits": HARD, "n_soft": len(SOFT), "soft_sample": SOFT[:5],
        "n_tests": n_aes + n_priv + n_dec, "secs": round(time.time() - T0)}
G.jsonl(LOG, summ)
print(json.dumps({k: v for k, v in summ.items() if k != "soft_sample"}, indent=1)[:3000])
