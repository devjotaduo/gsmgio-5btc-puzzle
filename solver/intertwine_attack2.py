# -*- coding: utf-8 -*-
"""INTERTWINE v2 — a mecanica esta PROVADA (cosmic pw = XOR dos sha256 das
partes: enter, lastwordsbeforearchichoice, thispassword, yourlastcommand,
secondanswer — ver intertwine_attack.py). Falta a SELECAO final.
'select from over twenty-three ciphers sixteen encryptions and or seven
intertwined passwords' -> bateria exaustiva de selecoes:
  - pool cronologico das senhas do puzzle (~30) com selecoes por header-words
    (indices), primos, first-7/16/23;
  - TODAS as 7-subsets do nucleo da pagina (C(12,7)=792);
  - janelas deslizantes de 7/16/23 palavras sobre o monologo e o texto 3.2.2;
  - receita-cosmica + 1 token (todas as extensoes);
  - palavras inseridas do diff do Arquiteto (YOU/ME/WELL/NOT/CODES/HOPEFULLY).
Oraculo duplo: alvo + espelho. AES-35-blocos CBC (6 IVs) + ECB + privkey.
"""
from __future__ import annotations
import hashlib, itertools, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
from architect_diff import PUZZLE as MONO

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
MIRROR_PUBKEY = b"\x04" + TARGET_PUBKEY[1:33] + (
    (P - int.from_bytes(TARGET_PUBKEY[33:65], "big")) % P).to_bytes(32, "big")
S322 = ("IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND "
        "BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE")
FULL69 = "matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"


def pub(s):
    return PublicKey.from_valid_secret(s).format(compressed=False)


def pr(d):
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in d) / len(d) if d else 0.0


def valid_pt(d):
    if not d or len(d) % 16:
        return False
    p = d[-1]
    return 1 <= p <= 16 and d.endswith(bytes([p]) * p) and pr(d[:-p]) >= 0.80


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).digest()


def xorr(parts):
    x = bytes(32)
    for p in parts:
        x = bytes(a ^ b for a, b in zip(x, p))
    return x


def is_prime(n):
    return n >= 2 and all(n % d for d in range(2, int(n ** .5) + 1))


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    half, bh = R["half"], R["better_half"]
    ivs = (("zero", b"\x00" * 16), ("hdr", header28[:16]),
           ("half", half[:16]), ("bh", bh[:16]), ("blk0", body[:16]),
           ("cosmic", R["cosmic"][16:32]))
    hits, nkeys = [], 0

    def battery(label, key):
        nonlocal nkeys
        if len(key) != 32:
            return
        nkeys += 1
        for nm, s in (("T", TARGET_PUBKEY), ("M", MIRROR_PUBKEY)):
            try:
                if pub(key) == s:
                    hits.append(f"!!! PRIVKEY[{nm}] {label} = {key.hex()}")
                    print(hits[-1])
            except ValueError:
                pass
        for ivn, iv in ivs:
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            if valid_pt(pt) or b"Salted__" in pt:
                hits.append(f"SOFT {label}_aes_{ivn}: {pt[:60].hex()}")
                print(hits[-1])
            for j in range(0, len(pt) - 31, 16):
                c = pt[j:j + 32]
                for nm, s in (("T", TARGET_PUBKEY), ("M", MIRROR_PUBKEY)):
                    try:
                        if pub(c) == s:
                            hits.append(f"!!! PRIVKEY[{nm}] {label}_aes_{ivn}_off{j} = {c.hex()}")
                            print(hits[-1])
                    except ValueError:
                        pass
        try:
            joined = b"".join(AES.new(key, AES.MODE_ECB).decrypt(
                body[i * 32:(i + 1) * 32]) for i in range(35))
            for j in range(0, len(joined) - 31, 16):
                c = joined[j:j + 32]
                for nm, s in (("T", TARGET_PUBKEY), ("M", MIRROR_PUBKEY)):
                    try:
                        if pub(c) == s:
                            hits.append(f"!!! PRIVKEY[{nm}] {label}_ecb_off{j} = {c.hex()}")
                            print(hits[-1])
                    except ValueError:
                        pass
        except ValueError:
            pass

    def xor_tokens(label, tokens):
        battery(label, xorr([sha(t.encode()) for t in tokens]))

    # ============ pool cronologico das senhas do puzzle ============
    genesis_hex = ("0x736b6e616220726f662074756f6c69616220646e6f6365732066"
                   "6f206b6e697262206e6f20726f6c6c65636e61684320393030322"
                   "66e614a2f33302073656d697420656854")
    fen = "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    pool = [
        "theseedisplanted",
        "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
        "theflowerblossomsthroughwhatseemstobeaconcretesurface",
        "causality", "Safenet", "Luna", "HSM", "11110", genesis_hex, fen,
        "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
        "THEMATRIXHASYOU", "FUBCDORA.LETHINGKYMVPS.JQZXW",
        "matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
        "shabef", "ans", "too", "yourlastcommand", "secondanswer",
        "half", "betterhalf", "yinyang", "yellowblueprimes", "salvation",
        "HASHTHETEXT", FULL69, F.CHAIN2_WIF.decode(), F.COSMIC_PASSWORD.hex(),
    ]
    print(f"[pool] {len(pool)} senhas cronologicas")

    # selecoes por primos
    xor_tokens("pool_prime0_7", [pool[i] for i in range(len(pool)) if is_prime(i)][:7])
    xor_tokens("pool_prime1_7", [pool[i - 1] for i in range(1, len(pool) + 1) if is_prime(i)][:7])
    xor_tokens("pool_prime0_all", [pool[i] for i in range(len(pool)) if is_prime(i)])
    xor_tokens("pool_prime1_all", [pool[i - 1] for i in range(1, len(pool) + 1) if is_prime(i)])
    # primeiras N
    for n in (7, 16, 23, 29):
        xor_tokens(f"pool_first{n}", pool[:n])
    # header-words como indices (big/little, mod len)
    words = [int.from_bytes(header28[i * 4:(i + 1) * 4], e) for e in ("big", "little") for i in range(7)]
    for e, ws in (("big", words[:7]), ("little", words[7:])):
        sel = [pool[w % len(pool)] for w in ws]
        xor_tokens(f"pool_hdr7w_{e}", sel)

    # ============ nucleo da pagina: TODAS as 7-subsets (792) ============
    core = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
            "shabef", "ans", "too", "yourlastcommand", "secondanswer",
            "half", "betterhalf", "salvation"]
    print(f"[core] {len(core)} tokens -> C(12,7)={sum(1 for _ in itertools.combinations(core, 7))} subsets")
    for combo in itertools.combinations(core, 7):
        xor_tokens(f"core7_{'|'.join(c[:6] for c in combo)}", list(combo))

    # ============ receita cosmica + 1 token (extensoes) ============
    recipe = ["enter", "lastwordsbeforearchichoice", "thispassword",
              "yourlastcommand", "secondanswer"]
    for extra in pool:
        xor_tokens(f"recipe+{extra[:18]}", recipe + [extra])

    # ============ palavras inseridas do diff + frases do Arquiteto ============
    xor_tokens("diff_inserts", ["YOU", "ME", "WELL", "NOT", "CODES", "HOPEFULLY"])
    xor_tokens("arch_phrases", ["RETURNTOTHESOURCECODES", "REINSERTINGTHEPRIMEBASICS",
                                "THEACTUALPRIVATEKEYNOTE", "BRUTEFORCINGMIGHTBEREQUIRED"])
    xor_tokens("diff+arch", ["YOU", "ME", "WELL", "NOT", "CODES", "HOPEFULLY",
                             "THEACTUALPRIVATEKEYNOTE"])

    # ============ janelas deslizantes de 7/16/23 palavras ============
    for tname, text in (("mono", MONO), ("s322", S322)):
        wds = text.upper().split()
        for k in (7, 16, 23):
            for off in range(0, len(wds) - k + 1):
                win = [w.strip(".,'!?-;:") for w in wds[off:off + k]]
                xor_tokens(f"win{k}_{tname}_{off}", win)

    print()
    print("=" * 62)
    print(f"TOTAL: {nkeys} chaves testadas | HITS: {len(hits)}")
    print("=" * 62)
    if not hits:
        print("NEGATIVO — nenhuma selecao XOR fecha os 35 blocos.")


if __name__ == "__main__":
    main()
