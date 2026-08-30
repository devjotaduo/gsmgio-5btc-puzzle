# -*- coding: utf-8 -*-
"""INTERTWINED PASSWORDS: k1ng (Telegram 2025-08-23) revelou a receita do
passphrase do Cosmic: 'the combined passwords produce what he said, but you
need to hash them individually and then xor them together' -> a795de11.

'seven INTERTWINED passwords' do Arquiteto = XOR dos sha256 individuais.
Parte 1: pinar o conjunto EXATO de tokens cujo XOR de sha256 = a795de11 (prova
          da mecanica, zero graus de liberdade).
Parte 2: aplicar a mesma mecanica como chave dos 35 blocos (selecoes 7/16/23
          do pool natural, indices primos etc.) + a795de11 raw como chave.
Parte 3: preimage direto sha256(x) == a795de11 sobre o corpus.
"""
from __future__ import annotations
import hashlib, itertools, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
X_T = TARGET_PUBKEY[1:33]
Y_T = int.from_bytes(TARGET_PUBKEY[33:65], "big")
MIRROR_PUBKEY = b"\x04" + X_T + ((P - Y_T) % P).to_bytes(32, "big")
COSMIC_PW = F.COSMIC_PASSWORD  # a795de11...
FULL69 = "matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"


def pub(s):
    return PublicKey.from_valid_secret(s).format(compressed=False)


def pr(data):
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data) if data else 0.0


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


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    half, bh = R["half"], R["better_half"]
    small_salt, small_ct = O.blobs()["SMALL"]
    hits = []

    def full_battery(label: str, key: bytes):
        if len(key) != 32:
            return
        for nm, s in (("target", TARGET_PUBKEY), ("mirror", MIRROR_PUBKEY)):
            if pub(key) == s:
                hits.append(f"!!! PRIVKEY {nm}: {label} = {key.hex()}")
                print(hits[-1])
        for ivn, iv in (("zero", b"\x00" * 16), ("hdr", header28[:16]),
                        ("half", half[:16]), ("bh", bh[:16]), ("blk0", body[:16])):
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            if valid_pt(pt) or b"Salted__" in pt:
                hits.append(f"SOFT {label}_aes_{ivn}: {pt[:60].hex()}")
                print(hits[-1])
            for j in range(0, len(pt) - 31, 16):
                for nm, s in (("target", TARGET_PUBKEY), ("mirror", MIRROR_PUBKEY)):
                    if pub(pt[j:j + 32]) == s:
                        hits.append(f"!!! PRIVKEY {label}_aes_{ivn}_off{j} = {pt[j:j+32].hex()}")
                        print(hits[-1])
        try:
            pts = [AES.new(key, AES.MODE_ECB).decrypt(body[i * 32:(i + 1) * 32]) for i in range(35)]
            joined = b"".join(pts)
            for j in range(0, len(joined) - 31, 16):
                for nm, s in (("target", TARGET_PUBKEY), ("mirror", MIRROR_PUBKEY)):
                    if pub(joined[j:j + 32]) == s:
                        hits.append(f"!!! PRIVKEY {label}_ecb_off{j} = {joined[j:j+32].hex()}")
                        print(hits[-1])
        except ValueError:
            pass

    # ================= parte 1: pinar a receita do a795de11 =================
    print("=" * 62)
    print("PARTE 1: qual subset de tokens XORa para a795de11?")
    print("=" * 62)
    pool = [
        "matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
        "yourlastcommand", "secondanswer", "shabef", "ans", "too", "anstoo",
        "half", "betterhalf", "ourfirsthintisyourlastcommand", FULL69,
    ]
    found_recipes = []
    for r in range(1, len(pool) + 1):
        for combo in itertools.combinations(range(len(pool)), r):
            parts = [sha(pool[i].encode()) for i in combo]
            if xorr(parts) == COSMIC_PW:
                names = [pool[i] for i in combo]
                found_recipes.append(names)
                print(f"   RECEITA: XOR(sha256): {names}")
    if not found_recipes:
        print("   nenhum subset do pool (14 tokens) reproduz a795de11")
        # variantes de caixa
        pool_u = [p.upper() for p in pool]
        for r in range(1, len(pool_u) + 1):
            for combo in itertools.combinations(range(len(pool_u)), r):
                if xorr([sha(pool_u[i].encode()) for i in combo]) == COSMIC_PW:
                    print(f"   RECEITA (UPPER): {[pool_u[i] for i in combo]}")
                    found_recipes.append([pool_u[i] for i in combo])

    # ================= parte 2: a795de11 raw + mecanica nos 35 blocos ========
    print()
    print("=" * 62)
    print("PARTE 2: chaves nos 35 blocos (oraculo duplo: alvo + espelho)")
    print("=" * 62)
    full_battery("cosmic_pw_raw", COSMIC_PW)
    full_battery("sha256(cosmic_pw)", sha(COSMIC_PW))

    # pool natural de senhas do puzzle (ordem da pagina/fases/roadmap)
    genesis_hex = ("0x736b6e616220726f662074756f6c69616220646e6f6365732066"
                   "6f206b6e697262206e6f20726f6c6c65636e61684320393030322"
                   "66e614a2f33302073656d697420656854")
    fen = "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    big_pool = [
        "matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
        "shabef", "ans", "too", "ourfirsthintisyourlastcommand", "half",
        "betterhalf", "cosmicduality", "salphaseion", "yellowblueprimes",
        "yinyang", "causality", "Safenet", "Luna", "HSM", "11110",
        genesis_hex, fen, "THEMATRIXHASYOU", "HASHTHETEXT", "gsmg",
        "yourlastcommand", "secondanswer", "salvation",
        "theflowerblossomsthroughwhatseemstobeaconcretesurface",
        "jacquefrescocausalitydualityend",
    ]
    # selecoes naturais
    selections = {
        "first7": big_pool[:7],
        "first16": big_pool[:16],
        "first23": big_pool[:23],
        "all": big_pool,
        "phase3_7": ["causality", "Safenet", "Luna", "HSM", "11110", genesis_hex, fen],
        "page7": ["matrixsumlist", "enter", "lastwordsbeforearchichoice",
                  "thispassword", "shabef", "ans", "too"],
        "roadmap": ["yellowblueprimes", "matrixsumlist",
                    "lastwordsbeforearchichoice", "yinyang"],
    }
    # indices primos no pool (0-based e 1-based)
    def is_prime(n):
        if n < 2:
            return False
        return all(n % d for d in range(2, int(n ** .5) + 1))
    selections["prime_idx0_7"] = [big_pool[i] for i in range(len(big_pool)) if is_prime(i)][:7]
    selections["prime_idx1_7"] = [big_pool[i - 1] for i in range(1, len(big_pool) + 1) if is_prime(i)][:7]
    selections["prime_idx0_all"] = [big_pool[i] for i in range(len(big_pool)) if is_prime(i)]
    selections["prime_idx1_all"] = [big_pool[i - 1] for i in range(1, len(big_pool) + 1) if is_prime(i)]
    # senhas das FASES (a gramatica das senhas do puzzle, em ordem)
    phase_pws = [
        "theflowerblossomsthroughwhatseemstobeaconcretesurface",  # fase 2
        FULL69,                                                     # fase 3/SMALL
        "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",  # fase 3.2
        "THEMATRIXHASYOU",                                          # fase 3.2.1
        "FUBCDORA.LETHINGKYMVPS.JQZXW",                             # alfabeto VIC 3.2.2
    ]
    selections["phases"] = phase_pws
    selections["phases+recipe"] = phase_pws + ["enter", "yourlastcommand", "secondanswer"]
    # roadmap completo (8 frases decodificadas do criador)
    selections["roadmap8"] = [
        "yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice",
        "yinyang", "wewontgiveawaythepassword",
        "itsinfrontofyoureyesbutyourenotseeingit",
        "verylaststepisatruegiveaway", "promised",
    ]
    # senhas da CADEIA (chain1..chain4) — a gramatica da cadeia
    chain_pw_str = [FULL69, F.CHAIN2_WIF.decode(), COSMIC_PW.hex(), F.CHAIN4_PASSWORD.hex()]
    selections["chainpws_str"] = chain_pw_str
    chain_pw_raw = [FULL69.encode(), F.CHAIN2_WIF, COSMIC_PW, F.CHAIN4_PASSWORD]
    selections["chainpws_raw"] = ["RAW:" + x.hex() for x in chain_pw_raw]  # placeholder
    # receita + variantes
    recipe = ["enter", "lastwordsbeforearchichoice", "thispassword",
              "yourlastcommand", "secondanswer"]
    selections["recipe+matrixsumlist"] = recipe + ["matrixsumlist"]
    selections["recipe+shabef"] = recipe + ["shabef"]
    selections["recipe+ans"] = recipe + ["ans", "too"]
    selections["recipe+matrixsumlist+shabef"] = recipe + ["matrixsumlist", "shabef"]
    for name, sel in selections.items():
        if name == "chainpws_raw":
            continue
        key = xorr([sha(s.encode()) for s in sel])
        full_battery(f"xorsha_{name}", key)
    # chain raw (bytes: hash dos bytes crus)
    full_battery("xorsha_chainraw", xorr([sha(x) for x in chain_pw_raw]))
    full_battery("xorsha_chainraw_str", xorr([sha(s.encode()) for s in chain_pw_str]))

    # as 7 partes + yourlastcommand/secondanswer (a decomposicao do 'combined')
    combined_parts = ["matrixsumlist", "enter", "lastwordsbeforearchichoice",
                      "thispassword", "matrixsumlist", "yourlastcommand",
                      "secondanswer"]
    key_combined = xorr([sha(s.encode()) for s in combined_parts])
    print(f"   XOR(7 combined parts) = {key_combined.hex()}")
    print(f"   == cosmic_pw? {key_combined == COSMIC_PW}")
    full_battery("xorsha_combined7", key_combined)
    # sem o matrixsumlist duplicado (XOR cancela pares! -> equivale a 5 distintos)
    dedup = ["enter", "lastwordsbeforearchichoice", "thispassword",
             "yourlastcommand", "secondanswer"]
    full_battery("xorsha_combined5", xorr([sha(s.encode()) for s in dedup]))

    # se a receita foi encontrada, gerar variantes da RECEITA exata
    for recipe in found_recipes[:3]:
        full_battery(f"recipe_{len(recipe)}", xorr([sha(s.encode()) for s in recipe]))

    # ================= parte 3: preimage direto =================
    print()
    print("=" * 62)
    print("PARTE 3: preimage sha256(x) == a795de11 sobre corpus")
    print("=" * 62)
    corpus = set()
    for s in big_pool + pool + [FULL69]:
        corpus.add(s)
        corpus.add(s.upper())
        corpus.add(s.lower())
        corpus.add(s.replace(" ", ""))
    corpus.update(["GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
                   "gsmg.io/theseedisplanted", "theseedisplanted", "11SEP2001",
                   "11SEP2001", "11092001", "20010911", "SEP112001",
                   "GLOBALLYSUPPORTINGMYGENERATION", "Le Miroir de la Vie et de la Mort",
                   "LEMIROIRDELAVIEETDELAMORT", "COSMICDUALITY", "matrixsumlist101",
                   "matrixsumlistenterlastwordsbeforearchichoicethispassword"])
    pre = 0
    for c in corpus:
        if sha(c) == COSMIC_PW:
            print(f"   !!! PREIMAGE: {c!r}")
            pre += 1
    if not pre:
        print(f"   nenhum preimage em {len(corpus)} candidatos")

    print()
    print("=" * 62)
    print(f"TOTAL HITS: {len(hits)}")
    print("=" * 62)
    if not hits:
        print("NEGATIVO — mecanica XOR-of-sha256 nao fecha os 35 blocos nas selecoes naturais.")


if __name__ == "__main__":
    main()
