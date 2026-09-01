# -*- coding: utf-8 -*-
"""PASSO 3 — re-roda as familias de chave JA consideradas esgotadas, agora sob o
detector FORTE (strong_oracle_35). Reusa EXATAMENTE os candidatos de
intertwine_attack.py + as familias extras pedidas na auditoria. Sem sweep novo.
"""
import hashlib, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
import strong_oracle_35 as S

FULL69 = "matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).digest()


def xorr(parts):
    x = bytes(32)
    for p in parts:
        x = bytes(a ^ b for a, b in zip(x, p))
    return x


def families(R):
    """Gera (label, key32) — verbatim de intertwine_attack.py + extras."""
    COSMIC_PW = F.COSMIC_PASSWORD
    half, bh = R["half"], R["better_half"]
    header28 = R["header"][2:30]
    fam = []

    # --- cosmic pw raw + sha ---
    fam.append(("cosmic_pw_raw", COSMIC_PW))
    fam.append(("sha256(cosmic_pw)", sha(COSMIC_PW)))

    # --- pools/selecoes XOR-of-sha256 (copia verbatim de intertwine) ---
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
    selections = {
        "first7": big_pool[:7], "first16": big_pool[:16],
        "first23": big_pool[:23], "all": big_pool,
        "phase3_7": ["causality", "Safenet", "Luna", "HSM", "11110", genesis_hex, fen],
        "page7": ["matrixsumlist", "enter", "lastwordsbeforearchichoice",
                  "thispassword", "shabef", "ans", "too"],
        "roadmap": ["yellowblueprimes", "matrixsumlist",
                    "lastwordsbeforearchichoice", "yinyang"],
    }

    def is_prime(n):
        return n >= 2 and all(n % d for d in range(2, int(n ** .5) + 1))

    selections["prime_idx0_7"] = [big_pool[i] for i in range(len(big_pool)) if is_prime(i)][:7]
    selections["prime_idx1_7"] = [big_pool[i - 1] for i in range(1, len(big_pool) + 1) if is_prime(i)][:7]
    selections["prime_idx0_all"] = [big_pool[i] for i in range(len(big_pool)) if is_prime(i)]
    selections["prime_idx1_all"] = [big_pool[i - 1] for i in range(1, len(big_pool) + 1) if is_prime(i)]
    phase_pws = [
        "theflowerblossomsthroughwhatseemstobeaconcretesurface", FULL69,
        "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
        "THEMATRIXHASYOU", "FUBCDORA.LETHINGKYMVPS.JQZXW",
    ]
    selections["phases"] = phase_pws
    selections["phases+recipe"] = phase_pws + ["enter", "yourlastcommand", "secondanswer"]
    selections["roadmap8"] = [
        "yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice",
        "yinyang", "wewontgiveawaythepassword",
        "itsinfrontofyoureyesbutyourenotseeingit",
        "verylaststepisatruegiveaway", "promised"]
    selections["chainpws_str"] = [FULL69, F.CHAIN2_WIF.decode(),
                                  COSMIC_PW.hex(), F.CHAIN4_PASSWORD.hex()]
    recipe = ["enter", "lastwordsbeforearchichoice", "thispassword",
              "yourlastcommand", "secondanswer"]
    selections["recipe+matrixsumlist"] = recipe + ["matrixsumlist"]
    selections["recipe+shabef"] = recipe + ["shabef"]
    selections["recipe+ans"] = recipe + ["ans", "too"]
    selections["recipe+matrixsumlist+shabef"] = recipe + ["matrixsumlist", "shabef"]
    for name, sel in selections.items():
        fam.append((f"xorsha_{name}", xorr([sha(s.encode()) for s in sel])))

    chain_pw_raw = [FULL69.encode(), F.CHAIN2_WIF, COSMIC_PW, F.CHAIN4_PASSWORD]
    fam.append(("xorsha_chainraw", xorr([sha(x) for x in chain_pw_raw])))
    fam.append(("xorsha_chainraw_str", xorr([sha(s.encode()) for s in selections["chainpws_str"]])))
    combined7 = ["matrixsumlist", "enter", "lastwordsbeforearchichoice",
                 "thispassword", "matrixsumlist", "yourlastcommand", "secondanswer"]
    fam.append(("xorsha_combined7", xorr([sha(s.encode()) for s in combined7])))
    fam.append(("xorsha_combined5", xorr([sha(s.encode()) for s in recipe])))

    # --- extras da auditoria (PASSO 3) ---
    fc = F.MATRIX_COMPONENTS[-4:]  # fc0c1b02
    fam.append(("header28||fc0c1b02", header28 + fc))
    fam.append(("fc0c1b02||header28", fc + header28))
    fam.append(("sha256(header28)", sha(header28)))
    for hexc in ("41d464", "be2b9b", "ffffff", "7c5737", "f73d92"):
        fam.append((f"color_{hexc}", header28 + bytes.fromhex(hexc) + b"7"))
    fam.append(("half", half))
    fam.append(("better_half", bh))
    fam.append(("sha256(half)", sha(half)))
    fam.append(("sha256(better_half)", sha(bh)))
    fam.append(("sha256(half||better_half)", sha(half + bh)))
    return fam


def main():
    R = F.reproduce()
    fam = families(R)
    print(f"[strong_recheck] {len(fam)} familias de chave sob o detector FORTE")
    print(f"  alvo   pub = {S.TARGET_PUBKEY.hex()[:24]}...")
    print(f"  espelho pub = {S.MIRROR_PUBKEY.hex()[:24]}...")
    print("=" * 66)
    all_hits, softs = [], []
    t0 = time.time()
    for label, key in fam:
        if len(key) != 32:
            print(f"  [skip len={len(key)}] {label}")
            continue
        hits = S.detect(key, label, R)
        hard = [h for h in hits if h[0] in ("PRIVKEY", "BIP39-ADDR")]
        soft = [h for h in hits if h[0] == "SOFT-PKCS7"]
        all_hits += hard
        softs += soft
        flag = "  !!! HARD-HIT" if hard else ("  ~soft" if soft else "")
        print(f"  [{label:32}] key={key.hex()[:16]}.. hits={len(hard)} soft={len(soft)}{flag}")
        for h in hard:
            print("      ", h)
    dt = time.time() - t0
    print("=" * 66)
    print(f"FAMILIAS: {len(fam)} | HARD-HITS: {len(all_hits)} | SOFT-PKCS7: {len(softs)} | {dt:.1f}s")
    if all_hits:
        print("\n!!!!! ACHADO REAL !!!!!")
        for h in all_hits:
            print("  ", h)
    else:
        print("\nNEGATIVO — mesmo com detector forte (offset byte-a-byte, WIF, BIP39,")
        print("HEX-ASCII, 6 IVs + ECB), nenhuma familia produz privkey/endereco alvo.")
    if softs:
        print(f"\nSOFT-PKCS7 (padding valido, sem exigir ASCII) — {len(softs)} p/ triagem:")
        for h in softs:
            print("  ", h[1], h[2])


if __name__ == "__main__":
    main()
