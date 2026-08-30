# -*- coding: utf-8 -*-
"""INTERTWINE v3 — selecoes dirigidas pela estrutura 16+7=23 do filme.
('select from the matrix 23 individuals -- 16 female, 7 male')
16 'encryptions' = 16 partes-senha da pagina+fase3; 7 'passwords' = as sete
senhas das sete etapas. Oraculo duplo (alvo+espelho), AES-35 (6 IVs)+ECB+priv.
"""
from __future__ import annotations
import hashlib, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F

from coincurve import PublicKey
from Crypto.Cipher import AES

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
MIRROR_PUBKEY = b"\x04" + TARGET_PUBKEY[1:33] + (
    (P - int.from_bytes(TARGET_PUBKEY[33:65], "big")) % P).to_bytes(32, "big")
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


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    half, bh = R["half"], R["better_half"]
    ivs = (("zero", b"\x00" * 16), ("hdr", header28[:16]), ("half", half[:16]),
           ("bh", bh[:16]), ("blk0", body[:16]), ("cosmic", R["cosmic"][16:32]))
    hits, n = [], 0

    def battery(label, key):
        nonlocal n
        if len(key) != 32:
            return
        n += 1
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

    def xt(label, tokens):
        battery(label, xorr([sha(t) if isinstance(t, bytes) else sha(t) for t in tokens]))

    genesis_hex = ("0x736b6e616220726f662074756f6c69616220646e6f6365732066"
                   "6f206b6e697262206e6f20726f6c6c65636e61684320393030322"
                   "66e614a2f33302073656d697420656854")
    fen = "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    p322_hex = "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
    flower = "theflowerblossomsthroughwhatseemstobeaconcretesurface"
    vic = "FUBCDORA.LETHINGKYMVPS.JQZXW"

    # ===== 16 'female' = 16 partes-senha (fase3 7 + receita 5 + shabef/ans/too/matrixsumlist 4) =====
    sixteen = ["causality", "Safenet", "Luna", "HSM", "11110", genesis_hex, fen,
               "enter", "lastwordsbeforearchichoice", "thispassword",
               "yourlastcommand", "secondanswer",
               "matrixsumlist", "shabef", "ans", "too"]
    # ===== 7 'male' = as sete senhas das sete etapas =====
    seven_hex = [flower, p322_hex, "THEMATRIXHASYOU", vic, FULL69,
                 F.COSMIC_PASSWORD.hex(), F.CHAIN4_PASSWORD.hex()]
    seven_raw = [flower, p322_hex, "THEMATRIXHASYOU", vic, FULL69,
                 F.COSMIC_PASSWORD, F.CHAIN4_PASSWORD]

    xt("16f", sixteen)
    xt("7m_hex", seven_hex)
    xt("7m_raw", seven_raw)
    xt("23=16+7hex", sixteen + seven_hex)
    xt("23=16+7raw", sixteen + seven_raw)
    # variantes de caixa do 7
    xt("7m_lower", [s.lower() if isinstance(s, str) else s for s in seven_hex])
    xt("7m_upper", [s.upper() if isinstance(s, str) else s for s in seven_hex])
    # com WIF (8 etapas)
    xt("8stages", seven_hex + [F.CHAIN2_WIF.decode()])
    xt("8stages_raw", seven_raw + [F.CHAIN2_WIF])
    # com fase 1 (theseedisplanted / banner)
    xt("9stages", ["theseedisplanted"] + seven_hex)
    xt("9stages_banner", ["GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"] + seven_hex)
    # 23 alternativo: 16 + [half,betterhalf,yinyang,yellowblueprimes,salvation,HASHTHETEXT,theseedisplanted]
    xt("23alt", sixteen + ["half", "betterhalf", "yinyang", "yellowblueprimes",
                           "salvation", "HASHTHETEXT", "theseedisplanted"])
    # so as partes da fase 3 (7) + as da pagina (7)
    xt("7f3+7page", ["causality", "Safenet", "Luna", "HSM", "11110", genesis_hex, fen,
                     "matrixsumlist", "enter", "lastwordsbeforearchichoice",
                     "thispassword", "shabef", "ans", "too"])
    # 16 = so as strings AES-openssl do historico (as que abriram blobs de verdade)
    xt("16blobs", [flower, p322_hex, "THEMATRIXHASYOU", vic, FULL69,
                   F.COSMIC_PASSWORD.hex(), F.CHAIN4_PASSWORD.hex(),
                   F.CHAIN2_WIF.decode(),
                   "enter", "lastwordsbeforearchichoice", "thispassword",
                   "yourlastcommand", "secondanswer", "matrixsumlist",
                   "shabef", "ans"])

    print()
    print("=" * 62)
    print(f"TOTAL: {n} chaves | HITS: {len(hits)}")
    print("=" * 62)
    if not hits:
        print("NEGATIVO — 16+7=23 nas leituras naturais nao fecha.")


if __name__ == "__main__":
    main()
