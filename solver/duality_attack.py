# -*- coding: utf-8 -*-
"""A DUALIDADE CORDIAL — inducao da receita PROVADA (sessao 2026-08-30):
  senha-SMALL  = CONCAT das 7 partes (69 chars)
  senha-COSMIC = XOR dos sha256 das MESMAS 7 partes   [PROVADO]
  => 'Cosmic Duality' = cada par de senhas existe nas DUAS gramaticas.
Testes da inducao:
  A) fase 3: sha256(concat 7 partes) = 1a57c572 (documentado) — e o XOR-form
     das mesmas partes = a senha da fase 3.2 (250f3772...)?
  B) FINAL: chain4 pw = CONCAT das fatias (E_C||E_S||E_B) — logo a chave dos
     35 blocos = XOR(sha256(E_C), sha256(E_S), sha256(E_B)) e variantes.
Oraculo duplo (alvo + espelho); AES CBC 6 IVs + ECB + scan privkey.
"""
from __future__ import annotations
import hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

from coincurve import PublicKey
from Crypto.Cipher import AES

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
MIRROR_PUBKEY = b"\x04" + TARGET_PUBKEY[1:33] + (
    (P - int.from_bytes(TARGET_PUBKEY[33:65], "big")) % P).to_bytes(32, "big")


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


def evp_kdf(pw, salt):
    d = d_i = b""
    while len(d) < 48:
        d_i = hashlib.md5(d_i + pw + salt).digest()
        d += d_i
    return d[:32], d[32:48]


def evp_open(salt, ct, pw):
    key, iv = evp_kdf(pw, salt)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if not pt or len(pt) % 16:
        return None
    p = pt[-1]
    if not 1 <= p <= 16 or not pt.endswith(bytes([p]) * p):
        return None
    return pt[:-p]


def main():
    R = F.reproduce()
    header28 = R["header"][2:30]
    body = R["blocks"]
    half, bh = R["half"], R["better_half"]
    chain1, chain2, cosmic = R["chain1"], R["chain2"], R["cosmic"]
    E_C = chain1[64:79]
    E_S = chain2[64:79]
    E_B = cosmic[64:66]
    small_salt, small_ct = O.blobs()["SMALL"]
    cosmic_salt, cosmic_ct = O.blobs()["COSMIC"]
    ivs = (("zero", b"\x00" * 16), ("hdr", header28[:16]), ("half", half[:16]),
           ("bh", bh[:16]), ("blk0", body[:16]), ("cosmic", cosmic[16:32]))
    hits = []

    # ================= A) a dualidade na fase 3 =================
    print("=" * 62)
    print("A) DUALIDADE FASE 3: concat-form vs XOR-form das 7 partes")
    print("=" * 62)
    genesis_hex = ("0x736b6e616220726f662074756f6c69616220646e6f6365732066"
                   "6f206b6e697262206e6f20726f6c6c65636e61684320393030322"
                   "66e614a2f33302073656d697420656854")
    fen = "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    p3 = ["causality", "Safenet", "Luna", "HSM", "11110", genesis_hex, fen]
    concat_form = hashlib.sha256("".join(p3).encode()).hexdigest()
    xor_form = xorr([sha(x) for x in p3]).hex()
    print(f"   sha256(concat) = {concat_form}")
    print(f"   XOR-form       = {xor_form}")
    print(f"   (doc: fase 3 pw = 1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5)")
    print(f"   (doc: fase 3.2 pw = 250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c)")
    if concat_form == "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5":
        print("   -> concat-form CONFIRMA documentacao (fase 3)")
    if xor_form == "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c":
        print("   !!! DUALIDADE CONFIRMADA: fase 3.2 = XOR-form das 7 partes da fase 3 !!!")
    # e o inverso: o XOR-form das partes da fase 3.2 abre o blob 3.2?
    # (o 3.2 pw ja e o XOR? testar o concat-form da fase 3.2 se conhecido)

    # ================= B) a chave final: XOR-form das fatias do chain4 =====
    print()
    print("=" * 62)
    print("B) FINAL: chain4 = CONCAT(E_C||E_S||E_B) -> chave = XOR-form das fatias")
    print("=" * 62)
    print(f"   E_C = {E_C.hex()}  ({len(E_C)}B)")
    print(f"   E_S = {E_S.hex()}  ({len(E_S)}B)")
    print(f"   E_B = {E_B.hex()}  ({len(E_B)}B)")

    def battery(label, key):
        if len(key) != 32:
            print(f"   [skip] {label}: chave com {len(key)}B")
            return
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
            if valid_pt(joined) or b"Salted__" in joined:
                hits.append(f"SOFT {label}_ecb: {joined[:60].hex()}")
                print(hits[-1])
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

    # o palpite central da inducao
    key_duality = xorr([sha(E_C), sha(E_S), sha(E_B)])
    print(f"   XOR(sha(E_C),sha(E_S),sha(E_B)) = {key_duality.hex()}")
    battery("duality_slices", key_duality)

    # variantes de partes do chain4
    chain4 = R["chain4"]
    battery("xor_sha_c4_2half", xorr([sha(chain4[:16]), sha(chain4[16:])]))
    battery("xor_sha_c4_7w", xorr([sha(chain4[i * 4:(i + 1) * 4]) for i in range(7)] + [sha(b"7")]))
    battery("xor_sha_c4_7w2", xorr([sha(chain4[i * 4:(i + 1) * 4]) for i in range(8)]))
    # as fatias completas em 64: de cada estagio
    battery("xor_sha_64slices", xorr([sha(chain1[64:96]), sha(chain2[64:96]), sha(cosmic[64:96])]))
    # E_C/E_S/E_B + as senhas-mae
    battery("xor_sha_EC_ES_EB_full", xorr([sha(chain1), sha(chain2[64:79]), sha(cosmic[64:66])]))
    # duality aplicada a 69-char + WIF + c4pw (as senhas 'concat' da cadeia -> XOR-form)
    parts_chain = [F.CHAIN1_PASSWORD, F.CHAIN2_WIF, F.CHAIN4_PASSWORD]
    battery("xor_sha_chainpws3", xorr([sha(x) for x in parts_chain]))
    battery("xor_sha_chainpws4", xorr([sha(x) for x in parts_chain + [F.COSMIC_PASSWORD]]))
    # as 7 partes do combined em XOR = a795de11 (o cosmic) — o par dual do SMALL
    # (validacao) — e o XOR-form do CHAIN4-parts:
    print()
    print("   [validacao] XOR-form do combined 7 = cosmic pw? ",
          xorr([sha(t) for t in ["matrixsumlist", "enter", "lastwordsbeforearchichoice",
                                 "thispassword", "matrixsumlist", "yourlastcommand",
                                 "secondanswer"]]) == F.COSMIC_PASSWORD)

    # ================= C) as duas formas contra SMALL/COSMIC/35 ============
    print()
    print("=" * 62)
    print("C) chaves XOR-form como passphrases EVP (SMALL/COSMIC)")
    print("=" * 62)
    for label, pw in (("duality_slices", key_duality),
                      ("xor_sha_c4_7w", sha(chain4[:4]) and b""),
                      ("chain4pw", F.CHAIN4_PASSWORD)):
        if not pw:
            continue
        for nm, salt, ct in (("SMALL", small_salt, small_ct), ("COSMIC", cosmic_salt, cosmic_ct)):
            pt = evp_open(salt, ct, pw)
            if pt is not None:
                print(f"   [pad-ok] {label}_{nm} ascii={pr(pt):.2f} head={pt[:24].hex()}")
                if pr(pt) >= 0.85:
                    hits.append(f"!!! {label}_{nm} SEMANTICO: {pt[:60].hex()}")

    print()
    print("=" * 62)
    print(f"TOTAL HITS: {len(hits)}")
    print("=" * 62)
    for h in hits:
        print(f"  {h}")
    if not hits:
        print("NEGATIVO — a inducao da dualidade (fatias) nao fecha o FINAL.")


if __name__ == "__main__":
    main()
