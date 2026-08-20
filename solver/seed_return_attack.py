# -*- coding: utf-8 -*-
"""Ataque filosofico: "the SEED is PLANTED" + "return to the SOURCE" + "true GIVE AWAY".

Hipotese interpretativa NOVA:
  A matriz 14x14 da fase 1 (a primeira coisa que todos veem = "in front of your
  eyes") e a ENTROPIA BIP39 que deriva a seed master HD wallet. "The seed is
  planted" = a seed BIP39 esta plantada nos bits da matriz. "Return to the source"
  = voltar a essa seed. "True give away" = a resposta estava na fase 1 o tempo todo.

  Ninguem testou os BITS da matriz como entropia BIP39. O ENDGAME so testou BIP39
  dos INDICES coloridos (primos) — que era apofenia (null-model refutou).

  "Cosmic Duality" = half e better_half como parent_priv + chain_code em BIP32
  child key derivation (o "casamento" yin-yang). O "filho" dessa derivacao seria
  a privkey do premio.

Contrato: solve = check_privkey (gera 1GSMG1...) OU aes_open (padding PKCS7 + ascii).
"""
from __future__ import annotations
import hashlib, hmac, os, sys
from coincurve import PublicKey
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PRIZE = O.PRIZE_ADDR

# matriz 14x14 da fase 1 (verbatim do README)
MATRIX_ROWS = [
    "0 0 1 1 0 1 0 0 1 0 1 1 0 0","1 1 1 1 0 0 1 1 1 0 1 0 1 1",
    "1 1 0 1 1 1 0 1 0 0 1 0 0 1","0 1 1 0 1 0 0 0 0 1 1 1 0 1",
    "0 1 1 0 0 0 1 1 0 0 0 1 1 0","1 0 0 1 1 0 0 0 1 0 0 0 1 1",
    "1 0 0 1 1 1 0 0 0 1 0 0 0 0","1 1 1 0 0 0 0 0 0 0 1 0 0 0",
    "0 0 0 1 1 1 0 1 1 1 1 1 0 1","1 1 1 1 1 1 0 0 1 1 0 0 0 1",
    "1 1 0 1 0 0 0 0 0 1 1 0 1 1","1 1 1 1 0 0 1 0 1 0 1 1 0 0",
    "0 1 0 1 1 1 0 1 0 0 0 1 1 0","0 1 1 0 1 1 0 1 1 0 1 0 1 1",
]
GRID = [[int(b) for b in row.replace(" ", "")] for row in MATRIX_ROWS]


def spiral_bits(grid, n, direction):
    """direction='cw' = clockwise (right,down,left,up); 'ccw' = counterclockwise (down,right,up,left)."""
    dirs = [(0,1),(1,0),(0,-1),(-1,0)] if direction == "cw" else [(1,0),(0,1),(-1,0),(0,-1)]
    result, visited = [], [[False]*n for _ in range(n)]
    r, c, d = 0, 0, 0
    for _ in range(n*n):
        result.append(grid[r][c]); visited[r][c] = True
        nr, nc = r+dirs[d][0], c+dirs[d][1]
        if nr<0 or nr>=n or nc<0 or nc>=n or visited[nr][nc]:
            d = (d+1) % 4; nr, nc = r+dirs[d][0], c+dirs[d][1]
        r, c = nr, nc
    return result


def bits_to_bytes(bits):
    """Converte lista de 0/1 para bytes (trunca resto)."""
    n = len(bits) // 8 * 8
    return bytes(int("".join(str(b) for b in bits[i:i+8]), 2) for i in range(0, n, 8))


def check_privkey(priv32):
    return O.check_privkey(priv32)


def bip32_child(parent_priv, parent_chain, index):
    """BIP32 child key derivation (hardened se index >= 0x80000000)."""
    if index >= 0x80000000:
        data = b"\x00" + parent_priv + index.to_bytes(4, "big")
    else:
        pub = PublicKey.from_valid_secret(parent_priv).format(compressed=True)
        data = pub + index.to_bytes(4, "big")
    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_int = (int.from_bytes(h[:32], "big") + int.from_bytes(parent_priv, "big")) % N
    if child_int == 0:
        return None, h[32:]
    return child_int.to_bytes(32, "big"), h[32:]


def bip44_derive(seed_bytes, max_acct=3, max_idx=5):
    """Deriva enderecos BIP44 legacy m/44'/0'/a'/0/i e compara ao premio."""
    from bip_utils import Bip39SeedGenerator, Bip32Slip10Ed25519, Bip44, Bip44Coins, Bip44Changes
    hits = []
    try:
        seed = Bip39SeedGenerator.from_entropy(seed_bytes).Generate()
    except Exception:
        # tentar como seed direta (BIP32, sem BIP39)
        seed = seed_bytes if len(seed_bytes) >= 16 else seed_bytes + b"\x00" * (16 - len(seed_bytes))
    try:
        acct = Bip44.FromSeed(seed, Bip44Coins.BITCOIN) if hasattr(Bip44, "FromSeed") else None
    except Exception:
        acct = None
    if acct is None:
        # usar Bip32 direto
        try:
            from bip_utils import Bip32Slip10Secp256k1
            master = Bip32Slip10Secp256k1.FromSeed(seed)
            for a in range(max_acct):
                node = master.ChildKey(44 + 0x80000000).ChildKey(0 + 0x80000000).ChildKey(a + 0x80000000)
                node = node.ChildKey(Bip44Changes.CHAIN_EXT)
                for i in range(max_idx):
                    addr = node.ChildKey(i).PublicKey().ToAddress()
                    if addr == PRIZE:
                        hits.append(f"m/44'/0'/{a}'/0/{i}")
                    # also internal
                    node2 = master.ChildKey(44+0x80000000).ChildKey(0+0x80000000).ChildKey(a+0x80000000).ChildKey(Bip44Changes.CHAIN_INT)
                    addr2 = node2.ChildKey(i).PublicKey().ToAddress()
                    if addr2 == PRIZE:
                        hits.append(f"m/44'/0'/{a}'/1/{i}")
        except Exception as e:
            pass
        return hits
    for a in range(max_acct):
        for chg in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            ck = acct.Purpose().Coin().Account(a).Change(chg)
            for i in range(max_idx):
                try:
                    addr = ck.AddressIndex(i).PublicKey().ToAddress()
                    if addr == PRIZE:
                        hits.append(f"m/44'/0'/{a}'/{int(chg)}/{i}")
                except Exception:
                    pass
    return hits


def bip39_from_entropy(entropy_bytes):
    """Gera mnemonic BIP39 de entropia valida (16/20/24/28/32 bytes)."""
    from mnemonic import Mnemonic
    m = Mnemonic("english")
    if len(entropy_bytes) in (16, 20, 24, 28, 32):
        try:
            return m.to_mnemonic(entropy_bytes)
        except Exception:
            return None
    return None


def bip39_to_address(mnemonic_str, max_acct=3, max_idx=5):
    """Deriva enderecos de uma mnemonic BIP39 e compara ao premio."""
    from mnemonic import Mnemonic
    from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
    m = Mnemonic("english")
    if not m.check(mnemonic_str):
        return None, []
    seed = Bip39SeedGenerator(mnemonic_str).Generate()
    acct = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    hits = []
    for a in range(max_acct):
        for chg in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            ck = acct.Purpose().Coin().Account(a).Change(chg)
            for i in range(max_idx):
                try:
                    if ck.AddressIndex(i).PublicKey().ToAddress() == PRIZE:
                        hits.append(f"m/44'/0'/{a}'/{int(chg)}/{i}")
                except Exception:
                    pass
    seed_hex = seed.hex()
    return seed_hex, hits


def test_aes_on_35blocks(key, label, hard, soft):
    """Testa uma chave de 32B contra os 35 blocos (ECB + CBC com IVs naturais)."""
    R = F.reproduce()
    body = R["blocks"]
    blocks = [body[i*32:(i+1)*32] for i in range(35)]
    header28 = R["header"][2:30]
    half, bh = R["half"], R["better_half"]
    ivs = {"zero": b"\x00"*16, "hdr": header28[:16], "sha7": hashlib.sha256(b"+-"+header28+b"7").digest()[:16],
           "half": half[:16], "bh": bh[:16], "keylo": key[:16], "keyhi": key[16:32]}
    for ivn, iv in ivs.items():
        try: pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
        except ValueError: continue
        pad = pt[-1]
        if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
            body2 = pt[:-pad]
            asc = sum(32 <= b < 127 for b in body2) / len(body2) if body2 else 0
            if asc >= 0.80 or b"Salted__" in pt or b"\x04" in pt[:5]:
                soft.append({"label": f"{label}/CBC-stream/{ivn}", "asc": round(asc, 3), "head": pt[:80].hex()})
    for blk in blocks:
        try: pt = AES.new(key, AES.MODE_ECB).decrypt(blk)
        except ValueError: continue
        r = O.check_privkey(pt)
        if r: hard.append({"label": f"{label}/ECB", "priv": pt.hex()})


def main():
    R = F.reproduce()
    half, bh, tail = R["half"], R["better_half"], R["matrix_tail"]
    header28 = R["header"][2:30]
    body = R["blocks"]
    blocks = [body[i*32:(i+1)*32] for i in range(35)]

    hard, soft = [], []
    n = 0

    # ========== PARTE A: SEED BIP39 da matriz 14x14 ==========
    print("=== A: Seed BIP39 da matriz 14x14 ===")

    # verificar qual direcao da espiral produz a URL
    for d in ("cw", "ccw"):
        sp = spiral_bits(GRID, 14, d)
        s = "".join(str(b) for b in sp[:192])
        chars = "".join(chr(int(s[i:i+8], 2)) for i in range(0, 192, 8))
        print(f"  espiral {d}: primeiros 24 chars = {chars!r}")
        if "gsmg.io" in chars:
            print(f"  -> espiral {d} CORRETA (produz a URL)")

    # leituras da matriz
    bits_rm = [GRID[r][c] for r in range(14) for c in range(14)]  # row-major, 196 bits
    bits_cm = [GRID[r][c] for c in range(14) for r in range(14)]  # col-major, 196 bits
    bits_cw = spiral_bits(GRID, 14, "cw")
    bits_ccw = spiral_bits(GRID, 14, "ccw")

    readings = {"rowmajor": bits_rm, "colmajor": bits_cm, "spiral_cw": bits_cw, "spiral_ccw": bits_ccw}

    for rname, bits in readings.items():
        # entropia de varios tamanhos (128/160/192 bits)
        for ent_len in (16, 20, 24):  # bytes
            ent = bits_to_bytes(bits[:ent_len*8])
            n += 1
            mnem = bip39_from_entropy(ent)
            if mnem:
                seed_hex, hits = bip39_to_address(mnem)
                if hits:
                    hard.append({"kind": "bip39-matrix", "reading": rname, "ent_len": ent_len,
                                 "mnemonic": mnem, "paths": hits})
                    print(f"  !!! SOLVE BIP39: {rname}/{ent_len}B -> {mnem} -> {hits}")
            # SHA256 da entropia -> privkey direta
            priv = hashlib.sha256(ent).digest()
            n += 1
            r = check_privkey(priv)
            if r:
                hard.append({"kind": "sha256-ent", "reading": rname, "ent_len": ent_len, "priv": priv.hex()})
            # entropia como seed BIP32 direta (sem BIP39)
            n += 1
            hits2 = bip44_derive(ent)
            if hits2:
                hard.append({"kind": "bip32-from-ent", "reading": rname, "ent_len": ent_len, "paths": hits2})

        # SHA256 de TODOS os 196 bits -> privkey
        all_bits_str = "".join(str(b) for b in bits).encode()
        priv = hashlib.sha256(all_bits_str).digest()
        n += 1
        r = check_privkey(priv)
        if r:
            hard.append({"kind": "sha256-allbits", "reading": rname, "priv": priv.hex()})
        # 196 bits como inteiro -> mod n -> privkey
        big_int = int(all_bits_str, 2) % N
        if big_int > 0:
            priv = big_int.to_bytes(32, "big")
            n += 1
            r = check_privkey(priv)
            if r:
                hard.append({"kind": "int-modN", "reading": rname, "priv": priv.hex()})
        # sha256(allbits) como chave AES dos 35 blocos
        test_aes_on_35blocks(priv, f"sha256-allbits-{rname}", hard, soft)
        n += 1

    print(f"  testados: {n}")

    # ========== PARTE B: "gsmg.io/theseedisplanted" como entropia BIP39 ==========
    print("=== B: URL como entropia BIP39 ===")
    url_bytes = b"gsmg.io/theseedisplanted"  # 24 bytes = 192 bits = 18 palavras
    mnem = bip39_from_entropy(url_bytes)
    if mnem:
        print(f"  mnemonic da URL: {mnem}")
        seed_hex, hits = bip39_to_address(mnem)
        if hits:
            hard.append({"kind": "bip39-url", "mnemonic": mnem, "paths": hits})
            print(f"  !!! SOLVE: {hits}")
    # sha256 da URL como privkey
    priv = hashlib.sha256(url_bytes).digest()
    n += 1
    r = check_privkey(priv)
    if r: hard.append({"kind": "sha256-url", "priv": priv.hex()})
    # "theseedisplanted" (17 bytes) -> sha256 -> privkey
    priv = hashlib.sha256(b"theseedisplanted").digest()
    n += 1
    r = check_privkey(priv)
    if r: hard.append({"kind": "sha256-seedplanted", "priv": priv.hex()})
    # a senha da fase 2 (flor) -> sha256 -> privkey + AES 35 blocos
    FLOWER = b"theflowerblossomsthroughwhatseemstobeaconcretesurface"
    priv = hashlib.sha256(FLOWER).digest()
    n += 1
    r = check_privkey(priv)
    if r: hard.append({"kind": "sha256-flower", "priv": priv.hex()})
    test_aes_on_35blocks(priv, "sha256-flower", hard, soft)
    # senha da fase 3.2 (jacque fresco)
    F32 = b"jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
    priv = hashlib.sha256(F32).digest()
    n += 1
    r = check_privkey(priv)
    if r: hard.append({"kind": "sha256-f32", "priv": priv.hex()})
    test_aes_on_35blocks(priv, "sha256-f32", hard, soft)
    # senha da fase 3 (causality...)
    # sha256("causality") = eb3efb51...
    priv = bytes.fromhex("eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf")
    n += 1
    r = check_privkey(priv)
    if r: hard.append({"kind": "sha256-causality", "priv": priv.hex()})
    test_aes_on_35blocks(priv, "sha256-causality", hard, soft)

    print(f"  testados: {n}")

    # ========== PARTE C: BIP32 "Cosmic Duality" = half x better_half ==========
    print("=== C: BIP32 child derivation (half x better_half) ===")
    # half como parent_priv, better_half como chain_code (e vice-versa)
    combos = [
        ("half-priv/bh-chain", half, bh),
        ("bh-priv/half-chain", bh, half),
        ("half-priv/half-chain", half, half),
        ("bh-priv/bh-chain", bh, bh),
    ]
    for label, pp, pc in combos:
        for idx in list(range(10)) + [0x80000000 + i for i in range(5)] + [0x80000000 + 44, 0x80000000 + 0, 0x80000000]:
            child, child_chain = bip32_child(pp, pc, idx)
            if child is None:
                continue
            n += 1
            r = check_privkey(child)
            if r:
                hard.append({"kind": "bip32-child", "combo": label, "index": idx, "priv": child.hex()})
                print(f"  !!! SOLVE BIP32: {label} idx={idx}")
            # derivar BIP44 completo a partir desse child
            if idx < 5:
                # tambem derivar m/44'/0'/0'/0/0 a partir do child como master seed
                try:
                    hits3 = bip44_derive(child, max_acct=2, max_idx=3)
                    if hits3:
                        hard.append({"kind": "bip32->bip44", "combo": label, "idx": idx, "paths": hits3})
                except Exception:
                    pass

    # HMAC-SHA512 direto (sem BIP32, so o hash)
    for label, key, msg in [("half/bh", half, bh), ("bh/half", bh, half)]:
        h = hmac.new(key, msg, hashlib.sha512).digest()
        for half_label, sl in [("lo32", h[:32]), ("hi32", h[32:])]:
            n += 1
            r = check_privkey(sl)
            if r:
                hard.append({"kind": "hmac512", "combo": label, "part": half_label, "priv": sl.hex()})
            test_aes_on_35blocks(sl, f"hmac-{label}-{half_label}", hard, soft)
            n += 1

    print(f"  testados: {n}")

    # ========== PARTE D: 7 palavras do header como senhas entrelacadas ==========
    print("=== D: 7 palavras do header como senhas EVP entrelacadas ===")
    # sequencial: word[i] = header28[i*4:(i+1)*4]
    words_seq = [header28[i*4:(i+1)*4] for i in range(7)]
    # de-interleaved: word[i] = bytes(header28[j] for j in range(i, 28, 7))
    words_deint = [bytes(header28[j] for j in range(i, 28, 7)) for i in range(7)]

    for layout_name, words in (("seq", words_seq), ("deint", words_deint)):
        for group_mode in ("contiguous", "roundrobin"):
            for kdf in (MD5, SHA256):
                # cada palavra abre 5 blocos; usar salt do chain4
                salt = R["chain4_blob"][8:16]
                plains = []
                for i, blk in enumerate(blocks):
                    row = i // 5 if group_mode == "contiguous" else i % 7
                    pw = words[row]
                    k, iv = O._evp(pw, salt, kdf)
                    try:
                        pt = AES.new(k, AES.MODE_CBC, iv).decrypt(blk)
                        plains.append(pt)
                    except ValueError:
                        plains.append(b"")
                    n += 1
                joined = b"".join(plains)
                asc = sum(32 <= b < 127 for b in joined) / len(joined) if joined else 0
                if asc >= 0.80 or b"Salted__" in joined:
                    soft.append({"label": f"7words-{layout_name}-{group_mode}-{kdf.__name__}",
                                 "asc": round(asc, 3), "head": joined[:80].hex()})
                # cada plain como privkey
                for pt in plains:
                    r = check_privkey(pt)
                    if r: hard.append({"kind": "7words-priv", "layout": layout_name, "priv": pt.hex()})
                # XOR dos 7 grupos
                if group_mode == "contiguous":
                    groups = [plains[r*5:(r+1)*5] for r in range(7)]
                    xors = [bytes(a^b^c^d^e for a,b,c,d,e in zip(*g)) for g in groups]
                    for x in xors:
                        r = check_privkey(x)
                        if r: hard.append({"kind": "7words-xor", "layout": layout_name, "priv": x.hex()})
                        n += 1
                    # xor de todos os 7
                    final = bytes(a^b^c^d^e^f^g for a,b,c,d,e,f,g in zip(*xors))
                    r = check_privkey(final)
                    if r: hard.append({"kind": "7words-xor-all", "layout": layout_name, "priv": final.hex()})
                    n += 1

    print(f"  testados: {n}")

    # ========== RESULTADO ==========
    print("\n" + "="*60)
    print(f"TOTAL testes: {n}")
    print(f"HARD hits (pubkey/endereco): {len(hard)}")
    print(f"SOFT hits (padding/ascii): {len(soft)}")
    if hard:
        print("!!! SOLVE !!!")
        for h in hard:
            print(f"  {h}")
    if soft:
        print("--- soft ---")
        for s in soft:
            print(f"  {s}")
    if not hard and not soft:
        print("NEGATIVO — a seed da matriz e a dualidade BIP32 nao fecham o oraculo.")


if __name__ == "__main__":
    main()
