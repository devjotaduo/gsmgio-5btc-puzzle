# -*- coding: utf-8 -*-
"""A1 — checagens deterministicas PEQUENAS de integridade da cadeia Chain1->Chain4.

NAO e sweep. Cada checagem mede um GRAU DE LIBERDADE especifico de um elo e diz
se o valor escolhido no final_chain.py e FORCADO/ANCORADO (unico que funciona,
ou verificado por algo externo) ou SO-PADDING (o parametro foi ajustado para
passar padding/produzir header, sem oraculo independente).
"""
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import final_chain as F
import oracles as O

R = F.reproduce()
chain1, chain2, cosmic = R["chain1"], R["chain2"], R["cosmic"]


def padding_ok(raw, pw):
    """decrypt_salted ja desfaz PKCS7 e levanta ValueError se invalido.

    Aqui a PROPRIA falha de padding e o sinal que queremos medir: ValueError ==
    'esta senha nao abre'. Nao e erro engolido; e o resultado do teste.
    """
    try:
        pt = F.decrypt_salted(raw, pw)
    except ValueError:
        return False, 0, b""
    return True, len(pt), pt[:2]


print("=" * 70)
print("CHECK 1 — Chain4 XOR mask: 'Salted__' e ancora ou e circular?")
print("=" * 70)
head = cosmic[158:166]
derived_mask = bytes(a ^ b for a, b in zip(head, b"Salted__"))
print("  cosmic[158:166]      =", head.hex())
print("  mask usado (const)   =", F.CHAIN4_MASK.hex())
print("  cosmic[158:166]^'Salted__' =", derived_mask.hex())
print("  -> mask == cosmic[158:166]^'Salted__' ?", derived_mask == F.CHAIN4_MASK)
# se sim: os 8 bytes da mask sao exatamente os que forcam 'Salted__'.
# a mask tem 8 bytes de liberdade == o header tem 8 bytes. header NAO e evidencia.
mask_ascii = "".join(chr(c) if 32 <= c < 127 else "." for c in F.CHAIN4_MASK)
print("  mask como ASCII      =", repr(mask_ascii))

print()
print("=" * 70)
print("CHECK 2 — matriz base-38: (i+7)%103 e forcado ou generico?")
print("=" * 70)
bits = "".join(f"{v:08b}" for v in cosmic)[: 103 * 103]
row = [sum(map(int, bits[i * 103:(i + 1) * 103])) for i in range(103)]
col = [sum(bits[r * 103 + c] == "1" for r in range(103)) for c in range(103)]
print(f"  densidade de 1s: {bits.count('1')}/{len(bits)} = {bits.count('1')/len(bits):.3f}")
print(f"  row_sum: min={min(row)} max={max(row)} | col_sum: min={min(col)} max={max(col)}")


def base38_ok(shift, op="add", combine="rowcol"):
    """Retorna (ok, digits) para uma parametrizacao da leitura secundaria."""
    sec = []
    for i in range(103):
        a = row[i]
        b = col[(i + shift) % 103]
        v = (a + b) & 0xFF if op == "add" else (a - b) & 0xFF
        sec.append(v)
    digits = [v - 80 for v in sec]
    ok = all(0 <= d < 38 for d in digits)
    return ok, digits


# quantos shifts 0..102 tambem produzem base-38 valido? (mede quao raro e o encaixe)
ok_shifts = [s for s in range(103) if base38_ok(s, "add")[0]]
print(f"  shifts add com base-38 TODOS validos: {ok_shifts}")
ok_sub = [s for s in range(103) if base38_ok(s, "sub")[0]]
print(f"  shifts sub com base-38 TODOS validos: {ok_sub}")
# distancia da borda: quantos digitos ficam a <=2 do limite [0,38)?
_, dig7 = base38_ok(7, "add")
edge = sum(1 for d in dig7 if d <= 1 or d >= 36)
print(f"  no shift=7: digitos min={min(dig7)} max={max(dig7)}; a <=1 da borda: {edge}/103")

print()
print("=" * 70)
print("CHECK 3 — Chain1->Chain2: encoding da senha (grau de liberdade)")
print("=" * 70)
sk = chain1[:32]
import base58
cands = {
    "wif_uncompressed": F.wif_uncompressed(sk),
    "wif_compressed": base58.b58encode(
        b"\x80" + sk + b"\x01" +
        hashlib.sha256(hashlib.sha256(b"\x80" + sk + b"\x01").digest()).digest()[:4]),
    "raw_hex_lower": sk.hex().encode(),
    "raw_hex_upper": sk.hex().upper().encode(),
    "raw_bytes32": sk,
}
raw2 = base64.b64decode(F.CHAIN2_B64)
for name, pw in cands.items():
    ok, ln, mk = padding_ok(raw2, pw)
    hit = " <-- usado no final_chain" if name == "wif_uncompressed" else ""
    print(f"  {name:18s}: PKCS7 valido = {ok} (len={ln}){hit}")

print()
print("=" * 70)
print("CHECK 4 — Chain4: offset 64 e unico ou muitos offsets abrem?")
print("=" * 70)
# a senha e chain1[o:o+15] + chain2[o:o+15] + cosmic[64:66]; varia so o offset o
# dos dois keymats de 79B (0..64). tambem varia o slice da cosmic e o [158:-1].
blob = F.xor_cycle(cosmic[158:-1], F.CHAIN4_MASK)
good = []
for o in range(0, 65):
    pw = chain1[o:o + 15] + chain2[o:o + 15] + cosmic[64:66]
    ok, ln, mk = padding_ok(blob, pw)
    if ok:
        good.append((o, ln, mk))
print(f"  offsets 0..64 que dao PKCS7 valido no Chain4: {[g[0] for g in good]}")
for o, ln, mk in good:
    print(f"    offset {o}: len={ln} marker={mk!r}")

# sensibilidade do offset 158 do blob XOR: outros offsets dao 'Salted__'?
print("  offsets vizinhos de 158 que produzem header 'Salted__' apos XOR:")
found = []
for off in range(140, 180):
    seg = cosmic[off:off + 8]
    if len(seg) == 8 and bytes(a ^ b for a, b in zip(seg, F.CHAIN4_MASK)) == b"Salted__":
        found.append(off)
print(f"    {found}  (mask fixa; so o offset usado casa por construcao)")

print()
print("=" * 70)
print("CHECK 5 — half/better_half -> enderecos externos (ancora forte?)")
print("=" * 70)
au_h, ac_h, _, _ = O.priv_to_addresses(R["half"])
au_b, ac_b, _, _ = O.priv_to_addresses(R["better_half"])
claim = {"1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu", "145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ"}
got = {au_h, ac_h, au_b, ac_b}
print(f"  half        unc={au_h}  comp={ac_h}")
print(f"  better_half unc={au_b}  comp={ac_b}")
print(f"  ENDGAME afirma: 1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu / 145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ")
print(f"  -> algum endereco derivado bate a afirmacao do ENDGAME? {bool(got & claim)}")
