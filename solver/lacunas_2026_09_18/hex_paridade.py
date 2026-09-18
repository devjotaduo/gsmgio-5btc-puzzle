"""Conversão hex -> bytes de comprimento ímpar: zero à esquerda (kit) × From Hex do CyberChef.

Reproduz a entrega de 18/09 e registra por que a divergência só existe em hex de comprimento ímpar.
  - CyberChef `fromHex` (src/core/lib/Hex.mjs): pares desde o início; o dígito que sobra vira um byte.
  - `G.z_method` e ~40 scripts: zero à esquerda (inverso exato de bytes -> inteiro).
Uso: python hex_paridade.py   (só asserts e contagens; nenhuma AES)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments" / "claude_endgame_2026_09_02"))
import gsmg_common as G  # noqa: E402

LETRAS = "abcdefghi"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]


def cyberchef(h):
    return bytes(int(h[i:i + 2], 16) for i in range(0, len(h), 2))


def zero_esquerda(h):
    return bytes.fromhex("0" + h if len(h) % 2 else h)


def hex_de(campo, zerados):
    dig = "".join("0" if c in zerados else str(LETRAS.index(c) + 1) for c in campo)
    return format(int(dig), "x")


def main():
    assert cyberchef("123") == b"\x12\x03" and zero_esquerda("123") == b"\x01\x23"
    assert G.z_method([1, 2, 3]) == zero_esquerda(format(123, "x"))  # o kit usa zero à esquerda

    # Direção do criador (texto -> hex -> decimal): printável tem 1.º nibble >= 2, logo hex par,
    # e as duas convenções devolvem o mesmo texto. Vale para os dois controles da página.
    for t in (b"lastwordsbeforearchichoice", b"thispassword", bytes(range(0x20, 0x7F))):
        h = format(int.from_bytes(t, "big"), "x")
        assert len(h) % 2 == 0 and cyberchef(h) == zero_esquerda(h) == t
    # Bytes crus com 1.º byte 0x0N: hex ímpar, e só o zero à esquerda devolve os bytes originais.
    cru = bytes([0x03, 0x17, 0x80, 0xAB])
    h = format(int.from_bytes(cru, "big"), "x")
    assert zero_esquerda(h) == cru and cyberchef(h) != cru

    h = hex_de(R84, set())
    assert len(h) == 51
    assert zero_esquerda(h)[:3].hex() == "031780" and cyberchef(h)[:3].hex() == "317807"

    tot = dif = impar = 0
    for campo in (R83, R84, G.DBBI, G.FAED):
        for s in (campo, campo[::-1]):
            for z in range(512):
                h = hex_de(s, {c for k, c in enumerate(LETRAS) if z >> k & 1})
                tot += 1
                impar += len(h) % 2 and h != "0"  # tudo zerado dá n = 0, hex "0": as duas dão 00
                dif += cyberchef(h) != zero_esquerda(h)
    assert (tot, dif) == (4096, 1767) and dif == impar  # diverge exatamente quando o hex é ímpar
    print(f"4096 configurações; {dif} divergem, todas com hex ímpar; 0 com hex par")


if __name__ == "__main__":
    main()
