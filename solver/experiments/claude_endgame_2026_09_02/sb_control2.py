# Controles positivos extras: motores bits-1bit e multibit recuperam alvo plantado.
import sys, random
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import select_bits as S, gsmg_common as G

priv = G.sha(b"ctl2"); bits = format(int.from_bytes(priv, "big"), "0256b")
rnd = random.Random(3)

# 1) 1 bit/simbolo (predicado 'odd') na selecao mod2_0 de um faed sintetico
s = [rnd.choice("abcdefghi") for _ in range(570)]
pos = list(range(0, 570, 2))                      # mod2_0
for k, b in enumerate(bits):
    d = rnd.choice([1,3,5,7,9]) if b == "1" else rnd.choice([2,4,6,8])
    s[pos[k]] = chr(96 + d)
sub = "".join(s[i] for i in pos)
d1 = G.digits(sub, True)
rec = "".join(str(d % 2) for d in d1)[:256]
ok1 = int(rec, 2).to_bytes(32, "big") == priv

# 2) multibit pack3 nas 104 posicoes primas (86 simbolos x 3 bits = 258 >= 256)
s = [rnd.choice("abcdefghi") for _ in range(570)]
P = S.primes_below(570)
for k in range(86):
    v = int(bits[3*k:3*k+3].ljust(3, "0"), 2) if 3*k < 256 else 0
    s[P[k]] = chr(97 + v)                          # d0 = v (0..7)
sub = "".join(s[i] for i in P)
d0 = G.digits(sub, False)
ok2 = S.packbits(d0, 3)[:256] == bits
print("controle bits-1bit (mod2_0/odd):", ok1)
print("controle multibit (pack3/primos):", ok2)
assert ok1 and ok2
