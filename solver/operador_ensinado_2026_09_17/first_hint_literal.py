# -*- coding: utf-8 -*-
"""
Hipotese (prosa, finita, falsificavel):
"our first hint is your last command" fica IMEDIATAMENTE antes do blob SMALL.
"our first hint" = o primeiro hint que o criador deu publicamente (22/04/2019): ele publicou
   sha256("theflowerblossoms...") = 5ac40783...746f75 e disse "just try hit your options against that hash".
"your last command" = o ultimo comando que o solver rodou = `openssl enc -aes-256-cbc -d -a -pass pass:<X>`.
Logo a frase diria: o primeiro hint (aquele hash) E o argumento -pass do seu ultimo comando.
Falsificavel: o conjunto de materiais e finito (o hash, a senha que o gera, suas formas e composicoes).
"""
import sys, hashlib, itertools
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G

P1 = "theflowerblossomsthroughwhatseemstobeaconcretesurface"
H1 = hashlib.sha256(P1.encode()).hexdigest()
assert H1 == "5ac407837447fba24ba2802e4d1e9aecb4580aa29fef1088cc387c180b746f75", H1
PATH = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
TITLE = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
PH2 = hashlib.sha256(b"causality").hexdigest()
PH3 = "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
PH32 = "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"

base = []
# o hash publicado, em todas as formas de um argumento -pass
for h in (H1, H1.upper()):
    base += [h, h+"\n", " "+h, h+" "]
base += [P1, P1.upper(), P1.capitalize()]
# o hash como bytes crus (o "hash" e nao o "hex do hash")
raw = bytes.fromhex(H1)
base += [raw, raw.hex().encode(), hashlib.sha256(raw).hexdigest(), hashlib.sha256(H1.encode()).hexdigest()]
# linhas de comando literais (o "last command" inteiro como senha)
for tgt in (H1, PH32, PH3, PH2):
    base += [f"openssl enc -aes-256-cbc -d -a -pass pass:{tgt}",
             f"openssl enc -aes-256-cbc -d -a -in phase3.2.txt -pass pass:{tgt}",
             f"-pass pass:{tgt}", f"pass:{tgt}"]
# composicoes com os rotulos vizinhos na pagina
for tail in ("", "anstoo", "ans too", "answer too", "enter", "shabef", "sha256"):
    base += [H1+tail, tail+H1, (H1+tail).upper()]
# "our first hint" = a primeira frase-hint da pagina? e o hash dela
for s in ("our first hint is your last command", "ourfirsthintisyourlastcommand",
          "OUR FIRST HINT IS YOUR LAST COMMAND", "shabefourfirsthintisyourlastcommand",
          "shabef our first hint is your last command"):
    base += [s, hashlib.sha256(s.encode()).hexdigest()]
# cadeia: sha256 iterado do primeiro hint (1..8 voltas)
x = H1
for _ in range(8):
    x = hashlib.sha256(x.encode()).hexdigest(); base.append(x)
x = raw
for _ in range(8):
    x = hashlib.sha256(x).digest(); base += [x, x.hex()]

forms = []
seen = set()
for b in base:
    bb = b if isinstance(b, bytes) else b.encode("utf-8", "surrogateescape")
    for cand in (bb, hashlib.sha256(bb).hexdigest().encode(), hashlib.sha256(bb).hexdigest().upper().encode()):
        if cand not in seen:
            seen.add(cand); forms.append(cand)

hard, pads = [], []
for f in forms:
    h, s = G.try_password_all(f)
    if h: hard.append((f[:60], h))
    pads += s
print(f"materiais-base={len(base)} senhas unicas={len(forms)} AES={len(forms)*6}")
print(f"HITS DUROS: {len(hard)}")
for x in hard: print("  ", x)
print(f"paddings validos (ruido esperado ~{len(forms)*6/256:.1f}): {len(pads)}")
for p in sorted(pads, key=lambda r: -r['printable'])[:5]:
    print(f"   {p['blob']}/{p['kdf']} printable={p['printable']} head={p['head'][:40]!r}")
# nulo casado: 200 replicas de hex64 aleatorios do mesmo formato
import os
rnd = [os.urandom(32).hex().encode() for _ in range(200)]
np = sum(len(G.try_password_all(r)[1]) for r in rnd)
print(f"nulo: {len(rnd)} senhas hex64 aleatorias -> {np} paddings (esperado {len(rnd)*6/256:.1f})")
