# -*- coding: utf-8 -*-
"""
FAMILIA zeroed_primes — hints "some characters need to be zeroed out", "prime positions",
"First or zero", "a prime number is very important", decodificados pelo metodo ENSINADO
pela pagina (a-i -> 1..9, o -> 0, decimal -> hex -> ASCII = z-method).

Hipotese: dbbi/faed nao tem 'o', logo nao decodificam direto; alguns simbolos devem virar 0
(posicoes primas / coloridas / 163,193 / uma letra) antes do z-method, dando senha ASCII ou
privkey. Leitura inversa: inserir zeros nas posicoes primas; blocos de comprimento primo.
"""
import sys, hashlib, itertools, json, time
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G

LOG = SP + r"\zeroed_primes.jsonl"
open(LOG, "w").close()
HYP = ("A pagina ensina a-i=1..9,o=0 -> decimal -> hex -> ASCII. dbbi/faed nao tem 'o'; os hints "
       "'zeroed out'/'prime positions'/'First or zero' dizem que posicoes primas (0/1-based), coloridas, "
       "163/193 ou uma letra especifica valem 0 antes do z-method, produzindo senha ASCII/privkey. "
       "Inversa: inserir zeros em posicoes primas; blocos de comprimento primo em base 9/10.")
G.jsonl(LOG, {"hypothesis": HYP})

ZSEG1 = "agdafaoaheiecggchgicbbhcgbehcfcoabicfdhhcdbbcagbdaiobbgbeadedde"
ZSEG2 = "cfobfdhgdobdgooiigdocdaoofidh"
PRIMES = [p for p in range(2, 700) if G.is_prime(p)]
PSET = set(PRIMES)

SOURCES = {
    "dbbi": G.DBBI, "faed": G.FAED, "faed_noprefix": G.FAED[4:],
    "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:], "faed_h2_noaied": G.FAED[289:],
    "zseg1": ZSEG1, "zseg2": ZSEG2, "dbbi+faed": G.DBBI + G.FAED,
}

def digs(s, mapping):
    """mapping 'A': a=1..i=9,o=0 ; 'B': a=0..i=8,o=0"""
    out = []
    for c in s:
        if c == "o": out.append(0)
        elif mapping == "A": out.append(ord(c) - 96)
        else: out.append(ord(c) - 97)
    return out

# ----------------------------------------------------------------- mascaras
def masks(s, mapping):
    """Gera (nome, lista_de_digitos). Zerar = substituir por 0; del = remover."""
    n = len(s); d = digs(s, mapping)
    def zero_at(pos): return [0 if i in pos else x for i, x in enumerate(d)]
    def keep(pos): return [x for i, x in enumerate(d) if i in pos]
    def drop(pos): return [x for i, x in enumerate(d) if i not in pos]
    yield "none", d
    for base in (0, 1):
        P = {i for i in range(n) if (i + base) in PSET}
        NP = set(range(n)) - P
        yield f"zero_prime_b{base}", zero_at(P)
        yield f"zero_nonprime_b{base}", zero_at(NP)
        yield f"keep_prime_b{base}", keep(P)
        yield f"keep_nonprime_b{base}", drop(P)
    # 24 indices coloridos (espiral), mod n, 0- e 1-based
    for base in (0, 1):
        for cname, idxs in (("all", list(G.COLORED)), ("blue", G.BLUE_IDX), ("yellow", G.YELLOW_IDX)):
            pos = {(i - base) % n for i in idxs}
            yield f"zero_col_{cname}_b{base}", zero_at(pos)
            yield f"del_col_{cname}_b{base}", drop(pos)
        # indice local 0..23 das coloridas ((i-7)/8), so zerar
        pos = {((i - 7) // 8 - base) % n for i in G.COLORED}
        yield f"zero_col_local_b{base}", zero_at(pos)
    # 163 / 193 e vizinhos
    for base in (0, 1):
        for name, idxs in (("163", [163]), ("193", [193]), ("163+193", [163, 193]),
                           ("163n", [162, 163, 164]), ("193n", [192, 193, 194]),
                           ("163n+193n", [162, 163, 164, 192, 193, 194])):
            pos = {(i - base) % n for i in idxs}
            yield f"zero_{name}_b{base}", zero_at(pos)
            yield f"del_{name}_b{base}", drop(pos)
    # letras: zerar cada uma, pares, e deletar cada uma
    L = "abcdefghi"
    for c in L:
        pos = {i for i, x in enumerate(s) if x == c}
        yield f"zero_letter_{c}", zero_at(pos)
        yield f"del_letter_{c}", drop(pos)
    for c1, c2 in itertools.combinations(L, 2):
        pos = {i for i, x in enumerate(s) if x in (c1, c2)}
        yield f"zero_letters_{c1}{c2}", zero_at(pos)
    # letra em posicao prima (1-based) zerada
    for c in L:
        pos = {i for i, x in enumerate(s) if x == c and (i + 1) in PSET}
        if pos: yield f"zero_letter_{c}_at_prime", zero_at(pos)
    # paridade de linha/coluna ao arranjar em largura w
    for w in (14, 38, 15, 13, 7):
        if w >= n: continue
        for par in (0, 1):
            yield f"zero_rows_par{par}_w{w}", zero_at({i for i in range(n) if (i // w) % 2 == par})
            yield f"zero_cols_par{par}_w{w}", zero_at({i for i in range(n) if (i % w) % 2 == par})
    # matriz 14x14 em ordem espiral como mascara (bit 0 / bit 1), ciclica
    bits = [G.MATRIX_IMG[r][c] for r, c in G.SPIRAL]
    for b in (0, 1):
        yield f"zero_where_matrixbit{b}", zero_at({i for i in range(n) if bits[i % 196] == b})
    # ---- inversa: INSERIR zeros nas posicoes primas (0/1-based)
    for base in (0, 1):
        out = []; i = 0
        for x in d:
            while (len(out) + base) in PSET: out.append(0)
            out.append(x)
        yield f"insert0_prime_b{base}", out

# ----------------------------------------------------------------- leituras
def readings(dl, mapping):
    """digitos -> bytes. 'dec': z-method (base10 -> hex -> bytes); 'b9': base 9 -> bytes."""
    if not dl: return
    yield "dec", G.z_method(dl)
    if mapping == "B":
        n = 0
        for x in dl: n = n * 9 + x
        yield "b9", n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")

def block_readings(dl, mapping):
    for Lb in (2, 3, 5, 7, 11, 13):
        blocks = [dl[i:i + Lb] for i in range(0, len(dl) - Lb + 1, Lb)]
        for base in ((10,) if mapping == "A" else (9, 10)):
            vals = [int("".join(map(str, b)), base) if base == 10 else sum(x * 9 ** (len(b) - 1 - j) for j, x in enumerate(b)) for b in blocks]
            yield f"blk{Lb}_b{base}_mod256", bytes(v % 256 for v in vals)
            yield f"blk{Lb}_b{base}_lt256", bytes(v for v in vals if v < 256)
            yield f"blk{Lb}_b{base}_a1z26", bytes(97 + (v - 1) % 26 for v in vals)

# ----------------------------------------------------------------- oraculos
N = {"outputs": 0, "priv_checks": 0, "aes_pw": 0}
hard, soft, scored = [], [], []

def judge(name, out):
    N["outputs"] += 1
    pr = G.printable(out)
    txt = out.decode("latin-1")
    sc = G.english_score(txt) if pr >= 0.5 and len(out) >= 8 else -99
    rec = {"name": name, "len": len(out), "printable": round(pr, 3), "score": round(sc, 3),
           "head": txt[:40]}
    # oraculo duro 1: privkey em qualquer offset / hex64 / WIF
    if len(out) >= 32:
        N["priv_checks"] += max(0, len(out) - 31)
        h = G.scan_priv(out, name)
        if h:
            rec["PRIV_HIT"] = str(h); hard.append({"kind": "privkey", **rec, "hex": out.hex()})
    # oraculo duro 2: saida como senha, sha256hex(saida), digitos como senha
    for pwname, pw in (("raw", out), ("sha256hex", G.shahex(out).encode()), ("hex", out.hex().encode())):
        N["aes_pw"] += 1
        hd, sf = G.try_password_all(pw)
        for x in hd: hard.append({"kind": "aes", "pw": pwname, "pwbytes": pw.hex(), **x, **rec})
        for x in sf: soft.append({"pw": pwname, **x, "name": name})
    if sc > -99: scored.append((sc, name, txt[:60]))
    G.jsonl(LOG, rec)

# ----------------------------------------------------------------- controle positivo
assert G.z_method(digs(ZSEG1, "A")) == b"lastwordsbeforearchichoice"
assert G.z_method(digs(ZSEG2, "A")) == b"thispassword"
# controle do "zerar": trocar os 'o' de zseg2 por 'i' e zerar exatamente essas posicoes recupera
pos_o = {i for i, c in enumerate(ZSEG2) if c == "o"}
fake = ZSEG2.replace("o", "i")
d = [0 if i in pos_o else x for i, x in enumerate(digs(fake, "A"))]
assert G.z_method(d) == b"thispassword"
G.jsonl(LOG, {"control": "z-method reproduz lastwords/thispassword; zerar posicoes dos 'o' recupera", "ok": True})
print("controle OK; posicoes 'o' zseg1:", [i for i, c in enumerate(ZSEG1) if c == "o"],
      "zseg2:", sorted(pos_o))

t0 = time.time()
for sname, s in SOURCES.items():
    for mapping in ("A", "B"):
        for mname, dl in masks(s, mapping):
            for rname, out in readings(dl, mapping):
                judge(f"{sname}|{mapping}|{mname}|{rname}", out)
                # digitos crus como senha (so para a leitura dec, evita duplicar)
                if rname == "dec":
                    N["aes_pw"] += 1
                    pw = "".join(map(str, dl)).encode()
                    hd, sf = G.try_password_all(pw)
                    for x in hd: hard.append({"kind": "aes", "pw": "digits", "pwbytes": pw.hex(), "name": f"{sname}|{mapping}|{mname}", **x})
                    for x in sf: soft.append({"pw": "digits", **x, "name": f"{sname}|{mapping}|{mname}"})
        # blocos de comprimento primo sobre a fonte sem mascara e zerada em primos (b0/b1)
        for mname, dl in masks(s, mapping):
            if mname not in ("none", "zero_prime_b0", "zero_prime_b1", "zero_nonprime_b0", "zero_nonprime_b1"): continue
            for rname, out in block_readings(dl, mapping):
                judge(f"{sname}|{mapping}|{mname}|{rname}", out)

scored.sort(reverse=True)
n_tests = N["priv_checks"] + N["aes_pw"] * 6  # cada senha = 3 blobs x 2 kdf
summary = {"summary": True, "outputs": N["outputs"], "priv_checks": N["priv_checks"],
           "aes_passwords": N["aes_pw"], "n_tests": n_tests, "hard": len(hard), "soft": len(soft),
           "top": scored[:10], "secs": round(time.time() - t0)}
G.jsonl(LOG, summary)
for h in hard: G.jsonl(LOG, {"HARD": h})
for sft in soft: G.jsonl(LOG, {"soft": sft})
print(json.dumps(summary, ensure_ascii=False, indent=1))
print("HARD:", hard)
print("SOFT:", soft)
