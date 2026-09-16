# -*- coding: utf-8 -*-
"""
Hipótese: dbbi/faed são dígitos decimais 1–9 de um número do qual os ZEROS foram removidos
("some characters need to be zeroed out"); os zeros ocupam as "prime positions" (base 0 ou 1,
"First or zero"). Reinserindo '0' nas posições primas e aplicando o z-method da própria página
(decimal → inteiro → hex → bytes) sai texto/senha/privkey. Variantes: zeros nas posições primas
ou nas NÃO-primas; base 0/1; direto/reverso; dbbi, faed, metades, dbbi+faed; a=1..9.
Oráculos: printable ≥ 0,85 do z-method, G.fast_priv_scan nos bytes, sha256(string)→senha nos
3 blobs (KDF SHA256) + privkey, string crua como senha.
"""
import sys, json, os
SCR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCR)
import gsmg_common as G
sys.set_int_max_str_digits(0)

LOG = os.path.join(SCR, "insert_zeros_primes.jsonl")
open(LOG, "w").close()
N = 0; HARD = []; BEST = []

def primes_upto(n):
    s = bytearray([1]) * (n + 1); s[0] = s[1] = 0
    for i in range(2, int(n ** 0.5) + 1):
        if s[i]: s[i * i::i] = bytearray(len(s[i * i::i]))
    return [i for i in range(n + 1) if s[i]]

def insert_zeros(digs, base, at_primes=True):
    """Constrói a string final onde as posições primas (índice base 0/1) valem '0' e as demais
    recebem os dígitos em ordem. Comprimento final N mínimo tal que #não-primas(N) == len(digs)."""
    out = []; it = iter(digs); k = base
    LIM = 20 * len(digs) + 1000
    P = set(primes_upto(LIM))
    while k < LIM:
        isp = k in P
        if isp == at_primes:
            out.append("0")
        else:
            try: out.append(str(next(it)))
            except StopIteration: break
        k += 1
    return "".join(out).rstrip("0") if False else "".join(out)

def test_string(s, how):
    global N
    if not s or s[0] == "0" and how.endswith("lead0"): return
    n = int(s); h = format(n, "x")
    if len(h) % 2: h = "0" + h
    b = bytes.fromhex(h)
    N += 1
    pr = G.printable(b)
    if pr >= 0.85 and len(b) >= 8:
        BEST.append((pr, how, b[:80].decode("latin-1")))
    hit = G.fast_priv_scan(b)
    if hit: HARD.append({"how": how, "priv": hit}); G.jsonl(LOG, {"HARD": {"how": how, "priv": str(hit)}})
    # string decimal / hex / bytes como senha, e sha256 → senha/privkey
    for pw, tag in ((s, "dec"), (h, "hex"), (b, "bytes"), (G.shahex(s), "sha_dec")):
        for blob in ("SMALL", "COSMIC", "TAIL32"):
            N += 1
            for k, p in G.aes_try(pw, blob, kdf="sha256"):
                if G.semantic(p):
                    rec = {"how": how, "form": tag, "blob": blob, "pt": p.hex()}
                    HARD.append(rec); G.jsonl(LOG, {"HARD": rec})
    for pk in (G.sha(s), G.sha(h), G.sha(b), G.sha(G.shahex(s))):
        N += 1
        r = G.priv_hit(pk)
        if r: HARD.append({"how": how, "priv": pk.hex(), **r}); G.jsonl(LOG, {"HARD": {"how": how, "priv": pk.hex()}})

SRC = {"dbbi": G.DBBI, "faed": G.FAED, "faedA": G.FAED[:285], "faedB": G.FAED[285:],
       "dbbi+faed": G.DBBI + G.FAED, "faed+dbbi": G.FAED + G.DBBI}
for name, s in list(SRC.items()):
    SRC[name + "_rev"] = s[::-1]

for name, s in SRC.items():
    digs = G.digits(s, base1=True)
    for base in (0, 1):
        for at_primes in (True, False):
            for lead in ("keep", "strip"):
                z = insert_zeros(digs, base, at_primes)
                if lead == "strip": z = z.lstrip("0")
                if not z: continue
                how = f"{name}/base{base}/{'zeros@primes' if at_primes else 'zeros@nonprimes'}/{lead}"
                test_string(z, how)
                # também o inverso: ler a string como base 9? não (tem 0..9 = 10 símbolos) — só decimal
    # controle de sanidade: sem inserção (já fechado antes) — só para comparar printable
    test_string("".join(map(str, digs)), f"{name}/no_insert")

BEST.sort(reverse=True)
G.jsonl(LOG, {"summary": {"n_tests": N, "hard": len(HARD), "best": BEST[:10]}})
print(json.dumps({"n_tests": N, "hard": HARD[:3], "best_printable": BEST[:10]}, ensure_ascii=False, indent=1, default=str))
