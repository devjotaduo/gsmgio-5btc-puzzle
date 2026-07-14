# -*- coding: utf-8 -*-
"""
Frente "REINSERTING THE PRIME BASICS" / "some characters need to be zeroed out"
/ "prime positions" — a pista real e NAO resolvida do criador, onde ele e o
llama3 convergem. Fato VERIFICADO: no dbbi, 'd' e a unica letra que so aparece
em posicoes nao-primas (1,48,55,74) -> candidata a ser "zerada".

Sweep de construcoes concretas baseadas em primos; cada saida e julgada pelos
oraculos DUROS (readable + aes_open + priv + BIP39). O oraculo decide, nao o achismo.
"""
import os, json, time, hashlib
import oracles as O
from scorer import Scorer

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"); os.makedirs(OUT, exist_ok=True)
ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"

def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n ** .5) + 1):
        if n % i == 0: return False
    return True

PRIMESET = {n for n in range(1, 4000) if is_prime(n)}

def bifid_decrypt(ct, alpha, period):
    p = {c: (i // 5, i % 5) for i, c in enumerate(alpha)}
    out = []
    for off in range(0, len(ct), period):
        blk = ct[off:off + period]; seq = []
        for c in blk:
            r, co = p[c]; seq += [r, co]
        n = len(blk); rows, cols = seq[:n], seq[n:]
        out.append("".join(alpha[rows[i] * 5 + cols[i]] for i in range(n)))
    return "".join(out)

def kw_square(kw):
    seen = []
    for c in (kw.upper().replace("J", "I") + ALPHA25):
        if c in ALPHA25 and c not in seen:
            seen.append(c)
    return "".join(seen) if len(seen) == 25 else None

# ---- oraculos duros sobre uma saida (letras A-Z ou simbolos a-i) ----
def hard_oracles(pt):
    forms = [pt, pt[7:]] if len(pt) > 7 else [pt]
    for s in forms:
        for f in {s, s.lower(), hashlib.sha256(s.encode()).hexdigest()}:
            h = O.aes_open(f)
            if h: return {"kind": "aes_open", "pw": f[:40], "hits": h}
        for c in (hashlib.sha256(s.encode()).digest(), hashlib.sha256(s.lower().encode()).digest()):
            r = O.check_privkey(c)
            if r: return {"kind": "privkey", "hit": r}
    return None

def key_from_symbols(sym):
    """Se a saida for sobre a-i, testa como material de chave (base-9) + BIP39."""
    if not sym or set(sym) - set("abcdefghi"):
        return None
    from mnemonic import Mnemonic
    M = Mnemonic("english")
    n = 0
    for c in sym: n = n * 9 + (ord(c) - ord('a'))
    for pk in ((n % (1 << 256)).to_bytes(32, "big"), (n % (1 << 256)).to_bytes(32, "little")):
        r = O.check_privkey(pk)
        if r: return {"kind": "privkey-base9", "hit": r}
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    for L in (16, 24, 32):
        for chunk in (b[:L], b[-L:]):
            if len(chunk) == L:
                try:
                    res = O.check_mnemonic(M.to_mnemonic(chunk).split())
                    if res and res.get("match"): return {"kind": "bip39-base9", "hit": res}
                except Exception: pass
    return None

def evaluate(name, text, scorer, results):
    """Registra score; roda oraculos duros; retorna dict de solve se houver."""
    sc = scorer(text) if text and set(text) <= set(ALPHA25) else -9.9
    results.append((round(sc, 3), name, text[:44]))
    for oracle in (lambda: hard_oracles(text), lambda: key_from_symbols(text)):
        hit = oracle()
        if hit:
            return {"solve": True, "construction": name, "text": text[:80], **hit}
    return None

def main():
    scorer = Scorer()
    faed = O.sources()["faed"]              # a-i, 570
    dbbi = O.sources()["dbbi"]              # a-i, 91
    BIF = bifid_decrypt(faed.upper(), CANON, 570)   # A-Z, 570 (BTCSEED...)
    results = []
    t0 = time.time()

    def prime_mask(seq, oneidx=True, keep_prime=True):
        return "".join(c for i, c in enumerate(seq)
                       if (( (i + 1) if oneidx else i) in PRIMESET) == keep_prime)

    # ---- A/B/C: mascaras de primos sobre faed, depois Bifid(CANON) em varios periodos
    faed_variants = {
        "faed_primeonly_1idx": prime_mask(faed, True, True),
        "faed_primeonly_0idx": prime_mask(faed, False, True),
        "faed_nonprime_1idx": prime_mask(faed, True, False),
        "faed_drop_d": "".join(c for c in faed if c != 'd'),         # "zerar" o D
        "faed_d_to_a": "".join('a' if c == 'd' else c for c in faed),
    }
    for vname, fv in faed_variants.items():
        if not fv: continue
        for period in (570, 285, 190, 114, 95, 57, 38, 30, 19, 15, len(fv)):
            if period < 2 or period > len(fv): continue
            pt = bifid_decrypt(fv.upper(), CANON, period)
            hit = evaluate(f"{vname}|bifidCANON|p{period}", pt, scorer, results)
            if hit: return finish(hit, results, t0)
        # tambem testa a propria mascara como material de chave
        hit = evaluate(f"{vname}|as-key", fv, scorer, results)
        if hit: return finish(hit, results, t0)

    # ---- D/E: prime-positions da saida Bifid (BIF) e do BIF_REST
    for bname, seq in (("BIF", BIF), ("BIFrest", BIF[7:])):
        for oneidx in (True, False):
            sub = prime_mask(seq, oneidx, True)
            hit = evaluate(f"{bname}_primepos_{'1' if oneidx else '0'}idx", sub, scorer, results)
            if hit: return finish(hit, results, t0)

    # ---- F/G: squares alternativos vindos do dbbi "zerado"
    dbbi_squares = {
        "dbbi_drop_d": kw_square("".join(c for c in dbbi if c != 'd')),
        "dbbi_firstocc": kw_square(dbbi),
        "dbbi_primepos": kw_square(prime_mask(dbbi, True, True)),
        "dbbi_nonprimepos": kw_square(prime_mask(dbbi, True, False)),
    }
    for sname, sq in dbbi_squares.items():
        if not sq: continue
        for period in (570, 285, 190, 114, 57, 38, 19, 15):
            pt = bifid_decrypt(faed.upper(), sq, period)
            hit = evaluate(f"{sname}|p{period}", pt, scorer, results)
            if hit: return finish(hit, results, t0)

    # ---- H: CANON reordenado movendo letras de indice primo p/ frente
    prime_idx = [i for i in range(25) if i in PRIMESET]
    rest_idx = [i for i in range(25) if i not in PRIMESET]
    reord = "".join(CANON[i] for i in prime_idx + rest_idx)
    for period in (570, 285, 190, 114, 57, 38, 19, 15):
        pt = bifid_decrypt(faed.upper(), reord, period)
        hit = evaluate(f"CANON_primefront|p{period}", pt, scorer, results)
        if hit: return finish(hit, results, t0)

    # ---- I: keystream de primos (mod 9) sobre os digitos do faed, depois Bifid
    primes_seq = [p for p in range(2, 6000) if is_prime(p)]
    digits = [ord(c) - ord('a') for c in faed]
    for direction in (1, -1):
        ks = [(digits[i] + direction * primes_seq[i]) % 9 for i in range(len(digits))]
        sym = "".join("abcdefghi"[d] for d in ks)
        for period in (570, 190, 57, 38, 19):
            pt = bifid_decrypt(sym.upper(), CANON, period)
            hit = evaluate(f"primeKS_{'+' if direction>0 else '-'}|p{period}", pt, scorer, results)
            if hit: return finish(hit, results, t0)

    finish(None, results, t0)

def finish(hit, results, t0):
    if hit:
        json.dump(hit, open(os.path.join(OUT, "SOLVED.json"), "w"), indent=2)
        print(f"\n!!! SOLVE via {hit['construction']} — out/SOLVED.json\n{json.dumps(hit, indent=2)}")
        return
    results.sort(key=lambda r: -r[0])
    print(f"=== PRIME ATTACK: {len(results)} construcoes testadas em {time.time()-t0:.0f}s ===")
    print(f"(baseline CANON puro = -5.577; ingles ~ -4.5; nenhum oraculo abriu)")
    print("TOP 15 por legibilidade:")
    for sc, name, head in results[:15]:
        print(f"  {sc:7.3f}  {name:34s} {head}")
    json.dump([{"score": s, "name": n, "head": h} for s, n, h in results[:60]],
              open(os.path.join(OUT, "prime_attack.json"), "w"), ensure_ascii=False, indent=2)
    print("\n(gravado out/prime_attack.json)")

if __name__ == "__main__":
    print("=== PRIME BASICS ATTACK (pista real do criador) ===")
    main()
