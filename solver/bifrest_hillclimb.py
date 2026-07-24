# -*- coding: utf-8 -*-
"""
Frente PENDENTE do ENDGAME.md: hill-climb monoalfabetico sobre BIF_REST.
Objetivo honesto: fechar a lacuna. Reporta score real; se sinal, testa AES.

- BIF_REST = saida Bifid(faed, CANON, periodo 570) apos 'BTCSEED' (563 chars).
- Caracteriza: alfabeto usado, IoC, viés.
- Hill-climb: mapeamento monoalfabetico -> maximiza quadgramas EN (Scorer).
  Controle: cifra um texto EN conhecido por subst. aleatoria e recupera (mede teto).
- Qualquer plaintext com score alto -> testa como senha AES (SMALL/COSMIC).
"""
import random, math, hashlib, time
from collections import Counter
import dsl
from scorer import Scorer
import oracles as O

_t0 = time.perf_counter()
sc = Scorer()
print(f"[timer] Scorer pronto em {time.perf_counter()-_t0:.1f}s (carrega quadgram.pkl)")

def ioc(s):
    n = len(s)
    if n < 2: return 0.0
    c = Counter(s)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

def hill_climb(cipher, alphabet, iters=6000, restarts=6, seed=0, patience=400):
    """Subst. monoalfabetica: key = permutacao de `alphabet`.
    Early-stop: para o restart apos `patience` swaps sem melhora."""
    rng = random.Random(seed)
    A = list(alphabet)
    idx = {alphabet[i]: i for i in range(len(alphabet))}
    cipher_idx = [idx[ch] for ch in cipher]  # pre-mapeia p/ velocidade
    best_key, best_score, best_pt = None, -1e9, ""
    def decode(k):
        return "".join(k[ci] for ci in cipher_idx)
    for r in range(restarts):
        key = A[:]; rng.shuffle(key)
        cur = key[:]; cur_s = sc(decode(cur)); since = 0
        for it in range(iters):
            a, b = rng.randrange(len(A)), rng.randrange(len(A))
            if a == b: continue
            cur[a], cur[b] = cur[b], cur[a]
            s = sc(decode(cur))
            if s > cur_s:
                cur_s = s; since = 0
            else:
                cur[a], cur[b] = cur[b], cur[a]  # reverte
                since += 1
                if since >= patience:
                    break
        pt = decode(cur)
        if cur_s > best_score:
            best_key, best_score, best_pt = cur[:], cur_s, pt
    return best_score, best_pt, best_key

def control(alphabet, length, seed=1):
    """Cifra um EN conhecido por subst. aleatoria e mede recuperacao (teto)."""
    en = ("THEUNANIMOUSDECLARATIONOFTHETHIRTEENUNITEDSTATESOFAMERICAWHENINTHE"
          "COURSEOFHUMANEVENTSITBECOMESNECESSARYFORONEPEOPLETODISSOLVETHE"
          "POLITICALBANDSWHICHHAVECONNECTEDTHEMWITHANOTHERANDTOASSUMEAMONG"
          "THEPOWERSOFTHEEARTHTHESEPARATEANDEQUALSTATIONTOWHICHTHELAWSOF"
          "NATUREANDOFNATURESGODENTITLETHEMADECENTRESPECTTOTHEOPINIONSOF"
          "MANKINDREQUIRESTHATTHEYSHOULDDECLARETHECAUSES")
    en = "".join(c for c in en if c in alphabet)[:length]
    rng = random.Random(seed)
    perm = list(alphabet); rng.shuffle(perm)
    tbl = {alphabet[i]: perm[i] for i in range(len(alphabet))}
    ct = "".join(tbl[c] for c in en)
    s, pt, _ = hill_climb(ct, alphabet, iters=30000, restarts=6, seed=7)
    match = sum(a == b for a, b in zip(pt, en)) / len(en)
    return s, match

def main():
    bif = dsl.bif_full()
    print(f"[bif] total {len(bif)} chars; head: {bif[:20]}")
    rest = bif[7:]  # apos BTCSEED
    alpha = "".join(sorted(set(rest)))
    print(f"[bif_rest] len={len(rest)} distinct={len(alpha)} alpha={alpha}")
    print(f"[bif_rest] IoC={ioc(rest):.4f}  (EN~0.067, rand-{len(alpha)}~{1/len(alpha):.4f})")
    freq = Counter(rest).most_common(8)
    print(f"[bif_rest] top freq: {freq}")

    # CONTROLE: mede teto de recuperacao com o mesmo alfabeto/comprimento
    cs, cm = control(alpha, len(rest))
    print(f"\n[CONTROLE] EN-conhecido cifrado->recuperado: score={cs:.3f} match={cm:.1%}")
    print("  (se match alto, o motor funciona; entao negativo no real tem peso)")

    # ATAQUE REAL
    print(f"\n[ATAQUE] hill-climb sobre BIF_REST real...")
    s, pt, key = hill_climb(rest, alpha, iters=40000, restarts=10, seed=0)
    print(f"[real] best score={s:.3f}")
    print(f"[real] plaintext[:120]={pt[:120]}")

    # Teste AES de candidatos (varias formas)
    print(f"\n[AES] testando plaintext como senha...")
    forms = {pt, pt.lower(), pt.upper(),
             hashlib.sha256(pt.encode()).hexdigest(),
             hashlib.sha256(pt.lower().encode()).hexdigest()}
    total_hits = []
    for f in forms:
        total_hits += O.aes_open(f)
    print(f"[AES] hits: {total_hits if total_hits else 'NENHUM'}")

    # veredito honesto
    print("\n=== VEREDITO ===")
    if s > cs - 0.5:
        print(f"BIF_REST recupera como o controle EN (score {s:.2f} ~ teto {cs:.2f}) -> POSSIVEL INGLES")
    else:
        print(f"BIF_REST NAO recupera (score {s:.2f} << teto EN {cs:.2f}) -> NAO e subst. monoalfabetica de ingles")
    print(f"AES: {'ABRIU!' if total_hits else 'nenhum blob aberto (negativo)'}")

if __name__ == "__main__":
    main()
