# -*- coding: utf-8 -*-
"""
Leitura DIRETA do que a pagina SalPhaseIon entrega (sem depender do faed):
- "shabef our first hint is your last command" + blob  => senha = sha256(frase)?
- seg1/seg2 dao "lastwordsbeforearchichoice" e "thispassword" (o proprio password?)
- "shabef ans too" => sha256(answer) abre o COSMIC.
Testa essas frases dadas com a gramatica do puzzle (raw / HASHTHETEXT = upper sem
espaco / sha256hex / concatenacoes) contra SMALL e COSMIC via oraculo AES.
"""
import hashlib, itertools
import oracles as O

def sha256hex(s): return hashlib.sha256(s.encode()).hexdigest()

# frases que a PROPRIA pagina fornece
PHRASES = [
    "our first hint is your last command",
    "lastwordsbeforearchichoice",
    "thispassword",
    "this password",
    "last words before archi choice",
    "last words before the architect's choice",
    "ans too",
    "answer too",
    "enter",
    "matrixsumlist",
    "salphaseion",
    "our first hint is your last command enter",
]

def variants(p):
    """Formas de uma frase segundo a gramatica observada no puzzle."""
    base = {
        p,
        p.lower(),
        p.upper(),
        p.replace(" ", ""),
        p.replace(" ", "").lower(),
        p.replace(" ", "").upper(),         # HASHTHETEXT
    }
    out = set()
    for b in base:
        out.add(b)                          # senha crua
        out.add(sha256hex(b))               # sha256 hex (como nas fases anteriores)
        out.add(sha256hex(b).upper())
    return out

def run():
    cands = set()
    for p in PHRASES:
        cands |= variants(p)
    # concatenacoes de pares (gramatica "concatena N partes")
    key_pairs = ["lastwordsbeforearchichoice", "thispassword",
                 "our first hint is your last command", "enter", "matrixsumlist"]
    for a, b in itertools.permutations(key_pairs, 2):
        for joiner in ("", " "):
            s = a + joiner + b
            cands.add(s); cands.add(s.replace(" ", "")); cands.add(sha256hex(s.replace(" ", "")))
    # triplas chave
    for combo in itertools.permutations(["lastwordsbeforearchichoice", "thispassword", "enter"], 3):
        s = "".join(combo)
        cands.add(s); cands.add(sha256hex(s)); cands.add(sha256hex(s).upper())

    print(f"=== FOCUSED AES: {len(cands)} senhas (frases dadas pela pagina) vs SMALL+COSMIC ===")
    hits = []
    for c in cands:
        h = O.aes_open(c, min_ascii=0.85)
        if h:
            hits.append((c, h))
            print(f"  !! HIT senha='{c[:50]}' -> {h}")
    if not hits:
        print("[negativo] nenhuma frase dada abre os blobs (padding+ascii).")
        # relatorio: melhor ascii mesmo sem passar o corte, p/ diagnostico
        best = None
        for c in list(cands)[:2000]:
            r = O.aes_open(c, min_ascii=0.0)
            if r:
                for hit in r:
                    if best is None or hit["ascii"] > best[1]["ascii"]:
                        best = (c, hit)
        if best:
            print(f"[diag] melhor ascii sem corte: senha='{best[0][:40]}' ascii={best[1]['ascii']:.2f} "
                  f"blob={best[1]['blob']}")
    return hits

if __name__ == "__main__":
    run()
