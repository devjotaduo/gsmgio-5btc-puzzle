# -*- coding: utf-8 -*-
"""
Frente "matrixsumlist + enter" — as DUAS instrucoes em texto claro que o puzzle
poe entre o dbbi e o faed, e que eu so testei como o escalar 101. Aqui uso a
LISTA REAL de somas da matriz 14x14 da fase 1 como:
  (a) keystream mod 9 sobre os digitos do faed (lista ciclada), e
  (b) transposicao colunar (chave = sum-list, largura = 'enter' = grade),
antes E depois do Bifid. Ataca a assinatura "BTCSEED aparece mas o resto e ruido"
(= transposicao). Cada saida julgada por oraculo DURO (readable/aes/priv/BIP39).
"""
import os, json, time, hashlib
import oracles as O
from scorer import Scorer
from prime_attack import bifid_decrypt, hard_oracles, key_from_symbols, CANON, ALPHA25

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"); os.makedirs(OUT, exist_ok=True)

ROWSUM = [6, 10, 8, 7, 6, 6, 5, 4, 9, 9, 7, 8, 7, 9]      # somas de linha (total 101)
COLSUM = [8, 10, 8, 10, 8, 7, 3, 6, 7, 5, 9, 6, 6, 8]      # somas de coluna

def reading_order(key):
    return sorted(range(len(key)), key=lambda i: (key[i], i))

def col_encrypt(text, key):
    """Transposicao colunar ragged: escreve por linhas (largura=len(key)),
    le colunas na ordem da chave."""
    W = len(key); n = len(text); order = reading_order(key)
    out = []
    for c in order:
        r = 0
        while r * W + c < n:
            out.append(text[r * W + c]); r += 1
    return "".join(out)

def col_decrypt(text, key):
    """Inversa da col_encrypt."""
    W = len(key); n = len(text); order = reading_order(key)
    rows_full, rem = divmod(n, W)
    col_len = {c: rows_full + (1 if c < rem else 0) for c in range(W)}
    # fatia o ciphertext em colunas na ordem de leitura
    cols = {}; idx = 0
    for c in order:
        L = col_len[c]; cols[c] = text[idx:idx + L]; idx += L
    # remonta linha a linha
    out = []
    for r in range((n + W - 1) // W):
        for c in range(W):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)

def keystream_mod9(faed, klist, direction):
    digits = [ord(c) - ord('a') for c in faed]
    ks = [(digits[i] + direction * klist[i % len(klist)]) % 9 for i in range(len(digits))]
    return "".join("abcdefghi"[d] for d in ks)

def evaluate(name, text, scorer, results):
    sc = scorer(text) if text and set(text) <= set(ALPHA25) else -9.9
    results.append((round(sc, 3), name, text[:46]))
    for oracle in (lambda: hard_oracles(text), lambda: key_from_symbols(text)):
        hit = oracle()
        if hit:
            return {"solve": True, "construction": name, "text": text[:80], **hit}
    return None

def main():
    scorer = Scorer()
    faed = O.sources()["faed"]                       # a-i, 570
    BIF = bifid_decrypt(faed.upper(), CANON, 570)     # BTCSEED...
    BIFrest = BIF[7:]
    results = []
    t0 = time.time()
    keys = {"rowsum": ROWSUM, "colsum": COLSUM, "rowsum_mod9": [s % 9 for s in ROWSUM]}
    PERIODS = (570, 285, 190, 114, 95, 57, 38, 30, 19, 15)

    # ---- (a) KEYSTREAM mod 9 da lista, depois Bifid ----
    for kname, kl in (("rowsum", ROWSUM), ("colsum", COLSUM)):
        for d in (1, -1):
            sym = keystream_mod9(faed, kl, d)
            for period in (570, 190, 95, 57, 38, 19):
                pt = bifid_decrypt(sym.upper(), CANON, period)
                hit = evaluate(f"KS9_{kname}{'+' if d>0 else '-'}|bifid|p{period}", pt, scorer, results)
                if hit: return finish(hit, results, t0)
            hit = evaluate(f"KS9_{kname}{'+' if d>0 else '-'}|as-key", sym, scorer, results)
            if hit: return finish(hit, results, t0)

    # ---- (b1) TRANSPOSICAO COLUNAR do faed (antes do Bifid) ----
    for kname, kl in keys.items():
        for mode, fn in (("enc", col_encrypt), ("dec", col_decrypt)):
            tf = fn(faed, kl)
            for period in PERIODS:
                pt = bifid_decrypt(tf.upper(), CANON, period)
                hit = evaluate(f"faedTRANS_{kname}_{mode}|bifid|p{period}", pt, scorer, results)
                if hit: return finish(hit, results, t0)
            hit = evaluate(f"faedTRANS_{kname}_{mode}|as-key", tf, scorer, results)
            if hit: return finish(hit, results, t0)

    # ---- (b2) TRANSPOSICAO COLUNAR aplicada ao BIF/BIFrest (depois do Bifid) ----
    for tgt_name, tgt in (("BIF", BIF), ("BIFrest", BIFrest)):
        for kname, kl in keys.items():
            for mode, fn in (("enc", col_encrypt), ("dec", col_decrypt)):
                out = fn(tgt, kl)
                hit = evaluate(f"{tgt_name}TRANS_{kname}_{mode}", out, scorer, results)
                if hit: return finish(hit, results, t0)

    # ---- (c) faed em grade largura W ('enter'), colunas na ordem da lista, varias larguras ----
    for W in (14, 10, 9, 7, 15, 19, 30, 38):
        # chave = ordem induzida pela sublista (cicla se W>len)
        key = [(ROWSUM * 3)[:W]][0] if W <= len(ROWSUM) else (ROWSUM * ((W // len(ROWSUM)) + 1))[:W]
        for mode, fn in (("enc", col_encrypt), ("dec", col_decrypt)):
            tf = fn(faed, key)
            for period in (570, 190, 57, 38, 19):
                pt = bifid_decrypt(tf.upper(), CANON, period)
                hit = evaluate(f"grid{W}_{mode}|bifid|p{period}", pt, scorer, results)
                if hit: return finish(hit, results, t0)

    finish(None, results, t0)

def finish(hit, results, t0):
    if hit:
        json.dump(hit, open(os.path.join(OUT, "SOLVED.json"), "w"), indent=2)
        print(f"\n!!! SOLVE via {hit['construction']} — out/SOLVED.json\n{json.dumps(hit, indent=2)}")
        return
    results.sort(key=lambda r: -r[0])
    print(f"=== MATRIXSUMLIST ATTACK: {len(results)} construcoes em {time.time()-t0:.0f}s ===")
    print("(baseline CANON puro = -5.577 ; ingles ~ -4.5 ; nenhum oraculo abriu)")
    print("TOP 16 por legibilidade:")
    for sc, name, head in results[:16]:
        print(f"  {sc:7.3f}  {name:36s} {head}")
    json.dump([{"score": s, "name": n, "head": h} for s, n, h in results[:60]],
              open(os.path.join(OUT, "matrixsum_attack.json"), "w"), ensure_ascii=False, indent=2)
    print("\n(gravado out/matrixsum_attack.json)")

if __name__ == "__main__":
    print("=== MATRIXSUMLIST + ENTER ATTACK (instrucao literal do puzzle) ===")
    # sanidade da transposicao: enc->dec == identidade
    for k in (ROWSUM, COLSUM):
        assert col_decrypt(col_encrypt("abcdefghijklmnopqrstuvwxy", k), k) == "abcdefghijklmnopqrstuvwxy"
    print("[ok] transposicao colunar enc/dec valida (identidade)")
    main()
