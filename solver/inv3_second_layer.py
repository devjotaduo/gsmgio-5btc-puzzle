# -*- coding: utf-8 -*-
"""INV3 - 2a CAMADA DE CIFRA em cc (gramatica de senha derivada).

Hipotese falsificavel: cc (plaintext Cosmic, 1327 B, entropia 7.87 b/byte) e ele
proprio um ciphertext de 2a camada AES. A chave segue a MESMA familia ja provada
no puzzle:
  - SMALL  = sha256(concat de tokens)
  - COSMIC = XOR(sha256 individual de cada token)
usando os tokens que a pagina SalPhaseIon mostra mas a 1a camada NAO consumiu, ou
a instrucao "shabef ans too" (= sha256 da resposta tambem).

Receita da 1a camada (pinada): COSMIC_PW = XOR(sha256) de
  [enter, lastwordsbeforearchichoice, thispassword, yourlastcommand, secondanswer]
Tokens LIVRES (nao consumidos): matrixsumlist, shabef,
  ourfirsthintisyourlastcommand, ans, too.

Deciframos cc[:1312] (82 blocos; cc NAO tem "Salted__" -> AES raw) em:
  - CBC com IVs naturais {zero, cc0, half, bh}
  - ECB bloco-a-bloco
Deteccao por decifracao:
  (1) "Salted__" aninhado no plaintext;
  (2) padding PKCS7 valido + imprimibilidade >= 0.90 (plaintext estruturado);
  (3) privkey-alvo/espelho via strong_oracle_35.scan (byte-a-byte, WIF, BIP39,
      hex-ascii) + a propria chave como privkey.
"""
import hashlib, itertools, json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
import strong_oracle_35 as SO
from Crypto.Cipher import AES

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "_work", "inv3_second_layer.jsonl")


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).digest()


def xorr(parts):
    x = bytes(32)
    for p in parts:
        x = bytes(a ^ b for a, b in zip(x, p))
    return x


def printable(d):
    if not d:
        return 0.0
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in d) / len(d)


def pkcs7_body(pt):
    """Retorna corpo se padding PKCS7 valido, senao None."""
    if not pt or len(pt) % 16:
        return None
    p = pt[-1]
    if 1 <= p <= 16 and pt.endswith(bytes([p]) * p):
        return pt[:-p]
    return None


def build_keys(R):
    """Constroi o conjunto derivado de chaves de 2a camada. Retorna dict rotulado."""
    half, bh, tail = R["half"], R["better_half"], R["matrix_tail"]
    chain1, chain2 = R["chain1"], R["chain2"]
    components = half + bh + tail
    keys = {}  # label -> 32B key

    # --- Familia SMALL: sha256(concat) de tokens livres, ordem da pagina ---
    free = ["matrixsumlist", "shabef", "ourfirsthintisyourlastcommand", "ans", "too"]
    concat_variants = [
        "matrixsumlist", "shabef", "ans", "too", "anstoo", "shabefanstoo",
        "ourfirsthintisyourlastcommand",
        "matrixsumlistshabef", "shabefanstoo",
        "matrixsumlistshabefanstoo",
        "shabefourfirsthintisyourlastcommand",
        "".join(free), "matrixsumlistshabefourfirsthintisyourlastcommandanstoo",
        # instrucao literal "our first hint is your last command"
        "ourfirsthintisyourlastcommandanstoo",
    ]
    for s in dict.fromkeys(concat_variants):  # dedupe preservando ordem
        keys[f"concat:{s}"] = sha(s)

    # --- Familia COSMIC: XOR(sha256 individual) sobre subsets do pool da pagina ---
    # pool = 8 atomos unicos que a pagina apresenta (consumidos + livres); a mesma
    # gramatica, subset diferente. 2^8-1 = 255 subsets.
    page_atoms = ["matrixsumlist", "enter", "lastwordsbeforearchichoice",
                  "thispassword", "shabef", "ourfirsthintisyourlastcommand",
                  "ans", "too"]
    atom_sha = {a: sha(a) for a in page_atoms}
    for r in range(1, len(page_atoms) + 1):
        for combo in itertools.combinations(page_atoms, r):
            keys[f"xor:{'+'.join(combo)}"] = xorr([atom_sha[a] for a in combo])

    # --- Familia "shabef ans too" = sha256 da RESPOSTA (e double-sha) ---
    answers = {
        "chain1": chain1, "chain1_32": chain1[:32],
        "chain2": chain2, "chain2_32": chain2[:32],
        "components": components, "half_bh": half + bh,
        "cosmic_pw": F.COSMIC_PASSWORD, "cc_full": R["cosmic"],
        "half": half, "bh": bh,
    }
    for name, a in answers.items():
        keys[f"sha(ans:{name})"] = sha(a)
        keys[f"sha2(ans:{name})"] = sha(sha(a))

    # --- Familia half/bh como chave direta (ja coberto no groundtruth; incluido
    #     para completude / overlap explicito) ---
    keys["half_raw"] = half
    keys["bh_raw"] = bh

    return keys


def try_key(key, label, cc1312, ivs, R, log):
    """Aplica a chave em CBC(ivs)+ECB sobre cc1312. Retorna lista de hits."""
    hits = []
    if len(key) != 32:
        return hits
    # a propria chave pode SER a privkey
    pv = []
    SO._privhit(key, f"{label}:keyself", pv)
    for h in pv:
        hits.append({"kind": "PRIVKEY", "key": label, "detail": h})

    # CBC com IVs naturais
    for ivn, iv in ivs:
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(cc1312)
        _inspect(pt, f"{label}:cbc:{ivn}", hits)
    # ECB bloco-a-bloco
    ecb = b"".join(AES.new(key, AES.MODE_ECB).decrypt(cc1312[i * 16:(i + 1) * 16])
                   for i in range(len(cc1312) // 16))
    _inspect(ecb, f"{label}:ecb", hits)
    return hits


def _inspect(pt, where, hits):
    # (1) Salted__ aninhado
    if b"Salted__" in pt:
        hits.append({"kind": "SALTED", "where": where,
                     "at": pt.index(b"Salted__"), "head": pt[:48].hex()})
    # (2) padding PKCS7 + alta imprimibilidade
    body = pkcs7_body(pt)
    if body is not None:
        pr = printable(body)
        if pr >= 0.90:
            hits.append({"kind": "STRUCTURED", "where": where,
                         "ascii": round(pr, 3),
                         "plain": body[:80].decode("latin-1")})
    # (3) privkey por scan forte (byte-a-byte, WIF, BIP39, hex-ascii)
    out = []
    SO.scan(pt, where, out)
    for o in out:
        # SOFT-PKCS7 de scan nao existe aqui; scan so emite tipos de privkey/addr
        hits.append({"kind": o[0], "where": o[1], "detail": o[2], "extra": o[3]})


def main():
    t0 = time.time()
    R = F.reproduce()
    cc = R["cosmic"]
    assert len(cc) == 1327
    cc1312 = cc[:1312]
    half, bh = R["half"], R["better_half"]
    ivs = [("zero", b"\x00" * 16), ("cc0", cc[:16]),
           ("half", half[:16]), ("bh", bh[:16])]

    keys = build_keys(R)
    # dedupe por valor de chave (labels multiplos p/ mesma chave contam 1x no scan)
    seen = {}
    for label, k in keys.items():
        seen.setdefault(k, label)
    uniq = {v: k for k, v in seen.items()}  # label -> key (unico)

    print(f"[inv3] chaves construidas={len(keys)} unicas={len(uniq)} "
          f"IVs_CBC={len(ivs)} modos/chave={len(ivs)+1}")
    print(f"[inv3] decifracoes totais = {len(uniq) * (len(ivs)+1)}")

    all_hits = []
    with open(LOG, "w", encoding="utf-8") as fh:
        for i, (label, key) in enumerate(uniq.items()):
            hits = try_key(key, label, cc1312, ivs, R, fh)
            for h in hits:
                rec = {"key_label": label, "key_hex": key.hex(), **h}
                all_hits.append(rec)
                fh.write(json.dumps(rec) + "\n")
                print("  HIT", rec)
            if (i + 1) % 50 == 0:
                print(f"  ... {i+1}/{len(uniq)} chaves ({time.time()-t0:.0f}s)")

    dt = time.time() - t0
    print(f"[inv3] FIM: {len(uniq)} chaves, "
          f"{len(uniq)*(len(ivs)+1)} decifracoes, {len(all_hits)} hits, {dt:.0f}s")
    # resumo por tipo
    from collections import Counter
    c = Counter(h["kind"] for h in all_hits)
    print("[inv3] hits por tipo:", dict(c))
    return all_hits


if __name__ == "__main__":
    main()
