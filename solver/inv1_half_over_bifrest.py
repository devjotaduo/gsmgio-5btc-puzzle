# -*- coding: utf-8 -*-
"""
INV1 — teste da topologia: half/better_half (do ramo Cosmic) seriam a CHAVE da
2a camada do ramo faed (BIF_REST, 563 chars pos-BTCSEED)?

Hipotese falsificavel: se Cosmic da a chave e faed da o premio, entao half,
better_half, half^bh ou sha256(half||bh) como keystream polialfabetico sobre o
BIF_REST devem produzir (a) texto ingles legivel, ou (b) material que abra
SMALL/COSMIC, ou (c) uma privkey do premio.

Pequeno e derivado: 4 materiais de chave x 3 cifras (Vigenere-dec, Vigenere-enc,
Beaufort) sobre o alfabeto Bifid de 25 letras = 12 saidas, cada uma julgada por
scorer EN + oraculos DUROS (aes_open, check_privkey). Auto-check positivo inclui.
"""
import hashlib, json, os, time
import dsl, oracles as O
from scorer import Scorer

ALPHA = "".join(sorted(set(dsl.bif_full()[7:])))   # 25 letras: A-Z sem J
assert len(ALPHA) == 25
IDX = {c: i for i, c in enumerate(ALPHA)}
REST = dsl.bif_full()[7:]
assert len(REST) == 563

HALF = bytes.fromhex("0423d9115a1dc756d5d08d2de880ab508bd4745fc97709f4fcb513f2cb8fcc35")
BH   = bytes.fromhex("48cc46e66bdd36b09ae344552f606a761f9d90681f20dfefe2b43db18b623971")
KEYS = {
    "half": HALF,
    "better_half": BH,
    "half_xor_bh": bytes(a ^ b for a, b in zip(HALF, BH)),
    "sha256_half_bh": hashlib.sha256(HALF + BH).digest(),
}

sc = Scorer()

def keystream(kbytes, n):
    """bytes de chave -> shifts mod-25, ciclados ate n."""
    return [kbytes[i % len(kbytes)] % 25 for i in range(n)]

def apply_cipher(text, ks, mode):
    ci = [IDX[c] for c in text]
    if mode == "vig_dec":
        out = [(ci[i] - ks[i]) % 25 for i in range(len(ci))]
    elif mode == "vig_enc":
        out = [(ci[i] + ks[i]) % 25 for i in range(len(ci))]
    else:  # beaufort
        out = [(ks[i] - ci[i]) % 25 for i in range(len(ci))]
    return "".join(ALPHA[x] for x in out)

def hard_oracles(pt):
    """Retorna (aes_hits, priv_hits) para varias formas do plaintext."""
    aes, priv = [], []
    forms = {pt, pt.lower(), pt.upper()}
    shas = {hashlib.sha256(f.encode()).hexdigest() for f in forms}
    for f in forms | shas:
        aes += O.aes_open(f)
    for f in forms:
        h = O.check_privkey(hashlib.sha256(f.encode()).digest())
        if h: priv.append(h)
    return aes, priv

def positive_control():
    """Cifra um EN conhecido com half (Vigenere-enc) e decifra com half -> recupera."""
    en = "".join(c for c in
         "THEUNANIMOUSDECLARATIONOFTHETHIRTEENUNITEDSTATESOFAMERICAWHENINTHECOURSE"
         if c in ALPHA)
    ks = keystream(HALF, len(en))
    ct = apply_cipher(en, ks, "vig_enc")
    rec = apply_cipher(ct, ks, "vig_dec")
    return rec == en, sc(en), sc(REST)

def main():
    out_path = os.path.join(os.path.dirname(__file__), "..", "_work", "inv1_half_over_bifrest.jsonl")
    ok, sc_en, sc_rest = positive_control()
    print(f"[control] roundtrip half-keystream OK={ok} | score(EN)={sc_en:.3f} score(BIF_REST cru)={sc_rest:.3f}")
    assert ok, "engine de keystream quebrado"

    rows = []
    best = (-1e9, None)
    for kname, kb in KEYS.items():
        ks = keystream(kb, len(REST))
        for mode in ("vig_dec", "vig_enc", "beaufort"):
            pt = apply_cipher(REST, ks, mode)
            s = sc(pt)
            aes, priv = hard_oracles(pt)
            # tambem: chave hex/raw como senha AES direta e privkey direta
            row = {"key": kname, "mode": mode, "score": round(s, 3),
                   "pt_head": pt[:48], "aes_hits": aes, "priv_hits": priv}
            rows.append(row)
            if s > best[0]:
                best = (s, row)
            print(f"[{kname:14s} {mode:8s}] score={s:7.3f} aes={len(aes)} priv={len(priv)} | {pt[:40]}")

    # chaves cruas como senha AES / privkey direta (cheap, completude)
    key_aes, key_priv = [], []
    for kname, kb in KEYS.items():
        key_aes += [("hex", kname, h) for h in O.aes_open(kb.hex())]
        key_aes += [("raw", kname, h) for h in O.aes_open(kb)]
        p = O.check_privkey(kb)
        if p: key_priv.append((kname, p))
    print(f"\n[chaves cruas] aes_hits={key_aes} priv_hits={key_priv}")

    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
        f.write(json.dumps({"key_raw_aes": key_aes, "key_raw_priv": key_priv,
                            "control_score_en": round(sc_en, 3),
                            "control_score_bifrest": round(sc_rest, 3)}) + "\n")

    total_aes = sum(len(r["aes_hits"]) for r in rows) + len(key_aes)
    total_priv = sum(len(r["priv_hits"]) for r in rows) + len(key_priv)
    print("\n=== VEREDITO INV1 (pergunta 3) ===")
    print(f"melhor score legibilidade={best[0]:.3f} (teto EN~{sc_en:.2f}; BIF_REST cru={sc_rest:.2f})")
    print(f"total AES hits={total_aes} | total privkey hits={total_priv}")
    print("CONCLUSAO:", "half/bh ABRE o ramo faed!" if (total_aes or total_priv)
          else "half/bh NAO e a chave da 2a camada do faed (0 oraculos duros).")

if __name__ == "__main__":
    main()
