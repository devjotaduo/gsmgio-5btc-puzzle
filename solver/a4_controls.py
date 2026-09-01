# -*- coding: utf-8 -*-
"""A4 — CETICO ADVERSARIAL: controles POSITIVOS e fechamento de gaps.

O que este script prova (rodavel, byte-exato):

CONTROLE A3 (o que A3 AFIRMA ter feito mas nenhum script roda de fato):
  injeta uma privkey-needle CONHECIDA no pipeline e confirma que
  strong_oracle_35.detect() a ACHA por CADA caminho:
    (a) scan byte-a-byte em offset NAO-alinhado (o ponto-cego do oraculo antigo)
    (b) AES-CBC completo dentro de detect() (needle no plaintext decifrado)
    (c) keyself (a chave AES == privkey alvo)
    (d) WIF base58 embutido no plaintext
    (e) hex-ASCII (64 chars) embutido no plaintext
    (f) BIP39 (mnemonic -> BIP44 -> privkey derivada == alvo)
  Se algum caminho NAO disparar, o negativo de A3 naquele caminho e VAZIO.

ANCORA A1 (base do "COSMIC = ANCORADO FORTE"):
  reproduz COSMIC_PASSWORD == XOR de sha256 de 5 frases. Se nao bater, a
  classificacao ANCORADO FORTE do A1 cai.

GAP A2 (derivacao concretamente NAO testada pelo mask_provenance):
  a gramatica-assinatura do puzzle e CONCAT->SHA256 (nao XOR-de-digests, nao
  single-token). A2 nunca testou sha256(concat de tokens)[off:off+8]==mask.
  Idem md5(concat) (EVP usa MD5), mask byte-invertido, e janela-cosmic XOR
  janela-cosmic (auto-referencial). Rodo todos aqui.
"""
import hashlib
import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F
import oracles as O
import strong_oracle_35 as S
from coincurve import PublicKey
from Crypto.Cipher import AES

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_work",
                   "a4_controls.jsonl")


def sha(b):
    return hashlib.sha256(b).digest()


def pub_unc(priv):
    return PublicKey.from_valid_secret(priv).format(False)


# ---------------------------------------------------------------------------
# CONTROLE A3: needle conhecida, patch do alvo, confirma deteccao por caminho
# ---------------------------------------------------------------------------
def run_a3_controls():
    R = F.reproduce()
    results = {}

    # needle: privkey de teste (NAO e o alvo real; viramos alvo por patch)
    needle = sha(b"a4-control-needle")
    needle_pub = pub_unc(needle)

    # salva estado original e injeta a needle como "alvo"
    orig_pubs, orig_target = S.PUBS, S.TARGET_PUBKEY
    S.PUBS = {needle_pub}
    S.TARGET_PUBKEY = needle_pub
    try:
        # (a) scan byte-a-byte, offset NAO-alinhado (offset 7, dentro de 32B blk)
        buf = b"X" * 7 + needle + b"Y" * 40
        out = []
        S.scan(buf, "ctrl_a", out)
        results["a_offset_scan_nonaligned"] = any(h[0] == "PRIVKEY" for h in out)

        # (b) AES-CBC completo em detect(): forjo blocks tal que CBC(key,IV=zero)
        #     decifre para um plaintext contendo a needle em offset nao-alinhado.
        key = sha(b"a4-aes-key")
        iv_zero = b"\x00" * 16
        target_pt = (b"Z" * 13 + needle + b"W" * (1120 - 13 - 32))
        assert len(target_pt) == 1120
        forged_blocks = AES.new(key, AES.MODE_CBC, iv_zero).encrypt(target_pt)
        Rp = dict(R)
        Rp["blocks"] = forged_blocks
        hits = S.detect(key, "ctrl_b", Rp)
        results["b_aes_cbc_pipeline"] = any(
            h[0] == "PRIVKEY" and "cbc:zero" in h[1] for h in hits)

        # (c) keyself: a chave AES E a propria privkey alvo
        S.PUBS = {pub_unc(key)}
        S.TARGET_PUBKEY = pub_unc(key)
        hits = S.detect(key, "ctrl_c", R)
        results["c_keyself"] = any(
            h[0] == "PRIVKEY" and "keyself" in h[1] for h in hits)
        # restaura needle como alvo p/ os demais
        S.PUBS = {needle_pub}
        S.TARGET_PUBKEY = needle_pub

        # (d) WIF embutido no plaintext
        wif = F.wif_uncompressed(needle).decode()  # 51 chars, prefixo '5'
        buf = b"prefixo|" + wif.encode() + b"|sufixo"
        out = []
        S.scan(buf, "ctrl_d", out)
        results["d_wif_scan"] = any(h[0] == "PRIVKEY" and ":wif@" in h[1] for h in out)

        # (e) hex-ASCII (64 chars) embutido
        buf = b"....." + needle.hex().encode() + b"....."
        out = []
        S.scan(buf, "ctrl_e", out)
        results["e_hexpriv_scan"] = any(
            h[0] == "PRIVKEY" and ":hexpriv@" in h[1] for h in out)

        # (f) BIP39: mnemonic conhecido -> BIP44 m/44'/0'/0'/0/0 -> priv derivada.
        #     patch do alvo p/ o pub dessa priv derivada, e embuto o mnemonic.
        from bip_utils import (Bip39SeedGenerator, Bip44, Bip44Coins,
                               Bip44Changes)
        from mnemonic import Mnemonic
        # mnemonic NAO-degenerado (palavras distintas) para exercitar o caminho;
        # o all-abandon e rejeitado de proposito pela guarda de diversidade.
        _mm = Mnemonic("english")
        mnem = _mm.generate(strength=128)
        while len(set(mnem.split())) / 12 < 0.60:  # garante nao-degenerado
            mnem = _mm.generate(strength=128)
        seed = Bip39SeedGenerator(mnem).Generate()
        ck = (Bip44.FromSeed(seed, Bip44Coins.BITCOIN).Purpose().Coin()
              .Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
        derived_priv = ck.PrivateKey().Raw().ToBytes()
        S.PUBS = {pub_unc(derived_priv)}
        S.TARGET_PUBKEY = pub_unc(derived_priv)
        buf = ("head " + mnem + " tail").encode()
        out = []
        S.scan(buf, "ctrl_f", out)
        results["f_bip39_derived_priv"] = any(h[0] == "PRIVKEY" for h in out)
    finally:
        S.PUBS, S.TARGET_PUBKEY = orig_pubs, orig_target

    results["ALL_PATHS_FIRE"] = all(results.values())
    return results


# ---------------------------------------------------------------------------
# ANCORA A1: COSMIC_PASSWORD == XOR de sha256 de 5 frases?
# ---------------------------------------------------------------------------
def run_a1_cosmic_anchor():
    phrases = [b"enter", b"lastwordsbeforearchichoice", b"thispassword",
               b"yourlastcommand", b"secondanswer"]
    acc = bytearray(32)
    for p in phrases:
        d = sha(p)
        for i in range(32):
            acc[i] ^= d[i]
    return {
        "xor5_sha_phrases": bytes(acc).hex(),
        "COSMIC_PASSWORD": F.COSMIC_PASSWORD.hex(),
        "matches": bytes(acc) == F.COSMIC_PASSWORD,
    }


# ---------------------------------------------------------------------------
# GAP A2: derivacoes concretamente NAO testadas pelo mask_provenance
# ---------------------------------------------------------------------------
def run_a2_gap():
    MASK = F.CHAIN4_MASK
    R = F.reproduce()
    cc = R["cosmic"]
    TOKENS = [b"enter", b"matrixsumlist", b"lastwordsbeforearchichoice",
              b"thispassword", b"yourlastcommand", b"secondanswer", b"shabef",
              b"Salted__"]

    found = []

    # G1: sha256(concat de tokens) — a gramatica-assinatura CONCAT->SHA256.
    #     todas as permutacoes de subsets tamanho 2..4, com/sem separadores.
    def concat_variants(combo):
        yield b"".join(combo)
        yield b"".join(c + b"\n" for c in combo)
    for r in (2, 3, 4):
        for combo in itertools.permutations(TOKENS, r):
            for cat in concat_variants(combo):
                dg = sha(cat)
                for off in range(0, 25):
                    if dg[off:off + 8] == MASK:
                        found.append({"kind": "sha256(concat)", "combo":
                                      [c.decode() for c in combo], "off": off})
                dm = hashlib.md5(cat).digest()
                for off in range(0, 9):
                    if dm[off:off + 8] == MASK:
                        found.append({"kind": "md5(concat)", "combo":
                                      [c.decode() for c in combo], "off": off})

    # G2: mask byte-invertido == qualquer slice sha256(token) (single) / concat
    rmask = MASK[::-1]
    for tok in TOKENS:
        dg = sha(tok)
        for off in range(0, 25):
            if dg[off:off + 8] == rmask:
                found.append({"kind": "reversed==sha(token)", "tok": tok.decode(),
                              "off": off})

    # G3: auto-referencial — mask == cosmic[a:a+8] XOR cosmic[b:b+8]?
    #     (varredura leve: a fixo em janelas-chave, b livre) -> so o par obvio
    #     158/qualquer que reproduz Salted__ ja e conhecido; procuro OUTRO par.
    hits_self = 0
    example = None
    step = 1
    n = len(cc)
    # limita a janelas ancoradas: a in {64,66,158,166}; b percorre tudo
    for a in (64, 66, 158, 166):
        wa = cc[a:a + 8]
        if len(wa) < 8:
            continue
        for b in range(0, n - 8, step):
            if bytes(x ^ y for x, y in zip(wa, cc[b:b + 8])) == MASK:
                hits_self += 1
                if example is None:
                    example = {"a": a, "b": b}
    found_self = {"pairs": hits_self, "example": example}

    return {"concat_and_reversed_hits": found, "self_xor": found_self}


def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    report = {
        "a3_positive_controls": run_a3_controls(),
        "a1_cosmic_anchor": run_a1_cosmic_anchor(),
        "a2_untested_derivations": run_a2_gap(),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(report, ensure_ascii=False) + "\n")

    # asserts-controle: os controles positivos DEVEM disparar, senao os
    # negativos de A3 sao vazios (o motor nao recupera nem uma needle plantada).
    c = report["a3_positive_controls"]
    assert c["ALL_PATHS_FIRE"], f"CONTROLE A3 FALHOU: {c}"
    assert report["a1_cosmic_anchor"]["matches"], "ANCORA COSMIC nao reproduz"
    print("\n[a4_controls] CONTROLES POSITIVOS OK — o detector recupera a needle "
          "em TODOS os caminhos; negativos de A3 tem peso.")


if __name__ == "__main__":
    main()
