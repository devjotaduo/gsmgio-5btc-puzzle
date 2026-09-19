# -*- coding: utf-8 -*-
"""
F9 "degrau_oraculo" — cadeia em miniatura COMPLETA na gramatica do criador.

Tres cadeias de 3 elos cada, com o PASSO DE CONSUMO DO RESIDUO conhecido por construcao:
    elo 1: tokens de hint -> sha256hex -> AES-256-CBC/b64 -> plaintext com prosa + residuo a-i
    consumo: letras do residuo nas POSICOES PRIMAS (1-indexadas) -> a1z26 -> digitos -> token
    elo 2: token do residuo + token fixo -> sha256hex -> AES -> plaintext do tipo X
    elo 3: -> AES -> plaintext final (a "chave")

Mede em que elo o oraculo atual (G.try_password_all + G.semantic/nested/ebcdic/fast_priv_scan)
PARARIA se o solucionador dependesse dele para reconhecer que acertou.

Segunda implementacao: openssl CLI cifra e decifra; o kit decifra em paralelo.
"""
import base64, hashlib, json, os, random, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "experiments", "claude_endgame_2026_09_02")))
import gsmg_common as G                                   # noqa: E402
from mini_puzzle import (cifra_openssl, decifra_openssl, cp273_bytes, chave_aleatoria,
                         h160_de, ruido, _FWD_MIN)        # noqa: E402
import oracles as O                                       # noqa: E402

RNG = random.Random(84)


def residuo_ai(n=91):
    return "".join(RNG.choice("abcdefghi") for _ in range(n))


def consome_residuo(res):
    """Passo de consumo CONHECIDO: letras em posicoes primas (1-indexado) -> a1z26 -> digitos."""
    prim = [res[i - 1] for i in range(1, len(res) + 1) if G.is_prime(i)]
    return "".join(str(G.A2I[c]) for c in prim)


def elo(pt: bytes, tokens):
    """Cifra um elo e devolve (senha_hex, b64, plaintext). Certifica nas duas implementacoes."""
    frase = "".join(tokens)
    h = hashlib.sha256(frase.encode()).hexdigest()
    b64 = cifra_openssl(pt, h)
    assert decifra_openssl(b64, h) == pt, "openssl CLI nao reproduz o plaintext"
    raw = base64.b64decode(b64)
    G.BLOBS["ELO"] = (raw[8:16], raw[16:])
    kit = [p for k, p in G.aes_try(h, "ELO") if p == pt]
    assert kit, "kit (pycryptodome) nao reproduz o plaintext"
    G.BLOBS.pop("ELO")
    return {"frase": frase, "senha_sha256": h, "b64": b64, "pt": pt}


def veredito(e, plantar_key=None):
    """O oraculo atual, com a senha CERTA em maos: o acerto sobrevive e vira candidato?"""
    raw = base64.b64decode(e["b64"])
    G.BLOBS["ELO"] = (raw[8:16], raw[16:])
    add = ()
    if plantar_key:
        k = bytes.fromhex(plantar_key)
        add = (h160_de(k, True), h160_de(k, False))
        G.TARGET_H160S = G.TARGET_H160S + add
        O.TARGET_H160S = O.TARGET_H160S + add
    try:
        hard, soft = G.try_password_all(e["senha_sha256"], blobs=("ELO",), kdf="both")
        pt = e["pt"]
        return {"sobreviveu": any(bytes.fromhex(h["hex"]) == pt for h in hard + soft),
                "candidato": any(bytes.fromhex(h["hex"]) == pt for h in hard),
                "printable": round(G.printable(pt), 3),
                "semantic": bool(G.semantic(pt)), "nested": bool(G.nested_blob(pt)),
                "ebcdic": round(G.ebcdic_sig(pt), 3),
                "priv": bool(G.fast_priv_scan(pt)) if len(pt) >= 32 else False}
    finally:
        if add:
            G.TARGET_H160S = G.TARGET_H160S[:-2]
            O.TARGET_H160S = O.TARGET_H160S[:-2]
        G.BLOBS.pop("ELO", None)


def cadeia(nome, tipos):
    """tipos: lista de 3 construtores de plaintext (funcao -> (bytes, plantar_key|None))."""
    res = residuo_ai()
    tok = consome_residuo(res)
    elos, ver = [], []
    toks_base = [["mini", "degrau", nome], [tok, "prime", "basics"], [tok, "last", "key"]]
    for i, f in enumerate(tipos):
        pt, plant = f(res, tok)
        e = elo(pt, toks_base[i])
        elos.append(e)
        ver.append(veredito(e, plant))
    # elo em que a cadeia morre (primeiro elo cujo acerto nao vira candidato)
    morre = next((i + 1 for i, v in enumerate(ver) if not v["candidato"]), None)
    return {"cadeia": nome, "residuo": res, "token_do_residuo": tok,
            "senhas": [e["senha_sha256"] for e in elos],
            "veredito_por_elo": ver, "morre_no_elo": morre}


# ---- construtores de plaintext por elo -------------------------------------------------
def pt_prosa_com_residuo(res, tok):
    return (b"Reinsert the prime basics. The remainder below is your next password material.\n"
            + res.encode() + b"\n"), None


def pt_raw32_estagio(res, tok):
    return hashlib.sha256(tok.encode()).digest(), None            # chave da proxima camada (-K)


def pt_chave_final(res, tok):
    k = chave_aleatoria()
    return k, k.hex()                                             # raw32 = a chave do premio


def pt_ebcdic(res, tok):
    return b"One for one, four for one.\n" + cp273_bytes(res * 2) + b"\n", None


def pt_hex64(res, tok):
    k = chave_aleatoria()
    return b"the actual private keynote: " + k.hex().encode(), k.hex()


def pt_b64_multilinha(res, tok):
    inner = cifra_openssl(b"sixteen encryptions " + res.encode(), hashlib.sha256(tok.encode()).hexdigest())
    return inner.encode(), None


def pt_binario_com_chave(res, tok):
    k = chave_aleatoria()
    return ruido(24) + k[::-1] + ruido(24), k.hex()               # little-endian


def main():
    saida = [
        cadeia("I_texto_depois_binario", [pt_prosa_com_residuo, pt_raw32_estagio, pt_chave_final]),
        cadeia("II_todos_visiveis", [pt_b64_multilinha, pt_ebcdic, pt_hex64]),
        cadeia("III_chave_em_LE", [pt_prosa_com_residuo, pt_raw32_estagio, pt_binario_com_chave]),
    ]
    for c in saida:
        print("\n== %s ==  residuo consumido -> token %s..." % (c["cadeia"], c["token_do_residuo"][:20]))
        for i, v in enumerate(c["veredito_por_elo"]):
            print("  elo %d: sobreviveu=%s candidato=%s printable=%.3f sem=%s nest=%s ebc=%.2f priv=%s"
                  % (i + 1, v["sobreviveu"], v["candidato"], v["printable"], v["semantic"],
                     v["nested"], v["ebcdic"], v["priv"]))
        print("  -> morre no elo:", c["morre_no_elo"])
    with open(os.path.join(HERE, "cadeias.json"), "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
