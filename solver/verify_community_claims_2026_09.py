# -*- coding: utf-8 -*-
"""
Verificacao dura das alegacoes da comunidade de jul-set/2026 (issues #99, #108, #110, #111)
do repositorio original puzzlehunt/gsmgio-5btc-puzzle, contra os dados autenticos e o
oraculo duro (pubkey on-chain do premio).

Rodar a partir da raiz do repositorio:
    C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe solver/verify_community_claims_2026_09.py

Resultado (2026-09-17): as tres alegacoes caem. Detalhes em
_work/frontier_2026-09-17/RELATORIO.md
"""
import base64
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles as O
import final_chain as FC
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

CHAIN1_PASSWORD = b"matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"


def _unpad(p):
    if not p:
        return None
    n = p[-1]
    return p[:-n] if 1 <= n <= 16 and p.endswith(bytes([n]) * n) else None


def _readme_blob(prefix):
    txt = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "README.md"), encoding="utf-8").read()
    i = txt.index(prefix)
    out = []
    for line in txt[i:].splitlines():
        line = line.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]{4,64}", line):
            break
        out.append(line)
    return base64.b64decode("".join(out))


def check_108():
    """#108: 'o blob SMALL tem dois typos na pagina ao vivo (pos 18 R->J, pos 51 k->s)'."""
    salt, ct = O.blobs()["SMALL"]
    b64 = base64.b64encode(b"Salted__" + salt + ct).decode()
    print("== issue #108 — 'dois typos no blob SMALL' ==")
    print("  blob publicado:", b64)
    print(f"  posicao 18 = {b64[18]!r} (a issue diz que a pagina tem 'R' e o certo seria 'J')")
    print(f"  posicao 51 = {b64[51]!r} (a issue diz que a pagina tem 'k' e o certo seria 's')")
    print("  salt publicado :", salt.hex())
    print("  salt 'corrigido' segundo a issue: 3ab585348552415d ->",
          "IDENTICO" if salt.hex() == "3ab585348552415d" else "DIFERENTE")
    for hm in (MD5, SHA256):
        k, iv = O._evp(CHAIN1_PASSWORD, salt, hm)
        p = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
        pad, name = p[-1], hm.__name__.split(".")[-1]
        ok = 1 <= pad <= 16 and p.endswith(bytes([pad]) * pad)
        asc = sum(32 <= x < 127 for x in p) / len(p)
        print(f"  {name:>6}: padding_valido={ok} pad=0x{pad:02x} ascii={asc:.2f}")
    print("  VEREDITO: REFUTADA. A pagina ja contem os caracteres que a issue chama de correcao;")
    print("            o blob nao foi alterado e o 'decrypt' e a Chain1 conhecida, que so abre")
    print("            sob EVP-MD5 com pad 0x01 e plaintext de alta entropia (falso-positivo).\n")


def check_111(cosmic):
    """#111: FirstHalf/BetterHalf a partir de um 'gros_decrypted.bin' de 2432 B."""
    print("== issue #111 — FirstHalf / Reduction(SOURCE_4) sobre 'gros' ==")
    fh_claim = bytes.fromhex("8048c428a6faf6d3df77db13ca68766d")
    g_claim = bytes.fromhex("3be6ecf1d5c126e50f25ded3bc8fb6d9")
    src4 = base64.b64decode(
        "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ")
    print("  SOURCE_4 confere com o hex da issue:",
          src4.hex() == "42f5f4b7cbf78cf078a24a6ca7179b462eac13504c9791c8f119"
                        "2ef8a7a352a4ef756397ea74234a97a95f01ae37f8c9")
    fh_calc = bytes(a ^ b for a, b in zip(cosmic[0::4][:16], cosmic[1145:1161]))
    print("  cosmic[1161:1177] =", cosmic[1161:1177].hex(), "| bate com a issue:",
          cosmic[1161:1177] == g_claim)
    print("  FirstHalf recalc. =", fh_calc.hex(), "| bate com a issue:", fh_calc == fh_claim)
    lens = {"SMALL": 80, "TAIL32": 80, "COSMIC": 1328,
            "PHASE2": len(_readme_blob("U2FsdGVkX18GKGYS")) - 16,
            "PHASE3": len(_readme_blob("U2FsdGVkX1+fvEUdE9Bx")) - 16,
            "PHASE32": len(_readme_blob("U2FsdGVkX1/u/Exb78Fl")) - 16}
    print("  tamanhos de ciphertext dos blobs publicados:", lens)
    print("  um plaintext de 2432 B exigiria ct >= 2448; PHASE32 tem ct = 2432 (é o CIPHERTEXT).")
    print("  VEREDITO: NAO REPRODUZIVEL. O 'gros' de 2432 B nao corresponde a nenhuma decifracao")
    print("            autentica dos blobs publicados, logo FirstHalf/BetterHalf/Reduction nao")
    print("            sao testaveis e nao tem ancoragem nos dados do puzzle.\n")


def main():
    r = FC.reproduce()
    cosmic = r["cosmic"]
    print("cadeia comunitaria reproduzida: cosmic", len(cosmic), "B sha256",
          hashlib.sha256(cosmic).hexdigest()[:16], "\n")
    check_108()
    check_111(cosmic)
    print("== issues #99 / #110 — extracao de 12 enderecos de cosmic_decrypted.bin ==")
    print("  Ambas operam sobre o mesmo cosmic de 1327 B da cadeia comunitaria, cuja abertura")
    print("  nunca foi autenticada (pad 0x01 + EVP-MD5 + mascara construida). Os enderecos")
    print("  extraidos nao sao o premio; o premio segue intacto.")
    print("\n  premio:", O.PRIZE_ADDR, "- conferir saldo em mempool.space/api/address/" + O.PRIZE_ADDR)


if __name__ == "__main__":
    main()
