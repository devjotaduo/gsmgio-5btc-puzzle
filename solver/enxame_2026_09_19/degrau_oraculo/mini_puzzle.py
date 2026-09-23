# -*- coding: utf-8 -*-
"""
F9 "degrau_oraculo" — enxame 2026-09-19.

Problema-ponte: o alvo NAO e o espaco de chaves, e o DETECTOR.

Constroi puzzles em miniatura na gramatica do criador
    tokens -> sha256hex -> openssl enc -aes-256-cbc -a -pass pass:<hex> (EVP-SHA256)
com o plaintext CONHECIDO POR CONSTRUCAO, e mede se o oraculo atual do kit
(G.semantic / G.nested_blob / G.ebcdic_sig / G.fast_priv_scan / G.try_password_all)
reconheceria o acerto.

Segunda implementacao: o `openssl` CLI cifra; o kit (pycryptodome, G.aes_try) decifra.
Toda instancia so entra na medicao depois do ida-e-volta conferido nas DUAS
implementacoes (openssl -d e G.aes_try devolvem o mesmo plaintext).

Uso:  python3 mini_puzzle.py            # gera, certifica e mede
Saida: instancias.json + medicao.json + resumo em stdout.
"""
import base64, hashlib, json, os, random, subprocess, sys, tempfile, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.abspath(os.path.join(HERE, "..", "..", "experiments", "claude_endgame_2026_09_02"))
sys.path.insert(0, KIT)
import gsmg_common as G           # noqa: E402
import oracles as O               # noqa: E402
from coincurve import PublicKey   # noqa: E402
from Crypto.Cipher import AES     # noqa: E402
from Crypto.Hash import SHA256    # noqa: E402

N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

RNG = random.Random(20260919)
TMP = tempfile.mkdtemp(prefix="mini_puzzle_")
OPENSSL = "openssl"

# --------------------------------------------------------------- gramatica do criador
def senha_da_frase(tokens):
    """Fase 0-3.2: palavras concatenadas na ordem, caixa preservada -> sha256 -> hex e a senha."""
    frase = "".join(tokens)
    return frase, hashlib.sha256(frase.encode()).hexdigest()


def cifra_openssl(plaintext: bytes, senha_hex: str, cipher="-aes-256-cbc", extra=()):
    """Cifra com o CLI (a segunda implementacao). Devolve o base64 armadurado."""
    fin = os.path.join(TMP, "pt.bin")
    with open(fin, "wb") as f:
        f.write(plaintext)
    cmd = [OPENSSL, "enc", cipher, "-a", "-md", "sha256", "-pass", "pass:" + senha_hex, "-in", fin]
    cmd += list(extra)
    out = subprocess.run(cmd, capture_output=True, check=True).stdout
    return out.decode().strip()


def decifra_openssl(b64: str, senha_hex: str, cipher="-aes-256-cbc", extra=()):
    fin = os.path.join(TMP, "ct.b64")
    with open(fin, "w") as f:
        f.write(b64 + "\n")
    cmd = [OPENSSL, "enc", cipher, "-d", "-a", "-md", "sha256", "-pass", "pass:" + senha_hex, "-in", fin]
    cmd += list(extra)
    r = subprocess.run(cmd, capture_output=True)
    return r.stdout if r.returncode == 0 else None


# --------------------------------------------------------------- material de plaintext
PROSA = [
    b"The next step is hidden in the remainder. Take the letters at prime positions and read them as numbers.",
    b"Congratulations. You have reinserted the prime basics. The password of the next layer follows.",
    b"Well done. Now return to the source codes and select from the ciphers you were taught.",
    b"This is not the end. Concatenate the words you found and hash them again with sha256.",
    b"You found the seed. The private key note is below, keep the case and the spaces.",
]


# direcao AUTENTICA da fase 3.2 (a mesma que G._EBCDIC_AZ usa): o byte ASCII da letra e
# DECODIFICADO como cp273 e o caractere resultante guardado em latin-1. Reproduz os bytes
# reais do segmento "╬╚,╬°%_..." do plaintext da 3.2.
_FWD_MIN = {c: bytes([ord(c)]).decode("cp273").encode("latin-1")[0] for c in "abcdefghijklmnopqrstuvwxyz"}
_FWD_MAI = {c: bytes([ord(c)]).decode("cp273").encode("latin-1")[0] for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}


def cp273_bytes(texto: str, tabela=None) -> bytes:
    tab = tabela or _FWD_MIN
    return bytes(tab[c] for c in texto if c in tab)


def chave_aleatoria():
    while True:
        k = bytes(RNG.getrandbits(8) for _ in range(32))
        n = int.from_bytes(k, "big")
        if 0 < n < N_ORDER:
            return k


def h160_de(k: bytes, comp=True):
    return hashlib.new("ripemd160", hashlib.sha256(PublicKey.from_valid_secret(k).format(comp)).digest()).hexdigest()


def wif(k: bytes, comp=True):
    import base58
    payload = b"\x80" + k + (b"\x01" if comp else b"")
    return base58.b58encode_check(payload).decode()


def mnemonic_de(k: bytes):
    from mnemonic import Mnemonic
    return Mnemonic("english").to_mnemonic(k)


def a1z26_de(k: bytes):
    """hex64 -> letras: 0-9a-f mapeado em a-p (representacao 'nao obvia' mas ASCII)."""
    h = k.hex()
    return "".join(chr(ord("a") + int(c, 16)) for c in h)


def ruido(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


# --------------------------------------------------------------- tipos de acerto
def gera_instancias(por_tipo=10):
    """Cada instancia: (tipo, plaintext, cipher, extra, meta). Plaintext = o ACERTO conhecido."""
    inst = []

    def add(tipo, pt, cipher="-aes-256-cbc", extra=(), **meta):
        inst.append({"tipo": tipo, "pt": pt, "cipher": cipher, "extra": list(extra), "meta": meta})

    for i in range(por_tipo):
        prosa = PROSA[i % len(PROSA)]

        # A — texto ASCII como as fases 0-3.2 (o caso facil)
        add("A_ascii_prosa", prosa + b" step %d." % i)

        # B — mistura prosa + segmento cp273 (imita o plaintext REAL da fase 3.2, printable ~0.59)
        seg = cp273_bytes("".join(RNG.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(160)))
        add("B_ebcdic_cp273_misto", prosa[:60] + b"\n" + seg + b"\n")

        # C1 — plaintext e outro blob openssl em armadura base64 (SIXTEEN ENCRYPTIONS)
        interno = cifra_openssl(b"inner layer %d" % i, hashlib.sha256(b"inner%d" % i).hexdigest())
        add("C1_aninhado_b64", interno.encode())

        # C2 — plaintext e o blob openssl CRU (Salted__ + salt + ct)
        add("C2_aninhado_cru", base64.b64decode(interno))

        # C3 — blob aninhado em base64 de VARIAS linhas de 64 chars: o formato REAL de
        #      SMALL/TAIL32 no site (duas linhas) e o de COSMIC/fases 2-3.2 no README.
        grande = cifra_openssl(b"inner layer %d " % i + b"x" * 120,
                               hashlib.sha256(b"multi%d" % i).hexdigest())
        add("C3_aninhado_b64_multilinha", grande.encode())

        # C4 — blob aninhado precedido de prosa (como o plaintext REAL da fase 3.2)
        add("C4_aninhado_apos_prosa", b"Raising the stakes.\n" + grande.encode())

        # C5 — blob aninhado (base64) precedido de bytes binarios
        add("C5_aninhado_apos_binario", ruido(24) + b"\n" + grande.encode())

        # C6 — blob aninhado CRU fora do offset 0 (nested_blob so olha p[:8])
        add("C6_aninhado_cru_deslocado", ruido(24) + base64.b64decode(grande))

        # D — chave em representacao nao obvia
        k = chave_aleatoria()
        add("D1_hex64", k.hex().encode(), key=k.hex())
        add("D2_wif", wif(k).encode(), key=k.hex())
        add("D3_mnemonic", mnemonic_de(k).encode(), key=k.hex())
        add("D4_decimal", str(int.from_bytes(k, "big")).encode(), key=k.hex())
        add("D5_base64_da_chave", base64.b64encode(k), key=k.hex())
        add("D6_a1z26_da_chave", a1z26_de(k).encode(), key=k.hex())
        # D7a — raw32 que E a chave do premio (plantada nos alvos: o scanner DEVE ver)
        add("D7a_raw32_chave_premio", k, key=k.hex(), plantar=True)
        # D7b — raw32 que e a chave da PROXIMA camada AES (-K), nao um endereco alvo
        k2 = chave_aleatoria()
        add("D7b_raw32_chave_de_estagio", k2, key=k2.hex(), plantar=False)
        # D8 — chave do premio no interior de um plaintext binario
        k3 = chave_aleatoria()
        add("D8_raw32_em_binario", ruido(24) + k3 + ruido(24), key=k3.hex(), plantar=True)
        # D9 — hex64 no interior de um plaintext binario
        k4 = chave_aleatoria()
        add("D9_hex64_em_binario", ruido(16) + k4.hex().encode() + ruido(16), key=k4.hex(), plantar=True)
        # D10 — chave do premio guardada em little-endian (o scanner do kit so le BE)
        k5 = chave_aleatoria()
        add("D10_raw32_LE", ruido(16) + k5[::-1] + ruido(16), key=k5.hex(), plantar=True)
        # D11 — chave de 16 B (metade) + 16 B de contexto: janela raw32 nunca casa
        k6 = chave_aleatoria()
        add("D11_meia_chave_16B", k6[:16], key=k6.hex(), plantar=True)
        # D12 — hex64 MAIUSCULO no interior de binario (o regex aceita; controle de caixa)
        k7 = chave_aleatoria()
        add("D12_hex64_maiusculo", ruido(16) + k7.hex().upper().encode() + ruido(16), key=k7.hex(), plantar=True)

        # F — codificacoes de texto que nao sao ASCII nem cp273 minusculo
        txt = (prosa.decode() + " %d" % i)
        add("F1_utf16le", txt.encode("utf-16-le"))
        add("F2_ebcdic_maiusculo", cp273_bytes(txt.upper(), _FWD_MAI))
        add("F3_zlib", zlib.compress(prosa * 3))
        # F4 — texto logo ABAIXO do limiar de 0,85 (mistura calibrada)
        base = bytearray(prosa[:80])
        for j in RNG.sample(range(80), 16):          # 20% de bytes altos -> printable 0.80
            base[j] = RNG.randrange(0x80, 0x100)
        add("F4_printable_0_80", bytes(base))

    # E — modos/paddings fora do CBC-com-PKCS7 (5 cada; plaintext de 64 B para caber em -nopad)
    for i in range(5):
        pt64 = (PROSA[i % len(PROSA)] + b" " * 64)[:64]
        add("E1_cbc_nopad", pt64, extra=("-nopad",))
        add("E2_ctr", pt64, cipher="-aes-256-ctr")
        add("E3_ofb", pt64, cipher="-aes-256-ofb")
        add("E4_cfb", pt64, cipher="-aes-256-cfb")
        add("E5_cfb8", pt64, cipher="-aes-256-cfb8")
    return inst


# --------------------------------------------------------------- certificacao e medicao
def certifica(b64, senha_hex, pt, cipher, extra):
    """Ida-e-volta nas duas implementacoes. Devolve (ok_openssl, ok_kit)."""
    ok_cli = decifra_openssl(b64, senha_hex, cipher, extra) == pt
    raw = base64.b64decode(b64)
    ok_kit = None
    if cipher == "-aes-256-cbc" and not extra:
        salt, ct = raw[8:16], raw[16:]
        k, iv = G.evp(senha_hex.encode(), salt, SHA256)
        ok_kit = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct)) == pt
    return ok_cli, ok_kit


def mede(inst):
    """Roda o oraculo atual sobre o ACERTO conhecido. Devolve o veredito por braco."""
    tipo, pt = inst["tipo"], inst["pt"]
    senha_frase, senha_hex = senha_da_frase(["mini", "degrau", tipo, str(inst["idx"])])
    b64 = cifra_openssl(pt, senha_hex, inst["cipher"], inst["extra"])
    ok_cli, ok_kit = certifica(b64, senha_hex, pt, inst["cipher"], inst["extra"])

    # o pipeline real: injeta o blob no kit e roda try_password_all com a senha CERTA
    raw = base64.b64decode(b64)
    G.BLOBS["MINI"] = (raw[8:16], raw[16:])

    # chave plantada: so entra nos alvos quem, por construcao, e "a chave do premio"
    plant = inst["meta"].get("plantar")
    h_add = ()
    if plant:
        k = bytes.fromhex(inst["meta"]["key"])
        h_add = (h160_de(k, True), h160_de(k, False))
        G.TARGET_H160S = G.TARGET_H160S + h_add
        O.TARGET_H160S = O.TARGET_H160S + h_add
    try:
        hard, soft = G.try_password_all(senha_hex, blobs=("MINI",), kdf="both")
        r = {
            "tipo": tipo, "idx": inst["idx"], "len": len(pt),
            "senha_frase": senha_frase, "senha_sha256": senha_hex, "blob_b64": b64,
            "cli_roundtrip": ok_cli, "kit_roundtrip": ok_kit,
            "printable": round(G.printable(pt), 3),
            "semantic": bool(G.semantic(pt)),
            "nested_blob": bool(G.nested_blob(pt)),
            "ebcdic_sig": round(G.ebcdic_sig(pt), 3),
            "fast_priv_scan": bool(G.fast_priv_scan(pt) if len(pt) >= 32 else []),
            "wif_ou_hex64": bool(G.wif_candidates(pt.decode("latin-1")) or
                                 G.hex64_candidates(pt.decode("latin-1"))),
            # o veredito do PIPELINE: o acerto sobreviveu e foi marcado candidato?
            "pipeline_sobreviveu": any(bytes.fromhex(h["hex"]) == pt for h in hard + soft),
            "pipeline_candidato": any(bytes.fromhex(h["hex"]) == pt for h in hard),
        }
    finally:
        if plant:
            G.TARGET_H160S = G.TARGET_H160S[:-2]
            O.TARGET_H160S = O.TARGET_H160S[:-2]
        G.BLOBS.pop("MINI", None)
    return r


def controles():
    """Controle positivo obrigatorio (spec.json): fase 2 e checkerboard 3.2.2."""
    raw = base64.b64decode(G.PHASE2_B64)
    k, iv = G.evp(G.shahex("causality").encode(), raw[8:16], SHA256)
    p2 = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(raw[16:]))
    c1 = p2 is not None and p2.startswith(b"The ironic")
    alpha = "FUBCDORA.LETHINGKYMVPS.JQZXW"
    digs = [int(c) for c in ("15165943121972409169171213758951813141543131412428154191312181219433121171617137"
                             "1491109166312131312814911091661314121991143716121260216643137111541" "12")]
    c2 = G.checkerboard_decode(digs, alpha, escapes=(1, 4), universe="0123456789").startswith("INCASEYOUMANAGETOCRACKTHIS")
    # controle do scanner de privkey: chave plantada tem de ser recuperada
    k3 = chave_aleatoria()
    antes = bool(G.fast_priv_scan(b"\x00" * 7 + k3 + b"\x00" * 9))
    G.TARGET_H160S = G.TARGET_H160S + (h160_de(k3, True),)
    depois = bool(G.fast_priv_scan(b"\x00" * 7 + k3 + b"\x00" * 9))
    G.TARGET_H160S = G.TARGET_H160S[:-1]
    # controle do scorer textual: existe neste ambiente?
    try:
        G.english_score("THEQUICKBROWNFOX")
        scorer_ok = True
    except Exception as e:
        scorer_ok = "INDISPONIVEL: %s" % type(e).__name__
    return {"fase2_abre_com_sha256hex_causality": c1, "checkerboard_322": c2,
            "priv_scan_sem_plantio": antes, "priv_scan_com_plantio": depois,
            "scorer_quadgramas": scorer_ok}


def especificidade(n=50000, tam=80):
    """Taxa de FALSO POSITIVO do detector: ruido uniforme de `tam` bytes (o que um padding
    valido por acaso entrega). Calibra o outro lado da medicao."""
    r = random.Random(7)
    fp = {"semantic": 0, "nested": 0, "ebcdic": 0, "printable_085": 0, "wif_hex64": 0}
    for _ in range(n):
        p = bytes(r.getrandbits(8) for _ in range(tam))
        fp["semantic"] += G.semantic(p)
        fp["nested"] += G.nested_blob(p)
        fp["ebcdic"] += G.ebcdic_sig(p) >= 0.75
        fp["printable_085"] += G.printable(p) >= 0.85
        t = p.decode("latin-1")
        fp["wif_hex64"] += bool(G.wif_candidates(t) or G.hex64_candidates(t))
    fp["n"] = n
    return fp


def main():
    ctr = controles()
    print("CONTROLES:", json.dumps(ctr, ensure_ascii=False))
    assert ctr["fase2_abre_com_sha256hex_causality"] and ctr["checkerboard_322"]
    assert (not ctr["priv_scan_sem_plantio"]) and ctr["priv_scan_com_plantio"]

    inst = gera_instancias(por_tipo=10)
    for i, x in enumerate(inst):
        x["idx"] = i
    res = []
    for x in inst:
        res.append(mede(x))

    # agregacao por tipo
    tipos = {}
    for r in res:
        t = tipos.setdefault(r["tipo"], {"n": 0, "cli": 0, "kit": 0, "sobrev": 0, "cand": 0,
                                         "semantic": 0, "nested": 0, "ebcdic": 0, "priv": 0})
        t["n"] += 1
        t["cli"] += bool(r["cli_roundtrip"]); t["kit"] += bool(r["kit_roundtrip"])
        t["sobrev"] += bool(r["pipeline_sobreviveu"]); t["cand"] += bool(r["pipeline_candidato"])
        t["semantic"] += bool(r["semantic"]); t["nested"] += bool(r["nested_blob"])
        t["ebcdic"] += r["ebcdic_sig"] >= 0.75; t["priv"] += bool(r["fast_priv_scan"])

    fp = especificidade()
    print("FALSO POSITIVO (ruido uniforme 80 B):", json.dumps(fp))

    with open(os.path.join(HERE, "medicao.json"), "w", encoding="utf-8") as f:
        json.dump({"controles": ctr, "falso_positivo": fp, "por_tipo": tipos,
                   "instancias": res}, f, ensure_ascii=False, indent=1)

    print("\n%-28s %3s %5s %5s %6s %6s %6s %6s %6s %6s" %
          ("tipo", "n", "cli", "kit", "sobrev", "cand", "sem", "nest", "ebc", "priv"))
    for t in sorted(tipos):
        v = tipos[t]
        print("%-28s %3d %5d %5s %6d %6d %6d %6d %6d %6d" %
              (t, v["n"], v["cli"], v["kit"], v["sobrev"], v["cand"], v["semantic"],
               v["nested"], v["ebcdic"], v["priv"]))
    det = sum(v["cand"] for v in tipos.values()); n = sum(v["n"] for v in tipos.values())
    print("\nTOTAL: %d/%d acertos marcados CANDIDATO  (falso negativo = %d, %.1f%%)"
          % (det, n, n - det, 100 * (n - det) / n))


if __name__ == "__main__":
    main()
