# -*- coding: utf-8 -*-
"""Teste falsificavel da hipotese primaria do hint 2026-03-03 do criador:

    "rewatch episode 3.5 with the better half"

Episodio: Mr. Robot S03E06 (28o da serie) = "eps3.5_kill-process.inc".
Temas do episodio que ecoam o puzzle:
  * HSM + roubo de certificados de code-signing  (fase 3 do puzzle = Thales HSM)
  * `shred -uzn3` -> ZERO OUT dados              (hint "some characters need
                                                   to be zeroed out")
  * misdirection / "looking in the wrong
    direction" / "in front of your eyes but
    not seeing it"                              (Bingo do criador, 2026-03-03)
  * 71 prédios destruidos; 28o episodio          (header do Chain4 = 28 bytes)

Contrato: so conta como solve se bater a pubkey publica do premio
(matches_pubkey) ou produzir abertura AES estruturalmente forte
(padding PKCS7 valido E corpo >=80% ascii, OU `Salted__` embutido,
OU a pubkey-alvo dentro do plaintext). Padding isolado nao e solve.

NOVA: nenhum desses candidatos estava nas 47 frases testadas na fronteira
(roadmap/Venus/Fresco/cosmic/tiny-hint). eps3.5/kill-process estava explicitamente
registrado no ENDGAME como proposta "nao-testada/nao-confirmada".
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

from coincurve import PublicKey
from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import final_chain as F

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "_work", "eps35_attack.jsonl")

TARGET_PUBKEY = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
    "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)


def matches_pubkey(secret: bytes) -> bool:
    if len(secret) != 32 or not any(secret):
        return False
    try:
        return PublicKey.from_valid_secret(secret).format(compressed=False) == TARGET_PUBKEY
    except ValueError:
        return False


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in (9, 10, 13) or 32 <= b < 127 for b in data) / len(data)


def valid_plaintext(data: bytes) -> bool:
    if not data or len(data) % 16:
        return False
    pad = data[-1]
    if not 1 <= pad <= 16 or not data.endswith(bytes([pad]) * pad):
        return False
    body = data[:-pad]
    return bool(body) and printable_ratio(body) >= 0.80


def xor_cycle(data: bytes, key: bytes) -> bytes:
    return bytes(v ^ key[i % len(key)] for i, v in enumerate(data))


def main() -> None:
    R = F.reproduce()
    header = R["header"]            # 31 bytes: +- + 28B + 7
    header28 = header[2:30]         # 28 bytes (o "header" sem +-/7)
    blocks = [R["blocks"][i * 32:(i + 1) * 32] for i in range(35)]
    body = R["blocks"]              # 1120 bytes
    half = R["half"]
    better_half = R["better_half"]
    tail = R["matrix_tail"]         # fc0c1b02
    seven = b"7"

    log = open(OUT, "w", encoding="utf-8")
    hard_hits = []
    soft_hits = []
    n_keys = 0
    n_aes = 0
    n_priv = 0
    top = []  # (ratio, label, head_hex)

    def note(label: str, **kw) -> None:
        log.write(json.dumps({"label": label, **kw}, ensure_ascii=False) + "\n")

    # ---------- materiais candidatos derivados do eps3.5 ----------
    EP_TITLES = [
        "eps3.5_kill-process.inc", "eps3.5kill-process.inc",
        "eps3.5_kill-pr0cess.inc", "eps3.5kill-pr0cess.inc",
        "Eps3.5_Kill-Process.Inc", "EPS3.5_KILL-PROCESS.INC",
        "kill-process", "killprocess", "kill process", "kill-pr0cess",
        "kill-process.inc", "killprocessinc", "kill_process", "kill-process-inc",
        "eps3.5", "eps35", "eps3_5",
        # "better half" do titulo (segunda metade):
        "process.inc", "process", ".inc", "inc",
        # 71 / 28 do episodio:
        "71", "seventyone", "71buildings", "28", "eps3.5_71",
        # Red Wheelbarrow (cena-chave do episodio):
        "RedWheelbarrow", "redwheelbarrow", "red wheelbarrow",
        # "rewatch episode 3.5 with the better half" literal / gramatica:
        "rewatchepisode3.5withthebetterhalf",
        "rewatchepisode35withthebetterhalf",
        "eps3.5withthebetterhalf", "episode3.5withthebetterhalf",
        # bingo + in front of your eyes (mesma conversa 2026-03-03):
        "itsinfrontofyoureyesbutyourenotseeingit",
        # combinacoes com better_half (literal "with the better half"):
        "eps3.5_kill-process.inc" + better_half.hex(),
        better_half.hex() + "eps3.5_kill-process.inc",
        "kill-process" + better_half.hex(),
        better_half.hex() + "kill-process",
        # fase-2 ja usava eps3.4; juntar 3.4+3.5:
        "eps3.4_runtime-err0r.r00eps3.5_kill-process.inc",
        "eps3.5_kill-processinceps3.4_runtime-err0r.r00",
    ]

    # conjuntos de materiais -> chaves AES/priv
    def key_forms(material: bytes):
        """Gera chaves de 32 bytes a partir do material."""
        yield "sha256", hashlib.sha256(material).digest()
        yield "dblsha256", hashlib.sha256(hashlib.sha256(material).digest()).digest()
        if len(material) == 32:
            yield "raw32", material
        if len(material) >= 32:
            yield "first32", material[:32]
            yield "last32", material[-32:]
        # sha256 do hex (gramatica HASHTHETEXT-like sobre o texto)
        if any(32 <= b < 127 for b in material):
            yield "sha256hexstr", hashlib.sha256(material).hexdigest().encode()

    # IVs naturais para CBC (stream inteiro de 1120 B e por-bloco de 32 B)
    ivs = {
        "zero": b"\x00" * 16,
        "header16": header28[:16],
        "header28lo": header28[12:28],
        "half16": half[:16],
        "half16hi": half[16:32],
        "bh16": better_half[:16],
        "bh16hi": better_half[16:32],
        "tailpad": (tail * 4)[:16],
        "sevenpad": (seven * 16)[:16],
        "pm7": b"+-" + header28[:12] + b"7",
        "sha7": hashlib.sha256(b"+-" + header28 + b"7").digest()[:16],
    }

    def test_aes(key: bytes, label: str) -> None:
        nonlocal n_aes, n_priv
        # 1) stream inteiro 1120 B como um AES-CBC
        for ivname, iv in ivs.items():
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            except ValueError:
                continue
            n_aes += 1
            ratio = printable_ratio(pt)
            if len(top) < 20:
                top.append((ratio, f"{label}/CBC-stream/{ivname}", pt[:32].hex()))
            elif ratio > min(t[0] for t in top):
                top.sort(reverse=True)
                top[-1] = (ratio, f"{label}/CBC-stream/{ivname}", pt[:32].hex())
            if valid_plaintext(pt) or b"Salted__" in pt or TARGET_PUBKEY in pt:
                soft_hits.append({"label": f"{label}/CBC-stream/{ivname}",
                                  "ratio": round(ratio, 4), "head": pt[:80].hex()})
                note("SOFT", label=f"{label}/CBC-stream/{ivname}", head=pt[:80].hex())
            # cada fatia de 32 B do plaintext como privkey
            for i in range(0, len(pt) - 31, 32):
                n_priv += 1
                if matches_pubkey(pt[i:i + 32]):
                    hard_hits.append({"label": f"{label}/CBC-stream/{ivname}",
                                      "slice": i, "priv": pt[i:i + 32].hex()})
        # 2) por-bloco: cada 32 B (2 AES blocks) independente
        for ivname, iv in ivs.items():
            plains = []
            for block in blocks:
                try:
                    plains.append(AES.new(key, AES.MODE_CBC, iv).decrypt(block))
                except ValueError:
                    plains.append(b"")
            n_aes += 35
            joined = b"".join(plains)
            ratio = printable_ratio(joined)
            if len(top) < 20:
                top.append((ratio, f"{label}/CBC-perblock/{ivname}", joined[:32].hex()))
            elif ratio > min(t[0] for t in top):
                top.sort(reverse=True)
                top[-1] = (ratio, f"{label}/CBC-perblock/{ivname}", joined[:32].hex())
            if valid_plaintext(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
                soft_hits.append({"label": f"{label}/CBC-perblock/{ivname}",
                                  "ratio": round(ratio, 4), "head": joined[:80].hex()})
                note("SOFT", label=f"{label}/CBC-perblock/{ivname}", head=joined[:80].hex())
            for i, plain in enumerate(plains):
                n_priv += 1
                if matches_pubkey(plain):
                    hard_hits.append({"label": f"{label}/CBC-perblock/{ivname}",
                                      "block": i, "priv": plain.hex()})
        # 3) ECB por-bloco
        plains = []
        for block in blocks:
            try:
                plains.append(AES.new(key, AES.MODE_ECB).decrypt(block))
            except ValueError:
                plains.append(b"")
        n_aes += 35
        joined = b"".join(plains)
        ratio = printable_ratio(joined)
        if len(top) < 20:
            top.append((ratio, f"{label}/ECB-perblock", joined[:32].hex()))
        elif ratio > min(t[0] for t in top):
            top.sort(reverse=True)
            top[-1] = (ratio, f"{label}/ECB-perblock", joined[:32].hex())
        if valid_plaintext(joined) or b"Salted__" in joined or TARGET_PUBKEY in joined:
            soft_hits.append({"label": f"{label}/ECB-perblock",
                              "ratio": round(ratio, 4), "head": joined[:80].hex()})
            note("SOFT", label=f"{label}/ECB-perblock", head=joined[:80].hex())
        for i, plain in enumerate(plains):
            n_priv += 1
            if matches_pubkey(plain):
                hard_hits.append({"label": f"{label}/ECB-perblock",
                                  "block": i, "priv": plain.hex()})

    # ---- caixa de chaves ----
    tested_keys = set()

    def emit(material: bytes, src: str) -> None:
        nonlocal n_keys, n_priv
        for kname, key in key_forms(material):
            if key in tested_keys:
                continue
            tested_keys.add(key)
            n_keys += 1
            n_priv += 1
            if matches_pubkey(key):
                hard_hits.append({"label": f"DIRECT/{src}/{kname}", "priv": key.hex()})
            test_aes(key, f"{src}/{kname}")

    # (A) strings do episodio
    for title in EP_TITLES:
        emit(title.encode(), f"title:{title[:28]}")

    # (B) "with the better half" = combinar material com better_half (32B)
    for title in ("eps3.5_kill-process.inc", "eps3.5kill-process.inc",
                  "eps3.5_kill-pr0cess.inc", "kill-process", "killprocess",
                  "process.inc", "process", "rewatchepisode3.5withthebetterhalf"):
        tb = title.encode()
        emit(tb + better_half, f"t+bh:{title[:20]}")
        emit(better_half + tb, f"bh+t:{title[:20]}")
        emit(hashlib.sha256(tb).digest() + better_half, f"sha(t)+bh:{title[:18]}")
        emit(better_half + hashlib.sha256(tb).digest(), f"bh+sha(t):{title[:18]}")
        # XOR ciclico do titulo com better_half (gera material de 32 B)
        emit(xor_cycle((tb * 32)[:32], better_half), f"t^bh:{title[:20]}")
        # better_half como CHAVE e titulo->IV
        emit(better_half, f"bh-key:{title[:18]}")

    # (C) "kill-process" = ZERO OUT (matar) o header28; chave = resto (+-7+blocos)
    #    leitura: o processo (header) e morto; o que sobra vira chave.
    emit(b"+-" + b"7", "kill-header:+-7")
    emit(b"+-7" + body[:32], "kill-header:+-7+block0")
    emit(hashlib.sha256(b"+-7").digest(), "kill-header:sha(+-7)")
    emit(hashlib.sha256(body[:32]).digest(), "kill-header:sha(block0)")
    # zerar (kill) o header28 mantendo a estrutura: +-\0...\0 7
    emit(b"+-" + b"\x00" * 28 + b"7", "kill-header:zero28+7")
    emit(hashlib.sha256(b"+-" + b"\x00" * 28 + b"7").digest(), "kill-header:sha(zero28+7)")
    # kill = remover; usar so o bloco cujo indice = processo morto
    for i in range(35):
        emit(hashlib.sha256(b"kill" + blocks[i]).digest(), f"kill-block{i}")

    # (D) 28o episodio = 28 bytes do header como CHAVE direta (ja 28B -> nao 32)
    #    completar para 32 de varias formas
    emit(header28 + b"\x00\x00\x00\x00", "ep28:header28+pad4")
    emit(header28 + tail, "ep28:header28+tail")
    emit(header28 + b"7\x00\x00\x00", "ep28:header28+7pad3")
    emit(hashlib.sha256(header28).digest(), "ep28:sha(header28)")

    # (E) 71 prédios -> 71 como escalar / offset / chave
    emit((71).to_bytes(32, "big"), "ep71:int71")
    emit(hashlib.sha256(b"71").digest(), "ep71:sha('71')")
    # bloco de indice 71? so 35 -> 71%35=1
    emit(blocks[71 % 35], "ep71:block71mod35")
    emit(hashlib.sha256(blocks[71 % 35]).digest(), "ep71:sha(block71mod35)")

    log.close()

    top.sort(reverse=True)
    print("=== eps3.5 attack (hint criador 2026-03-03) ===")
    print(f"chaves unicas: {n_keys} | testes AES: {n_aes} | testes privkey: {n_priv}")
    print(f"HARD hits (pubkey): {len(hard_hits)}")
    print(f"SOFT hits (padding/ascii/Salted): {len(soft_hits)}")
    if hard_hits:
        print("!!! SOLVE !!!")
        for h in hard_hits:
            print(" ", h)
    if soft_hits:
        print("--- soft (investigar) ---")
        for h in soft_hits:
            print(" ", h)
    print("--- top printabilidade ---")
    for ratio, label, head in top[:8]:
        print(f"  {ratio:.3f}  {label}  {head}")


if __name__ == "__main__":
    main()
