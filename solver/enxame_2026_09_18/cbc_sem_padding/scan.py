# -*- coding: utf-8 -*-
"""Frente de teste "cbc_sem_padding" da campanha enxame_2026-09-18.

Fecha a lacuna ENDGAME §3.13 / limites do multiagente ("CBC sem padding") em duas partes,
todas com oráculo duro (AGENTS.md regra 1: candidato != solução) e KDF SHA256 primário + MD5:

  A) I4 do Codex: os 7 operandos públicos → 7! = 5.040 concatenações × {raw, sha256hex} =
     10.080 senhas (manifesto c484239757d5aec47479ed18698a9ee7531ace61229f86e8ebf2fa017162b311).
     SMALL e TAIL32 decifrados SEM unpad (EVP-SHA256 e EVP-MD5); as 49 janelas raw32 BE e LE de
     cada plaintext contra os DOIS alvos (h160 comprimido e não comprimido); hex64/WIF/semantic.

  B) COSMIC (1.328 B = 83 blocos) com oráculo por bloco sem PKCS7, sobre o corpus histórico
     (466.310 senhas-base → 1.272.149 formas raw/sha256hex/SHA256HEX) × {SHA256, MD5}.
     Por decisão: D = AES-ECB-decrypt(CT); P = D XOR (iv || CT[:-16]); conta blocos ASCII limpos
     ({9,10,13} ∪ [32,126]) e blocos cp273 limpos. Sinal se ≥ 2 blocos limpos (ASCII ou cp273),
     cabeçalho Salted__/U2FsdGVk no início de um bloco, ou G.semantic(P). Cada sinal: plaintext
     em hex, reprodução com openssl -nopad, raw32 BE/LE contra os dois alvos.

O falso negativo foi reproduzido antes de rodar (repro_gap.py / repro no RELATORIO): o unpad
estrito de G.try_password_all descarta um plaintext -nopad com uma privkey embutida (0 registros),
enquanto a varredura raw32 sem unpad a encontra. ct_blockscan_oracle.py cobria só SMALL/TAIL32.

Windows: Pool exige if __name__ == "__main__". WORKERS = 4 (outras frentes rodam junto).
"""
import sys, os, re, json, time, math, hashlib, pickle, subprocess, itertools
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
KIT = os.path.join(REPO, "solver", "experiments", "claude_endgame_2026_09_02")
sys.path.insert(0, KIT)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as _SHA256, MD5 as _MD5
from coincurve import PublicKey
try:
    import numpy as np
except Exception as e:  # numpy é dependência do ambiente Python312
    raise SystemExit("numpy ausente: " + str(e))

OUT = os.path.join(REPO, "_work", "enxame_2026-09-18", "cbc_sem_padding")
os.makedirs(OUT, exist_ok=True)
OPENSSL = r"C:\Program Files\Git\usr\bin\openssl.exe"
WORKERS = 4

KDFS = (("sha256", _SHA256, hashlib.sha256), ("md5", _MD5, hashlib.md5))
# conjuntos de bytes "limpos"
ASCII_CLEAN = sorted({9, 10, 13} | set(range(32, 127)))                       # 98 bytes
EBC_CLEAN = sorted({bytes([a]).decode("cp273").encode("latin-1")[0] for a in ASCII_CLEAN})  # 98 bytes
NESTED_HEADS = (b"Salted__", b"U2FsdGVk")


# ---------------------------------------------------------------- oráculo duro raw32 (BE e LE)
def scan_raw32(buf, where, h160s):
    """Varre toda janela de 32 B de `buf`, nas orientações BE e LE, contra os h160 alvo (comp e
    uncomp). Confirma cada hit com o oráculo duro G.priv_hit (check_privkey). Lista de dicts."""
    hits = []
    n = len(buf)
    for j in range(0, n - 31):
        w = buf[j:j + 32]
        for orient, sec in (("BE", w), ("LE", w[::-1])):
            try:
                pk = PublicKey.from_valid_secret(sec)
            except Exception:
                continue
            if any(G._h160_hex(pk.format(c)) in h160s for c in (True, False)):
                conf = G.priv_hit(sec)  # oráculo duro (ecdsa independente)
                hits.append({"where": where, "off": j, "orient": orient,
                             "priv": sec.hex(), "confirm": conf})
    return hits


def semantic_extra(p, h160s):
    """Candidatos semânticos de um plaintext sem unpad: nested blob, printable, ebcdic, hex64/WIF.
    Reaproveita G.semantic (kit) e registra hex64/WIF resolvidos pelo oráculo duro."""
    rec = {}
    if G.semantic(p):
        rec["semantic"] = True
        rec["printable"] = round(G.printable(p), 3)
        rec["nested"] = G.nested_blob(p)
        rec["ebcdic_sig"] = round(G.ebcdic_sig(p), 3)
        t = p.decode("latin-1")
        h64 = G.hex64_candidates(t)
        wif = G.wif_candidates(t)
        if h64:
            rec["hex64"] = [{"h": h, "confirm": G.priv_hit(bytes.fromhex(h))} for h in h64]
        if wif:
            import base58
            rec["wif"] = []
            for w in wif:
                try:
                    raw = base58.b58decode_check(w)
                    rec["wif"].append({"w": w, "confirm": G.priv_hit(raw[1:33])})
                except Exception:
                    pass
    return rec


# ================================================================ PARTE A: SMALL + TAIL32 (I4)
OPERANDS_MANIFEST = "c484239757d5aec47479ed18698a9ee7531ace61229f86e8ebf2fa017162b311"


def operandos():
    readme = open(os.path.join(REPO, "README.md"), encoding="utf-8").read()
    p3 = re.search(r"SHA256\((causalitySafenet.+?)\) = ([0-9a-f]{64})", readme)
    p32 = re.search(r"SHA256\((jacquefresco.+?)\) = ([0-9a-f]{64})", readme)
    assert hashlib.sha256(p3[1].encode()).hexdigest() == p3[2], "pré-imagem fase 3 não confere"
    assert hashlib.sha256(p32[1].encode()).hexdigest() == p32[2], "pré-imagem fase 3.2 não confere"
    return ["theflowerblossomsthroughwhatseemstobeaconcretesurface", "causality",
            p3[1], p32[1], "THEMATRIXHASYOU", "gsmg.io/theseedisplanted",
            "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"]


def senhas_parteA():
    ops = operandos()
    mat = {"".join(p).encode() for p in itertools.permutations(ops)}
    pws = mat | {hashlib.sha256(m).hexdigest().encode() for m in mat}
    man = hashlib.sha256(b"".join(len(p).to_bytes(4, "big") + p for p in sorted(pws))).hexdigest()
    assert man == OPERANDS_MANIFEST, ("manifesto", man)
    return list(pws), {"lens": [len(o) for o in ops], "materiais": len(mat),
                       "senhas": len(pws), "manifesto": man}


def _a_um(pw):
    # G.TARGET_H160S é global do kit, presente em cada worker (spawn re-importa o módulo).
    h160s = G.TARGET_H160S
    out = {"paddings": 0, "candidatos": []}
    for kn, hm, _ in KDFS:
        for blob in ("SMALL", "TAIL32"):
            salt, ct = G.BLOBS[blob]
            k, iv = G.evp(pw, salt, hm)
            P = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)        # SEM unpad
            if G.unpad(P) is not None:
                out["paddings"] += 1                            # registra padding (regra 5)
                out.setdefault("pad_rec", []).append({"pw": pw.decode("latin-1"), "kdf": kn,
                                                       "blob": blob, "hex": P.hex()})
            raw = scan_raw32(P, f"{blob}/{kn}", h160s)
            sem = semantic_extra(P, h160s)
            if raw or sem:
                out["candidatos"].append({"pw": pw.decode("latin-1"), "kdf": kn, "blob": blob,
                                          "hex": P.hex(), "raw32": raw, **sem})
    return out


def parte_A():
    pws, meta = senhas_parteA()
    t0 = time.time()
    paddings, candidatos, pad_recs = 0, [], []
    with Pool(WORKERS) as pool:
        for r in pool.imap_unordered(_a_um, pws, chunksize=64):
            paddings += r["paddings"]
            candidatos += r["candidatos"]
            pad_recs += r.get("pad_rec", [])
    n_aes = len(pws) * len(KDFS) * 2
    n_win = n_aes * (80 - 32 + 1) * 2  # 49 janelas × BE/LE
    esperado = n_aes * sum(256.0 ** -j for j in range(1, 17))
    if pad_recs:
        with open(os.path.join(OUT, "parteA_paddings.jsonl"), "w", encoding="utf-8") as f:
            for r in pad_recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return {"parte": "A_SMALL_TAIL32_I4", **meta, "aes": n_aes, "raw32_janelas": n_win,
            "paddings": paddings, "paddings_esperados": round(esperado, 2),
            "candidatos": candidatos, "segundos": round(time.time() - t0, 1)}


# ================================================================ PARTE B: COSMIC por bloco
COSMIC_SALT, COSMIC_CT = G.BLOBS["COSMIC"]
COSMIC_N = len(COSMIC_CT)                                  # 1328
COSMIC_NB = COSMIC_N // 16                                 # 83
COSMIC_PREV_TAIL = COSMIC_CT[:-16]                         # bytes 0..N-16 (para P_i, i>=1)
_LUT_ASCII = np.zeros(256, bool); _LUT_ASCII[ASCII_CLEAN] = True
_LUT_EBC = np.zeros(256, bool); _LUT_EBC[EBC_CLEAN] = True
_LUT_ASCII_PRINT = np.zeros(256, bool); _LUT_ASCII_PRINT[list(range(32, 127))] = True
# LUTs para vetorizar as demais condições de G.semantic (ebcdic_sig, hex64, WIF)
_LUT_AZ = np.zeros(256, bool); _LUT_AZ[list(G._EBCDIC_AZ)] = True          # cp273 a–z (17 valores)
_LUT_HEX = np.zeros(256, bool); _LUT_HEX[[ord(c) for c in "0123456789abcdefABCDEF"]] = True
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"           # WIF: [5KL]+50-51 base58
_LUT_B58 = np.zeros(256, bool); _LUT_B58[[ord(c) for c in _B58]] = True
_PREV_TAIL_ARR = np.frombuffer(COSMIC_PREV_TAIL, dtype=np.uint8)  # (N-16,)


def _tem_run(mask, w):
    """True por linha se existe uma janela de comprimento `w` inteiramente True (cumsum vetorizado)."""
    c = np.zeros((mask.shape[0], mask.shape[1] + 1), np.int32)
    np.cumsum(mask, axis=1, out=c[:, 1:])
    win = c[:, w:] - c[:, :mask.shape[1] - w + 1]
    return (win == w).any(axis=1)


def _cosmic_decisions(forms):
    """Decifra o COSMIC para cada forma × {SHA256, MD5}. Devolve arrays D (n,1328) e a lista
    paralela de (forma, kdf) para reconstruir sinais."""
    D = np.empty((len(forms) * 2, COSMIC_N), dtype=np.uint8)
    meta = []
    i = 0
    for form in forms:
        for kn, hm, _ in KDFS:
            k, iv = G.evp(form, COSMIC_SALT, hm)
            d = AES.new(k, AES.MODE_ECB).decrypt(COSMIC_CT)
            D[i] = np.frombuffer(d, dtype=np.uint8)
            # P = D XOR (iv || CT[:-16]); guarda iv nos 16 primeiros p/ o XOR vetorizado
            D[i, :16] ^= np.frombuffer(iv, dtype=np.uint8)
            meta.append((form, kn))
            i += 1
    # XOR do restante com CT[:-16] (fixo) — os 16 primeiros já receberam iv acima
    D[:, 16:] ^= _PREV_TAIL_ARR[np.newaxis, :]
    return D, meta  # D agora é P (plaintext sem unpad)


def _cosmic_signals(P, meta):
    """Vetoriza os sinais por decisão. Devolve índices sinalizados + histogramas."""
    n = P.shape[0]
    blk = P.reshape(n, COSMIC_NB, 16)
    ascii_ok = _LUT_ASCII[blk].all(axis=2)      # (n, 83) bool
    ebc_ok = _LUT_EBC[blk].all(axis=2)
    n_ascii = ascii_ok.sum(axis=1)
    n_ebc = ebc_ok.sum(axis=1)
    printable = _LUT_ASCII_PRINT[P].mean(axis=1)  # fração 32..126 (para G.semantic printable>=0.85)
    # cabeçalho aninhado no início de qualquer bloco
    head8 = blk[:, :, :8]
    nested = np.zeros(n, bool)
    for h in NESTED_HEADS:
        harr = np.frombuffer(h, dtype=np.uint8)
        nested |= (head8 == harr).all(axis=2).any(axis=1)
    # ebcdic_sig >= 0,75 (G.semantic): fração dos bytes >= 0x80 que caem na imagem cp273 de a–z
    hi = P >= 0x80
    hic = hi.sum(axis=1)
    azc = (_LUT_AZ[P] & hi).sum(axis=1)
    with np.errstate(invalid="ignore", divide="ignore"):
        ebc_sig = np.where(hic >= 8, azc / np.maximum(hic, 1), 0.0)
    # hex64 / WIF (G.semantic): pré-filtro por run vetorizado; confirmação exata em _b_lote
    hexrun = _tem_run(_LUT_HEX[P], 64)
    wifrun = _tem_run(_LUT_B58[P], 51)
    sig = ((n_ascii >= 2) | (n_ebc >= 2) | nested | (printable >= 0.85)
           | (ebc_sig >= 0.75) | hexrun | wifrun)
    hist_a = np.bincount(n_ascii, minlength=3)
    hist_e = np.bincount(n_ebc, minlength=3)
    return sig, n_ascii, n_ebc, nested, printable, hist_a, hist_e


def _b_lote(forms):
    h160s = G.TARGET_H160S  # global do kit, presente em cada worker (spawn re-importa o módulo)
    P, meta = _cosmic_decisions(forms)
    sig, n_a, n_e, nested, pr, hist_a, hist_e = _cosmic_signals(P, meta)
    sinais = []
    for idx in np.nonzero(sig)[0]:
        p = P[idx].tobytes()
        form, kn = meta[idx]
        rec = {"forma": form.decode("latin-1")[:80], "kdf": kn,
               "n_ascii": int(n_a[idx]), "n_ebc": int(n_e[idx]),
               "nested": bool(nested[idx]), "printable": round(float(pr[idx]), 3),
               "hex": p.hex()}
        rec["semantic"] = semantic_extra(p, h160s)
        rec["raw32"] = scan_raw32(p, f"COSMIC/{kn}", h160s)
        sinais.append(rec)
    # histograma até índice 8 para reconciliação
    return (np.pad(hist_a, (0, max(0, 9 - len(hist_a))))[:9],
            np.pad(hist_e, (0, max(0, 9 - len(hist_e))))[:9],
            len(meta), sinais)


def make_forms(pws):
    """raw, sha256hex, SHA256HEX com dedup (idêntico a ct_blockscan_oracle.make_forms)."""
    seen, out = set(), []
    for pw in pws:
        hx = hashlib.sha256(pw).hexdigest()
        for f in (pw, hx.encode(), hx.upper().encode()):
            if f not in seen:
                seen.add(f); out.append(f)
    return out


def _chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def parte_B(corpus_pkl, workers=WORKERS, lote=4000):
    d = pickle.load(open(corpus_pkl, "rb"))
    n_base = len(d["pws"])
    forms = make_forms(d["pws"])
    t0 = time.time()
    hist_a = np.zeros(9, np.int64); hist_e = np.zeros(9, np.int64)
    total = 0; sinais = []
    jobs = list(_chunks(forms, lote))
    with Pool(workers) as pool:
        for ha, he, nm, sg in pool.imap_unordered(_b_lote, jobs):
            hist_a += ha; hist_e += he; total += nm; sinais += sg
            for s in sg:
                G.jsonl(os.path.join(OUT, "parteB_sinais.jsonl"), s)
    if sinais:
        for s in sinais:
            _repro_openssl(s)
    esperado_1 = total * COSMIC_NB * (98 / 256) ** 16
    return {"parte": "B_COSMIC_bloco", "corpus_pkl_sha256": _sha_arquivo(corpus_pkl),
            "n_base": n_base, "formas": len(forms), "kdf": ["sha256", "md5"],
            "decisoes": total, "hist_n_ascii": hist_a.tolist(), "hist_n_ebc": hist_e.tolist(),
            "esperado_1bloco_limpo": round(esperado_1, 2), "sinais": len(sinais),
            "sinais_detalhe": sinais, "segundos": round(time.time() - t0, 1)}


# ---------------------------------------------------------------- reprodução openssl -nopad
def _repro_openssl(sinal):
    """Reproduz um sinal com o openssl CLI (-nopad) e compara byte a byte com o Python."""
    if not os.path.exists(OPENSSL):
        sinal["openssl"] = "ausente"; return
    kn = sinal["kdf"]
    salt_hex = COSMIC_SALT.hex()
    blob = b"Salted__" + COSMIC_SALT + COSMIC_CT
    form = sinal["forma"].encode("latin-1")
    p = subprocess.run([OPENSSL, "enc", "-aes-256-cbc", "-d", "-nopad", "-md", kn,
                        "-pass", "pass:" + sinal["forma"]], input=blob,
                       capture_output=True)
    sinal["openssl"] = {"rc": p.returncode, "igual_python": p.stdout.hex() == sinal["hex"]}


def _sha_arquivo(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ================================================================ controles e nulo
def controles():
    """Controles (a)-(h) do plano do gate, na mesma função de varredura."""
    r = {}
    # controle positivo do kit (fase 2 abre por SHA256, não por MD5)
    kit = subprocess.run([sys.executable, os.path.join(KIT, "gsmg_common.py")],
                         capture_output=True, text=True, timeout=120)
    r["kit_selftest_ok"] = kit.returncode == 0 and "gsmg_common OK" in kit.stdout

    # chave-alvo sintética plantada
    sec = hashlib.sha256(b"cbc-sem-padding-controle").digest()
    pk = PublicKey.from_valid_secret(sec)
    h160s = tuple(G._h160_hex(pk.format(c)) for c in (True, False))
    planted = G.TARGET_H160S + h160s

    def _enc_nopad(data, kn, passwd):
        """Cifra com o openssl CLI (-nopad, sem -S: emite Salted__+salt+ct como o blob real)."""
        p = subprocess.run([OPENSSL, "enc", "-aes-256-cbc", "-nopad", "-md", kn,
                            "-pass", "pass:" + passwd], input=data, capture_output=True)
        assert p.returncode == 0 and p.stdout[:8] == b"Salted__", p.stderr[:200]
        return p.stdout[8:16], p.stdout[16:]      # (salt, ct)

    def _bloco_p(ct, salt, passwd, hm):
        k, iv = G.evp(passwd.encode(), salt, hm)
        Pn = np.frombuffer(AES.new(k, AES.MODE_ECB).decrypt(ct), np.uint8).copy()
        Pn[:16] ^= np.frombuffer(iv, np.uint8)
        Pn[16:] ^= np.frombuffer(ct[:-16], np.uint8)
        return Pn

    if os.path.exists(OPENSSL):
        # (a) texto ASCII de 1.328 B, -nopad, sha256 e md5 -> n_ascii == 83
        txt = (b"COSMIC DUALITY CONTROL " * 60)[:COSMIC_N]
        for kn, hm, _ in KDFS:
            salt, ct = _enc_nopad(txt, kn, "ctl-a")
            Pn = _bloco_p(ct, salt, "ctl-a", hm)
            r[f"a_ascii_nopad_{kn}"] = int(_LUT_ASCII[Pn.reshape(-1, 16)].all(axis=1).sum())
        # (b) 1.320 B texto + 8 zeros (padding zero) -> n_ascii >= 82
        salt, ct = _enc_nopad(b"A" * 1320 + b"\x00" * 8, "sha256", "ctl-b")
        Pn = _bloco_p(ct, salt, "ctl-b", _SHA256)
        r["b_padding_zero_nascii"] = int(_LUT_ASCII[Pn.reshape(-1, 16)].all(axis=1).sum())

    # (e) plaintext = blob Salted__ binário de 1.328 B (nested) detectado pelo cabeçalho
    nested_pt = b"Salted__" + os.urandom(COSMIC_N - 8)
    blk = np.frombuffer(nested_pt, np.uint8).reshape(-1, 16)
    r["e_nested_header"] = bool((blk[:, :8] == np.frombuffer(b"Salted__", np.uint8)).all(axis=1).any())

    # (f) segmento cp273 autêntico da fase 3.2 -> n_ebc >= 2.
    # A visão da fase é Y = ASCII.decode(cp273).encode(latin-1); o plaintext AES contém Y.
    X = b"IN CASE YOU MANAGE TO CRACK THIS!"[:32]  # 32 B ASCII limpos = 2 blocos
    Y = X.decode("cp273").encode("latin-1")
    blk = np.frombuffer(Y, np.uint8).reshape(-1, 16)
    r["f_cp273_nebc"] = int(_LUT_EBC[blk].all(axis=1).sum())

    # (g) blob real da fase 2 abre por sha256hex('causality') e dá blocos limpos pelo mesmo código
    raw2 = __import__("base64").b64decode(G.PHASE2_B64)
    s2, c2 = raw2[8:16], raw2[16:]
    k, iv = G.evp(G.shahex("causality").encode(), s2, _SHA256)
    Pn = np.frombuffer(AES.new(k, AES.MODE_ECB).decrypt(c2), np.uint8).copy()
    Pn[:16] ^= np.frombuffer(iv, np.uint8); Pn[16:] ^= np.frombuffer(c2[:-16], np.uint8)
    r["g_fase2_nascii"] = int(_LUT_ASCII[Pn.reshape(-1, 16)].all(axis=1).sum())
    r["g_fase2_head"] = AES.new(k, AES.MODE_CBC, iv).decrypt(c2)[:10].decode("latin-1")

    # (h) senha errada -> n_ascii <= 1 no COSMIC
    k, iv = G.evp(b"senha-errada-xyz", COSMIC_SALT, _SHA256)
    Pn = np.frombuffer(AES.new(k, AES.MODE_ECB).decrypt(COSMIC_CT), np.uint8).copy()
    Pn[:16] ^= np.frombuffer(iv, np.uint8); Pn[16:] ^= _PREV_TAIL_ARR
    r["h_senha_errada_nascii"] = int(_LUT_ASCII[Pn.reshape(-1, 16)].all(axis=1).sum())

    # controle raw32: privkey plantada em 80 B -nopad é recuperada; sem plantar, nada
    if os.path.exists(OPENSSL):
        fixture = b"\xff" * 17 + sec + b"\xff" * 31
        assert len(fixture) == 80 and G.unpad(fixture) is None
        salt, ct = _enc_nopad(fixture, "sha256", "ctl-raw")
        k, iv = G.evp(b"ctl-raw", salt, _SHA256)
        P = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
        assert P == fixture, "openssl/python divergem no controle raw32"
        r["raw32_sem_plantar"] = len(scan_raw32(P, "ctl", G.TARGET_H160S))
        r["raw32_plantado"] = [h["orient"] + "@" + str(h["off"]) for h in scan_raw32(P, "ctl", planted)]
        r["raw32_unpad_rejeita"] = G.unpad(P) is None
    return r


def nulo(n=100000, workers=WORKERS, seed=99):
    """Nulo aleatório: n senhas de 12 B × 3 formas × 2 KDF no COSMIC; histograma de blocos limpos
    contra a taxa analítica (98/256)^16 por bloco."""
    import random
    rng = random.Random(seed)
    pws = [rng.randbytes(12) for _ in range(n)]
    forms = make_forms(pws)
    t0 = time.time()
    hist_a = np.zeros(9, np.int64); hist_e = np.zeros(9, np.int64); total = 0; ge2 = 0
    with Pool(workers) as pool:
        for ha, he, nm, sg in pool.imap_unordered(_b_lote, list(_chunks(forms, 4000))):
            hist_a += ha; hist_e += he; total += nm; ge2 += len(sg)
    return {"n_senhas": len(pws), "formas": len(forms), "decisoes": total,
            "hist_n_ascii": hist_a.tolist(), "hist_n_ebc": hist_e.tolist(),
            "sinais": ge2, "p_bloco_limpo_teorico": (98 / 256) ** 16,
            "esperado_1bloco": round(total * COSMIC_NB * (98 / 256) ** 16, 2),
            "segundos": round(time.time() - t0, 1)}


if __name__ == "__main__":
    CORPUS = os.path.join(OUT, "corpus.pkl")
    t0 = time.time()
    print("== controles ==", flush=True)
    ctl = controles()
    print(json.dumps(ctl, ensure_ascii=False), flush=True)
    ok = (ctl.get("kit_selftest_ok") and ctl.get("g_fase2_head", "").startswith("The ironic")
          and ctl.get("h_senha_errada_nascii", 9) <= 1
          and ctl.get("raw32_sem_plantar", 9) == 0 and ctl.get("raw32_plantado")
          and ctl.get("raw32_unpad_rejeita"))
    assert ok, ("controles falharam", ctl)

    print("== nulo ==", flush=True)
    nul = nulo()
    print(json.dumps(nul, ensure_ascii=False), flush=True)

    print("== parte A (SMALL + TAIL32, I4) ==", flush=True)
    rA = parte_A()
    print(json.dumps({k: v for k, v in rA.items() if k != "candidatos"}, ensure_ascii=False),
          "candidatos:", len(rA["candidatos"]), flush=True)

    print("== parte B (COSMIC por bloco) ==", flush=True)
    rB = parte_B(CORPUS)
    print(json.dumps({k: v for k, v in rB.items() if k != "sinais_detalhe"}, ensure_ascii=False),
          flush=True)

    kit = G.commit_do_kit() if hasattr(G, "commit_do_kit") else {}
    if not kit:
        kh = hashlib.sha256(open(os.path.join(KIT, "gsmg_common.py"), "rb").read()).hexdigest()
        c = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True)
        kit = {"commit": c.stdout.strip(), "kit_sha256": kh}

    summary = {"frente": "cbc_sem_padding", "controles": ctl, "nulo": nul,
               "parteA": rA, "parteB": {k: v for k, v in rB.items() if k != "sinais_detalhe"},
               "parteB_sinais": rB["sinais_detalhe"], "kit": kit,
               "segundos_total": round(time.time() - t0, 1)}
    json.dump(summary, open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    json.dump(ctl, open(os.path.join(OUT, "controls.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("OK total", summary["segundos_total"], "s; candidatos A/B =",
          len(rA["candidatos"]), "/", rB["sinais"], flush=True)
