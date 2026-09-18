# -*- coding: utf-8 -*-
r"""
CRITICO da familia "codecs_23" (familia4_codecs.py) — braco que o agente declarou ter deixado de fora.

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O agente esgotou os 65 codecs de BYTE UNICO como fonte de senha (token codificado em C, cru ou
sha256) e mostrou que sobre [a-z0-9] eles colapsam em 2 imagens (ASCII e uma unica EBCDIC). Os
codecs MULTI-BYTE nao colapsam: um token ASCII tem 7 imagens distintas em UTF-16 (BOM+LE, LE, BE),
UTF-32 (BOM+LE, LE, BE) e UTF-8 com BOM. E o cenario "Notepad salva como Unicode" / pipe do
PowerShell: `openssl enc -pass file:senha.txt` ou `sha256sum senha.txt` sobre um arquivo UTF-16
produzem bytes que nenhuma forma ASCII alcanca. A campanha Unicode (ENDGAME §4.C) so aplicou
essas codificacoes a strings com o simbolo ☯ e a concatenacoes com ele — nunca aos tokens ASCII
puros do roadmap nem as suas permutacoes.

Falsa se, para as MESMAS bases do agente (tokens do roadmap, conhecidos, dbbi/faed/residuos,
permutacoes de 2, 3 e 7 tokens do roadmap, nomes de codec multi-byte compostos com o roadmap)
e para as 7 imagens multi-byte, nenhuma das 5 formas (bytes crus; sha256hex dos bytes; digest cru;
hex de sha256(ascii) re-codificado; sha256hex disso) abre SMALL/COSMIC/TAIL32 sob EVP-MD5/SHA256
com plaintext que passe no oraculo duro (G.semantic / G.nested_blob / privkey em toda janela de
32 B nas duas ordens de byte).

Alem disso, o script RE-VARRE todos os plaintexts com padding valido gravados no log do agente
(campo `hex`) com o oraculo completo, nas duas ordens de byte.

CONTROLE POSITIVO: (1) fase 2 abre com sha256hex("causality") sob EVP-SHA256; (2) controle
PLANTADO da familia: um blob cifrado aqui com senha = "yellowblueprimes" em UTF-16LE tem de ser
recuperado pelo MESMO pipeline (falha a execucao se nao for).
NULO CASADO: 100 lotes de 3.000 senhas aleatorias com a mesma forma (hex64 / bytes crus de mesmo
comprimento), mesmo pipeline; padding observado vs 1/256 e z por sub-familia.

Uso: python critico_codecs23.py
"""
import sys, os, json, time, random, hashlib, itertools, base64
from collections import Counter

ROOT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(ROOT, r"solver\experiments\claude_endgame_2026_09_02"))
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from coincurve import PublicKey
import base58

OUT = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\critico_codecs23")
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, "critico_codecs23.jsonl"), "w", encoding="utf-8")
LOG_AGENTE = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\familia4_codecs\familia4_codecs.jsonl")
def log(**kw):
    LOG.write(json.dumps(kw, ensure_ascii=False) + "\n"); LOG.flush()
def say(*a):
    print(*a, flush=True)

RNG = random.Random(23)
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
# ponytail: --rapido = sem as 5.040 permutacoes de 7 tokens (road7), nulo de 20 lotes e sem re-varredura
# (a re-varredura completa foi executada a parte com o mesmo oraculo; ver relatorio do critico)
RAPIDO = "--rapido" in sys.argv

def priv_ok(sec):
    try:
        return PublicKey.from_valid_secret(sec).format(False) == TGT
    except Exception:
        return False

def oraculo_duro(p, tag):
    """Oraculo completo sobre um plaintext AES: semantico, blob aninhado, privkey em toda
    janela de 32 B nas DUAS ordens, hex64/WIF embutidos como privkey."""
    hits = []
    if G.semantic(p): hits.append("semantic")
    if G.nested_blob(p): hits.append("nested")
    for ordem, buf in (("fwd", p), ("rev", p[::-1])):
        for j in range(0, len(buf) - 31):
            if priv_ok(buf[j:j + 32]): hits.append(f"priv/{ordem}@{j}")
    t = p.decode("latin-1")
    for h in G.hex64_candidates(t):
        if priv_ok(bytes.fromhex(h)): hits.append("hex64priv")
    for w in G.wif_candidates(t):
        try:
            if priv_ok(base58.b58decode_check(w)[1:33]): hits.append("wifpriv")
        except Exception:
            pass
    return hits

# --------------------------------------------------------------- controles
def controles():
    raw2 = base64.b64decode(G.PHASE2_B64)
    k2, iv2 = G.evp(G.shahex("causality").encode(), raw2[8:16], SHA256)
    p2 = G.unpad(AES.new(k2, AES.MODE_CBC, iv2).decrypt(raw2[16:]))
    assert p2 and p2.startswith(b"The ironic"), "controle de KDF (fase 2 / causality) falhou"
    # controle plantado da familia: blob cifrado com senha UTF-16LE de um token do roadmap
    pw = "yellowblueprimes".encode("utf-16-le")
    salt = b"\x13\x37\xc0\xff\xee\x00\x42\x23"
    k, iv = G.evp(pw, salt, SHA256)
    msg = b"controle plantado: se este texto nao for recuperado, o pipeline esta quebrado"
    pad = 16 - len(msg) % 16
    ct = AES.new(k, AES.MODE_CBC, iv).encrypt(msg + bytes([pad]) * pad)
    G.BLOBS["CTL"] = (salt, ct)
    say("[CTL] KDF fase2/causality OK; blob plantado (UTF-16LE) registrado como G.BLOBS['CTL']")
    log(arm="CTL", kdf="fase2/causality/EVP-SHA256 OK", plantado="yellowblueprimes@utf-16-le")

# --------------------------------------------------------------- corpus
ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit",
           "verylaststepisatruegiveawaypromised"]
CONHECIDOS = ["causality", "thispassword", "sha256", "enter", "theseedisplanted",
              "thematrixhasyou", "followthewhiterabbit", "salphaseion", "cosmicduality",
              "our first hint is your last command", "ans too", "shabef",
              "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
              "twentythreeciphers", "sixteenencryptions", "seven intertwined passwords",
              "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",
              "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
              "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
              "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"]
RESID_L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
RESID_L83 = RESID_L84[:-1]
NOMES_MB = ["utf-16", "utf16", "UTF-16", "utf-16le", "utf-16be", "UTF-16LE", "UTF-16BE", "unicode",
            "Unicode", "UNICODE", "ucs-2", "ucs2", "UCS-2", "utf-32", "utf32", "UTF-32", "utf-8", "utf8",
            "UTF-8", "wchar", "widechar", "notepad"]
MB = ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be", "utf-8-sig"]

def corpus():
    bases = [("token", t) for t in ROADMAP + CONHECIDOS]
    bases += [("campo", s) for s in (G.DBBI, G.FAED, RESID_L84, RESID_L83)]
    bases += [("road2", a + b) for a, b in itertools.permutations(ROADMAP, 2)]
    bases += [("road3", "".join(p)) for p in itertools.permutations(ROADMAP, 3)]
    if not RAPIDO:
        bases += [("road7", "".join(p)) for p in itertools.permutations(ROADMAP)]
    bases += [("nome", n) for n in NOMES_MB]
    bases += [("nome+road", n + t) for n in NOMES_MB for t in ROADMAP]
    bases += [("road+nome", t + n) for n in NOMES_MB for t in ROADMAP]
    vistos, saida = set(), []
    def add(sub, pw):
        if pw in vistos: return
        vistos.add(pw); saida.append((sub, pw))
    for sub, s in bases:
        sb = s.encode("ascii")
        hx = hashlib.sha256(sb).hexdigest()
        for c in MB:
            eb = s.encode(c)
            add(f"{sub}/mb_raw/{c}", eb)
            add(f"{sub}/mb_sha/{c}", hashlib.sha256(eb).hexdigest().encode())
            add(f"{sub}/mb_shaR/{c}", hashlib.sha256(eb).digest())
            hxe = hx.encode(c)
            add(f"{sub}/sha_mb/{c}", hxe)
            add(f"{sub}/sha_mb_sha/{c}", hashlib.sha256(hxe).hexdigest().encode())
    return saida, len(bases)

def ataque():
    senhas, n_bases = corpus()
    say(f"[MB] {n_bases} bases x 7 codecs multi-byte x 5 formas -> {len(senhas)} senhas distintas x 3 blobs x 2 KDF = {len(senhas)*6}")
    t0 = time.time()
    pad_sub, tot_sub, duros, ctl_hits = Counter(), Counter(), [], 0
    for sub, pw in senhas:
        fam = sub.split("/", 1)[1]
        for blob in ("SMALL", "COSMIC", "TAIL32", "CTL"):
            for kraw, p in G.aes_try(pw, blob, "both"):
                k = kraw.rsplit(".", 1)[-1]
                if blob == "CTL":
                    if p.startswith(b"controle plantado"): ctl_hits += 1
                    continue
                tag = f"{fam}|{blob}|{k}"
                pad_sub[tag] += 1
                hits = oraculo_duro(p, tag)
                rec = {"arm": "MB_duro" if hits else "MB_pad", "sub": sub, "blob": blob, "kdf": k,
                       "len": len(p), "printable": round(G.printable(p), 3), "hex": p.hex()}
                if hits:
                    rec["hits"] = hits; duros.append(rec)
                log(**rec)
            if blob != "CTL":
                for k in ("MD5", "SHA256"):
                    tot_sub[f"{fam}|{blob}|{k}"] += 1
    dt = time.time() - t0
    assert ctl_hits >= 1, "controle plantado NAO recuperado: pipeline quebrado"
    obs, tot = sum(pad_sub.values()), sum(tot_sub.values())
    say(f"[MB] {tot} decifracoes em {dt:.1f}s; controle plantado recuperado {ctl_hits}x; "
        f"oraculo duro: {len(duros)} hits; padding {obs}/{tot} = {obs/tot:.5f} vs 1/256 = 0.00391")
    for d in duros:
        say("   DURO:", d["hits"], d["sub"], d["blob"], d["kdf"], d["hex"][:64])
    # nulo casado: mesma forma (hex64 ou bytes crus de mesmo comprimento)
    formas = Counter()
    for _, pw in senhas:
        formas["hex64" if (len(pw) == 64 and all(c in b"0123456789abcdef" for c in pw)) else f"raw{len(pw)}"] += 1
    n_lote, lotes = 3000, []
    fs, ws = list(formas), list(formas.values())
    N_LOTES = 20 if RAPIDO else 100
    for _ in range(N_LOTES):
        pad = 0
        for _ in range(n_lote):
            f = RNG.choices(fs, weights=ws)[0]
            pw = bytes(RNG.choice(b"0123456789abcdef") for _ in range(64)) if f == "hex64" \
                else bytes(RNG.randrange(256) for _ in range(int(f[3:])))
            for blob in ("SMALL", "COSMIC", "TAIL32"):
                pad += len(G.aes_try(pw, blob, "both"))
        lotes.append(pad)
    mu = sum(lotes) / N_LOTES
    sd = (sum((x - mu) ** 2 for x in lotes) / (N_LOTES - 1)) ** 0.5
    zs = {}
    for tag, n in tot_sub.items():
        zs[tag] = round((pad_sub[tag] - n / 256) / (n * (1 / 256) * (255 / 256)) ** 0.5, 2)
    piores = sorted(zs.items(), key=lambda kv: -abs(kv[1]))[:8]
    say(f"[MB] nulo: 100 lotes de {n_lote} senhas -> mu={mu:.2f} sd={sd:.2f} (esperado {n_lote*6/256:.2f}); "
        f"max|z| por sub-familia = {max(abs(v) for v in zs.values()):.2f} em {len(zs)} tags; piores: {piores}")
    log(arm="MB_resumo", n_bases=n_bases, n_senhas=len(senhas), n_decifracoes=tot, segundos=round(dt, 1),
        ctl_hits=ctl_hits, n_duros=len(duros), padding_obs=obs, padding_tot=tot,
        nulo_mu=mu, nulo_sd=sd, nulo_esperado=n_lote * 6 / 256, z_por_subfamilia=zs)
    return len(senhas), tot, len(duros)

# --------------------------------------------------------------- re-varredura do log do agente
def revarre_log_agente():
    if not os.path.exists(LOG_AGENTE):
        say("[REV] log do agente ausente"); return 0, 0
    n, janelas, hits, dedup = 0, 0, [], set()
    mx = {"printable": 0.0, "ebcdic_sig": 0.0}
    arms = Counter()
    for l in open(LOG_AGENTE, encoding="utf-8"):
        d = json.loads(l)
        if "hex" not in d or d["arm"] in ("A1_material", "A2"):   # material truncado / transformadas nao-AES
            continue
        p = bytes.fromhex(d["hex"]); n += 1; arms[d["arm"]] += 1; dedup.add(p)
        janelas += 2 * max(0, len(p) - 31)
        h = oraculo_duro(p, d["arm"])
        e = G.ebcdic_sig(p); pr = G.printable(p)
        mx["printable"] = max(mx["printable"], pr); mx["ebcdic_sig"] = max(mx["ebcdic_sig"], e)
        if e >= 0.75: h.append("ebcdic_sig")
        if h:
            hits.append({"arm": d["arm"], "sub": d.get("sub", d.get("campo")), "blob": d.get("blob"),
                         "kdf": d.get("kdf"), "hits": h, "hex": d["hex"][:128]})
    say(f"[REV] {n} plaintexts do log do agente ({len(dedup)} distintos; {dict(arms)}): {janelas} janelas de 32 B "
        f"(2 ordens), hits={len(hits)}, max printable={mx['printable']:.3f}, max ebcdic_sig={mx['ebcdic_sig']:.3f}")
    for h in hits: say("   HIT:", h)
    log(arm="REV_resumo", n=n, distintos=len(dedup), por_arm=dict(arms), janelas=janelas, hits=hits, **mx)
    return n, len(hits)

if __name__ == "__main__":
    t0 = time.time()
    controles()
    n_rev, h_rev = (0, 0) if RAPIDO else revarre_log_agente()
    n_pw, n_dec, n_duros = ataque()
    resumo = {"arm": "FIM", "segundos": round(time.time() - t0, 1), "REV_plaintexts": n_rev, "REV_hits": h_rev,
              "MB_senhas": n_pw, "MB_decifracoes": n_dec, "MB_duros": n_duros}
    log(**resumo); say("RESUMO:", json.dumps(resumo)); LOG.close()
