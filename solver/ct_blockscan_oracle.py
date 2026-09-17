# -*- coding: utf-8 -*-
"""Critico r2 — teste INDEPENDENTE e mais forte da familia montagem_ct.

Hipotese a refutar (registrada antes de rodar): existe no corpus historico (1,27 M formas) uma
chave EVP (salt S/T x KDF sha256/md5) que decifra corretamente o SMALL ou o TAIL32 sob QUALQUER
ordem de blocos, QUALQUER IV e COM OU SEM padding. Se existir, entre os 25 blocos candidatos
por (chave, CT) — D_i ^ iv e D_i ^ C_j (i != j) — pelo menos 4 sao inteiramente 'limpos'
(bytes em {9,10,13} U [32,126]), porque em CBC o bloco i decifra como D_i ^ C_(anterior)
independentemente de IV/padding/posicao. Sob o nulo, P(bloco limpo) = (98/256)^16 = 2,1e-7;
P(>=2 limpos em 25) ~ 6,6e-12 por (chave, CT); em 10,2 M pares esperam-se ~7e-5 casos.
Logo: >=2 blocos limpos sob a mesma chave = sinal; 0 casos = hipotese de montagem refutada
tambem para IV errado, nopad e ordem arbitraria (o agente so cobriu montagens com padding valido
no ultimo bloco e IV = EVP)."""
import sys, os, json, time, hashlib, pickle, random, collections, base64
HERE = os.path.dirname(os.path.abspath(__file__))
MC = os.path.join(os.path.dirname(HERE), "montagem_ct")
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
from Crypto.Cipher import AES
import gsmg_common as G
SALTS = {"S": G.BLOBS["SMALL"][0], "T": G.BLOBS["TAIL32"][0]}
CTS = {"S": G.BLOBS["SMALL"][1], "T": G.BLOBS["TAIL32"][1]}
CINT = {k: [int.from_bytes(v[i:i + 16], "big") for i in range(0, 80, 16)] for k, v in CTS.items()}
NONCLEAN = bytes(set(range(256)) - set(range(32, 127)) - {9, 10, 13})
KDFS = (("sha256", hashlib.sha256), ("md5", hashlib.md5))

def evp(pw, salt, h):
    d = prev = b""
    while len(d) < 48: prev = h(prev + pw + salt).digest(); d += prev
    return d[:32], d[32:48]

def n_clean(D, iv, cint):
    """nº de blocos limpos entre os 25 candidatos; devolve (n, lista de (i, j|'iv'))."""
    ivi = int.from_bytes(iv, "big"); hits = []
    for i in range(5):
        di = int.from_bytes(D[16 * i:16 * i + 16], "big")
        if len((di ^ ivi).to_bytes(16, "big").translate(None, NONCLEAN)) == 16: hits.append((i, "iv"))
        for j in range(5):
            if j != i and len((di ^ cint[j]).to_bytes(16, "big").translate(None, NONCLEAN)) == 16: hits.append((i, j))
    return len(hits), hits

def scan_forms(forms):
    hist = collections.Counter(); sig = []
    for form in forms:
        for st, salt in SALTS.items():
            for kn, h in KDFS:
                key, iv = evp(form, salt, h); ecb = AES.new(key, AES.MODE_ECB)
                for ct in "ST":
                    D = ecb.decrypt(CTS[ct]); n, hits = n_clean(D, iv, CINT[ct])
                    hist[n] += 1
                    if n >= 2: sig.append({"form": form.decode("latin-1")[:120], "salt": st, "kdf": kn, "ct": ct, "n_clean": n, "hits": hits, "D_hex": D.hex(), "iv_hex": iv.hex()})
    return hist, sig

def make_forms(pws):
    seen = set(); out = []
    for pw in pws:
        hx = hashlib.sha256(pw).hexdigest()
        for f in (pw, hx.encode(), hx.upper().encode()):
            if f not in seen: seen.add(f); out.append(f)
    return out

def control():
    """Positivo: CT sintetico de 5 blocos (chave/iv da fase 2, texto da fase 2) embaralhado [3,0,4,1,2]:
    (a) IV certo -> 5 limpos; (b) IV errado (zeros) -> 4 limpos; (c) nopad (texto de 80 B exatos, sem
    padding) + IV errado -> 4 limpos; (d) chave errada -> <=1 limpo. Usa o MESMO n_clean do scan."""
    raw = base64.b64decode(G.PHASE2_B64); s2, c2 = raw[8:16], raw[16:]
    key, iv = evp(G.shahex("causality").encode(), s2, hashlib.sha256)
    p2 = G.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(c2)); assert p2.startswith(b"The ironic")
    perm = [3, 0, 4, 1, 2]; out = {}
    def shuffled_ct(msg, pad):
        if pad: n = 16 - len(msg) % 16; msg = msg + bytes([n]) * n
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(msg); assert len(ct) == 80
        C = [ct[i:i + 16] for i in range(0, 80, 16)]; return b"".join(C[i] for i in perm)
    ct_pad = shuffled_ct(p2[:70], True); ct_nopad = shuffled_ct(p2[:80], False)
    ecb = AES.new(key, AES.MODE_ECB)
    cint = lambda ct: [int.from_bytes(ct[i:i + 16], "big") for i in range(0, 80, 16)]
    out["iv_certo"] = n_clean(ecb.decrypt(ct_pad), iv, cint(ct_pad))[0]
    out["iv_errado"] = n_clean(ecb.decrypt(ct_pad), b"\0" * 16, cint(ct_pad))[0]
    out["nopad_iv_errado"] = n_clean(ecb.decrypt(ct_nopad), b"\0" * 16, cint(ct_nopad))[0]
    kw, ivw = evp(b"wrongpassword", s2, hashlib.sha256)
    out["chave_errada"] = n_clean(AES.new(kw, AES.MODE_ECB).decrypt(ct_pad), ivw, cint(ct_pad))[0]
    ok = out["iv_certo"] == 5 and out["iv_errado"] == 4 and out["nopad_iv_errado"] == 4 and out["chave_errada"] <= 1
    print("CONTROLE:", out, "OK" if ok else "FALHOU"); assert ok
    return out

def chunks(lst, n):
    for i in range(0, len(lst), n): yield lst[i:i + n]

if __name__ == "__main__":
    import multiprocessing as mp
    LOG = os.path.join(HERE, "blockscan.jsonl"); open(LOG, "w").close()
    G.jsonl(LOG, {"kind": "hypothesis", "text": __doc__.strip()})
    ctl = control(); G.jsonl(LOG, {"kind": "control", **ctl})
    t0 = time.time()
    with mp.Pool(16) as pool:
        # nulo: 200 k senhas aleatorias de 12 B x 3 formas
        rng = random.Random(99); nul = make_forms([rng.randbytes(12) for _ in range(200000)])
        hist0 = collections.Counter(); sig0 = []
        for h, s in pool.imap_unordered(scan_forms, list(chunks(nul, 5000))): hist0.update(h); sig0 += s
        null = {"kind": "null", "n_forms": len(nul), "n_pairs": sum(hist0.values()), "hist": dict(sorted(hist0.items())), "n_ge2": len(sig0),
                "p_clean_block_teorico": (98 / 256) ** 16, "esperado_ge1": round(sum(hist0.values()) * 25 * (98 / 256) ** 16, 2)}
        G.jsonl(LOG, null); print(json.dumps(null), f"{time.time()-t0:.0f}s", flush=True)
        d = pickle.load(open(os.path.join(MC, "corpus.pkl"), "rb")); forms = make_forms(d["pws"])
        print(f"corpus: {len(d['pws'])} senhas-base -> {len(forms)} formas", flush=True)
        hist = collections.Counter(); sig = []; jobs = list(chunks(forms, 5000))
        for i, (h, s) in enumerate(pool.imap_unordered(scan_forms, jobs)):
            hist.update(h); sig += s
            for x in s: G.jsonl(LOG, {"kind": "SIGNAL_ge2_clean", **x}); print("!!! >=2 blocos limpos:", json.dumps(x)[:400], flush=True)
            if i % 40 == 0: print(f"  chunk {i}/{len(jobs)} {time.time()-t0:.0f}s", flush=True)
    summ = {"kind": "summary", "n_forms": len(forms), "n_key_ct_pairs": sum(hist.values()), "hist_clean_blocks": dict(sorted(hist.items())),
            "n_ge2": len(sig), "esperado_ge1_nulo": round(sum(hist.values()) * 25 * (98 / 256) ** 16, 2), "secs": round(time.time() - t0)}
    G.jsonl(LOG, summ); json.dump(summ, open(os.path.join(HERE, "blockscan.json"), "w"), indent=1); print(json.dumps(summ))
