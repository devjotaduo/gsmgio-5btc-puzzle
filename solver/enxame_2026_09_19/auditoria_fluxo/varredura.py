# -*- coding: utf-8 -*-
"""
F2 auditoria_fluxo — varredura independente dos modos de fluxo.

Dominio: senhas x {cfb, cfb1, cfb8, ofb, ctr} x {EVP-SHA256, EVP-MD5} x
{SMALL, COSMIC, TAIL32}. Sem filtro de padding (modos de fluxo nao produzem
padding) e sem filtro semantico: TODA janela de 32 B do plaintext, em BE e LE,
contra os DOIS h160 alvo. Registra tambem hex64/WIF ASCII embutidos.

Conjunto de senhas (reconstruivel so do repositorio, declarado em prosa no FINDINGS):
  L1 strings-base verbatim do README/ENDGAME x 7 formas
  L2 120 permutacoes dos 5 tokens do endgame x 3 formas
  L3 duplo sha256hex de cada string-base
  L4 20 pares ordenados dos 5 tokens x 2 formas
  L5 24 permutacoes das 4 senhas canonicas das fases x 2 formas

Uso: python3 varredura.py
"""
import hashlib, itertools, json, os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import indep_fluxo as X

OUT = os.path.join(X.REPO, "_work", "enxame_2026-09-19", "auditoria_fluxo")
os.makedirs(OUT, exist_ok=True)
TARGETS = ("a9553269572a317e39f0f518cb87c1a0ee1dbae4",
           "4bc468447fe1b048ad030a2f9a125478eabc4ed6")

def sh(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()

# ---------------------------------------------------------------- fontes do repositorio
def sources():
    txt = open(os.path.join(X.REPO, "README.md"), encoding="utf-8").read()
    line = [l for l in txt.splitlines() if l.startswith("> d b b i")][0]
    s = line[2:].replace(" ", "").replace("*", "")
    dbbi, faed = s[0:91], s[195:765]
    assert len(dbbi) == 91 and len(faed) == 570 and faed.startswith("faed")
    return dbbi, faed

TOKENS5 = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword", "sha256"]
FASES4 = ["theflowerblossomsthroughwhatseemstobeaconcretesurface",
          "causality",
          ("causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F6365"
           "7320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F3330207365"
           "6D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"),
          "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"]

def build_passwords():
    dbbi, faed = sources()
    base = list(FASES4) + TOKENS5 + [
        "our first hint is your last command", "ans too", "shabef",
        dbbi, faed, faed[4:],
        "thematrixhasyou", "gsmg.io/theseedisplanted", "theseedisplanted",
        "salphaseion", "cosmicduality", "SalPhaseIon", "Cosmic Duality",
        "matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist",
        "lastwordsbeforearchichoicethispassword",
        "yellowblueprimes", "causalitySafenet",
    ]
    pw = []
    for b in base:                                           # L1
        nosp = b.replace(" ", "")
        for f in (b, b.lower(), b.upper(), nosp, sh(b), sh(b).upper(), sh(nosp)):
            pw.append(f)
    for b in base:                                           # L3
        pw.append(sh(sh(b)))
    for p in itertools.permutations(TOKENS5):                # L2
        j = "".join(p)
        pw += [j, sh(j), sh(j).upper()]
    for a, b in itertools.permutations(TOKENS5, 2):          # L4
        j = a + b
        pw += [j, sh(j)]
    for p in itertools.permutations(FASES4):                 # L5
        j = "".join(p)
        pw += [j, sh(j)]
    seen, uniq = set(), []
    for s in pw:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return uniq

HEX64 = re.compile(r"[0-9a-fA-F]{64}")
WIF = re.compile(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}")

def main():
    blobs = X.load_blobs()
    assert set(blobs) == {"SMALL", "COSMIC", "TAIL32"}
    pws = build_passwords()
    sc = X.Scanner(TARGETS)
    modes = sorted(X.STREAM_MODES)
    kdfs = list(X.KDFS)

    n_dec = 0
    n_bytes = 0
    n_hex64 = 0
    n_wif = 0
    hits = []
    hits_path = os.path.join(OUT, "hits.jsonl")
    open(hits_path, "w").close()          # arquivo de hits criado ANTES da varredura
    t0 = time.time()
    for i, pw in enumerate(pws):
        pwb = pw.encode()
        for bn, (salt, ct) in blobs.items():
            for mode in modes:
                for kdf in kdfs:
                    pt = X.decrypt(mode, kdf, pwb, salt, ct)
                    n_dec += 1
                    n_bytes += len(pt)
                    for h in sc.scan(pt, "%s/%s/%s" % (bn, mode, kdf)):
                        hits.append({"pw": pw, "blob": bn, "mode": mode, "kdf": kdf, "hit": h})
                    t = pt.decode("latin-1")
                    for m in HEX64.finditer(t):
                        n_hex64 += 1
                        r = sc._check(bytes.fromhex(m.group()), "%s/%s/%s" % (bn, mode, kdf), "hex64")
                        if r: hits.append({"pw": pw, "blob": bn, "mode": mode, "kdf": kdf, "hit": r})
                    n_wif += len(WIF.findall(t))
        if i % 100 == 0:
            el = time.time() - t0
            print("  %d/%d senhas  %d decifras  %d escalares  %.0fs" %
                  (i, len(pws), n_dec, sc.scalars, el), flush=True)

    for h in hits:
        with open(hits_path, "a") as f:
            f.write(json.dumps(h) + "\n")

    res = {
        "senhas_unicas": len(pws),
        "modos": modes, "kdfs": kdfs, "blobs": sorted(blobs),
        "decifracoes": n_dec,
        "decifracoes_esperadas": len(pws) * len(modes) * len(kdfs) * len(blobs),
        "bytes_plaintext": n_bytes,
        "janelas_raw32": sc.windows,
        "janelas_esperadas": len(pws) * len(modes) * len(kdfs) *
                             sum(len(c) - 31 for _, c in blobs.values()),
        "escalares_testados": sc.scalars,
        "mult_escalares_ec_realizadas": sc.ec,
        "hex64_ascii_testados": n_hex64,
        "wif_ascii_encontrados": n_wif,
        "hits": len(hits),
        "hits_file": hits_path,
        "hits_file_bytes": os.path.getsize(hits_path),
        "alvos": list(TARGETS),
        "segundos": round(time.time() - t0, 1),
        "blob_digest": X.blob_digest(blobs),
    }
    assert res["decifracoes"] == res["decifracoes_esperadas"]
    assert res["janelas_raw32"] == res["janelas_esperadas"]
    assert res["escalares_testados"] == 2 * res["janelas_raw32"] + n_hex64
    json.dump(res, open(os.path.join(OUT, "varredura.json"), "w"), indent=2)
    print(json.dumps({k: v for k, v in res.items() if k != "blob_digest"}, indent=2))

if __name__ == "__main__":
    main()
