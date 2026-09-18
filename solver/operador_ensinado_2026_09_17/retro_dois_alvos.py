# -*- coding: utf-8 -*-
"""Varredura RETROATIVA com o oraculo estendido (dois enderecos do premio).

Motivo: solver/oracles.py e G.fast_priv_scan so testam 1GSMG1JC9...prBe. O segundo endereco
do premio, 17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa (3,75 BTC, nunca gastou), nunca foi alvo de
nenhuma varredura de privkey do projeto. A mensagem da fase 3.2 diz "the private keyS belong
to half and better half" (plural). Esta varredura cobre TODO plaintext com padding valido
ja registrado no repositorio, nas duas ordens de byte, contra os DOIS h160.
"""
import os, re, json, glob, sys, hashlib
from multiprocessing import Pool
import base58
ROOT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
H160 = {base58.b58decode_check(a)[1:].hex(): a for a in
        ("1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa")}
HEXK = ("hex", "plain_hex", "plaintext_hex", "pt_hex")
HEXRE = re.compile(r"[0-9a-fA-F]{64}")
WIFRE = re.compile(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}")

def collect():
    seen = set()
    def walk(o, out):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in HEXK and isinstance(v, str) and len(v) >= 64 and len(v) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", v):
                    out.append(v)
                else: walk(v, out)
        elif isinstance(o, list):
            for v in o: walk(v, out)
    for pat in ("_work/**/*.jsonl", "_work/**/*.json", "solver/**/*.jsonl"):
        for p in glob.glob(os.path.join(ROOT, pat), recursive=True):
            got = []
            try: txt = open(p, encoding="utf-8", errors="replace").read()
            except Exception: continue
            if p.endswith(".jsonl"):
                for line in txt.splitlines():
                    line = line.strip()
                    if line:
                        try: walk(json.loads(line), got)
                        except Exception: pass
            else:
                try: walk(json.loads(txt), got)
                except Exception: pass
            for h in got:
                h = h.lower()
                if h not in seen:
                    seen.add(h)
    return sorted(seen)

def h160b(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).hexdigest()

def work(chunk):
    from coincurve import PublicKey
    hits, nwin = [], 0
    for h in chunk:
        try: buf = bytes.fromhex(h)
        except Exception: continue
        for j in range(0, len(buf) - 31):
            for tag, w in (("fwd", buf[j:j+32]), ("rev", buf[j:j+32][::-1])):
                nwin += 1
                try: pk = PublicKey.from_valid_secret(w)
                except Exception: continue
                for form, blob in (("unc", pk.format(False)), ("comp", pk.format(True))):
                    a = H160.get(h160b(blob))
                    if a: hits.append({"addr": a, "form": form, "order": tag, "off": j, "priv": w.hex(), "src": h[:64]})
        t = buf.decode("latin-1")
        for m in HEXRE.finditer(t):
            try: w = bytes.fromhex(m.group())
            except Exception: continue
            try: pk = PublicKey.from_valid_secret(w)
            except Exception: continue
            for form, blob in (("unc", pk.format(False)), ("comp", pk.format(True))):
                a = H160.get(h160b(blob))
                if a: hits.append({"addr": a, "form": form, "order": "hex64", "priv": w.hex(), "src": h[:64]})
        for m in WIFRE.finditer(t):
            try: raw = base58.b58decode_check(m.group())
            except Exception: continue
            if len(raw) not in (33, 34): continue
            w = raw[1:33]
            try: pk = PublicKey.from_valid_secret(w)
            except Exception: continue
            for form, blob in (("unc", pk.format(False)), ("comp", pk.format(True))):
                a = H160.get(h160b(blob))
                if a: hits.append({"addr": a, "form": form, "order": "wif", "priv": w.hex(), "src": h[:64]})
    return hits, nwin

if __name__ == "__main__":
    pts = collect()
    print(f"plaintexts unicos: {len(pts):,}  bytes: {sum(len(p)//2 for p in pts):,}", flush=True)
    # controle plantado: injeta uma chave conhecida cujo h160 entra no alvo temporariamente
    ctrl = hashlib.sha256(b"controle-retro").digest()
    from coincurve import PublicKey as PK
    H160[h160b(PK.from_valid_secret(ctrl).format(False))] = "PLANTADO"
    plant = (b"\xab" * 13 + ctrl + b"\xcd" * 9).hex()
    ch, _ = work([plant])
    assert any(x["addr"] == "PLANTADO" and x["off"] == 13 for x in ch), "controle plantado falhou"
    print("controle plantado: OK (chave achada no offset 13)", flush=True)
    del H160[h160b(PK.from_valid_secret(ctrl).format(False))]
    NP = max(1, (os.cpu_count() or 4) - 2)
    CH = 400
    chunks = [pts[i:i+CH] for i in range(0, len(pts), CH)]
    allhits, total = [], 0
    with Pool(NP) as pool:
        for i, (hits, nw) in enumerate(pool.imap_unordered(work, chunks), 1):
            allhits += hits; total += nw
            if i % 50 == 0 or i == len(chunks):
                print(f"  {i}/{len(chunks)} chunks  janelas={total:,}  hits={len(allhits)}", flush=True)
    out = {"plaintexts": len(pts), "janelas_verificadas": total, "hits": allhits,
           "alvos": list(H160.values())}
    json.dump(out, open("retro2_resultado.json", "w"), indent=1)
    print(f"\nFIM  plaintexts={len(pts):,}  verificacoes={total:,}  HITS={len(allhits)}")
    for h in allhits[:10]: print("  ", h)
