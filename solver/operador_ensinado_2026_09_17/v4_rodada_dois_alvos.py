# -*- coding: utf-8 -*-
"""V4 — re-varredura consolidada dos plaintexts com padding valido DESTA rodada (operador_ensinado_2026-09-17)
contra os DOIS enderecos do premio (1GSMG... e 17ucy...), toda janela de 32 B nas duas ordens + hex64 + WIF.

A V4 original, lancada pelo agente de sintese, morreu no spawn do multiprocessing (WinError 87) quando o
processo-pai encerrou; este script a refaz. Exclui o material C5 (247.580 blobs de 32 B ja testados em §3.3).
Reusa work() de retro_dois_alvos.py (controle plantado incluido la).
"""
import os, re, json, glob, gzip, hashlib, sys
from multiprocessing import Pool
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import retro_dois_alvos as R

ROOT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17"
OUT = os.path.join(ROOT, "orquestrador")
HEXK = ("hex", "plain_hex", "plaintext_hex", "pt_hex")

def walk(o, out):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in HEXK and isinstance(v, str) and len(v) >= 64 and len(v) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", v):
                out.append(v.lower())
            else:
                walk(v, out)
    elif isinstance(o, list):
        for v in o: walk(v, out)

def collect():
    seen, por = set(), {}
    pats = ("**/*.jsonl", "**/*.json", "**/*.jsonl.gz")
    for pat in pats:
        for p in glob.glob(os.path.join(ROOT, pat), recursive=True):
            rel = os.path.relpath(p, ROOT)
            if rel.startswith("orquestrador") or rel.startswith("sintese"): continue
            got = []
            op = gzip.open if p.endswith(".gz") else open
            try:
                with op(p, "rt", encoding="utf-8", errors="replace") as f:
                    if p.endswith(".json"):
                        try: walk(json.load(f), got)
                        except Exception: pass
                    else:
                        for line in f:
                            line = line.strip()
                            if not line: continue
                            try: o = json.loads(line)
                            except Exception: continue
                            if isinstance(o, dict) and str(o.get("kind", o.get("tipo", ""))).startswith("C5"): continue
                            walk(o, got)
            except Exception as e:
                print("  falha lendo", rel, e); continue
            got = [h for h in got if len(h) != 64]  # 32 B isolados = material C5, ja testado
            novos = [h for h in got if h not in seen]
            seen.update(novos)
            if got: por[rel] = {"lidos": len(got), "novos": len(novos)}
    return sorted(seen), por

if __name__ == "__main__":
    pts, por = collect()
    tot_win = sum(max(0, len(h)//2 - 31) for h in pts)
    print(f"plaintexts distintos: {len(pts):,}  janelas previstas: {tot_win:,} (x2 ordens)", flush=True)
    NP = max(1, (os.cpu_count() or 4) - 4)
    chunks = [pts[i:i+400] for i in range(0, len(pts), 400)]
    hits, total = [], 0
    with Pool(NP) as pool:
        for i, (h, nw) in enumerate(pool.imap_unordered(R.work, chunks), 1):
            hits += h; total += nw
            if i % 100 == 0 or i == len(chunks):
                print(f"  {i}/{len(chunks)} chunks  verificacoes={total:,}  hits={len(hits)}", flush=True)
    res = {"plaintexts": len(pts), "verificacoes": total, "hits": hits, "por_arquivo": por,
           "alvos": sorted(R.H160.values())}
    json.dump(res, open(os.path.join(OUT, "v4_resultado.json"), "w"), indent=1)
    print(f"\nFIM V4  plaintexts={len(pts):,}  verificacoes={total:,}  HITS={len(hits)}")
