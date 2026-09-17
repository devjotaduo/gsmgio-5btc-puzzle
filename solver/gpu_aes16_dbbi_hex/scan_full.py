# -*- coding: utf-8 -*-
"""Worker da varredura completa das 16! bijeções (ordem direta, hex minúsculo).

Roda em segundo plano. A cada lote grava checkpoint.json (próximo índice a
processar) para poder retomar. Cada sobrevivente do kernel é REVERIFICADO na
CPU (senha reconstruída -> EVP-SHA256 -> AES) e registrado em survivors.jsonl
com plain_hex. Um hit semântico (G.semantic / G.nested_blob) é SOLVE:
grava SOLVE.json, imprime senha+plaintext e encerra.
"""
import json
import os
import sys
import time

from Crypto.Cipher import AES

import host
import refkit as R
G = R.G

HERE = os.path.dirname(os.path.abspath(__file__))
CKPT = os.path.join(HERE, "checkpoint.json")
SURV = os.path.join(HERE, "survivors.jsonl")
SOLVE = os.path.join(HERE, "SOLVE.json")

SALT, CT = G.BLOBS["SMALL"]
FACT16 = R.FACT16
BATCH = 1 << 27          # lote grande: amortiza overhead de enfileiramento
CAP = 65536


def scan_range(gpu, base, count):
    """Sobreviventes em [base, base+count). Se o buffer estourar, divide o lote."""
    survivors, total, ovf = gpu.scan_batch(base, count, SALT, CT, cap=CAP)
    if not ovf:
        return survivors
    # estouro (praticamente impossível com ~0.1 sobreviventes/16!): divide e reprocessa
    half = count // 2
    print(f"OVERFLOW base={base} count={count} (total={total}); dividindo", flush=True)
    out = scan_range(gpu, base, half)
    out += scan_range(gpu, base + half, count - half)
    return out


def verify_survivor(index):
    """Reconstrói a senha e reverifica na CPU. Decifra os 80B completos (pega
    blob aninhado sem PKCS7) e também roda G.aes_try (padded)."""
    pw = R.password_for_index(index)
    key, iv = G.evp(pw, SALT, G.SHA256)
    raw = AES.new(key, AES.MODE_CBC, iv).decrypt(CT)
    unp = G.unpad(raw)
    aes_hits = G.aes_try(pw, "SMALL", "sha256")   # honra a especificação
    sem = G.semantic(raw) or (unp is not None and G.semantic(unp)) or any(G.semantic(p) for _, p in aes_hits)
    nest = G.nested_blob(raw)
    rec = {
        "index": index, "pw": pw.decode(), "len": len(raw),
        "printable": round(G.printable(raw), 3),
        "head": raw[:48].decode("latin-1"),
        "plain_hex": raw.hex(),
        "unpad_hex": (unp.hex() if unp is not None else None),
        "nested": bool(nest), "semantic": bool(sem),
    }
    return rec


def main():
    gpu = host.GPU()
    base = 0
    if os.path.exists(CKPT):
        base = json.load(open(CKPT))["next_index"]
    print(f"[start] device={gpu.dev.name} base={base} FACT16={FACT16} BATCH={BATCH}", flush=True)
    t0 = time.time(); done = 0
    while base < FACT16:
        count = min(BATCH, FACT16 - base)
        survivors = scan_range(gpu, base, count)
        for idx in survivors:
            rec = verify_survivor(idx)
            G.jsonl(SURV, rec)
            if rec["semantic"] or rec["nested"]:
                print(f"*** CANDIDATO FORTE *** index={idx} nested={rec['nested']} "
                      f"semantic={rec['semantic']} pw={rec['pw']}", flush=True)
            if rec["semantic"]:
                json.dump({"SOLVE": True, **rec}, open(SOLVE, "w", encoding="utf-8"),
                          ensure_ascii=False, indent=2)
                print(f"*** SOLVE *** index={idx}\n  pw={rec['pw']}\n  plain_hex={rec['plain_hex']}", flush=True)
                return
        base += count
        json.dump({"next_index": base, "ts": time.time()}, open(CKPT, "w"))
        done += count
        el = time.time() - t0
        rate = done / el / 1e6 if el else 0
        eta = (FACT16 - base) / (done / el) / 3600 if done and el else 0
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] base={base} "
              f"({base/FACT16*100:.4f}%) {rate:.1f} M/s ETA {eta:.1f}h", flush=True)
    print("[done] varredura completa sem SOLVE semântico.", flush=True)


if __name__ == "__main__":
    main()
