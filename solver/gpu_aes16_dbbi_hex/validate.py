# -*- coding: utf-8 -*-
"""Validação obrigatória do kernel: Controle A (byte a byte vs pycryptodome),
Controle B (plantado end-to-end: normal + aninhado) e benchmark de throughput."""
import json
import random
import time
import numpy as np
from Crypto.Cipher import AES

import host
import refkit as R
G = R.G

SALT, CT = G.BLOBS["SMALL"]
FACT16 = R.FACT16


def pkcs7(m, bs=16):
    n = bs - (len(m) % bs)
    return m + bytes([n]) * n


def encrypt_planted(index, message, salt):
    """Cifra `message` com a senha do índice (EVP-SHA256 + AES-256-CBC + PKCS7)."""
    pw = R.password_for_index(index)
    key, iv = G.evp(pw, bytes(salt), G.SHA256)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7(message))
    return ct, pw, key, iv


def control_A(gpu, n=256):
    rng = random.Random(1234)
    idxs = [rng.randrange(FACT16) for _ in range(n)]
    res = gpu.debug_run(idxs, SALT, CT)
    bad = 0
    for i, idx in enumerate(idxs):
        key, iv, P0, P3, P4 = host.cpu_blocks(idx, SALT, CT)
        g = res[i]
        if not (g["key"] == key and g["iv"] == iv and g["P0"] == P0
                and g["P3"] == P3 and g["P4"] == P4):
            bad += 1
            if bad <= 3:
                print("  A FAIL idx", idx)
    ok = bad == 0
    msg = f"{n} índices aleatórios: key/iv/P0/P3/P4 idênticos (pycryptodome) — {'OK' if ok else str(bad)+' falhas'}"
    return ok, msg


def control_B_normal(gpu):
    rng = random.Random(99)
    istar = rng.randrange(FACT16)
    message = b"THE PLANTED CONTROL PLAINTEXT FOR GSMG SMALL BLOB VALIDATION 001"  # 63 -> pad
    message = message[:79]
    ct_ctl, pw, key, iv = encrypt_planted(istar, message, SALT)
    assert len(ct_ctl) == 80, len(ct_ctl)
    count = 10_000_000
    base = min(max(0, istar - 5_000_000), FACT16 - count)
    assert base <= istar < base + count
    survivors, total, ovf = gpu.scan_batch(base, count, SALT, ct_ctl)
    found = istar in survivors
    # Python reabre a mensagem
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct_ctl)
    reopened = G.unpad(dec) == message
    ok = found and reopened and not ovf
    msg = (f"idx plantado={istar} em [{base},{base+count}); kernel devolveu {total} sobreviventes, "
           f"contém o índice={found}, Python reabriu a mensagem={reopened}, overflow={ovf}")
    return ok, msg


def control_B_nested(gpu):
    rng = random.Random(4242)
    jstar = rng.randrange(FACT16)
    message = b"Salted__" + b"NESTED_BLOB_CONTROL_PRINTABLE_TAIL_" + b"A" * 40
    message = message[:72]   # 64..79 -> ct de 80B
    ct_ctl, pw, key, iv = encrypt_planted(jstar, message, SALT)
    assert len(ct_ctl) == 80
    # confirma que P0 começa com Salted__
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct_ctl)
    assert dec[:8] == b"Salted__"
    count = 10_000_000
    base = min(max(0, jstar - 3_000_000), FACT16 - count)
    assert base <= jstar < base + count
    survivors, total, ovf = gpu.scan_batch(base, count, SALT, ct_ctl)
    found = jstar in survivors
    ok = found and not ovf
    msg = (f"idx aninhado={jstar}; P0 começa com 'Salted__'; kernel devolveu {total} sobreviventes, "
           f"contém o índice={found}, overflow={ovf}")
    return ok, msg


def benchmark(gpu):
    # aquece
    gpu.time_scan(0, 1 << 22, SALT, CT)
    results = {}
    best = 0.0
    for shift in (24, 25, 26):
        count = 1 << shift
        ts = [gpu.time_scan(0, count, SALT, CT) for _ in range(3)]
        t = min(ts)
        mps = count / t / 1e6
        results[f"2^{shift}"] = {"count": count, "s": round(t, 4), "Mps": round(mps, 2)}
        best = max(best, mps)
    eta_h = FACT16 / (best * 1e6) / 3600.0
    return best, eta_h, results


def main():
    gpu = host.GPU()
    out = {"device": gpu.dev.name}
    a_ok, a_msg = control_A(gpu)
    print("Controle A:", a_msg)
    bn_ok, bn_msg = control_B_normal(gpu)
    print("Controle B (normal):", bn_msg)
    bnest_ok, bnest_msg = control_B_nested(gpu)
    print("Controle B (aninhado):", bnest_msg)
    best_mps, eta_h, bench = benchmark(gpu)
    print("Benchmark:", json.dumps(bench), "-> melhor", round(best_mps, 2), "M/s, ETA 16! =", round(eta_h, 1), "h")
    out.update({
        "controle_A_ok": a_ok, "controle_A": a_msg,
        "controle_B_normal_ok": bn_ok, "controle_B_normal": bn_msg,
        "controle_B_nested_ok": bnest_ok, "controle_B_nested": bnest_msg,
        "throughput_Mps": round(best_mps, 2), "eta_horas_16fat": round(eta_h, 2),
        "bench": bench,
    })
    with open("validate_result.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\nJSON =>", json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
