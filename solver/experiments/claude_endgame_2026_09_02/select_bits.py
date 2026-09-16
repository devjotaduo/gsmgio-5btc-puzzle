# -*- coding: utf-8 -*-
"""
FAMILIA select_bits — GSMG endgame.

HIPOTESE (prosa, falsificavel):
  faed (570 simbolos a-i, ~1806 bits) e dbbi (91) se comportam como fonte de entropia
  i.i.d.; portanto a chave privada de 32 B (ou a senha) nao esta na leitura do TODO
  (permutar/decodificar ja foi refutado nas rodadas 1-2), mas num SUBCONJUNTO de
  posicoes SELECIONADO por uma regra do puzzle (primos, celulas coloridas, matriz
  README, mod k, escapes g/i, janelas, indices vindos do dbbi).  Cada selecao vira
  digitos -> (a) inteiro base-9/base-10 -> bytes; (b) 1 bit por simbolo -> 256 bits em
  todo offset; (c) sha256 do texto -> senha/privkey.  Espaco finito: ~1.2k selecoes x
  ~6 materializacoes.  Falsifica-se por ausencia de oraculo duro.

ORACULO DURO: privkey -> pubkey do premio (coincurve) ou blob AES aberto com semantica.
CONTROLE POSITIVO: privkey conhecida plantada nas posicoes primas de um faed sintetico
(base-9 dos 104 digitos primos) tem que ser recuperada pelo proprio motor.
"""
import sys, os, json, time, hashlib, itertools

SCRATCH = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SCRATCH)
import gsmg_common as G
from coincurve import PublicKey

LOG = os.path.join(SCRATCH, "select_bits.jsonl")
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)

NT = 0                    # contador exato de testes (oraculos chamados)
HARD = []                 # hits duros
SOFT = []                 # padding valido sem semantica
BEST = {"score": -99.0, "text": "", "how": ""}


# ------------------------------------------------------------------ oraculos
def pcheck(sec, where=""):
    """Oraculo duro de privkey. Conta 1 teste."""
    global NT
    NT += 1
    if len(sec) != 32:
        return False
    try:
        if PublicKey.from_valid_secret(sec).format(False) == TGT:
            HARD.append({"kind": "privkey", "priv_hex": sec.hex(), "how": where})
            G.jsonl(LOG, {"HARD": "privkey", "priv_hex": sec.hex(), "how": where})
            return True
    except Exception:
        pass
    return False


def scan_bytes(buf, where):
    """Todo offset de 32 B do buffer."""
    for j in range(0, len(buf) - 31):
        pcheck(buf[j:j + 32], f"{where}@{j}")


def try_pw(pw, where):
    """Senha nos 3 blobs, KDF EVP-SHA256 (padrao provado)."""
    global NT
    for blob in ("SMALL", "COSMIC", "TAIL32"):
        NT += 1
        for kdf, p in G.aes_try(pw, blob, kdf="sha256"):
            rec = {"blob": blob, "kdf": kdf, "len": len(p), "pw": pw[:80],
                   "printable": round(G.printable(p), 3), "how": where,
                   "head": p[:32].hex()}
            if G.semantic(p):
                HARD.append({"kind": "aes", **rec, "plain_hex": p.hex()})
                G.jsonl(LOG, {"HARD": "aes", **rec, "plain_hex": p.hex()})
            else:
                SOFT.append(rec)
                G.jsonl(LOG, {"SOFT": rec})
            for h in G.fast_priv_scan(p, where):
                HARD.append({"kind": "priv_in_plain", "hit": h})


# ------------------------------------------------------------------ selecoes
def primes_below(n):
    s = [True] * n
    s[0:2] = [False, False]
    for i in range(2, int(n ** .5) + 1):
        if s[i]:
            s[i * i::i] = [False] * len(s[i * i::i])
    return [i for i, v in enumerate(s) if v]


def matrix_idx(M, order, val):
    if order == "spiral":
        seq = [M[r][c] for r, c in G.SPIRAL]
    else:
        seq = [M[r][c] for r in range(14) for c in range(14)]
    return [i for i, b in enumerate(seq) if b == val]


def selections(src, name):
    """dict rotulo -> lista de indices (base 0) dentro de src."""
    N = len(src)
    P = primes_below(N)
    sel = {}
    sel["primes_b0"] = P
    sel["primes_b1"] = [p - 1 for p in P if 1 <= p <= N]          # base 1
    Ps = set(P)
    sel["nonprimes_b0"] = [i for i in range(N) if i not in Ps]
    P1 = set(p - 1 for p in P)
    sel["nonprimes_b1"] = [i for i in range(N) if i not in P1]

    col = sorted(G.COLORED)                                        # 7,15,...,191
    sel["colored"] = [i for i in col if i < N]
    sel["blue"] = [i for i in sorted(G.BLUE_IDX) if i < N]
    sel["yellow"] = [i for i in sorted(G.YELLOW_IDX) if i < N]
    sel["colored_b1"] = [i - 1 for i in col if 1 <= i <= N]
    for c in col:                                                  # multiplos de cada indice colorido
        sel[f"mult{c}"] = [i for i in range(N) if i and i % c == 0]

    MR = G.MATRIX_README
    for order in ("spiral", "rowmajor"):
        for val, tag in ((1, "ones"), (0, "zeros")):
            idx = [i for i in matrix_idx(MR, order, val) if i < N]
            sel[f"mtx_{order}_{tag}"] = idx

    esc = "gi" if name.startswith("faed") else "be"                # escapes candidatos
    sel["esc_gi"] = [i for i, c in enumerate(src) if c in esc]
    sel["esc_gi_c"] = [i for i, c in enumerate(src) if c not in esc]

    for k in range(2, 20):
        for r in range(k):
            sel[f"mod{k}_{r}"] = list(range(r, N, k))

    first, last = {}, {}
    for i, c in enumerate(src):
        first.setdefault(c, i)
        last[c] = i
    sel["first_occ"] = sorted(first.values())
    sel["last_occ"] = sorted(last.values())

    # selecionado PELO outro string (dbbi como saltos / indices)
    other = G.DBBI if name.startswith("faed") else G.FAED
    for base1 in (True, False):
        d = G.digits(other, base1)
        pos, acc = [], 0
        for x in d:
            acc += x
            if acc >= N:
                break
            pos.append(acc)
        sel[f"jump{'1' if base1 else '0'}"] = sorted(set(pos))
        sel[f"jumpmod{'1' if base1 else '0'}"] = sorted({(sum(d[:i + 1]) % N) for i in range(len(d))})
    dv = G.digits(other, True)
    sel["other_esc"] = [i for i in range(N) if dv[i % len(dv)] in (2, 5)]   # b,e
    sel["other_hi"] = [i for i in range(N) if dv[i % len(dv)] >= 5]
    sel["other_odd"] = [i for i in range(N) if dv[i % len(dv)] % 2]

    return {k: v for k, v in sel.items() if len(v) >= 8}


# ------------------------------------------------------------------ materializacoes
PREDS = [
    ("odd", lambda d: d % 2),
    ("hi", lambda d: 1 if d >= 5 else 0),
    ("prime", lambda d: 1 if d in (2, 3, 5, 7) else 0),
    ("gi", lambda d: 1 if d in (7, 9) else 0),          # g=7, i=9
    ("abc", lambda d: 1 if d <= 3 else 0),
]


def int_to_bytes32(v):
    h = format(v, "x")
    if len(h) % 2:
        h = "0" + h
    b = bytes.fromhex(h)
    return b


def materialize(txt, where, do_bits=True, do_pw=True):
    """Recebe a subsequencia de simbolos e roda todos os oraculos."""
    d1 = G.digits(txt, True)        # a=1..i=9
    d0 = G.digits(txt, False)       # a=0..h=8
    if len(d1) < 8:
        return

    # (i) inteiro base-9 (d0) e base-10 (d1) -> bytes
    v9 = 0
    for x in d0:
        v9 = v9 * 9 + x
    v10 = int("".join(str(x) for x in d1))
    for tag, v in (("b9", v9), ("b10", v10)):
        b = int_to_bytes32(v)
        if len(b) >= 32:
            scan_bytes(b, f"{where}/{tag}")
        else:
            pcheck(b.rjust(32, b"\0"), f"{where}/{tag}/rpad")
            pcheck(b.ljust(32, b"\0"), f"{where}/{tag}/lpad")
        pcheck(G.sha(b), f"{where}/{tag}/sha")

    # pares e trios decimais -> bytes
    pairs = bytes((d1[i] * 10 + d1[i + 1]) & 0xFF for i in range(0, len(d1) - 1, 2))
    trios = bytes((d1[i] * 100 + d1[i + 1] * 10 + d1[i + 2]) & 0xFF for i in range(0, len(d1) - 2, 3))
    nib = bytes((d0[i] << 4 | d0[i + 1]) for i in range(0, len(d0) - 1, 2))
    for tag, b in (("pairs", pairs), ("trios", trios), ("nib", nib)):
        if len(b) >= 32:
            scan_bytes(b, f"{where}/{tag}")
        pcheck(G.sha(b), f"{where}/{tag}/sha")

    # (iii) sha256 do texto cru / da string de digitos
    ds = "".join(str(x) for x in d1)
    for tag, s in (("raw", txt), ("digits", ds)):
        h = G.sha(s)
        pcheck(h, f"{where}/{tag}/sha")
        pcheck(G.sha(h), f"{where}/{tag}/sha2")
        if do_pw:
            try_pw(G.shahex(s), f"{where}/{tag}/shahex")
            try_pw(s, f"{where}/{tag}/plain")

    # (ii) bits: 1 bit por simbolo, 256 bits em todo offset
    if do_bits and len(d1) >= 256:
        for pname, f in PREDS:
            bits = "".join(str(f(d)) for d in d1)
            for o in range(0, len(bits) - 255):
                key = int(bits[o:o + 256], 2).to_bytes(32, "big")
                pcheck(key, f"{where}/bits_{pname}@{o}")
            # a mesma chave (offset 0) como senha hex
            k0 = int(bits[:256], 2).to_bytes(32, "big")
            if do_pw:
                try_pw(k0.hex(), f"{where}/bits_{pname}/hexpw")


# ------------------------------------------------------------------ controle positivo
def control():
    """Planta privkey nas 104 posicoes primas de um faed sintetico (base-9) e recupera."""
    import random
    rnd = random.Random(7)
    priv = G.sha(b"control-select-bits")
    v = int.from_bytes(priv, "big")
    P = primes_below(570)                       # 104 primos
    digs = []
    x = v
    for _ in range(len(P)):
        digs.append(x % 9)
        x //= 9
    assert x == 0, "104 digitos base-9 nao cabem"
    digs = digs[::-1]
    s = [rnd.choice("abcdefghi") for _ in range(570)]
    for p, d in zip(P, digs):
        s[p] = chr(97 + d)                      # d0: a=0..i=8
    syn = "".join(s)
    sub = "".join(syn[i] for i in P)
    d0 = G.digits(sub, False)
    v9 = 0
    for y in d0:
        v9 = v9 * 9 + y
    ok = int_to_bytes32(v9).rjust(32, b"\0") == priv
    return ok, priv.hex()


# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    ok, pv = control()
    G.jsonl(LOG, {"control_positive": ok, "planted_priv": pv,
                  "hypothesis": "selecao de posicoes de faed/dbbi (primos, coloridos, matriz, mod k, escapes, janelas, indices do dbbi) -> digitos/bits -> privkey de 32B ou senha"})
    print("controle positivo (privkey plantada nas posicoes primas):", ok, flush=True)
    assert ok, "controle falhou — motor nao recupera alvo plantado"

    sources = {"faed": G.FAED, "dbbi": G.DBBI,
               "faed_dbbi": G.FAED + G.DBBI, "dbbi_faed": G.DBBI + G.FAED}

    for sname, src in sources.items():
        sels = selections(src, sname)
        print(f"[{sname}] {len(sels)} selecoes", flush=True)
        for lbl, idx in sels.items():
            sub = "".join(src[i] for i in idx)
            # so faz senha (AES) para selecoes "principiadas" — mod_k tem muitas variantes
            do_pw = not lbl.startswith(("mod", "mult"))
            materialize(sub, f"{sname}/{lbl}", do_bits=True, do_pw=do_pw)
        print(f"[{sname}] n_tests={NT} t={time.time()-t0:.0f}s", flush=True)

    # janelas deslizantes de 32/64/128/256 simbolos, todo offset, em faed e no concat
    for sname in ("faed", "faed_dbbi"):
        src = sources[sname]
        for L in (32, 64, 128, 256):
            for o in range(0, len(src) - L + 1):
                materialize(src[o:o + L], f"{sname}/win{L}@{o}",
                            do_bits=(L == 256), do_pw=False)
        print(f"[{sname}] janelas ok n_tests={NT} t={time.time()-t0:.0f}s", flush=True)

    # janelas tambem como SENHA (sha256 do texto) — barato, cobre 'thispassword'-like
    for sname in ("faed", "dbbi", "faed_dbbi"):
        src = sources[sname]
        for L in (16, 32, 64):
            for o in range(0, len(src) - L + 1, max(1, L // 8)):
                w = src[o:o + L]
                try_pw(G.shahex(w), f"{sname}/pwwin{L}@{o}")
        print(f"[{sname}] senhas-janela ok n_tests={NT} t={time.time()-t0:.0f}s", flush=True)

    summary = {"family": "select_bits", "n_tests": NT, "hard": len(HARD), "soft": len(SOFT),
               "secs": round(time.time() - t0, 1)}
    G.jsonl(LOG, {"SUMMARY": summary})
    print(json.dumps(summary))
    if SOFT:
        s = sorted(SOFT, key=lambda r: -r["printable"])[:5]
        print("melhores soft:", json.dumps(s, ensure_ascii=False)[:1200])
    if HARD:
        print("HARD HITS:", json.dumps(HARD, ensure_ascii=False)[:4000])




# ------------------------------------------------------------------ FASE 2
# Empacotamento multi-bit (2/3/4 bits por simbolo, todo offset de bit) e leitura
# REVERSA de cada selecao — o que a fase 1 nao cobriu.
def packbits(d0, w):
    """Concatena w bits por simbolo (valor mod 2**w)."""
    m = (1 << w) - 1
    return "".join(format(x & m, f"0{w}b") for x in d0)


def multibit(txt, where):
    d0 = G.digits(txt, False)
    if len(d0) < 64:
        return
    for w in (2, 3, 4):
        bits = packbits(d0, w)
        if len(bits) < 256:
            continue
        for o in range(0, len(bits) - 255):
            pcheck(int(bits[o:o + 256], 2).to_bytes(32, "big"), f"{where}/pack{w}@{o}")


def main2():
    t0 = time.time()
    sources = {"faed": G.FAED, "dbbi": G.DBBI,
               "faed_dbbi": G.FAED + G.DBBI, "dbbi_faed": G.DBBI + G.FAED}
    for sname, src in sources.items():
        sels = selections(src, sname)
        for lbl, idx in sels.items():
            sub = "".join(src[i] for i in idx)
            multibit(sub, f"{sname}/{lbl}")
            multibit(sub[::-1], f"{sname}/{lbl}/rev")
            # reversa tambem nas materializacoes da fase 1 (barato, sem AES)
            materialize(sub[::-1], f"{sname}/{lbl}/rev", do_bits=True, do_pw=False)
        print(f"[fase2 {sname}] n_tests={NT} t={time.time()-t0:.0f}s", flush=True)
    # janelas de 256/128 com empacotamento multi-bit
    for sname in ("faed", "faed_dbbi"):
        src = sources[sname]
        for L in (128, 256):
            for o in range(0, len(src) - L + 1, 4):
                multibit(src[o:o + L], f"{sname}/win{L}@{o}")
        print(f"[fase2 janelas {sname}] n_tests={NT} t={time.time()-t0:.0f}s", flush=True)
    summary = {"family": "select_bits/fase2", "n_tests": NT, "hard": len(HARD),
               "soft": len(SOFT), "secs": round(time.time() - t0, 1)}
    G.jsonl(LOG, {"SUMMARY2": summary})
    print(json.dumps(summary))
    if HARD:
        print("HARD HITS:", json.dumps(HARD, ensure_ascii=False)[:4000])


if __name__ == "__main__":
    (main2 if len(sys.argv) > 1 else main)()
