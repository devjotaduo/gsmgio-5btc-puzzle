# -*- coding: utf-8 -*-
"""
Straddling checkerboard (VIC) na GPU. Sacada: para (e1,e2) fixos, a estrutura do
decode (quais posicoes de saida vem de topo/linha1/linha2 e com que indice) NAO
depende da permutacao das letras — so dos valores dos digitos. Entao pre-computo,
para cada par (e1,e2), uma sequencia de SLOTS (indices 0..24 em perm) e o decode
vira perm[slot_seq] = um gather vetorizavel, idêntico em custo ao Bifid GPU.

GA sobre perm25 (25 letras), ciclando os 36 pares (e1,e2). Oraculos DUROS no melhor.
Modo --control valida que recupera um checkerboard de ingles conhecido.
"""
import os, sys, json, time, argparse, itertools, random
import torch
import oracles as O
from scorer import Scorer
from gpu_search import (DEV, ALPHA25, AZ, _az_map, _qgram_tensor, sq_to_perm,
                        perm_to_sq, theme_seeds, O_append, hard_oracles_on)

HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

def faed_digits():
    s = O.sources()["faed"]
    return [ord(c) - ord('a') + 1 for c in s]  # a=1..i=9

def slot_seq(digits, e1, e2):
    """Sequencia de slots (0..24) para (e1,e2). top->0..6, row1->7..15, row2->16..24."""
    col_order = [c for c in range(1, 10) if c != e1 and c != e2]  # 7 colunas do topo
    ci = {c: k for k, c in enumerate(col_order)}
    out = []; i = 0; n = len(digits)
    while i < n:
        d = digits[i]
        if d == e1 and i + 1 < n:
            out.append(7 + (digits[i + 1] - 1)); i += 2
        elif d == e2 and i + 1 < n:
            out.append(16 + (digits[i + 1] - 1)); i += 2
        else:
            out.append(ci.get(d, 0)); i += 1   # d==e1/e2 no fim: cai no topo (col morta ~0)
        # nota: d2 in 1..9 -> indice 0..8 dentro da linha (9 slots) OK
    return out

def build_slot_tensors(digits):
    pairs = list(itertools.combinations(range(1, 10), 2))  # 36 pares
    seqs = {}
    for (e1, e2) in pairs:
        s = slot_seq(digits, e1, e2)
        seqs[(e1, e2)] = torch.tensor(s, dtype=torch.long, device=DEV)
    return pairs, seqs

def score_batch(perms, seq_t, azmap, QT):
    out = perms[:, seq_t]          # (B, L) valores 0..24 (gather vetorizado)
    az = azmap[out]                # (B, L) 0..25
    idx = ((az[:, :-3] * 26 + az[:, 1:-2]) * 26 + az[:, 2:-1]) * 26 + az[:, 3:]
    return QT[idx].mean(dim=1)

def decode_text(perm, seq_t):
    out = perm[seq_t]
    return "".join(ALPHA25[i] for i in out.tolist())

# ---------------- controle ----------------
def control():
    import re
    from checkerboard import encode, decode
    azmap = _az_map(); QT, floor = _qgram_tensor()
    sc = Scorer()
    en = re.sub(r"[^A-Z]", "", ("THEQUICKBROWNFOXIUMPSOVERALAZYDOGTHISISATESTOFTHESTRADDLING"
                                "CHECKERBOARDCIPHERHIDDENPAYLOAD" * 5).upper()).replace("J", "I")[:400]
    key = list(ALPHA25); random.seed(11); random.shuffle(key); key = "".join(key)
    e1, e2 = 3, 7
    digits = encode(en, key, e1, e2)
    assert decode(digits, key, e1, e2) == en
    seq_t = torch.tensor(slot_seq(digits, e1, e2), dtype=torch.long, device=DEV)
    # confere que o decode GPU (com a key) == original
    assert decode_text(sq_to_perm(key), seq_t) == en, "decode GPU != original"
    print(f"[ok] roundtrip + decode GPU==CPU ({len(digits)} digitos, saida {seq_t.numel()})")
    # GA para recuperar
    B = 8192; perms = torch.stack([torch.randperm(25, device=DEV) for _ in range(B)])
    best = -9; bestperm = None; t0 = time.time()
    for g in range(2500):
        s = score_batch(perms, seq_t, azmap, QT); o = torch.argsort(s, descending=True)
        if s[o[0]].item() > best:
            best = s[o[0]].item(); bestperm = perms[o[0]].clone()
        surv = perms[o[:B // 2]]; ch = surv.clone()
        for _ in range(2):
            i = torch.randint(0, 25, (ch.shape[0],), device=DEV); j = torch.randint(0, 25, (ch.shape[0],), device=DEV)
            ar = torch.arange(ch.shape[0], device=DEV); t = ch[ar, i].clone(); ch[ar, i] = ch[ar, j]; ch[ar, j] = t
        perms = torch.cat([surv, ch])[:B]
        if g % 40 == 0:
            k = B // 8; perms[-k:] = torch.stack([torch.randperm(25, device=DEV) for _ in range(k)])
            if bestperm is not None: perms[0] = bestperm
    rec = decode_text(bestperm, seq_t)
    m = sum(a == c for a, c in zip(rec, en)) / len(en)
    print(f"[controle] best={best:.3f} match={m:.0%} ({time.time()-t0:.0f}s)")
    print(f"  rec[:64]={rec[:64]}")
    print(f"  org[:64]={en[:64]}")
    return m

# ---------------- busca real ----------------
def run(args):
    torch.manual_seed(int(time.time()) & 0xffff)
    azmap = _az_map(); QT, floor = _qgram_tensor()
    digits = faed_digits()
    pairs, seqs = build_slot_tensors(digits)
    seeds = theme_seeds()
    B = args.pop
    perms = torch.stack([torch.randperm(25, device=DEV) for _ in range(B)])
    for i, s in enumerate(seeds[:B]):
        perms[i] = sq_to_perm(s)
    best_score = -1e9; best = None
    per_best = {p: -1e9 for p in pairs}
    gen = 0; t0 = time.time(); last_hb = t0
    deadline = t0 + args.max_hours * 3600 if args.max_hours else None
    phase = args.phase
    print(f"[{time.strftime('%H:%M:%S')}] GPU checkerboard | pairs={len(pairs)} pop={B} "
          f"phase={phase} max_h={args.max_hours} bt={args.breakthrough}")
    while True:
        gen += 1
        e1, e2 = pairs[(gen // phase) % len(pairs)]
        seq_t = seqs[(e1, e2)]
        s = score_batch(perms, seq_t, azmap, QT)
        order = torch.argsort(s, descending=True)
        gbest = s[order[0]].item()
        if gbest > per_best[(e1, e2)]:
            per_best[(e1, e2)] = gbest
        if gbest > best_score:
            best_score = gbest
            bperm = perms[order[0]].clone()
            pt = decode_text(bperm, seq_t)
            best = (perm_to_sq(bperm), (e1, e2), pt)
            meta = {"gen": gen, "score": round(best_score, 3), "escapes": [e1, e2],
                    "square": best[0], "head": pt[:40]}
            print(f"[{time.strftime('%H:%M:%S')}] gen{gen} NEW BEST {best_score:.3f} e=({e1},{e2}) head={pt[:32]}")
            O_append("cb_candidates.jsonl", {"ts": time.strftime('%H:%M:%S'), **meta, "plaintext": pt})
            hit = hard_oracles_on(pt, meta)
            if hit:
                json.dump(hit, open(os.path.join(OUT, "SOLVED.json"), "w"), ensure_ascii=False, indent=2)
                print("\n!!! SOLVE (checkerboard) — out/SOLVED.json"); return
            if best_score >= args.breakthrough:
                json.dump({**meta, "plaintext": pt, "reason": "readable checkerboard"},
                          open(os.path.join(OUT, "BREAKTHROUGH.json"), "w"), ensure_ascii=False, indent=2)
                print(f"\n*** BREAKTHROUGH checkerboard {best_score:.3f} ***"); return
        surv = perms[order[:B // 2]]; ch = surv.clone()
        for _ in range(args.mut):
            i = torch.randint(0, 25, (ch.shape[0],), device=DEV); j = torch.randint(0, 25, (ch.shape[0],), device=DEV)
            ar = torch.arange(ch.shape[0], device=DEV); t = ch[ar, i].clone(); ch[ar, i] = ch[ar, j]; ch[ar, j] = t
        perms = torch.cat([surv, ch])[:B]
        if gen % phase == 0:
            k = B - B // 8; perms[B // 8:] = torch.stack([torch.randperm(25, device=DEV) for _ in range(k)])
            for i, s2 in enumerate(theme_seeds()[:B // 8]): perms[i] = sq_to_perm(s2)
            if best: perms[0] = sq_to_perm(best[0])
        elif gen % 40 == 0:
            k = B // 8; perms[-k:] = torch.stack([torch.randperm(25, device=DEV) for _ in range(k)])
            if best: perms[0] = sq_to_perm(best[0])
        if time.time() - last_hb > 15:
            last_hb = time.time(); el = time.time() - t0
            st = {"gen": gen, "cur_escapes": [e1, e2], "best_score": round(best_score, 3),
                  "sq_per_s": round(gen * B / el), "elapsed_s": int(el),
                  "remaining_h": round((deadline - time.time()) / 3600, 2) if deadline else None,
                  "best_head": best[2][:32] if best else None, "best_escapes": list(best[1]) if best else None}
            json.dump(st, open(os.path.join(OUT, "cb_status.json"), "w"), ensure_ascii=False, indent=2)
            print(f"[{time.strftime('%H:%M:%S')}] gen={gen} e=({e1},{e2}) best={best_score:.3f} {gen*B/el/1e6:.1f}M sq/s")
        if deadline and time.time() >= deadline:
            print(f"[fim] {args.max_hours}h. best={best_score:.3f}")
            json.dump({"best_score": round(best_score, 3), "best": [best[0], list(best[1]), best[2]] if best else None},
                      open(os.path.join(OUT, "cb_final.json"), "w"), ensure_ascii=False, indent=2)
            return

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", action="store_true")
    ap.add_argument("--pop", type=int, default=8192)
    ap.add_argument("--mut", type=int, default=2)
    ap.add_argument("--phase", type=int, default=300)
    ap.add_argument("--max-hours", type=float, default=0)
    ap.add_argument("--breakthrough", type=float, default=-4.8)
    a = ap.parse_args()
    if a.control:
        control()
    else:
        run(a)
