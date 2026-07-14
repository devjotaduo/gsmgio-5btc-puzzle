# -*- coding: utf-8 -*-
"""
Ataque BASE-3 / TRIFID (trigramas) ao faed na GPU.
Motivacao estrutural: faed = 9 simbolos = 3^2; 570 simbolos x 2 trits = 1140 = 3 x 380.
Cada simbolo a-i -> 2 trits (base 3); a corrente de 1140 trits agrupada em 380
trigramas (0..26) -> alfabeto de 27 letras. Se o faed for prosa em base-3, sai
uma mensagem de 380 letras (tamanho de senha — casa com 'faed=prosa').

Estrutura decode (sem transposicao / com seriacao trifid por periodo):
  para (ordem-de-trits, periodo) fixos, o VALOR de cada trigrama e fixo (so depende
  do faed) -> saida = alfabeto27[trigram_value] = gather vetorizavel (GPU), igual
  ao truque de Bifid/checkerboard. GA sobre a permutacao de 27 letras.
Modo --control valida recuperando ingles conhecido (encode->decode->GA).
"""
import os, sys, json, time, argparse, itertools, random
import torch
import oracles as O
from scorer import Scorer, build as build_qgram

HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)
DEV = "cuda" if torch.cuda.is_available() else "cpu"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA27 = AZ + "."                       # 26 letras + 1 filler = 27

def _az_map27():
    # indice 0..26 no alfabeto27 -> indice A-Z(0..25); '.' -> 26 (ignorado no score)
    return torch.tensor([AZ.index(c) if c in AZ else 26 for c in ALPHA27],
                        dtype=torch.long, device=DEV)

def _qgram_tensor():
    tab, floor = build_qgram()
    # estende p/ indice 26 (filler) com piso, e usa base 27 no score p/ pular filler
    return torch.tensor(tab, dtype=torch.float32, device=DEV), floor

def faed_trits(order="hilo"):
    """faed (a-i) -> corrente de trits (base 3). a=0..i=8 -> (v//3, v%3)."""
    s = O.sources()["faed"]
    trits = []
    for c in s:
        v = ord(c) - ord('a')            # 0..8
        hi, lo = v // 3, v % 3
        trits += [hi, lo] if order == "hilo" else [lo, hi]
    return trits                          # 1140 trits

def seriate(trits, period):
    """Seriacao trifid: reordena a corrente de trits por periodo (blocos de 3xP).
    period=0 -> sem transposicao (trigramas consecutivos)."""
    n = len(trits)
    if not period:
        return trits
    out = []
    for off in range(0, n, 3 * period):
        blk = trits[off:off + 3 * period]
        L = len(blk) // 3 * 3
        blk = blk[:L]
        p = L // 3
        # 3 linhas x p colunas (preenche por linha), le por coluna
        rows = [blk[0:p], blk[p:2 * p], blk[2 * p:3 * p]]
        for c in range(p):
            out += [rows[0][c], rows[1][c], rows[2][c]]
    return out

def trigram_values(order, period):
    trits = seriate(faed_trits(order), period)
    L = len(trits) // 3 * 3
    vals = [9 * trits[i] + 3 * trits[i + 1] + trits[i + 2] for i in range(0, L, 3)]
    return torch.tensor(vals, dtype=torch.long, device=DEV)   # 0..26

# ---------- score (base 27, pula filler) ----------
def score_batch(perms, val_seq, azmap, QT):
    out = perms[:, val_seq]              # (B,L) 0..26 (indice no alfabeto27)
    az = azmap[out]                      # (B,L) 0..25 (ou 26 p/ filler)
    a0, a1, a2, a3 = az[:, :-3], az[:, 1:-2], az[:, 2:-1], az[:, 3:]
    idx = ((a0 * 26 + a1) * 26 + a2) * 26 + a3
    mask = (a0 < 26) & (a1 < 26) & (a2 < 26) & (a3 < 26)
    idx = idx.clamp(max=26**4 - 1)
    sc = QT[idx] * mask
    return sc.sum(dim=1) / mask.sum(dim=1).clamp(min=1)

def decode_text(perm, val_seq):
    return "".join(ALPHA27[i] for i in perm[val_seq].tolist())

def perm_to_sq(perm): return "".join(ALPHA27[i] for i in perm.tolist())
def sq_to_perm(sq): return torch.tensor([ALPHA27.index(c) for c in sq], dtype=torch.long, device=DEV)

def hard_oracles_on(pt, meta):
    import hashlib
    for s in (pt, pt.replace(".", "")):
        for f in {s, s.lower(), hashlib.sha256(s.encode()).hexdigest()}:
            h = O.aes_open(f)
            if h: return {"kind": "aes_open", "pw": f[:40], "hits": h, **meta}
        for c in (hashlib.sha256(s.encode()).digest(), hashlib.sha256(s.lower().encode()).digest()):
            r = O.check_privkey(c)
            if r: return {"kind": "privkey", "hit": r, **meta}
    return None

# ---------------- controle ----------------
def control():
    import re
    azmap = _az_map27(); QT, floor = _qgram_tensor()
    # ingles -> trigramas (via alfabeto27) -> trits -> simbolos a-i -> recupera
    en = re.sub(r"[^A-Z]", "", ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGSECRETPAYLOADHIDDEN"
                                "INSIDETHEPUZZLEPROSEPASSWORD" * 6).upper())
    key = list(ALPHA27); random.seed(5); random.shuffle(key); key = "".join(key)
    inv = {c: i for i, c in enumerate(key)}
    L = 378
    en = en[:L]
    vals = [inv[c] for c in en]                     # 0..26
    trits = []
    for v in vals: trits += [v // 9, (v // 3) % 3, v % 3]
    # empacota trits em pares -> simbolos a-i (ordem hilo)
    assert len(trits) % 2 == 0
    syms = "".join("abcdefghi"[trits[i] * 3 + trits[i + 1]] for i in range(0, len(trits), 2))
    # verifica que a fonte reproduz: monkeypatch faed_trits usando esses simbolos
    def local_trits(order="hilo"):
        t = []
        for c in syms:
            v = ord(c) - ord('a'); t += [v // 3, v % 3]
        return t
    trits2 = local_trits()
    valseq = torch.tensor([9*trits2[i]+3*trits2[i+1]+trits2[i+2] for i in range(0,len(trits2)//3*3,3)],
                          dtype=torch.long, device=DEV)
    assert decode_text(sq_to_perm(key), valseq) == en, "roundtrip falhou"
    print(f"[ok] roundtrip base-3 ({len(syms)} simbolos -> {valseq.numel()} letras)")
    # GA recupera
    B = 8192; perms = torch.stack([torch.randperm(27, device=DEV) for _ in range(B)])
    best = -9; bestperm = None; t0 = time.time()
    for g in range(2500):
        s = score_batch(perms, valseq, azmap, QT); o = torch.argsort(s, descending=True)
        if s[o[0]].item() > best: best = s[o[0]].item(); bestperm = perms[o[0]].clone()
        surv = perms[o[:B//2]]; ch = surv.clone()
        for _ in range(2):
            i=torch.randint(0,27,(ch.shape[0],),device=DEV); j=torch.randint(0,27,(ch.shape[0],),device=DEV)
            ar=torch.arange(ch.shape[0],device=DEV); t=ch[ar,i].clone(); ch[ar,i]=ch[ar,j]; ch[ar,j]=t
        perms = torch.cat([surv, ch])[:B]
        if g % 40 == 0:
            k=B//8; perms[-k:]=torch.stack([torch.randperm(27,device=DEV) for _ in range(k)])
            if bestperm is not None: perms[0]=bestperm
    rec = decode_text(bestperm, valseq)
    m = sum(a==c for a,c in zip(rec,en))/len(en)
    print(f"[controle] best={best:.3f} match={m:.0%} ({time.time()-t0:.0f}s)")
    print(f"  rec[:64]={rec[:64]}"); print(f"  org[:64]={en[:64]}")
    return m

# ---------------- busca real ----------------
def run(args):
    torch.manual_seed(int(time.time()) & 0xffff)
    azmap = _az_map27(); QT, floor = _qgram_tensor()
    # variantes: ordem de trits x periodo de seriacao (0=sem)
    variants = [(o, p) for o in ("hilo", "lohi") for p in (0, 5, 7, 10, 19, 38, 95, 190, 380)]
    seqs = [(o, p, trigram_values(o, p)) for (o, p) in variants]
    B = args.pop
    perms = torch.stack([torch.randperm(27, device=DEV) for _ in range(B)])
    best_score = -1e9; best = None
    gen = 0; t0 = time.time(); last_hb = t0
    deadline = t0 + args.max_hours * 3600 if args.max_hours else None
    phase = args.phase
    print(f"[{time.strftime('%H:%M:%S')}] GPU trifid | variants={len(seqs)} pop={B} "
          f"phase={phase} max_h={args.max_hours} bt={args.breakthrough}")
    while True:
        gen += 1
        o, p, val_seq = seqs[(gen // phase) % len(seqs)]
        s = score_batch(perms, val_seq, azmap, QT)
        order = torch.argsort(s, descending=True)
        gbest = s[order[0]].item()
        if gbest > best_score:
            best_score = gbest
            bperm = perms[order[0]].clone()
            pt = decode_text(bperm, val_seq)
            best = (perm_to_sq(bperm), (o, p), pt)
            meta = {"gen": gen, "score": round(best_score, 3), "order": o, "period": p, "head": pt[:40]}
            print(f"[{time.strftime('%H:%M:%S')}] gen{gen} NEW BEST {best_score:.3f} {o} per={p} head={pt[:32]}")
            O_append("tri_candidates.jsonl", {"ts": time.strftime('%H:%M:%S'), **meta, "plaintext": pt})
            hit = hard_oracles_on(pt, meta)
            if hit:
                json.dump(hit, open(os.path.join(OUT, "SOLVED.json"), "w"), ensure_ascii=False, indent=2)
                print("\n!!! SOLVE (trifid) — out/SOLVED.json"); return
            if best_score >= args.breakthrough:
                json.dump({**meta, "plaintext": pt, "reason": "readable trifid"},
                          open(os.path.join(OUT, "BREAKTHROUGH.json"), "w"), ensure_ascii=False, indent=2)
                print(f"\n*** BREAKTHROUGH trifid {best_score:.3f} ***"); return
        surv = perms[order[:B//2]]; ch = surv.clone()
        for _ in range(args.mut):
            i=torch.randint(0,27,(ch.shape[0],),device=DEV); j=torch.randint(0,27,(ch.shape[0],),device=DEV)
            ar=torch.arange(ch.shape[0],device=DEV); t=ch[ar,i].clone(); ch[ar,i]=ch[ar,j]; ch[ar,j]=t
        perms = torch.cat([surv, ch])[:B]
        if gen % phase == 0:
            k=B-B//8; perms[B//8:]=torch.stack([torch.randperm(27,device=DEV) for _ in range(k)])
            if best: perms[0]=sq_to_perm(best[0])
        elif gen % 40 == 0:
            k=B//8; perms[-k:]=torch.stack([torch.randperm(27,device=DEV) for _ in range(k)])
            if best: perms[0]=sq_to_perm(best[0])
        if time.time() - last_hb > 15:
            last_hb = time.time(); el = time.time() - t0
            st = {"gen": gen, "cur": [o, p], "best_score": round(best_score, 3),
                  "sq_per_s": round(gen*B/el), "elapsed_s": int(el),
                  "remaining_h": round((deadline-time.time())/3600, 2) if deadline else None,
                  "best_head": best[2][:32] if best else None, "best_variant": list(best[1]) if best else None}
            json.dump(st, open(os.path.join(OUT, "tri_status.json"), "w"), ensure_ascii=False, indent=2)
            print(f"[{time.strftime('%H:%M:%S')}] gen={gen} {o},{p} best={best_score:.3f} {gen*B/el/1e6:.1f}M sq/s")
        if deadline and time.time() >= deadline:
            print(f"[fim] {args.max_hours}h. best={best_score:.3f}"); return

def O_append(fname, obj):
    with open(os.path.join(OUT, fname), "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", action="store_true")
    ap.add_argument("--pop", type=int, default=8192)
    ap.add_argument("--mut", type=int, default=2)
    ap.add_argument("--phase", type=int, default=300)
    ap.add_argument("--max-hours", type=float, default=0)
    ap.add_argument("--breakthrough", type=float, default=-4.8)
    a = ap.parse_args()
    control() if a.control else run(a)
