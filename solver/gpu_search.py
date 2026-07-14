# -*- coding: utf-8 -*-
"""
Busca GENETICA na GPU (PyTorch/CUDA) sobre a criptanalise de Bifid do faed.
Avalia milhares de quadrados 25-letras por geracao, maximizando o score de
quadgramas EN da saida. Motor "incansavel": gradiente continuo (ao contrario do
oraculo AES). A cada novo melhor plaintext, roda os oraculos DUROS na CPU.

Corretude: o modo --selftest confirma que o decode Bifid batelado na GPU
reproduz "BTCSEED" para o quadrado CANON (identico ao caminho CPU verificado).
"""
import os, sys, json, time, argparse
import torch
import oracles as O
from scorer import Scorer, build as build_qgram

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out"); os.makedirs(OUT, exist_ok=True)
DEV = "cuda" if torch.cuda.is_available() else "cpu"

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"           # 25 letras, I=J (sem J)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"
DIVISORS_570 = [570, 285, 190, 114, 95, 57, 38, 30, 19, 15, 10, 6, 5, 3, 2]

def _az_map():
    # alpha25 index -> A-Z(26) index
    return torch.tensor([AZ.index(c) for c in ALPHA25], dtype=torch.long, device=DEV)

def _qgram_tensor():
    tab, floor = build_qgram()
    return torch.tensor(tab, dtype=torch.float32, device=DEV), floor

def _ct_idx(target="faed"):
    s = O.sources()[target].upper().replace("J", "I")
    return torch.tensor([ALPHA25.index(c) for c in s], dtype=torch.long, device=DEV), s

def sq_to_perm(square):
    return torch.tensor([ALPHA25.index(c) for c in square], dtype=torch.long, device=DEV)

def perm_to_sq(perm):
    return "".join(ALPHA25[i] for i in perm.tolist())

class GPUBifid:
    def __init__(self, target="faed"):
        self.ct, self.ct_str = _ct_idx(target)     # (L,) valores 0..8
        self.L = self.ct.numel()
        self.azmap = _az_map()
        self.QT, self.floor = _qgram_tensor()

    def decrypt(self, perms, period):
        """perms: (B,25) permutacoes (long). period qualquer (blocos completos +
        bloco-resto). Retorna letras (B,L) em 0..24. Layout de blocos e identico
        para todos os quadrados do batch, entao vetoriza limpo."""
        B = perms.shape[0]; L = self.L; P = period
        nb = L // P; r = L - nb * P
        inv = torch.argsort(perms, dim=1)          # (B,25): posicao de cada letra
        pos = inv[:, self.ct]                       # (B,L)
        row = pos // 5; col = pos % 5               # (B,L)
        outs = []
        if nb > 0:
            rf = row[:, :nb * P].view(B, nb, P); cf = col[:, :nb * P].view(B, nb, P)
            seq = torch.empty(B, nb, 2 * P, dtype=torch.long, device=DEV)
            seq[..., 0::2] = rf; seq[..., 1::2] = cf
            op = (seq[..., :P] * 5 + seq[..., P:]).reshape(B, nb * P)
            outs.append(op)
        if r > 0:
            rr = row[:, nb * P:].view(B, 1, r); cr = col[:, nb * P:].view(B, 1, r)
            seqr = torch.empty(B, 1, 2 * r, dtype=torch.long, device=DEV)
            seqr[..., 0::2] = rr; seqr[..., 1::2] = cr
            opr = (seqr[..., :r] * 5 + seqr[..., r:]).reshape(B, r)
            outs.append(opr)
        out_pos = torch.cat(outs, dim=1)            # (B,L)
        return torch.gather(perms, 1, out_pos)

    def score(self, perms, period):
        """Score medio de quadgramas EN por quadrado. (B,)"""
        out = self.decrypt(perms, period)          # (B,L) 0..24
        az = self.azmap[out]                        # (B,L) 0..25
        idx = ((az[:, :-3] * 26 + az[:, 1:-2]) * 26 + az[:, 2:-1]) * 26 + az[:, 3:]
        return self.QT[idx].mean(dim=1)             # (B,)

    def plaintext(self, perm, period):
        out = self.decrypt(perm.unsqueeze(0), period)[0]
        return "".join(ALPHA25[i] for i in out.tolist())


def theme_seeds():
    from runner import base_alphabets
    seeds = []
    for a in base_alphabets():
        a = a.upper().replace("J", "I")
        if len(set(a)) == 25:
            seeds.append(a)
    if CANON not in seeds: seeds.insert(0, CANON)
    return seeds


def hard_oracles_on(pt, meta):
    """Roda oraculos duros no plaintext. Retorna dict de solve ou None."""
    import dsl
    hyp_forms = [pt, pt[7:]]  # full e pos-header
    for s in hyp_forms:
        # senha AES
        for f in {s, s.lower(), O.hashlib.sha256(s.encode()).hexdigest()}:
            hits = O.aes_open(f)
            if hits:
                return {"kind": "aes_open", "pw_preview": f[:40], "hits": hits, **meta}
        # priv key
        for cand in (O.hashlib.sha256(s.encode()).digest(),
                     O.hashlib.sha256(s.lower().encode()).digest()):
            r = O.check_privkey(cand)
            if r:
                return {"kind": "privkey", "hit": r, **meta}
    return None


def run(args):
    torch.manual_seed(int(time.time()) & 0xffff)
    eng = GPUBifid(args.target)
    scorer = Scorer()  # p/ verificar plaintext no path CPU quando achar melhor
    seeds = theme_seeds()
    B = args.pop
    # populacao inicial: sementes + aleatorios
    perms = torch.stack([torch.randperm(25, device=DEV) for _ in range(B)])
    for i, s in enumerate(seeds[:B]):
        perms[i] = sq_to_perm(s)
    periods = args.periods
    best_score = -1e9; best = None
    per_best = {p: -1e9 for p in periods}     # melhor por periodo (rigor)
    gen = 0; t0 = time.time(); last_hb = t0
    deadline = t0 + args.max_hours * 3600 if args.max_hours else None
    phase = args.phase                         # gens dedicadas por periodo antes de ciclar

    print(f"[{time.strftime('%H:%M:%S')}] GPU search | dev={DEV} pop={B} periods={periods} "
          f"phase={phase} max_h={args.max_hours} bt={args.breakthrough} target={args.target}")
    while True:
        gen += 1
        # PERIODO ATUAL (ciclo dedicado: cada periodo recebe 'phase' geracoes seguidas)
        per = periods[(gen // phase) % len(periods)]
        sc = eng.score(perms, per)             # (B,) score so do periodo atual
        order = torch.argsort(sc, descending=True)
        gbest = sc[order[0]].item()
        if gbest > per_best[per]:
            per_best[per] = gbest
        if gbest > best_score:
            best_score = gbest
            bsq = perms[order[0]].clone()
            pt = eng.plaintext(bsq, per)
            best = (perm_to_sq(bsq), per, pt)
            meta = {"gen": gen, "score": round(best_score, 3), "period": per,
                    "square": best[0], "head": pt[:40]}
            print(f"[{time.strftime('%H:%M:%S')}] gen{gen} NEW BEST {best_score:.3f} per={per} "
                  f"sq={best[0]} head={pt[:32]}")
            O_append("gpu_candidates.jsonl", {"ts": time.strftime('%H:%M:%S'), **meta, "plaintext": pt})
            # oraculos DUROS
            hit = hard_oracles_on(pt, meta)
            if hit:
                with open(os.path.join(OUT, "SOLVED.json"), "w", encoding="utf-8") as f:
                    json.dump(hit, f, ensure_ascii=False, indent=2)
                print("\n" + "=" * 60 + f"\n!!! SOLVE VERIFICADO POR ORACULO !!!\n{json.dumps(hit, indent=2)}\n" + "=" * 60)
                return
            # BREAKTHROUGH de legibilidade (pontuacao ideal p/ ingles): para p/ revisao
            if best_score >= args.breakthrough:
                with open(os.path.join(OUT, "BREAKTHROUGH.json"), "w", encoding="utf-8") as f:
                    json.dump({**meta, "plaintext": pt, "reason": "readable score >= breakthrough"},
                              f, ensure_ascii=False, indent=2)
                print(f"\n*** BREAKTHROUGH: score {best_score:.3f} >= {args.breakthrough} — parando p/ revisao ***")
                return
        # nova geracao: elite (metade melhor) + mutacoes
        survivors = perms[order[:B // 2]]
        childs = survivors.clone()
        for _ in range(args.mut):
            i = torch.randint(0, 25, (childs.shape[0],), device=DEV)
            j = torch.randint(0, 25, (childs.shape[0],), device=DEV)
            ar = torch.arange(childs.shape[0], device=DEV)
            tmp = childs[ar, i].clone()
            childs[ar, i] = childs[ar, j]; childs[ar, j] = tmp
        perms = torch.cat([survivors, childs], dim=0)[:B]
        # ao TROCAR de periodo, reinicia diversidade (busca dedicada nova)
        if gen % phase == 0:
            k = B - B // 8
            fresh = torch.stack([torch.randperm(25, device=DEV) for _ in range(k)])
            perms[B // 8:] = fresh
            for i, s in enumerate(theme_seeds()[:B // 8]):
                perms[i] = sq_to_perm(s)
            if best:
                perms[0] = sq_to_perm(best[0])
        elif gen % args.fresh_every == 0:
            k = B // 8
            perms[-k:] = torch.stack([torch.randperm(25, device=DEV) for _ in range(k)])
            if best: perms[0] = sq_to_perm(best[0])
        # heartbeat
        if time.time() - last_hb > 15:
            last_hb = time.time()
            el = time.time() - t0
            st = {"gen": gen, "cur_period": per, "best_score": round(best_score, 3),
                  "per_best": {str(p): round(v, 3) for p, v in per_best.items()},
                  "sq_per_s": round(gen * B / el), "elapsed_s": int(el),
                  "remaining_h": round((deadline - time.time()) / 3600, 2) if deadline else None,
                  "best_head": best[2][:32] if best else None,
                  "best_period": best[1] if best else None, "best_square": best[0] if best else None}
            with open(os.path.join(OUT, "gpu_status.json"), "w", encoding="utf-8") as f:
                json.dump(st, f, ensure_ascii=False, indent=2)
            print(f"[{time.strftime('%H:%M:%S')}] gen={gen} per={per} best={best_score:.3f} "
                  f"{gen*B/el/1e6:.1f}M sq/s")
        if deadline and time.time() >= deadline:
            print(f"[fim] limite de {args.max_hours}h. best={best_score:.3f}")
            with open(os.path.join(OUT, "gpu_final.json"), "w", encoding="utf-8") as f:
                json.dump({"best_score": round(best_score, 3), "best": best,
                           "per_best": {str(p): round(v, 3) for p, v in per_best.items()}},
                          f, ensure_ascii=False, indent=2)
            return
        if args.max_gen and gen >= args.max_gen:
            print(f"[fim] max_gen. best={best_score:.3f}")
            return

def O_append(fname, obj):
    with open(os.path.join(OUT, fname), "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def selftest():
    eng = GPUBifid("faed")
    perm = sq_to_perm(CANON)
    pt = eng.plaintext(perm, 570)
    print("CANON GPU decode head:", pt[:12])
    assert pt.startswith("BTCSEED"), f"FALHA: GPU nao reproduz BTCSEED (got {pt[:12]})"
    sc = eng.score(perm.unsqueeze(0), 570).item()
    from scorer import Scorer
    from search import bifid_decrypt
    cpu_pt = bifid_decrypt(O.sources()["faed"].upper(), CANON, 570)
    assert pt == cpu_pt, "FALHA: GPU != CPU decode"
    print(f"[ok] GPU==CPU decode (per=570), CANON score={sc:.3f}")
    # periodo irregular (nao divide 570): GPU deve bater com CPU
    for per in (7, 13, 11):
        gp = eng.plaintext(perm, per)
        cp = bifid_decrypt(O.sources()["faed"].upper(), CANON, per)
        assert gp == cp, f"FALHA: GPU!=CPU em per={per}"
    print("[ok] GPU==CPU decode em periodos irregulares 7/13/11")
    print("=== GPU SELFTEST OK ===")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--pop", type=int, default=8192)
    ap.add_argument("--mut", type=int, default=2)
    ap.add_argument("--fresh-every", type=int, default=40)
    ap.add_argument("--periods", type=int, nargs="+",
                    default=[3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,25,30,38,57,570])
    ap.add_argument("--target", default="faed")
    ap.add_argument("--max-gen", type=int, default=0)
    ap.add_argument("--max-hours", type=float, default=0, help="parar apos N horas (0=infinito)")
    ap.add_argument("--phase", type=int, default=250, help="geracoes dedicadas por periodo antes de ciclar")
    ap.add_argument("--breakthrough", type=float, default=-4.8,
                    help="score de legibilidade que dispara BREAKTHROUGH e para (ingles ~ -4.3)")
    a = ap.parse_args()
    if a.selftest:
        selftest()
    else:
        run(a)
