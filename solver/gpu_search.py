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
    gen = 0; t0 = time.time(); last_hb = t0
    elite_n = max(4, B // 16)

    print(f"[{time.strftime('%H:%M:%S')}] GPU search | dev={DEV} pop={B} periods={periods} target={args.target}")
    while True:
        gen += 1
        # avalia todos os periodos, pega o melhor por quadrado
        best_per_sq = torch.full((B,), -1e9, device=DEV)
        best_period_sq = torch.zeros(B, dtype=torch.long, device=DEV)
        for per in periods:
            sc = eng.score(perms, per)
            better = sc > best_per_sq
            best_per_sq = torch.where(better, sc, best_per_sq)
            best_period_sq = torch.where(better, torch.tensor(per, device=DEV), best_period_sq)
        order = torch.argsort(best_per_sq, descending=True)
        top = order[:elite_n]
        gbest = best_per_sq[top[0]].item()
        if gbest > best_score:
            best_score = gbest
            bi = top[0].item()
            bp = int(best_period_sq[bi].item())
            bsq = perms[bi].clone()
            pt = eng.plaintext(bsq, bp)
            best = (perm_to_sq(bsq), bp, pt)
            meta = {"gen": gen, "score": round(best_score, 3), "period": bp,
                    "square": best[0], "head": pt[:40]}
            print(f"[{time.strftime('%H:%M:%S')}] gen{gen} NEW BEST {best_score:.3f} per={bp} "
                  f"sq={best[0]} head={pt[:32]}")
            O_append("gpu_candidates.jsonl", {"ts": time.strftime('%H:%M:%S'), **meta, "plaintext": pt})
            # oraculos duros
            hit = hard_oracles_on(pt, meta)
            if hit:
                with open(os.path.join(OUT, "SOLVED.json"), "w", encoding="utf-8") as f:
                    json.dump(hit, f, ensure_ascii=False, indent=2)
                print("\n" + "=" * 60 + f"\n!!! SOLVE VERIFICADO POR ORACULO !!!\n{json.dumps(hit, indent=2)}\n" + "=" * 60)
                return
        # nova geracao: elite + mutacoes dos sobreviventes + sangue novo
        survivors = perms[order[:B // 2]]
        newpop = [survivors]
        # mutacoes (1-3 swaps) dos sobreviventes
        childs = survivors.clone()
        for _ in range(args.mut):
            i = torch.randint(0, 25, (childs.shape[0],), device=DEV)
            j = torch.randint(0, 25, (childs.shape[0],), device=DEV)
            ar = torch.arange(childs.shape[0], device=DEV)
            tmp = childs[ar, i].clone()
            childs[ar, i] = childs[ar, j]; childs[ar, j] = tmp
        newpop.append(childs)
        perms = torch.cat(newpop, dim=0)[:B]
        # injeta sangue novo periodicamente p/ escapar de otimos locais
        if gen % args.fresh_every == 0:
            k = B // 8
            fresh = torch.stack([torch.randperm(25, device=DEV) for _ in range(k)])
            perms[-k:] = fresh
            # re-semear elite p/ nao perder o melhor
            perms[0] = sq_to_perm(best[0]) if best else perms[0]
        # heartbeat
        if time.time() - last_hb > 15:
            last_hb = time.time()
            el = time.time() - t0
            st = {"gen": gen, "best_score": round(best_score, 3),
                  "gens_per_s": round(gen / el, 1), "sq_per_s": round(gen * B / el),
                  "elapsed_s": int(el), "best_head": best[2][:32] if best else None,
                  "best_period": best[1] if best else None, "best_square": best[0] if best else None}
            with open(os.path.join(OUT, "gpu_status.json"), "w", encoding="utf-8") as f:
                json.dump(st, f, ensure_ascii=False, indent=2)
            print(f"[{time.strftime('%H:%M:%S')}] gen={gen} best={best_score:.3f} "
                  f"{gen*B/el/1e6:.1f}M sq/s")
        if args.max_gen and gen >= args.max_gen:
            print(f"[fim] max_gen. best={best_score:.3f} (EN>-4.5). head={best[2][:40] if best else '-'}")
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
    a = ap.parse_args()
    if a.selftest:
        selftest()
    else:
        run(a)
