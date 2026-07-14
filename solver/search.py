# -*- coding: utf-8 -*-
"""
Busca com GRADIENTE sobre a criptanalise de Bifid: hill-climb com restarts
sobre o par (quadrado 25-letras, periodo), maximizando o score de quadgramas
EN da saida. Este e o motor "incansavel" — ao contrario do oraculo AES (binario,
sem gradiente), aqui ha um sinal continuo para escalar.

Se ALGUM quadrado tornar o faed legivel (score > limiar de ingles), e um
breakthrough (o transform real). Caso contrario, o MELHOR score atingivel sobre
TODO o espaco de quadrados e um negativo forte e quantificado.

A cada novo melhor plaintext, o runner roda os oraculos duros (aes_open/as_privkey).
"""
import random
import dsl, oracles as O

ALNUM = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letras (sem J)
PERIODS = [570, 285, 190, 114, 95, 57, 45, 38, 30, 19, 15, 13, 11, 9, 7, 6, 5, 3]

def bifid_decrypt(ct, square, period):
    pos = {c: (i // 5, i % 5) for i, c in enumerate(square)}
    out = []
    for off in range(0, len(ct), period):
        blk = ct[off:off + period]
        seq = []
        for c in blk:
            r, co = pos[c]; seq += [r, co]
        n = len(blk); rows, cols = seq[:n], seq[n:]
        out.append("".join(square[rows[i] * 5 + cols[i]] for i in range(n)))
    return "".join(out)

class AlphabetSearch:
    """Hill-climb (square, period) para maximizar legibilidade do decrypt do faed."""
    def __init__(self, scorer, seeds=None, target="faed"):
        self.scorer = scorer
        # ct sobre 25 letras: faed e a-i (linhas 0-1 do quadrado). Precisa das 25 posicoes
        # so quando o decrypt as usa; a entrada so tem a-i, ok.
        self.ct = O.sources()[target].upper().replace("J", "I")
        self.best_score = -1e9
        self.best = None            # (square, period, plaintext)
        self.pool = []              # sementes injetadas (theme squares)
        self.cur_sq = None
        self.cur_per = None
        self.cur_score = -1e9
        self.stall = 0
        self.iters = 0
        self.restarts = 0
        seeds = seeds or []
        for s in seeds:
            self.seed(s)
        self._restart()

    def seed(self, square):
        sq = square.upper().replace("J", "I")
        if len(sq) == 25 and len(set(sq)) == 25:
            self.pool.append(sq)

    def _fitness(self, sq, per):
        pt = bifid_decrypt(self.ct, sq, per)
        return self.scorer(pt), pt

    def _restart(self):
        if self.pool and random.random() < 0.5:
            sq = list(random.choice(self.pool))
        else:
            sq = list(ALNUM); random.shuffle(sq)
        self.cur_sq = sq
        self.cur_per = random.choice(PERIODS)
        self.cur_score, _ = self._fitness("".join(sq), self.cur_per)
        self.stall = 0
        self.restarts += 1

    def step(self):
        """Uma iteracao de hill-climb. Retorna (improved, score, square, period, plaintext)."""
        self.iters += 1
        # movimento: troca 2 letras, ou (raro) muda o periodo
        if random.random() < 0.08:
            new_per = random.choice(PERIODS)
            sc, pt = self._fitness("".join(self.cur_sq), new_per)
            if sc >= self.cur_score:
                self.cur_per = new_per; self.cur_score = sc; self.stall = 0
            else:
                self.stall += 1
        else:
            a, b = random.sample(range(25), 2)
            self.cur_sq[a], self.cur_sq[b] = self.cur_sq[b], self.cur_sq[a]
            sc, pt = self._fitness("".join(self.cur_sq), self.cur_per)
            if sc >= self.cur_score:
                self.cur_score = sc; self.stall = 0
            else:
                self.cur_sq[a], self.cur_sq[b] = self.cur_sq[b], self.cur_sq[a]
                self.stall += 1
        improved = False
        if self.cur_score > self.best_score:
            self.best_score = self.cur_score
            sq = "".join(self.cur_sq)
            pt = bifid_decrypt(self.ct, sq, self.cur_per)
            self.best = (sq, self.cur_per, pt)
            improved = True
        if self.stall > 1500:
            self._restart()
        if improved:
            return (True, self.best_score, self.best[0], self.best[1], self.best[2])
        return (False, self.best_score, None, None, None)


if __name__ == "__main__":
    from scorer import Scorer
    sc = Scorer()
    s = AlphabetSearch(sc, seeds=["DBIFHCEGAKLMNOPQRSTUVWXYZ"])
    canon_score, canon_pt = s._fitness("DBIFHCEGAKLMNOPQRSTUVWXYZ", 570)
    print(f"CANON(570) score={canon_score:.3f} head={canon_pt[:24]}")
    best = -9
    for i in range(120000):
        imp, score, sq, per, pt = s.step()
        if imp and score > best:
            best = score
            print(f"iter {i:6d} restart {s.restarts:3d} NEW BEST {score:.3f} per={per} sq={sq} head={pt[:32]}")
    print(f"\nfim: melhor score sobre o espaco de quadrados = {s.best_score:.3f}")
    print(f"(ingles legivel > -4.5; CANON = {canon_score:.3f})")
    print("plaintext do melhor:", s.best[2][:120])
