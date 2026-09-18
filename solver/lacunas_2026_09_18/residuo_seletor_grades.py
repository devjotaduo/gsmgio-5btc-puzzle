# -*- coding: utf-8 -*-
"""Mais instâncias de "o resíduo é seletor, não texto": wrap em dbbi, pares em grades, bijeção (2026-09-18).

O PR #17 fechou os saltos aditivos sobre `faed` (sem wrap). Ficaram declaradas quatro continuações;
esta trata três delas, e uma morre só pelo teto:

  (A) **dbbi como grade de pares (7×13): impossível.** Lendo L83 como 30 pares, os valores chegam a 9
      nas duas paridades de posição, e `dbbi` só tem 7 linhas. Descartada por teto, sem execução.
  (B) **Saltos sobre `dbbi` (91) COM wrap** — 91 offsets × 4 resíduos × 2 âncoras × 2 direções = 1.456
      seleções. Exaustivo.
  (C) **Pares (linha, coluna) em `faed` (15×38) e na matriz (14×14)** — L83 dá 30 pares; variantes de
      ordem, base 0/1 e sentido. Exaustivo.
  (D) **Saltos com bijeção arbitrária símbolo→valor**: a soma varia de 233 a 377 e portanto SEMPRE cabe
      nos 570 de `faed`, o que torna o espaço 9!·offsets·16 — grande demais para AES completo. Aqui
      entra por **amostra declarada**, testada em texto e chave.

Cada material é testado como texto (`clean_scorer`), como chave (sha256 contra os dois alvos) e — nos
conjuntos exaustivos — como senha (`raw` e `sha256hex`, 3 blobs × 2 KDF).
Uso: python residuo_seletor_grades.py [--amostra 200000]
"""
import argparse, hashlib, json, random, sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(AQUI.parent / "enxame_2026_09_18"))
sys.path.insert(0, str(REPO / "solver" / "primos_2026_09_17"))
import comum as C  # noqa: E402
import clean_scorer  # noqa: E402
from coincurve import PublicKey  # noqa: E402

G = C.G
OUT = REPO / "_work" / "residuo_saltos_2026-09-18"
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
ALFA = "abcdefghi"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ALVOS = {bytes.fromhex(h): a for h, a in zip(G.O.TARGET_H160S, G.O.PRIZE_ADDRS)}
RES = {"L84": R84, "L84_rev": R84[::-1], "L83": R83, "L83_rev": R83[::-1]}


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def vals(s, sig=None):
    return [(sig[ALFA.index(c)] if sig else ALFA.index(c) + 1) for c in s]


# ---------------------------------------------------------------- (A) teto: dbbi como grade de pares
def teto_dbbi_grade():
    v = vals(R83)
    return {"linhas_de_dbbi": 7, "max_valor_pos_impares": max(v[0::2]), "max_valor_pos_pares": max(v[1::2]),
            "viavel": max(max(v[0::2]), max(v[1::2])) <= 7,
            "conclusao": "impossível: o resíduo tem valor 9 nas duas paridades e dbbi só tem 7 linhas"}


# ---------------------------------------------------------------- (B) saltos sobre dbbi com wrap
def saltos_dbbi():
    campo = G.DBBI
    n = len(campo)
    for rn, R in RES.items():
        sal = vals(R)
        for direcao in (1, -1):
            for ancora in ("depois", "antes"):
                for off in range(n):
                    p, out = off, []
                    for s in sal:
                        if ancora == "antes":
                            out.append(campo[p % n])
                            p += direcao * s
                        else:
                            p += direcao * s
                            out.append(campo[p % n])
                    yield f"B/{rn}/{'fwd' if direcao == 1 else 'rev'}/{ancora}/off{off}", "".join(out)


# ---------------------------------------------------------------- (C) pares (linha, coluna) em grades
def pares_grades():
    grades = {"faed": (G.FAED, 15, 38), "matriz": (None, 14, 14)}
    mat = G.MATRIX_README
    for gnome, (campo, nl, nc) in grades.items():
        for rn, R in RES.items():
            v = vals(R)
            v = v[:len(v) // 2 * 2]
            for ordem in ("lc", "cl"):
                for base in (0, 1):
                    out = []
                    for i in range(0, len(v), 2):
                        a, b = v[i] - base, v[i + 1] - base
                        r, c = (a, b) if ordem == "lc" else (b, a)
                        if not (0 <= r < nl and 0 <= c < nc):
                            out = None
                            break
                        out.append(campo[r * nc + c] if campo else ("1" if mat[r][c] else "0"))
                    if out:
                        yield f"C/{gnome}/{rn}/{ordem}/base{base}", "".join(out)


# ---------------------------------------------------------------- (D) saltos com bijeção (amostra)
def saltos_bijecao(n_amostra, rnd):
    campo = G.FAED
    n = len(campo)
    base = list(range(1, 10))
    for _ in range(n_amostra):
        sig = base[:]
        rnd.shuffle(sig)
        rn = rnd.choice(list(RES))
        sal = vals(RES[rn], sig)
        total = sum(sal)
        if total >= n:          # âncora "depois": o último acesso é campo[off + total]
            continue
        off = rnd.randrange(0, n - total)
        p, out = off, []
        for s in sal:
            p += s
            out.append(campo[p])
        yield f"D/{rn}/sig{''.join(map(str, sig))}/off{off}", "".join(out)


def testar_chave(materiais):
    hits = []
    for s, r in materiais.items():
        sec = hashlib.sha256(s.encode()).digest()
        if 0 < int.from_bytes(sec, "big") < N:
            pk = PublicKey.from_valid_secret(sec)
            for comp in (False, True):
                a = ALVOS.get(h160(pk.format(comp)))
                if a:
                    hits.append({"rotulo": r, "alvo": a, "comprimida": comp})
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--amostra", type=int, default=200000)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    sc = clean_scorer.Scorer()
    rnd = random.Random(20260918)
    ctl = {"fase2": bool(C.controle_positivo()["candidatos"])}

    exaustivo = {}
    for rot, s in saltos_dbbi():
        exaustivo.setdefault(s, rot)
    n_b = len(exaustivo)
    for rot, s in pares_grades():
        exaustivo.setdefault(s, rot)
    amostra = {}
    for rot, s in saltos_bijecao(a.amostra, rnd):
        amostra.setdefault(s, rot)

    def resumo(mat, nome):
        if not mat:
            return {"materiais": 0}
        melhor = max((sc(s.upper()), s, r) for s, r in mat.items())
        return {"materiais": len(mat), "melhor_escore": round(melhor[0], 3),
                "rotulo": melhor[2], "texto": melhor[1][:70],
                "hits_de_chave": testar_chave(mat)}

    res_aes = C.testar(list(exaustivo), formas=("raw", "sha256hex"), workers=8, rotulo="seletor")
    out = {"hipotese": "o resíduo é seletor/parâmetro, não linguagem — mais instâncias",
           "controle": ctl,
           "A_dbbi_como_grade_de_pares": teto_dbbi_grade(),
           "B_saltos_dbbi_com_wrap": {"selecoes": n_b, "cobertura": "exaustiva: 91 offsets × 4 resíduos × 2 âncoras × 2 direções"},
           "C_pares_em_grades": {"cobertura": "exaustiva: faed 15×38 e matriz 14×14, ordens lc/cl, bases 0/1"},
           "exaustivo": resumo(exaustivo, "exaustivo"),
           "D_saltos_com_bijecao_AMOSTRA": {**resumo(amostra, "amostra"),
                                            "declarado": "amostra, NÃO exaustivo: 9!·offsets·16 é grande demais"},
           "aes_sobre_o_exaustivo": {k: res_aes[k] for k in ("senhas", "aes", "paddings", "paddings_esperados", "z_padding")},
           "candidatos_aes": res_aes["candidatos"],
           "referencia_ingles": round(sc("INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYS"), 3),
           "kit": C.commit_do_kit(),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    json.dump(out, open(OUT / "seletor_grades.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(out, ensure_ascii=False, indent=1)[:3000])


if __name__ == "__main__":
    main()
