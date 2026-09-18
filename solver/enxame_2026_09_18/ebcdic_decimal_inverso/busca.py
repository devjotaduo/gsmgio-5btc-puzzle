# -*- coding: utf-8 -*-
"""Frente ebcdic_decimal_inverso (campanha enxame_2026-09-18; hipótese I1 do Codex Astra).

Lacuna: a busca de 16/09 (solver/ebcdic_decimal.cjs:11 no checkout principal) aceitava bytes cuja
leitura EBCDIC 1141 convencional é ASCII imprimível, isto é, a imagem cp273 DIRETA do texto. A fase
3.2 real usa a direção inversa, bytes = ASCII.decode('cp273').encode('latin-1'), desfeita por
b.decode('latin-1').encode('cp273'). Os dois repertórios têm 98 bytes e só 43 em comum.

I1 (conjunto exato): dbbi na ordem publicada, a=1..i=9; uma letra ℓ zerável por ocorrência;
inteiro → bytes big-endian mínimos → aceito só se todo byte está no repertório inverso.
33.819.184 inteiros distintos, enumerados diretamente (código de Gray, soma de controle em forma
fechada) e conferidos por DFS com poda por sucessor. Extensões por DFS: faed, ordem invertida,
0/1/2 letras zeráveis com alfabeto literal e as 9! bijeções com uma letra zerável, ou seja, a
cobertura inteira da busca de 16/09 refeita no repertório correto.
Cada texto aceito t: C.testar (raw e sha256hex; SMALL, COSMIC, TAIL32; KDF sha256 e md5) e
sha256(t) como privkey dos dois alvos.

Rodar em primeiro plano:  python busca.py [--workers 3] [--sem-bijecoes]
Saída: _work/enxame_2026-09-18/ebcdic_decimal_inverso/{controls.json, summary.json, aceitos.jsonl}.
Qualquer achado é CANDIDATO (AGENTS.md, regra 1), nunca solução.
"""
import argparse, hashlib, itertools, json, os, random, re, subprocess, sys, time
from multiprocessing import Pool
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[2]
sys.path.insert(0, str(AQUI.parent))
import comum as C  # noqa: E402
G = C.G

MAIN = Path(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle")  # dados locais (AGENTS.md)
CJS_ANTIGO = MAIN / "solver" / "ebcdic_decimal.cjs"
OPENSSL = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
OUT = REPO / "_work" / "enxame_2026-09-18" / "ebcdic_decimal_inverso"
LETRAS = "abcdefghi"

IMPRIMIVEL = frozenset(range(32, 127)) | {9, 10, 13}
_DEC273 = bytes(range(256)).decode("cp273")
# b entra se b.decode('latin-1').encode('cp273') é imprimível (direção autêntica da fase 3.2)
REP_INVERSO = bytes(sorted(ord(_DEC273[a]) for a in IMPRIMIVEL))
# o repertório de 16/09: bytes EBCDIC de ASCII imprimível (cp273 direta)
REP_DIRETO = bytes(sorted(chr(a).encode("cp273")[0] for a in IMPRIMIVEL))


class Repertorio:
    def __init__(self, rep):
        assert rep and rep[0] != 0 and len(set(rep)) == len(rep)
        self.rep, self.minimo = rep, rep[0]
        self.prox = [next((a for a in rep if a > b), None) for b in range(256)]
        self.ruim = re.compile(b"[^" + b"".join(b"\\x%02x" % a for a in rep) + b"]")


R_INV, R_DIR = Repertorio(REP_INVERSO), Repertorio(REP_DIRETO)


def bytes_min(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def aceito(n, rep=REP_INVERSO):
    bs = bytes_min(n)
    return bool(bs) and not bs.translate(None, rep)


def aceito_por_definicao(n):
    """Definição literal da I1, sem tabela: decode latin-1 → encode cp273 → tudo imprimível."""
    bs = bytes_min(n)
    try:
        t = bs.decode("latin-1").encode("cp273")
    except UnicodeEncodeError:
        return False
    return bool(bs) and all(x in IMPRIMIVEL for x in t)


def texto(n):
    return bytes_min(n).decode("latin-1").encode("cp273")


def sucessor(n, R):
    """Menor inteiro aceito por R que é ≥ n (bytes mínimos)."""
    bs = bytearray(bytes_min(n) or b"\x00")
    m = R.ruim.search(bs)
    if m is None:
        return n
    for j in range(m.start(), -1, -1):
        a = R.prox[bs[j]]
        if a is not None:
            bs[j] = a
            bs[j + 1:] = bytes([R.minimo]) * (len(bs) - j - 1)
            return int.from_bytes(bs, "big")
    return int.from_bytes(bytes([R.minimo]) * (len(bs) + 1), "big")


def dfs(base, pesos, R):
    """Todos os n = base + Σ(subconjunto de pesos) aceitos por R. Poda: se o menor aceito ≥ n
    passa de n + Σ(pesos restantes), nenhum descendente é aceito. Pesos ≥ 0; ordem decrescente
    só acelera. Sem limite de nós: a busca é sempre completa."""
    caudas = [0] * (len(pesos) + 1)
    for i in range(len(pesos) - 1, -1, -1):
        caudas[i] = caudas[i + 1] + pesos[i]
    achados, nos, pilha = [], 0, [(0, base)]
    while pilha:
        i, n = pilha.pop()
        nos += 1
        if sucessor(n, R) > n + caudas[i]:
            continue
        if i == len(pesos):
            achados.append(n)
            continue
        pilha.append((i + 1, n + pesos[i]))
        pilha.append((i + 1, n))
    return achados, nos


def leitura(campo, ordem):
    return campo if ordem == "orig" else campo[::-1]


def modelo_literal(s, zeraveis):
    """Alfabeto literal a=1..i=9; as ocorrências das letras em `zeraveis` valem 0 ou o dígito."""
    L, base, pesos = len(s), 0, []
    for p, c in enumerate(s):
        w = (ord(c) - 96) * 10 ** (L - 1 - p)
        if c in zeraveis:
            pesos.append(w)
        else:
            base += w
    return base, pesos


# ------------------------------------------------------------------ I1: enumeração direta
def enumerar_direto(s, letra, R=REP_INVERSO):
    """Percorre as 2^c − 1 máscaras não vazias da letra por código de Gray (a vazia, o inteiro
    sem zeros, é contada à parte). Devolve aceitos, contagem e a checagem da soma em forma
    fechada: Σ_máscaras n = 2^c·n0 − 2^(c−1)·Σw."""
    base, pesos = modelo_literal(s, letra)
    n0 = base + sum(pesos)
    c, n, soma, aceitos = len(pesos), n0, 0, []
    for g in range(1, 1 << c):
        k = (g & -g).bit_length() - 1
        if (g ^ (g >> 1)) >> k & 1:
            n -= pesos[k]
        else:
            n += pesos[k]
        soma += n
        if not n.to_bytes((n.bit_length() + 7) // 8, "big").translate(None, R):
            aceitos.append(n)
    assert n == n0 - pesos[c - 1], "código de Gray não terminou onde deveria"
    assert soma + n0 == (n0 << c) - (sum(pesos) << (c - 1)), "soma de controle divergiu"
    return {"letra": letra, "ocorrencias": c, "mascaras_nao_vazias": (1 << c) - 1,
            "aceitos": aceitos}


def i1_direto(s):
    n0 = int("".join(str(ord(c) - 96) for c in s))  # a máscara vazia, comum às nove letras
    todos, por_letra = ({n0} if aceito(n0) else set()), []
    for letra in LETRAS:
        t0 = time.perf_counter()
        r = enumerar_direto(s, letra)
        todos.update(r["aceitos"])
        por_letra.append({**r, "aceitos": len(r["aceitos"]), "s": round(time.perf_counter() - t0, 1)})
    total = 1 + sum(x["mascaras_nao_vazias"] for x in por_letra)
    return {"inteiros": total, "aceitos": sorted(todos), "por_letra": por_letra}


def i1_dfs(s):
    todos, nos = set(), 0
    for letra in LETRAS:
        base, pesos = modelo_literal(s, letra)
        h, k = dfs(base, pesos, R_INV)
        todos.update(h)
        nos += k
    return {"aceitos": sorted(todos), "nos": nos}


# ------------------------------------------------------------------ extensões por DFS
def familia_literal():
    """A família "fixed" de 16/09: dbbi e faed, duas ordens, 0/1/2 letras zeráveis."""
    zer = [""] + list(LETRAS) + ["".join(p) for p in itertools.combinations(LETRAS, 2)]
    res, hits, nos = [], [], 0
    for campo_nome in ("dbbi", "faed"):
        campo = G.DBBI if campo_nome == "dbbi" else G.FAED
        for ordem in ("orig", "rev"):
            s = leitura(campo, ordem)
            for z in zer:
                base, pesos = modelo_literal(s, z)
                h, k = dfs(base, pesos, R_INV)
                nos += k
                res.append({"campo": campo_nome, "ordem": ordem, "zeraveis": z, "pesos": len(pesos),
                            "nos": k, "aceitos": len(h)})
                hits += [{"familia": "literal", "campo": campo_nome, "ordem": ordem, "zeraveis": z,
                          "n": str(n)} for n in h]
    return {"configuracoes": len(res), "nos": nos, "grupos": res, "hits": hits}


def preparar_bijecao(s, alias):
    """Massa posicional Σ10^p de cada letra não zerável e as potências das ocorrências de alias."""
    L, massa, unid = len(s), [0] * 9, []
    for p, c in enumerate(s):
        if c == alias:
            unid.append(10 ** (L - 1 - p))
        else:
            massa[LETRAS.index(c)] += 10 ** (L - 1 - p)
    return massa, unid, LETRAS.index(alias)


def modelo_bijecao(prep, perm):
    """perm[i] = dígito da letra LETRAS[i]; devolve (base, pesos) para o DFS."""
    massa, unid, ia = prep
    return sum(d * m for d, m in zip(perm, massa)), [perm[ia] * u for u in unid]


def _bijecoes(args):
    """Um grupo (campo, ordem, letra zerável) × 9! bijeções a..i → 1..9."""
    campo_nome, ordem, alias = args
    prep = preparar_bijecao(leitura(G.DBBI if campo_nome == "dbbi" else G.FAED, ordem), alias)
    t0, casos, nos, hits = time.perf_counter(), 0, 0, []
    for perm in itertools.permutations(range(1, 10)):
        h, k = dfs(*modelo_bijecao(prep, perm), R_INV)
        casos += 1
        nos += k
        hits += [{"familia": "bijecao", "campo": campo_nome, "ordem": ordem, "zeraveis": alias,
                  "mapa": "".join(map(str, perm)), "n": str(n)} for n in h]
    return {"campo": campo_nome, "ordem": ordem, "zeraveis": alias, "casos": casos, "nos": nos,
            "hits": hits, "s": round(time.perf_counter() - t0, 1)}


# ------------------------------------------------------------------ oráculos sobre os aceitos
def privkey_de(t):
    return G.fast_priv_scan(hashlib.sha256(t).digest(), "sha256(t)")


def testar_textos(textos, workers):
    r = C.testar(textos, formas=("raw", "sha256hex"), workers=workers, rotulo="ebcdic_decimal_inverso")
    r["privkey_hits"] = [{"t": t.hex(), "hits": privkey_de(t)} for t in textos if privkey_de(t)]
    return r


# ------------------------------------------------------------------ controles
def codificar_autentico(t, alias, mapa=None):
    """Ponte: texto ASCII → direção autêntica da 3.2 → inteiro → decimal; 0 vira a letra `alias`."""
    mapa = mapa or list(range(1, 10))
    inv = {str(d): LETRAS[i] for i, d in enumerate(mapa)}
    n = int.from_bytes(t.decode("cp273").encode("latin-1"), "big")
    return n, "".join(alias if ch == "0" else inv[ch] for ch in str(n))


def controle_repertorios():
    tab = json.loads((MAIN / "_work" / "ebcdic_decimal_2026-09-16" / "encoding.json").read_text("utf-8-sig"))
    antigo = bytes(i for i, c in enumerate(tab["decoded"])
                   if len(c) == 1 and (32 <= ord(c) <= 126 or ord(c) in (9, 10, 13)))
    assert antigo == REP_DIRETO, "repertório de 16/09 ≠ cp273 direta"
    az = bytes(range(97, 123)).decode("cp273").encode("latin-1")
    so_ant, so_novo = set(REP_DIRETO) - set(REP_INVERSO), set(REP_INVERSO) - set(REP_DIRETO)
    assert len(REP_DIRETO) == len(REP_INVERSO) == 98 and len(so_ant) == len(so_novo) == 55
    return {"rep_antigo_eq_encoding_json_1141": True, "tamanhos": 98, "so_antigo": len(so_ant),
            "so_inverso": len(so_novo), "comum": 98 - len(so_ant),
            "az_autentico_hex": az.hex(), "az_rejeitados_pelo_antigo": sum(b not in REP_DIRETO for b in az),
            "az_rejeitados_pelo_inverso": sum(b not in REP_INVERSO for b in az),
            "rep_inverso_hex": REP_INVERSO.hex(), "rep_antigo_hex": REP_DIRETO.hex()}


def controle_fase32():
    pt = (REPO / "_work" / "phase32_plaintext.bin").read_bytes()
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    esperado = next(l.strip() for l in readme.splitlines() if l.startswith("vtkvplmepphluwaht")).encode()
    seg = pt[447:447 + len(esperado)]
    assert len(esperado) == 1539 and seg.decode("latin-1").encode("cp273") == esperado
    assert not seg.translate(None, REP_INVERSO)
    return {"plaintext_sha256": hashlib.sha256(pt).hexdigest(), "offset": 447, "beaufort_bytes": 1539,
            "transformacao": "b.decode('latin-1').encode('cp273')", "reproduz_readme": True,
            "bytes_no_rep_inverso": 1539, "bytes_no_rep_antigo": sum(b in REP_DIRETO for b in seg)}


def controle_sucessor():
    """sucessor() contra força bruta em todo n < 2^16, nos dois repertórios; aceito() contra a
    definição literal em todo n < 2^16 e em inteiros aleatórios de 30–40 bytes (metade aceitos)."""
    for R, rep in ((R_INV, REP_INVERSO), (R_DIR, REP_DIRETO)):
        valores = sorted([a for a in rep] + [a * 256 + b for a in rep for b in rep] + [rep[0] * 65793])
        j = 0
        for n in range(65536):
            while valores[j] < n:
                j += 1
            assert sucessor(n, R) == valores[j], (n, R.rep[:4])
    for n in range(65536):
        assert aceito(n) == aceito_por_definicao(n), n
    rnd, ok = random.Random(273), 0
    for _ in range(20000):
        k = rnd.randint(30, 40)
        if rnd.random() < 0.5:
            bs = bytes([rnd.choice(REP_INVERSO) for _ in range(k)])
        else:
            bs = bytes(rnd.randrange(1, 256) for _ in range(k))
        n = int.from_bytes(bs, "big")
        assert aceito(n) == aceito_por_definicao(n)
        ok += aceito(n)
    # inteiros grandes: [n, sucessor(n)) sem aceitos, pela contagem independente
    grandes = 0
    for _ in range(3000):
        k = rnd.randint(1, 240)
        bs = bytearray(rnd.choice(REP_INVERSO) for _ in range(k))
        for _ in range(rnd.randint(0, 3)):
            bs[rnd.randrange(k)] = rnd.randrange(256)
        n = int.from_bytes(bs, "big") or 1
        for R, rep in ((R_INV, REP_INVERSO), (R_DIR, REP_DIRETO)):
            s = sucessor(n, R)
            assert s >= n and aceito(s, rep) and conta_aceitos_ate(s - 1, rep) == conta_aceitos_ate(n - 1, rep)
            grandes += 1
    return {"sucessor_inteiros_por_repertorio": 65536, "aceito_vs_definicao": 65536 + 20000,
            "aleatorios_aceitos": ok, "sucessor_grandes_vs_contagem": grandes}


def conta_aceitos_ate(x, rep):
    """Quantos inteiros em [1, x] são aceitos: contagem posicional em base 256, sem sucessor."""
    if x <= 0:
        return 0
    bs, r = bytes_min(x), len(rep)
    menores = [sum(a < b for a in rep) for b in range(256)]
    total = sum(r ** j for j in range(1, len(bs)))
    for i, b in enumerate(bs):
        total += menores[b] * r ** (len(bs) - 1 - i)
        if b not in rep:
            return total
    return total + 1


def controle_dfs_forca_bruta():
    """DFS == enumeração de máscaras em fontes aleatórias curtas (1 ou 2 letras zeráveis)."""
    rnd, casos, com_hits, total_hits = random.Random(3141), 0, 0, 0
    for i in range(2000):
        if i % 2:  # plantado: bytes aceitos → decimal com os zeros trocados por uma letra
            alias = rnd.choice(LETRAS)
            n = int.from_bytes(bytes(rnd.choice(REP_INVERSO) for _ in range(rnd.randint(1, 5))), "big")
            s = "".join(alias if ch == "0" else LETRAS[int(ch) - 1] for ch in str(n))
            z = alias + rnd.choice(("",) + tuple(c for c in LETRAS if c != alias))
        else:
            s = "".join(rnd.choice(LETRAS) for _ in range(rnd.randint(4, 16)))
            z = "".join(rnd.sample(LETRAS, rnd.choice((1, 2))))
        base, pesos = modelo_literal(s, z)
        if len(pesos) > 14:
            continue
        esperado = sorted({base + sum(w for k, w in enumerate(pesos) if m >> k & 1)
                           for m in range(1 << len(pesos))
                           if aceito(base + sum(w for k, w in enumerate(pesos) if m >> k & 1))})
        h, _ = dfs(base, pesos, R_INV)
        assert sorted(set(h)) == esperado, (s, z)
        assert not i % 2 or n in esperado, (s, z)
        casos += 1
        com_hits += bool(esperado)
        total_hits += len(esperado)
    return {"casos": casos, "casos_com_aceitos": com_hits, "aceitos_conferidos": total_hits}


def _cjs_antigo(fonte, alias, texto_antigo):
    """Roda a busca de 16/09 (código original, só leitura) sobre `fonte` e, como positivo do
    arnês, sobre o mesmo texto codificado na direção antiga."""
    js = r"""
const m=require(process.argv[1]);const [fonte,alias,txt]=JSON.parse(require('fs').readFileSync(0,'utf8'));
const f=m.fixed(fonte,alias),r=m.search(f.low,f.weights);
const src2=m.encode(txt,[1,2,3,4,5,6,7,8,9],alias),f2=m.fixed(src2,alias),r2=m.search(f2.low,f2.weights);
console.log(JSON.stringify({complete:r.complete,hits:r.hits.map(h=>h.decimal),
  harness_complete:r2.complete,harness_hits_hex:r2.hits.map(h=>h.hex)}));"""
    p = subprocess.run(["node", "-e", js, str(CJS_ANTIGO)], input=json.dumps([fonte, alias, texto_antigo]),
                       capture_output=True, text=True, timeout=600, check=True)
    return json.loads(p.stdout)


def controle_ponte():
    """Texto ASCII → direção autêntica → decimal com zeros trocados pela letra ℓ: o código novo
    recupera (DFS e enumeração direta); o repertório antigo o rejeita; o código antigo (node) não
    o encontra, mas acha o mesmo texto codificado na direção antiga."""
    t = b"I've been waiting for you.\nThe matrix has you!"
    t_antigo = t.decode("ascii")
    res = []
    for alias in LETRAS:
        n, fonte = codificar_autentico(t, alias)
        base, pesos = modelo_literal(fonte, alias)
        h, nos = dfs(base, pesos, R_INV)
        assert n in h and texto(n) == t and aceito(n) and not aceito(n, REP_DIRETO)
        direto = None
        if len(pesos) <= 22:
            r = enumerar_direto(fonte, alias)
            direto = n in r["aceitos"] or n == base + sum(pesos)
            assert direto
        old = _cjs_antigo(fonte, alias, t_antigo)
        assert old["complete"] and str(n) not in old["hits"], "código antigo achou a ponte?"
        assert old["harness_complete"] and any(
            bytes.fromhex(x).decode("cp273") == t_antigo for x in old["harness_hits_hex"])
        res.append({"alias": alias, "digitos": len(fonte), "zeraveis": len(pesos), "nos_dfs": nos,
                    "dfs_recupera": True, "direta_recupera": direto,
                    "rep_antigo_aceita": False, "cjs_antigo_hits": len(old["hits"]),
                    "cjs_antigo_recupera_direcao_antiga": True})
    return {"texto": t.decode(), "bytes_autenticos_hex": t.decode("cp273").encode("latin-1").hex(),
            "bytes_fora_do_rep_antigo": sum(b not in REP_DIRETO for b in t.decode("cp273").encode("latin-1")),
            "casos": res}


def controle_bijecao_plantada():
    """Textos ASCII aleatórios na direção autêntica, bijeção e letra zerável aleatórias: o mesmo
    modelo_bijecao()+dfs() das 9! bijeções recupera cada um (inteiros de 8–60 bytes)."""
    rnd, casos = random.Random(1141), 0
    imprimiveis = sorted(IMPRIMIVEL)
    for _ in range(400):
        t = bytes(rnd.choice(imprimiveis) for _ in range(rnd.randint(8, 60)))
        perm, alias = tuple(rnd.sample(range(1, 10), 9)), rnd.choice(LETRAS)
        n, fonte = codificar_autentico(t, alias, perm)
        base, pesos = modelo_bijecao(preparar_bijecao(fonte, alias), perm)
        assert base + sum(pesos) == int("".join(str(perm[LETRAS.index(c)]) for c in fonte))
        h, _ = dfs(base, pesos, R_INV)
        assert n in h and texto(n) == t
        casos += 1
    return {"recuperados": casos}


def controle_privkey():
    from coincurve import PublicKey
    t = b"I've been waiting for you.\nThe matrix has you!"
    sec = hashlib.sha256(t).digest()
    h = G._h160_hex(PublicKey.from_valid_secret(sec).format(True))
    assert not privkey_de(t)
    G.TARGET_H160S = G.TARGET_H160S + (h,)
    try:
        assert privkey_de(t), "alvo plantado não disparou"
    finally:
        G.TARGET_H160S = G.TARGET_H160S[:-1]
    assert len(G.TARGET_H160S) == 2 and not privkey_de(t)
    return {"plantado_e_recuperado": True, "restaurado": True}


def controle_aes_openssl():
    """Blob sintético cifrado pelo openssl CLI (EVP sha256) com sha256hex(t); o kit o abre."""
    t = b"I've been waiting for you.\nThe matrix has you!"
    senha = hashlib.sha256(t).hexdigest()
    p = subprocess.run([str(OPENSSL), "enc", "-aes-256-cbc", "-md", "sha256", "-a", "-A",
                        "-pass", "pass:" + senha],  # sal aleatório: com -S o openssl 3 omite o Salted__
                       input=b"ponte ebcdic decimal inverso OK\n", capture_output=True, check=True)
    G.BLOBS["PONTE"] = G._parse(p.stdout.decode().strip())
    try:
        hard, soft = G.try_password_all(senha.encode(), ("PONTE",), "both")
    finally:
        del G.BLOBS["PONTE"]
    assert any(r["kdf"].endswith("SHA256") and r["head"].startswith("ponte ebcdic") for r in hard)
    return {"openssl": subprocess.run([str(OPENSSL), "version"], capture_output=True, text=True).stdout.strip(),
            "abre_com_sha256": True}


def esperado_analitico(s):
    """Número esperado de aceitos na I1 se os bytes fossem uniformes: Σ inteiros × (98/256)^len."""
    base, _ = modelo_literal(s, "")
    k = len(bytes_min(base))
    total = 1 + sum((1 << s.count(c)) - 1 for c in LETRAS)
    return {"bytes_do_inteiro": k, "p_por_inteiro": (98 / 256) ** k, "esperado": total * (98 / 256) ** k}


def sha_arq(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--sem-bijecoes", action="store_true")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    controles = {"fase2": {"abre": bool(C.controle_positivo(workers=1)["candidatos"])},
                 "repertorios": controle_repertorios(), "fase32_direcao": controle_fase32(),
                 "sucessor": controle_sucessor(), "dfs_vs_forca_bruta": controle_dfs_forca_bruta(),
                 "ponte": controle_ponte(), "bijecao_plantada": controle_bijecao_plantada(),
                 "privkey_plantada": controle_privkey(),
                 "aes_openssl": controle_aes_openssl()}
    (OUT / "controls.json").write_text(json.dumps(controles, ensure_ascii=False, indent=2) + "\n", "utf-8")
    print("controles OK", round(time.perf_counter() - t0, 1), "s", flush=True)

    d = i1_direto(G.DBBI)
    v = i1_dfs(G.DBBI)
    assert d["inteiros"] == 33819184 and d["aceitos"] == v["aceitos"], "I1: direto e DFS divergem"
    print("I1:", d["inteiros"], "inteiros,", len(d["aceitos"]), "aceitos; DFS", v["nos"], "nós", flush=True)

    lit = familia_literal()
    print("literal:", lit["configuracoes"], "configs,", lit["nos"], "nós,", len(lit["hits"]), "aceitos", flush=True)
    i1_no_literal = {int(h["n"]) for h in lit["hits"] if h["campo"] == "dbbi" and h["ordem"] == "orig"
                     and len(h["zeraveis"]) <= 1}
    assert i1_no_literal == set(d["aceitos"]), "família literal não reproduz a I1"

    bij = None
    if not a.sem_bijecoes:
        grupos = [(c, o, z) for c in ("dbbi", "faed") for o in ("orig", "rev") for z in LETRAS]
        with Pool(a.workers) as pool:
            gs = []
            for g in pool.imap_unordered(_bijecoes, grupos):
                gs.append(g)
                print("bijeções", g["campo"], g["ordem"], g["zeraveis"], g["casos"], g["nos"],
                      len(g["hits"]), g["s"], "s", flush=True)
        bij = {"casos": sum(g["casos"] for g in gs), "nos": sum(g["nos"] for g in gs),
               "hits": [h for g in gs for h in g["hits"]],
               "grupos": [{k: g[k] for k in ("campo", "ordem", "zeraveis", "casos", "nos", "s")} | {"aceitos": len(g["hits"])}
                          for g in sorted(gs, key=lambda g: (g["campo"], g["ordem"], g["zeraveis"]))]}
        assert bij["casos"] == 36 * 362880

    registros = [{"familia": "I1", "campo": "dbbi", "ordem": "orig", "n": str(n)} for n in d["aceitos"]]
    registros += lit["hits"] + (bij["hits"] if bij else [])
    textos = sorted({texto(int(r["n"])) for r in registros})
    with (OUT / "aceitos.jsonl").open("w", encoding="utf-8") as f:
        for r in registros:
            n = int(r["n"])
            f.write(json.dumps({**r, "bytes_hex": bytes_min(n).hex(), "texto": texto(n).decode("ascii")},
                               ensure_ascii=False) + "\n")
    aes = testar_textos(textos, a.workers) if textos else None
    if aes and aes["registros_padding"]:
        with (OUT / "paddings.jsonl").open("w", encoding="utf-8") as f:
            for r in aes["registros_padding"]:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    summary = {
        "frente": "ebcdic_decimal_inverso", "hipotese": "I1 (Codex Astra, 2026-09-18)",
        "repertorio": "b.decode('latin-1').encode('cp273') ⊂ ASCII 32–126/TAB/LF/CR (98 bytes)",
        "I1": {"inteiros": d["inteiros"], "aceitos": len(d["aceitos"]), "dfs_nos": v["nos"],
               "direto_eq_dfs": True, "por_letra": d["por_letra"], "analitico": esperado_analitico(G.DBBI)},
        "literal": {k: lit[k] for k in ("configuracoes", "nos", "grupos")} | {"aceitos": len(lit["hits"])},
        "bijecoes": ({k: bij[k] for k in ("casos", "nos", "grupos")} | {"aceitos": len(bij["hits"])}) if bij else None,
        "textos_unicos": len(textos),
        "aes": ({k: aes[k] for k in ("senhas", "aes", "paddings", "paddings_esperados", "z_padding", "kdf", "blobs", "formas")}
                | {"candidatos": aes["candidatos"], "privkey_hits": aes["privkey_hits"]}) if aes else
               {"senhas": 0, "aes": 0, "paddings": 0, "candidatos": [], "privkey_hits": []},
        "kit": C.commit_do_kit(),
        "hashes": {"busca.py": sha_arq(__file__), "comum.py": sha_arq(AQUI.parent / "comum.py"),
                   "cjs_antigo": sha_arq(CJS_ANTIGO), "dbbi": hashlib.sha256(G.DBBI.encode()).hexdigest(),
                   "faed": hashlib.sha256(G.FAED.encode()).hexdigest()},
        "segundos": round(time.perf_counter() - t0, 1),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", "utf-8")
    print(json.dumps({k: summary[k] for k in ("textos_unicos", "segundos")} | {"aes": summary["aes"]["aes"],
                      "paddings": summary["aes"]["paddings"], "candidatos": len(summary["aes"]["candidatos"])}))


if __name__ == "__main__":
    main()
