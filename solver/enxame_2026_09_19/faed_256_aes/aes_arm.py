# -*- coding: utf-8 -*-
"""
Frente F4 "faed_256_aes" (campanha enxame_2026-09-19).

LACUNA (ENDGAME.md tabela 4-E): "Selecao de 256 bits de `faed` por indices principiados
(primos, cores, g/i, multiplos, i/i+285): 3,77 M privkeys; parcial: o braco AES ficou
~200x mais fino". As mesmas selecoes que o script historico `select_bits.py` testava
quase so como CHAVE PRIVADA (pcheck) tambem precisam ser testadas como MATERIAL DE SENHA
AES (o mesmo gargalo que a frente enxame_2026-09-18/faed_selecao_sha256 fechou so para o
sub-conjunto "bits/multibit sem mod|mult, so faed" -- aqui cobrimos as 5 familias
NOMEADAS pela lacuna, com metodo proprio e declarado, e igualamos os DOIS bracos: toda
selecao vira valor de 32 B (u) e e testada tanto como privkey (G.fast_priv_scan/priv_hit)
quanto como senha, em 5 formas.

HIPOTESE (finita, falsificavel): alguma das selecoes de 256 bits (primos, cores da matriz,
simbolos g/i, multiplos dos indices coloridos, par i/i+285) sobre `faed`, num dos 5 formatos
de senha abaixo, abre SMALL/COSMIC/TAIL32 (EVP SHA256 ou MD5) ou bate como privkey nos dois
alvos. Falsifica-se por zero no oraculo duro (AGENTS.md regra 1) com a cobertura exata
declarada abaixo.

METODO DE SELECAO (declarado explicitamente -- nao e o `select_bits.py` historico
reproduzido byte a byte, e sim as mesmas 5 familias descritas pela lacuna, com o metodo de
empacotamento em 32 B que o `select_bits.py` ja usava para a chave: inteiro base-9 dos
digitos a=0..h=8, ou leitura ASCII direta dos simbolos selecionados):

  1) primos        -- indices i (0-based) e i+1 (1-based) primos em [0,570)
  2) cores          -- indices coloridos da espiral 14x14 (G.COLORED/BLUE_IDX/YELLOW_IDX)
                        usados como indices diretos em faed (todos < 570)
  3) g/i            -- posicoes onde faed[i] em {g,i} e o complemento
  4) multiplos      -- multiplos de cada indice colorido c (i % c == 0, i>0), c em COLORED
  5) par i/i+285    -- 570 = 2x285: combina faed[i] e faed[i+285] por soma mod 9 (digito) e
                        por XOR do byte ASCII, para i em 0..284

EMPACOTAMENTO EM u (32 B), por selecao/variante:
  (a) pack_b9   -- inteiro base-9 dos digitos (a=0..h=8) da subsequencia, para bytes big-endian
                    de 32 B (trunca os bits altos se sobrar, zero-preenche a esquerda se faltar)
  (b) ascii32   -- primeiros 32 bytes ASCII dos simbolos selecionados (zero-preenche a direita
                    se a selecao tiver <32 simbolos)
  (c) janelas   -- se a selecao tiver >=32 simbolos, TODAS as janelas contiguas de 32 bytes ASCII
                    (ou dos digitos combinados no par i/i+285), deslizando 1 posicao por vez

FORMAS DE SENHA testadas para cada u (gramatica do puzzle: tokens -> SHA256 -> hex; e as
formas textuais naturais da propria selecao):
  - "u_raw"        : os 32 bytes de u usados crus como -pass
  - "u_sha256hex"  : sha256(u).hexdigest() como -pass (a forma canonica das fases 0-3.2)
  - "u_hex"        : u.hex() como texto de senha (representacao textual natural de u)
  - "texto_raw"    : a subsequencia de simbolos a-i (ou dos digitos do par) como texto de senha
  - "texto_sha256" : sha256hex da subsequencia de simbolos como -pass

ORACULO DURO: G.try_password_all (candidato semantico/privkey embutido) + G.priv_hit /
G.fast_priv_scan em u e sha256(u) contra os dois enderecos-alvo (TARGET_H160S). Padding PKCS7
isolado e RUIDO (1/255 em escala) -- so registrado para o z-score, nunca chamado de achado.
"""
import sys, os, json, time, math, random, hashlib
from collections import OrderedDict

AQUI = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.join(AQUI, "..", "..", "experiments", "claude_endgame_2026_09_02")
sys.path.insert(0, os.path.abspath(KIT))
import gsmg_common as G  # noqa: E402

SAIDA = os.path.abspath(os.path.join(AQUI, "..", "..", "..", "_work",
                                      "enxame_2026-09-19", "faed_256_aes"))
os.makedirs(SAIDA, exist_ok=True)

BLOBS = ("SMALL", "COSMIC", "TAIL32")
KDF = "both"  # SHA256 + MD5
FORMAS = ("u_raw", "u_sha256hex", "u_hex", "texto_raw", "texto_sha256")


# ------------------------------------------------------------------ empacotamento
def int_to_bytes32(v):
    if v == 0:
        return b"\x00" * 32
    h = format(v, "x")
    if len(h) % 2:
        h = "0" + h
    b = bytes.fromhex(h)
    if len(b) > 32:
        b = b[-32:]           # trunca os bits ALTOS (mod 2**256); mantem os 256 bits baixos
    else:
        b = b.rjust(32, b"\0")  # zero-preenche a esquerda (leitura big-endian natural)
    return b


def pack_b9(sub):
    d0 = G.digits(sub, False)  # a=0..h=8
    v = 0
    for x in d0:
        v = v * 9 + x
    return int_to_bytes32(v)


def ascii32(sub):
    b = bytes(ord(c) for c in sub)
    return (b[:32]).ljust(32, b"\0")


def ascii_windows(sub):
    b = bytes(ord(c) for c in sub)
    n = len(b)
    if n < 32:
        return
    for o in range(n - 31):
        yield b[o:o + 32], sub[o:o + 32]


# ------------------------------------------------------------------ as 5 familias de selecao
def familia_indices(faed):
    N = len(faed)
    sel = OrderedDict()
    sel["primos_b0"] = [i for i in range(N) if G.is_prime(i)]
    sel["primos_b1"] = [i for i in range(N) if G.is_prime(i + 1)]
    sel["cores_colored"] = sorted(i for i in G.COLORED if i < N)
    sel["cores_blue"] = sorted(i for i in G.BLUE_IDX if i < N)
    sel["cores_yellow"] = sorted(i for i in G.YELLOW_IDX if i < N)
    sel["gi"] = [i for i, c in enumerate(faed) if c in "gi"]
    sel["gi_complemento"] = [i for i, c in enumerate(faed) if c not in "gi"]
    for c in sorted(set(G.COLORED)):
        idx = [i for i in range(N) if i and i % c == 0]
        if len(idx) >= 8:
            sel[f"multiplos_{c}"] = idx
    return sel


def familia_pares(faed):
    """i / i+285 (570 = 2x285): duas combinacoes, cada uma vira 1 sequencia de 285 'digitos'."""
    assert len(faed) == 570
    A2I0 = {c: i for i, c in enumerate("abcdefghi")}  # a=0..i=8
    soma_digs, xor_bytes = [], []
    for i in range(285):
        a, b = faed[i], faed[i + 285]
        soma_digs.append((A2I0[a] + A2I0[b]) % 9)
        xor_bytes.append(ord(a) ^ ord(b))
    return soma_digs, xor_bytes, faed[:285], faed[285:]


def digs_pack_b9(digs):
    v = 0
    for x in digs:
        v = v * 9 + x
    return int_to_bytes32(v)


def digs_windows_bytes(vals, texto_a, texto_b, nome):
    """vals: lista de 285 inteiros pequenos (soma mod 9 ou xor de bytes ASCII).
    Gera janelas de 32 usando os proprios valores como bytes (mod 256)."""
    buf = bytes(v & 0xFF for v in vals)
    n = len(buf)
    for o in range(n - 31):
        # texto natural = concatenacao dos pares (faed[i], faed[i+285]) na janela, p/ forma textual
        txt = "".join(texto_a[o:o + 32]) + "".join(texto_b[o:o + 32])
        yield buf[o:o + 32], f"{nome}@{o}", txt


PREDS = [
    ("odd", lambda d: d % 2),
    ("hi", lambda d: 1 if d >= 5 else 0),
    ("prime", lambda d: 1 if d in (2, 3, 5, 7) else 0),
    ("gi", lambda d: 1 if d in (7, 9) else 0),   # g=7, i=9 na indexacao a=1..i=9
    ("abc", lambda d: 1 if d <= 3 else 0),
]


def bits_preds_windows(sub, nome):
    """1 bit/simbolo por predicado (so quando a selecao tem >=256 simbolos): todas as janelas
    de 256 bits, como o `select_bits.py` historico fazia -- aqui viram SENHA, nao so privkey."""
    d1 = G.digits(sub, True)
    if len(d1) < 256:
        return
    for pname, f in PREDS:
        bits = "".join(str(f(d)) for d in d1)
        for o in range(len(bits) - 255):
            u = int(bits[o:o + 256], 2).to_bytes(32, "big")
            yield u, sub, f"{nome}/bits_{pname}@{o}"


def multibit_windows(sub, nome):
    """2/3/4 bits por simbolo (valor mod 2**w), todas as janelas de 256 bits (equivalente ao
    `multibit` historico, que so alimentava privkey; aqui tambem vira senha)."""
    d0 = G.digits(sub, False)
    if len(d0) < 64:
        return
    for w in (2, 3, 4):
        bits = "".join(format(x & ((1 << w) - 1), f"0{w}b") for x in d0)
        if len(bits) < 256:
            continue
        for o in range(len(bits) - 255):
            u = int(bits[o:o + 256], 2).to_bytes(32, "big")
            yield u, sub, f"{nome}/pack{w}@{o}"


# ------------------------------------------------------------------ geracao de candidatos U
def gerar_candidatos(faed):
    """Retorna lista de (u:bytes32, texto:str, origem:str). texto e a forma textual natural
    correspondente (subsequencia de simbolos, ou concat dos pares no caso i/i+285)."""
    cands = []
    sel = familia_indices(faed)
    for nome, idx in sel.items():
        sub = "".join(faed[i] for i in idx)
        rev = sub[::-1]
        cands.append((pack_b9(sub), sub, f"{nome}/pack_b9"))
        cands.append((pack_b9(rev), rev, f"{nome}/pack_b9/rev"))
        cands.append((ascii32(sub), sub[:32], f"{nome}/ascii32"))
        for u, txt in ascii_windows(sub):
            cands.append((u, txt, f"{nome}/win@?"))
        for direcao, s in (("", sub), ("/rev", rev)):
            for u, txt, org in bits_preds_windows(s, nome + direcao):
                cands.append((u, txt, org))
            for u, txt, org in multibit_windows(s, nome + direcao):
                cands.append((u, txt, org))

    soma_digs, xor_bytes, ta, tb = familia_pares(faed)
    # pack unico (todos os 285)
    cands.append((digs_pack_b9(soma_digs), "".join(ta) + "".join(tb), "par_i_i285_soma/pack_b9"))
    xb = bytes(v & 0xFF for v in xor_bytes)
    cands.append(((xb[:32]).ljust(32, b"\0"), ta[:32] + tb[:32], "par_i_i285_xor/ascii32"))
    for u, nome, txt in digs_windows_bytes(soma_digs, ta, tb, "par_i_i285_soma/win"):
        cands.append((u, txt, nome))
    for u, nome, txt in digs_windows_bytes(xor_bytes, ta, tb, "par_i_i285_xor/win"):
        cands.append((u, txt, nome))
    return cands


# ------------------------------------------------------------------ formas de senha
def formas_de(u, texto):
    return {
        "u_raw": u,
        "u_sha256hex": hashlib.sha256(u).hexdigest(),
        "u_hex": u.hex(),
        "texto_raw": texto,
        "texto_sha256": hashlib.sha256(texto.encode("latin-1", "replace")).hexdigest(),
    }


# ------------------------------------------------------------------ oraculo AES + privkey
def testar_um(pw):
    """pw: bytes ou str. Retorna (hard, soft) de G.try_password_all."""
    return G.try_password_all(pw, blobs=BLOBS, kdf=KDF)


def testar_privkey(u):
    hits = []
    for tag, k in (("u", u), ("sha256(u)", G.sha(u))):
        r = G.priv_hit(k)
        if r:
            hits.append({"forma": tag, "priv": k.hex(), "resultado": r})
    return hits


# ------------------------------------------------------------------ controle positivo
def controle_positivo():
    """(A) estrutural: planta uma privkey K nas 104 posicoes primas (base-9) de um faed
    sintetico e confere que pack_b9(sub_primos) == K (o motor de selecao recupera o alvo).
    (B) AES: usa sha256hex(K) como senha de um envelope plantado e confere que o BRACO DE
    SENHA desta frente (testar_um) o abre -- prova que o braco AES realmente funciona, nao
    so o de privkey."""
    rnd = random.Random(7)
    K = G.sha(b"faed_256_aes controle positivo 2026-09-19")
    P = [i for i in range(570) if G.is_prime(i)]
    assert len(P) == 104
    v = int.from_bytes(K, "big")
    digs = []
    x = v
    for _ in range(104):
        digs.append(x % 9)
        x //= 9
    assert x == 0, "104 digitos base-9 nao cobrem 256 bits"
    digs = digs[::-1]
    s = [rnd.choice("abcdefghi") for _ in range(570)]
    for p, d in zip(P, digs):
        s[p] = chr(97 + d)
    faed_sint = "".join(s)
    sub = "".join(faed_sint[i] for i in P)
    u_rec = pack_b9(sub)
    estrutural_ok = (u_rec == K)

    # envelope plantado, senha = sha256hex(K)
    import subprocess
    OPENSSL = "openssl"
    senha = hashlib.sha256(K).hexdigest()
    pt = b"faed_256_aes 2026-09-19: envelope plantado, sha256hex(u) como senha do braco AES."
    r = subprocess.run([OPENSSL, "enc", "-aes-256-cbc", "-md", "sha256", "-salt",
                        "-pass", "pass:" + senha], input=pt, capture_output=True, timeout=30)
    assert r.returncode == 0 and r.stdout[:8] == b"Salted__", r.stderr
    env = r.stdout
    G.BLOBS["CONTROLE_PONTE"] = (env[8:16], env[16:])
    try:
        formas = formas_de(u_rec, sub)
        aberturas = []
        for nome, pw in formas.items():
            hard, soft = G.try_password_all(pw, blobs=("CONTROLE_PONTE",), kdf="both")
            for rec in hard:
                if bytes.fromhex(rec["hex"]) == pt:
                    aberturas.append({"forma": nome, "kdf": rec["kdf"]})
    finally:
        del G.BLOBS["CONTROLE_PONTE"]
    aes_ok = any(a["forma"] == "u_sha256hex" for a in aberturas)
    return {"estrutural_ok": estrutural_ok, "K_hex": K.hex(), "senha_sha256hex": senha,
            "aes_ok": aes_ok, "aberturas": aberturas, "u_recuperado": u_rec.hex()}


# ------------------------------------------------------------------ nulo casado
def _celula_padrao(faed):
    """Sub-conjunto barato e representativo para o nulo: familia 'primos' + 'gi' + 'par i/i285'
    (pack_b9 + ascii32, sem as janelas grandes) x forma sha256hex x SMALL/TAIL32 x 2 KDF."""
    n_padding = 0
    n_pw = 0
    sel = familia_indices(faed)
    subset = {k: v for k, v in sel.items() if k in
              ("primos_b0", "primos_b1", "gi", "gi_complemento", "cores_colored",
               "cores_blue", "cores_yellow")}
    us = []
    for nome, idx in subset.items():
        sub = "".join(faed[i] for i in idx)
        us.append(pack_b9(sub))
        us.append(ascii32(sub))
    soma_digs, xor_bytes, ta, tb = familia_pares(faed)
    us.append(digs_pack_b9(soma_digs))
    xb = bytes(v & 0xFF for v in xor_bytes)
    us.append((xb[:32]).ljust(32, b"\0"))
    for u in us:
        pw = hashlib.sha256(u).hexdigest()
        n_pw += 1
        for b in ("SMALL", "TAIL32"):
            for k, p in G.aes_try(pw, b, kdf="both"):
                n_padding += 1
    return n_pw, n_padding


def nulo_um(semente):
    f = list(G.FAED)
    random.Random(semente).shuffle(f)
    n_pw, n_pad = _celula_padrao("".join(f))
    return semente, n_pw, n_pad


# ------------------------------------------------------------------ principal
def main():
    t0 = time.time()
    print("controle positivo...", flush=True)
    ctl = controle_positivo()
    print("controle:", ctl["estrutural_ok"], ctl["aes_ok"], round(time.time() - t0, 1), "s", flush=True)
    assert ctl["estrutural_ok"] and ctl["aes_ok"], "controle positivo falhou"

    print("gerando candidatos U...", flush=True)
    cands = gerar_candidatos(G.FAED)
    print("candidatos U (com repeticao):", len(cands), flush=True)

    # senhas distintas, por forma, preservando a origem de menor indice para o relatorio
    senhas = {}  # pw(bytes) -> (forma, origem, u_hex)
    n_formas_geradas = 0
    for u, texto, origem in cands:
        for forma, pw in formas_de(u, texto).items():
            n_formas_geradas += 1
            pwb = pw if isinstance(pw, bytes) else pw.encode("latin-1", "replace")
            senhas.setdefault(pwb, (forma, origem, u.hex()))
    print("senhas distintas:", len(senhas), "chamadas de formas_de:", n_formas_geradas,
          round(time.time() - t0, 1), "s", flush=True)

    n_aes_calls = 0
    n_padding = 0
    candidatos_duros = []
    priv_hits = []
    u_ja_testados = set()
    for u, texto, origem in cands:
        if u not in u_ja_testados:
            u_ja_testados.add(u)
            ph = testar_privkey(u)
            if ph:
                priv_hits.append({"u": u.hex(), "origem": origem, "hits": ph})

    for pwb, (forma, origem, uhex) in senhas.items():
        n_aes_calls += 1
        hard, soft = testar_um(pwb)
        n_padding += len(hard) + len(soft)
        if hard:
            for rec in hard:
                candidatos_duros.append({"forma": forma, "origem": origem, "u_hex": uhex,
                                          "pw_hex": pwb.hex(), **rec})

    print("AES: senhas testadas", n_aes_calls, "decisoes AES", n_aes_calls * len(BLOBS) * 2,
          "paddings(hard+soft)", n_padding, "candidatos_duros", len(candidatos_duros),
          "priv_hits", len(priv_hits), round(time.time() - t0, 1), "s", flush=True)

    print("nulo casado (100 embaralhamentos)...", flush=True)
    nulo = [nulo_um(s) for s in range(1, 101)]
    ns_pad = [n for _, _, n in nulo]
    obs_pw, obs_pad = _celula_padrao(G.FAED)
    media = sum(ns_pad) / len(ns_pad)
    dp = math.sqrt(sum((x - media) ** 2 for x in ns_pad) / (len(ns_pad) - 1)) if len(ns_pad) > 1 else 0.0
    z = (obs_pad - media) / dp if dp > 0 else float("nan")
    taxa_esperada = 1 - (255 / 256) ** 32  # padding PKCS7 valido por decifracao, ~1/8 nao, ver nota
    n_pw_celula = ns_pad and nulo[0][1]
    esperado_analitico = n_pw_celula * 2 * 2 * (1 / 255)  # SMALL,TAIL32 x SHA256,MD5 x taxa 1/255
    nulo_res = {"embaralhamentos": 100, "celula": "primos+gi+cores+par_i_i285 (pack_b9+ascii32) "
                "x sha256hex x SMALL,TAIL32 x SHA256,MD5",
                "senhas_por_embaralhamento": nulo[0][1], "observado_real": obs_pad,
                "nulo_media": round(media, 3), "nulo_dp": round(dp, 3),
                "nulo_min": min(ns_pad), "nulo_max": max(ns_pad),
                "z_padding": round(z, 3) if dp > 0 else None,
                "esperado_analitico_1_255": round(esperado_analitico, 3)}
    print("nulo:", nulo_res, flush=True)

    # contagem por familia (para declarar cobertura exata)
    por_familia = {}
    for u, texto, origem in cands:
        fam = origem.split("/")[0]
        por_familia[fam] = por_familia.get(fam, 0) + 1

    summary = {
        "frente": "faed_256_aes", "campanha": "enxame_2026-09-19",
        "candidatos_u_com_repeticao": len(cands),
        "candidatos_u_distintos": len(u_ja_testados),
        "por_familia_contagem_u": por_familia,
        "formas_de_senha": list(FORMAS),
        "senhas_distintas_testadas": len(senhas),
        "chamadas_formas_de": n_formas_geradas,
        "blobs": list(BLOBS), "kdf": "SHA256+MD5 (both)",
        "decisoes_aes_totais": n_aes_calls * len(BLOBS) * 2,
        "paddings_hard_mais_soft": n_padding,
        "candidatos_duros_oraculo_semantico": len(candidatos_duros),
        "candidatos_duros_lista": candidatos_duros,
        "privkey_hits_diretos": priv_hits,
        "privkeys_testadas_u_e_sha256u": 2 * len(u_ja_testados),
        "controle_positivo": ctl,
        "nulo": nulo_res,
        "segundos": round(time.time() - t0, 1),
    }
    with open(os.path.join(SAIDA, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print("FIM", json.dumps({k: summary[k] for k in (
        "candidatos_u_com_repeticao", "candidatos_u_distintos", "senhas_distintas_testadas",
        "decisoes_aes_totais", "paddings_hard_mais_soft", "candidatos_duros_oraculo_semantico",
        "privkey_hits_diretos", "segundos")}))


if __name__ == "__main__":
    main()
