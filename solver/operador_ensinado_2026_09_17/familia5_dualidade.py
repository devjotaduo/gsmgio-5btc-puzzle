# -*- coding: utf-8 -*-
"""
FAMILIA 5 - "yinyang" como OPERACAO DE DUALIDADE sobre os proprios objetos do puzzle.

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O par "THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF" nao e um par de palavras-senha: e uma
INSTRUCAO ESTRUTURAL. Existem, no material publicado, pares de objetos do MESMO TIPO que o autor
partiu ao meio ou publicou em duplicata (as duas linhas base64 de 64 caracteres do blob SMALL, com
a palavra "enter" entre elas; os dois envelopes openssl de 96 bytes SMALL e TAIL32; as duas metades
de dbbi/faed/dos 84 tokens logicos; a matriz e seu complemento azul<->amarelo; as duas estrelas da
capa de "Cosmic Duality", uma branca e uma amarela). A hipotese e que UM membro do par gera a senha
do OUTRO - por ser usado cru, em base64, em hex ou como sha256 hex (o formato canonico das fases
0-3.2) - ou que a combinacao dual dos dois (XOR, concatenacao trocada, sha dos shas) e a senha.

FALSIFICACAO: se nenhuma das senhas derivadas desses pares abrir um dos tres blobs sob o oraculo
duro (privkey do premio, >=85% ASCII, WIF/hex64, blob openssl aninhado, assinatura EBCDIC cp273), e
se a taxa de padding PKCS7 observada ficar dentro do nulo casado (1/256), a familia esta fechada.

COLISOES DECLARADAS com a tabela do ENDGAME.md (nao regastadas aqui)
-------------------------------------------------------------------
- Montagem/permutacao dos blocos do ciphertext e salt cruzado SMALL<->TAIL32: REFUTADO com cobertura
  completa (1,22 bi logicos). NAO e repetido. Aqui os blobs entram so como MATERIAL DE SENHA.
- Metades do faed combinadas por aritmetica modular (halfhalf_arith) e por intercalacao
  (yinyang_interleave): fechadas. Aqui as metades entram so como senha/chave crua/hex/b64/sha.
- Inversao yin-yang da matriz e cores como numeros: negativo PARCIAL (945 k AES). A parte nova
  atacada aqui e so a serializacao pelo operador RAB (a1z26 -> lista|soma) e pelo codec z do
  COMPLEMENTO (matriz invertida, URL com o bit das cores trocado), nao as cores como numeros.
- Senhas Unicode com yin-yang (754 k) e o corpus historico de 466 k tokens: fechados; as frases
  "whitestar"/"yellowstar" e seus derivados de indice nunca foram geradas.

CONTROLE POSITIVO: o blob da fase 2 abre com sha256hex("causality") sob EVP-SHA256 (e nao sob MD5),
rodando pelo MESMO caminho (evp -> AES-CBC -> unpad -> G.semantic) usado nas quatro sub-familias.
NULO CASADO: 100 aleatorizacoes por sub-familia preservando tipo, comprimento e alfabeto de cada
senha, no mesmo pipeline; z da taxa de padding e do maximo de "printable".

Uso: python familia5_dualidade.py
"""
import sys, os, json, time, random, base64, itertools, statistics

SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

OUT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\_work\operador_ensinado_2026-09-17\familia5_dualidade"
os.makedirs(OUT, exist_ok=True)
LOG = os.path.join(OUT, "familia5_dualidade.jsonl")
TARGETS = ("SMALL", "COSMIC", "TAIL32")
NULL_ITERS = 100
NULL_CAP = 2000          # senhas por sub-familia em cada embaralhamento (declarado no relatorio)

# ---------------------------------------------------------------- material bruto
S_SALT, S_CT = G.BLOBS["SMALL"]
S_RAW = b"Salted__" + S_SALT + S_CT                                        # 96 B
T_SALT, T_CT = G.BLOBS["TAIL32"]
T_RAW = b"Salted__" + T_SALT + T_CT                                        # 96 B
C_SALT, C_CT = G.BLOBS["COSMIC"]
C_RAW = b"Salted__" + C_SALT + C_CT                                        # 1344 B
# as duas linhas base64 de 64 chars exatamente como estao na pagina (com "enter" entre elas)
S_L1, S_L2 = G.SMALL_B64[:64], G.SMALL_B64[64:]
T_L1, T_L2 = G.TAIL32_B64[:64], G.TAIL32_B64[64:]
URL = b"gsmg.io/theseedisplanted"


def X(a, b):
    """XOR truncado ao menor."""
    n = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(n))


def segmentacoes(text=G.DBBI):
    """Regra yellowblueprimes: posicao logica prima consome b ou be; as demais, 1 simbolo."""
    res = []

    def rec(i, pos, toks):
        if i == len(text):
            res.append(list(toks))
            return
        if G.is_prime(pos):
            if text[i] == "b":
                if i + 1 < len(text) and text[i + 1] == "e":
                    rec(i + 2, pos + 1, toks + ["be"])
                rec(i + 1, pos + 1, toks + ["b"])
        else:
            rec(i + 1, pos + 1, toks + [text[i]])

    rec(0, 1, [])
    return res


SEGS = sorted(segmentacoes(), key=len)
assert len(SEGS) == 2 and [len(s) for s in SEGS] == [83, 84], [len(s) for s in SEGS]
TOK83, TOK84 = SEGS
RESID84 = "".join(t for i, t in enumerate(TOK84, 1) if not G.is_prime(i))
RESID83 = "".join(t for i, t in enumerate(TOK83, 1) if not G.is_prime(i))
assert RESID84 == "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae", RESID84


# ---------------------------------------------------------------- formas de senha
def byte_forms(b):
    """As 4 formas pedidas (crua, base64, hex, sha256) + variantes triviais do mesmo objeto."""
    h = b.hex()
    s64 = base64.b64encode(b).decode()
    yield "raw", b
    yield "hex", h
    yield "HEX", h.upper()
    yield "b64", s64
    yield "sha", G.shahex(b)
    yield "shabytes", G.sha(b)
    yield "sha_of_hex", G.shahex(h)
    yield "sha_of_b64", G.shahex(s64)
    yield "sha2", G.shahex(G.shahex(b))          # encadeamento de fase (sha do sha hex)
    yield "rev", b[::-1]
    yield "rev_hex", b[::-1].hex()


def text_forms(s):
    for t in sorted({s, s.lower(), s.upper(), s.replace(" ", ""),
                     s.lower().replace(" ", ""), s.upper().replace(" ", "")}):
        yield "txt", t
        yield "sha", G.shahex(t)
        yield "sha2", G.shahex(G.shahex(t))


def digits_of(s):
    return [G.A2I[c] for c in s if c in G.A2I]


# ---------------------------------------------------------------- sub-familia A: blobs
def fam_A():
    """Um envelope/metade como SENHA do outro. NAO monta ciphertext (isso esta refutado)."""
    objs = {}
    objs["S_h1"], objs["S_h2"] = S_RAW[:48], S_RAW[48:]
    objs["T_h1"], objs["T_h2"] = T_RAW[:48], T_RAW[48:]
    objs["C_h1"], objs["C_h2"] = C_RAW[:672], C_RAW[672:]
    objs["S_ct_h1"], objs["S_ct_h2"] = S_CT[:40], S_CT[40:]
    objs["T_ct_h1"], objs["T_ct_h2"] = T_CT[:40], T_CT[40:]
    objs["C_ct_h1"], objs["C_ct_h2"] = C_CT[:664], C_CT[664:]
    objs.update(S_raw=S_RAW, T_raw=T_RAW, C_raw=C_RAW, S_ct=S_CT, T_ct=T_CT, C_ct=C_CT,
                S_salt=S_SALT, T_salt=T_SALT, C_salt=C_SALT)
    # dualidades: XOR das metades e dos envelopes
    objs["xor_S_halves"] = X(objs["S_h1"], objs["S_h2"])
    objs["xor_T_halves"] = X(objs["T_h1"], objs["T_h2"])
    objs["xor_C_halves"] = X(objs["C_h1"], objs["C_h2"])
    objs["xor_S_ct_halves"] = X(objs["S_ct_h1"], objs["S_ct_h2"])
    objs["xor_T_ct_halves"] = X(objs["T_ct_h1"], objs["T_ct_h2"])
    objs["xor_ST_ct"] = X(S_CT, T_CT)
    objs["xor_ST_raw"] = X(S_RAW, T_RAW)
    objs["xor_ST_salt"] = X(S_SALT, T_SALT)
    objs["xor_SC_ct_head"] = X(S_CT, C_CT[:80])
    objs["xor_SC_ct_tail"] = X(S_CT, C_CT[-80:])
    objs["xor_TC_ct_head"] = X(T_CT, C_CT[:80])
    objs["xor_TC_ct_tail"] = X(T_CT, C_CT[-80:])
    objs["xor_S_h1_T_h1"] = X(objs["S_h1"], objs["T_h1"])
    objs["xor_S_h2_T_h2"] = X(objs["S_h2"], objs["T_h2"])
    objs["xor_S_h1_T_h2"] = X(objs["S_h1"], objs["T_h2"])
    objs["xor_S_h2_T_h1"] = X(objs["S_h2"], objs["T_h1"])
    objs["xor_S_ct_rev"] = X(S_CT, S_CT[::-1])
    objs["xor_T_ct_rev"] = X(T_CT, T_CT[::-1])
    # metades trocadas / cruzadas
    objs["S_swap"] = objs["S_h2"] + objs["S_h1"]
    objs["T_swap"] = objs["T_h2"] + objs["T_h1"]
    objs["S_ct_swap"] = objs["S_ct_h2"] + objs["S_ct_h1"]
    objs["T_ct_swap"] = objs["T_ct_h2"] + objs["T_ct_h1"]
    objs["cross_S1T2"] = objs["S_h1"] + objs["T_h2"]
    objs["cross_T1S2"] = objs["T_h1"] + objs["S_h2"]
    objs["ct_ST"] = S_CT + T_CT
    objs["ct_TS"] = T_CT + S_CT

    out = []
    for name, b in objs.items():
        for f, pw in byte_forms(b):
            out.append(("A/%s/%s" % (name, f), pw))
    # as linhas base64 literais da pagina, como texto
    for name, s in (("S_L1", S_L1), ("S_L2", S_L2), ("T_L1", T_L1), ("T_L2", T_L2),
                    ("S_L2L1", S_L2 + S_L1), ("T_L2T1", T_L2 + T_L1),
                    ("S_L1_T_L2", S_L1 + T_L2), ("T_L1_S_L2", T_L1 + S_L2),
                    ("S_b64", G.SMALL_B64), ("T_b64", G.TAIL32_B64)):
        for f, pw in text_forms(s):
            out.append(("A/%s/%s" % (name, f), pw))
    # a pagina poe a palavra "enter" INLINE entre as duas linhas base64: metade ENTER melhor-metade
    for sep in ("", "enter", "ENTER", " enter ", "\n", "\nenter\n", " ", "Enter"):
        for na, a, nb, b in (("S1", S_L1, "S2", S_L2), ("S2", S_L2, "S1", S_L1),
                             ("T1", T_L1, "T2", T_L2), ("T2", T_L2, "T1", T_L1),
                             ("S1", S_L1, "T2", T_L2), ("T1", T_L1, "S2", S_L2)):
            s = a + sep + b
            out.append(("A/enter/%s%s%s/txt" % (na, sep.strip() or "_", nb), s))
            out.append(("A/enter/%s%s%s/sha" % (na, sep.strip() or "_", nb), G.shahex(s)))
    # pares ordenados de metades: sha da concatenacao em cada forma + xor dos shas
    halves = [(k, objs[k]) for k in ("S_h1", "S_h2", "T_h1", "T_h2",
                                     "S_ct_h1", "S_ct_h2", "T_ct_h1", "T_ct_h2")]
    for (na, a), (nb, b) in itertools.permutations(halves, 2):
        p = "A/pair/%s+%s" % (na, nb)
        out.append((p + "/sha_hex", G.shahex(a.hex() + b.hex())))
        out.append((p + "/sha_b64", G.shahex(base64.b64encode(a).decode() +
                                             base64.b64encode(b).decode())))
        out.append((p + "/sha_raw", G.shahex(a + b)))
        out.append((p + "/sha_of_shas", G.shahex(G.shahex(a) + G.shahex(b))))
        out.append((p + "/xor_shas", X(G.sha(a), G.sha(b)).hex()))
        out.append((p + "/raw", a + b))
    return out


# ---------------------------------------------------------------- sub-familia B: matriz/URL complementar
def fam_B():
    """Complemento yin-yang da matriz e da URL, serializado pelo operador RAB e pelo codec z."""
    inv = [[1 - v for v in row] for row in G.MATRIX_README]
    bits_sp = "".join(str(G.MATRIX_README[r][c]) for r, c in G.SPIRAL)
    bits_sp_inv = "".join("01"[1 - int(b)] for b in bits_sp)
    bits_rm = "".join(str(v) for row in G.MATRIX_README for v in row)
    bits_rm_inv = "".join("01"[1 - int(b)] for b in bits_rm)

    def packbits(bs):
        bs = bs[:len(bs) // 8 * 8]
        return bytes(int(bs[i:i + 8], 2) for i in range(0, len(bs), 8))

    objs = {
        "url": URL,
        "url_bitflip": bytes(b ^ 1 for b in URL),          # troca azul<->amarelo (ultimo bit de cada byte)
        "url_complement": bytes(b ^ 0xFF for b in URL),    # inversao total
        "matrix_spiral": packbits(bits_sp),
        "matrix_spiral_inv": packbits(bits_sp_inv),
        "matrix_rowmajor": packbits(bits_rm),
        "matrix_rowmajor_inv": packbits(bits_rm_inv),
    }
    out = []
    for name, b in objs.items():
        for f, pw in byte_forms(b):
            out.append(("B/%s/%s" % (name, f), pw))
    # operador RAB (a1z26): letras -> ordinais -> lista concatenada | soma
    rab_src = {
        "url": "gsmgiotheseedisplanted",
        "url_bitflip": "".join(chr(b ^ 1) for b in URL),
        "yinyang": "yinyang", "yingyang": "yingyang",
        "yellowblueprimes": "yellowblueprimes", "blueyellowprimes": "blueyellowprimes",
        "matrixsumlist": "matrixsumlist", "thispassword": "thispassword",
        "lastwords": "lastwordsbeforearchichoice",
        "salphaseion": "salphaseion", "cosmicduality": "cosmicduality",
        "halfandbetterhalf": "halfandbetterhalf", "half": "half", "betterhalf": "betterhalf",
        "whitestar": "whitestar", "yellowstar": "yellowstar",
        "colorseq": G.COLOR_SEQ.lower(),
        "colorseq_swap": G.COLOR_SEQ.lower().translate(str.maketrans("by", "yb")),
    }
    for name, s in rab_src.items():
        ords = [ord(c) - 96 for c in s if "a" <= c <= "z"]
        if not ords:
            continue
        lista = "".join(str(o) for o in ords)
        soma = str(sum(ords))
        for f, pw in text_forms(lista):
            out.append(("B/rab_lista/%s/%s" % (name, f), pw))
        for f, pw in text_forms(soma):
            out.append(("B/rab_soma/%s/%s" % (name, f), pw))
        try:
            zb = G.z_method([o % 10 for o in ords])
            for f, pw in byte_forms(zb):
                out.append(("B/rab_z/%s/%s" % (name, f), pw))
        except Exception:
            pass
    # somas de linha/coluna da matriz e do complemento (RAB: lista e soma)
    for name, M in (("matrix", G.MATRIX_README), ("matrix_inv", inv)):
        for tag, lst in (("rows", G.row_sums(M)), ("cols", G.col_sums(M))):
            lista = "".join(str(v) for v in lst)
            soma = str(sum(lst))
            for f, pw in text_forms(lista):
                out.append(("B/%s_%s_lista/%s" % (name, tag, f), pw))
            for f, pw in text_forms(soma):
                out.append(("B/%s_%s_soma/%s" % (name, tag, f), pw))
            try:
                for f, pw in byte_forms(G.z_method([v % 10 for v in lst])):
                    out.append(("B/%s_%s_z/%s" % (name, tag, f), pw))
            except Exception:
                pass
    return out


# ---------------------------------------------------------------- sub-familia C: o par de estrelas
def fam_C():
    """A capa: uma estrela branca no campo escuro e uma amarela no campo claro, como par."""
    base = ["whitestar", "yellowstar", "white star", "yellow star", "starwhite", "staryellow",
            "thewhitestar", "theyellowstar", "whitestarandyellowstar",
            "onewhitestaroneyellowstar", "awhitestarandayellowstar",
            "whitestaryellowstar", "yellowstarwhitestar", "white and yellow star",
            "whitesun", "yellowsun", "whitedot", "yellowdot", "whitepoint", "yellowpoint"]
    glue = ["yinyang", "yingyang", "cosmicduality", "salphaseion", "halfandbetterhalf",
            "yellowblueprimes"]
    phrases = list(base)
    for a, b in itertools.permutations(["whitestar", "yellowstar"], 2):
        for sep in ("", " ", "and", "&", "-"):
            phrases.append(a + sep + b)
    for g in glue:
        for p in ("whitestar", "yellowstar", "whitestaryellowstar", "yellowstarwhitestar"):
            phrases += [g + p, p + g]
    # cores como par (branco da celula FEFEFE, amarelo #FFF200, azul #3F48CC)
    cores = ["FEFEFE", "FFFFFF", "FFF200", "3F48CC"]
    for a, b in itertools.permutations(cores, 2):
        phrases += [a + b, "#" + a + "#" + b, a + " " + b]
    # o par de indices: estrela branca = indice espiral 163; amarelas = 9 indices
    w_idx = 163
    w_r, w_c = G.COLORED[163][1], G.COLORED[163][2]
    yells = sorted(i for i, v in G.COLORED.items() if v[0] == "Y")
    for y in yells:
        yr, yc = G.COLORED[y][1], G.COLORED[y][2]
        phrases += ["%d%d" % (w_idx, y), "%d%d" % (y, w_idx), "%d,%d" % (w_idx, y),
                    "%d-%d" % (w_idx, y), str(w_idx + y), str(abs(w_idx - y)), str(w_idx * y),
                    "%d%d%d%d" % (w_r, w_c, yr, yc), "%d%d%d%d" % (yr, yc, w_r, w_c)]
    phrases.append("".join(str(y) for y in yells) + str(w_idx))
    phrases.append(str(w_idx) + "".join(str(y) for y in yells))
    out = []
    for p in dict.fromkeys(phrases):
        for f, pw in text_forms(p):
            out.append(("C/%s/%s" % (p[:24], f), pw))
    return out


# ---------------------------------------------------------------- sub-familia D: corte ao meio
def fam_D():
    """half/betterhalf como PARAMETRO DE CORTE; cada metade como senha e como chave."""
    tok84 = "".join(TOK84)
    tok83 = "".join(TOK83)
    bits_sp = "".join(str(G.MATRIX_README[r][c]) for r, c in G.SPIRAL)
    splits = {
        "dbbi45": (G.DBBI[:45], G.DBBI[45:]), "dbbi46": (G.DBBI[:46], G.DBBI[46:]),
        "faed285": (G.FAED[:285], G.FAED[285:]),
        "tok84_str": (tok84[:len(tok84) // 2], tok84[len(tok84) // 2:]),
        "tok83_str": (tok83[:len(tok83) // 2], tok83[len(tok83) // 2:]),
        "tok84_logic": ("".join(TOK84[:42]), "".join(TOK84[42:])),
        "tok83_logic": ("".join(TOK83[:41]), "".join(TOK83[41:])),
        "resid84_30": (RESID84[:30], RESID84[30:]), "resid84_31": (RESID84[:31], RESID84[31:]),
        "resid83_30": (RESID83[:30], RESID83[30:]),
        "matrixbits": (bits_sp[:98], bits_sp[98:]),
        "url": ("gsmg.io/thes", "eedisplanted"),
        "url_nodot": ("gsmgiot", "heseedisplanted"),
        "msl": ("matrixsum", "list"),
        "lastwords": ("lastwordsbefo", "rearchichoice"),
        "colorseq": (G.COLOR_SEQ[:12], G.COLOR_SEQ[12:]),
    }
    out = []
    for name, (a, b) in splits.items():
        for lbl, h in (("half", a), ("better", b)):
            for f, pw in text_forms(h):
                out.append(("D/%s/%s/%s" % (name, lbl, f), pw))
            d = digits_of(h)
            if d:
                for f, pw in text_forms("".join(str(x) for x in d)):
                    out.append(("D/%s/%s/dig/%s" % (name, lbl, f), pw))
                out.append(("D/%s/%s/soma" % (name, lbl), str(sum(d))))
                try:
                    for f, pw in byte_forms(G.z_method(d)):
                        out.append(("D/%s/%s/z/%s" % (name, lbl, f), pw))
                except Exception:
                    pass
        # combinacoes duais do par
        out += [("D/%s/AB" % name, a + b), ("D/%s/BA" % name, b + a),
                ("D/%s/sha_AB" % name, G.shahex(a + b)), ("D/%s/sha_BA" % name, G.shahex(b + a)),
                ("D/%s/shaA_shaB" % name, G.shahex(a) + G.shahex(b)),
                ("D/%s/shaB_shaA" % name, G.shahex(b) + G.shahex(a)),
                ("D/%s/sha_of_shas" % name, G.shahex(G.shahex(a) + G.shahex(b))),
                ("D/%s/sha_of_shas_rev" % name, G.shahex(G.shahex(b) + G.shahex(a))),
                ("D/%s/xor_shas" % name, X(G.sha(a), G.sha(b)).hex()),
                ("D/%s/xor_shas_raw" % name, X(G.sha(a), G.sha(b)))]
    return out


# ---------------------------------------------------------------- sub-familia E: gramatica do par
def fam_E():
    """Fechamento: sha256(A||B) para TODO par ordenado de representacoes duais (a gramatica das
    fases 0-3.2 e 'concatene as palavras na ordem certa e passe por sha256')."""
    S_h1, S_h2 = S_RAW[:48], S_RAW[48:]
    T_h1, T_h2 = T_RAW[:48], T_RAW[48:]
    pool = {}
    byte_objs = {"S_h1": S_h1, "S_h2": S_h2, "T_h1": T_h1, "T_h2": T_h2,
                 "S_ct_h1": S_CT[:40], "S_ct_h2": S_CT[40:],
                 "T_ct_h1": T_CT[:40], "T_ct_h2": T_CT[40:],
                 "S_ct": S_CT, "T_ct": T_CT, "S_salt": S_SALT, "T_salt": T_SALT}
    for n, b in byte_objs.items():
        pool[n + ".hex"] = b.hex()
        pool[n + ".b64"] = base64.b64encode(b).decode()
        pool[n + ".sha"] = G.shahex(b)
    pool["url"] = "gsmg.io/theseedisplanted"
    pool["url_bitflip"] = "".join(chr(b ^ 1) for b in URL)
    pool["colorseq"] = G.COLOR_SEQ
    pool["colorseq_swap"] = G.COLOR_SEQ.translate(str.maketrans("BY", "YB"))
    pool["whitestar"] = "whitestar"
    pool["yellowstar"] = "yellowstar"
    pool["half"] = "half"
    pool["betterhalf"] = "betterhalf"
    pool["yinyang"] = "yinyang"
    pool["dbbi_h1"], pool["dbbi_h2"] = G.DBBI[:45], G.DBBI[45:]
    pool["faed_h1"], pool["faed_h2"] = G.FAED[:285], G.FAED[285:]
    pool["resid_h1"], pool["resid_h2"] = RESID84[:30], RESID84[30:]
    out = []
    items = sorted(pool.items())
    for (na, a), (nb, b) in itertools.permutations(items, 2):
        p = "E/%s+%s" % (na, nb)
        out.append((p + "/cat", a + b))
        out.append((p + "/sha_cat", G.shahex(a + b)))
        out.append((p + "/sha_of_shas", G.shahex(G.shahex(a) + G.shahex(b))))
    return out


# ---------------------------------------------------------------- pipeline
def probe(pw):
    """Caminho unico: evp -> AES-CBC -> unpad -> oraculo duro. Devolve (hard, soft)."""
    return G.try_password_all(pw, blobs=TARGETS, kdf="both")


def probe_light(pw):
    """Mesmo caminho sem a varredura de privkey (usado no nulo)."""
    npad = nsem = 0
    mx = 0.0
    for b in TARGETS:
        for _, p in G.aes_try(pw, b, "both"):
            npad += 1
            mx = max(mx, G.printable(p))
            if G.semantic(p):
                nsem += 1
    return npad, nsem, mx


def controle_positivo():
    """Fase 2 abre com sha256hex('causality') sob EVP-SHA256 e e aceita pelo MESMO oraculo."""
    raw = base64.b64decode(G.PHASE2_B64)
    salt, ct = raw[8:16], raw[16:]
    res = {}
    for hm in (MD5, SHA256):
        k, iv = G.evp(G.shahex("causality").encode(), salt, hm)
        p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        res[hm.__name__] = None if p is None else {"semantic": G.semantic(p),
                                                   "head": p[:40].decode("latin-1")}
    r256 = res["Crypto.Hash.SHA256"]
    ok = bool(r256 and r256["semantic"] and r256["head"].startswith("The ironic")
              and not res["Crypto.Hash.MD5"])
    # controle negativo: senha errada do mesmo formato nao passa no oraculo
    k, iv = G.evp(G.shahex("caUsality").encode(), salt, SHA256)
    p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
    neg = (p is None) or (not G.semantic(p))
    return {"passou": bool(ok and neg), "detalhe": res, "negativo_ok": bool(neg)}


def shuffle_like(pw, rnd):
    """Nulo casado: preserva tipo, comprimento e alfabeto da senha."""
    if isinstance(pw, bytes):
        return bytes(rnd.randrange(256) for _ in range(len(pw)))
    alpha = sorted(set(pw)) or ["a"]
    return "".join(rnd.choice(alpha) for _ in pw)


def roda_familia(nome, pws, fh):
    t0 = time.time()
    n_trials = 0
    n_pad = 0
    hard_hits = []
    mx = 0.0
    for tag, pw in pws:
        hard, soft = probe(pw)
        n_trials += len(TARGETS) * 2
        for rec in hard + soft:
            n_pad += 1
            mx = max(mx, rec["printable"])
            rec["tag"] = tag
            rec["pw"] = pw.hex() if isinstance(pw, bytes) else pw
            fh.write(json.dumps({"tipo": "padding", **rec}, ensure_ascii=False) + "\n")
        for rec in hard:
            hard_hits.append({"tag": tag, **rec})
            fh.write(json.dumps({"tipo": "HARD", "tag": tag, **rec}, ensure_ascii=False) + "\n")
    # nulo casado
    rnd = random.Random(20260917)
    amostra = pws if len(pws) <= NULL_CAP else rnd.sample(pws, NULL_CAP)
    taxas = []
    sem_nulo = 0
    mx_nulo = []
    for it in range(NULL_ITERS):
        r = random.Random(1000 + it)
        pad_i = sem_i = 0
        mx_i = 0.0
        for _, pw in amostra:
            a, b, m = probe_light(shuffle_like(pw, r))
            pad_i += a
            sem_i += b
            mx_i = max(mx_i, m)
        taxas.append(pad_i / (len(amostra) * len(TARGETS) * 2))
        sem_nulo += sem_i
        mx_nulo.append(mx_i)
    mu = statistics.mean(taxas)
    sd = statistics.pstdev(taxas) or 1e-12
    taxa_obs = n_pad / max(1, n_trials)
    res = {"familia": nome, "senhas": len(pws), "decifracoes": n_trials,
           "padding_valido": n_pad, "taxa_padding": round(taxa_obs, 6),
           "taxa_esperada_1_256": round(1 / 256, 6),
           "nulo": {"iters": NULL_ITERS, "senhas_por_iter": len(amostra),
                    "decifracoes": NULL_ITERS * len(amostra) * len(TARGETS) * 2,
                    "taxa_media": round(mu, 6), "taxa_sd": round(sd, 6),
                    "hits_semanticos": sem_nulo,
                    "max_printable_medio": round(statistics.mean(mx_nulo), 3),
                    "max_printable_max": round(max(mx_nulo), 3)},
           "z_padding": round((taxa_obs - mu) / sd, 3), "max_printable_obs": round(mx, 3),
           "hits_duros": hard_hits, "segundos": round(time.time() - t0, 1)}
    fh.write(json.dumps({"tipo": "resumo_familia", **res}, ensure_ascii=False) + "\n")
    print(json.dumps({k: v for k, v in res.items() if k != "hits_duros"}, ensure_ascii=False))
    if hard_hits:
        print("  HITS DUROS:", json.dumps(hard_hits, ensure_ascii=False)[:2000])
    return res


def chaves_diretas(pws):
    """'the private keys belong to half and better half': senha de 32 B / hex64 / sha como privkey."""
    hits = []
    vistos = set()
    for tag, pw in pws:
        cands = []
        if isinstance(pw, bytes):
            if len(pw) == 32:
                cands.append(pw)
            cands.append(G.sha(pw))
        else:
            if len(pw) == 64 and all(c in "0123456789abcdefABCDEF" for c in pw):
                cands.append(bytes.fromhex(pw))
            cands.append(G.sha(pw))
        for c in cands:
            if c in vistos:
                continue
            vistos.add(c)
            if G.priv_hit(c):
                hits.append({"tag": tag, "priv": c.hex()})
    return {"privkeys_testadas": len(vistos), "hits": hits}


def main():
    t0 = time.time()
    ctrl = controle_positivo()
    print("controle positivo:", json.dumps(ctrl, ensure_ascii=False))
    assert ctrl["passou"], "CONTROLE POSITIVO FALHOU - nao confie em nada abaixo"
    fams = {"A_blobs_duais": fam_A(), "B_matriz_complemento": fam_B(),
            "C_par_de_estrelas": fam_C(), "D_corte_ao_meio": fam_D(),
            "E_gramatica_do_par": fam_E()}
    with open(LOG, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"tipo": "hipotese", "texto": __doc__.strip()}, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"tipo": "controle_positivo", **ctrl}, ensure_ascii=False) + "\n")
        resumos = [roda_familia(n, p, fh) for n, p in fams.items()]
        todas = [x for p in fams.values() for x in p]
        pk = chaves_diretas(todas)
        print("chaves diretas:", json.dumps(pk, ensure_ascii=False))
        fh.write(json.dumps({"tipo": "privkeys", **pk}, ensure_ascii=False) + "\n")
        total = {"tipo": "TOTAL", "senhas": sum(r["senhas"] for r in resumos),
                 "decifracoes": sum(r["decifracoes"] for r in resumos),
                 "decifracoes_nulo": sum(r["nulo"]["decifracoes"] for r in resumos),
                 "padding_valido": sum(r["padding_valido"] for r in resumos),
                 "hits_duros": sum(len(r["hits_duros"]) for r in resumos),
                 "privkeys_testadas": pk["privkeys_testadas"], "privkey_hits": len(pk["hits"]),
                 "segundos": round(time.time() - t0, 1)}
        fh.write(json.dumps(total, ensure_ascii=False) + "\n")
    print("TOTAL:", json.dumps(total, ensure_ascii=False))
    print("log:", LOG)


if __name__ == "__main__":
    main()
