# -*- coding: utf-8 -*-
r"""
FAMILIA 4 — "select from over twenty-three ciphers" como FAMILIA DE CODECS DE BYTE UNICO.

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
Na fase 3.2 o criador ja usou "cifra" com o sentido de CODEC: o campo 3 daquela pagina e um
texto cujos caracteres (lidos como Latin-1) RE-CODIFICADOS em IBM code page 1141 (Python cp273)
viram letras ASCII minusculas, e ele anunciou o codec por trocadilho ("One for one, four for
one" = 1141). A frase do Arquiteto "select from over twenty-three ciphers" nomearia, entao,
essa familia: os ~65 codecs de byte unico da stdlib (ISO-8859-1..16, cp125x, EBCDIC
037/273/424/500/875/1026/1140, cp437/850/..., KOI8, mac_*, tis_620, hp_roman8). O passo que
falta seria escolher OUTRO membro da familia para reinterpretar algum material do endgame.

A hipotese e falsa se, para TODOS os 65 codecs C:
  (A1) nenhum plaintext com padding valido ja coletado vira texto legivel sob C quando nao era
       legivel sob Latin-1;
  (A2) nenhum campo da pagina final (dbbi, faed, campos z, ciphertexts, base64) vira texto
       legivel/semantico sob C, em nenhuma das duas direcoes (re-encode e re-decode);
  (A3) nenhuma senha derivada de C abre SMALL/COSMIC/TAIL32 — nem o nome do codec como senha,
       nem (o braco forte) o padrao sha256(token) do puzzle aplicado aos BYTES DO TOKEN
       CODIFICADOS EM C em vez de ASCII.

Observacao que estrutura A3: 57 dos 65 codecs sao a IDENTIDADE sobre ASCII imprimivel, logo
sobre tokens ASCII so as 8 paginas EBCDIC (cp037, cp273, cp424, cp500, cp875, cp1026, cp1140,
ebcdic_cp_us) produzem bytes novos. O espaco realmente inedito e token x 8 EBCDIC, e o script
deduplica por bytes para nao inflar cobertura.

cp1141..cp1149 nao existem na stdlib do Python; cp1141 difere de cp273 SO no byte 0x9F
(EUR vs CURRENCY SIGN), que nao toca a imagem a-z nem o ASCII imprimivel — cp273 cobre o caso.

ORACULO DURO: G.semantic / G.fast_priv_scan / G.nested_blob (o mesmo de sempre).
DETECTOR DA FAMILIA (triagem, nunca prova): fracao dos bytes >= 0x80 que, sob C, caem em
ASCII minusculo (ou ASCII imprimivel), nas duas direcoes.

CONTROLE POSITIVO ESPECIFICO: o segmento alto do plaintext REAL da fase 3.2 tem que dar
lower=1.000 sob cp273 e 0.000 sob todo codec nao-EBCDIC. Se nao der, o detector nao vale nada.
CONTROLE POSITIVO DE KDF: fase 2 abre com sha256hex("causality") sob EVP-SHA256.
NULO CASADO: A1 -> 100 randomizacoes dos bytes altos preservando tamanho/posicoes;
             A3 -> 100 lotes de senhas aleatorias com a mesma forma, padding observado vs 1/256.

Uso: python familia4_codecs.py [--rapido]
"""
import sys, os, json, glob, time, random, hashlib, itertools, base64
from collections import Counter

ROOT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(ROOT, r"solver\experiments\claude_endgame_2026_09_02"))
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

OUT = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\familia4_codecs")
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, "familia4_codecs.jsonl"), "w", encoding="utf-8")
def log(**kw):
    LOG.write(json.dumps(kw, ensure_ascii=False) + "\n"); LOG.flush()
def say(*a):
    print(*a, flush=True)

RAPIDO = "--rapido" in sys.argv
RNG = random.Random(20260917)

CODECS = ("latin_1 iso8859_2 iso8859_3 iso8859_4 iso8859_5 iso8859_6 iso8859_7 iso8859_8 "
          "iso8859_9 iso8859_10 iso8859_11 iso8859_13 iso8859_14 iso8859_15 iso8859_16 "
          "cp1250 cp1251 cp1252 cp1253 cp1254 cp1255 cp1256 cp1257 cp1258 "
          "cp037 cp273 cp424 cp500 cp1026 cp1140 cp875 ebcdic_cp_us "
          "cp437 cp720 cp737 cp775 cp850 cp852 cp855 cp856 cp857 cp858 cp860 cp861 cp862 "
          "cp863 cp864 cp865 cp866 cp869 cp874 cp1006 "
          "koi8_r koi8_u koi8_t kz1048 ptcp154 mac_roman mac_cyrillic mac_greek mac_iceland "
          "mac_latin2 mac_turkish hp_roman8 tis_620").split()

# --------------------------------------------------------------- tabelas 256->256
def enc_table(c):
    """v (char latin-1) -> byte sob o codec c, ou -1 se nao codifica em 1 byte."""
    t = [-1] * 256
    for v in range(256):
        try:
            b = chr(v).encode(c)
        except Exception:
            continue
        if len(b) == 1:
            t[v] = b[0]
    return t
def dec_table(c):
    """byte v -> codepoint sob o codec c (latin-1 do char decodificado), ou -1."""
    t = [-1] * 256
    for v in range(256):
        try:
            ch = bytes([v]).decode(c)
        except Exception:
            continue
        o = ord(ch)
        t[v] = o if o < 256 else -1
    return t
ENC = {c: enc_table(c) for c in CODECS}
DEC = {c: dec_table(c) for c in CODECS}
LOWER = lambda b: 0x61 <= b <= 0x7A
PRINT = lambda b: 0x20 <= b <= 0x7E

def score_hist(hist_hi, n_hi, tab):
    """hist_hi: Counter dos bytes >= 0x80. Devolve (frac_lower, frac_print)."""
    if n_hi < 8:
        return 0.0, 0.0
    lo = pr = 0
    for v, n in hist_hi.items():
        b = tab[v]
        if b < 0:
            continue
        if LOWER(b): lo += n
        if PRINT(b): pr += n
    return lo / n_hi, pr / n_hi

def scan_bytes(p):
    """Melhor (lower, print, codec, direcao) sobre os bytes altos de p, nos 2 sentidos."""
    hi = Counter(x for x in p if x >= 0x80)
    n = sum(hi.values())
    best = (0.0, 0.0, None, None)
    for c in CODECS:
        for d, tabs in (("enc", ENC), ("dec", DEC)):
            lo, pr = score_hist(hi, n, tabs[c])
            if (lo, pr) > (best[0], best[1]):
                best = (lo, pr, c, d)
    return best, n

def traduz(p, c, d):
    t = (ENC if d == "enc" else DEC)[c]
    return bytes(t[x] & 0xFF for x in p if t[x] >= 0)

def duro_traduzido(out):
    """Oraculo duro sobre a saida TRADUZIDA.
    Duas tautologias evitadas de proposito (AGENTS.md §3):
      - printable>=0.85: o detector so dispara quando a saida JA e ASCII por construcao;
      - G.ebcdic_sig: aplicar a direcao 'dec' a um texto ASCII minusculo produz, por
        construcao, bytes na imagem EBCDIC de a-z — assinatura garantida, informacao zero.
    Sobra o que e realmente improvavel: blob aninhado, WIF/hex64, ingles/BIP39 em ASCII."""
    if G.nested_blob(out):
        return "nested_blob"
    txt = out.decode("latin-1")
    if G.wif_candidates(txt):
        return "wif"
    if G.hex64_candidates(txt) and any(not (48 <= x <= 57 or 97 <= x <= 102 or 65 <= x <= 70) for x in out):
        return "hex64"
    if not all(32 <= x <= 126 or x in (9, 10, 13) for x in out):
        return None            # escore de ingles so faz sentido sobre ASCII
    if len(out) >= 24 and G.english_score(txt) > -4.5:
        return "ingles"
    if len(G.word_hits(txt, 6)) >= 2:
        return "bip39x2"
    return None

def n_imagens(s):
    """Quantas imagens de bytes DISTINTAS os 65 codecs produzem para a string s.
    Se der 2 (ASCII + uma unica imagem EBCDIC), a 'familia de 23 cifras' nao tem
    grau de liberdade nenhum sobre texto ASCII: escolher o membro e vacuo."""
    im = set()
    for c in CODECS:
        try:
            im.add(s.encode(c))
        except Exception:
            pass
    return len(im), im

# --------------------------------------------------------------- A0 controle positivo
def a0_controle():
    raw = base64.b64decode(G.PHASE32_B64)
    k, iv = G.evp(b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c", raw[8:16], SHA256)
    p32 = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(raw[16:]))
    assert p32 and p32.startswith(b"I've been waiting for you."), "plaintext 3.2 nao reproduziu"
    hi = [i for i, x in enumerate(p32) if x >= 0x80]
    seg = p32[hi[0]:hi[-1] + 1]
    hc = Counter(x for x in seg if x >= 0x80); nh = sum(hc.values())
    tabela = {}
    for c in CODECS:
        tabela[c] = round(score_hist(hc, nh, ENC[c])[0], 4)
    assert tabela["cp273"] == 1.0, "cp273 nao deu 1.0 no campo 3 real"
    nao_ebcdic = [c for c in CODECS if c not in ("cp037", "cp273", "cp424", "cp500", "cp875", "cp1026", "cp1140", "ebcdic_cp_us")]
    assert all(tabela[c] == 0.0 for c in nao_ebcdic), "detector disparou fora do EBCDIC"
    reenc = bytes(ENC["cp273"][x] for x in seg)
    assert reenc[:12] == b"vtkvplmepphl", "re-encode cp273 nao reproduziu o campo 3"
    # controle de KDF
    p2 = G.aes_try(G.shahex("causality"), "PHASE2", "sha256") if "PHASE2" in G.BLOBS else None
    raw2 = base64.b64decode(G.PHASE2_B64)
    k2, iv2 = G.evp(G.shahex("causality").encode(), raw2[8:16], SHA256)
    p2 = G.unpad(AES.new(k2, AES.MODE_CBC, iv2).decrypt(raw2[16:]))
    assert p2 and G.printable(p2) > 0.9, "controle de KDF (fase 2 / causality) falhou"
    say(f"[A0] OK  cp273=1.000  demais EBCDIC={[tabela[c] for c in ('cp037','cp500','cp1140','ebcdic_cp_us','cp1026','cp424','cp875')]}  "
        f"nao-EBCDIC todos 0.000 ({len(nao_ebcdic)} codecs)")
    log(arm="A0", ok=True, tabela=tabela, reenc_head=reenc[:64].decode("latin-1"),
        kdf_control="fase2/causality/EVP-SHA256 OK")
    return seg

# --------------------------------------------------------------- A1 varredura retroativa
def carrega_plaintexts():
    """Varre TODO `plain_hex`/`hex` gravado em _work e separa em duas particoes:
      AES  = registro que carrega contexto de decifracao (`blob`/`kdf`) -> plaintext com padding
             valido, o alvo real da varredura retroativa;
      MAT  = qualquer outro blob hex (saidas de decoder, materiais, candidatos). Sobre MAT o
             detector dispara por CONSTRUCAO (ha campanhas que gravaram material EBCDIC de
             proposito), entao MAT e reportado separado e NUNCA entra no nulo.
    O proprio log desta campanha e excluido para nao realimentar."""
    aes, mat, arquivos, vistos = [], [], Counter(), set()
    def colhe(obj, src):
        if isinstance(obj, dict):
            hx = obj.get("plain_hex") or obj.get("hex")
            if isinstance(hx, str) and 32 <= len(hx) and len(hx) % 2 == 0 and hx not in vistos:
                try:
                    b = bytes.fromhex(hx)
                except ValueError:
                    b = None
                if b:
                    vistos.add(hx)
                    pw = obj.get("pw") or obj.get("password") or obj.get("senha") or ""
                    (aes if ("blob" in obj or "kdf" in obj) else mat).append((b, src, str(pw)[:120]))
                    arquivos[src] += 1
            for v in obj.values(): colhe(v, src)
        elif isinstance(obj, list):
            for v in obj: colhe(v, src)
    for pat in (r"_work\**\*.jsonl", r"_work\**\*.json"):
        for f in glob.glob(os.path.join(ROOT, pat), recursive=True):
            if os.path.normpath(f).startswith(os.path.normpath(OUT)):
                continue
            rel = os.path.relpath(f, ROOT)
            try:
                txt = open(f, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            if "plain_hex" not in txt and '"hex"' not in txt:
                continue
            if f.endswith(".jsonl"):
                for line in txt.splitlines():
                    line = line.strip()
                    if not line: continue
                    try: colhe(json.loads(line), rel)
                    except Exception: pass
            else:
                try: colhe(json.loads(txt), rel)
                except Exception: pass
    return aes, mat, arquivos

def varre(itens, rotulo):
    hits, dist = [], Counter()
    melhor = (0.0, 0.0, None, None, None)
    n_altos_ok = 0
    for b, src, pw in itens:
        (lo, pr, c, d), n = scan_bytes(b)
        if n >= 8: n_altos_ok += 1
        dist[round(lo, 1)] += 1
        if (lo, pr) > (melhor[0], melhor[1]):
            melhor = (lo, pr, c, d, (src, pw, b[:32].hex()))
        if lo >= 0.75 or pr >= 0.95:
            out = traduz(b, c, d)
            duro = duro_traduzido(out)
            rec = {"arm": rotulo, "codec": c, "dir": d, "lower": round(lo, 3), "print": round(pr, 3),
                   "src": src, "pw": pw, "hex": b.hex()[:512],
                   "trans_head": out[:80].decode("latin-1", "replace"), "oraculo_duro": duro}
            hits.append(rec); log(**rec)
    return hits, dist, melhor, n_altos_ok

def a1_retro():
    aes, mat, arquivos = carrega_plaintexts()
    say(f"[A1] corpus: {len(aes)} plaintexts AES com padding + {len(mat)} blobs hex de material, "
        f"em {len(arquivos)} arquivos")
    hA, dA, mA, nA = varre(aes, "A1_aes")
    hM, dM, mM, nM = varre(mat, "A1_material")
    dur_A = [h for h in hA if h["oraculo_duro"]]
    dur_M = [h for h in hM if h["oraculo_duro"]]
    say(f"[A1-AES] {len(aes)} plaintexts ({nA} com >=8 bytes altos): detector={len(hA)} duros={len(dur_A)} "
        f"max_lower={mA[0]:.3f} ({mA[2]}/{mA[3]})")
    say(f"[A1-MAT] {len(mat)} materiais ({nM} com >=8 bytes altos): detector={len(hM)} duros={len(dur_M)} "
        f"max_lower={mM[0]:.3f} ({mM[2]}/{mM[3]})")
    for h in dur_A + dur_M[:5]:
        say("   DURO:", h["oraculo_duro"], h["codec"], h["dir"], h["src"], "|", h["trans_head"][:60])
    # NULO casado (so na particao AES): bytes altos reamostrados uniforme em 0x80..0xFF,
    # preservando tamanho e as posicoes altas/baixas -> mesma forma, sem a estrutura.
    # Estatistica CONTINUA (media e maximo do melhor `lower` por plaintext): o limiar 0,75
    # nunca dispara nem no real nem no nulo, e "0 vs 0" nao e um nulo informativo.
    amostra = aes if len(aes) <= 500 else RNG.sample(aes, 500)
    obs_m = sum(scan_bytes(b)[0][0] for b, _, _ in amostra) / len(amostra)
    obs_x = max(scan_bytes(b)[0][0] for b, _, _ in amostra)
    nm, nx = [], []
    for _ in range(100):
        s, mx = 0.0, 0.0
        for b, _, _ in amostra:
            nb = bytes((RNG.randrange(0x80, 0x100) if x >= 0x80 else x) for x in b)
            lo = scan_bytes(nb)[0][0]
            s += lo; mx = max(mx, lo)
        nm.append(s / len(amostra)); nx.append(mx)
    mu = sum(nm) / len(nm)
    sd = (sum((x - mu) ** 2 for x in nm) / (len(nm) - 1)) ** 0.5
    z = (obs_m - mu) / sd if sd else 0.0
    mux = sum(nx) / len(nx)
    sdx = (sum((x - mux) ** 2 for x in nx) / (len(nx) - 1)) ** 0.5
    zx = (obs_x - mux) / sdx if sdx else 0.0
    say(f"[A1] nulo casado: {len(amostra)} plaintexts AES x 100 randomizacoes | "
        f"media(lower) obs={obs_m:.4f} nulo={mu:.4f}+-{sd:.4f} z={z:.2f} | "
        f"max(lower) obs={obs_x:.3f} nulo={mux:.3f}+-{sdx:.3f} z={zx:.2f}")
    log(arm="A1_resumo", n_aes=len(aes), n_material=len(mat), n_arquivos=len(arquivos),
        arquivos_top=dict(Counter(arquivos).most_common(25)),
        aes_hits=len(hA), aes_duros=len(dur_A), aes_max_lower=mA[0], aes_max_codec=mA[2], aes_max_dir=mA[3],
        mat_hits=len(hM), mat_duros=len(dur_M), mat_max_lower=mM[0], mat_max_codec=mM[2],
        hist_lower_aes={str(k): v for k, v in sorted(dA.items())},
        nulo_media_obs=obs_m, nulo_media_mu=mu, nulo_media_sd=sd, nulo_media_z=z,
        nulo_max_obs=obs_x, nulo_max_mu=mux, nulo_max_sd=sdx, nulo_max_z=zx,
        nulo_amostra=len(amostra))
    return (len(aes), len(mat)), hA + hM, (mu, sd, obs_m, z, zx)

# --------------------------------------------------------------- material da pagina final
RESID_L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
RESID_L83 = RESID_L84[:-1]
CAMPO3_32 = None  # preenchido por a0

def campos_pagina(seg32):
    c3 = bytes(ENC["cp273"][x] for x in seg32).decode("latin-1")
    campos = {
        "dbbi": G.DBBI, "faed": G.FAED,
        "matrixsumlist": G.TOKENS["matrixsumlist"], "enter": G.TOKENS["enter"],
        "lastwords": G.TOKENS["lastwordsbeforearchichoice"], "thispassword": G.TOKENS["thispassword"],
        "linha_antes": G.TOKENS["line_before_small"], "linha_depois": G.TOKENS["line_after_small"],
        "resid_L84": RESID_L84, "resid_L83": RESID_L83,
        "campo3_32": c3,
        "small_b64": G.SMALL_B64, "tail32_b64": G.TAIL32_B64,
    }
    bin_ = {"small_ct": G.BLOBS["SMALL"][1], "cosmic_ct": G.BLOBS["COSMIC"][1], "tail32_ct": G.BLOBS["TAIL32"][1],
            "small_salt": G.BLOBS["SMALL"][0], "cosmic_salt": G.BLOBS["COSMIC"][0], "tail32_salt": G.BLOBS["TAIL32"][0]}
    return campos, bin_

def a2_campos(seg32):
    campos, bin_ = campos_pagina(seg32)
    achados, n_transf, imagens = 0, 0, {}
    for nome, s in list(campos.items()) + [(k, v.decode("latin-1")) for k, v in bin_.items()]:
        b0 = s.encode("latin-1", "replace")
        imagens[nome] = n_imagens(s)[0]
        vistos = set()
        for c in CODECS:
            for d, tabs in (("enc", ENC), ("dec", DEC)):
                t = tabs[c]
                out = bytes(t[x] & 0xFF for x in b0 if t[x] >= 0)
                if len(out) < len(b0) * 0.9 or out == b0 or out in vistos:
                    continue
                vistos.add(out); n_transf += 1
                duro = duro_traduzido(out)
                if duro:
                    achados += 1
                    log(arm="A2", campo=nome, codec=c, dir=d, oraculo_duro=duro,
                        head=out[:120].decode("latin-1"), hex=out.hex()[:512])
                # a transformada tambem entra como SENHA (raw e sha256hex)
                for pw in (out, hashlib.sha256(out).hexdigest().encode()):
                    for blob in ("SMALL", "COSMIC", "TAIL32"):
                        for kraw, p in G.aes_try(pw, blob, "both"):
                            if G.semantic(p) or G.nested_blob(p) or (len(p) >= 32 and G.fast_priv_scan(p, "A2")):
                                achados += 1
                                log(arm="A2_senha", campo=nome, codec=c, dir=d, blob=blob,
                                    kdf=kraw.rsplit(".", 1)[-1], hex=p.hex())
                            else:
                                log(arm="A2_pad", campo=nome, codec=c, dir=d, blob=blob,
                                    kdf=kraw.rsplit(".", 1)[-1], hex=p.hex())
    say(f"[A2] {len(campos)+len(bin_)} campos x {len(CODECS)} codecs x 2 direcoes = {n_transf} "
        f"transformadas distintas (+ 2 senhas cada): {achados} hits de oraculo duro")
    say(f"[A2] imagens de bytes distintas por campo (65 codecs): {imagens}")
    log(arm="A2_resumo", n_campos=len(campos) + len(bin_), n_codecs=len(CODECS),
        n_transformadas_distintas=n_transf, n_hits=achados, imagens_distintas=imagens)
    return achados

# --------------------------------------------------------------- A3 senhas
ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit",
           "verylaststepisatruegiveawaypromised"]
CONHECIDOS = ["causality", "thispassword", "sha256", "enter", "theseedisplanted",
              "thematrixhasyou", "followthewhiterabbit", "salphaseion", "cosmicduality",
              "our first hint is your last command", "ans too", "shabef",
              "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
              "twentythreeciphers", "sixteenencryptions", "seven intertwined passwords",
              # "our first hint is your last command": o ultimo comando de cada fase foi
              # `openssl ... -pass pass:<digest>`. Os digests entram como token proprio.
              "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",   # fase 2
              "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",   # fase 3
              "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",   # fase 3.2
              "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"]   # URL do endgame

def formas_codec(c):
    """Nomes/formas de um codec como token de senha."""
    n = c.replace("_", "-")
    out = {c, n, c.upper(), n.upper()}
    if c.startswith("cp") and c[2:].isdigit():
        out |= {c[2:], "ibm" + c[2:], "IBM" + c[2:], "cp-" + c[2:], "codepage" + c[2:]}
    if c.startswith("iso8859_"):
        k = c.split("_")[1]
        out |= {"iso-8859-" + k, "ISO-8859-" + k, "iso8859-" + k, "latin" + k, "8859-" + k}
    if c == "latin_1":
        out |= {"latin1", "latin-1", "iso-8859-1", "ISO-8859-1", "8859-1"}
    return out

def corpus_senhas():
    """Devolve (nome_subfamilia, bytes_da_senha) deduplicado."""
    EB = ["cp037", "cp273", "cp424", "cp500", "cp875", "cp1026", "cp1140", "ebcdic_cp_us"]
    bases = []
    bases += [("token", t) for t in ROADMAP + CONHECIDOS]
    bases += [("campo", s) for s in (G.DBBI, G.FAED, RESID_L84, RESID_L83)]
    bases += [("road2", a + b) for a, b in itertools.permutations(ROADMAP, 2)]
    if not RAPIDO:
        bases += [("road7", "".join(p)) for p in itertools.permutations(ROADMAP)]
        bases += [("road3", "".join(p)) for p in itertools.permutations(ROADMAP, 3)]
    nomes = sorted({f for c in CODECS for f in formas_codec(c)})
    bases += [("nome", f) for f in nomes]
    bases += [("nome+road", f + t) for f in nomes for t in ROADMAP]
    bases += [("road+nome", t + f) for f in nomes for t in ROADMAP]
    bases += [("nome+conh", f + t) for f in nomes for t in CONHECIDOS[:8]]

    vistos, saida = set(), []
    def add(sub, pw):
        if pw in vistos: return
        vistos.add(pw); saida.append((sub, pw))
    for sub, s in bases:
        sb = s.encode("latin-1", "replace")
        # 1) o texto codificado em cada pagina EBCDIC (as demais 57 sao identidade em ASCII)
        for c in EB:
            try:
                eb = s.encode(c)
            except Exception:
                continue
            add(sub + "/eb_raw/" + c, eb)                      # bytes EBCDIC como senha crua
            add(sub + "/eb_sha/" + c, hashlib.sha256(eb).hexdigest().encode())  # padrao do puzzle
            add(sub + "/eb_shaR/" + c, hashlib.sha256(eb).digest())             # digest cru
            # ordem inversa: hash primeiro em ASCII, depois recodifica o hex em C
            hx = hashlib.sha256(sb).hexdigest()
            try:
                hxe = hx.encode(c)
            except Exception:
                continue
            add(sub + "/sha_eb/" + c, hxe)
            add(sub + "/sha_eb_sha/" + c, hashlib.sha256(hxe).hexdigest().encode())
        # 2) a forma ASCII (so nova para os nomes de codec)
        add(sub + "/ascii_raw", sb)
        add(sub + "/ascii_sha", hashlib.sha256(sb).hexdigest().encode())
    return saida

def a3_senhas():
    # fato estrutural da familia, medido antes de gastar AES
    for probe in ("yellowblueprimes", "Yellow Blue Primes 23!", G.DBBI):
        n, _ = n_imagens(probe)
        say(f"[A3] imagens de bytes distintas entre os 65 codecs para {probe[:28]!r}: {n}")
        log(arm="A3_imagens", probe=probe[:40], n_imagens=n)
    senhas = corpus_senhas()
    say(f"[A3] {len(senhas)} senhas distintas x 3 blobs x 2 KDF = {len(senhas)*6} decifracoes")
    t0 = time.time()
    pad_por_sub, tot_por_sub, duros = Counter(), Counter(), []
    for sub, pw in senhas:
        fam = sub.split("/", 1)[1] if "/" in sub else sub
        for blob in ("SMALL", "COSMIC", "TAIL32"):
            # aes_try devolve hm.__name__ = "Crypto.Hash.MD5"/"Crypto.Hash.SHA256": normalizar,
            # senao pad_por_sub e tot_por_sub usam chaves diferentes e todo z sai -sqrt(n/256).
            for kraw, p in G.aes_try(pw, blob, "both"):
                k = kraw.rsplit(".", 1)[-1]
                tag = f"{fam}|{blob}|{k}"
                pad_por_sub[tag] += 1
                if G.semantic(p) or G.nested_blob(p) or (len(p) >= 32 and G.fast_priv_scan(p, tag)):
                    rec = {"arm": "A3", "sub": sub, "blob": blob, "kdf": k,
                           "pw": pw[:120].decode("latin-1", "replace"), "hex": p.hex()}
                    duros.append(rec); log(**rec)
                else:
                    log(arm="A3_pad", sub=sub, blob=blob, kdf=k, len=len(p),
                        printable=round(G.printable(p), 3), hex=p.hex())
            for k in ("MD5", "SHA256"):
                tot_por_sub[f"{fam}|{blob}|{k}"] += 1
    dt = time.time() - t0
    say(f"[A3] {len(senhas)*6} decifracoes em {dt:.1f}s; oraculo duro: {len(duros)} hits; "
        f"padding total {sum(pad_por_sub.values())}/{sum(tot_por_sub.values())} "
        f"({sum(pad_por_sub.values())/max(1,sum(tot_por_sub.values())):.5f} vs 1/256=0.00391)")

    # NULO CASADO: 100 lotes de senhas aleatorias com a MESMA FORMA (comprimento/alfabeto)
    formas = Counter()
    for sub, pw in senhas:
        f = "hex64" if (len(pw) == 64 and all(c in b"0123456789abcdef" for c in pw)) else f"raw{min(len(pw),64)//8*8}"
        formas[f] += 1
    n_lote = min(3000, len(senhas))
    lotes = []
    for r in range(100):
        pad = 0
        for i in range(n_lote):
            f = RNG.choices(list(formas), weights=list(formas.values()))[0]
            if f == "hex64":
                pw = bytes(RNG.choice(b"0123456789abcdef") for _ in range(64))
            else:
                ln = max(4, int(f[3:]) or 8)
                pw = bytes(RNG.randrange(256) for _ in range(ln))
            for blob in ("SMALL", "COSMIC", "TAIL32"):
                pad += len(G.aes_try(pw, blob, "both"))
        lotes.append(pad)
    mu = sum(lotes) / len(lotes)
    sd = (sum((x - mu) ** 2 for x in lotes) / (len(lotes) - 1)) ** 0.5
    esperado = n_lote * 6 / 256.0
    say(f"[A3] nulo: 100 lotes de {n_lote} senhas -> mu={mu:.2f} sd={sd:.2f} (esperado 1/256 = {esperado:.2f})")
    zs = {}
    for tag, tot in tot_por_sub.items():
        obs = pad_por_sub[tag]; exp = tot / 256.0
        zs[tag] = round((obs - exp) / max(1e-9, (tot * (1 / 256) * (255 / 256)) ** 0.5), 2)
    piores = sorted(zs.items(), key=lambda kv: -abs(kv[1]))[:10]
    say("[A3] z de padding por sub-familia (10 maiores |z|):", piores)
    log(arm="A3_resumo", n_senhas=len(senhas), n_decifracoes=len(senhas) * 6, segundos=round(dt, 1),
        n_duros=len(duros), padding_obs=sum(pad_por_sub.values()), padding_tot=sum(tot_por_sub.values()),
        nulo_mu=mu, nulo_sd=sd, nulo_esperado=esperado, nulo_lote=n_lote,
        z_por_subfamilia=zs)
    return len(senhas), duros, zs

# --------------------------------------------------------------- A4 plaintexts das fases
def a4_fases():
    """"Um segundo segmento escondido como o EBCDIC da 3.2" nos plaintexts autenticos das
    fases 2, 3 e 3.2. Um segmento de codec SO PODE existir onde ha bytes >= 0x80."""
    fases = {"fase2": (G.PHASE2_B64, "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf"),
             "fase3": (G.PHASE3_B64, "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"),
             "fase32": (G.PHASE32_B64, "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c")}
    res = {}
    for nome, (b64, pw) in fases.items():
        raw = base64.b64decode(b64)
        k, iv = G.evp(pw.encode(), raw[8:16], SHA256)
        p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(raw[16:]))
        hi = Counter(x for x in p if x >= 0x80); n = sum(hi.values())
        top = sorted(((round(score_hist(hi, n, ENC[c])[0], 3), c) for c in CODECS), reverse=True)[:3]
        res[nome] = {"len": len(p), "printable": round(G.printable(p), 3), "n_altos": n,
                     "top3_lower": top if n >= 8 else "sem bytes altos: segmento de codec impossivel"}
    say("[A4] plaintexts autenticos das fases:", json.dumps(res, ensure_ascii=False))
    log(arm="A4_fases", **res)
    return res

# --------------------------------------------------------------- main
if __name__ == "__main__":
    t0 = time.time()
    seg32 = a0_controle()
    a4_fases()
    (n_aes, n_mat), hits1, nulo1 = a1_retro()
    n_a2 = a2_campos(seg32)
    n_pw, duros3, zs3 = a3_senhas()
    resumo = {"arm": "FIM", "segundos": round(time.time() - t0, 1), "n_codecs": len(CODECS),
              "A1_plaintexts_aes": n_aes, "A1_material": n_mat,
              "A1_hits_detector": len(hits1), "A1_hits_duros": sum(1 for h in hits1 if h["oraculo_duro"]),
              "A1_nulo": {"nulo_mu": nulo1[0], "nulo_sd": nulo1[1], "obs_media": nulo1[2], "z_media": nulo1[3], "z_max": nulo1[4]},
              "A2_triagem": n_a2, "A3_senhas": n_pw, "A3_duros": len(duros3),
              "A3_maior_abs_z": max((abs(v) for v in zs3.values()), default=0.0)}
    log(**resumo)
    say("RESUMO:", json.dumps(resumo, ensure_ascii=False))
    LOG.close()
