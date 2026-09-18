# -*- coding: utf-8 -*-
r"""
CRITICO ADVERSARIAL da familia 4 ("over twenty-three ciphers" = familia de codecs).

HIPOTESE DESTE SCRIPT (prosa, finita, falsificavel)
---------------------------------------------------
O agente da familia 4 afirma (a) ter varrido 65 codecs de byte unico da stdlib, (b) que
esses 65 colapsam em exatamente DUAS imagens de bytes sobre material alfanumerico
minusculo — o que tornaria a "escolha de um membro entre 23 cifras" vacua —, (c) ter
varrido 53.573 plaintexts AES com padding valido de 95 arquivos, (d) ter testado 105.519
senhas distintas com 0 hits de oraculo duro, e (e) que o unico gap relevante que sobrou
sao os codecs MULTI-BYTE e os codecs aplicados a FATIAS.

Este script tenta REFUTAR cada uma dessas cinco afirmacoes. Elas sao falsas se:
  (R1) a stdlib do Python tiver codecs de byte unico ALEM dos 65 dele, ou se a lista dele
       contiver alias duplicado (inflando a cobertura declarada);
  (R2) o colapso 65 -> 2 nao valer nas DUAS direcoes (enc e dec) ou nao valer sobre algum
       campo da pagina — ele mediu `n_imagens` so na direcao ENCODE;
  (R3) existirem, em _work, arquivos/chaves com plaintext em hex que o coletor dele NAO
       pega (ele so le `plain_hex`/`hex` em *.json e *.jsonl) — a varredura anterior
       (f5_retro_ebcdic) declara 1.305 arquivos contra os 95 dele;
  (R4) o corpus de senhas nao reproduzir 105.519 distintas, ou a taxa de padding do log
       dele nao bater com 1/256 dentro do ruido calibrado, ou algum |z| por sub-familia
       passar de |2,9| alem do esperado por multiplicidade;
  (R5) algum plaintext com padding valido dos logs (o dele e o corpus inteiro de _work)
       passar no oraculo duro COMPLETO — G.semantic, G.nested_blob, G.ebcdic_sig e
       privkey em TODA janela de 32 bytes, nas DUAS ordens de byte —, ou se o braco
       multi-byte que ele declarou ter deixado de fora produzir imagem de bytes nova que
       abra qualquer blob.

Alem disso mede o LOOK-ELSEWHERE do unico numero "significativo" que ele reportou
(z = +3,14 no maximo de `lower` do nulo A1): quantas tentativas equivalentes havia.

ORACULO DURO: privkey de 32 B == pubkey do premio (coincurve), ou plaintext semantico
(>=85% ASCII / WIF / hex64 / blob aninhado / assinatura EBCDIC cp273 >= 0,75).
Padding PKCS7 valido sozinho e ruido (1/256) e NAO conta.

CONTROLE POSITIVO: fase 2 abre com sha256hex("causality") sob EVP-SHA256; o segmento alto
do plaintext real da fase 3.2 da ebcdic_sig 1,000 e re-encoda em "vtkvplmepphl..." sob cp273;
plantio de privkey conhecida num buffer para provar que o scanner de 32 B acha nas 2 ordens.
NULO CASADO: 100 lotes de senhas aleatorias de mesma forma (R4) + 100 randomizacoes dos
bytes altos preservando forma (R2/look-elsewhere).

Uso: python critico_familia4_codecs.py [--rapido]
"""
import sys, os, json, glob, time, random, hashlib, itertools, base64, codecs as _codecs
import pkgutil, encodings
from collections import Counter

ROOT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(ROOT, r"solver\experiments\claude_endgame_2026_09_02"))
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from coincurve import PublicKey

OUT = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\critico_familia4_codecs")
os.makedirs(OUT, exist_ok=True)
LOGPATH = os.path.join(OUT, "critico_familia4_codecs.jsonl")
LOG = None
def log(**kw):
    # ATENCAO: no Windows o mp.Pool usa spawn e RE-IMPORTA este modulo em cada filho.
    # Abrir o log em "w" no nivel do modulo truncava o arquivo uma vez por worker
    # (foi o que aconteceu na primeira execucao). Abertura preguicosa, modo append;
    # a truncagem acontece so no bloco __main__.
    global LOG
    if LOG is None:
        LOG = open(LOGPATH, "a", encoding="utf-8")
    LOG.write(json.dumps(kw, ensure_ascii=False) + "\n"); LOG.flush()
def say(*a):
    print(*a, flush=True)

RAPIDO = "--rapido" in sys.argv
RNG = random.Random(20260918)
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)

# lista EXATA do agente auditado (65 nomes)
CODECS_AGENTE = ("latin_1 iso8859_2 iso8859_3 iso8859_4 iso8859_5 iso8859_6 iso8859_7 iso8859_8 "
    "iso8859_9 iso8859_10 iso8859_11 iso8859_13 iso8859_14 iso8859_15 iso8859_16 "
    "cp1250 cp1251 cp1252 cp1253 cp1254 cp1255 cp1256 cp1257 cp1258 "
    "cp037 cp273 cp424 cp500 cp1026 cp1140 cp875 ebcdic_cp_us "
    "cp437 cp720 cp737 cp775 cp850 cp852 cp855 cp856 cp857 cp858 cp860 cp861 cp862 "
    "cp863 cp864 cp865 cp866 cp869 cp874 cp1006 "
    "koi8_r koi8_u koi8_t kz1048 ptcp154 mac_roman mac_cyrillic mac_greek mac_iceland "
    "mac_latin2 mac_turkish hp_roman8 tis_620").split()

META = {"charmap", "raw_unicode_escape", "unicode_escape", "undefined", "punycode",
        "idna", "quopri_codec", "base64_codec", "hex_codec", "uu_codec", "zlib_codec",
        "bz2_codec", "rot_13", "tactis", "string_escape", "mbcs", "oem", "palmos"}

def censo_codecs():
    """Todos os codecs de byte unico REAIS da stdlib, deduplicados por nome canonico."""
    nomes = {n for _, n, _ in pkgutil.iter_modules(encodings.__path__)}
    sb, canon = [], {}
    for n in sorted(nomes):
        if n.startswith("_") or n in META:
            continue
        try:
            ci = _codecs.lookup(n)
        except Exception:
            continue
        ok, cnt = True, 0
        for v in range(256):
            try:
                ch = bytes([v]).decode(n)
            except Exception:
                continue
            cnt += 1
            if len(ch) != 1:
                ok = False; break
        if ok and cnt >= 200:
            sb.append(n); canon.setdefault(ci.name, n)
    return sb, canon

SB_ALL, CANON = censo_codecs()

def enc_table(c):
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
    t = [-1] * 256
    for v in range(256):
        try:
            o = ord(bytes([v]).decode(c))
        except Exception:
            continue
        t[v] = o if o < 256 else -1
    return t

CODECS = sorted(set(SB_ALL) | set(CODECS_AGENTE))   # superconjunto: stdlib + a lista do agente
ENC = {c: enc_table(c) for c in CODECS}
DEC = {c: dec_table(c) for c in CODECS}
EBCDIC = [c for c in CODECS if ENC[c][ord("a")] == 0x81]   # deteccao estrutural, nao lista fixa
LOWER = lambda b: 0x61 <= b <= 0x7A

# --------------------------------------------------------------- oraculo duro completo
def priv_windows(buf):
    """privkey em TODA janela de 32 B, nas DUAS ordens de byte. Devolve lista de hits."""
    hits = []
    for src, tag in ((buf, "fwd"), (buf[::-1], "rev")):
        for j in range(0, len(src) - 31):
            sec = src[j:j + 32]
            try:
                if PublicKey.from_valid_secret(sec).format(False) == TGT:
                    hits.append((tag, j, sec.hex()))
            except Exception:
                pass
    return hits

def oraculo_duro(p, com_priv=True):
    """Devolve rotulo do hit duro ou None. Padding valido NAO e hit."""
    r = []
    if G.nested_blob(p): r.append("nested_blob")
    if G.printable(p) >= 0.85: r.append("ascii85")
    if G.ebcdic_sig(p) >= 0.75: r.append("ebcdic")
    t = p.decode("latin-1")
    if G.wif_candidates(t): r.append("wif")
    if G.hex64_candidates(t): r.append("hex64")
    if com_priv and len(p) >= 32 and priv_windows(p): r.append("PRIVKEY")
    return "+".join(r) if r else None

# --------------------------------------------------------------- C0 controles
def c0():
    raw = base64.b64decode(G.PHASE32_B64)
    k, iv = G.evp(b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c", raw[8:16], SHA256)
    p32 = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(raw[16:]))
    assert p32 and p32.startswith(b"I've been waiting for you."), "fase 3.2 nao reproduziu"
    hi = [i for i, x in enumerate(p32) if x >= 0x80]
    seg = p32[hi[0]:hi[-1] + 1]
    assert G.ebcdic_sig(seg) >= 0.99, "ebcdic_sig do segmento real da 3.2 nao deu 1.0"
    reenc = bytes(ENC["cp273"][x] for x in seg)
    assert reenc[:12] == b"vtkvplmepphl", "re-encode cp273 nao reproduziu o campo 3"
    raw2 = base64.b64decode(G.PHASE2_B64)
    k2, iv2 = G.evp(G.shahex("causality").encode(), raw2[8:16], SHA256)
    p2 = G.unpad(AES.new(k2, AES.MODE_CBC, iv2).decrypt(raw2[16:]))
    assert p2 and G.printable(p2) > 0.9, "controle de KDF (fase 2 / causality) falhou"
    # controle do scanner de privkey nas 2 ordens: planta uma chave conhecida
    seed = hashlib.sha256(b"controle-plantado-critico").digest()
    pub = PublicKey.from_valid_secret(seed).format(False)
    global TGT
    salvo = TGT
    TGT = pub
    buf = bytes(7) + seed + bytes(9)
    assert any(t == "fwd" for t, _, _ in priv_windows(buf)), "scanner fwd falhou"
    assert any(t == "rev" for t, _, _ in priv_windows(bytes(5) + seed[::-1] + bytes(3))), "scanner rev falhou"
    TGT = salvo
    say("[C0] OK: fase 3.2 (ebcdic 1.000 + re-encode cp273), fase 2 (causality/EVP-SHA256), "
        "scanner de privkey 32B nas 2 ordens com chave plantada")
    log(arm="C0", ok=True, reenc_head=reenc[:32].decode("latin-1"),
        fase2_printable=round(G.printable(p2), 3), seg32_len=len(seg))
    return seg

# --------------------------------------------------------------- C1 censo de codecs
def c1():
    ag = CODECS_AGENTE
    canon_ag = {}
    for c in ag:
        canon_ag.setdefault(_codecs.lookup(c).name, []).append(c)
    dup = {k: v for k, v in canon_ag.items() if len(v) > 1}
    faltando = sorted(set(CANON.values()) - {_codecs.lookup(c).name for c in ag}
                      if False else
                      {n for n in SB_ALL if _codecs.lookup(n).name not in canon_ag})
    faltando_canon = sorted({_codecs.lookup(n).name for n in faltando})
    eb_ag = sorted({_codecs.lookup(c).name for c in ag if ENC[c][ord("a")] == 0x81} if True else [])
    say(f"[C1] agente declarou {len(ag)} codecs = {len(canon_ag)} canonicos distintos; "
        f"aliases duplicados: {dup}")
    say(f"[C1] stdlib tem {len(SB_ALL)} nomes de byte unico = {len(CANON)} canonicos; "
        f"faltando no agente ({len(faltando_canon)}): {faltando_canon}")
    say(f"[C1] paginas EBCDIC canonicas na lista do agente: {eb_ag} | no repo todo: "
        f"{sorted({_codecs.lookup(c).name for c in EBCDIC})}")
    log(arm="C1", agente_nomes=len(ag), agente_canonicos=len(canon_ag), aliases_dup=dup,
        stdlib_nomes=len(SB_ALL), stdlib_canonicos=len(CANON), faltando=faltando_canon,
        ebcdic_agente=eb_ag, ebcdic_total=sorted({_codecs.lookup(c).name for c in EBCDIC}))
    return faltando_canon, dup

# --------------------------------------------------------------- C2 colapso nas 2 direcoes
RESID_L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
RESID_L83 = RESID_L84[:-1]

def campos_pagina(seg32):
    c3 = bytes(ENC["cp273"][x] for x in seg32).decode("latin-1")
    txt = {"dbbi": G.DBBI, "faed": G.FAED,
           "matrixsumlist": G.TOKENS["matrixsumlist"], "enter": G.TOKENS["enter"],
           "lastwords": G.TOKENS["lastwordsbeforearchichoice"],
           "thispassword": G.TOKENS["thispassword"],
           "linha_antes": G.TOKENS["line_before_small"], "linha_depois": G.TOKENS["line_after_small"],
           "resid_L84": RESID_L84, "resid_L83": RESID_L83, "campo3_32": c3,
           "small_b64": G.SMALL_B64, "tail32_b64": G.TAIL32_B64}
    bina = {"small_ct": G.BLOBS["SMALL"][1], "cosmic_ct": G.BLOBS["COSMIC"][1],
            "tail32_ct": G.BLOBS["TAIL32"][1], "small_salt": G.BLOBS["SMALL"][0],
            "cosmic_salt": G.BLOBS["COSMIC"][0], "tail32_salt": G.BLOBS["TAIL32"][0]}
    return txt, bina

def imagens(b0, use=CODECS):
    """Conjunto de imagens de bytes DISTINTAS nas DUAS direcoes (inclui a identidade)."""
    im = set()
    for c in use:
        for tab in (ENC[c], DEC[c]):
            out = bytes(tab[x] & 0xFF for x in b0 if tab[x] >= 0)
            if len(out) == len(b0):
                im.add(out)
    return im

def c2(seg32):
    txt, bina = campos_pagina(seg32)
    todos = {k: v.encode("latin-1", "replace") for k, v in txt.items()}
    todos.update(bina)
    todos["alfabeto_az"] = bytes(range(0x61, 0x7B))
    todos["alfabeto_az09"] = bytes(range(0x61, 0x7B)) + b"0123456789"
    tab = {}
    for nome, b0 in todos.items():
        i65 = imagens(b0, CODECS_AGENTE)
        iall = imagens(b0, CODECS)
        tab[nome] = {"n_2dir_65": len(i65), "n_2dir_stdlib": len(iall),
                     "novas_fora_dos_65": len(iall - i65)}
    # prova de VACUIDADE DAS FATIAS: codec de byte unico e mapa por caractere,
    # logo imagem(fatia) == fatia(imagem) e o numero de imagens de qualquer fatia
    # e <= o numero de imagens da string inteira. Testado por amostragem.
    ok_fatia = True
    base = G.FAED.encode()
    for _ in range(200):
        i = RNG.randrange(0, len(base) - 4); j = RNG.randrange(i + 4, len(base) + 1)
        if not imagens(base[i:j]) <= {im[i:j] for im in imagens(base)}:
            ok_fatia = False; break
    say(f"[C2] imagens de bytes DISTINTAS nas 2 direcoes (o agente contou so ENCODE):")
    for k, v in tab.items():
        say(f"      {k:16s} 65-codecs={v['n_2dir_65']:2d}  stdlib={v['n_2dir_stdlib']:2d}  "
            f"novas fora dos 65={v['novas_fora_dos_65']}")
    say(f"[C2] fatias sao vacuas (imagem(fatia)=fatia(imagem)) em 200 fatias aleatorias: {ok_fatia}")
    log(arm="C2", tabela=tab, fatias_vacuas=ok_fatia)
    return tab, ok_fatia

# --------------------------------------------------------------- C3 recontagem do corpus A3
ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit",
           "verylaststepisatruegiveawaypromised"]
CONHECIDOS = ["causality", "thispassword", "sha256", "enter", "theseedisplanted",
              "thematrixhasyou", "followthewhiterabbit", "salphaseion", "cosmicduality",
              "our first hint is your last command", "ans too", "shabef",
              "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
              "twentythreeciphers", "sixteenencryptions", "seven intertwined passwords",
              "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",
              "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
              "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
              "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"]

def formas_codec(c):
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

def corpus_senhas_agente():
    """Reimplementacao da geradora do agente, so para RECONTAR o que ele alegou."""
    EB = ["cp037", "cp273", "cp424", "cp500", "cp875", "cp1026", "cp1140", "ebcdic_cp_us"]
    bases = []
    bases += [("token", t) for t in ROADMAP + CONHECIDOS]
    bases += [("campo", s) for s in (G.DBBI, G.FAED, RESID_L84, RESID_L83)]
    bases += [("road2", a + b) for a, b in itertools.permutations(ROADMAP, 2)]
    bases += [("road7", "".join(p)) for p in itertools.permutations(ROADMAP)]
    bases += [("road3", "".join(p)) for p in itertools.permutations(ROADMAP, 3)]
    nomes = sorted({f for c in CODECS_AGENTE for f in formas_codec(c)})
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
        for c in EB:
            try: eb = s.encode(c)
            except Exception: continue
            add(sub + "/eb_raw/" + c, eb)
            add(sub + "/eb_sha/" + c, hashlib.sha256(eb).hexdigest().encode())
            add(sub + "/eb_shaR/" + c, hashlib.sha256(eb).digest())
            hx = hashlib.sha256(sb).hexdigest()
            try: hxe = hx.encode(c)
            except Exception: continue
            add(sub + "/sha_eb/" + c, hxe)
            add(sub + "/sha_eb_sha/" + c, hashlib.sha256(hxe).hexdigest().encode())
        add(sub + "/ascii_raw", sb)
        add(sub + "/ascii_sha", hashlib.sha256(sb).hexdigest().encode())
    return saida, len(bases), len(nomes)

def c3():
    senhas, n_bases, n_nomes = corpus_senhas_agente()
    # padding observado no LOG DELE (fonte primaria, nao reexecucao)
    p = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\familia4_codecs\familia4_codecs.jsonl")
    pad_sub, resumo = Counter(), None
    n_pad_log = 0
    for line in open(p, encoding="utf-8"):
        d = json.loads(line)
        if d.get("arm") == "A3_pad":
            n_pad_log += 1
            pad_sub[f"{d['sub'].split('/',1)[1]}|{d['blob']}|{d['kdf']}"] += 1
        elif d.get("arm") == "A3_resumo":
            resumo = d
    n_dec = len(senhas) * 6
    say(f"[C3] recontagem do corpus de senhas: {n_bases} bases, {n_nomes} formas de nome de codec, "
        f"{len(senhas)} senhas DISTINTAS (agente alegou {resumo['n_senhas']}) -> {n_dec} decifracoes")
    say(f"[C3] padding no log dele: {n_pad_log} registros A3_pad (resumo diz {resumo['padding_obs']}); "
        f"taxa {n_pad_log/n_dec:.5f} vs 1/256 = {1/256:.5f}")
    # z global de padding
    exp = n_dec / 256.0
    zg = (n_pad_log - exp) / (n_dec * (1 / 256) * (255 / 256)) ** 0.5
    zmax = max((abs(v) for v in resumo["z_por_subfamilia"].values()), default=0)
    n_sub = len(resumo["z_por_subfamilia"])
    say(f"[C3] z global de padding = {zg:+.2f}; maior |z| por sub-familia = {zmax:.2f} em {n_sub} "
        f"sub-familias (esperado |z|>2 por acaso: {n_sub*0.0455:.1f})")
    bate = (len(senhas) == resumo["n_senhas"]) and (n_pad_log == resumo["padding_obs"])
    log(arm="C3", senhas_recontadas=len(senhas), senhas_alegadas=resumo["n_senhas"],
        bases=n_bases, formas_nome=n_nomes, decifracoes=n_dec, pad_log=n_pad_log,
        pad_alegado=resumo["padding_obs"], taxa=n_pad_log / n_dec, z_global=zg,
        z_max_subfamilia=zmax, n_subfamilias=n_sub, bate=bate)
    return senhas, bate, zg

# --------------------------------------------------------------- C4 auditoria do corpus A1
HEXKEYS = ("plain_hex", "hex", "pt_hex", "plaintext_hex", "p_hex", "plain", "plaintext",
           "out_hex", "material_hex", "bytes_hex", "dec_hex", "hexa")

def coleta_ampla(limite_arquivos=None):
    """Coletor MAIS LARGO que o do agente: todas as extensoes de texto em _work,
    qualquer chave cujo nome termine em 'hex' (ou esteja em HEXKEYS), + strings hex
    soltas em listas. Serve para medir se os 95 arquivos dele sao o universo."""
    aes, mat, arquivos, vistos = [], [], Counter(), set()
    def colhe(obj, src):
        if isinstance(obj, dict):
            ctx = ("blob" in obj) or ("kdf" in obj)
            for k, v in obj.items():
                if isinstance(v, str) and (k in HEXKEYS or k.endswith("hex")):
                    h = v.strip()
                    if 32 <= len(h) and len(h) % 2 == 0 and h not in vistos:
                        try: b = bytes.fromhex(h)
                        except ValueError: continue
                        vistos.add(h)
                        (aes if ctx else mat).append((b, src))
                        arquivos[src] += 1
            for v in obj.values(): colhe(v, src)
        elif isinstance(obj, list):
            for v in obj: colhe(v, src)
    pats = (r"_work\**\*.jsonl", r"_work\**\*.json", r"_work\**\*.txt",
            r"_work\**\*.out", r"_work\**\*.log", r"_work\**\*.hex", r"_work\**\*.ndjson")
    arq = []
    for pat in pats:
        arq += glob.glob(os.path.join(ROOT, pat), recursive=True)
    arq = sorted(set(arq))
    if limite_arquivos: arq = arq[:limite_arquivos]
    n_tocados = 0
    for f in arq:
        if os.path.normpath(f).startswith(os.path.normpath(OUT)):
            continue
        rel = os.path.relpath(f, ROOT)
        try:
            txt = open(f, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        n_tocados += 1
        if "hex" not in txt:
            continue
        if f.endswith((".jsonl", ".ndjson")):
            for line in txt.splitlines():
                line = line.strip()
                if not line: continue
                try: colhe(json.loads(line), rel)
                except Exception: pass
        else:
            try: colhe(json.loads(txt), rel)
            except Exception: pass
    return aes, mat, arquivos, len(arq), n_tocados

def c4():
    t0 = time.time()
    aes, mat, arquivos, n_arq, n_tocados = coleta_ampla()
    say(f"[C4] coletor amplo: {len(arquivos)} arquivos com blob hex (de {n_arq} candidatos, "
        f"{n_tocados} lidos) -> {len(aes)} AES + {len(mat)} material = {len(aes)+len(mat)} blobs "
        f"distintos em {time.time()-t0:.0f}s")
    say(f"[C4] agente declarou 95 arquivos / 53.573 AES / 684.413 material "
        f"(varredura anterior f5_retro_ebcdic: 1.305 arquivos / 563.133 plaintexts)")
    log(arm="C4", arquivos_com_hex=len(arquivos), arquivos_candidatos=n_arq,
        arquivos_lidos=n_tocados, n_aes=len(aes), n_material=len(mat),
        agente_arquivos=95, agente_aes=53573, agente_material=684413,
        top=dict(Counter(arquivos).most_common(15)))
    return aes, mat, arquivos

# --------------------------------------------------------------- C5 re-varredura com oraculo completo
def _priv_worker(args):
    """Roda em processo separado: devolve (idx, hits) da varredura de privkey nas 2 ordens."""
    from coincurve import PublicKey
    tgt = bytes.fromhex("04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
                        "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
    out = []
    for idx, b in args:
        for src, tag in ((b, "fwd"), (b[::-1], "rev")):
            for j in range(0, len(src) - 31):
                sec = src[j:j + 32]
                try:
                    if PublicKey.from_valid_secret(sec).format(False) == tgt:
                        out.append((idx, tag, j, sec.hex()))
                except Exception:
                    pass
    return out

def oraculo_barato(p):
    """Tudo do oraculo duro menos a privkey (que vai em paralelo)."""
    r = []
    if G.nested_blob(p): r.append("nested_blob")
    if G.printable(p) >= 0.85: r.append("ascii85")
    if G.ebcdic_sig(p) >= 0.75: r.append("ebcdic")
    t = p.decode("latin-1")
    if G.wif_candidates(t): r.append("wif")
    if G.hex64_candidates(t): r.append("hex64")
    return "+".join(r) if r else None

def c5(aes, mat, workers=None):
    """Oraculo duro COMPLETO sobre TODO blob com padding valido/material disponivel:
    G.semantic (printable/wif/hex64), G.nested_blob, G.ebcdic_sig e privkey de 32 B em
    TODA janela, nas DUAS ordens de byte (o G.fast_priv_scan do kit so faz a ordem direta).
    A privkey vai para um Pool porque sao ~1,2 x 10^8 janelas."""
    import multiprocessing as mp
    pl = os.path.join(ROOT, "_work", "operador_ensinado_2026-09-17",
                      "familia4_codecs", "familia4_codecs.jsonl")
    itens, vistos = [], set()
    n_log = 0
    for line in open(pl, encoding="utf-8"):
        d = json.loads(line)
        h = d.get("hex")
        if isinstance(h, str) and len(h) >= 32 and len(h) % 2 == 0:
            try: b = bytes.fromhex(h)
            except ValueError: continue
            n_log += 1
            if b not in vistos:
                vistos.add(b); itens.append((b, "log_familia4/" + str(d.get("arm"))))
    n_so_log = len(itens)
    for b, src in aes:
        if b not in vistos: vistos.add(b); itens.append((b, "AES/" + src))
    n_apos_aes = len(itens)
    for b, src in mat:
        if b not in vistos: vistos.add(b); itens.append((b, "MAT/" + src))
    janelas = sum(max(0, len(b) - 31) * 2 for b, _ in itens)
    say(f"[C5] corpus unificado: {len(itens)} blobs distintos "
        f"({n_so_log} do log do agente, +{n_apos_aes-n_so_log} AES, +{len(itens)-n_apos_aes} material); "
        f"{janelas} janelas de 32 B x 2 ordens a verificar")
    # 1) oraculo barato, integral
    t0 = time.time()
    # Tautologias conhecidas (AGENTS.md §3 e o proprio agente auditado): material gerado por
    # decoder e ASCII por construcao (printable>=0.85) e, quando passa pela direcao 'dec' de
    # uma pagina EBCDIC, cai na imagem EBCDIC de a-z por construcao. Esses dois disparos sao
    # contados mas nao gravados um a um; tudo o mais vai integral para o log.
    TAUT = {"ascii85", "ebcdic", "ascii85+ebcdic"}
    por_tipo, por_particao, hits, n_det = Counter(), Counter(), [], 0
    for b, src in itens:
        r = oraculo_barato(b)
        if not r: continue
        n_det += 1
        por_tipo[r] += 1
        por_particao[src.split("/", 1)[0]] += 1
        if r not in TAUT:
            rec = {"arm": "C5_det", "oraculo": r, "src": src, "len": len(b), "hex": b.hex()[:512]}
            hits.append(rec); log(**rec)
    say(f"[C5] oraculo semantico/nested/ebcdic integral: {len(itens)} blobs em {time.time()-t0:.0f}s, "
        f"{n_det} disparos de detector ({len(hits)} nao-tautologicos)")
    say(f"[C5] disparos por tipo: {dict(por_tipo.most_common(12))}")
    say(f"[C5] disparos por particao: {dict(por_particao)}")
    # 2) privkey em paralelo
    t1 = time.time()
    w = workers or max(1, (os.cpu_count() or 4) - 2)
    lote, chunks, acc, cnt = [], [], 0, 0
    for i, (b, _) in enumerate(itens):
        if len(b) < 32: continue
        lote.append((i, b)); acc += (len(b) - 31) * 2; cnt += 1
        if acc >= 400_000:
            chunks.append(lote); lote, acc = [], 0
    if lote: chunks.append(lote)
    privhits = []
    with mp.Pool(w) as pool:
        for r in pool.imap_unordered(_priv_worker, chunks, chunksize=1):
            privhits.extend(r)
    say(f"[C5] privkey: {cnt} blobs >= 32 B, {janelas} janelas x 2 ordens em {time.time()-t1:.0f}s "
        f"com {w} processos -> {len(privhits)} hits")
    for idx, tag, j, sec in privhits:
        log(arm="C5_PRIVKEY", src=itens[idx][1], ordem=tag, off=j, sec=sec)
    log(arm="C5_resumo", blobs_distintos=len(itens), do_log_agente=n_so_log,
        aes=n_apos_aes - n_so_log, material=len(itens) - n_apos_aes, registros_log_agente=n_log,
        janelas_2ordens=janelas, blobs_com_priv=cnt, hits_detector=n_det,
        hits_nao_tautologicos=len(hits), hits_privkey=len(privhits), workers=w,
        detector_por_tipo=dict(por_tipo.most_common(20)),
        detector_por_particao=dict(por_particao))
    return len(itens), janelas, hits, privhits

# --------------------------------------------------------------- C6 COMPLETA: codecs multi-byte
MB = ["utf_8", "utf_8_sig", "utf_16", "utf_16_le", "utf_16_be", "utf_32", "utf_32_le",
      "utf_32_be", "utf_7", "shift_jis", "shift_jis_2004", "shift_jisx0213", "euc_jp",
      "euc_jis_2004", "euc_jisx0213", "euc_kr", "gb2312", "gbk", "gb18030", "big5",
      "big5hkscs", "cp932", "cp949", "cp950", "johab", "iso2022_jp", "iso2022_jp_2",
      "iso2022_kr", "hz"]

def c6():
    """O gap que o agente declarou: 'cifras' como codecs MULTI-BYTE.
    Mede primeiro o colapso (quantas imagens novas existem sobre token ASCII) e so
    entao gasta AES nas imagens realmente distintas."""
    bases = ROADMAP + CONHECIDOS + [G.DBBI, G.FAED, RESID_L84, RESID_L83]
    # censo de imagens
    im_por_token = {}
    for s in bases[:8]:
        im = set()
        for c in MB:
            try: im.add(s.encode(c))
            except Exception: pass
        im_por_token[s[:24]] = len(im)
    say(f"[C6] imagens de bytes distintas sob os {len(MB)} codecs multi-byte, por token: {im_por_token}")
    # corpus de senhas do braco multi-byte
    vistos, senhas = set(), []
    def add(sub, pw):
        if pw in vistos: return
        vistos.add(pw); senhas.append((sub, pw))
    for s in bases:
        sb = s.encode("latin-1", "replace")
        for c in MB:
            try: e = s.encode(c)
            except Exception: continue
            add(f"mb_raw/{c}", e)
            add(f"mb_sha/{c}", hashlib.sha256(e).hexdigest().encode())
            add(f"mb_shaR/{c}", hashlib.sha256(e).digest())
            hx = hashlib.sha256(sb).hexdigest()
            try: hxe = hx.encode(c)
            except Exception: continue
            add(f"sha_mb/{c}", hxe)
            add(f"sha_mb_sha/{c}", hashlib.sha256(hxe).hexdigest().encode())
    # + nomes dos codecs multi-byte como senha (o mesmo padrao do agente)
    for c in MB:
        for f in {c, c.replace("_", "-"), c.upper(), c.replace("_", "")}:
            add("mb_nome/ascii", f.encode())
            add("mb_nome/sha", hashlib.sha256(f.encode()).hexdigest().encode())
            for t in ROADMAP:
                add("mb_nome+road/sha", hashlib.sha256((f + t).encode()).hexdigest().encode())
    t0 = time.time()
    pad_sub, tot_sub, duros = Counter(), Counter(), []
    for sub, pw in senhas:
        for blob in ("SMALL", "COSMIC", "TAIL32"):
            for kraw, pl in G.aes_try(pw, blob, "both"):
                k = kraw.rsplit(".", 1)[-1]
                pad_sub[f"{sub}|{blob}|{k}"] += 1
                r = oraculo_duro(pl, com_priv=True)
                rec = {"arm": "C6_pad", "sub": sub, "blob": blob, "kdf": k, "len": len(pl),
                       "printable": round(G.printable(pl), 3), "hex": pl.hex()}
                if r:
                    rec["arm"] = "C6_HIT"; rec["oraculo"] = r; duros.append(rec)
                log(**rec)
            for k in ("MD5", "SHA256"):
                tot_sub[f"{sub}|{blob}|{k}"] += 1
    n_dec = len(senhas) * 6
    npad = sum(pad_sub.values())
    say(f"[C6] {len(senhas)} senhas multi-byte distintas x 3 blobs x 2 KDF = {n_dec} decifracoes "
        f"em {time.time()-t0:.0f}s; padding {npad}/{n_dec} = {npad/max(1,n_dec):.5f} vs 0.00391; "
        f"hits duros: {len(duros)}")
    zs = {}
    for tag, tot in tot_sub.items():
        zs[tag] = round((pad_sub[tag] - tot / 256) / max(1e-9, (tot * (1/256) * (255/256)) ** 0.5), 2)
    zmax = max((abs(v) for v in zs.values()), default=0)
    # NULO CASADO deste braco: 100 lotes de senhas aleatorias com a MESMA FORMA
    # (mesma distribuicao de comprimento em bytes), mesmo pipeline AES.
    tam = Counter(len(pw) for _, pw in senhas)
    lotes = []
    for _ in range(100):
        pad = 0
        for _ in range(len(senhas)):
            ln = RNG.choices(list(tam), weights=list(tam.values()))[0]
            pwr = bytes(RNG.randrange(256) for _ in range(ln))
            for blob in ("SMALL", "COSMIC", "TAIL32"):
                pad += len(G.aes_try(pwr, blob, "both"))
        lotes.append(pad)
    mu = sum(lotes) / len(lotes)
    sd = (sum((x - mu) ** 2 for x in lotes) / (len(lotes) - 1)) ** 0.5
    z_lote = (npad - mu) / sd if sd else 0.0
    # LOOK-ELSEWHERE do |z| maximo: as sub-familias tem poucas tentativas cada,
    # entao um |z| grande e artefato de contagem inteira, nao sinal.
    zmax_nulo = []
    for _ in range(100):
        zz = [abs((sum(1 for _ in range(tot) if RNG.random() < 1 / 256) - tot / 256)
                  / max(1e-9, (tot * (1 / 256) * (255 / 256)) ** 0.5))
              for tot in tot_sub.values()]
        zmax_nulo.append(max(zz))
    mu_zx = sum(zmax_nulo) / len(zmax_nulo)
    posto = sum(1 for x in zmax_nulo if x >= zmax)
    say(f"[C6] maior |z| por sub-familia: {zmax:.2f} em {len(zs)} sub-familias; nulo do MAXIMO "
        f"de |z| (100 replicas): mu={mu_zx:.2f}, replicas >= obs: {posto}/100 -> p={(posto+1)/101:.3f}")
    say(f"[C6] nulo casado do total: obs={npad} vs nulo mu={mu:.1f} sd={sd:.1f} -> z={z_lote:+.2f}")
    log(arm="C6_resumo", n_senhas=len(senhas), n_decifracoes=n_dec, padding=npad,
        taxa=npad / max(1, n_dec), n_duros=len(duros), z_max=zmax, n_sub=len(zs),
        nulo_mu=mu, nulo_sd=sd, z_lote=z_lote, nulo_zmax_mu=mu_zx,
        p_empirico_zmax=(posto + 1) / 101, imagens_por_token=im_por_token, codecs=MB)
    return len(senhas), duros, zmax

# --------------------------------------------------------------- C7 look-elsewhere do z=3,14
def c7(aes):
    """O agente reportou z = +3,14 no MAXIMO de `lower` do nulo A1 (obs 0,533).
    Um z sobre estatistica de maximo nao e interpretavel: calcula-se (a) o p empirico
    (posto do observado entre 100 replicas de nulo casado) e (b) o numero de tentativas
    equivalentes no espaco varrido (look-elsewhere analitico, binomial)."""
    import math
    # p de um byte alto cair em a-z sob a melhor pagina EBCDIC (direcao dec)
    p_az = sum(1 for v in range(0x80, 0x100) if 0 <= DEC["cp273"][v] and LOWER(DEC["cp273"][v])) / 128.0
    # tentativas independentes efetivas: as 8 paginas EBCDIC colapsam -> ~2 direcoes uteis
    n_tent = len(aes) * 2 if aes else 53573 * 2
    # P(>=16 de 30) sob binomial(30, p_az)
    def cauda(n, k, p):
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k, n + 1))
    pv = cauda(30, 16, p_az)
    esperado = n_tent * pv
    say(f"[C7] p(byte alto -> a-z sob cp273/dec) = {p_az:.4f}; P(>=16 de 30) = {pv:.3e}; "
        f"tentativas efetivas ~{n_tent} -> esperado {esperado:.2f} ocorrencias de lower>=0.533 "
        f"POR ACASO. O 'z=+3,14' dele e exatamente isso.")
    # nulo casado empirico sobre a estatistica de maximo, 100 replicas
    amostra = aes if len(aes) <= 400 else RNG.sample(aes, 400)
    def best_lower(b):
        hi = Counter(x for x in b if x >= 0x80); n = sum(hi.values())
        if n < 8: return 0.0
        best = 0.0
        for c in EBCDIC + ["latin_1"]:
            for tab in (ENC[c], DEC[c]):
                lo = sum(k for v, k in hi.items() if tab[v] >= 0 and LOWER(tab[v])) / n
                best = max(best, lo)
        return best
    obs = max(best_lower(b) for b, _ in amostra)
    nulos = []
    for _ in range(100):
        mx = 0.0
        for b, _ in amostra:
            nb = bytes((RNG.randrange(0x80, 0x100) if x >= 0x80 else x) for x in b)
            mx = max(mx, best_lower(nb))
        nulos.append(mx)
    posto = sum(1 for x in nulos if x >= obs)
    say(f"[C7] nulo casado empirico (400 plaintexts x 100 replicas): max obs = {obs:.3f}; "
        f"replicas do nulo com max >= obs: {posto}/100 -> p empirico = {(posto+1)/101:.3f}")
    log(arm="C7", p_az=p_az, p_bin_16de30=pv, tentativas=n_tent, esperado_por_acaso=esperado,
        max_obs=obs, nulo_max_mu=sum(nulos) / len(nulos), p_empirico=(posto + 1) / 101,
        replicas=100, amostra=len(amostra))
    return esperado, (posto + 1) / 101

# --------------------------------------------------------------- main
if __name__ == "__main__":
    open(LOGPATH, "w", encoding="utf-8").close()   # unica truncagem (ver a nota em log())
    t0 = time.time()
    seg32 = c0()
    faltando, dup = c1()
    tab2, ok_fatia = c2(seg32)
    senhas, bate3, zg = c3()
    aes, mat, arquivos = c4()
    n_varrido, janelas5, hits5, privhits5 = c5(aes, mat)
    n_mb, duros6, zmax6 = c6()
    esperado7, p7 = c7(aes)
    resumo = {"arm": "FIM", "segundos": round(time.time() - t0, 1),
              "C1_codecs_faltando": faltando, "C1_aliases_dup": dup,
              "C2_fatias_vacuas": ok_fatia,
              "C3_corpus_bate": bate3, "C3_z_global_padding": round(zg, 2),
              "C4_arquivos": len(arquivos), "C4_aes": len(aes), "C4_material": len(mat),
              "C5_total_varrido": n_varrido, "C5_janelas_2ordens": janelas5,
              "C5_hits_nao_tautologicos": len(hits5), "C5_hits_privkey": len(privhits5),
              "C6_senhas_multibyte": n_mb, "C6_duros": len(duros6), "C6_zmax": zmax6,
              "C7_esperado_por_acaso": round(esperado7, 2), "C7_p_empirico": p7}
    log(**resumo)
    say("RESUMO:", json.dumps(resumo, ensure_ascii=False))
    LOG.close()
