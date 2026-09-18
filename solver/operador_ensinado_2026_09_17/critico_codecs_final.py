# -*- coding: utf-8 -*-
r"""
CRITICO FINAL da familia "codecs_23" (familia4_codecs.py, campanha 2026-09-17).

O que este script verifica, nesta ordem (tudo quantitativo, tudo logado):
  1. CONTROLE POSITIVO cp273 — reimplementado sem reaproveitar as tabelas do agente: o segmento alto
     do plaintext real da fase 3.2 re-codificado em cp273 tem de dar a-z em 100 % dos bytes altos e
     0 % sob todo codec nao-EBCDIC; argmax unico = cp273. E o teste que o agente NAO fez: o oraculo
     duro dele (`duro_traduzido`, copiado literalmente) reconhece esse positivo?
  2. COBERTURA — reproduz A2 (campos x codecs x direcoes) e confronta os numeros do JSON de ataque
     com o log FINAL dele e com a recontagem C3/C4 do critico anterior.
  3. ORACULO — scanner de privkey com os DOIS enderecos do premio, duas ordens de byte, pubkey
     comprimida e nao comprimida; controle plantado obrigatorio.
  4. NULO — look-elsewhere analitico do "z = +3,14" reportado no JSON (que a execucao final dele
     nem reproduz: z_max = -0,88).
  5. COMPLETA o braco mais valioso deixado de fora: auditoria INDIVIDUAL dos 699 hits de detector
     da particao MATERIAL — necessaria porque o oraculo duro dele nao reconhece o positivo real.
     Bonus barato: censo dos 29 codecs multi-byte contra as 7 imagens UTF ja varridas.
  6. RE-VARRE todo plaintext com padding valido que ele (e o critico anterior) produziu, com o
     oraculo completo e os dois enderecos.

Nao importa familia4_codecs.py: aquele modulo abre o proprio log em modo "w" ao ser importado.
Uso: python critico_codecs_final.py
"""
import sys, os, json, time, math, hashlib, base64, random
from collections import Counter

ROOT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
sys.path.insert(0, os.path.join(ROOT, r"solver\experiments\claude_endgame_2026_09_02"))
sys.path.insert(0, os.path.join(ROOT, r"solver\primos_2026_09_17"))
import gsmg_common as G
import clean_scorer
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from coincurve import PublicKey
import base58

OUT = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\critico_codecs_final")
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, "critico_codecs_final.jsonl"), "w", encoding="utf-8")
LOG_AGENTE = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\familia4_codecs\familia4_codecs.jsonl")
LOG_C23 = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\critico_codecs23\critico_codecs23.jsonl")
LOG_CF4 = os.path.join(ROOT, r"_work\operador_ensinado_2026-09-17\critico_familia4_codecs\critico_familia4_codecs.jsonl")
JSON_ATAQUE = {"A1_aes": 53573, "A1_arquivos": 95, "A1_material": 684413, "A2_transf": 114,
               "A3_senhas": 105519, "A3_pad": 2540, "A1_z_max": 3.14}   # o que o JSON de ataque afirma

def log(**kw):
    LOG.write(json.dumps(kw, ensure_ascii=False, default=str) + "\n"); LOG.flush()
def say(*a):
    print(*a, flush=True)

RNG = random.Random(2309)
SC = clean_scorer.Scorer()

# ------------------------------------------------------------------ codecs (lista exata do agente)
CODECS = ("latin_1 iso8859_2 iso8859_3 iso8859_4 iso8859_5 iso8859_6 iso8859_7 iso8859_8 "
          "iso8859_9 iso8859_10 iso8859_11 iso8859_13 iso8859_14 iso8859_15 iso8859_16 "
          "cp1250 cp1251 cp1252 cp1253 cp1254 cp1255 cp1256 cp1257 cp1258 "
          "cp037 cp273 cp424 cp500 cp1026 cp1140 cp875 ebcdic_cp_us "
          "cp437 cp720 cp737 cp775 cp850 cp852 cp855 cp856 cp857 cp858 cp860 cp861 cp862 "
          "cp863 cp864 cp865 cp866 cp869 cp874 cp1006 "
          "koi8_r koi8_u koi8_t kz1048 ptcp154 mac_roman mac_cyrillic mac_greek mac_iceland "
          "mac_latin2 mac_turkish hp_roman8 tis_620").split()
EBC = ["cp037", "cp273", "cp424", "cp500", "cp875", "cp1026", "cp1140", "ebcdic_cp_us"]

def enc_table(c):
    t = [-1] * 256
    for v in range(256):
        try: b = chr(v).encode(c)
        except Exception: continue
        if len(b) == 1: t[v] = b[0]
    return t
def dec_table(c):
    t = [-1] * 256
    for v in range(256):
        try: o = ord(bytes([v]).decode(c))
        except Exception: continue
        t[v] = o if o < 256 else -1
    return t
ENC = {c: enc_table(c) for c in CODECS}
DEC = {c: dec_table(c) for c in CODECS}
def traduz(p, c, d):
    t = (ENC if d == "enc" else DEC)[c]
    return bytes(t[x] & 0xFF for x in p if t[x] >= 0)

# ------------------------------------------------------------------ oraculo duro: DOIS enderecos
ADDRS = ("1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa")
TARGETS = {base58.b58decode_check(a)[1:].hex(): a for a in ADDRS}
assert "4bc468447fe1b048ad030a2f9a125478eabc4ed6" in TARGETS and G.TARGET_H160 in TARGETS
def h160(b): return hashlib.new("ripemd160", hashlib.sha256(b).digest()).hexdigest()
def priv2(sec):
    """(endereco, forma) se sec for a privkey de um dos dois enderecos do premio; senao None."""
    if len(sec) != 32: return None
    try: pk = PublicKey.from_valid_secret(sec)
    except Exception: return None
    for form, blob in (("unc", pk.format(False)), ("comp", pk.format(True))):
        a = TARGETS.get(h160(blob))
        if a: return (a, form)
    return None
def priv_windows(buf):
    hits = []
    for ordem, src in (("fwd", buf), ("rev", buf[::-1])):
        for j in range(0, len(src) - 31):
            r = priv2(src[j:j + 32])
            if r: hits.append((ordem, j, r[0], r[1], src[j:j + 32].hex()))
    return hits
def oraculo_completo(p):
    """Rotulos do oraculo duro completo. 'ascii85'/'ebcdic' sao tautologicos sobre material
    gerado por decoder (nao sobre plaintext AES); os rotulos em MAIUSCULA sao os que decidem."""
    r = []
    if G.nested_blob(p): r.append("NESTED")
    if G.printable(p) >= 0.85: r.append("ascii85")
    if G.ebcdic_sig(p) >= 0.75: r.append("ebcdic")
    t = p.decode("latin-1")
    for h in G.hex64_candidates(t):
        r.append("hex64")
        x = priv2(bytes.fromhex(h))
        if x: r.append(f"HEX64PRIV:{x}")
    for w in G.wif_candidates(t):
        r.append("wif")
        try:
            x = priv2(base58.b58decode_check(w)[1:33])
            if x: r.append(f"WIFPRIV:{x}")
        except Exception:
            pass
    if len(p) >= 32:
        for h in priv_windows(p): r.append(f"PRIVKEY:{h}")
    return r

# ------------------------------------------------------------------ utilidades de texto
def letras(t): return "".join(c for c in t.upper() if "A" <= c <= "Z")
def ioc(t):
    t = letras(t); n = len(t)
    if n < 2: return 0.0
    c = Counter(t); return 26 * sum(v * (v - 1) for v in c.values()) / (n * (n - 1))
def beaufort(t, key="THEMATRIXHASYOU"):
    out = []
    for i, ch in enumerate(letras(t)):
        out.append(chr((ord(key[i % len(key)]) - ord(ch)) % 26 + 65))
    return "".join(out)
def duro_traduzido_do_agente(out):
    """Copia LITERAL de familia4_codecs.duro_traduzido (o oraculo dele sobre a saida traduzida)."""
    if G.nested_blob(out): return "nested_blob"
    txt = out.decode("latin-1")
    if G.wif_candidates(txt): return "wif"
    if G.hex64_candidates(txt) and any(not (48 <= x <= 57 or 97 <= x <= 102 or 65 <= x <= 70) for x in out): return "hex64"
    if not all(32 <= x <= 126 or x in (9, 10, 13) for x in out): return None
    if len(out) >= 24 and G.english_score(txt) > -4.5: return "ingles"
    if len(G.word_hits(txt, 6)) >= 2: return "bip39x2"
    return None

# ================================================================== 1. controle positivo
def passo1_controle():
    raw = base64.b64decode(G.PHASE32_B64)
    k, iv = G.evp(b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c", raw[8:16], SHA256)
    p32 = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(raw[16:]))
    assert p32 and p32.startswith(b"I've been waiting for you."), "fase 3.2 nao reproduziu"
    hi = [i for i, x in enumerate(p32) if x >= 0x80]
    seg = p32[hi[0]:hi[-1] + 1]
    altos = [x for x in seg if x >= 0x80]
    # fracao a-z sob RE-ENCODE, char a char (independente das tabelas do agente)
    frac = {}
    for c in CODECS:
        n = 0
        for x in altos:
            try: b = chr(x).encode(c)
            except Exception: continue
            if len(b) == 1 and 0x61 <= b[0] <= 0x7A: n += 1
        frac[c] = n / len(altos)
    ordenado = sorted(frac.items(), key=lambda kv: -kv[1])
    assert frac["cp273"] == 1.0, "cp273 nao deu 1.0"
    nao_ebc = [c for c in CODECS if c not in EBC]
    assert all(frac[c] == 0.0 for c in nao_ebc), "algum codec nao-EBCDIC disparou"
    assert ordenado[0][0] == "cp273" and ordenado[1][1] < 1.0, "argmax nao e unico"
    acima_limiar = [c for c in CODECS if frac[c] >= 0.75]
    reenc = seg.decode("latin-1").encode("cp273")
    assert reenc[:12] == b"vtkvplmepphl", "re-encode nao reproduziu o campo 3"
    # o oraculo duro DELE sobre o positivo real
    duro = duro_traduzido_do_agente(reenc)
    eng = G.english_score(reenc.decode("latin-1")); eng_limpo = SC(letras(reenc.decode("latin-1")))
    kit_sem = G.semantic(seg); kit_ebc = G.ebcdic_sig(seg)
    # KDF
    raw2 = base64.b64decode(G.PHASE2_B64)
    k2, iv2 = G.evp(G.shahex("causality").encode(), raw2[8:16], SHA256)
    p2 = G.unpad(AES.new(k2, AES.MODE_CBC, iv2).decrypt(raw2[16:]))
    assert p2 and G.printable(p2) > 0.9, "controle de KDF falhou"
    # scanner de privkey: chave plantada, 2 ordens x 2 formas, alvo forjado temporariamente
    seed = hashlib.sha256(b"controle-critico-final").digest()
    pk = PublicKey.from_valid_secret(seed)
    plant = {}
    for form, blob in (("unc", pk.format(False)), ("comp", pk.format(True))):
        TARGETS[h160(blob)] = "PLANTADO_" + form
        hf = priv_windows(bytes(7) + seed + bytes(9))
        hr = priv_windows(bytes(5) + seed[::-1] + bytes(3))
        plant[form] = (any(o == "fwd" and j == 7 and a == "PLANTADO_" + form for o, j, a, f, _ in hf),
                       any(o == "rev" and a == "PLANTADO_" + form for o, j, a, f, _ in hr))
        del TARGETS[h160(blob)]
    assert all(all(v) for v in plant.values()), f"scanner plantado falhou: {plant}"
    assert priv2(seed) is None, "scanner dispara em chave que nao e do premio"
    say(f"[1] controle cp273: frac=1.000, argmax unico, {len(nao_ebc)} nao-EBCDIC = 0.000; "
        f"codecs >= 0.75 (limiar do detector): {acima_limiar}")
    say(f"[1] oraculo duro DO AGENTE sobre o positivo real: {duro!r}  (english {eng:.2f}, limpo {eng_limpo:.2f}) "
        f"| kit: semantic={kit_sem} ebcdic_sig={kit_ebc:.3f}")
    say(f"[1] KDF fase2 OK; scanner privkey plantado: {plant} (2 ordens x 2 formas), nao dispara em chave alheia")
    log(passo=1, cp273=frac["cp273"], top5=ordenado[:5], acima_limiar=acima_limiar,
        nao_ebcdic_zero=True, argmax_unico=True, reenc_head=reenc[:32].decode("latin-1"),
        oraculo_agente_no_positivo=duro, english_positivo=round(eng, 3), english_limpo_positivo=round(eng_limpo, 3),
        kit_semantic=kit_sem, kit_ebcdic_sig=round(kit_ebc, 3), kdf_ok=True, plantado=plant)
    return seg, reenc, duro

# ================================================================== 2. cobertura
RESID_L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
RESID_L83 = RESID_L84[:-1]
def passo2_cobertura(seg32):
    c3 = seg32.decode("latin-1").encode("cp273").decode("latin-1")
    campos = {"dbbi": G.DBBI, "faed": G.FAED, "matrixsumlist": G.TOKENS["matrixsumlist"],
              "enter": G.TOKENS["enter"], "lastwords": G.TOKENS["lastwordsbeforearchichoice"],
              "thispassword": G.TOKENS["thispassword"], "linha_antes": G.TOKENS["line_before_small"],
              "linha_depois": G.TOKENS["line_after_small"], "resid_L84": RESID_L84, "resid_L83": RESID_L83,
              "campo3_32": c3, "small_b64": G.SMALL_B64, "tail32_b64": G.TAIL32_B64}
    bina = {"small_ct": G.BLOBS["SMALL"][1], "cosmic_ct": G.BLOBS["COSMIC"][1], "tail32_ct": G.BLOBS["TAIL32"][1],
            "small_salt": G.BLOBS["SMALL"][0], "cosmic_salt": G.BLOBS["COSMIC"][0], "tail32_salt": G.BLOBS["TAIL32"][0]}
    n_transf, por_campo = 0, {}
    for nome, s in list(campos.items()) + [(k, v.decode("latin-1")) for k, v in bina.items()]:
        b0 = s.encode("latin-1", "replace"); vistos = set()
        for c in CODECS:
            for d in ("enc", "dec"):
                out = traduz(b0, c, d)
                if len(out) < len(b0) * 0.9 or out == b0 or out in vistos: continue
                vistos.add(out)
        por_campo[nome] = len(vistos); n_transf += len(vistos)
    # numeros do log FINAL do agente e da recontagem do critico anterior
    a1 = fim = None
    for l in open(LOG_AGENTE, encoding="utf-8"):
        d = json.loads(l)
        if d["arm"] == "A1_resumo": a1 = d
        elif d["arm"] == "FIM": fim = d
    c3r = c4r = None
    for l in open(LOG_CF4, encoding="utf-8"):
        d = json.loads(l)
        if d["arm"] == "C3": c3r = d
        elif d["arm"] == "C4": c4r = d
        elif d["arm"].startswith("C5"): break
    top_src = a1["arquivos_top"]
    realimentado = {k: v for k, v in top_src.items() if "critico_" in k}
    say(f"[2] A2 reproduzido: {len(campos)+len(bina)} campos x 65 x 2 -> {n_transf} transformadas distintas "
        f"(JSON: {JSON_ATAQUE['A2_transf']})")
    say(f"[2] A1 no JSON: {JSON_ATAQUE['A1_aes']} AES / {JSON_ATAQUE['A1_arquivos']} arquivos / "
        f"{JSON_ATAQUE['A1_material']} material | no LOG FINAL dele: {a1['n_aes']} / {a1['n_arquivos']} / {a1['n_material']} "
        f"| critico anterior (coletor amplo): {c4r['n_aes']} / {c4r['arquivos_com_hex']} / {c4r['n_material']}")
    say(f"[2] registros do corpus dele vindos de logs de CRITICOS (realimentacao): {realimentado}")
    say(f"[2] A1 nulo no JSON: z_max=+{JSON_ATAQUE['A1_z_max']} | no LOG FINAL: z_media={a1['nulo_media_z']:+.2f} "
        f"z_max={a1['nulo_max_z']:+.2f} (max obs {a1['nulo_max_obs']:.3f} vs nulo {a1['nulo_max_mu']:.3f}+-{a1['nulo_max_sd']:.3f})")
    say(f"[2] A3 recontado pelo critico anterior: {c3r['senhas_recontadas']} senhas (alegado {c3r['senhas_alegadas']}), "
        f"{c3r['pad_log']} paddings (alegado {c3r['pad_alegado']}), z_global={c3r['z_global']:+.2f}, bate={c3r['bate']}")
    log(passo=2, a2_transformadas=n_transf, a2_por_campo=por_campo, json=JSON_ATAQUE,
        log_final_a1={k: a1[k] for k in ("n_aes", "n_material", "n_arquivos", "aes_hits", "mat_hits", "aes_max_lower",
                                          "aes_max_codec", "aes_max_dir", "nulo_media_z", "nulo_max_z", "nulo_max_obs",
                                          "nulo_max_mu", "nulo_max_sd")},
        realimentacao=realimentado, c3_critico_anterior={k: c3r[k] for k in ("senhas_recontadas", "pad_log", "z_global", "bate")},
        c4_critico_anterior={k: c4r[k] for k in ("arquivos_com_hex", "n_aes", "n_material")}, fim_agente=fim)
    return n_transf, a1

# ================================================================== 4. look-elsewhere do z=+3,14
def passo4_look_elsewhere(a1):
    # p(byte alto uniforme -> a-z) sob cada tabela EBCDIC, nas 2 direcoes; o maximo e o pior caso
    ps = {}
    for c in EBC:
        for d, T in (("enc", ENC), ("dec", DEC)):
            ps[f"{c}/{d}"] = sum(1 for v in range(0x80, 0x100) if T[c][v] >= 0 and 0x61 <= T[c][v] <= 0x7A) / 128
    pmax = max(ps.values())
    def cauda(n, k, p): return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k, n + 1))
    pv = cauda(30, 16, pmax)          # o "16/30 em 80 B" do JSON
    n_tent = JSON_ATAQUE["A1_aes"] * 2   # 2 direcoes efetivas (as paginas EBCDIC colapsam entre si)
    esperado = n_tent * pv
    say(f"[4] p(byte alto -> a-z) por tabela EBCDIC: max={pmax:.3f}; P(>=16/30)={pv:.2e}; "
        f"tentativas efetivas ~{n_tent} -> {esperado:.1f} ocorrencias esperadas POR ACASO de lower>=0.533. "
        f"O z=+3,14 do JSON e estatistica de maximo sem look-elsewhere; a execucao final dele deu z_max={a1['nulo_max_z']:+.2f}.")
    log(passo=4, p_por_tabela=ps, p_max=pmax, p_bin_16de30=pv, tentativas=n_tent, esperado_por_acaso=esperado,
        z_max_log_final=a1["nulo_max_z"])
    return esperado

# ================================================================== 5. auditoria dos 699 + censo multi-byte
def passo5_auditoria_699(seg32, reenc):
    ref = {"ioc": round(ioc(reenc.decode("latin-1")), 3), "eng_limpo": round(SC(letras(reenc.decode("latin-1"))), 3),
           "beaufort_eng": round(SC(beaufort(reenc.decode("latin-1"))), 3), "ebcdic_sig_cru": round(G.ebcdic_sig(seg32), 3)}
    itens = []
    for l in open(LOG_AGENTE, encoding="utf-8"):
        d = json.loads(l)
        if d["arm"] == "A1_material": itens.append(d)
    assert len(itens) == 699, f"esperava 699 hits MATERIAL, achei {len(itens)}"
    truncados = sum(1 for d in itens if len(d["hex"]) >= 512)
    por_src, melhores, duros = Counter(), [], []
    stats = {"eng_limpo_max": -99, "ioc_max": 0, "beaufort_max": -99, "bip39_max": 0}
    for d in itens:
        b = bytes.fromhex(d["hex"]); out = traduz(b, d["codec"], d["dir"]); t = out.decode("latin-1")
        por_src[os.path.basename(os.path.dirname(d["src"])) + "/" + os.path.basename(d["src"])] += 1
        m = {"eng_limpo": round(SC(letras(t)), 3) if len(letras(t)) >= 8 else -99.0, "ioc": round(ioc(t), 3),
             "beaufort": round(SC(beaufort(t)), 3) if len(letras(t)) >= 8 else -99.0,
             "bip39": len(G.word_hits(t, 5)), "ebcdic_cru": round(G.ebcdic_sig(b), 3)}
        o_cru = [x for x in oraculo_completo(b) if x.isupper()]
        o_tr = [x for x in oraculo_completo(out) if x.isupper()]
        if o_cru or o_tr: duros.append({**d, "oraculo_cru": o_cru, "oraculo_trad": o_tr})
        stats["eng_limpo_max"] = max(stats["eng_limpo_max"], m["eng_limpo"]); stats["ioc_max"] = max(stats["ioc_max"], m["ioc"])
        stats["beaufort_max"] = max(stats["beaufort_max"], m["beaufort"]); stats["bip39_max"] = max(stats["bip39_max"], m["bip39"])
        melhores.append((m["eng_limpo"], m["ioc"], d["src"], d["codec"], d["dir"], t[:48], m))
        log(passo=5, arm="audit699", src=d["src"], codec=d["codec"], dir=d["dir"], lower=d["lower"], **m,
            trad_head=t[:64], oraculo_cru=o_cru, oraculo_trad=o_tr)
    melhores.sort(key=lambda x: -x[0])
    say(f"[5] 699 hits MATERIAL auditados um a um ({truncados} com hex truncado): por origem {dict(por_src)}")
    say(f"[5] referencia = positivo real traduzido: {ref}")
    say(f"[5] maximos nos 699: {stats}  | oraculo duro (2 enderecos) cru+traduzido: {len(duros)} hits")
    for e, i, s, c, d, h, m in melhores[:5]:
        say(f"     eng_limpo={e:.2f} ioc={i:.2f} {c}/{d} {os.path.basename(s)} | {h!r}")
    log(passo=5, arm="audit699_resumo", n=699, truncados=truncados, por_src=dict(por_src), referencia=ref,
        maximos=stats, duros=len(duros), top5=[(e, i, s, c, d, h) for e, i, s, c, d, h, _ in melhores[:5]])
    return stats, duros

def passo5c_calibracao(reenc, stats5):
    """O oraculo da auditoria (Beaufort/THEMATRIXHASYOU sobre o traduzido) precisa de dois controles:
    (i) POSITIVO: o campo 3 real, traduzido em cp273 e decifrado, tem de dar ingles (a fala do Arquiteto)
        acima de -4,5 e fora do nulo de letras aleatorias de mesmo comprimento;
    (ii) NULO CASADO do maximo entre os 699: 100 replicas de 699 strings a-z com o MESMO numero de letras
        de cada item -> p empirico do maximo observado."""
    eng_long = letras("IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF THE MATRIX HAS YOU")
    calib = {"ingles_longo": round(SC(eng_long), 3), "ingles_15": round(SC(eng_long[:15]), 3),
             "aleatorio_1000": round(SC("".join(RNG.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(1000))), 3)}
    tr = reenc.decode("latin-1"); n = len(letras(tr)); bf = beaufort(tr); pos = SC(bf)
    nulo_pos = [SC(beaufort("".join(RNG.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(n)))) for _ in range(100)]
    assert pos > -4.5 and pos > max(nulo_pos) + 2.0, f"controle positivo da auditoria falhou: {pos} vs nulo {max(nulo_pos)}"
    assert bf.startswith("YOURLIFEISTHESUM"), "Beaufort do campo 3 real nao deu a fala do Arquiteto"
    n_letras = []   # numero exato de letras de cada um dos 699 traduzidos (recomputado do log do agente)
    for l in open(LOG_AGENTE, encoding="utf-8"):
        d = json.loads(l)
        if d["arm"] == "A1_material":
            n_letras.append(len(letras(traduz(bytes.fromhex(d["hex"]), d["codec"], d["dir"]).decode("latin-1"))))
    maxs = []
    for _ in range(100):
        m = -99.0
        for k in n_letras:
            if k >= 8: m = max(m, SC(beaufort("".join(RNG.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(k)))))
        maxs.append(m)
    obs = stats5["beaufort_max"]; posto = sum(1 for m in maxs if m >= obs)
    mu = sum(maxs) / len(maxs); sd = (sum((x - mu) ** 2 for x in maxs) / 99) ** 0.5
    dist = Counter(n_letras)
    say(f"[5c] scorer limpo: {calib} | POSITIVO: campo3 real -> cp273 -> Beaufort = {bf[:48]}... score {pos:.3f} "
        f"(nulo mesmo n={n}: mu={sum(nulo_pos)/100:.3f} max={max(nulo_pos):.3f})")
    say(f"[5c] 699: n_letras min={min(n_letras)} max={max(n_letras)} (<8 letras: {sum(1 for k in n_letras if k < 8)}); "
        f"max Beaufort obs={obs:.3f} | nulo do maximo (100 replicas casadas): mu={mu:.3f} sd={sd:.3f}, "
        f"replicas >= obs: {posto}/100 -> p={(posto+1)/101:.3f}")
    log(passo=5, arm="calibracao", scorer=calib, positivo_beaufort_head=bf[:64], positivo_score=round(pos, 3),
        positivo_n_letras=n, nulo_positivo_mu=round(sum(nulo_pos)/100, 3), nulo_positivo_max=round(max(nulo_pos), 3),
        n_letras_699=dict(sorted(dist.items())), max_obs=obs, nulo_max_mu=round(mu, 3), nulo_max_sd=round(sd, 3),
        p_empirico=round((posto + 1) / 101, 3))
    return round((posto + 1) / 101, 3)

MB = ["utf_8", "utf_8_sig", "utf_16", "utf_16_le", "utf_16_be", "utf_32", "utf_32_le", "utf_32_be", "utf_7",
      "shift_jis", "shift_jis_2004", "shift_jisx0213", "euc_jp", "euc_jis_2004", "euc_jisx0213", "euc_kr",
      "gb2312", "gbk", "gb18030", "big5", "big5hkscs", "cp932", "cp949", "cp950", "johab", "iso2022_jp",
      "iso2022_jp_2", "iso2022_kr", "hz"]
JA_COBERTOS = ["utf_16", "utf_16_le", "utf_16_be", "utf_32", "utf_32_le", "utf_32_be", "utf_8_sig"]  # critico_codecs23
ROADMAP = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang",
           "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit", "verylaststepisatruegiveawaypromised"]
CONHECIDOS = ["causality", "thispassword", "sha256", "enter", "theseedisplanted", "thematrixhasyou",
              "followthewhiterabbit", "salphaseion", "cosmicduality", "our first hint is your last command",
              "ans too", "shabef", "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
              "twentythreeciphers", "sixteenencryptions", "seven intertwined passwords",
              "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",
              "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
              "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
              "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"]
def passo5b_multibyte():
    bases = ROADMAP + CONHECIDOS + [G.DBBI, G.FAED, RESID_L84, RESID_L83]
    novas, por_codec = [], Counter()
    for s in bases:
        cob = {s.encode("ascii")} | {s.encode(c) for c in JA_COBERTOS}
        for c in MB:
            if c in JA_COBERTOS: continue
            try: e = s.encode(c)
            except Exception: continue
            if e not in cob: novas.append((c, s, e)); por_codec[c] += 1
    n_dec = duros = pads = 0
    for c, s, e in novas:      # so gasta AES no que e imagem realmente inedita
        hx = hashlib.sha256(s.encode("ascii")).hexdigest()
        for pw in (e, hashlib.sha256(e).hexdigest().encode(), hashlib.sha256(e).digest(), hx.encode(c),
                   hashlib.sha256(hx.encode(c)).hexdigest().encode()):
            for blob in ("SMALL", "COSMIC", "TAIL32"):
                n_dec += 2
                for k, p in G.aes_try(pw, blob, "both"):
                    pads += 1; o = [x for x in oraculo_completo(p) if x.isupper() or x == "ascii85"]
                    if o: duros += 1
                    log(passo=5, arm="mb_pad" if not o else "MB_HIT", codec=c, base=s[:40], blob=blob, kdf=k, oraculo=o, hex=p.hex())
    # controle positivo do censo: utf_16 (ja coberto) produz imagem nova por construcao
    assert "yellowblueprimes".encode("utf_16") not in {b"yellowblueprimes"}, "censo nao distingue imagens"
    say(f"[5b] censo multi-byte: {len(MB)-len(JA_COBERTOS)} codecs alem dos 7 UTF ja varridos, {len(bases)} bases -> "
        f"{len(novas)} imagens INEDITAS {dict(por_codec)}; AES nelas: {n_dec} decifracoes, {pads} paddings, {duros} duros")
    log(passo=5, arm="mb_resumo", codecs=MB, ja_cobertos=JA_COBERTOS, bases=len(bases), imagens_ineditas=len(novas),
        por_codec=dict(por_codec), decifracoes=n_dec, paddings=pads, duros=duros)
    return len(novas), duros

# ================================================================== 6. re-varredura com oraculo completo e 2 enderecos
def passo6_revarredura():
    corpus, vistos = [], set()
    def add(src, hx, ctx):
        try: b = bytes.fromhex(hx)
        except ValueError: return
        if b in vistos: return
        vistos.add(b); corpus.append((src, b, ctx))
    for l in open(LOG_AGENTE, encoding="utf-8"):
        d = json.loads(l)
        if d["arm"] in ("A3_pad", "A2_pad", "A1_material") and "hex" in d:
            add("agente/" + d["arm"], d["hex"], {k: d.get(k) for k in ("sub", "campo", "blob", "kdf", "codec", "dir", "src")})
    if os.path.exists(LOG_C23):
        for l in open(LOG_C23, encoding="utf-8"):
            d = json.loads(l)
            if d["arm"] in ("MB_pad", "MB_duro") and "hex" in d:
                add("critico23/" + d["arm"], d["hex"], {k: d.get(k) for k in ("sub", "blob", "kdf")})
    por_src = Counter(s for s, _, _ in corpus)
    janelas = sum(2 * max(0, len(b) - 31) for _, b, _ in corpus)
    say(f"[6] corpus da re-varredura: {len(corpus)} plaintexts distintos {dict(por_src)}; {janelas} janelas de 32 B (2 ordens x 2 formas x 2 enderecos)")
    t0 = time.time(); hits, tipos, mx = [], Counter(), {"printable": 0.0, "ebcdic_sig": 0.0}
    for i, (src, b, ctx) in enumerate(corpus):
        o = oraculo_completo(b)
        mx["printable"] = max(mx["printable"], G.printable(b)); mx["ebcdic_sig"] = max(mx["ebcdic_sig"], G.ebcdic_sig(b))
        for x in o: tipos[x.split(":")[0]] += 1
        decisivo = [x for x in o if x.isupper()]
        # sobre plaintext AES, ascii85/ebcdic NAO sao tautologicos: contam como hit semantico
        if src.startswith("agente/A3") or src.startswith("agente/A2") or src.startswith("critico23"):
            decisivo += [x for x in o if x in ("ascii85", "ebcdic")]
        if decisivo:
            rec = {"passo": 6, "arm": "REV_HIT", "src": src, "ctx": ctx, "oraculo": o, "hex": b.hex()[:256]}
            hits.append(rec); log(**rec)
        if (i + 1) % 500 == 0: say(f"     {i+1}/{len(corpus)} em {time.time()-t0:.0f}s, hits={len(hits)}")
    say(f"[6] re-varredura: {len(corpus)} plaintexts em {time.time()-t0:.0f}s; rotulos: {dict(tipos)}; "
        f"max printable={mx['printable']:.3f} max ebcdic_sig={mx['ebcdic_sig']:.3f}; HITS decisivos: {len(hits)}")
    for h in hits[:10]: say("   HIT:", h["src"], h["oraculo"], h["hex"][:64])
    log(passo=6, arm="REV_resumo", n=len(corpus), por_src=dict(por_src), janelas=janelas, rotulos=dict(tipos),
        hits=len(hits), segundos=round(time.time() - t0, 1), **{k: round(v, 3) for k, v in mx.items()})
    return len(corpus), janelas, hits, mx

# ================================================================== main
if __name__ == "__main__":
    t0 = time.time()
    seg32, reenc, duro_pos = passo1_controle()
    n_a2, a1 = passo2_cobertura(seg32)
    esperado4 = passo4_look_elsewhere(a1)
    stats5, duros5 = passo5_auditoria_699(seg32, reenc)
    p5c = passo5c_calibracao(reenc, stats5)
    n_mb, duros_mb = passo5b_multibyte()
    n6, jan6, hits6, mx6 = passo6_revarredura()
    resumo = {"passo": 0, "arm": "FIM", "segundos": round(time.time() - t0, 1),
              "controle_cp273": True, "oraculo_agente_reconhece_positivo": duro_pos is not None,
              "a2_reproduzido": n_a2, "look_elsewhere_esperado": round(esperado4, 2),
              "audit699_maximos": stats5, "audit699_duros": len(duros5), "audit699_p_beaufort_max": p5c,
              "multibyte_imagens_ineditas": n_mb, "multibyte_duros": duros_mb,
              "revarredura_n": n6, "revarredura_janelas": jan6, "revarredura_hits": len(hits6), "revarredura_max": mx6}
    log(**resumo)
    json.dump(resumo, open(os.path.join(OUT, "resumo.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False, default=str)
    say("RESUMO:", json.dumps(resumo, ensure_ascii=False, default=str))
    LOG.close()
