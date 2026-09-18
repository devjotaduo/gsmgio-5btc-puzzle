# -*- coding: utf-8 -*-
"""
FAMILIA 2 — "lastwordsbeforearchichoice" lido LITERALMENTE no transcript do filme.

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O rotulo `lastwordsbeforearchichoice` (que a propria pagina final entrega decodificado pelo
codec z) nao e um enfeite tematico: nomeia um objeto externo e concreto — as ultimas palavras
ditas ANTES da escolha do Arquiteto, na cena de Matrix Reloaded, na mesma transcricao de 2003
que o criador parafraseou no plaintext da fase 3.2. Se a hipotese vale, a senha de um dos tres
blobs (SMALL / TAIL32 / COSMIC) e derivada de um recorte literal dessa fronteira — a janela de
N palavras imediatamente antes da palavra "choice", a fala das duas portas, a fala de "Hope",
as ultimas palavras literais do Arquiteto ("We won't.", que e tambem o token
`wewontgiveawaythepassword` do roadmap), a ultima fala de Neo, ou o trecho de ~360 palavras que
o criador CORTOU ao remontar o discurso na fase 3.2 (o corte termina exatamente antes das
portas) — sob as convencoes que as fases 0–3.2 ja ensinaram: caixa preservada ou minuscula,
"connected enf" (sem espacos), sem pontuacao, iniciais; cada material usado cru E como sha256
hex; e tambem serializado pelo operador RAB (letras -> ordinais a1z26 -> concatenacao, soma e
lista) e pelo codec z da propria pagina (a–i,o <-> decimal <-> hex <-> ASCII).

FALSIFICACAO: se nenhum desses materiais abre nenhum dos tres blobs com plaintext semantico
(oraculo duro de `gsmg_common`: >=85% ASCII, WIF/hex64 plausivel, blob openssl aninhado, ou
assinatura EBCDIC cp273 >= 0,75) nem produz a privkey do premio, a familia esta morta na
cobertura declarada — e a taxa de padding valido observada deve ser indistinguivel do nulo
casado (embaralhamento da ordem das palavras dentro de cada frase, que preserva exatamente o
multiconjunto de letras, o tamanho e a forma de toda senha derivada).

O QUE E NOVO (a sobreposicao esta medida e impressa no log, chave "overlap")
---------------------------------------------------------------------------
`solver/architect_sum_attack.py` (historico) usou o transcript so como fonte de palavras
selecionadas pelas somas do faed, com cortes em "choice"/"select"/"there are two doors", so no
blob SMALL. `round3_inline.py` (R1) testou ~90 frases CURTAS (<15 palavras) da cena, em 11
grafias x 4 formas, so sob EVP-SHA256. Nao existe cobertura previa de: (a) a janela deslizante
sistematica de N=1..30 palavras antes de "choice"; (b) as falas LONGAS verbatim (portas
inteiras, discurso cortado inteiro); (c) a serializacao RAB e o codec z aplicados a essas
frases; (d) o braco EVP-MD5; (e) o oraculo de 2026-09-17 (blob aninhado + assinatura EBCDIC +
varredura de privkey no plaintext).

COBERTURA: ver o resumo final impresso e o registro {"kind":"resumo"} no JSONL.
NAO COBERTO (declarado): transcricoes alternativas do filme alem da local
(ChatExport_2026-09-08/files/MISC.txt), a cena ANTERIOR ao ponto de corte da fase 3.2 (o
arquivo local so tem o trecho final), composicoes de 2+ frases entre si, e o braco brainwallet
(sha256(senha) como privkey) dentro dos replicados nulos — no real ele roda para toda senha.
"""
import sys, os, re, json, time, random, hashlib

KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from Crypto.Util.strxor import strxor
sys.set_int_max_str_digits(0)

RAIZ = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
TRANS = os.path.join(RAIZ, "_work", "operador_ensinado_2026-09-17", "TRANSCRIPT_ARQUITETO.txt")
OUT = os.path.join(RAIZ, "_work", "operador_ensinado_2026-09-17", "familia2_lastwords")
os.makedirs(OUT, exist_ok=True)
LOG = os.path.join(OUT, "run.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)

# --------------------------------------------------------------- blobs e maquina de tentativa
HMS = (("SHA256", SHA256), ("MD5", MD5))
def prep(salt, ct): return (salt, ct, ct[-32:-16], ct[-16:])
BL_REAL = {n: prep(*G.BLOBS[n]) for n in ("SMALL", "TAIL32", "COSMIC")}

def pad_ok(b16):
    p = b16[-1]
    return 1 <= p <= 16 and b16[-p:] == bytes([p]) * p

class Run:
    """Um passe do pipeline. `bl` = blobs alvo; `priv` liga o braco brainwallet."""
    def __init__(self, bl, priv=True, registrar=True):
        self.bl, self.priv, self.registrar = bl, priv, registrar
        self.seen = set()
        self.trials = {}          # classe de operador -> [tentativas, paddings]
        self.pw = 0
        self.hard = []

    def conta(self, cls, pads=0, tr=0):
        c = self.trials.setdefault(cls, [0, 0]); c[0] += tr; c[1] += pads

    def tenta(self, pw, cls, tag):
        if isinstance(pw, str): pw = pw.encode("utf-8", "surrogateescape")
        if not pw or pw in self.seen: return
        self.seen.add(pw); self.pw += 1
        for bn, (salt, ct, cprev, clast) in self.bl.items():
            for kn, hm in HMS:
                k, iv = G.evp(pw, salt, hm)
                self.conta(cls, 0, 1)
                last = strxor(AES.new(k, AES.MODE_ECB).decrypt(clast), cprev)
                if not pad_ok(last): continue
                self.conta(cls, 1, 0)
                p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
                if p is None: continue
                # a varredura de privkey no plaintext custa ~15 k ops de curva por acerto de
                # padding no COSMIC; roda so no passe real. Nao afeta a estatistica do nulo
                # (que e a taxa de padding) nem o oraculo semantico, que roda nos dois.
                privs = G.fast_priv_scan(p, f"{bn}/{kn}") if (self.priv and len(p) >= 32) else []
                rec = {"blob": bn, "kdf": kn, "cls": cls, "tag": tag,
                       "pw": pw.decode("latin-1")[:120], "len": len(p),
                       "printable": round(G.printable(p), 3),
                       "ebcdic": round(G.ebcdic_sig(p), 3), "hex": p.hex()}
                if privs: rec["privkey"] = privs
                if G.nested_blob(p): rec["nested"] = True
                duro = G.semantic(p) or bool(privs)
                if duro:
                    self.hard.append(rec); print("### HARD", json.dumps(rec)[:300], flush=True)
                if self.registrar:
                    log({"kind": "hard" if duro else "padding", **rec})
        if self.priv:
            try:
                from coincurve import PublicKey
                s = hashlib.sha256(pw).digest()
                if PublicKey.from_valid_secret(s).format(False) == bytes.fromhex(G.TARGET_PUBKEY_HEX):
                    rec = {"kind": "PRIVKEY", "tag": tag, "priv": s.hex(), "pw": pw.decode("latin-1")[:120]}
                    self.hard.append(rec); log(rec); print("### HARD", rec, flush=True)
            except Exception:
                pass

# --------------------------------------------------------------- material: o transcript
WORD = re.compile(r"[A-Za-z][A-Za-z']*")
def carrega_cena():
    utts = []
    with open(TRANS, encoding="utf-8") as f:
        for l in f:
            l = l.strip().replace("\u2019", "'")
            if not l or l.startswith("#"): continue
            m = re.match(r"(Neo|Architect):\s*(.*)", l)
            if m: utts.append((m.group(1), m.group(2)))
    assert utts and utts[-1][1].startswith("We won't"), utts[-1] if utts else "vazio"
    return utts

def materiais():
    """Todos os recortes 'antes da escolha'. Devolve dict nome -> frase."""
    utts = carrega_cena()
    cena = " ".join(t for _, t in utts)
    arq = " ".join(t for s, t in utts if s == "Architect")
    M = {}
    ws = WORD.findall(cena); low = [w.lower() for w in ws]
    i = low.index("choice")
    # (a) janela deslizante: as N ultimas palavras ANTES de "choice"
    for n in range(1, 31):
        if i - n >= 0: M[f"janela_{n}"] = " ".join(ws[i - n:i])
    # (b) cauda da cena: as N ultimas palavras ate "We won't."
    for n in range(1, 31):
        M[f"cauda_{n}"] = " ".join(ws[len(ws) - n:])
    # (c) recortes nomeados
    def corte(a, b=None, incl=True):
        ia = cena.index(a)
        if b is None: return cena[ia:].strip()
        ib = cena.index(b, ia)
        return cena[ia:ib + (len(b) if incl else 0)].strip()
    M["portas_fala"] = corte("Which brings us at last", "to stop it.")
    M["portas_so"] = corte("There are two doors.", "end of your species.")
    M["hope"] = corte("Hope. It is the quintessential", "greatest weakness.")
    M["wewont"] = "We won't."
    M["neo_ultima"] = corte("If I were you", "meet again.")
    M["antes_choice_frase"] = corte("As you adequately put,", "the problem is")
    M["corte_todo"] = cena[:cena.index("There are two doors")].strip()   # o que o criador cortou
    M["arquiteto_todo"] = arq
    M["cena_toda"] = cena
    # (d) cada sentenca da cena (inclui as do trecho cortado e as das portas)
    for k, s in enumerate(re.split(r"(?<=[.?!])\s+", cena)):
        s = s.strip()
        if len(WORD.findall(s)) >= 3: M[f"sent_{k:02d}"] = s
    return M

# --------------------------------------------------------------- formas e operadores
def formas(p):
    p = p.strip()
    nop = re.sub(r"[^\w\s']", "", p)
    lo, nlo = p.lower(), nop.lower()
    w = nlo.split()
    if not w: return []
    out = {p, lo, nop, nlo,
           nlo.replace(" ", ""), nlo.replace(" ", "").replace("'", ""),
           nlo.upper().replace(" ", ""), nop.replace(" ", ""),
           "".join(x[0] for x in w), "".join(x[0] for x in w).upper(),
           "".join(x[-1] for x in w)}
    return [x for x in out if x]

def operadores(s):
    """(classe, senha) — cada material cru E sha256 hex, mais RAB e o codec z."""
    yield "direto", s
    h = G.shahex(s)
    yield "sha", h
    yield "sha", h.upper()
    yield "sha", G.shahex(h)
    o = [ord(c) - 96 for c in s.lower() if "a" <= c <= "z"]
    if o:
        for v in ("".join(map(str, o)), str(sum(o)), "-".join(map(str, o)), " ".join(map(str, o))):
            yield "rab", v
            yield "rab", G.shahex(v)
    d = [0 if c == "o" else G.A2I[c] for c in s.lower() if c in "abcdefghio"]
    if 0 < len(d) <= 2000:
        try:
            b = G.z_method(d)
            yield "z", b
            yield "z", G.shahex(b)
        except Exception:
            pass
    body = re.sub(r"[^a-z0-9]", "", s.lower())
    if body:
        n = int(body.encode().hex(), 16)
        yield "z", "".join("o" if c == "0" else "abcdefghi"[int(c) - 1] for c in str(n))

COMPOS = ("lastwordsbeforearchichoice", "matrixsumlist", "thispassword", "yinyang")
def composicoes(s):
    for t in COMPOS:
        yield t + s
        yield s + t
    yield "yellowblueprimesmatrixsumlist" + s
    yield "yellowblueprimesmatrixsumlist" + s + "yinyang"
    yield "giveit" + s
    yield s + "enter"

def pipeline(run, M):
    for nome, frase in M.items():
        for f in formas(frase):
            for cls, pw in operadores(f):
                run.tenta(pw, cls, f"{nome}|{f[:40]}")
            for c in composicoes(f):
                run.tenta(c, "comp", f"{nome}|comp")
                run.tenta(G.shahex(c), "comp", f"{nome}|comp")

# --------------------------------------------------------------- controles
def controle_positivo():
    """(1) fase 2 abre com sha256hex('causality') SO sob EVP-SHA256. (2) o PIPELINE INTEIRO
    (frase -> formas -> operadores -> tentativa -> oraculo) encontra esse mesmo alvo plantado."""
    import base64
    raw = base64.b64decode(G.PHASE2_B64)
    bl2 = {"PHASE2": prep(raw[8:16], raw[16:])}
    r = Run(bl2, priv=False, registrar=False)
    pipeline(r, {"ctrl": "Causality."})
    ok = any(h.get("blob") == "PHASE2" and h.get("kdf") == "SHA256"
             and bytes.fromhex(h["hex"]).startswith(b"The ironic") for h in r.hard)
    md5 = any(h.get("blob") == "PHASE2" and h.get("kdf") == "MD5"
              and bytes.fromhex(h["hex"]).startswith(b"The ironic") for h in r.hard)
    return ok, md5, r.pw

def overlap_historico(M):
    """Quantas das minhas formas-base ja estavam na lista R1 de round3_inline.py (a campanha
    historica que mais se sobrepoe a esta)."""
    src = open(os.path.join(KIT, "round3_inline.py"), encoding="utf-8").read()
    m = re.search(r"^R1 = \[(.*?)^\]", src, re.S | re.M)
    if not m: return None
    r1 = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
    velho = set()
    for ph in r1:
        base = ph.strip(); nop = re.sub(r"[^\w\s']", "", base); lo = nop.lower()
        velho |= {base, nop, lo, lo.replace(" ", ""), lo.replace("'", ""),
                  lo.replace("'", "").replace(" ", ""), nop.replace(" ", ""),
                  lo.upper().replace(" ", ""), base.upper()}
    minhas = set()
    for frase in M.values(): minhas |= set(formas(frase))
    return {"r1_frases": len(r1), "minhas_formas": len(minhas),
            "ja_cobertas": len(minhas & velho), "novas": len(minhas - velho)}

# --------------------------------------------------------------- nulo casado
def embaralha(M, rnd):
    """Embaralha a ORDEM DAS PALAVRAS dentro de cada frase: preserva multiconjunto de letras,
    numero de palavras, pontuacao anexada e portanto o tamanho/forma de toda senha derivada."""
    out = {}
    for k, v in M.items():
        toks = v.split(" ")
        rnd.shuffle(toks)
        out[k] = " ".join(toks)
    return out

def main():
    t0 = time.time()
    print("== controle positivo ==", flush=True)
    ok, md5, npw = controle_positivo()
    print(f"  fase 2 via pipeline: SHA256={ok} MD5={md5} (senhas no controle: {npw})", flush=True)
    assert ok and not md5, "CONTROLE POSITIVO FALHOU — nao prosseguir"
    log({"kind": "controle_positivo", "sha256_abre": ok, "md5_abre": md5, "senhas": npw})

    M = materiais()
    ov = overlap_historico(M)
    print(f"  materiais: {len(M)} | overlap R1: {ov}", flush=True)
    log({"kind": "materiais", "n": len(M), "nomes": sorted(M)})
    log({"kind": "overlap", **(ov or {})})

    print("== passe real ==", flush=True)
    real = Run(BL_REAL, priv=True, registrar=True)
    pipeline(real, M)
    tr = {k: v for k, v in real.trials.items()}
    tot_t = sum(v[0] for v in tr.values()); tot_p = sum(v[1] for v in tr.values())
    dt = time.time() - t0
    print(f"  senhas={real.pw} tentativas={tot_t} padding={tot_p} "
          f"taxa={tot_p/max(1,tot_t):.5f} (1/256={1/256:.5f}) hard={len(real.hard)} t={dt:.0f}s", flush=True)

    # Nulo: 100 replicados sobre uma SUBAMOSTRA fixa de materiais (declarada). O pipeline e o
    # mesmo; so o custo cai. Como n por replicado e menor que o do passe real, o sd nulo e maior
    # e o z resultante e conservador.
    NREP, NSUB = 100, 25
    sub = sorted(random.Random(7).sample(sorted(M), min(NSUB, len(M))))
    Msub = {k: M[k] for k in sub}
    real_sub = Run(BL_REAL, priv=False, registrar=False)
    pipeline(real_sub, Msub)
    t_sub = sum(v[0] for v in real_sub.trials.values()); p_sub = sum(v[1] for v in real_sub.trials.values())
    print(f"== nulo casado ({NREP} replicados, subamostra de {len(sub)} materiais, "
          f"{t_sub} tentativas/replicado) ==", flush=True)
    log({"kind": "subamostra_nulo", "materiais": sub, "tentativas": t_sub, "padding": p_sub})
    nulos, nulos_cls = [], {}
    for r in range(NREP):
        rnd = random.Random(1000 + r)
        nr = Run(BL_REAL, priv=False, registrar=False)
        pipeline(nr, embaralha(Msub, rnd))
        t = sum(v[0] for v in nr.trials.values()); p = sum(v[1] for v in nr.trials.values())
        nulos.append(p / max(1, t))
        for k, v in nr.trials.items():
            nulos_cls.setdefault(k, []).append(v[1] / max(1, v[0]))
        if nr.hard:
            log({"kind": "nulo_hard", "rep": r, "n": len(nr.hard)})
        if (r + 1) % 10 == 0:
            print(f"  nulo {r+1}/{NREP} t={time.time()-t0:.0f}s", flush=True)

    def z(obs, amostra):
        mu = sum(amostra) / len(amostra)
        sd = (sum((x - mu) ** 2 for x in amostra) / max(1, len(amostra) - 1)) ** 0.5
        return (obs - mu) / sd if sd > 0 else 0.0, mu, sd

    zg, mu, sd = z(tot_p / max(1, tot_t), nulos)
    zs = z(p_sub / max(1, t_sub), nulos)[0]
    resumo = {"kind": "resumo", "senhas_unicas": real.pw, "tentativas_aes": tot_t,
              "z_subamostra": round(zs, 3), "nulo_subamostra_tentativas": t_sub,
              "padding_valido": tot_p, "taxa_padding": round(tot_p / max(1, tot_t), 6),
              "esperado_1_256": round(1 / 256, 6), "nulo_media": round(mu, 6),
              "nulo_sd": round(sd, 6), "z_global": round(zg, 3),
              "hits_duros": len(real.hard), "replicados_nulos": NREP,
              "segundos": round(time.time() - t0, 1), "por_classe": {}}
    for k in sorted(tr):
        zc, mc, sc = z(tr[k][1] / max(1, tr[k][0]), nulos_cls.get(k, [0.0]))
        resumo["por_classe"][k] = {"tentativas": tr[k][0], "padding": tr[k][1],
                                   "taxa": round(tr[k][1] / max(1, tr[k][0]), 6),
                                   "nulo_media": round(mc, 6), "z": round(zc, 3)}
    log(resumo)
    print(json.dumps(resumo, indent=2, ensure_ascii=False), flush=True)
    print("HITS DUROS:", len(real.hard), flush=True)
    return 0 if not real.hard else 1

if __name__ == "__main__":
    sys.exit(main())
