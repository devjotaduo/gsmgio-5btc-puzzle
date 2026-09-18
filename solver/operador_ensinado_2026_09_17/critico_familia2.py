# -*- coding: utf-8 -*-
"""
CRITICO ADVERSARIAL da familia 2 ("lastwordsbeforearchichoice" literal).

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O negativo reportado pela familia 2 esta certo no que rodou, mas a cobertura declarada tem tres
buracos que o proprio relatorio afirma nao existirem ou descreve errado. Se algum deles esconder a
senha, o negativo da familia e prematuro. Especificamente:

(H1) "O arquivo local so traz o trecho final" e FALSO. `ChatExport_2026-09-08/files/MISC.txt`
     contem a cena do Arquiteto quase inteira: o bloco "The Matrix is older than you know" (com a
     fala de Neo "Choice. The problem is choice."), o paragrafo "Please As I was saying...", o bloco
     "This is about Zion", alem dos 34 fragmentos canonicos ("matrix:") que o puzzle parafraseia.
     Logo, a "janela de N palavras antes de choice" foi calculada na PRIMEIRA ocorrencia de "choice"
     de um recorte arbitrario, e nao nas ocorrencias reais da cena. Testo todas as ocorrencias.

(H2) O "verbatim" testado nao e verbatim. A fonte local usa U+2019 (10x) e U+2013 (8x); o agente
     retypou tudo em ASCII e ainda normaliza U+2019 -> ' no carregador. Como a senha e o sha256 da
     string exata, nenhuma forma com apostrofo/travessao REAL da fonte foi testada. Testo as duas
     grafias.

(H3) `corte_todo` foi descrito como "o texto cortado inteiro"; e apenas o pedaco do bloco final
     antes de "There are two doors". O puzzle corta TRES blocos. Testo os tres, inteiros e por
     sentenca, e tambem as composicoes de duas falas consecutivas entre si (declaradas fora).

FALSIFICACAO: se nenhum material do transcript COMPLETO (nas duas grafias, em todas as janelas
antes de cada "choice", nos tres blocos cortados e nas composicoes par-a-par) abre SMALL/TAIL32/
COSMIC com plaintext semantico (oraculo duro de gsmg_common) nem produz a privkey do premio, e a
taxa de padding for indistinguivel do nulo casado, entao a familia 2 esta fechada de verdade — e o
negativo dele passa a valer com a cobertura CORRIGIDA aqui, nao com a que ele declarou.

Alem disso: (1) reproduzo a contagem de cobertura dele executando as proprias funcoes dele;
(2) re-varro os 553 plaintexts com padding valido do log dele com o oraculo completo, incluindo
fast_priv_scan em toda janela de 32 B nas DUAS ordens de byte (o kit so varre a ordem direta).
"""
import sys, os, re, json, time, random, hashlib

KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from Crypto.Util.strxor import strxor
from coincurve import PublicKey
sys.set_int_max_str_digits(0)

RAIZ = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
MISC = os.path.join(RAIZ, "ChatExport_2026-09-08", "files", "MISC.txt")
LOG_AGENTE = os.path.join(RAIZ, "_work", "operador_ensinado_2026-09-17",
                          "familia2_lastwords", "run.jsonl")
SRC_AGENTE = os.path.join(RAIZ, "solver", "operador_ensinado_2026_09_17", "familia2_lastwords.py")
OUT = os.path.join(RAIZ, "_work", "operador_ensinado_2026-09-17", "critico_familia2")
os.makedirs(OUT, exist_ok=True)
LOG = os.path.join(OUT, "run.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)

TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)
HMS = (("SHA256", SHA256), ("MD5", MD5))
def prep(salt, ct): return (salt, ct, ct[-32:-16], ct[-16:])
BL_REAL = {n: prep(*G.BLOBS[n]) for n in ("SMALL", "TAIL32", "COSMIC")}
def pad_ok(b16):
    p = b16[-1]
    return 1 <= p <= 16 and b16[-p:] == bytes([p]) * p

# ===================================================================== 1. REPRODUZIR A COBERTURA
def carrega_modulo_do_agente():
    """Executa o fonte do agente com o diretorio de saida redirecionado para o MEU, para nao
    truncar o log dele (o modulo dele faz open(LOG,'w') no nivel do modulo)."""
    src = open(SRC_AGENTE, encoding="utf-8").read()
    src = src.replace('"familia2_lastwords")', '"critico_familia2", "_repro")')
    src = src.replace('if __name__ == "__main__":\n    sys.exit(main())', '')
    ns = {"__name__": "familia2_repro"}
    exec(compile(src, SRC_AGENTE, "exec"), ns)
    return ns

def reproduz_cobertura():
    ns = carrega_modulo_do_agente()
    M = ns["materiais"](); f_formas = ns["formas"]; f_ops = ns["operadores"]
    f_comp = ns["composicoes"]
    base = set()
    for f in M.values(): base |= set(f_formas(f))
    pws, por_cls = set(), {}
    for frase in M.values():
        for f in f_formas(frase):
            for cls, pw in f_ops(f):
                b = pw.encode("utf-8", "surrogateescape") if isinstance(pw, str) else pw
                if b and b not in pws:
                    pws.add(b); por_cls[cls] = por_cls.get(cls, 0) + 1
            for c in f_comp(f):
                for pw in (c, G.shahex(c)):
                    b = pw.encode()
                    if b and b not in pws:
                        pws.add(b); por_cls["comp"] = por_cls.get("comp", 0) + 1
    return {"materiais": len(M), "formas_base": len(base), "senhas_unicas": len(pws),
            "aes_esperado": len(pws) * 6, "por_classe": por_cls}, M

# ===================================================================== 2. RE-VARREDURA DO LOG DELE
def revarre_log():
    tot = nest = ebc = sem = privs = wins = 0
    maxp = maxe = 0.0
    for l in open(LOG_AGENTE, encoding="utf-8"):
        o = json.loads(l)
        if "hex" not in o: continue
        p = bytes.fromhex(o["hex"]); tot += 1
        maxp = max(maxp, G.printable(p)); maxe = max(maxe, G.ebcdic_sig(p))
        if G.nested_blob(p): nest += 1
        if G.ebcdic_sig(p) >= 0.75: ebc += 1
        if G.semantic(p): sem += 1
        for buf in (p, p[::-1]):            # AS DUAS ORDENS DE BYTE (o kit so faz a direta)
            for j in range(0, max(0, len(buf) - 31)):
                wins += 1
                try:
                    if PublicKey.from_valid_secret(buf[j:j + 32]).format(False) == TGT:
                        privs += 1
                        log({"kind": "PRIVKEY_RETRO", "rec": o})
                except Exception:
                    pass
    return {"plaintexts": tot, "janelas32_2ordens": wins, "semantic": sem,
            "nested": nest, "ebcdic_ge_075": ebc, "privkeys": privs,
            "max_printable": round(maxp, 3), "max_ebcdic": round(maxe, 3)}

# ===================================================================== 3. TRANSCRIPT COMPLETO
FALA = re.compile(r"^\s*(Neo|Architect|TV Neos)\s*:\s*(.+)$")
def cena_completa():
    """Reconstroi a cena do Arquiteto a partir do MISC.txt local, na ordem do arquivo:
    falas dos blocos '*skipped in puzzle*' + os 34 fragmentos canonicos 'matrix:'."""
    falas = []
    for l in open(MISC, encoding="utf-8"):
        l = l.rstrip("\n")
        m = FALA.match(l)
        if m:
            falas.append((m.group(1).strip(), m.group(2).strip())); continue
        m = re.match(r"^(?:\d+: )?matrix:\s*(.*)$", l.strip())
        if m and m.group(1).strip() and not m.group(1).startswith("*"):
            falas.append(("canon", m.group(1).strip()))
    return falas

def materiais_completos():
    falas = cena_completa()
    cena = " ".join(t for _, t in falas)
    ascii_cena = cena.replace("\u2019", "'").replace("\u2013", "-")
    M = {}
    for tag, texto in (("u", cena), ("a", ascii_cena)):
        ws = re.findall(r"[A-Za-z][A-Za-z'\u2019]*", texto)
        low = [w.lower().replace("\u2019", "'") for w in ws]
        for oc, i in enumerate([k for k, w in enumerate(low) if w == "choice"]):
            for n in (1, 2, 3, 5, 7, 8, 10, 12, 15, 16, 20, 23, 25, 30):
                if i - n >= 0: M["%s_jan%d_%d" % (tag, oc, n)] = " ".join(ws[i - n:i])
            M["%s_ate_choice%d" % (tag, oc)] = " ".join(ws[:i + 1])
        for nome, ini, fim in (
            ("bloco1", "The Matrix is older than you know", "The Oracle."),
            ("bloco2", "This is about Zion.", "existence eradicated."),
            ("bloco3", "You won", "meet again."),
        ):
            try:
                ia = texto.index(ini); ib = texto.index(fim, ia) + len(fim)
                M["%s_%s" % (tag, nome)] = texto[ia:ib].strip()
            except ValueError:
                pass
        M[tag + "_cena_toda"] = texto
        M[tag + "_arquiteto"] = " ".join(t for s, t in falas if s == "Architect")
        M[tag + "_neo"] = " ".join(t for s, t in falas if s in ("Neo", "TV Neos"))
        M[tag + "_canon"] = " ".join(t for s, t in falas if s == "canon")
        for k, s in enumerate(re.split(r"(?<=[.?!])\s+", texto)):
            s = s.strip()
            if len(re.findall(r"[A-Za-z]+", s)) >= 3: M["%s_sent%02d" % (tag, k)] = s
        seq = [t for _, t in falas]
        for k in range(len(seq) - 1):
            M["%s_par%02d" % (tag, k)] = (seq[k] + " " + seq[k + 1]).strip()
    return M

# ===================================================================== formas / operadores
def formas(p):
    p = p.strip()
    nop = re.sub(r"[^\w\s']", "", p, flags=re.U)
    lo, nlo = p.lower(), nop.lower()
    w = nlo.split()
    if not w: return []
    out = {p, lo, nop, nlo, nlo.replace(" ", ""),
           nlo.replace(" ", "").replace("'", "").replace("\u2019", ""),
           nlo.upper().replace(" ", ""), nop.replace(" ", ""), p.upper(),
           "".join(x[0] for x in w), "".join(x[0] for x in w).upper(),
           "".join(x[-1] for x in w)}
    return [x for x in out if x]

def operadores(s):
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
            b = G.z_method(d); yield "z", b; yield "z", G.shahex(b)
        except Exception:
            pass

COMPOS = ("lastwordsbeforearchichoice", "matrixsumlist", "thispassword", "yinyang")
def composicoes(s):
    for t in COMPOS:
        yield t + s
        yield s + t
    yield "yellowblueprimesmatrixsumlist" + s
    yield "giveit" + s
    yield s + "enter"

class Run:
    def __init__(self, bl, priv=True, registrar=True):
        self.bl, self.priv, self.registrar = bl, priv, registrar
        self.seen = set(); self.trials = {}; self.pw = 0; self.hard = []
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
                if not pad_ok(strxor(AES.new(k, AES.MODE_ECB).decrypt(clast), cprev)): continue
                self.conta(cls, 1, 0)
                p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
                if p is None: continue
                privs = []
                if self.priv and len(p) >= 32:
                    for buf in (p, p[::-1]):
                        privs += G.fast_priv_scan(buf, "%s/%s" % (bn, kn))
                rec = {"blob": bn, "kdf": kn, "cls": cls, "tag": tag,
                       "pw": pw.decode("latin-1")[:120], "len": len(p),
                       "printable": round(G.printable(p), 3),
                       "ebcdic": round(G.ebcdic_sig(p), 3), "hex": p.hex()}
                if privs: rec["privkey"] = privs
                if G.nested_blob(p): rec["nested"] = True
                duro = G.semantic(p) or bool(privs)
                if duro:
                    self.hard.append(rec); print("### HARD", json.dumps(rec)[:300], flush=True)
                if self.registrar: log({"kind": "hard" if duro else "padding", **rec})
        if self.priv:
            s = hashlib.sha256(pw).digest()
            try:
                if PublicKey.from_valid_secret(s).format(False) == TGT:
                    rec = {"kind": "PRIVKEY", "tag": tag, "priv": s.hex()}
                    self.hard.append(rec); log(rec); print("### HARD", rec, flush=True)
            except Exception:
                pass

def pipeline(run, M):
    for nome, frase in M.items():
        for f in formas(frase):
            for cls, pw in operadores(f):
                run.tenta(pw, cls, "%s|%s" % (nome, f[:30]))
            for c in composicoes(f):
                run.tenta(c, "comp", nome + "|comp")
                run.tenta(G.shahex(c), "comp", nome + "|comp")

def controle_positivo():
    import base64
    raw = base64.b64decode(G.PHASE2_B64)
    r = Run({"PHASE2": prep(raw[8:16], raw[16:])}, priv=False, registrar=False)
    pipeline(r, {"ctrl": "Causality."})
    ok = any(h.get("kdf") == "SHA256" and bytes.fromhex(h["hex"]).startswith(b"The ironic") for h in r.hard)
    md5 = any(h.get("kdf") == "MD5" and bytes.fromhex(h["hex"]).startswith(b"The ironic") for h in r.hard)
    return ok, md5, r.pw

def embaralha(M, rnd):
    out = {}
    for k, v in M.items():
        t = v.split(" "); rnd.shuffle(t); out[k] = " ".join(t)
    return out

def z(obs, am):
    mu = sum(am) / len(am)
    sd = (sum((x - mu) ** 2 for x in am) / max(1, len(am) - 1)) ** 0.5
    return ((obs - mu) / sd if sd > 0 else 0.0), mu, sd

def main():
    t0 = time.time()
    ok, md5, npw = controle_positivo()
    print("[controle] fase2 SHA256=%s MD5=%s senhas=%d" % (ok, md5, npw), flush=True)
    assert ok and not md5, "CONTROLE POSITIVO FALHOU"
    log({"kind": "controle_positivo", "sha256": ok, "md5": md5, "senhas": npw})

    print("[1] reproduzindo a cobertura declarada pelo agente...", flush=True)
    rep, M_ag = reproduz_cobertura()
    print("   ", json.dumps(rep), flush=True)
    log({"kind": "reproducao_cobertura", **rep})

    print("[2] re-varrendo os plaintexts do log dele (oraculo completo, 2 ordens)...", flush=True)
    rv = revarre_log()
    print("   ", json.dumps(rv), flush=True)
    log({"kind": "revarredura", **rv})

    print("[3] extensao: transcript COMPLETO (H1/H2/H3)...", flush=True)
    M = materiais_completos()
    base = set()
    for f in M.values(): base |= set(formas(f))
    dele = set()
    for f in M_ag.values(): dele |= set(formas(f))
    print("    materiais=%d formas_base=%d ineditas_vs_agente=%d"
          % (len(M), len(base), len(base - dele)), flush=True)
    log({"kind": "materiais", "n": len(M), "formas_base": len(base),
         "ineditas_vs_agente": len(base - dele), "nomes": sorted(M)})

    real = Run(BL_REAL, priv=True, registrar=True)
    pipeline(real, M)
    tt = sum(v[0] for v in real.trials.values()); tp = sum(v[1] for v in real.trials.values())
    print("    senhas=%d aes=%d padding=%d taxa=%.5f hard=%d t=%.0fs"
          % (real.pw, tt, tp, tp / max(1, tt), len(real.hard), time.time() - t0), flush=True)

    print("[4] nulo casado (100 replicados)...", flush=True)
    NREP, NSUB = 100, 30
    sub = sorted(random.Random(7).sample(sorted(M), min(NSUB, len(M))))
    Msub = {k: M[k] for k in sub}
    rs = Run(BL_REAL, priv=False, registrar=False); pipeline(rs, Msub)
    ts = sum(v[0] for v in rs.trials.values()); ps = sum(v[1] for v in rs.trials.values())
    nulos, ncls, nhard = [], {}, 0
    for r in range(NREP):
        nr = Run(BL_REAL, priv=False, registrar=False)
        pipeline(nr, embaralha(Msub, random.Random(2000 + r)))
        t = sum(v[0] for v in nr.trials.values()); p = sum(v[1] for v in nr.trials.values())
        nulos.append(p / max(1, t)); nhard += len(nr.hard)
        for k, v in nr.trials.items(): ncls.setdefault(k, []).append(v[1] / max(1, v[0]))
        if (r + 1) % 20 == 0:
            print("    nulo %d/%d t=%.0fs" % (r + 1, NREP, time.time() - t0), flush=True)

    zg, mu, sd = z(tp / max(1, tt), nulos)
    res = {"kind": "resumo", "senhas_unicas": real.pw, "tentativas_aes": tt,
           "padding_valido": tp, "taxa_padding": round(tp / max(1, tt), 6),
           "esperado_1_256": round(1 / 256, 6), "nulo_media": round(mu, 6),
           "nulo_sd": round(sd, 6), "z_global": round(zg, 3),
           "z_subamostra": round(z(ps / max(1, ts), nulos)[0], 3),
           "nulo_tentativas_por_rep": ts, "replicados": NREP, "nulo_hard": nhard,
           "hits_duros": len(real.hard), "segundos": round(time.time() - t0, 1),
           "por_classe": {}}
    for k in sorted(real.trials):
        a, b = real.trials[k]
        zc, mc, _ = z(b / max(1, a), ncls.get(k, [0.0]))
        res["por_classe"][k] = {"aes": a, "padding": b, "taxa": round(b / max(1, a), 6),
                                "nulo_media": round(mc, 6), "z": round(zc, 3)}
    log(res); print(json.dumps(res, indent=2), flush=True)
    print("HITS DUROS:", len(real.hard), flush=True)
    return 0 if not real.hard else 1

if __name__ == "__main__":
    sys.exit(main())
