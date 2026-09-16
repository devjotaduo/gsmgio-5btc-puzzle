"""phase2_leftovers (rodada 3) — RESOLUCAO da tabela "# X 2 S H 4 Y 0 Q B 15 #" e teste do que ela produz.

RESOLUCAO (fontes: Telegram GSMG Puzzle Solvers, msgs 17210/17232-17239/15514/9525/7859):
  Q = 82. "a hackers' swordless fish" = o peixe do hacker chamado QWERTY (Mr. Robot — o peixe de
      Darlene; o eps3.4 e' citado no paragrafo imediatamente acima da tabela) + "swordless" =
      Swordfish (filme de hackers) sem "sword" = fish. "extend the name" = QWERTY -> QWERTYUIOP.
      "the I and W are below": sob QWERTYUIOP escreve-se 1234567890; abaixo de I esta 8 e abaixo
      de W esta 2 -> lendo "I e W" nessa ordem: 82.
  B = 25 (leitura de rebus: BV80605001911AP = Intel Core i5; "i5" menos "i" = 5; 5^2 = 25).
      A leitura algebrica (5i-i)^2 = -16 nao fecha as coordenadas.
  H = 42 (Hitchhiker's) * -1 lido como "negar/inverter", nao como sinal.
  S = 32 (Klingon cha' + vagh*jav = 2 + 5*6).
  X e Y = N e E. "Ok kid, on the highway, let put it in the worst gear" = marcha re' = INVERTER a
      string: "X232424Y0822515" invertida = "5152280Y424232X" -> 51 52 28.0 N | 4 24 23.2 E =
      51deg52'28.0"N 4deg24'23.2"E = SafeNet Technologies B.V., Columbusstraat 25, 3165 AC
      Rotterdam-Albrandswaard (NL). Ou seja: a tabela EXISTE para confirmar "Safenet" (e nao
      "Thales") como a 2a parte da senha da fase 3 — ela ja' foi consumida pela fase 3.

HIPOTESE (falsificavel, espaco finito): se a tabela nao for so' confirmacao, o material NOVO que ela
produz — as coordenadas em todas as formas de escrita, o endereco/nome da SafeNet, a sequencia com os
valores CORRETOS (Q=82, B=25, X/Y = N/E, ordem invertida) e os numeros como bytes/nibbles/privkey —
e' senha (crua ou sha256, sozinha ou como 8a parte da gramatica das 7 partes da fase 3) que abre
SMALL/COSMIC/TAIL32 sob EVP-SHA256, ou e' a privkey do endereco-premio.
NOVO vs rodada 2: la' Q so' assumiu {2,3,82,...} com B fixo em +-16 e X,Y numericos — a combinacao
correta (B=25 com X=N,Y=E) e TODA a familia coordenadas/endereco nunca foram testadas.
Oraculo duro: G.semantic em saida AES / G.priv_hit / G.fast_priv_scan. Textual: G.semantic_text.
"""
import sys, itertools, time, json, re, base64
SP = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, SP)
import gsmg_common as G

LOG = SP + r"\phase2_leftovers_r3.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"family": "phase2_leftovers_r3", "hypothesis": __doc__.strip()})

N = 0; HARD = []; SOFT = []; BEST = {"score": -99, "text": "", "how": ""}
PW7 = ("causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"
       "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1")
assert G.shahex(PW7) == "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
PW7_W = PW7.replace("/2R5/", "/6R1/").replace(" b - - 0 1", " w - - 0 1")
# as 7 partes separadas (para inserir uma 8a parte em qualquer posicao)
PARTS = ["causality", "Safenet", "Luna", "HSM", "11110",
         "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
         "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"]
assert "".join(PARTS) == PW7

# ------------------------------------------------------------------ oraculos
def test_pw(pw, how, blobs=("SMALL", "COSMIC", "TAIL32"), kdf="sha256", priv=True):
    """Senha nos blobs (EVP-SHA256 por padrao) + sha256(pw) como privkey."""
    global N
    for b in blobs:
        N += (2 if kdf == "both" else 1)
        for k, p in G.aes_try(pw, b, kdf=kdf):
            rec = {"blob": b, "kdf": k, "pw": (pw if isinstance(pw, str) else pw.hex())[:120],
                   "how": how, "len": len(p), "printable": round(G.printable(p), 3)}
            if G.semantic(p):
                rec["plaintext_hex"] = p.hex(); HARD.append(rec); G.jsonl(LOG, {"HARD": rec})
            else:
                rec["head"] = p[:32].decode("latin-1"); SOFT.append(rec); G.jsonl(LOG, {"soft": rec})
    if priv:
        N += 1
        if G.priv_hit(G.sha(pw)):
            rec = {"priv_of_sha256": pw if isinstance(pw, str) else pw.hex(), "how": how}
            HARD.append(rec); G.jsonl(LOG, {"HARD": rec})

def note_best(text, how):
    s = G.english_score(text)
    if s > BEST["score"]: BEST.update(score=round(s, 3), text=text[:80], how=how)
    if G.semantic_text(text):
        rec = {"how": how, "score": round(s, 3), "text": text[:120], "words": G.word_hits(text, 6)[:8]}
        SOFT.append(rec); G.jsonl(LOG, {"soft_text": rec})

def forms(p):
    alnum = re.sub(r"[^A-Za-z0-9]", "", p)
    f = [p, p.replace(" ", ""), p.lower(), p.upper(), p.lower().replace(" ", ""),
         p.upper().replace(" ", ""), alnum, alnum.lower(), alnum.upper()]
    out = []
    for x in f:
        if x and x not in out: out.append(x)
    return out

# ------------------------------------------------------------------ controles positivos
raw2 = base64.b64decode(G.PHASE2_B64); G.BLOBS["PHASE2"] = (raw2[8:16], raw2[16:])
h0 = len(HARD); n0 = N
test_pw(G.shahex("causality"), "controle-fase2", blobs=("PHASE2",))
assert len(HARD) == h0 + 1 and HARD[-1]["blob"] == "PHASE2", "controle positivo FALHOU"
HARD.pop(); N = n0
raw3 = base64.b64decode(G.PHASE3_B64); G.BLOBS["PHASE3"] = (raw3[8:16], raw3[16:])
h0 = len(HARD); n0 = N
test_pw(G.shahex(PW7), "controle-fase3(7 partes)", blobs=("PHASE3",))
assert len(HARD) == h0 + 1, "controle das 7 partes FALHOU"
HARD.pop(); N = n0
G.jsonl(LOG, {"controls": "fase2 e fase3 abrem via test_pw sob EVP-SHA256; gramatica das 7 partes verificada"})

# ------------------------------------------------------------------ (1) coordenadas + endereco
LAT_D, LAT_M, LAT_S = 51, 52, "28.0"
LON_D, LON_M, LON_S = 4, 24, "23.2"
COORD = []
for n_, e_ in (("N", "E"), ("n", "e")):
    COORD += [
        f"51\u00b052'28.0\"{n_} 4\u00b024'23.2\"{e_}",
        f"51\u00b052'28.0\"{n_}4\u00b024'23.2\"{e_}",
        f"51 52 28.0 {n_} 4 24 23.2 {e_}",
        f"515228.0{n_}42423.2{e_}",
        f"5152280{n_}424232{e_}",
        f"51 52 28 0 {n_} 4 24 23 2 {e_}",
        f"51522804{n_}424232{e_}",
        f"{n_}5152280{e_}424232",
        f"{n_} 51 52 28.0 {e_} 4 24 23.2",
        f"4\u00b024'23.2\"{e_} 51\u00b052'28.0\"{n_}",
        f"4 24 23.2 {e_} 51 52 28.0 {n_}",
        f"424232{e_}5152280{n_}",
    ]
COORD += [
    "51.874444,4.406444", "51.874444, 4.406444", "51.874444 4.406444", "51.8744444.406444",
    "51.8744444406444", "518744444406444", "51.87444,4.40644", "51.8744,4.4064",
    "4.406444,51.874444", "51874444406444", "51.874444N4.406444E", "51.874444,4.406444,17z",
    "5152280424232", "515228042423 2", "5152 2804 2423 2",
]
ADDR = ["Columbusstraat 25", "Columbusstraat25", "Columbusstraat 25 3165 AC Rotterdam",
        "3165 AC", "3165AC", "Rotterdam", "Albrandswaard", "Rotterdam-Albrandswaard", "Poortugaal",
        "Safenet Technologies B.V.", "SafenetTechnologiesBV", "Safenet Technologies",
        "SafenetTechnologies", "Safenet B.V.", "SafenetBV", "Geodis", "Thales DIS", "ThalesDIS",
        "Thales DIS Technologies B.V.", "Netherlands", "Nederland", "Holland"]
QWERTY = ["Qwerty", "qwerty", "QWERTY", "Qwertyuiop", "qwertyuiop", "QWERTYUIOP",
          "Darlene", "darlene", "DarleneAlderson", "Qwerty the fish", "qwertythefish",
          "Swordfish", "swordfish", "fish", "Fish", "82", "8 2", "IW", "iw", "WI",
          "Qwerty82", "qwerty82", "82Qwerty", "QWERTYUIOP1234567890", "1234567890",
          # "the I and W are below" lido como shift de teclado (linha abaixo: I->K, W->S)
          "KS", "SK", "ks", "sk", "qsertyukop", "QSERTYUKOP", "Qserty", "QSERTY"]

t0 = time.time()
for group, items in (("coord", COORD), ("addr", ADDR), ("qwerty", QWERTY)):
    for c in items:
        for f in forms(c):
            test_pw(f, f"{group} raw")
            test_pw(G.shahex(f), f"{group} sha256")
            test_pw(G.shahex(PW7 + f), f"{group} sha256(PW7+c)")
            test_pw(G.shahex(f + PW7), f"{group} sha256(c+PW7)")
            test_pw(G.shahex(PW7_W + f), f"{group} sha256(PW7w+c)")
        for h in G.phrase_priv(c): HARD.append({"brainwallet": c, "r": str(h)}); G.jsonl(LOG, {"HARD": {"brainwallet": c}})
        N += 36
G.jsonl(LOG, {"stage": "1_coord_addr_qwerty", "n": N, "sec": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ (2) 8a parte em toda posicao
t0 = time.time()
EIGHTH = [c for c in COORD[:24]] + ["51.874444,4.406444", "5152280N424232E", "5152280E424232N",
                                    "N2324240822515", "E232424N0822515", "82", "25", "Qwerty",
                                    "Columbusstraat 25", "Safenet Technologies B.V."]
for c in EIGHTH:
    for pos in range(8):
        p = PARTS[:pos] + [c] + PARTS[pos:]
        test_pw(G.shahex("".join(p)), f"8a parte pos={pos} c={c[:40]}")
G.jsonl(LOG, {"stage": "2_eighth_part", "cands": len(EIGHTH), "n": N, "sec": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ (3) sequencia com valores corretos
t0 = time.time()
SEQ = []
for x, y in (("N", "E"), ("E", "N"), ("n", "e"), ("e", "n"), ("", ""), ("14", "5"), ("24", "5")):
    for q in (82, 28, 2, 3, 94):
        for b in (25, -16, 16):
            for h in (42, -42):
                vals = [x, 2, 32, h, 4, y, 0, q, b, 15]
                for order in ("fwd", "rev_items", "rev_chars"):
                    for sep in ("", " "):
                        s = sep.join(str(v) for v in vals if str(v) != "")
                        if order == "rev_items":
                            s = sep.join(str(v) for v in reversed(vals) if str(v) != "")
                        elif order == "rev_chars":
                            s = s[::-1]
                        for wrap in ("", "hash"):
                            SEQ.append((f"# {s} #" if wrap else s,
                                        dict(x=x, y=y, q=q, b=b, h=h, order=order, sep=sep, wrap=wrap)))
seen = set(); SEQ = [(s, m) for s, m in SEQ if not (s in seen or seen.add(s))]
for s, meta in SEQ:
    m = f"seq {meta['order']}/{meta['q']}/{meta['b']}/{meta['h']}/{meta['x']}{meta['y']}"
    test_pw(s, m + " raw")
    test_pw(G.shahex(s), m + " sha256")
    test_pw(G.shahex(PW7 + s), m + " sha256(PW7+s)")
G.jsonl(LOG, {"stage": "3_seq_correct_values", "seqs": len(SEQ), "n": N, "sec": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ (4) numeros como bytes/nibbles/privkey
t0 = time.time()
NUMSETS = {
    "correct": [51, 52, 28, 0, 4, 24, 23, 2],
    "table82_25": [2, 32, 42, 4, 0, 82, 25, 15],
    "table82_25_neg": [2, 32, -42, 4, 0, 82, -16, 15],
    "rev": [15, 25, 82, 0, 4, 42, 32, 2],
    "coord_all": [51, 52, 28, 0, 78, 4, 24, 23, 2, 69],       # N=78, E=69 (ASCII)
    "coord_ne": [51, 52, 28, 0, 14, 4, 24, 23, 2, 5],          # N=14, E=5 (a1z26)
}
nb = 0
for name, nums in NUMSETS.items():
    bs = bytes((v % 256) for v in nums)
    variants = {
        "bytes": bs,
        "bytes_rev": bs[::-1],
        "nibbles": bytes.fromhex("".join(f"{v % 16:x}" for v in nums) + ("" if len(nums) % 2 == 0 else "0")),
        "decstr": "".join(str(v) for v in nums).encode(),
        "hexstr": "".join(f"{v % 256:02x}" for v in nums).encode(),
    }
    for vn, v in variants.items():
        nb += 1
        # como privkey: repetir/padear ate 32B, e sha256
        for pad_name, k in (("padL", (b"\x00" * 32 + v)[-32:]), ("padR", (v + b"\x00" * 32)[:32]),
                            ("rep", (v * 32)[:32]), ("sha", G.sha(v))):
            N += 1
            if G.priv_hit(k):
                rec = {"priv": k.hex(), "how": f"{name}/{vn}/{pad_name}"}; HARD.append(rec); G.jsonl(LOG, {"HARD": rec})
        test_pw(v, f"nums {name}/{vn} raw")
        test_pw(G.shahex(v), f"nums {name}/{vn} sha256")
G.jsonl(LOG, {"stage": "4_bytes_nibbles", "variants": nb, "n": N, "sec": round(time.time() - t0, 1)})

# ------------------------------------------------------------------ (5) tabela como larguras/chave de transposicao
# leitura NOVA: os 10 numeros como chave de colunas (rank) sobre faed/dbbi; larguras 10/15/38.
t0 = time.time()
def colkey_transpose(txt, key, inverse=False):
    w = len(key)
    order = sorted(range(w), key=lambda i: (key[i], i))
    cols = [txt[i::w] for i in range(w)]
    if inverse:
        out = [""] * w
        for pos, i in enumerate(order): out[i] = cols[pos]
        cols = out
    else:
        cols = [cols[i] for i in order]
    return "".join(cols)
KEYS = {"correct10": [51, 52, 28, 0, 78, 4, 24, 23, 2, 69],
        "tab10": [14, 2, 32, 42, 4, 5, 0, 82, 25, 15],
        "tab10neg": [14, 2, 32, -42, 4, 5, 0, 82, -16, 15],
        "rev10": [15, 25, 82, 0, 5, 4, 42, 32, 2, 14],
        "coord8": [51, 52, 28, 0, 4, 24, 23, 2]}
nt = 0
for tname, txt in (("faed", G.FAED), ("dbbi", G.DBBI)):
    for kname, key in KEYS.items():
        for inv in (False, True):
            out = colkey_transpose(txt, key, inv); nt += 1; N += 1
            # leituras: z-method dos digitos, Bifid canonico, checkerboard 3.2.2-style
            try:
                z = G.z_method(G.digits(out)); N += 1
                if G.semantic(z):
                    rec = {"how": f"transp {tname}/{kname}/inv={inv} z", "hex": z.hex()[:200]}
                    HARD.append(rec); G.jsonl(LOG, {"HARD_z": rec})
                for h in G.fast_priv_scan(z, f"transp {tname}/{kname}"):
                    HARD.append({"priv": str(h)}); G.jsonl(LOG, {"HARD_priv": str(h)})
            except Exception:
                pass
            bf = G.bifid(out, G.CANON, len(out)); N += 1
            note_best(bf, f"transp {tname}/{kname}/inv={inv} bifid")
            for esc in ((1, 4), (2, 4), (8, 2), (4, 2)):
                cb = G.checkerboard_decode(G.digits(out), G.CANON, esc); N += 1
                note_best(cb, f"transp {tname}/{kname}/inv={inv} cb{esc}")
G.jsonl(LOG, {"stage": "5_transposition", "transposes": nt, "n": N, "sec": round(time.time() - t0, 1), "best": BEST})

# ------------------------------------------------------------------ (6) MD5 backstop no conjunto principal
t0 = time.time()
for c in COORD + ["5152280N424232E", "N2324240822515", "Qwerty", "qwertyuiop", "Columbusstraat 25"]:
    for f in (c, re.sub(r"[^A-Za-z0-9]", "", c)):
        test_pw(f, "md5-backstop raw", kdf="md5", priv=False)
        test_pw(G.shahex(f), "md5-backstop sha256", kdf="md5", priv=False)
        test_pw(G.shahex(PW7 + f), "md5-backstop 8a", kdf="md5", priv=False)
G.jsonl(LOG, {"stage": "6_md5_backstop", "n": N, "sec": round(time.time() - t0, 1)})

summary = {"n_tests": N, "hard": len(HARD), "soft": len(SOFT), "best": BEST,
           "soft_pad": [s for s in SOFT if "blob" in s][:25],
           "soft_text": [s for s in SOFT if "blob" not in s][:15]}
G.jsonl(LOG, {"summary": summary})
print(json.dumps(summary, ensure_ascii=False, indent=1)[:7000])

# ================================================================== ETAPA 7 (extensao)
# (7a) linhas literais do plaintext da fase 2 (inclusive a tabela) como senha/brainwallet
t0 = time.time()
P2 = bytes.fromhex([json.loads(l) for l in open(LOG, encoding="utf-8")
                    if '"controle-fase2"' in l][0]["HARD"]["plaintext_hex"]).decode("latin-1")
LINES = [l.strip() for l in P2.replace("\r\n", "\n").split("\n") if l.strip()]
TXTS = LINES + [P2, P2.strip(), P2.replace("\r\n", "\n"), P2.replace("\r\n", ""),
                "".join(LINES), " ".join(LINES), LINES[1] if len(LINES) > 1 else ""]
TXTS += [re.sub(r"[^A-Za-z0-9]", "", t) for t in LINES]
TXTS = [t for t in dict.fromkeys(TXTS) if t]
for t in TXTS:
    test_pw(t, "p2line raw")
    test_pw(G.shahex(t), "p2line sha256")
    test_pw(G.shahex(PW7 + t), "p2line 8a(PW7+t)")
    for h in G.phrase_priv(t[:200]): HARD.append({"brainwallet_line": t[:60]}); G.jsonl(LOG, {"HARD": {"bw_line": t[:60]}})
    N += 36
G.jsonl(LOG, {"stage": "7a_phase2_lines", "lines": len(TXTS), "n": N, "sec": round(time.time() - t0, 1)})

# (7b) alfabetos keyed NOVOS (qwerty/coordenadas/endereco) em checkerboard e Bifid sobre dbbi/faed
t0 = time.time()
KEYPHRASES = ["QWERTY", "QWERTYUIOP", "QWERTYUIOPASDFGHJKLZXCVBNM", "MNBVCXZLKJHGFDSAPOIUYTREWQ",
              "COLUMBUSSTRAAT", "ROTTERDAM", "ALBRANDSWAARD", "SAFENETTECHNOLOGIES", "POORTUGAAL",
              "DARLENE", "SWORDFISH", "QWERTYFISH", "FIFTYONEFIFTYTWO", "NORTHEAST", "WORSTGEAR",
              "HIGHWAY", "OKKID", "HITCHHIKER", "KLINGON", "GEODIS"]
ALPHAS = {}
for p in KEYPHRASES:
    ALPHAS[p] = G.keyed_alphabet(p); ALPHAS[p + "@rev"] = G.keyed_alphabet(p)[::-1]
ESC = [(8, 2), (2, 8), (2, 5), (5, 1), (1, 5), (5, 2), (1, 4), (2, 4), (4, 2), (1, 2), (4, 5), (8, 5)]
TEXTS = {"dbbi": G.DBBI, "faed": G.FAED, "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:],
         "dbbi_rev": G.DBBI[::-1], "faed_rev": G.FAED[::-1]}
n7 = 0
for aname, alpha in ALPHAS.items():
    for tname, txt in TEXTS.items():
        digs = G.digits(txt)
        for e in ESC:
            out = G.checkerboard_decode(digs, alpha, e); n7 += 1; N += 1
            if len(out) > 20: note_best(out, f"cb7 {aname} {tname} esc={e}")
        for per in (0, 2, 4, 15, 25, 28, 32, 42, 51, 52, 82, 285, 570):
            if per and per > len(txt): continue
            out = G.bifid(txt, alpha, per or len(txt)); n7 += 1; N += 1
            note_best(out, f"bifid7 {aname} {tname} per={per}")
G.jsonl(LOG, {"stage": "7b_qwerty_alphabets", "decodes": n7, "n": N, "sec": round(time.time() - t0, 1), "best": BEST})

# (7c) keystream com a lista CORRETA (Q=82,B=25,X/Y=N,E) mod 9/10, fwd/rev, +/- -> z-method/priv
t0 = time.time()
KS = {"tab_correct": [14, 2, 32, 42, 4, 5, 0, 82, 25, 15],
      "tab_ascii": [78, 2, 32, 42, 4, 69, 0, 82, 25, 15],
      "coord": [5, 1, 5, 2, 2, 8, 0, 4, 2, 4, 2, 3, 2],
      "coord8": [51, 52, 28, 0, 4, 24, 23, 2],
      "digits15": [int(c) for c in "515228042423 2".replace(" ", "")]}
n7c = 0
for kn, ks in KS.items():
    for tname in ("dbbi", "faed"):
        d = G.digits(TEXTS[tname])
        for order in ("fwd", "rev"):
            k = ks if order == "fwd" else ks[::-1]
            for m in (9, 10, 26):
                for op in ("+", "-", "b"):
                    st = [((v + kk) if op == "+" else (v - kk) if op == "-" else (kk - v)) % m
                          for v, kk in zip(d, itertools.cycle(k))]
                    n7c += 1; N += 1
                    try:
                        z = G.z_method([x % 10 for x in st])
                    except Exception:
                        continue
                    N += 1
                    if G.semantic(z):
                        rec = {"how": f"ks7 {kn}/{tname}/{order}/m{m}/{op}", "hex": z.hex()[:200]}
                        HARD.append(rec); G.jsonl(LOG, {"HARD_z": rec})
                    for h in G.fast_priv_scan(z, f"ks7 {kn}"):
                        HARD.append({"priv": str(h)}); G.jsonl(LOG, {"HARD_priv": str(h)})
                    txt = "".join(chr(65 + (x % 26)) for x in st)
                    note_best(txt, f"ks7 {kn}/{tname}/{order}/m{m}/{op} a1z26")
G.jsonl(LOG, {"stage": "7c_keystream_correct", "streams": n7c, "n": N, "sec": round(time.time() - t0, 1)})

summary = {"n_tests": N, "hard": len(HARD), "soft": len(SOFT), "best": BEST,
           "soft_pad": [s for s in SOFT if "blob" in s][:25],
           "soft_text": [s for s in SOFT if "blob" not in s][:15]}
G.jsonl(LOG, {"summary_final": summary})
print("FINAL", json.dumps({k: v for k, v in summary.items() if k != "soft_pad"}, ensure_ascii=False)[:3000])

# ================================================================== ETAPA 8
# "Ok kid, on the highway, let put it in the worst gear" (= marcha re') aplicado a GRAMATICA:
# se a instrucao de inverter vale alem da tabela, a senha da fronteira e' a concatenacao INVERTIDA.
t0 = time.time()
PW322 = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
BASES = {"PW7": PW7, "PW7_W": PW7_W, "PW322": PW322,
         "P7join": "".join(PARTS), "tokens_end": "matrixsumlistlastwordsbeforearchichoicethispassword",
         "tokens_end2": "matrixsumlist lastwordsbeforearchichoice thispassword",
         "yb": "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang",
         "causality": "causality", "p2pw": "theflowerblossomsthroughwhatseemstobeaconcretesurface"}
def rev_variants(s, parts=None):
    v = {"str_rev": s[::-1], "words_rev": " ".join(s.split()[::-1]),
         "upper_rev": s.upper()[::-1], "lower_rev": s.lower()[::-1]}
    if parts:
        v["parts_rev"] = "".join(parts[::-1])
        v["parts_each_rev"] = "".join(p[::-1] for p in parts)
        v["parts_rev_each_rev"] = "".join(p[::-1] for p in parts[::-1])
    return v
n8 = 0
for bn, b in BASES.items():
    for vn, v in rev_variants(b, PARTS if bn in ("PW7", "P7join") else None).items():
        n8 += 1
        test_pw(v, f"gear {bn}/{vn} raw")
        test_pw(G.shahex(v), f"gear {bn}/{vn} sha256")
        for c in ("", "5152280N424232E", "82", "25", "Qwerty"):
            if c:
                test_pw(G.shahex(v + c), f"gear {bn}/{vn}+{c} sha256")
                test_pw(G.shahex(c + v), f"gear {bn}/{c}+{vn} sha256")
G.jsonl(LOG, {"stage": "8_worst_gear_grammar", "variants": n8, "n": N, "sec": round(time.time() - t0, 1)})

summary = {"n_tests": N, "hard": len(HARD), "soft": len(SOFT), "best": BEST,
           "soft_pad_sample": [s for s in SOFT if "blob" in s][:10],
           "soft_text": [s for s in SOFT if "blob" not in s][:15]}
G.jsonl(LOG, {"summary_final2": summary})
print("FINAL2", json.dumps({k: v for k, v in summary.items() if k != "soft_pad_sample"}, ensure_ascii=False)[:2000])
