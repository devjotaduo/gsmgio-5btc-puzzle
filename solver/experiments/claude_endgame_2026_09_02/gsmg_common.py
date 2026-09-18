# -*- coding: utf-8 -*-
"""
Kit comum para os agentes do endgame GSMG (SalPhaseIon / Cosmic Duality).
Importe com:
    import sys; sys.path.insert(0, r"<scratchpad>"); import gsmg_common as G
Tudo aqui e DETERMINISTICO e verificado. Os oraculos duros sao a unica verdade.
"""
import os, sys, re, base64, hashlib, math, itertools
# solver/ desta cópia do repositório: numa worktree, o kit usa os oráculos e o README da própria worktree
SOLVER = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, SOLVER)
import oracles as O                      # aes_open / check_privkey / check_mnemonic
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

# ------------------------------------------------------------------ dados brutos
DBBI = O.sources()["dbbi"]               # 91 chars a-i
FAED = O.sources()["faed"]               # 570 chars a-i (comeca com 'faed')
TOKENS = {
    "matrixsumlist": "matrixsumlist",            # binario abba entre dbbi e faed
    "enter": "enter",                            # binario abba DENTRO do blob SMALL (entre as 2 linhas base64)
    "lastwordsbeforearchichoice": "lastwordsbeforearchichoice",  # z-segmento 1 (a-i,o -> dec -> hex -> ascii)
    "thispassword": "thispassword",              # z-segmento 2
    "shabef": "sha256",                          # a1z26: b=2,e=5,f=6
    "line_before_small": "our first hint is your last command",   # "shabef our first hint is your last command"
    "line_after_small": "ans too",               # "shabef ans too"
}
# blobs openssl (Salted__ + salt8 + ct). SMALL = SalPhaseIon; COSMIC = Cosmic Duality;
# TAIL32 = blob no fim da fase 3.2 ("Raising the stakes..."), NUNCA aberto de verdade.
SMALL_B64 = ("U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z"
             "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ")
TAIL32_B64 = ("U2FsdGVkX1+0Wl49gnWTyiimluu7V3+vl7st0gUt9sWDzNLxDmlPMsDSiuW2a46z"
              "gKlIi8aaqY5gpJPPEzW1n9n3/26qs4zstWtPKF8Zs/BTNN4IiEh4qu18mdC0NAv4")
def _parse(b64):
    raw = base64.b64decode(b64); assert raw[:8] == b"Salted__"
    return raw[8:16], raw[16:]
BLOBS = {"SMALL": _parse(SMALL_B64), "TAIL32": _parse(TAIL32_B64),
         "COSMIC": O.blobs()["COSMIC"]}
PRIZE_ADDR = O.PRIZE_ADDR
TARGET_H160 = O.TARGET_H160
PRIZE_ADDR_2 = O.PRIZE_ADDR_2          # 17ucy... = segunda metade do premio (ver oracles.py)
TARGET_H160_2 = O.TARGET_H160_2
TARGET_H160S = O.TARGET_H160S
TARGET_PUBKEY_HEX = ("04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4"
                     "649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")

# matriz 14x14 da imagem original (azul=1, amarelo=0, preto=1, branco=0).
# ATENCAO (refutado na rodada 2): MATRIX_IMG[7][6]=1 e ARTEFATO de amostragem. As celulas
# (6,6),(6,7),(7,6),(7,7),(7,8),(7,9),(8,6) contem o desenho de um COELHO BRANCO feito
# em 5 px, com fracao de preto 0.08..0.36 (todas as outras 189 celulas sao 0.00 ou 1.00).
# Use MATRIX_README (101 uns) como a matriz de BITS real; "102 uns / espiral 193 primo /
# cauda 0100 / 91 zeros em 0..191" NAO sao fatos do puzzle.
MATRIX_IMG = [list(map(int, r)) for r in """
00110100101100
11110011101011
11011101001001
01101000011101
01100011000110
10011000100011
10011100010000
11100010001000
00011101111101
11111100110001
11010000011011
11110010101100
01011101000110
01101101101011""".split()]
MATRIX_README = [row[:] for row in MATRIX_IMG]; MATRIX_README[7][6] = 0
def spiral_ccw(n=14):
    """Ordem espiral anti-horaria a partir de (0,0): desce a coluna 0, direita, sobe, esquerda..."""
    seen = set(); order = []; r = c = 0; d = 0
    dirs = [(1, 0), (0, 1), (-1, 0), (0, -1)]
    for _ in range(n * n):
        order.append((r, c)); seen.add((r, c))
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if not (0 <= nr < n and 0 <= nc < n) or (nr, nc) in seen:
            d = (d + 1) % 4; nr, nc = r + dirs[d][0], c + dirs[d][1]
        r, c = nr, nc
    return order
SPIRAL = spiral_ccw()
# celulas coloridas: indice espiral -> (cor, linha, coluna). W* = pixel FEFEFE (quase branco)
COLORED = {7: ('B', 7, 0), 15: ('B', 13, 2), 23: ('B', 13, 10), 31: ('B', 8, 13), 39: ('Y', 0, 13),
           47: ('B', 0, 5), 55: ('B', 4, 1), 63: ('B', 12, 1), 71: ('Y', 12, 9), 79: ('Y', 7, 12),
           87: ('B', 1, 10), 95: ('B', 1, 2), 103: ('B', 9, 2), 111: ('B', 11, 8), 119: ('Y', 6, 11),
           127: ('B', 2, 7), 135: ('B', 6, 3), 143: ('Y', 10, 7), 151: ('Y', 5, 10), 159: ('B', 3, 4),
           163: ('W*', 7, 4), 167: ('Y', 9, 6), 175: ('Y', 4, 9), 183: ('B', 8, 5), 191: ('Y', 5, 6)}
BLUE_IDX = [i for i, v in COLORED.items() if v[0] == 'B']     # 15
YELLOW_IDX = [i for i, v in COLORED.items() if v[0] == 'Y']   # 9
COLOR_SEQ = "BBBBYBBBYYBBBBYBBYYBYYBY"  # ordem espiral (sem o W*)
HEX_BLUE, HEX_YELLOW = "3F48CC", "FFF200"
def row_sums(M): return [sum(r) for r in M]
def col_sums(M): return [sum(M[r][c] for r in range(14)) for c in range(14)]

# ------------------------------------------------------------------ utilitarios
A2I = {c: i + 1 for i, c in enumerate("abcdefghi")}   # a=1..i=9 (metodo ensinado pela pagina)
def digits(s, base1=True):
    return [ord(c) - 96 if base1 else ord(c) - 97 for c in s.lower() if c in "abcdefghi"]
def z_method(digit_list):
    """Metodo da pagina: digitos decimais -> inteiro -> hex -> bytes (ascii)."""
    n = int("".join(str(d) for d in digit_list)); h = format(n, "x")
    if len(h) % 2: h = "0" + h
    return bytes.fromhex(h)
def printable(b):
    return sum(32 <= x < 127 for x in b) / max(1, len(b))
def sha(s): return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).digest()
def shahex(s): return sha(s).hex()
def is_prime(n):
    if n < 2: return False
    return all(n % p for p in range(2, int(n ** 0.5) + 1))
WIF_RE = re.compile(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}")
HEX64_RE = re.compile(r"[0-9a-fA-F]{64}")
def wif_candidates(t):
    """WIFs plausíveis em t: exige dígito E minúscula E maiúscula (evita runs de só-letras)."""
    return [m.group() for m in WIF_RE.finditer(t)
            if re.search(r"\d", m.group()) and re.search(r"[a-z]", m.group()) and re.search(r"[A-Z]", m.group())]
def hex64_candidates(t):
    """hex64 plausível: exige pelo menos um dígito e uma letra a-f (evita runs de só-dígitos ou só-letras)."""
    return [m.group() for m in HEX64_RE.finditer(t)
            if re.search(r"\d", m.group()) and re.search(r"[a-fA-F]", m.group())]
# blob da FASE 2 (controle de KDF): abre com sha256hex("causality") SÓ via EVP-SHA256 (openssl >= 1.1.0)
def _readme_blob(prefix):
    """Extrai do README o blob base64 (linhas de 64 chars) que começa com `prefix`."""
    txt = O._readme(); i = txt.index(prefix); lines = []
    for l in txt[i:].splitlines():
        l = l.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]{4,64}", l): break
        lines.append(l)
    return "".join(lines)
PHASE2_B64 = _readme_blob("U2FsdGVkX18GKGYS")      # fase 2: abre com sha256hex("causality") SÓ via EVP-SHA256
PHASE3_B64 = _readme_blob("U2FsdGVkX1+fvEUdE9Bx")  # fase 3: sha256hex(causalitySafenet...)
PHASE32_B64 = _readme_blob("U2FsdGVkX1/u/Exb78Fl") # fase 3.2: sha256hex(jacquefresco...)
BIP39_WORDS = set(O.WORDLIST)

# ------------------------------------------------------------------ AES / EVP
def evp(pw, salt, hmod, klen=32, ivlen=16):
    d = b""; prev = b""
    while len(d) < klen + ivlen:
        prev = hmod.new(prev + pw + salt).digest(); d += prev
    return d[:klen], d[klen:klen + ivlen]
def unpad(p):
    pad = p[-1]
    if 1 <= pad <= 16 and p.endswith(bytes([pad]) * pad): return p[:-pad]
    return None
def aes_try(pw, blob="SMALL", kdf="both"):
    """Tenta senha (str|bytes) no blob via EVP_BytesToKey (openssl -pass).
    Retorna lista de (kdf, plaintext) com padding valido (SEM filtro de ASCII)."""
    salt, ct = BLOBS[blob]
    pw = pw.encode() if isinstance(pw, str) else pw
    out = []
    for hm in ((MD5, SHA256) if kdf == "both" else ((MD5,) if kdf == "md5" else (SHA256,))):
        k, iv = evp(pw, salt, hm)
        p = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
        if p is not None: out.append((hm.__name__, p))
    return out
def aes_rawkey(key32, blob="SMALL", iv=None):
    """Chave crua de 32B (openssl -K) com IV dado (default: zeros). Retorna plaintext ou None."""
    salt, ct = BLOBS[blob]
    p = unpad(AES.new(key32, AES.MODE_CBC, iv or b"\x00" * 16).decrypt(ct))
    return p
_B64_RE = re.compile(rb"^[A-Za-z0-9+/]+={0,2}\s*$")
def nested_blob(p):
    """Oráculo de ENCRIPTAÇÃO ANINHADA ("SIXTEEN ENCRYPTIONS"): plaintext que é ele mesmo um blob
    openssl (`Salted__` cru ou em armadura base64 de 'U2FsdGVk'). P(falso positivo) ≈ 2^-64 — grátis.
    Adicionado em 2026-09-17: 67 mil plaintexts com padding válido nunca tinham sido checados nisto."""
    if p is None or len(p) < 32: return False
    if p[:8] == b"Salted__": return True
    if p[:8] == b"U2FsdGVk" and _B64_RE.match(p): return True
    return False
_EBCDIC_AZ = {bytes([ord(c)]).decode("cp273").encode("latin-1")[0] for c in "abcdefghijklmnopqrstuvwxyz"}
def ebcdic_sig(p):
    """Assinatura de um plaintext 'estilo fase 3.2': fração dos bytes >= 0x80 que caem na imagem
    cp273 de a–z (17 valores). O plaintext REAL da fase 3.2 tem printable 0,589 e era descartado
    pelo oráculo histórico; sua assinatura é ~1,0 e o máximo em ruído calibrado é 0,46 (2026-09-17)."""
    hi = [x for x in p if x >= 0x80]
    return (sum(x in _EBCDIC_AZ for x in hi) / len(hi)) if len(hi) >= 8 else 0.0
def semantic(p, thr=0.85):
    """Triagem de plaintext AES: True se parece mensagem real (ascii alto, WIF/hex64 plausível,
    um blob openssl aninhado — ver nested_blob — ou um segmento EBCDIC cp273 como o da fase 3.2).
    ATENÇÃO: só use em saídas de AES/decifração binária. Para decoders que emitem SÓ bytes 32..126 por
    construção (a1z26, pares+32, etc.) o teste de printable é tautológico — use semantic_text."""
    if p is None or not p: return False
    if nested_blob(p): return True
    if printable(p) >= thr: return True
    if ebcdic_sig(p) >= 0.75: return True
    t = p.decode("latin-1")
    return bool(wif_candidates(t) or hex64_candidates(t))
def semantic_text(t, min_score=-4.5, min_words=2):
    """Triagem para saídas textuais (letras): inglês por quadgramas OU ≥min_words palavras BIP39 ≥6 letras
    OU WIF/hex64 plausível. Não é oráculo duro."""
    if isinstance(t, bytes): t = t.decode("latin-1")
    if wif_candidates(t): return True
    # hex64 só conta se o texto NÃO for inteiramente alfabeto hexadecimal (senão é tautologia de
    # decoders que empacotam mod-16 — apontado pelo crítico da rodada 2)
    if hex64_candidates(t) and re.search(r"[^0-9a-fA-F\s]", t): return True
    if english_score(t) > min_score: return True
    return len(word_hits(t, 6)) >= min_words
def try_password_all(pw, blobs=("SMALL", "COSMIC", "TAIL32"), kdf="both"):
    """Roda aes_try em todos os blobs; devolve hits SEMANTICOS + paddings (soft).
    `hard` = CANDIDATO (semântico ou privkey embutida), não solução: ver AGENTS.md, regra 1.
    Desde 2026-09-17: todo plaintext com padding válido também é varrido por privkey embutida
    (fast_priv_scan) e por blob aninhado (nested_blob), e o plaintext completo vai no registro
    (`hex`) para permitir varredura retroativa — antes os plaintexts eram descartados."""
    hard, soft = [], []
    for b in blobs:
        for k, p in aes_try(pw, b, kdf):
            rec = {"blob": b, "kdf": k, "len": len(p), "printable": round(printable(p), 3),
                   "head": p[:48].decode("latin-1"), "hex": p.hex()}
            priv = fast_priv_scan(p, f"{b}/{k}") if len(p) >= 32 else []
            if priv: rec["privkey"] = priv
            if nested_blob(p): rec["nested"] = True
            (hard if (semantic(p) or priv) else soft).append(rec)
    return hard, soft

# ------------------------------------------------------------------ privkey
def priv_hit(b32):
    """Oraculo duro: privkey de 32B gera UM DOS DOIS enderecos do premio (comp ou uncomp)?
    Desde 2026-09-17 testa tambem 17ucy... (ver O.PRIZE_ADDRS)."""
    if len(b32) != 32: return None
    return O.check_privkey(b32)
def scan_priv(buf, where=""):
    """Varre todo offset de 32B + hex64 ascii + WIF embutido. Retorna lista de hits."""
    hits = []
    for j in range(0, len(buf) - 31):
        r = priv_hit(buf[j:j + 32])
        if r: hits.append((where, f"priv@{j}", r))
    t = buf.decode("latin-1")
    for h in hex64_candidates(t):
        r = priv_hit(bytes.fromhex(h))
        if r: hits.append((where, "hex64", r))
    for w in wif_candidates(t):
        try:
            import base58
            raw = base58.b58decode_check(w)
            r = priv_hit(raw[1:33])
            if r: hits.append((where, "wif", r))
        except Exception:
            pass
    return hits
def _h160_hex(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).hexdigest()
def fast_priv_scan(buf, where=""):
    """Como scan_priv, mas com coincurve (≈0,1 ms/chave) — use em varreduras grandes.
    Desde 2026-09-17 compara o h160 (comp e uncomp) contra os DOIS enderecos do premio; ate entao
    so comparava a pubkey nao comprimida de 1GSMG e era cego para 17ucy (que nunca gastou).
    Retorno inalterado: lista de (where, "priv@j", hex) — uma entrada por janela que casa."""
    from coincurve import PublicKey
    hits = []
    for j in range(0, len(buf) - 31):
        sec = buf[j:j + 32]
        try:
            pk = PublicKey.from_valid_secret(sec)
        except Exception:
            continue
        if any(_h160_hex(pk.format(form)) in TARGET_H160S for form in (False, True)):
            hits.append((where, f"priv@{j}", sec.hex()))
    return hits
def phrase_priv(phrase):
    """'brainwallet': sha256(frase) como privkey (varias formas). Retorna hits."""
    hits = []
    forms = {phrase, phrase.upper(), phrase.lower(), phrase.replace(" ", ""),
             phrase.upper().replace(" ", ""), phrase.lower().replace(" ", "")}
    for f in forms:
        for b in (f.encode(), f.encode() + b"\n"):
            for k in (sha(b), sha(sha(b)), sha(sha(b).hex().encode())):
                r = priv_hit(k)
                if r: hits.append((f, r))
    return hits

# ------------------------------------------------------------------ cifras classicas
def polybius(alphabet, n):
    assert len(alphabet) == n * n and len(set(alphabet)) == n * n
    return {c: (i // n, i % n) for i, c in enumerate(alphabet)}
def bifid(text, alphabet, period=None, n=5, mode="decrypt"):
    """Bifid generico n x n. Decrypt padrao (o que da BTCSEED com CANON, n=5, period=570)."""
    pos = polybius(alphabet, n); up = text.upper() if alphabet.isupper() else text
    up = "".join(c for c in up if c in pos)
    period = period or len(up); out = []
    for off in range(0, len(up), period):
        blk = up[off:off + period]; L = len(blk)
        if mode == "decrypt":
            seq = []
            for c in blk: seq += list(pos[c])
            rows, cols = seq[:L], seq[L:]
            out.append("".join(alphabet[rows[i] * n + cols[i]] for i in range(L)))
        else:
            rows = [pos[c][0] for c in blk]; cols = [pos[c][1] for c in blk]
            seq = rows + cols
            out.append("".join(alphabet[seq[2 * i] * n + seq[2 * i + 1]] for i in range(L)))
    return "".join(out)
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"   # keyword = ordem de 1a ocorrencia do dbbi (d,b,i,f,h,c,e,g,a) + filler
def keyed_alphabet(phrase, base="ABCDEFGHIKLMNOPQRSTUVWXYZ", merge_j=True):
    """Alfabeto de 25 (ou len(base)) letras: 1a ocorrencia da frase + filler."""
    seen = []
    for c in phrase.upper():
        if merge_j and c == "J": c = "I"
        if c in base and c not in seen: seen.append(c)
    return "".join(seen) + "".join(c for c in base if c not in seen)
def bif_full(): return bifid(FAED, CANON, 570)   # comeca com BTCSEED
def checkerboard_decode(digs, alphabet, escapes, universe="123456789"):
    """Straddling checkerboard. digs: lista de digitos (ints) do universo; escapes: 2 digitos.
    Linha 0 = universe sem escapes (7 letras p/ universo 1-9); linha e1 = 9 letras; e2 = 9 letras."""
    top = [d for d in universe if int(d) not in escapes]
    need = len(top) + 2 * len(universe)
    alphabet = (alphabet + "." * need)[:need]
    table = {}
    k = 0
    for d in top: table[(int(d),)] = alphabet[k]; k += 1
    for e in escapes:
        for d in universe: table[(e, int(d))] = alphabet[k]; k += 1
    out = []; i = 0
    while i < len(digs):
        d = digs[i]
        if d in escapes:
            if i + 1 < len(digs): out.append(table.get((d, digs[i + 1]), "?")); i += 2
            else: break
        else:
            out.append(table.get((d,), "?")); i += 1
    return "".join(out)
def checkerboard_encode(text, alphabet, escapes, universe="123456789"):
    """Inverso exato de checkerboard_decode (mesmo layout de tabela). Devolve a string de dígitos.
    Adicionado em 2026-09-17 (validado: reproduz os 149 dígitos da fase 3.2.2 a partir do plaintext).
    Permite re-codificar qualquer texto em qualquer tabuleiro para gerar material numérico de senha."""
    top = [int(d) for d in universe if int(d) not in escapes]
    need = len(top) + 2 * len(universe)
    alphabet = (alphabet + "." * need)[:need]
    enc = {}; k = 0
    for d in top: enc.setdefault(alphabet[k], (d,)); k += 1
    for e in escapes:
        for d in universe: enc.setdefault(alphabet[k], (e, int(d))); k += 1
    return "".join("".join(map(str, enc[c])) for c in text if c in enc)

# ------------------------------------------------------------------ scorer de ingles
_SC = None
def scorer():
    global _SC
    if _SC is None:
        from scorer import Scorer; _SC = Scorer()
    return _SC
def english_score(t):
    """quadgramas: ingles ~ -2.5..-3.5 ; ruido < -6 ; baseline BIF canonico = -5.577"""
    return scorer()("".join(c for c in t.upper() if "A" <= c <= "Z"))
_WORDS = None
def word_hits(t, minlen=5):
    """Palavras BIP39 (>=minlen) contidas em t (triagem barata de estrutura)."""
    global _WORDS
    if _WORDS is None: _WORDS = sorted({w.upper() for w in O.WORDLIST if len(w) >= minlen}, key=len, reverse=True)
    T = t.upper(); return [w for w in _WORDS if w in T]

# ------------------------------------------------------------------ log
def jsonl(path, obj):
    import json
    with open(path, "a", encoding="utf-8") as f: f.write(json.dumps(obj, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    assert bif_full().startswith("BTCSEED")
    assert z_method(digits("agdafaoaheiecggchgicbbhcgbehcfcoabicfdhhcdbbcagbdaiobbgbeadedde".replace("o", "a")) ) is not None
    # z-segmento real (o e' 0)
    seg = "agdafaoaheiecggchgicbbhcgbehcfcoabicfdhhcdbbcagbdaiobbgbeadedde"
    d = [0 if c == "o" else A2I[c] for c in seg]
    assert z_method(d) == b"lastwordsbeforearchichoice", z_method(d)
    assert sum(map(sum, MATRIX_IMG)) == 102 and sum(map(sum, MATRIX_README)) == 101
    bits = "".join(str(MATRIX_IMG[r][c]) for r, c in SPIRAL)
    assert "".join(chr(int(bits[i:i+8], 2)) for i in range(0, 192, 8)) == "gsmg.io/theseedisplanted"
    assert len(BLOBS["SMALL"][1]) == 80 and len(BLOBS["TAIL32"][1]) == 80 and len(BLOBS["COSMIC"][1]) == 1328
    # controle: senha lixo nao abre; padding aleatorio ~1/256
    assert aes_try("xyz_wrong") == [] or all(not semantic(p) for _, p in aes_try("xyz_wrong"))
    assert priv_hit(sha(b"test")) is None
    # controle dos DOIS alvos (2026-09-17): chave plantada e reconhecida por fast_priv_scan quando
    # seu h160 entra temporariamente em TARGET_H160S; sem isso, nao dispara
    _k = sha(b"controle-dois-alvos"); from coincurve import PublicKey as _PK
    _h = _h160_hex(_PK.from_valid_secret(_k).format(True))
    assert fast_priv_scan(b"\x00" * 5 + _k + b"\x00" * 3) == []
    TARGET_H160S = TARGET_H160S + (_h,)
    assert fast_priv_scan(b"\x00" * 5 + _k + b"\x00" * 3)[0][1] == "priv@5"
    TARGET_H160S = TARGET_H160S[:-1]
    assert O.check_privkey(bytes(32)) is None and len(O.PRIZE_ADDRS) == 2 and O.PRIZE_ADDR_2.startswith("17ucy")
    # controle positivo do checkerboard: fase 3.2.2
    alpha322 = "FUBCDORA.LETHINGKYMVPS.JQZXW"
    digs = [int(c) for c in "15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112"]
    pt = checkerboard_decode(digs, alpha322, escapes=(1, 4), universe="0123456789")
    assert pt.startswith("INCASEYOUMANAGETOCRACKTHIS"), pt[:40]
    # controle inverso: o encoder reproduz os 149 dígitos exatos da fase 3.2.2
    assert checkerboard_encode(pt, alpha322, (1, 4), "0123456789") == "".join(map(str, digs))
    # oráculo de blob aninhado: pega Salted__ cru e em base64, e não dispara em ruído
    assert nested_blob(b"Salted__" + b"\x00" * 24) and nested_blob(b"U2FsdGVkX18" + b"A" * 40)
    assert not nested_blob(b"\x01" * 64)
    # controle de KDF: fase 2 abre com sha256hex('causality') via EVP-SHA256 (e NAO via MD5)
    raw = base64.b64decode(PHASE2_B64); s2, c2 = raw[8:16], raw[16:]
    pw = shahex("causality").encode(); res = {}
    for hm in (MD5, SHA256):
        k, iv = evp(pw, s2, hm); p = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c2))
        res[hm.__name__] = (p is not None and p.startswith(b"The ironic"))
    assert res["Crypto.Hash.SHA256"] and not res["Crypto.Hash.MD5"], res
    assert not wif_candidates("K" + "A" * 51) and wif_candidates("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    assert semantic_text("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENSOMEMOREWORDS") and not semantic_text("QXZJKVWPBFMGHLCDNRTSYAEIOU" * 3)
    print("gsmg_common OK; KDF=EVP-SHA256 confirmado; BIF:", bif_full()[:30], "score", round(english_score(bif_full()), 3))
