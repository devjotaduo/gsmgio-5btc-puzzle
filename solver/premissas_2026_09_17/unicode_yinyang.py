# -*- coding: utf-8 -*-
"""
Familia: senhas NAO-ASCII (yin-yang em Unicode/CJK/coreano/emoji) contra os 3 blobs do endgame.

Hipotese (em prosa): o roadmap termina em `yinyang` e o criador disse "once you hit a ying yang
you'll solve it the same day". Todo o corpus historico (1,27 M formas) e ASCII. Se a "resposta"
final for o SIMBOLO ☯ (U+262F) ou a palavra em chines/japones/coreano, nenhuma forma ASCII a
alcanca. O openssl recebe BYTES em `-pass pass:`/`-pass file:`; o que chega depende do shell/
arquivo (UTF-8, UTF-8+BOM, UTF-16LE com BOM do Notepad "Unicode", CP1252 -> '?'). Testamos
cada string em todas essas codificacoes e normalizacoes (NFC/NFD/NFKC/NFKD), crua e hasheada
(sha256hex min/MAI, digest cru, sha256 duplo), sozinha e concatenada aos tokens da pagina em
todas as ordens de 2-3 elementos, contra SMALL/COSMIC/TAIL32 x {EVP-MD5, EVP-SHA256}; e o
sha256/sha256^2 de cada byte-string como privkey direta.

Oraculo: G.priv_hit / semantic / nested_blob (via try_password_all-equivalente). Todo padding
valido vai para o jsonl com plain_hex. Nulo: paddings esperados = n_aes/255 (CBC).
"""
import sys, os, json, time, math, hashlib, itertools, unicodedata, base64
KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
import gsmg_common as G
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from coincurve import PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
JSONL = os.path.join(HERE, "unicode_yinyang.jsonl")
SUMMARY = os.path.join(HERE, "unicode_yinyang_summary.json")
TGT = bytes.fromhex(G.TARGET_PUBKEY_HEX)

# ------------------------------------------------------------------ strings-base
SYMBOLS = ["☯", "☯\ufe0f", "☯\ufe0e", "☯☯", "⚊", "⚋", "⚊⚋", "⚋⚊", "⚊⚊", "⚋⚋",
           "☰", "☱", "☲", "☳", "☴", "☵", "☶", "☷", "☰☱☲☳☴☵☶☷", "☷☶☵☴☳☲☱☰", "☰☷", "☷☰",
           "䷀", "䷁", "䷀䷁", "䷁䷀", "".join(chr(0x4DC0 + i) for i in range(64)),
           "〇", "○●", "●○", "◐", "◑", "◐◑", "◑◐", "☮", "☯☮", "✴", "㊣",
           "🤐", "🤷‍♂", "🤷‍♂️", "🤷", "👆", "💯", "🤐🤷‍♂👆💯", "☯️", "🐇", "🐰", "🔑",
           "—", "→", "…", "█", "–", "2017 — 2026", "2017—2026", "A–B", "The lights are off.", ".:…"]
CJK = ["陰陽", "阴阳", "陰陽図", "陰陽圖", "太極", "太极", "太極図", "太极图", "太極圖", "太極図陰陽",
       "陰陽太極図", "陰", "陽", "阴", "阳", "陽陰", "阳阴", "陰陽道", "陰陽師", "陰陽五行", "太極拳",
       "易", "易経", "易經", "周易", "道", "無極", "无极", "两仪", "兩儀", "两仪图", "太一", "太乙",
       "いんよう", "インヨウ", "おんみょう", "インヤン", "たいきょく", "タイキョク",
       "태극", "음양", "태극도", "태극기", "음양오행", "陰陽論", "陰陽説",
       "阴阳鱼", "陰陽魚", "太极鱼"]
LATIN = ["yīnyáng", "yīn yáng", "Yīnyáng", "yīn-yáng", "Yīn Yáng", "yin yáng", "yīnyang",
         "tàijítú", "Tàijítú", "tài jí tú", "taijitu", "Taijitu", "TAIJITU", "tai ji tu", "taiji", "Taiji",
         "tai chi", "taichi", "Tai Chi", "TaiChi", "t'ai chi", "in'yō", "inyō", "in-yō", "onmyō", "onmyo",
         "eumyang", "eum-yang", "taegeuk", "taeguk", "yin yang", "yin-yang", "yin & yang", "yin&yang",
         "Yin Yang", "Yin-Yang", "YinYang", "YINYANG", "yinyang", "Yinyang", "ying yang", "yingyang",
         "Ying Yang", "YingYang", "ying-yang", "Yingyang", "YINGYANG", "yin/yang", "yin_yang", "yin+yang",
         "yin, yang", "yin and yang", "Yin and Yang", "yang yin", "yangyin", "yin", "yang", "ying",
         "yin yang symbol", "yin-yang symbol", "taijitu symbol", "YIN YANG", "YIN_YANG", "Yin_Yang",
         "ying yang symbol", "yinyangsymbol", "yingyangsymbol", "yin yang sign", "hit a ying yang",
         "once you hit a ying yang", "onceyouhitayingyang", "hitayingyang", "yin/yang/yin/yang"]
CODEPOINT = ["U+262F", "u+262f", "U+262f", "262F", "262f", "\\u262f", "\\u262F", "\\U0000262F",
             "&#9775;", "&#9775", "&#x262F;", "&#x262f;", "&#x262f", "9775", "%E2%98%AF", "%e2%98%af",
             "e298af", "E298AF", "0xe298af", "0x262F", "0x262f", "\\x{262F}", "2F26", "2f26", "262F FE0F",
             "262ffe0f", "262FFE0F", "\\xe2\\x98\\xaf", "\\342\\230\\257", "342230257", "11100010 10011000 10101111",
             "1110001010011000 10101111".replace(" ", ""), "0010011000101111", "0010 0110 0010 1111",
             "&yinyang;", "\\u9775", "?", "??", "???", "????", "\ufffd", "\ufffd\ufffd"]
try:
    CODEPOINT.append("xn--" + "☯".encode("punycode").decode())
except Exception:
    pass

BASES = {}
for grp, lst in (("symbol", SYMBOLS), ("cjk", CJK), ("latin", LATIN), ("codepoint", CODEPOINT)):
    for s in lst:
        BASES.setdefault(s, grp)

TOKENS = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword", "enter", "yellowblueprimes"]
ENCODINGS = ["utf-8", "utf-8-sig", "utf-16-le", "utf-16", "utf-16-be", "utf-32-le", "cp1252", "latin-1",
             "cp437", "gbk", "big5", "shift_jis", "euc-kr", "euc-jp"]

def norm_forms(s):
    out = []
    for f in ("NFC", "NFD", "NFKC", "NFKD"):
        t = unicodedata.normalize(f, s)
        if t not in out: out.append(t)
    return out

def encodings_of(s):
    """Todas as byte-strings distintas que um shell/arquivo poderia entregar para s."""
    seen = {}
    for t in norm_forms(s):
        for enc in ENCODINGS:
            try:
                b = t.encode(enc, "replace") if enc in ("cp1252", "latin-1", "cp437") else t.encode(enc)
            except Exception:
                continue
            if b and b not in seen: seen[b] = enc
    return seen  # bytes -> encoding (primeira que gerou)

def concats(s):
    """s sozinho e concatenado a 1-2 tokens em todas as ordens (2-3 elementos)."""
    out = [(s, "solo")]
    for t in TOKENS:
        out.append((s + t, f"S+{t}")); out.append((t + s, f"{t}+S"))
    for a, b in itertools.combinations(TOKENS, 2):
        for perm in itertools.permutations([("S", s), (a, a), (b, b)]):
            out.append(("".join(p[1] for p in perm), "+".join(p[0] for p in perm)))
    return out

def forms(b):
    h = hashlib.sha256(b).hexdigest()
    return [("raw", b), ("sha256hex", h.encode()), ("SHA256HEX", h.upper().encode()),
            ("digest", bytes.fromhex(h)), ("sha256x2hex", hashlib.sha256(h.encode()).hexdigest().encode()),
            ("dsha256hex", hashlib.sha256(bytes.fromhex(h)).hexdigest().encode())]

# ------------------------------------------------------------------ AES rapido
BLOBS = dict(G.BLOBS)
BLOBS["PHASE2"] = G._parse(G.PHASE2_B64)
KDFS = (("md5", MD5), ("sha256", SHA256))

def last_block_pad(k, iv, ct):
    """Decifra so o ultimo bloco (CBC): padding valido depende apenas dele. Equivalente exato ao unpad."""
    prev = ct[-32:-16] if len(ct) >= 32 else iv
    p = AES.new(k, AES.MODE_ECB).decrypt(ct[-16:])
    p = bytes(x ^ y for x, y in zip(p, prev))
    pad = p[-1]
    return 1 <= pad <= 16 and p.endswith(bytes([pad]) * pad)

def full_open(k, iv, ct):
    return G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))

def try_pw(pw, blobs=("SMALL", "COSMIC", "TAIL32")):
    """Devolve (n_aes, hard, soft)."""
    n = 0; hard = []; soft = []
    for b in blobs:
        salt, ct = BLOBS[b]
        for kname, hm in KDFS:
            k, iv = G.evp(pw, salt, hm); n += 1
            if not last_block_pad(k, iv, ct): continue
            p = full_open(k, iv, ct)
            rec = {"blob": b, "kdf": kname, "len": len(p), "printable": round(G.printable(p), 3),
                   "head": p[:48].decode("latin-1"), "plain_hex": p.hex()}
            priv = G.fast_priv_scan(p, f"{b}/{kname}") if len(p) >= 32 else []
            if priv: rec["privkey"] = priv
            if G.nested_blob(p): rec["nested"] = True
            (hard if (G.semantic(p) or priv) else soft).append(rec)
    return n, hard, soft

def priv_forms(b):
    """sha256 e sha256^2 da byte-string como privkey. Devolve hits."""
    hits = []
    d1 = hashlib.sha256(b).digest(); d2 = hashlib.sha256(d1).digest()
    for tag, sec in (("sha256", d1), ("dsha256", d2)):
        try:
            if PublicKey.from_valid_secret(sec).format(False) == TGT: hits.append((tag, sec.hex()))
        except Exception:
            pass
    return hits

# ------------------------------------------------------------------ controles
def controls():
    out = {}
    # (a) fase 2 abre com sha256hex("causality") no MESMO caminho (last_block_pad + full_open), so EVP-SHA256
    pw = G.shahex("causality").encode()
    n, hard, soft = try_pw(pw, blobs=("PHASE2",))
    out["phase2_sha256"] = [h["kdf"] for h in hard]; out["phase2_soft"] = [s["kdf"] for s in soft]
    out["phase2_head"] = hard[0]["head"] if hard else None
    assert out["phase2_sha256"] == ["sha256"] and not soft, out
    # (b) cifras de controle geradas por openssl real com senhas Unicode (-S fixo, sem cabecalho):
    #     descobre qual codificacao o shell entregou e prova o pipeline de codificacoes.
    salt = bytes.fromhex("3ab585348552415d")
    for fn, s in (("ctl_bash_utf8.b64", "☯"), ("ctl_bash_cjk.b64", "陰陽"), ("ctl_pwsh_yy.b64", "☯"),
                  ("ctl_cmd1252_yy.b64", "☯"), ("ctl_file_u16bom.b64", "☯")):
        path = os.path.join(HERE, fn)
        if not os.path.exists(path): out[fn] = "ausente"; continue
        ct = base64.b64decode(open(path).read())
        got = []
        for b, enc in encodings_of(s).items():
            k, iv = G.evp(b, salt, SHA256)
            p = full_open(k, iv, ct)
            if p == b"controle unicode gsmg": got.append(enc)
        out[fn] = got
        assert got, (fn, "nenhuma codificacao abriu o controle")
    return out

# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    ctl = controls()
    print("controles:", json.dumps(ctl, ensure_ascii=False))
    n_aes = 0; n_pw = 0; n_priv = 0; n_bytes = 0
    hard_hits = []; soft_hits = []; seen_pw = set()
    fo = open(JSONL, "w", encoding="utf-8")
    for base, grp in BASES.items():
        for s, ctag in concats(base):
            for b, enc in encodings_of(s).items():
                n_bytes += 1
                ph = priv_forms(b); n_priv += 2
                if ph:
                    rec = {"kind": "PRIVKEY", "base": base, "grp": grp, "concat": ctag, "enc": enc, "hits": ph}
                    hard_hits.append(rec); fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
                for ftag, pw in forms(b):
                    if pw in seen_pw: continue
                    seen_pw.add(pw); n_pw += 1
                    n, hard, soft = try_pw(pw); n_aes += n
                    for h in hard:
                        rec = {"kind": "HARD", "base": base, "grp": grp, "concat": ctag, "enc": enc, "form": ftag,
                               "pw_hex": pw.hex(), **h}
                        hard_hits.append(rec); fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    for sft in soft:
                        rec = {"kind": "pad", "base": base, "grp": grp, "concat": ctag, "enc": enc, "form": ftag,
                               "pw_hex": pw.hex(), **sft}
                        soft_hits.append(rec); fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
    fo.close()
    exp = n_aes * sum(256.0 ** -k for k in range(1, 17))
    obs = len(soft_hits) + sum(1 for h in hard_hits if h["kind"] == "HARD")
    z = (obs - exp) / math.sqrt(exp) if exp else 0.0
    by_blob = {}
    for r in soft_hits: by_blob[r["blob"]] = by_blob.get(r["blob"], 0) + 1
    best = max(soft_hits, key=lambda r: r["printable"], default=None)
    summ = {"family": "senhas nao-ASCII (yin-yang Unicode/CJK/emoji)", "n_bases": len(BASES),
            "n_bytestrings": n_bytes, "n_passwords": n_pw, "n_aes": n_aes, "n_privkey_tests": n_priv,
            "n_tests": n_aes + n_priv, "controls": ctl,
            "null": {"expected_pads": round(exp, 1), "observed_pads": obs, "z": round(z, 2), "by_blob": by_blob},
            "hard_hits": hard_hits, "best_readable": best, "secs": round(time.time() - t0, 1)}
    json.dump(summ, open(SUMMARY, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in summ.items() if k not in ("hard_hits",)}, ensure_ascii=False))
    print("hard_hits:", len(hard_hits))

if __name__ == "__main__":
    main()
