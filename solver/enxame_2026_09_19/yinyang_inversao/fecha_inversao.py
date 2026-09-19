# -*- coding: utf-8 -*-
"""F6 "yinyang_inversao" — fecha o EIXO DA INVOLUÇÃO da família "inversão yin-yang"
(ENDGAME.md §4-E, marcada "parcial").

Premissa (em prosa no FINDINGS.md): "inversão" só é operação definida sobre um objeto
que tenha uma involução canônica. No material do criador há exatamente quatro involuções
com lastro:

  C  — complemento do alfabeto a–i: x -> 10-x (a<->i, b<->h, c<->g, d<->f, e fixo).
       É a ÚNICA involução que inverte a ordem de {1..9}; em base 9 (a=0..i=8) dá
       x -> 8-x, que é a MESMA permutação de letras.
  R  — inversão da ordem de leitura (reverso da string).
  B  — complemento de bits, sobre os objetos binários da página. O criador publicou o
       roadmap de 2023-02-23 como "binário invertido": B é operação dele, demonstrada.
       Sobre a matriz, azul<->amarelo É B (azul=1, amarelo=0, provado em ENDGAME §1).
  M  — espelho da curva: k -> N-k (capa "Le Miroir de la Vie et de la Mort").

C e R comutam e são involuções, logo o grupo gerado sobre strings a–i é
{id, C, R, CR} — 4 elementos, não mais. Sobre strings binárias, {id, B, R, BR}.
M aplica-se só no nível do escalar e entra como 2 sinais em todo teste de privkey.

O que este script fecha: todos os objetos a–i e binários publicados, sob esse grupo,
materializados pela gramática das fases (cru / sha256hex / dígitos / z_method) contra
os 3 blobs x 2 KDF, e como escalar de 32 B contra os 2 alvos nos 2 sinais.

Uso:  python3 fecha_inversao.py [--null 100]
Saída: summary.json + hits.json no diretório de trabalho da frente.
"""
from __future__ import annotations
import argparse, hashlib, json, os, random, sys, time

KIT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                   "experiments", "claude_endgame_2026_09_02"))
sys.path.insert(0, KIT)
import gsmg_common as G  # noqa: E402

OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                   "_work", "enxame_2026-09-19", "yinyang_inversao"))
N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# resíduos de §6 (verbatim do ENDGAME.md / spec.json da campanha)
L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
L83 = L84[:-1]
# tipos dos 23 marcadores de L84 (b=0, be=1), ENDGAME.md §4d
MARK23 = "00001000110000100110010"

# ------------------------------------------------------------------ involuções
COMP = {c: chr(ord('a') + (8 - (ord(c) - ord('a')))) for c in "abcdefghi"}


def C(s: str) -> str:   # complemento do alfabeto a–i
    return "".join(COMP[c] for c in s)


def R(s: str) -> str:   # inversão da ordem
    return s[::-1]


def B(s: str) -> str:   # complemento de bits (strings de '0'/'1')
    return "".join("1" if c == "0" else "0" for c in s)


# ------------------------------------------------------------------ objetos
def bits_matrix():
    m = G.MATRIX_README
    rm = "".join(str(b) for r in m for b in r)                       # row-major
    cm = "".join(str(m[r][c]) for c in range(14) for r in range(14))  # column-major
    sp = "".join(str(m[y][x]) for (x, y) in G.SPIRAL)                 # espiral
    return {"matriz_rowmajor": rm, "matriz_colmajor": cm, "matriz_espiral": sp}


def objetos_ai():
    """Objetos sobre o alfabeto a–i."""
    o = {
        "dbbi": G.DBBI,
        "faed": G.FAED,
        "residuo_L84": L84,
        "residuo_L83": L83,
        # troca de papéis entre os dois campos (o eixo "dbbi<->faed")
        "dbbi_faed": G.DBBI + G.FAED,
        "faed_dbbi": G.FAED + G.DBBI,
        # metades yin/yang de faed e sua troca
        "faed_h1": G.FAED[:285], "faed_h2": G.FAED[285:],
        "faed_troca": G.FAED[285:] + G.FAED[:285],
        # metades de dbbi (91 ímpar: corte no centro, com e sem o símbolo central)
        "dbbi_troca": G.DBBI[46:] + G.DBBI[:45],
    }
    return o


def objetos_bin():
    o = bits_matrix()
    # palavra das 24 células coloridas (azul=1, amarelo=0) na ordem espiral
    o["cores24"] = "".join("1" if ch == "B" else "0" for ch in G.COLOR_SEQ)
    # idem com a célula inteira #FEFEFE (índice espiral 163) contada como azul: 25 eventos
    seq25 = list(G.COLOR_SEQ)
    seq25.insert(20, "B")
    o["cores25"] = "".join("1" if ch == "B" else "0" for ch in seq25)
    o["marcadores23"] = MARK23
    return o


# ------------------------------------------------------------------ materializações
def materiais(nome: str, s: str, binario: bool):
    """Devolve [(rotulo, senha_str, buffer_bytes_ou_None)] pela gramática das fases."""
    out = []
    out.append(("cru", s, s.encode()))
    out.append(("sha", hashlib.sha256(s.encode()).hexdigest(), None))
    if not binario:
        d1 = [G.A2I[c] for c in s]          # a=1..i=9 (a1z26 da página)
        d0 = [v - 1 for v in d1]            # a=0..i=8 (base 9)
        for tag, ds in (("dig1", d1), ("dig0", d0)):
            t = "".join(str(v) for v in ds)
            out.append((tag, t, t.encode()))
            out.append((tag + "_sha", hashlib.sha256(t.encode()).hexdigest(), None))
        try:
            z = G.z_method(d1)              # o decodificador ensinado pela página
            out.append(("zmethod", z.decode("latin-1"), z))
        except Exception:
            pass
    else:
        # bits -> bytes (MSB first), e os bits como string de dígitos
        out.append(("bits_sha", hashlib.sha256(s.encode()).hexdigest(), None))
        pad = s + "0" * ((8 - len(s) % 8) % 8)
        bb = bytes(int(pad[i:i + 8], 2) for i in range(0, len(pad), 8))
        out.append(("bits_bytes", bb.decode("latin-1"), bb))
    return out


def escalares(nome: str, s: str, binario: bool):
    """Escalares de 32 B derivados do objeto (int -> mod N), nos dois sinais."""
    vals = []
    if not binario:
        for base, off in ((10, 1), (9, 0)):
            t = "".join(str(G.A2I[c] - (1 - off)) for c in s)
            try:
                vals.append(int(t, base if base == 10 else 10) if base == 10 else int(t, 9))
            except ValueError:
                pass
        vals.append(int.from_bytes(hashlib.sha256(s.encode()).digest(), "big"))
    else:
        vals.append(int(s, 2))
        vals.append(int.from_bytes(hashlib.sha256(s.encode()).digest(), "big"))
    out = []
    for v in vals:
        k = v % N_CURVE
        if k == 0:
            continue
        out.append(k.to_bytes(32, "big"))
        out.append(((N_CURVE - k) % N_CURVE).to_bytes(32, "big"))  # espelho M
    return out


# ------------------------------------------------------------------ controles
def controle_positivo():
    """Fase 2 abre com sha256hex('causality') via EVP-SHA256 (AGENTS.md, regra 3)."""
    import base64
    from Crypto.Cipher import AES
    raw = base64.b64decode(G.PHASE2_B64)
    assert raw[:8] == b"Salted__"
    salt, ct = raw[8:16], raw[16:]
    pw = hashlib.sha256(b"causality").hexdigest().encode()
    k, iv = G.evp(pw, salt, G.SHA256)
    p = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct))
    ok = p is not None and G.printable(p) > 0.9
    return {"ok": bool(ok), "printable": round(G.printable(p), 3) if p else None,
            "head": p[:60].decode("latin-1") if p else None}


def controle_privkey():
    """Planta uma chave conhecida como ALVO e exige que priv_hit e fast_priv_scan a recuperem
    dentro de um buffer; depois restaura os alvos reais e confere que o ruído não dispara."""
    from coincurve import PublicKey
    k = hashlib.sha256(b"controle-f6-yinyang").digest()
    pub = PublicKey.from_valid_secret(k).format(compressed=True)
    h160 = G._h160_hex(pub)
    orig_o, orig_g = G.O.TARGET_H160S, G.TARGET_H160S
    try:
        G.O.TARGET_H160S = tuple(list(orig_o) + [h160])
        G.TARGET_H160S = tuple(list(orig_g) + [h160])
        buf = b"\x9c" * 11 + k + b"\x3e" * 13          # chave plantada no interior
        achou_scan = bool(G.fast_priv_scan(buf, "controle"))
        achou_hit = G.priv_hit(k) is not None
    finally:
        G.O.TARGET_H160S, G.TARGET_H160S = orig_o, orig_g
    return {"h160_plantado": h160, "fast_priv_scan_recuperou": achou_scan,
            "priv_hit_recuperou": achou_hit,
            "apos_restaurar_nao_dispara": G.priv_hit(k) is None,
            "priv_hit_aleatorio_eh_None": G.priv_hit(hashlib.sha256(b"x").digest()) is None,
            "alvos": list(G.TARGET_H160S)}


# ------------------------------------------------------------------ campanha
def roda(objs_ai, objs_bin, com_null=0, rotulo="real"):
    senhas = {}          # senha -> [rotulos]
    escs = {}            # bytes32 -> [rotulos]
    for fam, objs, binario in (("ai", objs_ai, False), ("bin", objs_bin, True)):
        grupo = (("id", lambda x: x), ("C" if not binario else "B",
                                       C if not binario else B),
                 ("R", R),
                 ("CR" if not binario else "BR",
                  (lambda x: R(C(x))) if not binario else (lambda x: R(B(x)))))
        for nome, s in objs.items():
            for tg, f in grupo:
                t = f(s)
                for tag, pw, buf in materiais(nome, t, binario):
                    senhas.setdefault(pw, []).append(f"{nome}|{tg}|{tag}")
                for e in escalares(nome, t, binario):
                    escs.setdefault(e, []).append(f"{nome}|{tg}|esc")
    return senhas, escs


_HEXD = "0123456789abcdef"


def expande_not(senhas):
    """Involução B ("NOT" do CyberChef) sobre o MATERIAL JÁ FORMADO: complemento de nibble
    do sha256 hex (f-x) e NOT bit a bit do buffer cru. Muda `senhas` no lugar."""
    for pw in list(senhas):
        rot = senhas[pw][0]
        if len(pw) == 64 and all(c in _HEXD for c in pw):
            senhas.setdefault("".join(_HEXD[15 - _HEXD.index(c)] for c in pw),
                              []).append(rot + "|NOThex")
        b = pw.encode("latin-1", "ignore")
        if b:
            senhas.setdefault(bytes(255 - x for x in b).decode("latin-1"),
                              []).append(rot + "|NOTbytes")
    return senhas


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--null", type=int, default=100)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()

    cp = controle_positivo()
    ck = controle_privkey()
    assert cp["ok"], "controle positivo da fase 2 FALHOU"

    oa, ob = objetos_ai(), objetos_bin()
    senhas, escs = roda(oa, ob)

    expande_not(senhas)
    hard, soft, aes = [], [], 0
    for pw, rots in senhas.items():
        h, s = G.try_password_all(pw)
        aes += 6
        for r in h:
            r["rotulos"] = rots[:6]
            hard.append(r)
        for r in s:
            r["rotulos"] = rots[:6]
            soft.append(r)

    hits_priv = []
    for e, rots in escs.items():
        r = G.priv_hit(e)
        if r:
            hits_priv.append({"hex": e.hex(), "rotulos": rots, "hit": str(r)})
    # varredura raw32 de todo buffer derivado (sem filtro de padding)
    janelas = 0
    for pw, rots in senhas.items():
        b = pw.encode("latin-1", "ignore")
        if len(b) >= 32:
            for i in range(len(b) - 31):
                janelas += 1
                if G.priv_hit(b[i:i + 32]):
                    hits_priv.append({"hex": b[i:i + 32].hex(), "rotulos": rots})

    # nulo casado: objetos embaralhados preservando contagens de símbolos
    nulo = None
    if a.null:
        rnd = random.Random(20260919)
        pads = []
        for _ in range(a.null):
            sa = {k: "".join(rnd.sample(v, len(v))) for k, v in oa.items()}
            sb = {k: "".join(rnd.sample(v, len(v))) for k, v in ob.items()}
            sn, _ = roda(sa, sb)
            expande_not(sn)
            n = 0
            for pw in sn:
                for b in ("SMALL", "COSMIC", "TAIL32"):   # mesmos 3 blobs do real
                    n += len(G.aes_try(pw, b))
            pads.append(n)
        mu = sum(pads) / len(pads)
        var = sum((x - mu) ** 2 for x in pads) / max(1, len(pads) - 1)
        sd = var ** 0.5
        obs = len(hard) + len(soft)
        nulo = {"rodadas": a.null, "media": round(mu, 2), "sd": round(sd, 2),
                "observado": obs, "z": round((obs - mu) / sd, 2) if sd else None,
                "aes_do_nulo": a.null * len(senhas) * 6}

    res = {
        "frente": "F6 yinyang_inversao",
        "kit_sha256": hashlib.sha256(open(os.path.join(KIT, "gsmg_common.py"), "rb").read()).hexdigest(),
        "controle_positivo_fase2": cp,
        "controle_privkey": ck,
        "objetos_ai": {k: len(v) for k, v in oa.items()},
        "objetos_bin": {k: len(v) for k, v in ob.items()},
        "grupo_involucoes": ["id", "C/B", "R", "CR/BR"],
        "senhas_distintas": len(senhas),
        "aes_executados": aes,
        "escalares_distintos": len(escs),
        "janelas_raw32": janelas,
        "paddings_validos": len(hard) + len(soft),
        "candidatos_semanticos": len(hard),
        "hits_oraculo_duro": hits_priv,
        "nulo": nulo,
        "segundos": round(time.time() - t0, 1),
    }
    json.dump(res, open(os.path.join(OUT, "summary.json"), "w"), indent=2, ensure_ascii=False)
    json.dump({"hard": hard, "soft": soft}, open(os.path.join(OUT, "paddings.json"), "w"),
              indent=2, ensure_ascii=False)
    print(json.dumps(res, indent=2, ensure_ascii=False)[:4000])


if __name__ == "__main__":
    main()
