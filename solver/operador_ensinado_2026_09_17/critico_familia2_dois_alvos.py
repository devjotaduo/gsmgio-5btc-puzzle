# -*- coding: utf-8 -*-
"""
CRITICO da familia 2 — complemento: ORACULO DE PRIVKEY COM OS DOIS ENDERECOS DO PREMIO.

HIPOTESE (prosa, finita, falsificavel)
--------------------------------------
O script do agente (familia2_lastwords.py) e o meu critico_familia2.py compararam toda privkey
candidata SO contra a pubkey de 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe (G.TARGET_PUBKEY_HEX, via
G.fast_priv_scan e o braco brainwallet). O premio tem uma segunda metade,
17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa (3,75 BTC; so o h160 e conhecido). A varredura retroativa do
orquestrador (retro_dois_alvos.py, 23:34) cobriu os plaintexts do log do agente mas NAO os 1.302 do
meu log (23:46) e, por construcao, NAO cobre o braco brainwallet, que nunca foi gravado em disco.

Se (a) alguma das senhas unicas das duas rodadas (23.352 do agente + 55.576 minhas), tomada como
sha256(senha), sha256(sha256(senha)) ou sha256(sha256hex(senha)), ou (b) alguma janela de 32 B
(nas duas ordens de byte) dos plaintexts com padding valido dos dois logs, for a privkey de
QUALQUER um dos dois enderecos (pubkey comprimida ou nao), o negativo da familia 2 esta errado.
Se nao, o negativo passa a valer tambem para o segundo alvo, com a contagem exata impressa aqui.
Este teste dispensa nulo: P(falso positivo) por chave ~ 2^-160 por h160.
"""
import sys, os, re, json, time, hashlib
AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
KIT = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02"
sys.path.insert(0, KIT)
import gsmg_common as G
import oraculo_dois_alvos as O2
from coincurve import PublicKey
sys.set_int_max_str_digits(0)

RAIZ = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle"
W = os.path.join(RAIZ, "_work", "operador_ensinado_2026-09-17")
SRC_AG = os.path.join(RAIZ, "solver", "operador_ensinado_2026_09_17", "familia2_lastwords.py")
SRC_CR = os.path.join(RAIZ, "solver", "operador_ensinado_2026_09_17", "critico_familia2.py")
LOG_AG = os.path.join(W, "familia2_lastwords", "run.jsonl")
LOG_CR = os.path.join(W, "critico_familia2", "run.jsonl")
OUT = os.path.join(W, "critico_familia2")
LOG = os.path.join(OUT, "dois_alvos.jsonl")
open(LOG, "w").close()
def log(o): G.jsonl(LOG, o)

def carrega(src_path, troca):
    """Executa o fonte com o diretorio de saida redirecionado (os modulos truncam o proprio log
    no nivel do modulo) e sem o bloco __main__."""
    src = open(src_path, encoding="utf-8").read()
    for a, b in troca: 
        assert a in src, a
        src = src.replace(a, b)
    src = src.replace('if __name__ == "__main__":\n    sys.exit(main())', '')
    ns = {"__name__": "repro_" + os.path.basename(src_path)[:-3]}
    exec(compile(src, src_path, "exec"), ns)
    return ns

def senhas(ns, M):
    pws = set()
    for frase in M.values():
        for f in ns["formas"](frase):
            for _, pw in ns["operadores"](f):
                b = pw.encode("utf-8", "surrogateescape") if isinstance(pw, str) else pw
                if b: pws.add(b)
            for c in ns["composicoes"](f):
                pws.add(c.encode()); pws.add(G.shahex(c).encode())
    return pws

def plaintexts(path):
    out = set()
    for l in open(path, encoding="utf-8"):
        o = json.loads(l)
        if "hex" in o: out.add(o["hex"])
    return out

def main():
    t0 = time.time()
    # --- controle plantado: chave conhecida injetada nos alvos, achada por brainwallet e por janela
    k = hashlib.sha256(b"controle-critico-2").digest()
    h = O2.h160(PublicKey.from_valid_secret(k).format(True))
    O2.TARGETS[h] = "PLANTADO"
    assert O2.priv_hit2(k) == ("PLANTADO", "comp")
    assert O2.scan32(b"\x11" * 5 + k + b"\x22" * 9)[0][:2] == (5, "fwd")
    assert O2.scan32(b"\x11" * 5 + k[::-1] + b"\x22" * 9)[0][:2] == (5, "rev")
    del O2.TARGETS[h]
    assert O2.priv_hit2(k) is None
    print("[controle plantado] OK: detector acha a chave plantada (comp) por brainwallet e por janela fwd/rev", flush=True)
    log({"kind": "controle_plantado", "ok": True, "alvos": sorted(O2.TARGETS.values())})

    # --- senhas das duas rodadas
    ag = carrega(SRC_AG, [('"familia2_lastwords")', '"critico_familia2", "_repro")')])
    cr = carrega(SRC_CR, [('"operador_ensinado_2026-09-17", "critico_familia2")',
                          '"operador_ensinado_2026-09-17", "critico_familia2", "_repro")')])
    S_ag = senhas(ag, ag["materiais"]())
    S_cr = senhas(cr, cr["materiais_completos"]())
    print(f"[senhas] agente={len(S_ag)} critico={len(S_cr)} uniao={len(S_ag | S_cr)}", flush=True)
    assert len(S_ag) == 23352, len(S_ag)
    assert len(S_cr) == 55576, len(S_cr)
    log({"kind": "senhas", "agente": len(S_ag), "critico": len(S_cr), "uniao": len(S_ag | S_cr)})

    hits, nk = [], 0
    for pw in S_ag | S_cr:
        k1 = hashlib.sha256(pw).digest()
        for nome, k in (("sha", k1), ("sha2", hashlib.sha256(k1).digest()),
                        ("shahex", hashlib.sha256(k1.hex().encode()).digest())):
            nk += 1
            r = O2.priv_hit2(k)
            if r:
                rec = {"kind": "PRIVKEY_BRAINWALLET", "forma": nome, "pw": pw.decode("latin-1")[:120],
                       "priv": k.hex(), "hit": r}
                hits.append(rec); log(rec); print("### HARD", rec, flush=True)
    print(f"[brainwallet] chaves={nk} hits={len(hits)} t={time.time()-t0:.0f}s", flush=True)
    log({"kind": "brainwallet", "chaves": nk, "hits": len(hits)})

    # --- plaintexts com padding valido dos dois logs, toda janela de 32 B, duas ordens, dois alvos
    P_ag, P_cr = plaintexts(LOG_AG), plaintexts(LOG_CR)
    P = P_ag | P_cr
    print(f"[plaintexts] agente={len(P_ag)} critico={len(P_cr)} uniao={len(P)}", flush=True)
    nwin = 0; phits = []
    for i, hx in enumerate(sorted(P)):
        b = bytes.fromhex(hx)
        nwin += 2 * max(0, len(b) - 31)
        for hh in O2.scan32(b, both_orders=True):
            rec = {"kind": "PRIVKEY_PLAINTEXT", "hex": hx, "hit": hh}
            phits.append(rec); log(rec); print("### HARD", rec, flush=True)
        if (i + 1) % 500 == 0:
            print(f"    {i+1}/{len(P)} janelas={nwin} t={time.time()-t0:.0f}s", flush=True)
    print(f"[plaintexts] janelas32_2ordens={nwin} hits={len(phits)} t={time.time()-t0:.0f}s", flush=True)
    res = {"kind": "resumo", "senhas_unicas": len(S_ag | S_cr), "chaves_brainwallet": nk,
           "hits_brainwallet": len(hits), "plaintexts": len(P), "janelas32_2ordens_2alvos": nwin,
           "hits_plaintext": len(phits), "alvos": sorted(O2.TARGETS.values()),
           "segundos": round(time.time() - t0, 1)}
    log(res); print(json.dumps(res, indent=2), flush=True)
    return 0 if not (hits or phits) else 1

if __name__ == "__main__":
    sys.exit(main())
