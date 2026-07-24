# -*- coding: utf-8 -*-
"""
Sweep CANONICO do 'first hint' — so strings verbatim das instrucoes do criador.
Objetivo: fechar a porta 'sha256(first hint) -> senha AES' de vez.
NAO e chute de ingles aleatorio: lista autoritativa + transformacoes mecanicas.
Loga cada tentativa em _work/first_hint_sweep.jsonl. Testa SMALL e COSMIC.
"""
import hashlib, json, itertools, os
import oracles as O

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_work", "first_hint_sweep.jsonl")

# Matriz 14x14 da fase 1 (verbatim do README, linhas 43-56)
MATRIX_ROWS = [
    "0 0 1 1 0 1 0 0 1 0 1 1 0 0","1 1 1 1 0 0 1 1 1 0 1 0 1 1",
    "1 1 0 1 1 1 0 1 0 0 1 0 0 1","0 1 1 0 1 0 0 0 0 1 1 1 0 1",
    "0 1 1 0 0 0 1 1 0 0 0 1 1 0","1 0 0 1 1 0 0 0 1 0 0 0 1 1",
    "1 0 0 1 1 1 0 0 0 1 0 0 0 0","1 1 1 0 0 0 0 0 0 0 1 0 0 0",
    "0 0 0 1 1 1 0 1 1 1 1 1 0 1","1 1 1 1 1 1 0 0 1 1 0 0 0 1",
    "1 1 0 1 0 0 0 0 0 1 1 0 1 1","1 1 1 1 0 0 1 0 1 0 1 1 0 0",
    "0 1 0 1 1 1 0 1 0 0 0 1 1 0","0 1 1 0 1 1 0 1 1 0 1 0 1 1",
]
matrix_spaces = "\n".join(MATRIX_ROWS)
matrix_nospace = "".join(r.replace(" ", "") for r in MATRIX_ROWS)

URL_HASH = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
URL_SRC  = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
COLOR_PHRASE = ("Roses are White but often Red. Yellow has a number and so does Blue. "
                "Go back to the first puzzle piece without further ado.")

# base canonica: (label, string)
BASE = [
    ("url_hash_hex", URL_HASH),                       # <- o lead novo: hash da URL como senha
    ("url_src", URL_SRC),
    ("matrix_spaces", matrix_spaces),
    ("matrix_nospace", matrix_nospace),
    ("color_phrase", COLOR_PHRASE),
    ("first_hint", "our first hint is your last command"),
    ("first_hint_nospace", "ourfirsthintisyourlastcommand"),
    ("ans_too", "ans too"),
    ("anstoo", "anstoo"),
    ("shabef", "shabef"),
    ("followwhiterabbit", "followthewhiterabbit"),
]

def variants(label, s):
    """Transformacoes mecanicas (nao arbitrarias)."""
    seen = set()
    forms = [s, s.strip(), s.lower(), s.upper(), s.replace(" ", ""),
             s.replace("\n", ""), s.replace("\n", "").replace(" ", "")]
    for f in forms:
        if f and f not in seen:
            seen.add(f)
            yield f

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    log = open(OUT, "w", encoding="utf-8")
    tried = 0; hits = []
    for label, s in BASE:
        for v in variants(label, s):
            for mode in ("sha256hex", "raw"):
                pw = hashlib.sha256(v.encode()).hexdigest() if mode == "sha256hex" else v
                h = O.aes_open(pw)  # testa SMALL e COSMIC
                tried += 1
                rec = {"label": label, "variant": v[:50], "mode": mode, "hits": h}
                log.write(json.dumps(rec, ensure_ascii=False) + "\n")
                if h:
                    hits.append(rec)
                    print(f"!!! HIT: {label}/{mode} -> {h}")
    log.close()
    print(f"\n[sweep] {tried} candidatos testados (SMALL+COSMIC), log em {OUT}")
    print(f"[sweep] HITS: {hits if hits else 'NENHUM'}")
    print("\n=== VEREDITO ===")
    if hits:
        print("ABRIU! Ver hits acima. NAO decodificar alem sem confirmacao humana.")
    else:
        print("Todos os candidatos canonicos do 'first hint' esgotados -> NEGATIVO.")
        print("A senha AES nao e sha256/raw de nenhuma string verbatim das instrucoes.")

if __name__ == "__main__":
    main()
