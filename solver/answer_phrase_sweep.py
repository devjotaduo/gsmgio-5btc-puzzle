# -*- coding: utf-8 -*-
"""
Fecha a ultima porta deterministica: as frases a-o DECODIFICADAS como 'ANSWER'
do pipeline (ENDGAME: sha256(first hint)->decodifica->ANSWER->sha256(ANSWER)->AES).
Testa lastwordsbeforearchichoice / thispassword em formas concatenadas.
"""
import hashlib, json, os, itertools
import oracles as O

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_work", "answer_phrase_sweep.jsonl")

LW = "lastwordsbeforearchichoice"
TP = "thispassword"
# frases da pagina que compoem o "ANSWER" possivel
PARTS = {
    "lastwords": LW,
    "thispass": TP,
    "concat": LW + TP,
    "concat_sp": LW + " " + TP,
    "rev": TP + LW,
    "enter_lw_tp": "enter" + LW + TP,
    "firsthint_lw": "ourfirsthintisyourlastcommand" + LW,
    "both_spaced": "last words before archi choice this password",
}

def variants(s):
    seen = set()
    for f in (s, s.lower(), s.upper(), s.replace(" ", ""), s.title().replace(" ", "")):
        if f and f not in seen:
            seen.add(f); yield f

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    log = open(OUT, "w", encoding="utf-8"); tried = 0; hits = []
    for label, s in PARTS.items():
        for v in variants(s):
            for mode in ("sha256hex", "raw", "double_sha256"):
                if mode == "sha256hex":
                    pw = hashlib.sha256(v.encode()).hexdigest()
                elif mode == "double_sha256":
                    pw = hashlib.sha256(hashlib.sha256(v.encode()).hexdigest().encode()).hexdigest()
                else:
                    pw = v
                h = O.aes_open(pw); tried += 1
                rec = {"label": label, "variant": v[:40], "mode": mode, "hits": h}
                log.write(json.dumps(rec, ensure_ascii=False) + "\n")
                if h:
                    hits.append(rec); print(f"!!! HIT: {label}/{mode} -> {h}")
    log.close()
    print(f"\n[sweep] {tried} candidatos (SMALL+COSMIC), log em {OUT}")
    print(f"[sweep] HITS: {hits if hits else 'NENHUM'}")
    print("\n=== VEREDITO ===")
    print("ABRIU!" if hits else "Frases-ANSWER decodificadas esgotadas -> NEGATIVO. Porta fechada.")

if __name__ == "__main__":
    main()
