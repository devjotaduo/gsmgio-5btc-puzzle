# -*- coding: utf-8 -*-
"""
PASSE 3 da familia bifid3x3_exhaustive — mede o MELHOR LEGIVEL (best_readable).

Os passes 1/2 so registravam decodes que PASSAVAM em G.semantic_text (nenhum passou). Aqui
reexecuto o downstream completo nos 20 melhores candidatos de faed e dbbi (por z_Hcond) e
registro o maximo de english_score independentemente de passar, para reportar honestamente
"quao perto" ficou. Controle positivo: o checkerboard real da fase 3.2.2 (texto do Arquiteto)
codificado em a-i tem de pontuar muito acima de qualquer candidato.
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gsmg_common as G

SP = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(SP, "bifid3x3_exhaustive.jsonl")
S = json.load(open(os.path.join(SP, "bifid3x3_exhaustive_summary.json")))
CB_ALPHAS = {"FUBCDORA": G.keyed_alphabet("FUBCDORALETHINGKYMVPS"), "CANON": G.CANON,
             "AZ": "ABCDEFGHIKLMNOPQRSTUVWXYZ"}
ESC = [(a, b) for a in range(1, 10) for b in range(a + 1, 10)]
N = 0
def decodes(out, how):
    """Todos os decodes textuais; devolve (score, texto, como)."""
    global N
    best = (-99, "", "")
    digs = G.digits(out)
    for an, alpha in CB_ALPHAS.items():
        for esc in ESC:
            t = G.checkerboard_decode(digs, alpha, esc); N += 1
            s = G.english_score(t)
            if s > best[0]: best = (s, t[:160], f"{how}|cb[{an}]esc{esc[0]}{esc[1]}")
    for m in ("decrypt", "encrypt"):
        t = G.bifid(out, G.CANON, None, 5, m); N += 1
        s = G.english_score(t)
        if s > best[0]: best = (s, t[:160], f"{how}|bif5CANON {m}")
    b = G.z_method(digs); N += 1
    pr = G.printable(b)
    return best, pr

# controle positivo: checkerboard real (fase 3.2.2) sobre o texto do Arquiteto
readme = open(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\README.md", encoding="utf-8").read()
i0 = readme.index("NOW TO RETURN TO THE SOURCE CODES")
ARCH = re.sub("[^A-Z]", "", readme[i0:i0 + 2500].upper().replace("J", "I"))
def cb_encode(pt, alphabet, escapes):
    top = [d for d in "123456789" if int(d) not in escapes]
    need = len(top) + 18; alphabet = (alphabet + "." * need)[:need]
    m = {}; k = 0
    for d in top: m[alphabet[k]] = [int(d)]; k += 1
    for e in escapes:
        for d in "123456789": m[alphabet[k]] = [e, int(d)]; k += 1
    return [d for c in pt if c in m for d in m[c]]
CTRL = "".join(chr(96 + d) for d in cb_encode(ARCH, G.CANON, (1, 4)))[:570]
cb, _ = decodes(CTRL, "CONTROL")
print("CONTROLE best_readable:", round(cb[0], 3), cb[2], "|", cb[1][:60])
G.jsonl(LOG, {"kind": "pass3_control", "score": cb[0], "how": cb[2], "text": cb[1][:120]})

rows = []
for label, txt, key in (("faed", G.FAED, "faed_top"), ("dbbi", G.DBBI, "dbbi_top")):
    for r in S[key]:
        out = G.bifid(txt, r["square"], r["period"], 3, r["mode"])
        how = f"bifid3[{r['square']}] p={r['period']} {r['mode']} {label} zH={r['z_class'][0]:.2f}"
        best, pr = decodes(out, how)
        rows.append({"label": label, "how": how, "score": best[0], "best_how": best[2],
                     "text": best[1], "z_printable": round(pr, 3)})
rows.sort(key=lambda x: -x["score"])
for r in rows[:5]: print(round(r["score"], 3), r["best_how"], "|", r["text"][:60])
G.jsonl(LOG, {"kind": "pass3_best_readable", "n_decodes": N, "control_score": cb[0],
              "top": rows[:10], "max_z_printable": max(r["z_printable"] for r in rows)})
json.dump({"n_decodes": N, "control": {"score": cb[0], "how": cb[2], "text": cb[1][:120]},
           "top": rows[:10]}, open(os.path.join(SP, "bifid3x3_pass3.json"), "w"), indent=1)
print("n_decodes", N, "max z-printable", max(r["z_printable"] for r in rows))
