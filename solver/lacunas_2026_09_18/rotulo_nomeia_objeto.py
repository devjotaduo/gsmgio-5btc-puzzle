# -*- coding: utf-8 -*-
"""Teste do princípio "o rótulo nomeia um objeto", aplicado aos demais rótulos (2026-09-18).

A hipótese das 28 somas mostrou o valor de inverter a função do rótulo: em vez de `matrixsumlist` ser a
operação que decifra o resíduo, o resíduo SERIA o objeto que o rótulo nomeia. Aquilo foi testado e deu
negativo. Aqui o mesmo princípio vai para os outros rótulos da página — `lastwordsbeforearchichoice`,
`thispassword` — e para os objetos que eles nomeiam, não para as letras deles.

O teto algébrico aqui é mais afiado que o das somas, e vem de uma observação sobre o próprio resíduo:

    o resíduo usa só os símbolos a..i, e NUNCA `o`. Na convenção da página (a=1..i=9, o=0), isso
    significa que a string de dígitos do resíduo NÃO CONTÉM NENHUM ZERO.

Em a1z26 concatenado, as únicas letras que produzem um dígito 0 são `j` (10) e `t` (20). Logo, se o
resíduo é a codificação a1z26 de um texto, esse texto **não pode conter `j` nem `t`** — e `t` é a
segunda letra mais frequente do inglês. O filtro é decidido antes de qualquer varredura.

Este script mede o efeito desse teto sobre o texto real que o rótulo nomeia (as janelas antes de
"choice" no transcript do Arquiteto) e testa as janelas sobreviventes contra os quatro alvos.
Uso: python rotulo_nomeia_objeto.py
"""
import hashlib, json, re, sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
OUT = REPO / "_work" / "residuo_como_somas_2026-09-18"
FONTES = [
    Path(r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\ChatExport_2026-09-08\files\MISC.txt"),
    Path(r"C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle"
         r"\bd1a3ae7-baeb-4498-9cf8-1a8d8944473a\scratchpad\marcadores\architect.txt"),
]
R84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
R83 = R84[:-1]
ALFA = "abcdefghi"
# os quatro alvos: resíduo em dígitos (a=1..i=9). Não há escolha de zero: o resíduo não tem `o`.
ALVOS = {"".join(str(ALFA.index(c) + 1) for c in s): nome
         for nome, s in (("L84", R84), ("L84_rev", R84[::-1]), ("L83", R83), ("L83_rev", R83[::-1]))}


def a1z26(texto):
    """letras -> números 1..26 concatenados. Devolve None se sair do alfabeto."""
    if not texto or not texto.isalpha():
        return None
    return "".join(str(ord(c) - 96) for c in texto.lower())


def janelas_antes_de_choice(texto):
    """Toda janela de 1..40 palavras que termina imediatamente antes de uma ocorrência de 'choice'."""
    palavras = re.findall(r"[A-Za-z]+", texto)
    idx = [i for i, p in enumerate(palavras) if p.lower() == "choice"]
    saida = []
    for i in idx:
        for k in range(1, 41):
            if i - k < 0:
                break
            saida.append("".join(palavras[i - k:i]).lower())
    return saida, len(idx)


def controle():
    """Um texto sem j/t codifica e volta; um texto com t produz zero (logo é impossível)."""
    limpo = "аbc"  # placeholder substituído abaixo
    limpo = "acegik"
    d = a1z26(limpo)
    assert "0" not in d and d == "1357911", d
    comt = a1z26("cat")
    assert "0" in comt, comt
    # e o resíduo realmente não tem zero nem `o`
    assert "o" not in R84 and all("0" not in a for a in ALVOS)
    return {"sem_jt_nao_gera_zero": True, "com_t_gera_zero": True, "residuo_sem_zero": True}


def main():
    ctl = controle()
    res = {"principio": "o rótulo nomeia um objeto a construir; o resíduo seria esse objeto codificado",
           "teto_algebrico": "o resíduo não tem `o`, logo sua string de dígitos não tem 0; em a1z26 só "
                             "j(10) e t(20) geram 0 -> o texto-fonte não pode conter j nem t",
           "controle": ctl, "alvos": list(ALVOS.values()), "fontes": {}}
    total_j = total_ok = total_len = total_hit = 0
    for f in FONTES:
        if not f.exists():
            res["fontes"][f.name] = {"erro": "ausente"}
            continue
        texto = f.read_text(encoding="utf-8", errors="replace")
        jan, n_choice = janelas_antes_de_choice(texto)
        sem_jt = [w for w in jan if "j" not in w and "t" not in w]
        cod = [(w, a1z26(w)) for w in sem_jt]
        comp_ok = [(w, d) for w, d in cod if d and len(d) in (60, 61)]
        hits = [(w, d, ALVOS[d]) for w, d in comp_ok if d in ALVOS]
        total_j += len(jan); total_ok += len(sem_jt); total_len += len(comp_ok); total_hit += len(hits)
        res["fontes"][f.name] = {
            "sha256": hashlib.sha256(f.read_bytes()).hexdigest()[:16],
            "ocorrencias_de_choice": n_choice, "janelas": len(jan),
            "sobrevivem_ao_filtro_j_t": len(sem_jt),
            "fracao_que_sobrevive": round(len(sem_jt) / max(1, len(jan)), 4),
            "com_comprimento_60_ou_61": len(comp_ok), "reconstroem_o_residuo": len(hits),
            "exemplos_sobreviventes": [w for w, _ in cod[:5]]}
    res["totais"] = {"janelas": total_j, "sem_j_nem_t": total_ok,
                     "comprimento_compativel": total_len, "reconstrucoes": total_hit}
    # os rótulos literais, para registro
    res["rotulos_literais"] = {}
    for r in ("lastwordsbeforearchichoice", "thispassword", "matrixsumlist", "yellowblueprimes",
              "causality", "thematrixhasyou", "enter", "yinyang"):
        d = a1z26(r)
        res["rotulos_literais"][r] = {"digitos": len(d), "tem_zero": "0" in d,
                                      "letras_proibidas": sorted(set(r) & {"j", "t"}),
                                      "reconstroi": d in ALVOS}
    res["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    OUT.mkdir(parents=True, exist_ok=True)
    json.dump(res, open(OUT / "rotulo_nomeia_objeto.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
