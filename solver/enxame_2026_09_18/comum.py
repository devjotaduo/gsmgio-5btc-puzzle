# -*- coding: utf-8 -*-
"""Executor comum das frentes de teste da campanha enxame_2026-09-18.

A frente gera as senhas-base e chama `testar(bases, ...)`. Cada base vira as formas pedidas
(`raw`, `sha256hex` = a gramática das fases 2–3.2), as senhas repetidas são descartadas e cada
senha única passa por G.try_password_all: 3 blobs × 2 KDF, privkey embutida dos dois alvos e blob
aninhado. `controle_positivo()` abre a fase 2 pelo mesmo caminho de código. O kit é importado
pelo caminho relativo a este arquivo (AGENTS.md, "Kit"), então roda igual em qualquer worktree.

Uso numa frente:
    import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    import comum as C
    if __name__ == "__main__":          # obrigatório no Windows (spawn)
        C.controle_positivo()
        r = C.testar(bases, rotulo="minha_frente")
"""
import os, sys, math, hashlib, subprocess
from multiprocessing import Pool

KIT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "experiments", "claude_endgame_2026_09_02"))
sys.path.insert(0, KIT)
import gsmg_common as G

# ponytail: registrado na importação para existir também nos processos filhos (spawn).
G.BLOBS.setdefault("PHASE2", G._parse(G.PHASE2_B64))

FORMAS = {
    "raw": lambda b: b,
    "sha256hex": lambda b: hashlib.sha256(b).hexdigest().encode(),
    "sha256HEX": lambda b: hashlib.sha256(b).hexdigest().upper().encode(),
}
BLOBS_PREMIO = ("SMALL", "COSMIC", "TAIL32")
TAXA_PADDING = sum(256.0 ** -j for j in range(1, 17))  # ≈ 1/255, ENDGAME §3.9


def _bytes(s):
    return s if isinstance(s, bytes) else s.encode("utf-8")


def _um(args):
    senha, blobs, kdf = args
    hard, soft = G.try_password_all(senha, blobs, kdf)
    return (senha, hard, soft) if (hard or soft) else None


def senhas_de(bases, formas):
    """Senha única -> (base, forma) da primeira origem, na ordem de entrada."""
    origem = {}
    for base in bases:
        b = _bytes(base)
        for f in formas:
            origem.setdefault(FORMAS[f](b), (b, f))
    return origem


def testar(bases, formas=("raw", "sha256hex"), blobs=BLOBS_PREMIO, kdf="both",
           workers=8, rotulo=""):
    """Testa as bases nas formas pedidas. Devolve contagens, paddings (com o plaintext em hex,
    regra 5), candidatos (`hard` do kit = CANDIDATO, nunca solução) e o z do número de paddings
    contra a taxa de referência 1/255."""
    origem = senhas_de(bases, formas)
    n_kdf = 2 if kdf == "both" else 1
    n_aes = len(origem) * len(blobs) * n_kdf
    paddings, candidatos = [], []
    tarefas = ((s, blobs, kdf) for s in origem)
    with Pool(workers) as pool:
        for r in pool.imap_unordered(_um, tarefas, chunksize=512):
            if r is None:
                continue
            senha, hard, soft = r
            base, forma = origem[senha]
            meta = {"senha": senha.decode("latin-1"), "base": base.decode("utf-8", "replace"),
                    "forma": forma}
            for rec in hard:
                candidatos.append({**meta, **rec})
            for rec in hard + soft:
                paddings.append({**meta, **rec})
    esperado = n_aes * TAXA_PADDING
    z = (len(paddings) - esperado) / math.sqrt(esperado * (1 - TAXA_PADDING)) if n_aes else 0.0
    return {"rotulo": rotulo, "bases": len(set(map(_bytes, bases))), "senhas": len(origem),
            "blobs": list(blobs), "kdf": kdf, "formas": list(formas), "aes": n_aes,
            "paddings": len(paddings), "paddings_esperados": round(esperado, 2),
            "z_padding": round(z, 2), "candidatos": candidatos, "registros_padding": paddings}


def controle_positivo(workers=2):
    """A fase 2 abre com sha256hex('causality') pelo mesmo caminho de código das frentes."""
    r = testar(["causality"], formas=("sha256hex",), blobs=("PHASE2",), kdf="sha256",
               workers=workers, rotulo="controle_fase2")
    ok = any(c["head"].startswith("The ironic") for c in r["candidatos"])
    assert ok, "controle positivo falhou: a fase 2 não abriu"
    return r


def commit_do_kit():
    """Commit e sha256 do kit, para o relatório (AGENTS.md, "Kit")."""
    kit = os.path.join(KIT, "gsmg_common.py")
    h = hashlib.sha256(open(kit, "rb").read()).hexdigest()
    try:
        c = subprocess.run(["git", "-C", KIT, "rev-parse", "HEAD"], capture_output=True,
                           text=True, timeout=10).stdout.strip()
    except Exception:
        c = "?"
    return {"commit": c, "kit_sha256": h}


if __name__ == "__main__":
    r = controle_positivo()
    assert r["senhas"] == 1 and r["candidatos"], r
    # senhas repetidas entre formas somam uma vez; o nulo aleatório não gera candidato
    assert len(senhas_de(["a", "a", b"a"], ("raw",))) == 1
    ruido = testar([os.urandom(12).hex() for _ in range(3000)], rotulo="ruido")
    assert not ruido["candidatos"], ruido["candidatos"][:1]
    assert abs(ruido["z_padding"]) < 5, ruido["z_padding"]
    print("comum OK:", {k: ruido[k] for k in ("senhas", "aes", "paddings", "paddings_esperados", "z_padding")},
          commit_do_kit())
