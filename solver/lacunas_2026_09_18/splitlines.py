# -*- coding: utf-8 -*-
"""Item 7 (lacunas 2026-09-18): conteúdos que a recoleta da §3.11 perdeu por str.splitlines().

retro_dois_alvos.collect() partia cada .jsonl com splitlines(), que também quebra em \\x85, U+2028 e U+2029
dentro das strings JSON (os logs gravam com ensure_ascii=False); o pedaço caía no except silencioso. O
collect() agora usa split("\\n"). Aqui:
  1. controle: uma linha sintética com \\x85 dentro de um campo some na coleta antiga e aparece na nova;
  2. coleta antiga (código do commit 2a535c6, via git show) × coleta corrigida sobre o checkout principal;
  3. a diferença passa pela varredura da frente orfaos_temp: raw32 BE/LE contra os dois alvos e
     scan.processar (hex64/WIF nas 7 visões, semântica, blob aninhado, ASCII ≥ 48 B);
  4. declara quantos desses conteúdos já estavam nos corpora da §3.12/§3.13.
Uso: python splitlines.py
"""
import hashlib, json, os, sqlite3, subprocess, sys, tempfile, time
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parents[1]
sys.path.insert(0, str(REPO / "solver" / "operador_ensinado_2026_09_17"))
sys.path.insert(0, str(REPO / "solver" / "enxame_2026_09_18" / "orfaos_temp"))
import retro_dois_alvos as R  # noqa: E402  collect() corrigido
import orfaos as O  # noqa: E402  trabalhar(): raw32 BE/LE + scan.processar; controle_raw32(); DBS

OUT = REPO / "_work" / "lacunas_2026-09-18" / "splitlines"
COMMIT_ANTIGO = "2a535c6"   # último commit com o collect() de splitlines()


def collect_antigo():
    src = subprocess.run(["git", "-C", str(REPO), "show", f"{COMMIT_ANTIGO}:solver/operador_ensinado_2026_09_17/retro_dois_alvos.py"],
                         capture_output=True, check=True).stdout.decode("utf-8")
    assert "txt.splitlines()" in src
    ns = {"__name__": "retro_antigo"}
    exec(compile(src, "retro_dois_alvos@" + COMMIT_ANTIGO, "exec"), ns)
    return ns


def controle_bug(antigo):
    """Linha JSONL com \\x85 e U+2028 num campo de texto: a coleta antiga perde o hex, a nova acha."""
    alvo = hashlib.sha256(b"lacunas splitlines").hexdigest() * 2
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "_work"))
        with open(os.path.join(tmp, "_work", "t.jsonl"), "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"head": "a\x85b c", "plain_hex": alvo}, ensure_ascii=False) + "\n")
            f.write(json.dumps({"plain_hex": alvo[::-1]}) + "\n")
        salvo = (R.ROOT, antigo["ROOT"])
        R.ROOT = antigo["ROOT"] = tmp
        try:
            velho, novo = antigo["collect"](), R.collect()
        finally:
            R.ROOT, antigo["ROOT"] = salvo
    assert velho == [alvo[::-1]] and sorted(novo) == sorted([alvo, alvo[::-1]]), (velho, novo)
    return {"coleta_antiga": len(velho), "coleta_corrigida": len(novo)}


def linhas_partidas():
    """Quantas linhas de .jsonl o splitlines() parte a mais que o split('\\n') (só arquivos com chave hex)."""
    import glob
    arqs, linhas, ilegiveis = 0, 0, []
    for pat in ("_work/**/*.jsonl", "solver/**/*.jsonl"):
        for p in glob.glob(os.path.join(R.ROOT, pat), recursive=True):
            try:
                txt = open(p, encoding="utf-8", errors="replace").read()
            except OSError as e:
                ilegiveis.append(f"{os.path.relpath(p, R.ROOT)}: {e}")  # o collect() também os pula
                continue
            if not any(f'"{k}"' in txt for k in R.HEXK):
                continue
            n = sum(len(l.splitlines()) > 1 for l in txt.split("\n"))
            arqs += n > 0
            linhas += n
    return {"arquivos": arqs, "linhas": linhas, "ilegiveis": ilegiveis}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    antigo = collect_antigo()
    ctl = {"bug_reproduzido_e_corrigido": controle_bug(antigo), "raw32_plantado": O.controle_raw32(),
           "alvos": O.controle_alvos()}
    velho, novo = set(antigo["collect"]()), set(R.collect())
    so_novo = sorted(novo - velho)
    dados = [bytes.fromhex(h) for h in so_novo]
    dbs = set()
    for rel in O.DBS.values():
        con = sqlite3.connect(f"file:{REPO / rel}?mode=ro&immutable=1", uri=True)
        dbs |= {r[0] for r in con.execute("select sha256 from payloads")}
        con.close()
    agg = O.trabalhar([(b, 0) for b in dados])
    res = {"item": 7, "commit_antigo": COMMIT_ANTIGO, "raiz": R.ROOT,
           "coleta_antiga": len(velho), "coleta_corrigida": len(novo), "so_na_corrigida": len(so_novo),
           "so_na_antiga": len(velho - novo), "bytes_so_na_corrigida": sum(map(len, dados)),
           "linhas_partidas_pelo_splitlines": linhas_partidas(),
           "nos_corpora_3.12_3.13": sum(hashlib.sha256(b).hexdigest() in dbs for b in dados),
           "varredura": {k: agg[k] for k in ("n", "bytes", "raw32_janelas", "raw32_validos", "validos_hexwif", "artefatos")}
           | {"tentativas_hexwif": dict(agg["tent"]), "motivos": dict(agg["motivos"]), "novos": dict(agg["novos"])},
           "hits": agg["hits"], "candidatos": [{k: c[k] for k in ("sha256", "len", "triagem", "orig_reasons", "visoes")}
                                               | {"texto": bytes.fromhex(c["hex"])[:160].decode("latin-1")}
                                               for c in agg["candidatos"]],
           "sha256_conteudos": hashlib.sha256(b"".join(hashlib.sha256(b).digest() for b in dados)).hexdigest(),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           "retro_dois_alvos_sha256": hashlib.sha256(Path(R.__file__).read_bytes()).hexdigest(),
           "segundos": round(time.monotonic() - t0, 1)}
    json.dump(res, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(ctl, open(OUT / "controls.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k not in ("candidatos",)}, ensure_ascii=False, indent=1)[:3000])


if __name__ == "__main__":
    main()
