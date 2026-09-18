# -*- coding: utf-8 -*-
"""
Monitor de pistas novas do GSMG 5 BTC puzzle — site + Telegram, em uma passada.

Uso:
    python solver/monitor_pistas.py            # roda e imprime o digest
    python solver/monitor_pistas.py --selftest # checagem mínima da lógica

O que faz:
1. SITE: baixa as páginas conhecidas de gsmg.io e compara o sha256 do corpo com a
   captura de referência de 2026-09-08 (`_work/gsmg_live_2026-09/`). Qualquer byte
   diferente é NOVIDADE; o corpo novo é salvo em `_work/monitor_pistas/` para diff.
   Uma URL-sentinela inexistente confere que o 404 continua sendo "Hello :-)".
2. TELEGRAM: se `TG_API_ID`/`TG_API_HASH` estiverem definidos e a sessão
   `.tg_session*` existir, roda `tg_monitor.py` (mensagens novas do grupo, criador em
   destaque). Senão, avisa como configurar e deixa a leitura manual para o Claude
   (Telegram Desktop via computer-use).

Só stdlib. Estado e saídas ficam em `_work/monitor_pistas/` (gitignored).
"""
import datetime as _dt
import hashlib
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "_work" / "monitor_pistas"
TG_MONITOR = REPO / "tg_monitor.py"
TG_GROUP = "GSMG Puzzle Solvers"
UA = "gsmg-monitor-pistas/1.0 (+devjotaduo)"
TIMEOUT = 25

HELLO_404 = "4641333e9699e25eb72091a08cb77797c8822281e360d7cf88894c413fa6c788"

# url -> sha256 do corpo na captura de referência (2026-09-08, Last-Modified 2026-08-15/17)
BASELINE = {
    "https://gsmg.io/": "2f896807a859e2f71a2f6e1e8277986af73b80dc0dd79a685a67c7f7f8c3303b",
    "https://gsmg.io/puzzle": "38125bbdf1ea58b9b30b075bc6bf71e4089d04bba37098317e47097e2f2a1830",
    "https://gsmg.io/theseedisplanted": "7cb766d406008a397f8ae32b3a38ca68b42724bb07b3481deb84baad5c725183",
    "https://gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself":
        "06fbd4461ab20d45c54a7053c7c0cfa256ba82a5ad4c73a47fac67f3f1cdf7d9",
    "https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32":
        "a83d3de7810f26b19b4965339b76d403e44f6b6877e5d7de2555480ca1779d77",
    "https://gsmg.io/robots.txt": "17ccdd08e8d3fd2d343f0a6c6b6751114cca0fa1885a606813b71ee8c0c04144",
    "https://gsmg.io/phase1verification": HELLO_404,          # era 404 "Hello :-)"
    "https://gsmg.io/__sentinela_monitor_pistas__": HELLO_404,  # nunca existiu: 404 esperado
}


def fetch(url: str) -> tuple[int, bytes, str]:
    """(status, corpo, Last-Modified). Erros HTTP devolvem o corpo do erro; falha de rede → status 0."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(), r.headers.get("Last-Modified", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Last-Modified", "")
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e).encode(), ""


def compare_site(fetcher=fetch, baseline=BASELINE) -> list[dict]:
    """Uma linha por URL: {url, status, sha, changed, last_modified, body}."""
    rows = []
    for url, ref in baseline.items():
        status, body, lm = fetcher(url)
        sha = hashlib.sha256(body).hexdigest()
        rows.append({"url": url, "status": status, "sha": sha, "last_modified": lm,
                     "changed": status == 0 or sha != ref, "body": body})
    return rows


def run_telegram() -> tuple[bool, str]:
    """(configurado?, texto). Só roda tg_monitor.py se credenciais e sessão existirem."""
    has_env = bool(os.environ.get("TG_API_ID")) and bool(os.environ.get("TG_API_HASH"))
    has_session = any(REPO.glob(".tg_session*"))
    if not (has_env and has_session):
        return False, ("Telegram automático NÃO configurado (faltam TG_API_ID/TG_API_HASH e/ou a sessão "
                       "`.tg_session`; ver docstring de tg_monitor.py). Ler o grupo manualmente.")
    proc = subprocess.run([sys.executable, str(TG_MONITOR), "--group", TG_GROUP],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=300, cwd=str(REPO))
    if proc.returncode != 0:
        return True, f"tg_monitor.py falhou (rc={proc.returncode}):\n{proc.stderr.strip()}"
    return True, proc.stdout.strip()


def render(rows: list[dict], tg_ok: bool, tg_text: str, now: str, saved: dict) -> str:
    changed = [r for r in rows if r["changed"]]
    lines = [f"# Monitor de pistas — {now}", ""]
    lines.append(f"RESULTADO: {'NOVIDADE NO SITE (' + str(len(changed)) + ')' if changed else 'SITE SEM MUDANÇA'}"
                 f" | TELEGRAM {'automático' if tg_ok else 'manual'}")
    lines.append("")
    lines.append("## Site gsmg.io (sha256 vs captura 2026-09-08)")
    for r in rows:
        mark = "⚠️ MUDOU" if r["changed"] else "ok"
        extra = f" → salvo em `{saved[r['url']]}`" if r["url"] in saved else ""
        lines.append(f"- {mark} `{r['url']}` HTTP {r['status']} {r['last_modified']} "
                     f"sha `{r['sha'][:16]}`{extra}")
    lines += ["", "## Telegram — grupo GSMG Puzzle Solvers", tg_text, ""]
    return "\n".join(lines) + "\n"


def main() -> int:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    rows = compare_site()
    saved = {}
    for r in rows:
        if r["changed"] and r["status"]:
            slug = r["url"].rstrip("/").rsplit("/", 1)[-1][:40] or "root"
            p = OUT_DIR / f"diff_{stamp}_{slug}.bin"
            p.write_bytes(r["body"])
            saved[r["url"]] = p.relative_to(REPO).as_posix()

    tg_ok, tg_text = run_telegram()
    digest = render(rows, tg_ok, tg_text, now, saved)
    (OUT_DIR / "ultimo.md").write_text(digest, encoding="utf-8")
    (OUT_DIR / f"digest_{stamp}.md").write_text(digest, encoding="utf-8")
    print(digest)
    return 0


def _selftest() -> None:
    base = {"https://x/a": hashlib.sha256(b"A").hexdigest(),
            "https://x/b": hashlib.sha256(b"B").hexdigest(),
            "https://x/c": hashlib.sha256(b"C").hexdigest()}
    live = {"https://x/a": (200, b"A", "lm"), "https://x/b": (200, b"B2", "lm"), "https://x/c": (0, b"erro", "")}
    rows = compare_site(lambda u: live[u], base)
    assert [r["changed"] for r in rows] == [False, True, True], rows
    txt = render(rows, False, "manual", "agora", {"https://x/b": "_work/x.bin"})
    assert "NOVIDADE NO SITE (2)" in txt and "_work/x.bin" in txt and "TELEGRAM manual" in txt
    txt2 = render([rows[0]], True, "nada", "agora", {})
    assert "SITE SEM MUDANÇA" in txt2 and "TELEGRAM automático" in txt2
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        sys.exit(main())
