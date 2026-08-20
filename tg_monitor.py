# -*- coding: utf-8 -*-
"""
Monitor LOCAL do Telegram para o GSMG 5 BTC puzzle — roda no SEU PC.

Lê o grupo PRIVADO "GSMG Puzzle Solvers" (onde você é membro) e reporta só as
mensagens NOVAS desde a última execução, destacando as do criador. A nuvem não
consegue ler grupo privado; o seu PC consegue porque você está autenticado.

SEGURANÇA: suas credenciais e a sessão NUNCA saem da sua máquina. api_id/api_hash
vêm de variáveis de ambiente; o login (telefone + código) acontece no SEU terminal
na 1ª execução e fica salvo em .tg_session (gitignored). Nada disso passa por mim.

--------------------------------------------------------------------------------
SETUP (uma vez):
  1. pip install telethon           (py -3.12 -m pip install telethon)
  2. Pegue api_id e api_hash em  https://my.telegram.org  → "API development tools".
  3. Defina as variáveis de ambiente (PowerShell):
        $env:TG_API_ID = "1234567"
        $env:TG_API_HASH = "0123456789abcdef0123456789abcdef"
  4. Descubra o nome exato do grupo nos seus diálogos:
        py -3.12 tg_monitor.py --list
     (na 1ª vez ele pede seu telefone + o código que o Telegram te manda)
  5. Rode o monitor apontando pro grupo:
        py -3.12 tg_monitor.py --group "GSMG"

USO DIÁRIO (depois de logado, roda sem interação):
        py -3.12 tg_monitor.py --group "GSMG"
  Só mostra o que é novo desde a última vez. Escreve o digest em tg_digest.md.

AGENDAR NO WINDOWS (roda todo dia 07:05, sem abrir janela):
  schtasks /Create /SC DAILY /ST 07:05 /TN "GSMG Telegram" ^
    /TR "py -3.12 \"%CD%\tg_monitor.py\" --group GSMG"
  (rode a 1ª vez manualmente antes, para o login ficar salvo na sessão)
--------------------------------------------------------------------------------
"""
import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = HERE / ".tg_state.json"        # último msg-id visto por chat (gitignored)
SESSION = str(HERE / ".tg_session")    # sessão do Telethon (gitignored)
DEFAULT_OUT = HERE / "tg_digest.md"

# Criador do puzzle (Jrk Bgrt / @SoWut) — usado só para DESTACAR as mensagens dele.
# O id numérico vem do export result.json; nomes/usernames são o casamento principal.
CREATOR_NAMES = {"jrk bgrt", "sowut", "@sowut"}
CREATOR_IDS = {9815232}

# Palavras que sinalizam "dica/pista" — usadas só para marcar 🔑 (não filtram nada).
TIP_WORDS = [
    "hint", "clue", "prime", "yin", "yang", "give away", "giveaway", "password",
    "seed", "key", "matrix", "cosmic", "duality", "salphaseion", "architect",
    "dica", "pista", "chave", "solved", "solve", "door", "porta", "fresco",
]


def load_state() -> dict:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {}
    return {}


def save_state(state: dict) -> None:
    STATE.write_text(json.dumps(state), encoding="utf-8")


def is_creator(sender_name: str, sender_username: str, sender_id) -> bool:
    name = (sender_name or "").strip().lower()
    user = (sender_username or "").strip().lower().lstrip("@")
    if sender_id in CREATOR_IDS:
        return True
    if name in CREATOR_NAMES or user in {n.lstrip("@") for n in CREATOR_NAMES}:
        return True
    return False


def tag_message(text: str, creator: bool) -> str:
    """Prefixo do item no digest: 👑 criador, 🔑 contém palavra-dica, • normal."""
    if creator:
        return "👑"
    low = (text or "").lower()
    if any(w in low for w in TIP_WORDS):
        return "🔑"
    return "•"


def render_digest(chat_name: str, items: list, now_utc: str) -> str:
    """items: lista de dicts {when,name,text,creator}. Retorna markdown pt-BR."""
    creator_hits = [i for i in items if i["creator"]]
    tip_hits = [i for i in items if not i["creator"] and tag_message(i["text"], False) == "🔑"]
    lines = [f"### GSMG Telegram — {chat_name} — {now_utc}"]
    if not items:
        lines.append("- **Sem novidades** desde a última execução.")
        lines.append("- **Para o GPT:** nada a passar hoje.")
        return "\n".join(lines) + "\n"
    lines.append(f"- **TL;DR:** {len(items)} msg(s) nova(s) — "
                 f"{len(creator_hits)} do criador 👑, {len(tip_hits)} com termo-dica 🔑.")
    lines.append("")
    for i in items:
        tag = tag_message(i["text"], i["creator"])
        text = " ".join((i["text"] or "").split())
        if len(text) > 500:
            text = text[:500] + "…"
        lines.append(f"{tag} `{i['when']}` **{i['name']}**: {text}")
    lines.append("")
    lines.append("- **Para o GPT:** se algo acima for hint real do criador (👑) ou "
                 "achado técnico novo, formule 1–2 hipóteses concretas e testáveis "
                 "(cifra + parâmetros), no estilo do fluxo Claude⇄GPT. Senão: nada a passar.")
    return "\n".join(lines) + "\n"


def run(group_needle: str, limit: int, out_path: Path, list_only: bool) -> int:
    api_id = int(os.environ.get("TG_API_ID", "0") or "0")
    api_hash = os.environ.get("TG_API_HASH", "")
    if not api_id or not api_hash:
        print("ERRO: defina TG_API_ID e TG_API_HASH (pegue em https://my.telegram.org).",
              file=sys.stderr)
        return 2
    try:
        from telethon.sync import TelegramClient
    except ImportError:
        print("ERRO: telethon não instalado. Rode:  py -3.12 -m pip install telethon",
              file=sys.stderr)
        return 2

    now_utc = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with TelegramClient(SESSION, api_id, api_hash) as client:
        if list_only:
            print("Seus diálogos (nome — id):")
            for d in client.iter_dialogs():
                print(f"  {d.name!r} — {d.id}")
            return 0

        target = None
        needle = group_needle.lower()
        for d in client.iter_dialogs():
            if needle in (d.name or "").lower():
                target = d
                break
        if target is None:
            print(f"ERRO: nenhum diálogo contém {group_needle!r}. "
                  f"Rode --list para ver os nomes exatos.", file=sys.stderr)
            return 3

        chat_id = str(target.id)
        state = load_state()
        last_id = int(state.get(chat_id, 0))

        items, max_id = [], last_id
        for m in client.iter_messages(target.entity, min_id=last_id, limit=limit):
            max_id = max(max_id, m.id)
            if not m.message:
                continue
            sender = m.sender
            name = getattr(sender, "first_name", None) or getattr(sender, "title", None) or "?"
            if getattr(sender, "last_name", None):
                name = f"{name} {sender.last_name}"
            username = getattr(sender, "username", None)
            when = m.date.strftime("%Y-%m-%d %H:%M") if m.date else "?"
            items.append({
                "when": when,
                "name": name,
                "text": m.message,
                "creator": is_creator(name, username, getattr(sender, "id", None)),
            })
        items.reverse()  # cronológico (mais antigo → mais novo)

        digest = render_digest(target.name or group_needle, items, now_utc)
        out_path.write_text(digest, encoding="utf-8")
        print(digest)

        if max_id > last_id:
            state[chat_id] = max_id
            save_state(state)
        return 0


def _selftest() -> None:
    # round-trip do estado
    import tempfile
    global STATE
    orig = STATE
    STATE = Path(tempfile.gettempdir()) / "_tg_state_test.json"
    try:
        save_state({"123": 42})
        assert load_state() == {"123": 42}
        STATE.unlink()
        assert load_state() == {}
    finally:
        STATE = orig
    # detecção de criador
    assert is_creator("Jrk Bgrt", None, None)
    assert is_creator("x", "SoWut", None)
    assert is_creator("x", None, 9815232)
    assert not is_creator("Random Solver", "randomguy", 42)
    # marcação
    assert tag_message("qualquer prime aqui", False) == "🔑"
    assert tag_message("bom dia", False) == "•"
    assert tag_message("oi", True) == "👑"
    # digest vazio vs com itens
    assert "Sem novidades" in render_digest("G", [], "now")
    d = render_digest("G", [{"when": "t", "name": "Jrk Bgrt", "text": "prime hint",
                             "creator": True}], "now")
    assert "👑" in d and "TL;DR" in d
    print("selftest OK")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Monitor local do Telegram (GSMG).")
    ap.add_argument("--group", default="GSMG", help="parte do nome do grupo/canal")
    ap.add_argument("--limit", type=int, default=300, help="máx de msgs a varrer por run")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="arquivo do digest")
    ap.add_argument("--list", action="store_true", help="lista seus diálogos e sai")
    ap.add_argument("--selftest", action="store_true", help="testa a lógica pura e sai")
    args = ap.parse_args(argv)
    if args.selftest:
        _selftest()
        return 0
    return run(args.group, args.limit, Path(args.out), args.list)


if __name__ == "__main__":
    raise SystemExit(main())
