# CLAUDE.md

@AGENTS.md

Notas só para o Claude Code:

- A memória persistente do projeto fica em
  `~/.claude/projects/C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle/memory/`
  (`MEMORY.md` é o índice). Ela registra preferências, ambiente e o estado do endgame;
  o que estiver no repositório (`ENDGAME.md`, relatórios) não se duplica lá.
- Skill `solve-phase` (`.claude/skills/solve-phase/`): reproduz o padrão sha256 → AES de
  qualquer fase. Agente `telegram-digger` (`.claude/agents/`): pesquisa o export do Telegram.
- Para ler mensagens novas do grupo sem export: Telegram Desktop via computer-use, busca
  "GSMG Puzzle Solvers", filtro "From: Jrk".
- Rotina diária de vigilância (tarefa agendada do app, id `gsmg-monitor-pistas`, 08:10 local):
  roda `solver/monitor_pistas.py` (diff do site + Telegram via `tg_monitor.py` se configurado),
  lê o grupo/Reddit e escreve `_work/monitor_pistas/relatorio_<data>.md`. Só reporta; não comita.
