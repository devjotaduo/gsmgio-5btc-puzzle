# Rodada de premissas — 2026-09-17

Scripts das cinco famílias que questionaram premissas do endgame (ver
`_work/frontier_2026-09-17/RELATORIO.md`, §4c). Todos usam o kit
`solver/experiments/claude_endgame_2026_09_02/gsmg_common.py` e o Python312.

| Script | Família | Resultado |
|---|---|---|
| `multicipher_attack.py` | 16 cifras/modos do `openssl enc` × corpus de 1,27 M formas | 122 M testes, 0 |
| `kfile_attack.py`, `lines_attack.py` | senha como 1.ª linha de arquivo (`-kfile`/`-pass file:`), digests, toda linha de texto | 767 k decifrações, 0 |
| `infrared_spectrum.py` | a–i como cores do espectro (nm/THz) | 11,9 M, 0 |
| `unicode_yinyang.py` | senhas Unicode (☯, CJK, emojis, UTF-8/16) | 4,5 M AES, 0 |
| `f2_segment.py`, `f3_html.py`, `f4_passwords.py` | forense de bytes dos plaintexts autênticos e HTMLs | nenhuma anomalia explorável |
| `retro_ebcdic.py` | varredura retroativa com a assinatura EBCDIC cp273 (crítico) | 431 k plaintexts, 0 |

Os caminhos de saída apontam para o scratchpad da sessão original; ajuste `HERE`/`OUT`
antes de reexecutar. Nenhuma senha final foi encontrada.
