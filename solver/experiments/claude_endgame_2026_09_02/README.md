# Snapshot Claude — endgame GSMG (2026-09-02)

Snapshot recuperado do scratchpad local da sessão Claude
`75ecc5a7-abb3-48d5-913f-974737310a51` em 2026-09-04.

O diretório foi mantido plano de propósito: vários experimentos importam
`gsmg_common.py` e leem corpus, modelos e resultados pelo diretório do próprio
arquivo. Separar fisicamente esses itens quebraria a reprodução das varreduras.

## Comece por aqui

- `BRIEFING.md`: mapa consolidado das hipóteses, controles e famílias fechadas.
- `gsmg_common.py`: dados canônicos, blobs, KDF/AES, oráculos, scores e cifras.
- `round3_inline.py`: bateria das leituras R1/R2/R3/R5.
- `symbol_map_variants.py`: mapas símbolo→valor e controles plantados.
- `running_key_gate.py`: triagem estatística de running keys.
- `external_running_key.py` e `erk_followup.py`: OCR de *Cosmic Duality*.
- `bifid3x3_exhaustive.py`, `bifid3x3_pass2.py` e `bifid3x3_pass3.py`:
  busca Bifid 3×3 e oráculo rápido de padding.
- `raising_variants.py`: variantes do parágrafo “Raising the stakes…”.

## Conteúdo preservado

- 76 scripts Python, incluindo utilitários, controles e ataques experimentais.
- 62 arquivos JSONL com resultados completos.
- corpus e extratos textuais usados pelas buscas.
- modelos/objetos `.pkl`, relatórios `.json`, logs e imagens diagnósticas.
- 287 arquivos originais, totalizando 75.061.891 bytes antes deste índice.

As saídas pesadas continuam presentes localmente, mas o `.gitignore` deste
diretório deixa versionáveis apenas os scripts e a documentação. Isso evita
adicionar acidentalmente cerca de 74 MB de resultados e material de consulta.

## Ambiente

Use o Python 3.12 documentado pelo projeto:

```powershell
& 'C:\Users\ruthe\AppData\Local\Programs\Python\Python312\python.exe' .\solver\experiments\claude_endgame_2026_09_02\<script>.py
```

Os scripts preservados ainda dependem de `solver/oracles.py` e de outros dados
do repositório. As referências que apontavam para `%LOCALAPPDATA%\Temp\claude`
foram atualizadas para este diretório.

## Proveniência

- Transcript da sessão:
  `C:\Users\ruthe\.claude\projects\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle\75ecc5a7-abb3-48d5-913f-974737310a51.jsonl`
- Memória consolidada:
  `C:\Users\ruthe\.claude\projects\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle\memory\endgame-map-2026-09.md`

Nenhum resultado positivo foi encontrado nesta rodada. Consulte `BRIEFING.md`
antes de repetir uma família de ataque.
