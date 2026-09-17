# Lead da segmentação por primos de `dbbi` — 2026-09-17

Scripts da campanha sobre o resíduo da segmentação `b`/`be` nas posições lógicas primas
(ver `_work/frontier_2026-09-17/RELATORIO.md`, §4d). Kit: `solver/experiments/claude_endgame_2026_09_02/gsmg_common.py`.

| Script | Conteúdo |
|---|---|
| `resid_decoders.py` | checkerboard (todos os escapes, 27 alfabetos), Polybius/Bifid 3×3, a1z26, bases, índices em textos — no resíduo e nas sequências lógicas |
| `clean_scorer.py` | scorer de quadgramas **descontaminado** (descarta as mensagens do Telegram que contêm as próprias cifras a–i); `solver/scorer.py` aprendeu os quadgramas de `dbbi` (DIFH = −5,13) e infla qualquer leitura rica em a–i |
| `faed_primes__*.py` | a mesma regra de marcadores aplicada a `faed`: 4.248 variantes, nenhuma segmentação |
| `matrixsumlist_struct__*.py` | `matrixsumlist` estrutural sobre o resíduo (preenchimento da matriz, somas de grade, transposição, parâmetros 60/61) |
| `marcadores__*.py` | os 23 marcadores e as duas omissões como chave/seleção/parâmetro; 16/7/23 |
| `critic4*.py` | crítico: reprodução, look-elsewhere (2.925 regras), bits↔cores (p≈6×10⁻⁴), re-varredura de 4.384 paddings, resíduo como chave sobre `faed`, aleatoriedade do resíduo |

Resultado: o lead é um fato estrutural robusto, mas o resíduo é i.i.d. e nenhuma leitura simples,
nem a gramática SHA256 das fases 2–3.2 (60.005 concatenações), produz senha ou chave.
