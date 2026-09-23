# F3 — `sem_zero_integral`: todos os caminhos de cada modelo sem-zero, não só o melhor

Campanha `enxame_2026-09-19` (contrato em `../spec.json`). Frente de recuperação de cobertura sobre
a linha "Codificações sem zero" da tabela §4-B do `ENDGAME.md`, marcada **cobertura parcial**:
*"DBBI admite 192.969 modelos compatíveis e só o melhor caminho de cada foi testado"*.

**Procedência.** Frente executada por subagente, impedida pelo harness de escrever relatórios; este
`FINDINGS.md` foi materializado pelo coordenador a partir do texto devolvido.
**Conferências do coordenador:** a contagem de modelos reconcilia com a histórica
(78.480 fwd + 114.480 rev = **192.960** ASCII; + 9 CP1141 = **192.969**, o número exato da §4-B), e a
taxa de padding observada bate com o ruído (**0,386 %** contra 1/255 = 0,392 %), o que valida o
pipeline. A DP de comprimento **não** foi reimplementada de forma independente.

## Hipótese

Dos 192.969 modelos "código decimal com zeros apagados" compatíveis com `dbbi`, testar **só o melhor
caminho de cada** podia ter escondido um acerto num caminho alternativo.

## Método

Reuso de `machine()`/`eachPermutation()` de `solver/zero_free_numerals.cjs` (código já testado), com
reprodução exata dos totais históricos como **controle de fidelidade**. Para cada modelo, uma **DP
exata sobre o comprimento de saída** decide, sobre **todos** os caminhos e sem enumerá-los, quais
comprimentos de texto são alcançáveis — o mesmo teste de limiar exato usado em §6, aplicado a
comprimento em vez de escore. Isto substitui o escore de quadgramas, indisponível neste container.

## Resultado por comprimento-alvo

| alvo | alcançável em | observação |
|---|---|---|
| **32 B (escalar cru)** | **0 / 192.960** | **impossibilidade estrutural provada**: o mínimo global de comprimento é **44**, acima de 32. Nenhum teste de privkey foi necessário. |
| 51 / 52 (WIF) | 192.960 / 192.960 | caminhos exatos: 1.213.431.434.168.112 e 8.518.623.760.800.576 — **inviável materializar** |
| 64 | 192.240 / 192.960 | 720 modelos não alcançam (decidido por DP). Só 41 modelos têm ≤ 4.000 caminhos |

Dos 41 modelos tratáveis em 64, foram materializados os **6.314 caminhos exatos** → **404.096 senhas
distintas de 64 B**. (Um bug de truncamento na expansão de colisões de código foi encontrado e
corrigido **antes** do teste.)

## Oráculo duro

404.096 senhas × 3 blobs × 2 KDF = **2.424.576 decisões AES**: **0 hits duros.**
9.368 paddings válidos por acaso (0,386 %) — ruído, compatível com 1/255, e registrados como tal.

## Controles e nulo

- **Positivo 1:** `causality` / KDF do kit — passou.
- **Positivo 2:** senha real plantada entre os próprios candidatos, blob sintético cifrado com ela, e
  o pipeline a **recuperou**.
- **Nulo casado: N/A justificado** — a DP é determinística e exaustiva sobre os caminhos, conforme a
  regra do `spec.json`.

```
node solver/enxame_2026_09_19/sem_zero_integral/full_paths.cjs
python3 solver/enxame_2026_09_19/sem_zero_integral/test_oracle.py
```

Saídas: `summary.json`, `oracle_results.json`, e `candidates.jsonl` (101 MB, fora do Git pelo
`.gitignore`).

## O que foi de fato fechado, e o que não foi

**Fechado por prova:** o alvo de **32 bytes** é estruturalmente inalcançável em todos os 192.960
modelos ASCII — o mínimo de comprimento é 44. Esse braço da família não precisa mais ser varrido.

**Lacuna restante, quantificada e não fechada:**
- comprimentos **51/52** (WIF) em todos os 192.960 modelos: ~1,2 × 10¹⁵ e ~8,5 × 10¹⁵ caminhos;
- **64** em 192.199 dos 192.240 modelos alcançáveis: ~5,8 × 10¹⁹ caminhos;
- **CP1141** (9 modelos, 0,0047 %): sem insumo neste clone (`encoding.json` ausente).

Portanto a linha §4-B **continua parcial**, mas agora com a parcialidade medida: o que falta não é
"o resto dos caminhos", é um espaço de 10¹⁵–10¹⁹ caminhos que nenhum orçamento materializa por
enumeração. Fechá-lo exigiria um teste de limiar sobre o **conteúdo** (como o de §6 para a1z26), não
sobre o comprimento — e esse teste precisa de um scorer, que este container não tem.

Nada aqui é solução: negativo com cobertura exata.
