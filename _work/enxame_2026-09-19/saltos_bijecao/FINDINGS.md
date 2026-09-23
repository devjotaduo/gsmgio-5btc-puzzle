# F5 saltos_bijecao — saltos sobre `faed` com bijeção arbitrária

**Estado: negativo, cobertura parcial com fração exata declarada (NÃO é exaustão, e não é
reportada como tal).** 0 candidatos AES, 0 acertos de chave, em 1.120.000 materiais testados.

## Hipótese

O resíduo do lead `yellowblueprimes` (§6 do `ENDGAME.md`) é lido como uma lista de **saltos**
sobre `faed` (570 símbolos), com o mapa símbolo→valor sendo uma **bijeção arbitrária** a–i → 1–9
(em vez da canônica a=1…i=9, já fechada por exaustão em 2026-09-18). O resultado da seleção
(~60/61 símbolos de `faed`) é testado como senha (raw e sha256-hex) nos 3 blobs e como escalar de
32 B (sha256 do material) contra os dois alvos do prêmio.

## Convenção usada (reconstrução declarada)

O script original de `_work/residuo_saltos_2026-09-18/` não está neste checkout (scripts dentro
de `_work/` são ignorados pelo `.gitignore`, ver `AGENTS.md`); só sobrou o JSON de resultado. A
reconstrução abaixo foi verificada contra o **único controle concreto publicado**: os saltos
`[3,1,4]` a partir do offset 0 devolvem `"dgd"` sobre `faed` (`faedggeedfcbdabhhggcadcfeddgfdg…`).

- Posições em `faed`, 0-indexadas (0–569).
- **Âncora "depois"**: posição_k = offset + direção·cumsoma(valores[1..k]) para k=1..L (usa o
  k-ésimo salto). **Verificada** pelo controle `[3,1,4]`→`"dgd"` (offset 0, direção +1): dá
  `faed[3]='d'`, `faed[4]='g'`, `faed[8]='d'`.
- **Âncora "antes"**: posição_k = offset + direção·cumsoma(valores[1..k−1]) (posição 1 = offset,
  usa 0 saltos; o último valor do resíduo não é consumido). Extensão simétrica não coberta pelo
  controle publicado — **assunção declarada**, documentada aqui para reprodutibilidade.
- **Direção**: "frente" = +1, "trás" = −1.
- **Offset viável**: todo o percurso (todas as L posições) tem de cair em [0, 569], sem wrap.

Isso é uma reconstrução, não o script original — se ela diferir da convenção histórica em algum
detalhe de ±1, o `run.py` publicado aqui é a fonte de verdade do que foi de fato testado.

## Teto algébrico investigado (e por que não reduz o domínio)

Antes de rodar qualquer coisa, testamos se a bijeção poderia ser colapsada: se algum símbolo a–i
**não** aparecesse no resíduo, o valor atribuído a ele pelas 9! bijeções seria irrelevante para o
material gerado, e o espaço real de bijeções distintas cairia de 9! para 9!/(9−k)! (k = símbolos
usados). Checagem exaustiva das frequências:

```
L84: a:3 b:2 c:8 d:4 e:11 f:10 g:10 h:8 i:5   (9 símbolos distintos)
L83: a:3 b:2 c:8 d:4 e:10 f:10 g:10 h:8 i:5   (9 símbolos distintos)
```

**Os 9 símbolos aparecem nos dois resíduos.** Não há colapso por letra ausente: as 9! = 362.880
bijeções são todas potencialmente distintas em seu efeito sobre o material. Esse é um resultado
negativo próprio (nenhum atalho algébrico aqui), registrado para não ser reinvestigado.

## Aritmética de cobertura do domínio completo

Domínio declarado no prompt desta frente: 9! bijeções × {L83, L84} × 2 âncoras × 2 direções ×
todos os offsets viáveis (nenhum offset é eliminado por comprimento, porque a soma dos saltos
varia de 233 a 377 e sempre cabe nos 570 de `faed`).

Fórmula fechada (sem enumerar as 9!): para uma bijeção uniforme sobre 9 valores, o valor esperado
atribuído a qualquer símbolo é 5 (média de 1..9), por simetria. Logo, somado sobre as 362.880
bijeções, a soma dos offsets viáveis por combinação (âncora, direção, resíduo) é:

- **depois** (usa os L valores do resíduo): Σ offsets = 9!·(570 − 5·L)
- **antes** (usa os L−1 primeiros valores): Σ offsets = 9!·(570 − 5·(L−1))
- direção (+1/−1) dá a mesma contagem de offsets por simetria de alcance ⇒ ×2

Calculado por código (`run.py --mode arith`, sem enumerar as permutações):

| resíduo | Σ offsets "depois" (9!) | Σ offsets "antes" (9!) | subtotal (×2 direções) |
|---|---:|---:|---:|
| L84 (61 símbolos) | 96.163.200 | 97.977.600 | 388.281.600 |
| L83 (60 símbolos) | 97.977.600 | 99.792.000 | 395.539.200 |

**Domínio completo = 783.820.800 materiais.** Cada material exige, na convenção desta frente,
2 formas de senha (raw + sha256-hex) × 3 blobs = 6 tentativas AES (KDF SHA256; ver limite de KDF
abaixo) + 1 verificação de escalar (2 alvos, 2 formatos de pubkey) = **7 oráculos por material**,
ou seja **≈ 5,49 bilhões de decisões de oráculo** no domínio completo.

## Por que a exaustão não coube no orçamento

Com AES via `pycryptodome` em processo (sem subprocess) e verificação de chave via `coincurve`
(`G.fast_priv_scan`, ~30× mais rápida que `G.priv_hit`, que usa `ecdsa` puro), a taxa medida neste
container (1 processo, 4 cores, sem GPU) foi **≈ 1.860 materiais/s** em regime estável. Varrer os
783.820.800 materiais levaria **≈ 117 horas** de CPU de um processo — muito além dos 40 minutos e
do teto de 1 processo desta frente. Não há atalho algébrico disponível (seção anterior) nem
paralelismo permitido pelas regras do ambiente (`AGENTS.md`: no máximo 12 processos **somados**
entre todas as frentes do enxame).

## Redução declarada (o que foi de fato coberto)

Em vez de amostrar aleatoriamente (o defeito que esta frente existe para corrigir), a redução é
**sistemática e exatamente declarada**: para cada bijeção, resíduo, âncora e direção, testa-se
**um único offset representativo — o menor offset viável** (`off_min`), em vez de todos os
offsets viáveis daquela combinação. Isso cobre integralmente os quatro eixos discretos (bijeção,
resíduo, âncora, direção) e reduz só o eixo contínuo de offsets a 1 valor determinístico por
combinação (não aleatório, sempre reproduzível a partir do mesmo código).

KDF: só **SHA256** (não "both"). Regra 2 do `AGENTS.md`: "os blobs autenticados... abrem **só**
assim; MD5 é controle secundário" — e o autoteste de `gsmg_common.py` confirma que o blob real da
fase 2 abre com SHA256 e **não** com MD5. Omitir MD5 aqui é uma exclusão declarada (dobra o
throughput), não um descuido.

Execução real, interrompida pelo teto de tempo (600 s de cômputo, ver `run.log`):

```
python3 run.py --mode run --offsets 1 --max-seconds 600 \
    --out _work/enxame_2026-09-19/saltos_bijecao/result.json
```

| item | valor |
|---|---:|
| bijeções cobertas (de 362.880) | **140.000** |
| resíduos × âncoras × direções por bijeção | 8 (completos) |
| materiais gerados e testados | **1.120.000** (todos distintos) |
| senhas testadas (raw + sha256-hex) | 2.240.000 |
| tentativas AES (3 blobs × 1 KDF) | 6.720.000 |
| verificações de escalar (privkey) | 1.120.000 |
| tempo de CPU | 600,3 s |
| taxa | 1.865,6 materiais/s |

**Fração do domínio completo coberta: 1.120.000 / 783.820.800 = 0,1429 % (≈ 1/700).**
**Fração do eixo de bijeções coberta integralmente (8 combinações completas cada): 140.000 / 362.880 = 38,58 %.**
**Fração NÃO coberta do domínio completo: 99,8571 %.**

## Controles

- **Seleção**: saltos `[3,1,4]` a partir do offset 0 (âncora "depois", direção "frente") devolvem
  `"dgd"` — reproduz o único controle publicado da campanha anterior.
- **Fase 2** (KDF): `sha256hex("causality")` abre `G.PHASE2_B64` só via EVP-SHA256 (não via MD5),
  plaintext começa com `"The ironic 2name of the keymak"` — confirma o caminho de código do KDF
  usado no oráculo AES.
- **Chave plantada**: `sha256("controle-dois-alvos-saltos-bijecao")` injetado temporariamente em
  `TARGET_H160S` é recuperado por `G.fast_priv_scan` (o mesmo caminho de código usado para testar
  cada material) — confirma que o oráculo de chave não está cego.

Os três controles passam (`run.py --mode run`, seção `controle_selecao` / `controle_privkey_plantado`
do `result.json`).

## Nulo

**N/A justificado.** Esta frente não usa escore de texto como critério (ver limite abaixo); o
teste é o oráculo duro (padding PKCS7 + `semantic()` + privkey), que já tem calibração de ruído
conhecida (regra de ouro 1 do `AGENTS.md`: padding isolado é 1/255). Conferência: em 1.120.000
materiais × 2 senhas × 3 blobs = 6.720.000 tentativas AES-SHA256, o padding válido observado foi
**26.431**, contra **26.352,9 esperados** por acaso (6.720.000/255) — **z = 0,48**, ruído.

## Resultado no oráculo duro

- **AES (candidato = padding válido + `semantic()`)**: **0** em 1.120.000 materiais × 2 formas de
  senha × 3 blobs (SHA256 KDF).
- **Escalar/privkey** (`sha256(material)` contra os dois endereços do prêmio, comprimida e não):
  **0** em 1.120.000 materiais.
- Nenhum blob aninhado (`Salted__`/`U2FsdGVk`) entre os paddings válidos observados.

## Limitações declaradas

1. **Não é exaustão.** 99,86 % do domínio completo (definido no prompt desta frente, com todos os
   offsets viáveis) ficou fora. O que muda em relação à rodada de 2026-09-18 é que a redução aqui
   é **declarada, sistemática e exata** (não uma amostra de 199.951 materiais escolhida sem
   critério explícito) — mas continua sendo redução, não fechamento.
2. **MD5 não testado** nesta rodada (exclusão declarada, ver acima); a rodada de 2026-09-18 testou
   `kdf="both"`.
3. **Convenção da âncora "antes" e da direção "trás"** são extensão nossa, não verificada contra
   o script original (que não está neste checkout) — só a âncora "depois"/direção "frente" tem
   controle publicado herdado. `run.py` é a fonte de verdade reprodutível.
4. **Sem scorer de quadgramas** neste container (`result.json`/Telegram export ausentes; `solver/scorer.py`
   e `solver/primos_2026_09_17/clean_scorer.py` quebram aqui). Não usamos nenhum escore de texto
   como critério de triagem ou resultado — só o oráculo duro. O "melhor material" reportado no
   `result.json` usa um critério trivial (fração de vogais a/e/i) só para reprodutibilidade, **sem
   nenhum peso probatório**.
5. **1 processo, sem GPU**, conforme o teto do ambiente desta campanha; a extrapolação de tempo
   (≈117 h de CPU para o domínio completo) é medida, não estimada por fórmula teórica.

## O que fechar essa lacuna de verdade exigiria

Duas saídas honestas para uma futura frente, se a prioridade justificar o custo: (a) portar este
mesmo `run.py` para `solver/gpu_aes16_dbbi_hex/`-style em Go/OpenCL (a AES/privkey já são a parte
cara; em GPU o ganho esperado é de 2-3 ordens de magnitude, na linha dos 44 M/s citados em
`ENDGAME.md` §5 para outra campanha) — a ≈100k materiais/s o domínio completo cai para ≈2,2 h; ou
(b) provar um teto algébrico genuíno sobre o **efeito** da bijeção no oráculo (não encontrado
aqui: a checagem de letras ausentes, que teria dado um colapso 9!/(9−k)!, deu k=9 nos dois
resíduos — sem colapso). Nenhuma das duas coube no orçamento de 40 minutos desta frente.

## Arquivos

- `solver/enxame_2026_09_19/saltos_bijecao/run.py` — script completo (mecanismo, aritmética,
  execução, controles).
- `_work/enxame_2026-09-19/saltos_bijecao/result.json` — saída completa da execução (140.000
  bijeções, 1.120.000 materiais; inclui `aes_candidatos` e `priv_hits`, ambos vazios).
- `_work/enxame_2026-09-19/saltos_bijecao/run.log` — log de progresso (taxa por checkpoint de
  5.000 bijeções).
- kit: `solver/experiments/claude_endgame_2026_09_02/gsmg_common.py`
  (sha256 `f109cd8a41441d7439b18cf60ec72d465a3a446ae03260036672457136932c3a`), commit base
  `f035834`.
