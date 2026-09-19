# Enxame de 2026-09-19 — relatório da campanha

Contrato: [`spec.json`](spec.json). Coordenador: sessão remota do Claude Code (Linux).
Base: `66fecdc`. **Estado: 7 das 10 frentes fechadas; F1 (modos de fluxo), F2 (auditoria de fluxo) e
F5 (saltos com bijeção) ainda em execução — este relatório será completado quando fecharem.**

> **Resultado no oráculo duro: 0.** Nenhum blob foi aberto e nenhuma chave dos dois alvos foi
> encontrada. O produto desta campanha é **cobertura e correção do mapa**, não solução — como o
> `spec.json` declarou antes de abrir as frentes.

## 1. Por que esta campanha pôde abrir

A regra 3 do `AGENTS.md` só admite campanha nova com insumo novo do criador, lacuna de cobertura
reproduzida, ou família ausente da tabela §4. **Nenhuma frente aqui é hipótese inventada para ocupar
agente**: cada uma está presa a um desses gates, declarado no `spec.json`.

## 2. Limites do ambiente (restringem o que a campanha pode afirmar)

- **Sem GPU** (`clGetPlatformIDs: PLATFORM_NOT_FOUND_KHR`): o trabalho de §5 (16! bijeções como
  senha, 132 h/variante) **permanece pronto e não executado**.
- **Corpora históricos ausentes** neste clone: as 466.310 senhas-base / 1,27 M formas, os plaintexts
  das §3.11/§3.12 e o `result.json` não estão aqui. **Nenhuma frente re-varreu o corpus histórico**,
  e nenhuma herdou suas contagens.
- **Sem scorer de quadgramas**: `solver/scorer.py` depende do `result.json` ausente e
  `solver/primos_2026_09_17/clean_scorer.py` tem caminho Windows fixo. Toda triagem textual foi
  substituída por critério determinístico ou pelo oráculo duro, e isso está declarado em cada frente.

## 3. As frentes fechadas

| Frente | Gate | Resultado |
|---|---|---|
| **F7** `insumo_novo` | insumo novo (gate a) | site e on-chain **idênticos** ao registrado; nenhum insumo novo no escopo coberto. Telegram inacessível daqui — declarado como limite |
| **F4** `faed_256_aes` | §4-E "braço AES ~200× mais fino" | 10.536 seleções, 32.182 senhas, 193.092 AES, 21.072 privkeys: **0**. z de padding −0,429 |
| **F11** `bases_nao_decimais` | §6 "continuam fora apenas bases não decimais…" | **prova**: bases 2–8 impossíveis (o resíduo contém `i`). 52 leituras, 1.248 AES, 71 escalares: **0** |
| **F9** `degrau_oraculo` | protocolo item 3 (degrau) | **o achado principal da campanha** — ver §4 |
| **F6** `yinyang_inversao` | §4-E "(parcial)" | domínio escrito: só 4 involuções com lastro, grupo de 4 elementos. 844 senhas, 5.064 AES, 336 escalares, 99.510 janelas: **0**, nulo z +0,27 |
| **F8** `antitese_primos` | antítese do lead §6 | construção contrária **falhou**; lead **reforçado** por cota exata — ver §4 |
| **F3** `sem_zero_integral` | §4-B "só o melhor caminho" | **prova**: alvo de 32 B inalcançável (mínimo 44). 404.096 senhas, 2.424.576 AES: **0** |

## 4. O que muda o mapa

Três resultados mudam o mapa, e **os três foram reproduzidos pelo coordenador com código próprio**
antes de entrarem aqui — relato de frente é insumo, não evidência.

### 4.1 O oráculo é cego por classe (F9) — a correção mais consequente

F9 mediu o **detector**, não o espaço de chaves: fabricou 275 acertos conhecidos na gramática do
criador e perguntou se o pipeline os reconheceria. Cada um dos 30 tipos deu **100 % ou 0 %**, sem
caso misto: o oráculo não erra por ruído, é **cego por construção** em classes inteiras.
Especificidade perfeita (0 falsos positivos em 50.000 ruídos) — estreito, não barulhento.

Quatro defeitos pontuais, **verificados pelo coordenador** lendo `gsmg_common.py` e executando:

1. **`nested_blob` devolve `False` para base64 multilinha** — o formato em que os blobs do próprio
   puzzle estão publicados (`_B64_RE` sem `re.M`). O oráculo de encriptação aninhada é cego ao
   formato real.
2. `nested_blob` só testa `p[:8]` → não vê blob cru fora do offset 0.
3. `fast_priv_scan` varre janelas **só em big-endian**.
4. `priv_hit` lê `O.TARGET_H160S` e `fast_priv_scan` lê `G.TARGET_H160S` — duas ligações distintas
   ao mesmo conjunto, a forma exata da cegueira a `17ucy` da §3.11.

E `aes_try` fixa CBC + `unpad`, de modo que **em modo de fluxo o plaintext correto nem chega a ser
produzido**: a lacuna da §3.14 deixa de ser suposição e vira falso negativo de 100 % medido, com
senha correta em mãos.

**Consequência declarada:** todo negativo histórico que passou por `try_password_all` vale **apenas
para as classes que o oráculo enxerga**. Para as classes cegas, o negativo **não é evidência de
ausência — é ausência de medida.**

Os itens 1–3 são baratos de corrigir e permitiriam **re-varredura retroativa** de todo o material
hex já persistido pela regra 5, **sem nenhuma decifração nova**. Nenhuma correção foi aplicada:
alterar o kit durante o enxame invalidaria o kit das outras frentes.

### 4.2 O lead do §6 fica muito mais forte (F8)

A construção contrária falhou em nove geradores alternativos (180.000 amostras), 41 pontos de
sensibilidade, 23,4 M testes de look-elsewhere e 535 mil janelas de texto real — zero em tudo. E o
resultado decisivo é **determinístico**: **P(encaixe) ≤ 1,86 × 10⁻¹⁷** sob o nulo de contagens, e
≤ 5,37 × 10⁻¹⁷ com Bonferroni exato sobre as 180 regras de posições primas.

**Reprodução independente do coordenador:** E[#seg] = **1,859 × 10⁻¹⁷**, maiores termos em L = 87 e
88, L84 = 1,14 × 10⁻¹⁸ contra L83 = 4,13 × 10⁻¹⁹ — batendo em três algarismos. Nota: os dois L que
`dbbi` realiza **não** são os favorecidos a priori.

Isso substitui o "0 em 20.000" (p < 1,5 × 10⁻⁴) por algo ~10¹² vezes mais forte, independente de
semente e da escolha do nulo. **Mas continua sendo inferência sobre intenção, não medida dela:** a
§3.4 permanece válida, e nada disto desambigua L83 de L84 (fator 2,8, fraco demais).

### 4.3 Um sub-argumento do §6 cai (F8)

**`faed` não é evidência de desenho.** Para a regra canônica é impossibilidade de contagem, não
resultado empírico: com n = 570, 49 `b` e 69 `e`, exigir π(L) ≤ 49 força L ≤ 228 e exigir
n − L ≤ π(L) força L ≥ 479 — janela vazia. **Verificado pelo coordenador** por varredura de todos os
L. Nenhum conteúdo de `faed`, em nenhuma ordem, poderia admitir a regra.

## 5. Reconciliação de conjuntos (protocolo, item 5)

Comparados objetos e parâmetros **antes** de combinar; sobreposições declaradas e **não somadas**:

- **F4 / F11 / F3 / F6 operam sobre objetos distintos** (seleções de `faed` 570; resíduo 60/61;
  modelos sem-zero sobre `dbbi` 91; os 16 objetos da involução), logo seus totais são disjuntos.
- **F11 vs §4-B:** a base 9 da tabela histórica é sobre `dbbi` **inteiro** (91 símbolos); F11 opera
  sobre o **resíduo** (60/61). Objetos distintos, nada a descontar.
- **F6 declarou as próprias sobreposições e não as somou:** `B` sobre a matriz e azul↔amarelo
  sobrepõem os 945 k AES de `frontier_2026-09-17`; o eixo do par sobrepõe a família 5; `C` sobre o
  resíduo como texto já estava coberto pelas 9! bijeções de §6.
- **F8, F9 e F7 não tocam material real** (estatística, instâncias sintéticas, leitura) — não entram
  em nenhum total de cobertura.
- O **nulo** de F6 (506.400 AES) **não** entra na cobertura: é nulo, não varredura.

**Totais legítimos sobre material real, das frentes fechadas:**

| unidade | total |
|---|---|
| decisões AES | **2.623.980** |
| escalares de 32 B contra os dois alvos | **21.479** |
| janelas raw32 (unidade distinta — não somar com escalares) | **99.510** |

## 6. O que **não** mudou

- O prêmio segue intacto; nenhum dos três blobs foi aberto.
- As linhas §4-B e §4-E **continuam parciais**, agora com a parcialidade *medida*: F3 deixa
  ~10¹⁵–10¹⁹ caminhos sem materializar em 51/52 e 64; F4 cobriu ~0,28 % do braço de chave; F6 não
  fechou o eixo do par, que **não é finito sem arbitrar**.
- O §5 (GPU) segue pronto e não executado.
- A segunda ligação desconhecida do §6 — **como `matrixsumlist` consome o resíduo** — segue intocada,
  e é para onde a prioridade aponta.

## 7. Deltas propostos

*(propostos; aplicados por quem integra o PR, nunca pelas frentes nem pelo coordenador)*

**Para `ENDGAME.md` §6:** substituir "0 em 20.000 embaralhamentos" por P(encaixe) ≤ 1,86 × 10⁻¹⁷
(cota exata; 6,6 × 10⁻¹² i.i.d.); acrescentar o Bonferroni exato de 5,37 × 10⁻¹⁷ sobre 180 regras de
posições primas e o look-elsewhere medido (1 falso positivo em 23,4 M testes); **remover `faed` da
lista de evidências**, anotando a impossibilidade por contagem.

**Para `ENDGAME.md` §4-E:** reescrever "inversão yin-yang (parcial)" conforme a §9 do
[FINDINGS de F6](yinyang_inversao/FINDINGS.md) — eixo da involução fechado, eixo do par
explicitamente **não** fechado.

**Para `ENDGAME.md` §3 (fato novo):** registrar os pontos cegos do oráculo medidos por F9 e a
consequência sobre a leitura dos negativos históricos.

**Para o kit** (`gsmg_common.py`), depois do fechamento do enxame: `re.M` em `_B64_RE` e busca de
`Salted__` em todo offset; janela LE em `fast_priv_scan`; unificação de `TARGET_H160S`.

**Para `docs/RESEARCH-INDEX.md`:** uma linha apontando para este relatório.

## 8. Frentes em execução

F1 `modos_fluxo` e F2 `auditoria_fluxo` (a lacuna que a §3.14 declara como **a única aberta**) e
F5 `saltos_bijecao` (§6, "ficam em amostra"). Esta seção será substituída pelos resultados.
