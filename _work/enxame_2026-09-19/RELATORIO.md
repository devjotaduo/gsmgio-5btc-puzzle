# Enxame de 2026-09-19 — relatório da campanha

Contrato: [`spec.json`](spec.json). Coordenador: sessão remota do Claude Code (Linux).
Base: `66fecdc`. **Estado: as 10 frentes fecharam.**

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
| **F5** `saltos_bijecao` | §6 "ficam em amostra" | domínio completo calculado (783.820.800); cobertos **0,1429 %** com 99,86 % **declarado fora**. 6,72 M AES, 1,12 M chaves: **0** |
| **F1** `modos_fluxo` | §3.14 "a única aberta" | 1.750 senhas, 52.500 decifrações sem filtro de padding, 48.825.000 janelas: **0** — ver §8 |
| **F2** `auditoria_fluxo` | §3.13 (contagem citada como execução) | reimplementação independente; veredito: **o 0 hits da F1 é confiável** — ver §8 |

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

- **F1 ∩ F2 = 69 senhas**, sobreposição **deliberada** (é verificação independente): das 70.080
  decifrações brutas, **2.070 são duplicadas de propósito** e entram uma única vez.
- **F5** opera sobre seleções do resíduo em `faed` por saltos, mecanismo distinto das seleções de
  256 bits de F4; **F1/F2** usam modos de cifra distintos de todo o resto (fluxo, não CBC).

**Totais legítimos sobre material real, das 10 frentes:**

| unidade | total |
|---|---|
| decisões AES | **9.411.990** |
| escalares de 32 B contra os dois alvos | **1.141.479** |
| janelas raw32 (unidade distinta — não somar com escalares) | **63.348.810** |

Composição das decisões AES: 2.623.980 (F4+F6+F11+F3, CBC sobre objetos disjuntos) + 6.720.000 (F5)
+ 68.010 (união única de F1∪F2, já descontadas as duplicadas).

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

## 8. A lacuna declarada aberta: modos de fluxo (F1 + F2)

Esta é a lacuna que a §3.14 nomeia como **a única ainda aberta**, e a campanha a atacou com uma
frente e sua antítese.

**F1 — cobertura.** 3 blobs × 5 modos (`cfb`, `cfb1`, `cfb8`, `ofb`, `ctr`) × 2 KDF × **1.750
senhas** reconstruídas do repositório = **52.500 decifrações sem filtro de padding** e **48.825.000
janelas raw32** BE+LE contra os dois alvos, nas duas formas de pubkey. Domínio 100 % concluído em
1.413,7 s. **0 chaves, 0 candidatos.** Os 10/10 pares modo × KDF reproduzem o `openssl` real byte a
byte, incluindo o CFB de 1 bit feito à mão.

**F2 — auditoria independente, e o veredito importa.** Reimplementou tudo sem reusar código da F1
(inclusive **secp256k1 em Python puro**), plantou chaves em offsets **desalinhados** (37 em BE, 113
em LE) e as recuperou **nos 5 modos**, com negativo casado contra os alvos reais. Sobre a F1:
**"o 0 hits é confiável — não é artefato de implementação nem aritmética disfarçada de execução"**,
que era precisamente o modo de falha da §3.13. Conferiu as contagens contra fórmula fechada nas 32
linhas de log e no total, verificou que `hits.jsonl` estava vazio **por execução** (criado antes do
laço), e mediu o throughput (24–37 k janelas/s contra os 30,6 k/s dela) para provar trabalho de EC
em tempo de parede.

**Sobreposição medida:** F1 ∩ F2 = **69** senhas; união **2.267**. As decifrações **não** se somam
inteiras — 2.070 são duplicadas de propósito, e é nelas que a verificação independente tem valor.
**Cobertura única da família: 68.010 decifrações e 63.249.300 janelas. Zero hits.**

**Ressalva que só a antítese produziu:** o controle plantado da F1 exercita o scanner em 2 dos 5
modos (`ofb`, `cfb1`); o da F2 cobre os 5.

### 8.1 Um achado estrutural que argumenta contra a própria família

F1 trouxe, além da varredura, um argumento **independente dela** — e o coordenador o verificou:

Modo de fluxo não faz padding, logo |plaintext| = |ciphertext|. Os três ciphertexts têm **80, 1328 e
80 bytes, e os três são ≡ 0 mod 16** (1328 = 16 × 83, os mesmos 83 blocos do COSMIC citados no §6).
Sob CBC/PKCS7 isso é **obrigatório**; sob modo de fluxo seria coincidência de ~(1/16)³ ≈ 2,4 × 10⁻⁴.
**Fator de Bayes ≈ 4 × 10³ contra a família dos modos de fluxo.**

É prior baixo *quantificado*, não refutação — a premissa de uniformidade dos comprimentos mod 16 é
uma suposição. Mas reposiciona a lacuna: ela é **real e continua aberta**, e ao mesmo tempo é um
lugar pouco provável para a resposta estar.

### 8.2 O que NÃO se pode escrever no `ENDGAME.md`

As duas frentes convergem e são explícitas: **isto não fecha a família.** Fecha 68.010 decifrações
sobre um conjunto nomeado de 2.267 senhas — contra as 1,27 M formas do corpus histórico, **ausente
deste clone**. A §3.14 continua valendo tal como está: *"continua aberto: só os modos de fluxo"*.

Para fechá-la de fato, F2 deixa a conta pronta: rodar o pipeline já certificado (C1–C5) sobre o
corpus de 1,27 M na máquina que o tem = **38.164.470 decifrações** e **35.493.457.500 escalares**,
~13 dias-CPU ao ritmo medido aqui, ~1,2 dia com 12 workers. **É uma conta a executar, não a citar.**

## 9. Um item aberto de auditoria

F2 conferiu as contagens históricas do `ENDGAME.md` e **todas saem exatas** (§3.13, §3.14, a tabela D
e o `summary.json` do `raw32_corpus_nopad`) — inclusive uma que devolve o tamanho do corpus
(1.272.149) sem que ele estivesse escrito ali.

Resta **uma ressalva de plausibilidade, não de aritmética**: aquele `summary.json` declara
498.682.408 janelas em 1.577,2 s = **316.182 verificações/s**, contra **30.617/s** medidos aqui com
`coincurve` em 1 processo — **~10,3×**. É compatível com 8 a 12 workers paralelos na máquina
original (o `AGENTS.md` declara teto de 12 processos), mas **não é verificável deste clone**, porque
o corpus não está aqui. Fica registrado como item aberto de auditoria, para quem tem o checkout
principal.
