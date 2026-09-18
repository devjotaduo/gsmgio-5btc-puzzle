# O resíduo como seleção: saltos sobre `faed`

**Estado: negativo, com cobertura exaustiva do espaço declarado.** Nenhuma abertura, nenhuma chave,
nenhum texto.

## Por que esta hipótese

As leituras **textuais** do resíduo estão esgotadas: `a1z26` sob todas as 3.628.800 bijeções e todos os
caminhos (PRs #15, #16), ASCII decimal sob todas as bijeções (PR #15), o `To_Base(16)` da página
(PR #7), o resíduo como lista das 28 somas, e os 512 subconjuntos de "zeroed out" (PR #8).

Sobrou a hipótese que nunca teve gramática para enumerar: **o resíduo pode não codificar linguagem**.
Se não é texto, a leitura natural seguinte é **seleção** — e aqui há um teto algébrico que ninguém
tinha usado.

## O teto

A soma dos valores do resíduo (`a=1…i=9`) é **341** em L84 e **336** em L83. Ambas **cabem nos 570
símbolos de `faed`**. Logo o resíduo pode ser lido como uma sequência de **saltos** que escolhe 61 (ou
60) posições em `faed` *sem dar a volta* — e o offset inicial admite apenas **230** valores em L84 e
**235** em L83.

Isso torna o espaço pequeno e fechado, em vez de uma família aberta.

## Cobertura

4 resíduos (L84 e L83, cada um direto e invertido) × 2 âncoras (o símbolo **antes** ou **depois** de
cada salto) × 2 direções (para frente e para trás) × **todos** os offsets que mantêm o percurso dentro
de `faed`: **3.712 seleções**, todas distintas.

Cada seleção devolve ~60 símbolos de `faed`, testados de três formas:

| teste | cobertura | resultado |
|---|---|---|
| Texto (`clean_scorer`) | 3.712 materiais | melhor **−6,516** (inglês real: −3,679) |
| Chave (sha256 do material, 2 alvos, pubkey comp. e não) | 3.712 | **0 hits** |
| Senha (`raw` e `sha256hex`, 3 blobs × 2 KDF) | 7.424 senhas, **44.544 AES** | **0 candidatos** |

Paddings: 167 observados contra 174,68 esperados — **z = −0,58**, ruído.

**Controles.** A regra de salto é reproduzida num caso conhecido (saltos `[3,1,4]` sobre `faed` a partir
do offset 0 devolvem `dgd`); e a fase 2 abre com `sha256hex("causality")` pelo mesmo caminho de código
do executor.

## Alcance

Fecha a leitura do resíduo como **saltos aditivos sobre `faed`**, em todas as âncoras, direções e
offsets — por exaustão do espaço, não por amostra.

Não fecha: saltos com outro mapeamento símbolo→valor (aqui vale `a=1…i=9`), saltos sobre outro campo
(`dbbi` tem 91 símbolos, então 341 daria a volta — é outra hipótese, com wrap), seleção por máscara em
vez de salto, nem o resíduo como parâmetro em vez de seletor.

O ponto que fica: a hipótese "o resíduo não é linguagem" continua viva, e esta foi a sua primeira
instância concreta a ser testada e descartada.

## Continuações: wrap em `dbbi`, pares em grades e bijeção

As quatro continuações declaradas acima foram atacadas
([`seletor_grades.json`](seletor_grades.json)). Uma morreu só pelo teto, duas foram fechadas por
exaustão e a quarta entra como amostra declarada.

### (A) `dbbi` como grade de pares: impossível, sem executar nada

Lendo L83 como 30 pares `(linha, coluna)` sobre `dbbi` (7×13): o resíduo tem valor **9** nas **duas**
paridades de posição, e `dbbi` tem apenas **7 linhas**. Nenhuma das duas ordens funciona. Descartada
por teto algébrico puro.

### (B) e (C): fechadas por exaustão

| instância | cobertura |
|---|---|
| Saltos sobre `dbbi` (91) **com wrap** | 91 offsets × 4 resíduos × 2 âncoras × 2 direções = **1.456** |
| Pares `(linha, coluna)` em `faed` (15×38) e na matriz (14×14) | ordens `lc`/`cl`, bases 0 e 1, 4 resíduos |

Juntas: **1.480 materiais distintos**.

| teste | resultado |
|---|---|
| Texto | melhor **−6,328** (inglês real −3,679) |
| Chave (sha256, dois alvos) | **0 hits** |
| Senha (`raw` + `sha256hex`, 3 blobs × 2 KDF) | 2.960 senhas, **17.760 AES**, **0 candidatos** |

Paddings: 82 contra 69,65 esperados — **z = +1,48**, dentro do ruído.

### (D) Saltos com bijeção arbitrária: amostra declarada

Aqui o teto trabalha contra fechar: a soma dos saltos varia de **233 a 377** conforme a bijeção, e
portanto **sempre** cabe nos 570 de `faed`. Nenhuma bijeção é eliminada por comprimento, e o espaço
fica em `9! × offsets × 16` — grande demais para varrer com AES.

Amostra de **199.951 materiais**: melhor escore **−6,014**, **0 hits de chave**. Declarado como
amostra, **não** exaustivo.

### Onde a hipótese "não é linguagem" está

| instância | estado |
|---|---|
| saltos aditivos sobre `faed` (sem wrap) | fechada (seção anterior) |
| saltos sobre `dbbi` com wrap | **fechada** |
| pares em `faed` e na matriz | **fechada** |
| `dbbi` como grade de pares | **impossível por teto** |
| saltos com bijeção arbitrária | **amostrada** |
| resíduo como *parâmetro* (não seletor) | **aberta** |

Nenhuma das leituras de seleção testadas produz texto, chave ou abertura. O melhor escore de todas elas
fica em torno de −6, contra −3,7 do inglês real — a mesma distância da leitura identidade.
