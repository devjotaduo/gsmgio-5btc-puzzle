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
