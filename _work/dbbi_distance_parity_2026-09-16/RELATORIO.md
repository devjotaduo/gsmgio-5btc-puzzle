# DBBI como tabela de distâncias: contradição de paridade

16/09/2026. **Nenhuma senha final foi encontrada.** Esta rodada usa o fato
de DBBI ter 91 símbolos, exatamente o número de pares entre 14 elementos.
A hipótese é que esses símbolos codifiquem distâncias entre linhas,
colunas ou outros vetores associados à matriz inicial. A igualdade de
comprimentos motiva o teste; não autentica essa interpretação.

O resultado novo se aplica a vetores, ampliando a restrição anterior sobre
distâncias entre valores escalares. Não depende de escolher números primos
específicos para as cores nem de impor um limite a esses números.

## Resultado

Nas oito leituras triangulares especificadas abaixo:

- Se `a..i` representa qualquer permutação dos dígitos `1..9`, DBBI não pode
  ser uma tabela completa das distâncias de Hamming, Manhattan ou
  euclidianas ao quadrado entre 14 vetores inteiros.
- A impossibilidade continua mesmo permitindo que **todas as ocorrências
  de uma letra escolhida tenham valores arbitrários e independentes**.
  Isso inclui, como caso particular, zerar qualquer subconjunto das
  ocorrências dessa letra.
- Sem essa letra indeterminada, se os nove símbolos tiverem **quaisquer
  nove valores inteiros distintos**, uma interpretação como Hamming
  binário exigiria pelo menos 18 dimensões. Logo, também não descreve as
  distâncias de Hamming entre 14 linhas ou colunas de uma matriz binária
  14×14 por uma substituição fixa e injetiva.

O último item é um limite necessário, não uma construção em 18 dimensões.
Os dois primeiros não exigem limite de dimensão. Valem também com pesos
inteiros por coordenada, pois a identidade de paridade é preservada.

## Identidade que torna o teste possível

Para coordenadas inteiras:

```text
|x-y| ≡ x+y (mod 2)
(x-y)² ≡ x+y (mod 2)
```

Somando coordenadas, a paridade de uma distância depende somente de uma
paridade atribuída a cada vértice:

```text
paridade(distância(i,j)) = paridade(vetor_i) XOR paridade(vetor_j)
```

Assim, em qualquer ciclo a soma das distâncias precisa ser par. DBBI
impõe tantas igualdades entre as arestas que **todos os símbolos de valor
fixo são forçados a representar números pares**.

Isso exige nove valores pares distintos na leitura sem exceções ou oito
na leitura que libera uma letra. Só existem quatro dígitos pares em
`1..9`: `2,4,6,8`. Nenhuma bijeção satisfaz essa exigência.

Um exemplo pequeno, na leitura por linhas e ignorando todas as arestas
`g`, é o triângulo de vértices 1, 3 e 6. Suas arestas ocupam as posições
2, 5 e 28 de DBBI e têm rótulos `b,b,e`. Como duas ocorrências de `b`
se cancelam módulo 2, `e` tem de ser par. O mapa literal `e=5` já viola
essa condição. Os certificados completos forçam da mesma maneira a
paridade de todas as oito letras restantes, sem assumir o mapa literal.

## Leituras e cobertura

Os pares são `(i,j)`, com `0 <= i < j < 14`, percorridos:

1. Por linhas: `i` primeiro, depois `j`.
2. Por colunas: `j` primeiro, depois `i`.
3. Por diferença crescente `j-i`, depois `i`.
4. Por diferença decrescente `j-i`, depois `i`.
5. Nas inversões completas desses quatro percursos.

Em cada leitura, o teste inclui o caso sem exceções e nove casos que
ignoram integralmente uma das letras. São **80 modelos e 648 certificados**.
Qualquer renomeação ou permutação dos 14 vértices está coberta, pois não
altera a existência de uma atribuição de paridades. Uma permutação
arbitrária das 91 arestas não está coberta.

O buscador resolve as equações módulo 2 e guarda, para cada letra forçada
a ser par, um conjunto de arestas que comprova isso. Cada vértice desse
conjunto aparece um número par de vezes; todas as letras aparecem um
número par de vezes, exceto a letra alvo. Nenhuma aresta da letra
indeterminada é usada em seu certificado.

O verificador não importa o buscador nem usa eliminação linear. Ele
enumera todas as `2^13` atribuições de paridade dos vértices por modelo,
fixando o primeiro em zero; inverter todos os vértices não altera nenhuma
aresta. Conferiu **655.360 atribuições** e os 648 certificados diretamente.
Só a atribuição constante sobrevive em cada modelo, com todas as letras
restantes pares.

Passaram também três controles de triângulos e 120 controles com vetores
inteiros conhecidos. Os certificados encontrados nesses controles nunca
forçaram uma distância ímpar a ser par.

## Limite para Hamming com rótulos arbitrários

Sem uma letra indeterminada, os nove valores precisam ser pares. Além
disso, em nenhuma das oito leituras existem dois vértices com os mesmos
rótulos de distância a todos os demais. Portanto, sob uma codificação
injetiva, nenhum par pode ser formado por vetores binários idênticos:
todos os nove valores de distância são positivos.

Até a dimensão 17 há somente oito distâncias positivas pares possíveis:
`2,4,6,8,10,12,14,16`. Nove valores distintos exigem dimensão de pelo
menos 18. Em particular, a matriz binária 14×14 original não atende ao
modelo, mesmo que se desconheça a ordem de suas linhas ou colunas.

## O que permanece aberto

Essa prova não elimina DBBI como pesos de uma matriz cujo resultado será
somado — esse é o sentido inverso usado na receita comunitária de X.
Também não elimina produtos internos, coordenadas reais, reduções por
módulo ímpar, rótulos arbitrários de grandes distâncias, homofonia,
alteração de várias letras, remoção de posições ou outras ordens de pares.

Não houve candidatos de senha nem testes AES nesta rodada. A consequência
é retirar a interpretação direta de DBBI como essas distâncias das
próximas buscas, mantendo a necessidade de explicar sua função e a de
FAED antes de abrir SMALL.

## Reprodução

```powershell
node solver/dbbi_distance_parity.cjs
node solver/verify_dbbi_distance_parity.cjs
```

Arquivos: [especificação](spec.json), [certificados](cases.json),
[resumo](summary.json), [verificação independente](verification.json),
[buscador](../../solver/dbbi_distance_parity.cjs) e
[verificador](../../solver/verify_dbbi_distance_parity.cjs).

SHA256 dos casos:
`6e35501594042203f22c576153c90ce1241dd29f47ab278c889ccbb069876966`.
