# Listas de somas dos campos DBBI e FAED

**16/09/2026 — nenhuma senha final encontrada.** Foi examinada uma leitura
literal de `matrixsumlist`: colocar os próprios campos numa tabela e ler suas
somas, com uma letra zerável. Os modelos de somas como códigos primos foram
excluídos integralmente. Outras leituras admitem muitas saídas; as seleções
descritas abaixo e suas normalizações não abriram os blocos.

## Hipótese delimitada

As fontes sustentam `matrixsumlist`, primos e a necessidade de zerar alguns
caracteres. Não especificam esta fórmula. Ela é distinta das buscas que
convertiam todo o campo decimal diretamente em um inteiro e das somas da
imagem inicial usadas como chave.

1. Usar o campo completo com `a=1,...,i=9`.
2. Escrevê-lo em cada retângulo com dimensões inteiras maiores que um, em
   ordem de linhas ou alternando o sentido das linhas.
3. Somar linhas ou colunas; ler a lista nas duas direções.
4. Escolher uma das nove letras. Cada ocorrência dessa letra pode valer zero
   ou seu valor original, independentemente. As demais permanecem positivas.
5. Interpretar cada soma como um código ASCII imprimível/TAB/LF/CR, como
   A1Z26 com zero=espaço, ou como `A=2,B=3,...,Z=101` com zero=espaço.

Não há módulo, deslocamento ajustado, chave adicional, remoção de posições
ou permutação arbitrária. Cada tabela usa todos os símbolos uma vez. Trocas
de ordem dentro de um grupo que não alteram a soma são deduplicadas.

Isso produz 12 partições distintas de DBBI e 84 de FAED: **2.592 modelos**
de campo, partição, letra zerável e formato. As escolhas dentro de cada grupo
são reduzidas às somas distintas que produzem. A contagem de saídas não deve
ser confundida com a quantidade de máscaras de zeros que as representam.

## Limites estruturais, antes de procurar palavras

| Campo | Formato das somas | Modelos | Todos os grupos têm ao menos um código possível |
|---|---|---:|---:|
| DBBI | ASCII | 108 | 54 |
| DBBI | A1Z26 | 108 | 0 |
| DBBI | Códigos primos | 108 | 0 |
| FAED | ASCII | 756 | 156 |
| FAED | A1Z26 | 756 | 92 |
| FAED | Códigos primos | 756 | 0 |

Assim, **todos os 864 modelos de códigos primos falham antes de qualquer
critério linguístico**. A1Z26 também falha para DBBI. Restam 302 modelos com
domínios de caracteres não vazios; isso não significa que contenham mensagens.

## Palavras e palavras concatenadas

Foram usados os dois vocabulários já preservados: 26.264 entradas com
contagem mínima de um milhão e 333.296 entradas no vocabulário completo.
Entradas alfabéticas têm até 32 letras; palavras de uma letra são apenas A/I.

Cada vocabulário foi aplicado em dois modos: sequências de letras precisam
ser palavras completas, ou podem ser palavras concatenadas, como
`matrixsumlist`. Dígitos e pontuação separam essas sequências; exige-se ao
menos uma palavra. Caixa é ignorada na consulta ao corpus, mas preservada
na saída. O corpus contém muitas siglas e abreviações.

Os **10.368 casos** terminaram, sem limites pendentes: 9.160 falham já no
domínio de códigos e 490 admitem uma derivação lexical. Os demais falham na
gramática de palavras. Em cada caso compatível foi escolhido o texto que
maximiza letras, depois minimiza outros caracteres, depois maximiza a soma
das probabilidades unigramas. A união dessas escolhas tem **355 textos**.

Nos modelos de palavras concatenadas, a contagem representa segmentações.
Um mesmo texto pode ter mais de uma segmentação; ela não é uma contagem de
textos distintos. Os grandes números registrados em `results.json` não são
senhas enumeradas ou autenticadas. Uma combinação de siglas pode passar o
filtro sem formar uma frase compreensível.

Dois algoritmos conferem contagem e escore ótimo: um acompanha os estados
de uma árvore de palavras, o outro percorre palavras completas. Uma terceira
implementação Python reconstruiu as partições por coordenadas, os conjuntos
de somas por adição de subconjuntos e os resultados por intervalos de palavras.
Conferiu todos os casos, escores ótimos e candidatos selecionados.

## Seleção sem dicionário

Para evitar que abreviações do corpus determinem toda a seleção, os mesmos
2.592 modelos foram avaliados também por frequências de quatro letras. O
perfil é o corpus geral já preservado, separado do material do Telegram.

O programa calcula exatamente a melhor saída por quantidade de letras e,
em seguida, pelo escore de quadgramas das letras. Ignora caixa e caracteres
não alfabéticos na contagem de quadgramas. Seleciona uma saída em cada um dos
302 domínios não vazios; não autentica todas as saídas desses domínios.

O algoritmo concordou com a enumeração literal de 1.344 strings em doze
controles. Recuperou quatro mensagens plantadas exatamente. No quinto,
`Read the numbers.`, recuperou `Read'the'numbers5`: as letras são as mesmas,
mas o critério não distingue essas alternativas de pontuação. Essa limitação
motivou conferir também as formas concatenadas descritas abaixo.

Uma implementação independente percorreu as posições da direita para a
esquerda e reproduziu todos os escores ótimos. As saídas inspecionadas do
puzzle continuam fragmentadas; esse escore não constitui autenticação.

## Composição e autenticação

Para os melhores textos dos dois critérios, foram usados o texto original,
minúsculas e maiúsculas, além da lista numérica efetivamente escolhida em
seis formatos: dígitos concatenados, vírgulas, espaços, quebras de linha,
JSON compacto e JSON com espaços. Cada material foi testado sozinho ou
seguido por uma das duas cláusulas anteriormente delimitadas:

```text
reinsertingtheprimebasicsafterwhichyouwillberequiredto
sheisgoingtodieandthereisnothingyoucandotostopit
```

Cada material é usado diretamente como senha ou como SHA256 hexadecimal.
Uma rodada suplementar remove whitespace ASCII, retém só alfanuméricos ou
só letras, nas três caixas declaradas e com as mesmas cláusulas. Senhas já
testadas nas duas seleções foram excluídas dessa rodada suplementar.

| Seleção | Materiais | Senhas testadas | Decisões AES | Paddings | Escalares |
|---|---:|---:|---:|---:|---:|
| Melhor derivação lexical | 9.027 | 18.054 | 108.324 | 450 | 18.054 |
| Melhor escore de quadgramas | 5.715 | 11.430 | 68.580 | 272 | 11.430 |
| Formas concatenadas, só senhas novas | 7.206 | 5.940 | 35.640 | 126 | 5.940 |

As primeiras duas seleções têm 96 senhas em comum. A união das três tem
**35.328 senhas distintas**, sem resultado validado. A contagem de materiais
da terceira linha inclui formas cujo teste foi dispensado por já existir.

Os testes usam SMALL, TAIL32 e COSMIC com EVP-SHA256 e EVP-MD5. Os escalares
são SHA256 das senhas; corpos inteiros de 32 bytes ou 64 dígitos hexadecimais
também seriam incluídos. Não houve correspondência com a chave pública do
prêmio nem com sua negação. A maior fração textual dos corpos com padding
foi 54,43%; padding e fração textual não validam uma decifração.

PyCryptodome reproduziu todas as decisões AES, inclusive as negativas;
coincurve reproduziu os pontos. Passaram os controles da fase 3.2, do gerador
da curva e do HASH160 do alvo. Todas as listas, normalizações, composições e
deduplicações foram reconstruídas independentemente.

## Evidências e escopo restante

- [Especificação e partições](spec.json), [resultados lexicais](results.json),
  [resumo](summary.json) e [355 escolhas distintas](selected.json).
- [Materiais](materials.json), [autenticação](oracles.json) e
  [conferência integral](verification.json).
- [Ótimos por quadgramas e controles](quadgrams.json),
  [materiais](quadgram_materials.json), [autenticação](quadgram_oracles.json)
  e [conferência independente](quadgram_verification.json).
- [Normalizações](normalized_materials.json),
  [autenticação de senhas novas](normalized_oracles.json) e
  [conferência](normalized_verification.json).

Programas: [somas e palavras](../../solver/matrix_sum_words.cjs),
[quadgramas](../../solver/matrix_sum_quadgrams.cjs) e
[materiais e autenticação principal](../../solver/matrix_sum_words_oracles.cjs).
As conferências Python e autenticações suplementares foram executadas inline;
suas entradas, parâmetros, pré-imagens e resultados estão preservados.

A exclusão estrutural vale somente para a fórmula declarada. As buscas e
otimizações terminaram, mas os textos compatíveis não foram todos testados
como senhas. Não foram examinados vários símbolos zeráveis simultaneamente,
outros mapas numéricos, tabelas irregulares ou uma cifra após as somas.
Não há processo desta rodada em execução. `matrixsumlist`, os blocos fechados
e a chave final continuam sem solução autenticada.
