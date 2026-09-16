# Nihilist: somas de coordenadas e limite da chave repetida

16/09/2026. **Nenhuma senha final foi recuperada.** A hipótese desta rodada
é que `matrixsumlist` descreva a soma de coordenadas de texto e chave numa
grade. A variante Nihilist da ACA faz essa operação com uma grade 5×5 e
uma chave repetida. Essa associação com a pista é nossa hipótese, não uma
identificação confirmada pelo criador.

Foram examinadas duas representações das somas, preservando integralmente
os campos e suas duas direções. Ambas permitem qualquer bijeção dos nove
símbolos para os dígitos 1..9 e uma letra que, por ocorrência, também possa
representar zero. Nenhuma escolha de alfabeto, palavra ou nota de linguagem
foi usada para rejeitar os modelos.

## 1. Somas reduzidas a dois dígitos

O modelo publicado pela [American Cryptogram Association](https://www.cryptogram.org/downloads/aca.info/ciphers/NihilistSubstitution.pdf)
associa letras a coordenadas `11..15, 21..25, 31..35, 41..45, 51..55`.
Cada número cifrado é a soma de uma coordenada do texto e outra da chave,
reduzida módulo 100 e escrita com dois dígitos. Por exemplo, 108 vira `08`.
A grade e a chave podem ser desconhecidas; sua estrutura numérica basta
para o teste desta rodada.

FAED fornece 285 pares. Foram considerados todos os períodos de 1 a 285,
todas as 9! bijeções de dígitos e todas as nove escolhas de letra zerável.
O comprimento ímpar de DBBI, 91, impede que ele seja sozinho um fluxo
completo de pares nesse modelo; isso não impede que tenha outra função.

| Ordem de FAED | Menor período possível com mapa desconhecido | Mapas possíveis nesse período |
|---|---:|---:|
| Original | **277** | 19 |
| Símbolos invertidos | **275** | 3 |

Portanto, **nenhuma chave repetida de até 274 letras funciona**, mesmo
permitindo qualquer alfabeto da grade e qualquer mapa dos dígitos nos
limites declarados. Isso inclui, por exemplo, chaves de 14 ou 38 elementos
derivadas diretamente das listas discutidas no puzzle. Não exclui uma
lista curta que gere uma chave longa por algum mecanismo adicional.

Com o mapa literal `a=1..i=9`, a ordem original não admite nenhum período;
a ordem invertida admite somente 282, 283 e 285 dentro da faixa examinada.
Nesses casos, a letra zerável necessariamente é `a`.

### Por que a cobertura é exata

Uma soma de duas colunas de 1 a 5 tem unidade em `0,2,3,4,5,6,7,8,9`, nunca
1. Todas as nove letras aparecem nas posições de unidade de FAED. Logo, a
letra mapeada para 1 precisa ser a letra zerável e precisa valer zero em
cada uma dessas posições. Isso elimina as outras oito escolhas de letra
zerável para cada bijeção, sem adivinhar máscaras.

Além disso, a soma 20 é impossível. O par ordenado das letras associadas
aos valores 2 e 1/0 precisa estar ausente entre os pares observados. FAED
tem 75 dos 81 pares possíveis, com quatro pares ausentes de letras
distintas em cada direção. Essa restrição deixa **20.160 bijeções por
direção**, que ainda passam pelo teste da chave repetida.

Para cada posição do período, o programa intersecta todos os conjuntos de
coordenadas de chave que permitem decifrar os respectivos pares. Uma
interseção vazia rejeita o modelo; todas as interseções não vazias fornecem
uma testemunha numérica. Como a chave pode conter qualquer letra da grade,
não falta outra restrição alfabética para esta decisão de viabilidade.

O buscador usa também uma restrição de grafo sobre as unidades para evitar
trabalho redundante. **O verificador não depende dessa redução:** percorre
as 362.880 bijeções em cada direção, calcula os valores possíveis por
subtração e compara todas as 285 listas de mapas viáveis com as salvas.
Reproduziu 5.745.600 decisões de período por direção após a rejeição local
dos mapas inviáveis.

Foram salvas e recifradas independentemente 22 testemunhas dos períodos
mínimos. Elas provam que o limite é atingível aritmeticamente. **São
construções para provar viabilidade, não mensagens decifradas.** Escolher
arbitrariamente uma das coordenadas permitidas de uma chave quase tão
longa quanto o texto não recupera a chave pretendida.

Controles: exemplo publicado pela ACA reproduzido e três mensagens
plantadas com mapas de dígitos diferentes, incluindo as escolhas de zero.

## 2. Somas decimais sem redução: dois ou três dígitos

Foi testada separadamente a variante hipotética que mantém as somas
100..110 com três dígitos, concatenando todos os números sem separadores
e sem zeros de preenchimento. Os 81 valores possíveis satisfazem:

```text
22 <= soma <= 110
soma % 10 != 1
```

Foram decididos **13.063.680 modelos**: DBBI e FAED, cada um nos dois
sentidos, todas as 9! bijeções e todas as nove letras zeráveis. O teste
abrange todas as máscaras e segmentações, sem exigir sequer uma chave
repetida. **Nenhum dos quatro campos/orientações admite uma segmentação.**

Um autômato de prefixos resolveu a gramática. Outro programa, com um
parser de fronteiras baseado diretamente nas desigualdades acima e
enumeração das permutações em ordem diferente, confirmou todas as
13.063.680 decisões. Passaram 81 controles positivos, quatro negativos
no buscador e 18 positivos no verificador.

Esse negativo vale mesmo se cada caractere tiver uma coordenada de chave
diferente. A impossibilidade aparece antes de escolher a chave ou as
letras da grade.

## Alcance e consequência

Não foram geradas novas senhas ou feitos testes AES nesta rodada: as
testemunhas numéricas da primeira família não são decifrações, e a segunda
família não produz candidato algum. SMALL, TAIL32 e COSMIC continuam sem
abertura autenticada.

Os resultados descartam a hipótese direta de uma Nihilist 5×5 com chave
curta nas representações examinadas. Não eliminam grades 6×6, vários
símbolos zeráveis, homofonia, transposição anterior, separadores removidos
por outra regra ou uma chave longa gerada por processo adicional. Uma
retomada dessa cifra precisa justificar uma dessas operações nas pistas.

## Reprodução

Na raiz do repositório:

```powershell
node solver/nihilist_constraints.cjs
node solver/verify_nihilist_constraints.cjs
node solver/nihilist_untruncated.cjs
node solver/verify_nihilist_untruncated.cjs
```

Artefatos: [especificação](spec.json), [mapas por período e testemunhas](results.json),
[resumo](summary.json), [verificação dos períodos](verification.json),
[gramática sem redução](untruncated/results.json) e
[verificação dessa gramática](untruncated/verification.json).

SHA256 dos resultados com dois dígitos:
`bd977447d76c16dd131f99187f760f009b28f7ab2b2f44c7246553d5e7251e8b`.
SHA256 dos resultados sem redução:
`cc735e1e82b5831f703c60ee7445fdbe5b712d8fe82862d81ebf85ccde034123`.
