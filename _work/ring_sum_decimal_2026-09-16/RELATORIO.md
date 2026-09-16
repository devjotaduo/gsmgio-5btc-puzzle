# Somas dos sete anéis da matriz — 2026-09-16

**Nenhuma senha final.** Foi excluída uma interpretação específica de
`matrixsumlist`: DBBI ou FAED como concatenação decimal das somas dos sete
anéis concêntricos da matriz inicial. Todos os pesos inteiros de cores
`p,q ≥ 2` estão cobertos, portanto também todos os pares de primos.

## Hipótese e fonte

A primeira fase usa uma espiral na matriz 14×14. Somar seus sete anéis é
uma alternativa geométrica às somas de linhas/colunas já examinadas. A
motivação combina essa espiral, `matrixsumlist`, as cores com números e a
indicação de que alguns caracteres devem ser zerados. O criador não
confirmou que esses elementos se combinam por este algoritmo.

Insumo: `../prime_geometry_2026-09-11/inputs.json`, SHA256
`2e58c16a953bc22c2361adb5124f43d8fe624d15e3c90858349dcb25ecefedc6`.
Foi usada a matriz corrigida de 101 uns. Os anéis têm índice
`min(r,c,13-r,13-c)`, de 0 a 6, e particionam as 196 células.

Com os bits não coloridos preservados, azul=`p` e amarelo=`q`:

| Anel, de fora para dentro | Soma |
| --- | --- |
| 0 | `5p + q + 25` |
| 1 | `4p + 2q + 21` |
| 2 | `3p + q + 15` |
| 3 | `2p + 2q + 10` |
| 4 | `2q + 11` |
| 5 | `p + q + 4` |
| 6 | `0` |

O teste também permite atribuir independentemente 0 ou 1 às células não
coloridas originalmente 0 e 1. São quatro perfis; os coeficientes de `p,q`
ficam iguais e as constantes mudam. O centro vale 0 ou 4. O quase branco
recebe o mesmo tratamento dos outros zeros não coloridos.

Cada soma é escrita em decimal sem zeros iniciais e sem separadores.
O mapa é `a=1,…,i=9`; até duas letras escolhidas dentre as nove podem
também representar zero, independentemente em cada ocorrência. Foram
incluídas as duas direções da lista e as duas direções do campo completo.

## Cobertura sem limite arbitrário para os primos

Os cinco anéis com ambas as cores são 0, 1, 2, 3 e 5. Escrevendo
`p=p'+2`, `q=q'+2`, seus coeficientes e constantes demonstram, para todos
`p',q' ≥ 0`, que cada soma é menor que dez vezes qualquer outra dessas
cinco. Portanto seus comprimentos são `L` ou `L+1`, com ao menos um `L`.

A soma do anel 4 também é menor que dez vezes cada soma mista; seu
comprimento não excede `L+1`. O centro ocupa um dígito. O comprimento total
fixa o comprimento do anel 4 depois que os outros cinco foram escolhidos.
Assim, todas as separações admissíveis formam uma lista finita, mesmo sem
escolher um maior primo ou tamanho arbitrário de operando.

Para cada separação, o produtor resolve os seis números por colunas
decimais. Os estados são os transportes das seis expressões. A cada coluna
considera todos os dígitos possíveis de `p,q`, respeitando os domínios dos
caracteres e a proibição de zero inicial. Um resultado precisaria reproduzir
integralmente as seis somas e o centro, com `p,q ≥ 2`.

## Resultado e conferência independente

- **1.472 modelos:** dois campos × quatro perfis × duas direções de campo
  × duas direções de lista × 46 conjuntos de letras zeráveis.
- **1.144** contradizem imediatamente o dígito do centro.
- Os demais geram **64.756 separações de comprimentos**, considerando
  suas ocorrências nos diferentes modelos.
- **64.770 nós**, 14 transições, nenhuma solução inteira.
- **20 controles plantados**, incluindo operandos com 96 dígitos e cores
  de tamanhos muito diferentes, mais **12 comparações exaustivas pequenas**.

O verificador reconstrói os anéis usando distância de Chebyshev ao centro
e enumera os comprimentos fixando o primeiro, em vez do menor. Não importa
o código do produtor e não usa seu algoritmo de transportes.

Para cada separação, testa os 100 pares de restos `p,q mod 10`.
**64.749 separações são impossíveis já no último dígito.** Para as sete
restantes, testa os 10.000 pares módulo 100: nenhuma funciona. Isso prova
o negativo sem depender da busca pelos demais dígitos. Vinte controles
preservam os restos corretos de pesos conhecidos. As sete exceções da
primeira coluna estão em `independent_verification.json`.

## Reprodução e limites

Na raiz do repositório, escolhendo um diretório ainda inexistente:

```powershell
node solver/ring_sum_decimal.cjs _work/ring_sum_reproduction
node solver/verify_ring_sum_decimal.cjs _work/ring_sum_reproduction
```

O resultado exclui somente as somas e a codificação declaradas. Não cobre
outro mapa de dígitos, três ou mais letras zeráveis, sinais negativos,
permutação arbitrária dos anéis, separadores, preenchimento com zeros ou
uso das somas como chave de outra transformação. Nenhum candidato para
AES foi produzido; SMALL, COSMIC e TAIL32 permanecem sem abertura validada.

Artefatos: `spec.json`, `cases.jsonl`, `summary.json`, `hits.json` e
`independent_verification.json`. Não há processo desta rodada em execução.
