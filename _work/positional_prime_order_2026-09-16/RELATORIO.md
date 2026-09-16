# Lista posicional em bases primas: qualquer ordem das linhas

**Nenhuma senha final.** A busca e a conferência independente terminaram
com saída 0, sem correspondência com FAED, permitindo qualquer permutação
dos 14 números de linhas ou colunas. Não há processo desta rodada ativo.

## Hipótese e cobertura

São mantidas todas as premissas do
[teste de prefixos](../positional_prime_prefix_2026-09-16/RELATORIO.md): base
prima uniforme, valores primos das cores menores que ela, preto/branco
independentemente 0 ou 1, linhas ou colunas, orientação interna uniforme,
representações decimais mínimas, ambos os sentidos de FAED, bijeção dos
dígitos positivos e até duas letras que também podem representar zero.

A diferença é a ordem externa: os 14 números podem aparecer em qualquer
permutação. Os limites da base continuam válidos porque reordenar os números
não altera a soma dos comprimentos decimais. Todas as linhas e colunas da
matriz têm pelo menos uma célula colorida; logo, seus valores são positivos.

Toda permutação possui uma primeira linha. As primeiras linhas 0 e 13 já
foram rejeitadas pelo teste anterior, com conferência independente. Esta
ampliação cobre as outras doze, usando os mesmos intervalos de primos.

## Execução concluída

| Medida | Resultado |
|---|---:|
| Casos de perfil/base/primeira linha adicionais | 83.700 |
| Valores de primo dominante | 163.860.480 |
| Intervalos rejeitados pelo prefixo | 327.720.907 |
| Intervalos que exigiram examinar a segunda cor | 53 |
| Atribuições da segunda cor examinadas nesses intervalos | 108.710 |
| Rejeições pelo primeiro número exato | 3.861 |
| Rejeições pelo comprimento total diferente de 570 | 103.693 |
| Casos que exigiram verificar a continuação da ordem | 1.156 |
| Nós dessas árvores de ordens | 16.184 |
| Árvores pendentes | 0 |
| Correspondências completas | 0 |

Nos 1.156 últimos casos, cada árvore tem 14 nós: a primeira linha compatível
e cada uma das 13 opções para a segunda. Todas as segundas linhas causam
contradição. Portanto, nenhuma permutação do restante pode reparar a lista.
O programa permite continuar até 14 linhas quando necessário, mas os dados
reais foram rejeitados antes disso.

Dezesseis controles com base 1.601, azul 37, amarelo 101, mapas de dígitos
direto/inverso e duas ordens conhecidas recuperaram a ordem plantada. Incluem
linhas e colunas e ambas as orientações internas. Todos terminaram; o maior
controle usou 92 nós. [Controles](controls.json).

## Conferência independente

O verificador não importa o buscador. Reutiliza somente as rotinas do
verificador independente anterior para coeficientes, primos e contradições
numéricas. Confere cada certificado de intervalo e todas as 108.710
atribuições secundárias. Para as árvores restantes, reconstitui todas as
opções de linha e usa conjuntos de dígitos por símbolo e símbolos por dígito
para verificar cada contradição. Também confere a cobertura e os hashes da
prova anterior que forneceu as primeiras linhas 0 e 13.

Todos os 83.700 casos adicionais, os 327.720.907 certificados de intervalo,
as 108.710 atribuições secundárias e as 1.156 árvores foram conferidos.
Não há estados pendentes nem correspondências. Juntamente com a prova
anterior, isso exclui o modelo para todos os primos permitidos pelos limites
de comprimento e qualquer ordem dos 14 números. [Verificação integral](verification.json).

## Artefatos e reprodução

```powershell
node solver/positional_prime_order.cjs
node solver/verify_positional_prime_order.cjs
```

O produtor recusa sobrescrever o diário existente. Nenhuma nova execução da
busca é necessária; o processo da busca já terminou com saída 0.

- [Especificação](spec.json).
- [Resumo da busca](summary.json).
- [Buscador e árvores de ordens](../../solver/positional_prime_order.cjs).
- [Verificador independente](../../solver/verify_positional_prime_order.cjs).

Os certificados binários guardam a posição da contradição de cada intervalo.
As raras entradas que não foram rejeitadas dessa forma possuem tabelas
completas dos primos da outra cor e, quando necessário, árvores de ordens.

Nenhuma saída forneceu uma senha para AES. Esta investigação testa uma
interpretação delimitada da matriz; não exclui outros significados de
`matrixsumlist` ou métodos que transformem os números antes de escrevê-los.
