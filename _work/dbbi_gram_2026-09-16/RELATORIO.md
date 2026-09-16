# DBBI como produtos internos das linhas ou colunas

16/09/2026. **Nenhuma senha final encontrada.** Foram examinadas duas
interpretações dos 91 símbolos de DBBI como os `14 × 13 / 2` pares de
linhas ou colunas da matriz inicial: produtos internos inteiros e seus
restos módulo 10. As exclusões abaixo têm escopos diferentes.

## Modelo comum

Cada uma das cinco categorias recebe um peso fixo: azul, amarelo, preto,
branco e o quadrado quase branco em `[7,4]`, usando índices a partir de
zero. Essa última célula corresponde ao índice espiral 163. Tratar o
quase branco separadamente também inclui atribuir-lhe o peso do branco.

Para cada par de linhas `a < b`, calcula-se
`G[a,b] = soma_k M[a,k] × M[b,k]`. A outra orientação usa as colunas.
As 14 entradas diagonais, que seriam os produtos de um vetor por ele
mesmo, ficam fora dos 91 valores.

A codificação admite qualquer bijeção `a..i → 1..9`. Qualquer **uma** das
letras pode valer zero ou seu dígito, independentemente por ocorrência.
Não se presume `g=0`, nem a ordem original das letras no alfabeto.

As frequências de DBBI, ordenadas, são:

```text
3, 4, 5, 8, 8, 10, 10, 18, 25
```

Se `H[d]` conta os resultados iguais ao dígito `d`, é preciso existir um
dígito positivo que receba a soma de `H[0]` com sua própria contagem.
Após essa fusão, as nove contagens precisam coincidir com as de DBBI,
permitindo permutação. Esse critério permite uma ordem arbitrária dos
91 pares; ele não depende de escolher uma rota triangular.

## Produtos internos sem redução modular

Aqui os pesos são quaisquer inteiros **não negativos**. Para cada uma
das quatro cores comuns, em ambas as orientações, há dois vetores com
essa mesma cor numa coordenada. O produto interno desse par contém o
quadrado do peso. Como as outras parcelas não são negativas e o resultado
precisa ser no máximo 9, cada peso comum fica limitado a `0..3`.

O quase branco aparece uma única vez. Se encontra algum peso positivo
na mesma coordenada de outro vetor, um produto interno é pelo menos seu
próprio peso; basta considerar `0..9`. Se todos esses outros pesos são
zero, o quase branco não influencia nenhum dos 91 resultados, e qualquer
peso maior equivale a zero. **Esse caso inerte não impõe um limite ao
peso real; apenas permite um representante finito equivalente.**

Assim, `2 × 4⁴ × 10 = 5.120` casos cobrem todos os pesos permitidos,
inclusive todos os primos, sem um teto arbitrário de busca.

| Motivo da exclusão | Casos |
|---|---:|
| Algum produto interno maior que 9 | 4.852 |
| Menos de oito valores positivos distintos | 222 |
| Frequências incompatíveis com DBBI | 46 |
| Sobreviventes | **0** |

Essa exclusão vale mesmo permitindo **qualquer permutação dos 91 pares**.
As coordenadas que provam os limites dos pesos estão na especificação.

## Produtos internos módulo 10

Agora todos os pesos inteiros, positivos ou negativos, se reduzem a
cinco restos `0..9`. Foram examinados **200.000 casos completos**.
Os produtos foram calculados por contagens de pares de categorias, sem
usar os limites da família anterior.

- 58.672 casos têm menos de oito dígitos positivos distintos.
- 141.324 têm frequências incompatíveis.
- **Quatro** passam pelo teste das frequências, todos usando colunas.

Na ordem azul, amarelo, preto, branco, quase branco, os quatro vetores
de restos são:

```text
[5, 1, 5, 4, 2]
[5, 3, 5, 2, 6]
[5, 7, 5, 8, 4]
[5, 9, 5, 6, 8]
```

Em todos eles, `b` seria a letra zerável: 13 de suas 25 ocorrências
representariam zero. Há quatro bijeções de dígitos para cada vetor.
Nenhum desses vetores mantém os fundos preto e branco ambos em `0/1`.

Para avaliar a estrutura, cada candidato foi comparado com oito ordens
dos pares: linhas, colunas, diagonais com afastamento crescente ou
decrescente, e as quatro sequências invertidas. Admite-se ainda qualquer
permutação das 14 linhas/colunas.

Para cada vértice, contamos quantas de suas 13 arestas têm cada letra.
Uma permutação dos vértices preserva o conjunto dessas assinaturas.
**Todos os 128 casos possuem uma assinatura com multiplicidade
incompatível.** São 32 casos distintos após eliminar equivalências de
relabelagem de dígitos entre os quatro vetores de pesos.

Isso exclui os quatro candidatos nessas oito rotas, mesmo com qualquer
permutação dos vértices. **Não os exclui para uma permutação arbitrária e
independente das 91 arestas.** A compatibilidade das frequências nesse
modelo mais amplo continua sendo apenas uma coincidência estrutural,
sem mensagem ou senha produzida.

## Verificação independente e limites

Dois verificadores reconstruíram todos os casos por somas de produtos
externos das coordenadas, sem importar os buscadores. Conferiram as
frequências por subtração da contagem de zeros na letra escolhida, em
vez de fundir contagens dos dígitos. O verificador modular regenerou
todas as bijeções e cada certificado de assinatura incompatível.

Os controles incluem 220 histogramas comparados com permutações
explícitas; matrizes de resultado conhecido; 520 verificações dos
limites, incluindo cinco casos inertes; 100 histogramas positivos;
202 comparações de coeficientes com produtos diretos; permutações
plantadas de vértices e 16 conjuntos de pesos elevados ou negativos
equivalentes módulo 10. Todas as conferências passaram.

Não houve candidatos a texto, testes AES ou testes de chave privada
nesta rodada. Os resultados não cobrem outros módulos, valores de
letras diferentes dos dígitos declarados, várias letras zeráveis,
vetores derivados de outra matriz ou operações posteriores adicionais.
A exclusão sem módulo tampouco cobre pesos negativos e cancelamentos.

```powershell
node solver/dbbi_gram.cjs
node solver/verify_dbbi_gram.cjs
node solver/dbbi_gram_mod10.cjs
node solver/verify_dbbi_gram_mod10.cjs
```

Sem módulo: [especificação](spec.json), [casos](cases.jsonl.gz),
[resumo](summary.json), [verificação](verification.json),
[buscador](../../solver/dbbi_gram.cjs),
[verificador](../../solver/verify_dbbi_gram.cjs).

Módulo 10: [especificação](modular_spec.json),
[casos](modular_cases.jsonl.gz), [sobreviventes de frequências](modular_survivors.json),
[certificados de estrutura](modular_graph_cases.json),
[resumo](modular_summary.json), [verificação](modular_verification.json),
[buscador](../../solver/dbbi_gram_mod10.cjs),
[verificador](../../solver/verify_dbbi_gram_mod10.cjs).
