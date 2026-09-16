# SalPhaseIon: execução da investigação de cores, primos e somas

Data: 11/09/2026. **Nenhuma senha ou chave do prêmio foi encontrada.**
Os resultados abaixo eliminam hipóteses delimitadas; não eliminam a pista
`yellowblueprimesmatrixsumlist` nem resolvem a SalPhaseIon.

## Correção de uma pista aparente

As **14 últimas palavras das linhas anteriores a `SELECT` no README não são
14 unidades de texto autenticadas pelo puzzle**.

1. A senha conhecida da fase 3.2, com EVP-SHA256, recupera o bloco original.
2. O segmento de símbolos nesse plaintext tem **1.539 bytes em uma única
   linha, sem espaços, tabs ou quebras internas**.
3. Decifrar as 1.539 letras transcritas com Beaufort e `THEMATRIXHASYOU`
   reproduz exatamente o texto documentado, depois de remover seus espaços,
   pontuação e quebras de linha.

Portanto, as quebras apresentadas no README não são preservadas nessa cifra.
Alinhar seus 14 finais de linha às 14 somas da matriz exige uma hipótese de
formatação adicional. Isso enfraquece os testes que usavam essa coincidência.
Não exclui que `lastwordsbeforearchichoice` se refira ao conteúdo dessa fala.

O final recuperado imediatamente antes de `SELECT` contém:
`REINSERTINGTHEPRIMEBASICSAFTERWHICHYOUWILLBEREQUIREDTO`.
Esse trecho é do puzzle, não uma passagem escolhida do livro Cosmic Duality.

## Teste A — 91 símbolos como os pares de 14 valores

**Pista → hipótese:** `len(dbbi)=91=C(14,2)` e a matriz inicial tem 14 linhas.
Testei se cada símbolo representa a soma ou a distância absoluta entre dois
valores atribuídos às linhas, permitindo qualquer ordem dos 14 valores e
qualquer renomeação bijetiva dos símbolos.

**Restrição exata:** dois valores iguais necessariamente produzem o mesmo
padrão de símbolos nas suas combinações com todos os outros valores. Nas oito
leituras examinadas, `dbbi` não tem nenhum par com essa propriedade. Logo,
nesse modelo, os 14 valores precisariam ser distintos.

Com valores distintos, um valor fixo só pode ter um parceiro para uma soma
fixa, ou no máximo dois para uma distância absoluta fixa na reta real.
Entretanto, há vértices com **6 ou 8 parceiros do mesmo símbolo**. Isso
contradiz os dois modelos. O argumento da soma também vale para soma modular
num grupo, quando os símbolos identificam os resultados sem ambiguidades.

**Resultado:** os dois modelos são incompatíveis nas oito ordens de leitura:
triângulo por linhas, colunas, diagonais crescentes e decrescentes, e suas
reversões. O resultado independe de quais primos ou números se atribuam às
cores e da permutação dos 14 valores. Não cobre uma permutação arbitrária das
91 arestas, codificação não injetiva, transposição posterior ou outra operação.
Controles com somas reais, distâncias e valores repetidos passaram.

## Teste B — recolocar os primos na geometria das cores

**Pistas → regra testada:** há 24 células coloridas e 24 primos até 91. Na ordem
espiral que já decodifica a URL, a célula colorida de ordem `k` recebe o primo
de ordem `k`, ou o dígito de `dbbi` situado nesse índice primo. Somar linhas e
colunas fornece a `matrixsumlist`. A igualdade das quantidades motiva a regra;
não prova que o criador a tenha usado.

A diferença em relação aos scripts anteriores é **recolocar os 24 pesos nas
coordenadas espaciais originais**, antes de somar. As buscas anteriores citadas
em `ANALISE_PRIORIDADES.md` selecionavam símbolos por cor/primo e usavam-nos
principalmente em transposições ou deslocamentos.

Espaço fixado no programa:

- Primos crescentes ou decrescentes; pesos pelo primo ou por `dbbi` com índices
  base 0/1 e alfabetos `a=0`/`a=1`.
- Ambas as cores, somente azul, somente amarelo ou azul menos amarelo.
- Células sem cor zeradas ou conservando os bits originais.
- Listas de linhas, colunas e suas duas concatenações; leitura direta e reversa.
- Listas serializadas; concatenação com as palavras locais anteriores a
  `SELECT`; seleções em `dbbi`, `faed` e nas palavras da fala local.
- A leitura pelos 14 finais de linha foi incluída, mas explicitamente marcada
  como dependente do layout do README. Índices circulares e estritos foram
  identificados separadamente.

Exemplo conferido independentemente: os 24 primos crescentes nas células
coloridas, com as demais células zeradas, dão:

```text
linhas:  [24,68,53,71,96,156,106,31,90,114,61,43,42,8]
colunas: [2,36,81,59,71,96,162,114,43,102,103,47,29,18]
```

Também comparei as frequências das listas de pares geradas por essas matrizes
com as de `dbbi`: soma, distância, produto e produto escalar, sem redução ou
módulo 9/10. **Nenhuma das 1.920 listas** tem o mesmo espectro de frequências
`3,4,5,8,8,10,10,18,25`. Elas não podem ser `dbbi` por simples reordenação e
renomeação bijetiva. Essa condição é necessária, não seria suficiente se
alguma lista tivesse passado.

## Validação nos blobs originais

| Medida | Resultado |
|---|---:|
| Matrizes construídas | 80 |
| Listas antes das leituras reversas | 320 |
| Textos candidatos distintos | 12.226 |
| Senhas distintas, incluindo SHA256 hexadecimal | 45.064 |
| Tentativas: 3 blobs × 2 KDFs | 270.384 |
| Saídas com padding válido | 1.078 |
| Quantidade esperada de padding aleatório, aproximadamente | 1.060 |
| Saídas com pelo menos 85% ASCII de texto ou cabeçalho `Salted__` | 0 |
| Janelas binárias de 32 bytes verificadas contra a chave pública do prêmio | 525.982 |
| Chaves correspondentes ao prêmio | 0 |

Foram usados **SMALL, TAIL32 e COSMIC originais**, AES-256-CBC e EVP com SHA256
ou MD5. A calibração recuperou a fase 3.2 conhecida, e 12 controles binários
cobriram ambos os KDFs e diferentes tamanhos/paddings.

Uma segunda implementação, com PyCryptodome, recalculou e comparou integralmente
as **1.078 saídas**, sem truncamento. A maior fração de ASCII foi 55,7%.
Foram examinadas todas as janelas binárias contíguas de 32 bytes em big-endian,
além de candidatos hexadecimais e WIF; nenhum destes dois formatos textuais
apareceu. O hash160 da chave pública usada no teste corresponde ao endereço
do prêmio. Isso não cobre todas as possíveis codificações de uma chave.

## Reprodução e consequência

```powershell
node solver/prime_geometry_constraints.cjs
```

O programa usa apenas os módulos nativos do Node, lê `inputs.json` e grava
`spec.json`, `lists.json`, `candidates.jsonl`, `graph_constraints.json`,
`padding_results.jsonl` e `summary.json`. O resumo primário de uma nova execução
marca a verificação independente de chaves como pendente. O registro separado
`independent_checks.json` documenta a conferência Python desta sessão.

**Decisão:** não ampliar a busca dessa regra de geometria com novas senhas
arbitrárias. A hipótese dos pares também perde prioridade. A pista de somas
continua aberta, mas uma próxima regra deve explicar a estrutura de `dbbi`
e o conteúdo de `lastwordsbeforearchichoice` sem depender das quebras editoriais
do README. A escolha anterior de trabalhar na SalPhaseIon permanece uma
prioridade comparativa, e não uma probabilidade numérica de sucesso.
