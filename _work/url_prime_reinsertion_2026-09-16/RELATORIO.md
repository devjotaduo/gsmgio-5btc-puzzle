# Valores ASCII primos da URL e reinserção na matriz

**Resultado: nenhuma senha final recuperada.** Foram testadas 3.250 senhas,
nos três blobs e com os dois digests EVP declarados: 19.500 decisões AES.
Os 80 paddings aceitos não contêm uma decifração validada; a maior proporção
de caracteres ASCII imprimíveis/TAB/LF/CR foi 50,63%. Os 3.250 escalares
derivados também não atingiram a chave pública do prêmio nem sua negação.

## Hipótese e ligação com as pistas

As 24 células coloridas marcam o último bit dos 24 bytes de
`gsmg.io/theseedisplanted`. Isso é verificável na imagem transcrita. A
hipótese desta rodada interpreta os **valores ASCII** desses caracteres
como os números a selecionar por primalidade, em vez de testar a primalidade
de suas posições. Nenhuma fala do criador confirma essa operação.

Há nove caracteres com valor primo, formando `gmg/eeeae`:
`103,109,103,47,101,101,101,97,101`. Sua soma é 863. Esses fatos aritméticos
não autenticam uma mensagem ou uma regra do puzzle.

Foram fixadas três seleções: valores primos, valores não primos e todos os
valores. As duas últimas são alternativas de comparação. Para cada seleção,
foram construídas três matrizes:

1. Preservar os bits dos bytes selecionados e zerar os demais bytes.
2. Substituir cada célula colorida pelo valor ASCII selecionado, ou zero,
   conservando os bits das células sem cor.
3. Fazer a mesma substituição, zerando também todas as células sem cor.

Os quatro bits finais da espiral original são zero e permanecem zero.
As nove matrizes geram listas de linhas, colunas, linhas+colunas,
colunas+linhas e intercalação linha/coluna, também em ordem inversa:
**90 listas**. Cada lista recebe seis formatos fixos: decimal concatenado,
vírgulas, espaços, novas linhas, JSON compacto e colchetes com vírgula/espaço.

Os materiais são a lista sozinha ou seguida por uma das duas cláusulas já
fixadas na investigação das últimas palavras:

- `reinsertingtheprimebasicsafterwhichyouwillberequiredto`
- `sheisgoingtodieandthereisnothingyoucandotostopit`

Também entram os caracteres selecionados da URL e sua forma com NUL nos
caracteres não selecionados. São **1.625 materiais distintos**, usados
diretamente ou após SHA256 hexadecimal, totalizando 3.250 senhas.

## Conferência

O programa principal é
[url_prime_reinsertion.cjs](../../solver/url_prime_reinsertion.cjs).
Ele executa o controle conhecido da fase 3.2 antes dos candidatos.
Uma implementação Python independente, executada inline, reconstruiu a
espiral por caminhada, gerou os primos por crivo, refez célula a célula
as matrizes, listas, materiais e senhas. PyCryptodome reproduziu todas as
decisões AES, incluindo as negativas; coincurve conferiu todos os escalares.

- [Especificação e hashes das fontes](spec.json)
- [Derivação integral e materiais](derivation.json)
- [Resultados criptográficos](oracles.json)
- [Conferência independente](verification.json)

O SHA256 de `oracles.json` é
`15ed40d88250ab2ea94f84b6d82db1895c3cba527cdd683ece1eb867e7f77693`.

O script pode ser executado com `node solver/url_prime_reinsertion.cjs` em
uma cópia sem `oracles.json` nesse diretório; ele recusa sobrescrever um
resultado existente. `derive(input)` também é exportada para regeneração
sem efeitos de escrita.

## Limite

O teste cobre somente os materiais e composições acima. Não usa novos URLs,
primos arbitrários, deslocamentos ajustados aos resultados, outras cifras
ou janelas binárias arbitrárias como chaves privadas. Não demonstra que
outras interpretações de `matrixsumlist` sejam impossíveis.

A lacuna continua sendo uma regra de transformação sustentada pelas pistas
que produza a senha de SalPhaseIon. Não há processo desta rodada em execução.
