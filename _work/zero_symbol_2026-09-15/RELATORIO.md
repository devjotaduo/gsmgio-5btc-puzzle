# Zeragem de qualquer símbolo — 15/09/2026

**Resultado: o puzzle continua sem solução validada.** Foram concluídos 36
testes de um modelo numérico, sem texto candidato ou senha nova. SMALL,
TAIL32 e COSMIC não foram abertos nesta rodada.

## Pista → hipótese

A mensagem #8000 de Jrk Bgrt, de 26/12/2021 no export local, diz que alguns
caracteres precisam ser zerados, mas não identifica quais. A
[fonte transcrita](../review_2026-09-11/primary_clues.json) e o
[contexto auditado](../matrix_hint_2026-09-11/RELATORIO.md) não estabelecem
que sejam necessariamente os `g`.

A rodada de 11/09 havia examinado todas as escolhas `g→0/7`. Esta rodada
generaliza **somente a identidade do símbolo ambíguo**:

1. Escolher um símbolo `s` entre `a..i`.
2. Cada ocorrência de `s` pode, independentemente, valer zero ou seu valor
   `a=1..i=9`. Os outros oito símbolos mantêm seus valores.
3. Interpretar o campo inteiro como decimal, incluindo zeros iniciais;
   convertê-lo à representação mínima em bytes.
4. Exigir que **todos** os bytes estejam entre 0 e 127. Isso admite caracteres
   de controle e é mais permissivo que exigir texto imprimível.

Aplicações: DBBI e FAED completos, na ordem original e com a sequência de
símbolos invertida. São `9 × 2 × 2 = 36` casos; os quatro casos com `g`
servem também de comparação com o resultado anterior. Não há seleção de
posições por cores, primos ou qualidade aparente da saída. O modelo continua
sendo uma interpretação condicional da pista, não uma instrução autenticada.

## Algoritmo → resultado

Para cada prefixo de decisões zero/dígito, o programa calcula um intervalo
inteiro contendo todas as escolhas restantes. Se o intervalo não contém
nenhum inteiro representável apenas com bytes de sete bits, todo o ramo
é impossível. O intervalo pode conter números que não correspondem às
máscaras; isso torna o descarte conservador.

| Campo | Ocorrências por símbolo a, b, c, d, e, f, g, h, i | Casos completos | Candidatos |
|---|---|---:|---:|
| DBBI | 3, 25, 8, 4, 18, 10, 10, 8, 5 | 18 | 0 |
| FAED | 54, 49, 52, 49, 69, 57, 107, 58, 75 | 18 | 0 |

Todos terminaram: **144 nós, 90 intervalos de exclusão, zero ramos pendentes**.
O programa contabiliza exatamente quantas máscaras cada intervalo cobre.
O caso FAED/g abrange suas `2^107` escolhas sem enumerá-las fisicamente;
o maior caso de DBBI tem `2^25` escolhas, para `b`.

**Conclusão restrita:** nenhum dos nove símbolos, quando é o único com valor
zero opcional, permite obter ASCII diretamente pela conversão decimal do
campo completo. A conclusão também vale ao inverter somente a ordem dos
bytes: isso não altera a propriedade de todos serem menores que 128.

Não foi disparada uma busca AES: o modelo não gerou nenhum candidato para
derivar uma senha. Os casos descartados não são senhas testadas.

## Conferência independente

O buscador passou por 54 comparações com enumeração completa em exemplos
pequenos e recuperou 27 mensagens plantadas: `matrixsumlist`,
`lastwordsbeforearchichoice` e `thispassword`, cada uma sob os nove símbolos
ambíguos. Outro controle verifica a contabilização de busca interrompida.

O verificador separado **não importa o buscador nem a função de sucessor**.
Ele conta diretamente quantos inteiros com bytes de sete bits existem até
um limite e demonstra que `contagem(máximo) − contagem(mínimo−1) = 0` em
cada certificado. Reconstitui os limites a partir do README, verifica que
as máscaras não se sobrepõem e que cobrem todas as escolhas de cada caso.

Passaram os 90 certificados dos 36 casos, 65.536 controles de contagem
inteira e 600 controles de mudança de comprimento, até 300 bytes.

## Reprodução e arquivos

```powershell
node solver/zero_symbol_constraints.cjs
node solver/verify_zero_symbol.cjs
```

- [Buscador](../../solver/zero_symbol_constraints.cjs).
- [Verificador independente](../../solver/verify_zero_symbol.cjs).
- [Entradas, hashes e certificados completos](results.json).
- [Resumo](summary.json) e [conferência](independent_verification.json).

Os scripts leem arquivos locais, usam módulos nativos do Node e gravam apenas
nesta pasta. Não houve alteração dos blobs, publicação ou transação.

## Limites e consequência

O resultado não exclui zerar **vários símbolos diferentes**, apagar/inserir
caracteres, usar outra base ou outro alfabeto, interpretar listas de números,
obter dados binários ou aplicar uma transformação posterior. Também não
resolve a busca parcial anterior de FAED/base127.

A lacuna continua sendo a operação que conecta cores/primos a `matrixsumlist`
e aos campos DBBI/FAED. Trocar apenas qual letra significa zero não corrige
o modelo de decimal inteiro → ASCII. A próxima hipótese deve explicar outra
transformação com apoio nas pistas; ampliar seletores de posições dentro
deste modelo já excluído não contorna a contradição.

Na consulta pública desta rodada, as issues mais recentemente atualizadas
do repositório original ainda eram #99, #93 e #106, todas com atualizações
até 11/09. A [#99](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/99)
continha pedidos de comprovação das alegações de solução; não foi localizada
uma nova decifração verificável nessa consulta. Isso não prova que ninguém
tenha resolvido o desafio.
