# Pista imprevista, cores e primos — 11/09/2026

**Resultado: nenhuma decifração nova.** A rodada recuperou o contexto da
resposta #6509 e excluiu modelos específicos por restrições sobre os campos
inteiros. Não foi encontrada uma senha nova justificada para testar em AES.
SMALL, TAIL32 e COSMIC continuam sem abertura validada.

## 1. O que a pista imprevista realmente identifica

Fonte primária: export local `result.json`; os trechos usados estão em
[hint_context.json](hint_context.json), com datas, autores e respostas.
O criador aparece como Jrk Bgrt, `user9815232`.

| Mensagem e data | Conteúdo e contexto | Limite da inferência |
|---|---|---|
| #5963, Janusz, 01/03/2021 08:34:22 | Pergunta quais primos usar e sugere 2, 3, 5, 7 | Essa lista é do participante |
| #5966 e #5969, Jrk Bgrt, 01/03/2021 08:34:42 e 08:35:15 | Reage à chegada à parte dos primos e observa que isso pode ter sido uma dica | Apoia o uso de primos, sem selecionar valores ou operações |
| #6245, #6247, #6248, Janusz, 05/03/2021 10:15 | Pergunta sobre XOR de cores, depois soma e vermelho | São propostas do participante |
| #6250, Jrk Bgrt, 05/03/2021 10:15:26 | Diz `Infrared` no meio dessa conversa; #6252 acrescenta que não haverá dicas | É uma fala real do criador, mas não endossa expressamente XOR ou soma |
| #6508 e #6509, 14/03/2021 | #6508 pede dica sobre `matrixsumlist`; #6509 responde diretamente que já houve uma pista imprevista | A resposta não aponta para uma mensagem anterior específica |

**Há pelo menos dois antecedentes plausíveis para #6509: a menção a primos
e a fala sobre infravermelho. Não foi encontrado um vínculo de resposta que
escolha um deles.** A leitura de infravermelho como “invisível” na #6518 é
de Janusz, não uma explicação do criador.

Essas falas já apareciam em pesquisas anteriores do projeto, inclusive no
`BRIEFING.md` de 02/09. A contribuição desta rodada é preservar o contexto
e limitar a atribuição, não reivindicar a descoberta de uma dica inédita.
A confirmação posterior de primos e zeragem continua valendo: #8000,
26/12/2021, e #8330, 09/01/2023. Ela não resolve a operação ausente.

## 2. Dois valores fixos nas cores: uma inversão exata

Modelo declarado antes da execução:

1. Todas as células azuis recebem o mesmo inteiro `p >= 2`; todas as
   amarelas recebem `q >= 2`.
2. Cada célula sem cor conserva seu bit, recebe o bit invertido, ou recebe
   zero. São três casos distintos, aplicados uniformemente.
3. Somam-se as 14 linhas ou as 14 colunas, em ordem direta ou inversa.
4. Concatenam-se suas representações decimais mínimas, sem separador nem
   preenchimento com zeros.
5. Dígitos 1 a 9 viram `a..i`; tanto 0 quanto 7 viram `g`. Cada ocorrência
   de `g` pode representar qualquer uma das duas opções.
6. A saída deve coincidir com **todo DBBI ou todo FAED original**.

Cada soma tem a forma `b_i*p + y_i*q + c_i`. Linhas com a mesma tripla de
coeficientes produzem exatamente o mesmo número e, portanto, o mesmo
trecho de letras. O maior trecho repetido de DBBI tem quatro caracteres;
o de FAED tem cinco. Isso limita o tamanho das somas repetidas e os
valores das cores, sem escolher um teto arbitrário para os primos.

Por exemplo, nas linhas com os bits originais, as repetições implicam,
para DBBI, `p <= 4996` e `q <= 9992`. Mesmo usando esses limites em todas
as linhas, a concatenação pode ter no máximo **64 dígitos**, enquanto DBBI
tem **91**. A contradição antecede a procura de qualquer par de primos.

| Perfil, nas duas ordens | Comprimento máximo para DBBI | Comprimento máximo para FAED |
|---|---:|---:|
| Linhas / bits originais | 64 | 78 |
| Linhas / bits invertidos | 63 | 77 |
| Linhas / zero | 63 | 77 |
| Colunas / bits originais | 65 | 79 |
| Colunas / bits invertidos | 65 | 79 |
| Colunas / zero | 58 | 72 |
| Comprimento exigido | **91** | **570** |

**Os 24 casos são impossíveis nesse modelo, para quaisquer inteiros
`p,q >= 2`, incluindo todos os primos.** Isso não exclui usar as somas
como chave, aplicar outra transformação depois delas, ou atribuir valores
diferentes às células de uma mesma cor.

Código: [color_sum_constraints.cjs](../../solver/color_sum_constraints.cjs).
[Especificação](color_sum_spec.json), [resultados](color_sum_results.json)
e [resumo](color_sum_summary.json).

## 3. Outras representações das somas

Foram declarados mais 57 perfis, usando a mesma hipótese de dois inteiros
fixos e exigindo a coincidência de toda a concatenação decimal:

| Família | Perfis | Alvos | Resultado |
|---|---:|---|---|
| Valor posicional binário de cada linha/coluna, com pesos de potências de 2 | 24 | DBBI | Nenhuma correspondência |
| As 28 somas de linhas e colunas, nas ordens especificadas | 24 | DBBI e FAED | Nenhuma correspondência |
| Os 24 grupos de oito bits da espiral original, com ou sem o grupo final de quatro bits; inversão da lista sem a cauda | 9 | DBBI e FAED | Nenhuma correspondência |

Total: **90 buscas completas**. Em 37 casos, o comprimento já contradiz
os limites. Nos outros 53, as possíveis primeiras somas determinam os
inteiros por um sistema linear; foram encontrados 78 pares que passaram
pelas verificações parciais, mas nenhum reproduziu o campo inteiro.

O caso de valores posicionais binários foi pesquisado somente para DBBI.
Não se afirma que esse modelo tenha sido excluído para FAED. As ordens e
os coeficientes exatos constam na
[especificação adicional](color_sum_extended_spec.json).
Código: [color_sum_extended.cjs](../../solver/color_sum_extended.cjs);
[resultados](color_sum_extended_results.json) e
[resumo](color_sum_extended_summary.json).

## 4. Primos como fatores dos números completos

A página já converte números decimais inteiros em texto em outros trechos.
Uma hipótese diferente é usar primos como fatores: representar todo DBBI
ou FAED como um inteiro `N`, permitindo cada `g` ser 0 ou 7, e obter
`N*p` ou `N/p`, exigindo divisão exata.

Foram usados os **44 primos até 196**, o total de células da matriz
original. Essa faixa é uma escolha explícita de investigação; nenhuma
fala do criador estabelece esse teto. A saída precisa ter todos os bytes
da representação mínima em ordem big-endian entre 0 e 127. Esse filtro
inclui caracteres de controle, sendo mais amplo que texto imprimível.

**176 casos completos, nenhuma saída de sete bits.** A prova por intervalos
percorreu 382 nós; 138 casos foram eliminados no intervalo inicial. Ela
cobre todas as 1.024 escolhas de DBBI e todas as `2^107` escolhas de FAED
para cada operação e primo declarado. Não equivale a enumerar fisicamente
todas essas combinações.

Também foram limitadas cinco operações conjuntas, permitindo simultaneamente
todas as máscaras dos dois campos: `FAED/DBBI`, produto, soma, diferença
e XOR. Em todas, os intervalos já forçam um byte maior que 127. Na divisão,
o primeiro byte é `D6`; no produto, o segundo é `9C`; na soma, diferença
e XOR, o segundo permanece entre `D4` e `D5`.

Esses resultados excluem apenas a leitura direta dos resultados como
bytes de sete bits. Dados binários, outras codificações, outros fatores
e operações adicionais continuam fora do teste.

Código: [prime_scale_constraints.cjs](../../solver/prime_scale_constraints.cjs).
[Especificação](prime_scale_spec.json),
[resultados e limites conjuntos](prime_scale_results.json) e
[resumo](prime_scale_summary.json).

## 5. Controles e reprodução

```powershell
node solver/color_sum_constraints.cjs
node solver/color_sum_extended.cjs
node solver/prime_scale_constraints.cjs
```

Os três programas usam apenas módulos nativos do Node, executam seus
controles antes dos testes e salvam os hashes das entradas e do código.
Nesta execução passaram **217 controles com soluções plantadas** e
**103 comparações de conjuntos de soluções com enumeração limitada**.
Esses números descrevem controles, não tentativas de senha.

Uma implementação independente em Python 3.12 também conferiu:

- Os 69 perfis, reconstruídos diretamente da matriz, cores e espiral.
- As 114 buscas de somas, incluindo os limites de repetição/comprimento.
  Para os 53 casos que exigiram inversão, ela permitiu todos os possíveis
  deslocamentos da segunda soma, um conjunto mais amplo que o alinhamento
  do programa principal. Conferiu 10.518 pares inteiros dessa busca mais
  ampla sem obter correspondência completa.
- As 176 buscas de fatores. Em DBBI, enumerou explicitamente 90.112 casos;
  em FAED, usou contradições independentes sobre intervalos de bytes, com
  288 nós. Também verificou os cinco limites das operações conjuntas.

Registros: [verificação das somas](independent_verification.json) e
[verificação dos fatores](prime_scale_independent_verification.json).
Eles incluem hashes dos resultados conferidos. A conferência Python foi
executada como análise inline; os comandos Node acima são os programas
persistidos e reproduzíveis desta rodada.

## 6. Consequência para a investigação

A operação que liga cores/primos a `matrixsumlist` **continua desconhecida**.
Esta rodada encerra as leituras literais declaradas; ampliar o teto dos
primos não pode salvar os modelos de somas já excluídos para todos os
inteiros. Tampouco há motivo novo para retomar a busca parcial FAED/base127.

O próximo modelo útil precisa especificar outro papel para as somas — por
exemplo, parâmetros de uma transformação — e explicar esse papel com uma
pista ou previsão independente. Ainda não há evidência suficiente para
escolher uma fórmula específica. A referência a `Infrared` permanece
ambígua e não autentica, por si só, uma operação de RGB, XOR ou soma.

SalPhaseIon → SMALL permanece a prioridade comparativa. As exclusões
desta rodada não demonstram que falte informação, que seja impossível
resolver o puzzle, ou que alguma cadeia histórica seja válida.
