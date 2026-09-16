# Execução do plano: dependências de X e três consequências

11/09/2026. **Primeira rodada do [plano](../../docs/notes/PLANO_PROXIMA_ETAPA.md) executada; nenhuma abertura validada de SMALL, TAIL32 ou COSMIC.** Foram concluídos os controles de símbolos/cores, a conferência com o script original, três modelos delimitados, duas extrações textuais e seus testes AES. A busca FAED/base127 permaneceu no ponto salvo, conforme o plano.

## 1. O que as fontes sustentam

A [tabela de operações e fontes](OPERACOES_E_FONTES.md) relaciona as escolhas da receita de X às mensagens originais. As dicas sustentam cores, primos, zeragem, lista de somas e referência ao Arquiteto. Elas não determinam, nas fontes consultadas, o XOR, os módulos 38/15/9, a disposição triangular dos pesos e a conversão final módulo 26.

As dimensões `91=14×13/2` e `570=38×15` são exatas. Isso torna as formas de matriz possíveis, sem provar sua escolha. Os bits das células não coloridas da matriz inicial não são consultados pelo script de X.

## 2. Mapa das dependências e controles executados

O [mapa completo](dependencies.json) registra, para cada uma das 114 letras das três saídas, as posições de DBBI, a linha de FAED, a soma, a chave, o XOR e o resto módulo 26. Os índices de posições de entrada/saída são base 1; as coordenadas `r/c` dos objetos de cor são base 0.

Foram feitas **5.288 alterações unitárias**, uma posição por vez para cada um dos outros oito símbolos, mantendo as demais entradas e a receita fixas. As **602.832 previsões analíticas** de saída concordaram com o recálculo integral.

| Campo | Alterações testadas | Preservam os três fragmentos originais | Preservam as três saídas completas |
|---|---:|---:|---:|
| DBBI | 728 | 48 | 0 |
| FAED | 4.560 | 3.361 | 3 |

Os fragmentos são `SENDTHE`, `BLUE` e `TOSETHEX`, em seus deslocamentos publicados. A extensão posterior `NET` não foi acrescentada ao critério. Eles ocupam, na união das três saídas, apenas as linhas 10–19 de FAED. Logo, **420 das 570 posições de FAED não influenciam esses fragmentos**, sob esta receita. Não é uma estimativa estatística: decorre das dependências por linha.

Também foram examinadas **135 trocas de uma célula azul por uma amarela**, preservando as quantidades 15/9. Oito trocas conservam os três fragmentos; nenhuma conserva as três saídas completas. A saída sem máscara é invariável sob todas as trocas, como o código prevê.

O módulo 26 também esconde diferenças: houve 44 eventos de mudança de XOR sem mudança da letra nos controles de DBBI e 85 nos de FAED. Esses números contam posições de saída afetadas por uma alteração, não entradas distintas nem soluções.

O [verificador independente](independent_verification.json) executou as funções do script original de X para conferir **todas as 5.288 alterações e todas as 135 trocas**. Não encontrou divergência.

Artefatos: [especificação](spec.json), [estado original](baseline.json), [parâmetros e posições zeradas](parameters.json), [alterações unitárias](unit_mutations.jsonl), [trocas de cores](color_swaps.json), [contagens](summary.json).

## 3. Uma colisão explícita mostra a informação que as somas descartam

Foi construída outra entrada, alterando **quatro posições de DBBI e 442 de FAED**, que conserva **as duas chaves, as duas listas de somas, todos os XORs e as três saídas completas**.

Em FAED, inverter a ordem dos símbolos dentro dos grupos de cada linha que têm a mesma elegibilidade espacial para a máscara conserva as duas somas. Em DBBI, um ciclo de quatro arestas não amarelas com incrementos alternados `+1,-1,+1,-1` conserva a soma de cada vértice. Os valores continuam entre 1 e 9. O exemplo e as posições estão em [aggregate_collision.json](aggregate_collision.json); as funções originais confirmaram a colisão.

A matriz linear das somas de DBBI tem posto 14. Acrescentando as somas das arestas amarelas removidas, o posto é 22 para 91 variáveis: nulidade racional 69. Isso não conta diretamente as soluções discretas em `1..9`; o exemplo anterior comprova pelo menos uma colisão discreta. [Cálculo dos postos](ranks.json).

**Interpretação limitada:** somar é uma operação que perde informação, e pode ser intencional num puzzle. A colisão não refuta a receita. Ela mostra por que recuperar os mesmos fragmentos ou até as saídas completas não verifica a ordem de todos os símbolos. Uma consequência externa, como uma abertura AES correta, continua necessária.

## 4. Três modelos testados, sem ajustar alfabetos ao resultado

O conjunto foi salvo com `--prepare` antes de executar `--test`. A terceira sequência de letras já havia sido vista na auditoria; nenhuma hipótese foi ajustada para melhorá-la.

| Modelo | Regra fixa | Novidade em relação aos testes recentes |
|---|---|---|
| H1 | Fazer OR dos valores efetivamente zerados em cada linha de FAED. Os valores permitidos são os pesos `1,2,4,8`; o resultado é um dígito hexadecimal | Usa o conjunto de valores removidos como bits; não é uma permutação de alfabeto dos tokens de DBBI |
| H2 | As colunas `2,6,13,14`, em ordem espacial, recebem bits `8,4,2,1`; cada posição efetivamente zerada liga seu bit | Usa ocupação das quatro colunas, sem buscar ordens alternativas |
| H3 | Aplicar simultaneamente as duas zeragens de X: soma azul de FAED XOR chave amarela de DBBI | Testa o quarto estado, ausente das três saídas publicadas |

H1/H2 foram representados com as 38 linhas completas ou todas as 14 linhas selecionadas pela máscara, como texto hex ou seus bytes decodificados. As posições não selecionadas são omitidas por essa hipótese de extração, não declaradas irrelevantes ao puzzle. H3 foi representado em bytes, texto hex e letras minúsculas pelo módulo 26 original. São **11 materiais**.

A identidade do quarto estado foi conferida em todas as 38 posições:

```text
quarto_XOR = XOR_base XOR XOR_azul XOR XOR_amarelo
```

Isso é consequência algébrica do próprio modelo, não uma confirmação externa. Sua sequência completa de letras foi:

```text
olupuerolqlzosdtdixqyoasaicjfgudfcvzwq
```

Não forneceu uma instrução legível. Os três modelos continuam condicionados às escolhas não autenticadas da receita original.

## 5. Últimas palavras e montagem de senha

A [análise textual](FRONTEIRA_TEXTUAL.md) fixa duas alternativas, sem varrer tamanhos de sufixos: a oração do puzzle iniciada por `REINSERTING`, imediatamente antes de `SELECT`, e a última oração antes de Neo se dirigir à porta esquerda no roteiro de 27/10/2001. A identificação da fronteira correta continua aberta. O roteiro é anterior à montagem final do filme. [Fonte primária consultada](https://www.horrorlair.com/movies/scripts/matrixreloaded.pdf).

Cada material foi testado sozinho via SHA256 ou na composição provisória:

```text
SHA256(material + lista_das_14_somas_de_DBBI + últimas_palavras)
```

A lista foi serializada em decimal concatenado ou separado por vírgulas; a ordem dos componentes segue a hipótese sugerida pelo texto das dicas. Não houve busca de permutações. O digest hexadecimal minúsculo foi usado como senha.

As **55 senhas distintas** não coincidem com nenhuma das **31.214 senhas indexadas** nos seis arquivos das campanhas recentes consultadas. Isso não prova ausência de repetição em todo o histórico do projeto. [Escopo da comparação](prior_overlap.json).

## 6. Resultado criptográfico e verificação

| Modelo | Senhas | Tentativas AES | Padding válido |
|---|---:|---:|---:|
| H1 | 20 | 120 | 1 |
| H2 | 20 | 120 | 0 |
| H3 | 15 | 90 | 0 |
| Total | **55** | **330** | **1** |

As tentativas cobrem os três blobs originais, EVP-SHA256 e EVP-MD5. O único plaintext com padding tem 37,68% de ASCII; não forneceu texto validado, formato comum examinado ou stream zlib/gzip completo. Não se infere que todo plaintext correto precise ser ASCII.

Foram conferidos **7.769 escalares distintos**, incluindo hashes, janelas de 32 bytes em ambas as ordens e hex64, sem corresponder ao alvo ou sua negação. A conferência adicional não encontrou WIF válida.

A execução independente regenerou os 11 materiais e as 55 senhas usando as funções originais de X, repetiu **todos os 330 testes AES, inclusive as falhas**, e confrontou o plaintext completo e os escalares. PyCryptodome e coincurve concordaram com Node. O controle positivo da fase 3.2 passou.

Artefatos: [especificação das consequências](consequence_spec.json), [linhas e nibbles](nibble_rows.json), [quarto estado](fourth_rail.json), [pré-imagens e senhas](consequence_passwords.jsonl), [todas as decisões AES](consequence_aes.jsonl), [resumo](consequence_summary.json), [verificação independente](consequence_verification.json).

## 7. Decisão após a rodada

**SalPhaseIon → SMALL permanece o alvo principal.** Nenhum dos três modelos forneceu uma nova instrução verificável ou abriu os blobs. O resultado elimina somente as fórmulas e serializações declaradas; não elimina toda interpretação de cores, primos ou somas.

Novas variações de alfabetos derivadas apenas dos fragmentos de X perdem prioridade. O próximo trabalho deve buscar uma fonte que determine a projeção entre cores e somas, especialmente o contexto da pista imprevista mencionada na resposta #6509, ou uma regra que explique o restante das saídas e tenha consequência independente. A fronteira textual fica documentada como ambígua, sem promover Hope ou as quebras de linha do README a solução.

FAED/base127 continua parcial no estado anterior de 177 candidatos. Nenhuma nova evidência nesta rodada selecionou uma máscara, portanto sua enumeração não foi retomada. Nenhum processo ficou rodando em segundo plano.

## Reprodução

Na raiz do repositório, com Node:

```powershell
node solver/recipe_dependency_audit.cjs
node solver/recipe_consequences.cjs --prepare
node solver/recipe_consequences.cjs --test
```

Os comandos usam somente arquivos locais e recriam os artefatos destas experiências. Código: [auditoria](../../solver/recipe_dependency_audit.cjs), [consequências e AES](../../solver/recipe_consequences.cjs). Os resultados independentes desta execução estão preservados separadamente; os comandos acima não repetem a conferência Python nem baixam o roteiro.
