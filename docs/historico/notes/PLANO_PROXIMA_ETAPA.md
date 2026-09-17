# Plano da próxima etapa — SalPhaseIon → SMALL

**Objetivo:** deduzir uma senha a partir das pistas e obter uma abertura verificável de SMALL. TAIL32 e COSMIC serão conferidos com os mesmos candidatos. A prioridade é comparativa; não há dados para estimar uma porcentagem de sucesso.

**Estado atual:** a auditoria das dependências de X e a investigação seguinte
do contexto de #6509 foram executadas. A primeira não produziu abertura AES;
a segunda excluiu modelos explícitos de somas e fatores. A operação pretendida
de `matrixsumlist` continua sem identificação. Não há justificativa nova para
ampliar dicionários de senhas ou retomar FAED/base127.

A investigação seguinte, de dados compactados, também foi implementada e
executada. Os modelos completos foram negativos; dicionários de compressão
maiores receberam apenas sondagens parciais. Ver o
[relatório de compressão](../../../_work/compressed_payload_2026-09-11/RELATORIO.md).

**Estado após a execução:** a primeira rodada abaixo foi concluída. Os controles,
as três hipóteses e os testes AES estão no [relatório de execução](../../../_work/recipe_audit_2026-09-11/RELATORIO.md).
Nenhum blob foi aberto de forma validada; a identificação da senha continua pendente.

## Base já disponível

- [Análise de prioridades](ANALISE_PRIORIDADES.md) e [revisão integral do ENDGAME](../../../_work/endgame_review_2026-09-11/LEITURA_ENDGAME.md).
- Script original de X (arquivo local: `_work/endgame_review_2026-09-11/original_dbbi_sum_faed.py`): três resultados reproduzidos; a leitura `SEND THE BLUE TO SET HEX` continua sendo interpretação comunitária.
- [Testes dos alfabetos azuis e das composições](../../../_work/blue_hex_2026-09-11/RELATORIO.md): 5.346 senhas, nenhuma abertura validada.
- [Mapa comum, ASCII 127 e bases primas](../../../_work/shared_numeric_2026-09-11/RELATORIO.md): autoria da frase recuperada. A busca FAED/base127 foi [concluída em 16/09](../../../_work/radix127_completion_2026-09-16/RELATORIO.md): exatamente 188 candidatos e 1.504 senhas nas formas declaradas, sem abertura validada. O estado anterior de 177 candidatos era parcial e foi preservado como histórico.
- Os dois controles de embaralhamento da receita de X já existem em blue_net_attack.json (arquivo local: `_work/blue_net_attack.json`), com 20.000 amostras cada. Eles condicionam a receita e os fragmentos já escolhidos; não medem a probabilidade de a interpretação ser a solução.

## Sequência de trabalho

| Ordem | Trabalho | Entrega | Condição para avançar |
|---|---|---|---|
| 1 | Relacionar cada operação da receita de X às fontes | Tabela de operação, parâmetro, fonte e grau de sustentação | Distinguir identidade matemática, instrução do criador e escolha do solver |
| 2 | Mapear dependências e informação perdida | Mapa posição → soma → XOR → letra, com controles locais | Identificar uma consequência verificável fora dos fragmentos selecionados |
| 3 | Formular até três modelos para a ligação que falta | Fórmulas completas, previsão e diferença em relação aos testes antigos | Nenhum parâmetro escolhido apenas porque melhora uma palavra ou padding |
| 4 | Fixar a extração de `lastwordsbeforearchichoice` | Texto original, fronteira de extração e normalização explícita | Cada alternativa deve vir de uma referência identificada |
| 5 | Testar as senhas derivadas e validar integralmente | Pré-imagens, hashes, plaintexts completos e comparação independente | Conteúdo verificável, consequência posterior ou correspondência com o alvo |
| 6 | Atualizar a prioridade conforme o resultado | Relatório com hipóteses eliminadas, sobreviventes e próximo teste | Não prolongar uma busca apenas porque está incompleta |

### 1. Determinar o que sustenta a receita

Reutilizar os dados originais já conferidos, preservando seus hashes. Examinar especificamente:

- `91 = 14×13/2`: justifica a possibilidade de distribuir DBBI nos pares de 14 elementos, mas não prova essa interpretação.
- `570 = 38×15`: justifica a dimensão possível de FAED; ainda é necessário explicar a orientação e a escolha de 15.
- As somas dos pesos, o XOR, a repetição da chave de 14 valores e o módulo 26: identificar quais passos são inferências de X e quais têm pista independente.
- A redução das posições coloridas pelos módulos 38, 15 e 9: registrar o motivo de cada módulo e da contagem iniciada em 1.
- O script de X usa as posições das cores; os bits das células não coloridas não entram nessas fórmulas. Determinar se o papel de `matrixsumlist` nessa interpretação é suficientemente explicado.

Usar o contexto já recuperado das mensagens #1710, #6508–#6509, #8000, #8330 e #8446/#8483. ASCII 127 (#32613) é uma fonte confirmada, mas não será convertido automaticamente em comando de remoção ou base numérica.

**Entrega:** uma tabela curta de decisões justificadas e decisões ainda livres. Não repetir a coleta completa do Telegram ou a leitura integral do ENDGAME.

### 2. Testar as consequências da receita, além das palavras encontradas

Construir o mapa exato dos 38 caracteres de cada resultado, preservando os números antes do módulo 26. Localizar os fragmentos originais nos seus deslocamentos publicados, sem realinhá-los para parecerem uma frase contínua.

Fazer controles locais delimitados:

1. Alterar uma posição por vez de DBBI e FAED para cada um dos outros oito símbolos de `a..i`: **5.288 alterações unitárias**, conservando a receita fixa.
2. Registrar quais saídas mudam, quais não mudam e quais diferenças são apagadas pelo módulo 26.
3. Como controle das cores, examinar as **135 trocas de uma célula azul por uma amarela**, conservando as 15 azuis e 9 amarelas. Não selecionar uma troca como solução apenas por produzir palavras melhores.
4. Comparar o mapa analítico de dependências com as mudanças observadas.

Esses controles medem dependência e perda de informação, não autenticidade. A consequência procurada é uma regra que explique dados ainda não utilizados para escolher os fragmentos, como o restante das saídas ou uma composição de senha determinada pelas fontes.

**Critério de decisão:** se o resultado apenas reproduzir as palavras já conhecidas sem uma consequência independente, rebaixar a exploração de alfabetos derivados dessa leitura. Não repetir os controles globais de embaralhamento já concluídos.

### 3. Transformar a lacuna numa hipótese falsificável

Escolher no máximo três modelos para a primeira rodada, depois das etapas 1 e 2. Cada modelo precisa declarar:

- O papel de DBBI e de FAED: chave, lista, mensagem ou parâmetros; não exigir que ambos sejam o mesmo tipo de objeto.
- Como entram cores, primos, zeragem e `matrixsumlist`, quando utilizados.
- Quais posições influenciam o resultado e por que eventuais posições são ignoradas.
- O algoritmo completo e uma previsão testável antes de examinar a saída.
- A diferença concreta em relação às famílias já negativas no ENDGAME e nos relatórios recentes.

Não retomar o mesmo mapa hexadecimal bijetivo para ambos os campos: na leitura `b/g`, DBBI tem 16 tipos e FAED tem 25. Outros mapas permanecem possíveis, mas precisam de motivação própria. Também não repetir as 24 ordens dos pesos `8,2,1,4` nem os alfabetos azuis já testados.

**Critério de decisão:** uma contradição elimina apenas o modelo formulado. Se nenhum modelo novo tiver parâmetros justificáveis, voltar ao contexto das pistas ainda ambíguas; não substituir a lacuna por um dicionário maior de senhas.

### 4. Resolver a referência textual que entra na senha

Confrontar `lastwordsbeforearchichoice` com a sequência original da fase 3.2 e a passagem identificável da cena do Arquiteto. Primeiro verificar os materiais locais; se faltar o texto da referência cultural, buscar uma fonte primária.

Registrar exatamente onde ocorre a escolha e qual trecho termina imediatamente antes dela. A extensão do trecho e sua normalização precisam ser justificadas; evitar varrer sufixos de tamanhos arbitrários.

As 14 quebras de linha do README são editoriais e não servem como fronteiras autenticadas. A página 39 de Cosmic Duality também não é uma seleção endossada pelo criador. A capa com yin-yang, por sua vez, tem apoio no anexo recuperado.

**Entrega:** uma extração textual preferida e, apenas se a fonte for ambígua, alternativas explicitamente documentadas. Confrontar as formas escolhidas com o histórico para evitar repetir candidatos.

### 5. Submeter somente derivações completas aos verificadores

Usar primeiro o padrão comprovado nas fases anteriores: partes derivadas das pistas → concatenação especificada → SHA256 em hexadecimal → senha AES-256-CBC. Formas diretas ou bytes crus só entram quando a hipótese as justificar.

- SMALL é o alvo principal; testar também TAIL32 e COSMIC com os mesmos candidatos.
- Priorizar EVP-SHA256 e conferir EVP-MD5; o digest dos blobs ainda fechados não está demonstrado.
- Reutilizar a fase 3.2 como controle positivo e preservar o plaintext completo.
- Registrar a procedência de cada candidato, não apenas o hash.
- Uma instrução coerente exige reprodução independente e uma consequência verificável. Padding, ASCII, palavras isoladas ou checksum BIP39 sozinhos não bastam.
- Caso apareça uma chave privada candidata, verificar localmente a chave pública/endereço esperado. Não realizar transações.

## Lugar da busca FAED/base127

**Atualização de 16/09/2026: concluída.** A enumeração e sua prova independente
encontraram exatamente 188 saídas ASCII no modelo declarado. As 177 anteriores
foram recuperadas e as onze adicionais foram verificadas. Não há máscaras
pendentes nem processo a retomar nessa hipótese.

As 1.504 senhas das formas declaradas, considerando os 188 candidatos,
não produziram abertura validada. A propriedade ASCII não distingue essas
saídas como mensagens intencionais. Uma nova frente precisaria mudar uma
premissa explicitamente e justificar essa mudança por evidência; ampliar
a duração do mesmo teste não gera trabalho adicional.

As menções abaixo à busca parcial descrevem o estado histórico das rodadas
de 11/09 e não substituem esta atualização.

## Resultado esperado da primeira rodada

Uma de três entregas concretas:

1. Uma abertura reproduzível de SMALL, com conteúdo verificável e próximo passo extraído dela.
2. Uma transformação nova, inteiramente especificada pelas fontes e com consequência independente, pronta para validação adicional.
3. A exclusão de modelos definidos e uma atualização fundamentada da prioridade, com a lacuna restante claramente identificada.

O plano não promete resolver o puzzle numa rodada. Ele exige que cada rodada produza evidência que mude a decisão seguinte.

## Resultado da primeira rodada

- Etapas 1–2: operações ligadas às fontes; 5.288 alterações unitárias e 135
  trocas de cores conferidas com o script original. Os fragmentos não dependem
  de 420 posições de FAED. Uma colisão explícita altera quatro posições de
  DBBI e 442 de FAED sem alterar nenhuma soma ou saída.
- Etapa 3: três modelos delimitados foram testados: OR dos valores zerados,
  bits das quatro colunas e aplicação das duas zeragens simultaneamente.
- Etapa 4: duas fronteiras textuais documentadas; o roteiro de 27/10/2001
  confirma que Hope vem após o movimento de Neo em direção à porta.
  A fronteira pretendida pelo puzzle continua ambígua.
- Etapa 5: 55 senhas, 330 tentativas AES, um padding válido, nenhuma abertura
  validada. Regeneração independente dos candidatos e dos resultados concluída.
- Etapa 6: SMALL permanece o alvo; novas variações dos alfabetos de X perdem
  prioridade sem uma consequência independente. A busca parcial na base 127
  não foi retomada, conforme o critério do plano.

O próximo ponto de investigação é a fonte que determina a operação de
`matrixsumlist`, incluindo o contexto da resposta #6509 sobre uma pista
imprevista. Os limites demonstrados nesta rodada devem impedir a repetição
dos mesmos modelos com outras ordens escolhidas arbitrariamente.

## Continuação executada: pista imprevista e somas

O contexto de #6509 admite pelo menos duas referências anteriores: a menção
a primos em 01/03/2021 e `Infrared` em 05/03/2021. A resposta não seleciona
uma delas. Os valores 2, 3, 5, 7 e as sugestões de XOR/soma vieram de
participantes, não de uma instrução correspondente do criador.

Foram concluídas 114 buscas de modelos de somas e 176 de multiplicação ou
divisão por primos até 196, além de cinco limites sobre operações conjuntas
entre DBBI e FAED. Nenhuma correspondência completa. Os modelos de 14 somas
diretas foram excluídos para todos os inteiros por limites de repetição e
comprimento. As demais exclusões têm os escopos explícitos no
[relatório](../../../_work/matrix_hint_2026-09-11/RELATORIO.md).

A continuação precisa justificar uma transformação das somas ou outro papel
para os campos completos. Repetir as mesmas concatenações com primos maiores
não contorna as contradições provadas. A seleção dessa transformação é a
lacuna atual, sem uma fórmula nova autenticada nesta rodada.

## Continuação executada: dados compactados

O plano de interpretar os campos como dados binários foi implementado em
`solver/compressed_payload_constraints.cjs`, com verificador independente
em `solver/verify_compressed_payload.cjs`.

- Seis famílias de cabeçalhos em DBBI/FAED foram excluídas na representação
  decimal mínima, cobrindo todas as máscaras `g→0/7`.
- DEFLATE sem dicionário foi excluído nos dois campos. FAED foi excluído
  também com qualquer dicionário de até 38 bytes, tamanho do DBBI binário.
- Controles de recuperação, truncamento, bytes excedentes, checksum e
  limites passaram. A conferência independente confirmou a cobertura.
- Dicionários de 91 e 32.768 bytes tiveram sondagens de 256 nós cada;
  continuam parciais e não constituem modelos eliminados.

Nenhuma saída compactada válida foi recuperada, portanto a etapa condicional
de derivar e testar novas senhas não foi acionada. O
[relatório](../../../_work/compressed_payload_2026-09-11/RELATORIO.md) registra os
formatos não abrangidos e a fronteira pendente. Não retomar as buscas
parciais apenas por existirem; é necessário justificar o dicionário ou a
transformação adicional com uma pista independente.
