# Prioridade de investigação — 11/09/2026

> **Auditoria de 15/09/2026: o classificador histórico está contaminado pelas
> próprias cifras.** O filtro de `solver/scorer.py` admite 65 mensagens com
> DBBI e 25 com FAED; reconstruir o treino reproduziu integralmente o cache.
> Notas desse modelo não são evidência independente de linguagem natural.
> Há um perfil de quadgramas gerais de inglês, sem o corpus do puzzle, em
> `general_english/scorer.json` (arquivo local: `_work/ambiguous_checkerboard_2026-09-15/general_english/scorer.json`).
> Preservar o cache antigo para reprodução e usar o perfil independente em
> novas classificações. [Auditoria e limites](../../_work/ambiguous_checkerboard_2026-09-15/RELATORIO.md).

**Escolha: avançar a SalPhaseIon até abrir autenticamente o blob SMALL.**
Dentro dessa etapa, priorizar o significado operacional de
`yellowblueprimes / matrixsumlist` e o papel de `dbbi`. Essa é uma preferência
comparativa baseada nas pistas; não há base para atribuir uma porcentagem de sucesso.
O algoritmo exato continua desconhecido.

A revisão abrangeu o README, o histórico ENDGAME, os briefings, a colaboração
Claude/GPT, as fontes e verificadores do solver, os resumos e mensagens originais
do Telegram e um inventário dos **183 scripts Python**, sem executá-los. Foram
inspecionados os mecanismos de validação e experimentos representativos das
principais famílias. Não foi uma auditoria linha a linha de todos os scripts,
nem uma repetição de todas as campanhas antigas.

## O achado que muda a leitura das pistas

**O anexo elogiado pelo criador é a CAPA de Cosmic Duality, com um yin-yang.
Não é a página 39 nem o poema francês.**

- Em 10/12/2022, a mensagem **#8310**, de semaj, enviou
  `image_2022-12-11_07-09-14.png`: 146.396 bytes, 377×499 pixels.
- Em 11/12/2022, **#8311**, o criador respondeu diretamente a esse anexo:
  “.... That is very specific”. Em **#8315**, reforçou a especificidade.
- A imagem reaparece encaminhada de barrystyle em **#48646**, de 02/09/2025.
  O arquivo foi localizado no export de Downloads e inspecionado visualmente.
  Nome, tamanho e dimensões coincidem com os metadados do original. Não existe
  hash do arquivo original de 2022 no export para comparação criptográfica.
- A mensagem original **#8328**, de 09/01/2023, diz apenas que barrystyle já
  forneceu uma pista específica. O acréscimo
  “(Cosmic Duality Book Page - Life and Death)” aparece na compilação de
  **Diego Schmidt, #43344, de 13/06/2025**, não nessa fala original do criador.

Cópia recuperada: capa (arquivo local: `_work/review_2026-09-11/creator_endorsed_cosmic_cover.png`).
SHA256: `3a9b0a6ecacef83e1ef9f688303105570b3dcae95fd82be75f1fcbd2f5fddd04`.

Consequência: **Cosmic Duality ↔ yin-yang tem sustentação direta no anexo**.
A seleção da página 39, de suas últimas palavras ou de uma operação de espelho
continua sendo interpretação posterior. Isso não demonstra que o livro inteiro
seja irrelevante, nem que a palavra `yinyang` seja a senha.

## Pistas, com o que realmente permitem concluir

Os IDs abaixo referem-se ao `result.json`, salvo as mensagens de julho de 2026,
verificadas no export complementar. Trechos e relações de resposta estão em
primary_clues.json (arquivo local: `_work/review_2026-09-11/primary_clues.json`).

| Evidência | Força e consequência operacional |
|---|---|
| **Página SalPhaseIon:** `matrixsumlist`, `lastwordsbeforearchichoice`, `thispassword`, `shabef …`, `ans too` | Texto primário decodificado. Indica operações e referências a resolver. Não comprova que todas essas palavras sejam ingredientes literais da senha. |
| **14/01/2020, #1710:** cores com números e retorno à primeira peça | Forte ligação à matriz inicial e às cores. Não especifica contagem, RGB, soma hexadecimal nem fatoração. |
| **14/03/2021, #6508–#6509:** pedido de pista sobre `matrixsumlist`; criador responde que já deu uma pista imprevista | Liga diretamente esse trecho ao histórico de dicas. Primos são uma referência plausível pelo contexto de março; a resposta não nomeia uma operação. |
| **26/12/2021, #8000:** outra porta, primos necessários e caracteres a zerar | Forte. A fala não contém “prime positions”, não identifica os caracteres e não diz que zerar significa necessariamente trocar `g` por `0`. |
| **09/01/2023, #8330:** pelo menos um primo é importante | Reforça a relevância de primos. Não escolhe 101, 163, um ISBN ou um índice. |
| **23/02/2023, #8446; endosso #8483:** mensagem binária | Revertendo o fluxo inteiro de 1.288 bits obtém-se `yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang…`. A ordem textual é objetiva; interpretá-la como etapas sequenciais é uma hipótese forte, não uma definição formal do algoritmo. |
| **06/08/2023, #9599; 28/04/2025, #39224 e #39237:** ao alcançar ying-yang a solução seria rápida; é a próxima fase | Melhor indicação do ponto de avanço. #39237 responde a uma pergunta sobre encontrar yin-yang após AES, mas não identifica qual dos três blobs. |
| **26/01/2024, #20223:** uma chave privada Bitcoin normal | Define o objetivo final. Não exclui BIP39 como intermediário e não exige que o plaintext seja uma chave binária crua. |
| **03/03/2026, #60304, #60309–#60312:** Looking Forward / “in front of your eyes” / Bingo | O livro é uma interpretação contextual plausível. O criador não responde diretamente à pergunta que o nomeia. Não há indicação de página, passagem ou cifra de livro. |
| **12/07/2026, #66573–#66574:** amigos próximos teriam mais chance; “isso é uma pista” | Sugere que referências familiares ao autor podem importar. Não demonstra necessidade de informação privada ou acesso ao laptop. |
| **28/05/2026, #63957:** puzzle continua válido apesar dos sites fora do ar | Desfavorece declarar o problema bloqueado por um serviço desaparecido. Não prova que todos os insumos já estejam neste repositório. |
| **29/08/2023, #12653:** confirma que as mensagens citadas na blockchain não são dele | Rebaixa a trilha dessas mensagens. Não é necessário investigar carteiras de outros solvers para decifrar o material local. |

## Por que escolher SMALL primeiro

1. Ele está no mesmo trecho que as instruções parcialmente entendidas de
   SalPhaseIon. É o alvo com associação local mais direta a essas pistas.
2. A frase `ans too` após SMALL torna plausível que sua resposta alimente
   COSMIC. Essa ligação ainda precisa ser demonstrada por decifração.
3. Uma abertura correta daria um ponto de apoio muito mais forte que um
   fragmento isolado de um decoder clássico.
4. O criador descreve yin-yang como uma etapa a alcançar, apesar de a imagem
   do símbolo e o título Cosmic Duality já serem públicos. Portanto, apenas
   reconhecer o símbolo não equivale a chegar à etapa prometida.

`dbbi` merece atenção dentro dessa frente porque tem distribuição mais desigual
e está imediatamente antes de `matrixsumlist`. Isso permite investigar sua
estrutura e função sem assumir que seja uma chave Bifid. Seus 91 símbolos dão
pouco texto para análise estatística: ser mais curto não o torna automaticamente
mais fácil. `faed` deve permanecer no modelo, pois ambos podem depender da mesma
regra.

Sob AES-CBC/PKCS#7, os comprimentos confirmados de ciphertext impõem:

| Alvo | Ciphertext | Plaintext possível | Prioridade |
|---|---:|---:|---|
| SMALL | 80 B | 64–79 B | Primeiro ponto de validação |
| TAIL32, ao fim da fase 3.2 | 80 B | 64–79 B | Segundo alvo; testar os mesmos candidatos, sem presumir dependência de SMALL |
| COSMIC | 1.328 B | 1.312–1.327 B | Testar também; leitura do conjunto favorece uma etapa posterior, sem prová-la |

Esses tamanhos não revelam o conteúdo. Por exemplo, 64 caracteres hexadecimais
cabem nos blobs curtos; uma WIF isolada de 51/52 caracteres não teria ciphertext
de 80 bytes nesse formato. Rótulos e outros conteúdos podem mudar essa conta.

## O que perde prioridade

**Os 35 blocos e a cadeia comunitária.** Partem de resultados sem autenticação
independente. Em particular, o `Salted__` interno é produzido pela própria
escolha da máscara XOR (`cc[158:166] XOR Salted__`), não descoberto como um
cabeçalho inesperado. Reproduzir esse cabeçalho ou os hashes posteriores não
confirma a cadeia.

**BTCSEED como cabeçalho confirmado.** Fiz um controle novo: mantendo somente
oito símbolos de `faed` e alterando os outros **562**, o Bifid canônico continuou
produzindo `BTCSEED` em **1.000/1.000 casos**. Isso demonstra que o fragmento não
valida o corpo. Não demonstra, sozinho, que o fragmento original seja acidental.
Sem uma consequência independente, não é a melhor âncora para escolher novas cifras.

**“dbbi é um SHA256 disfarçado”.** A tokenização com prefixos `b/g` realmente dá
64 tokens e 16 símbolos. Porém isso é uma forma compatível com hash, não uma
identificação. Uma auditoria adicional de frequências, com 200.000 simulações
de 64 nibbles uniformes, deu cauda de 7,62% para a estatística observada
(4,26% condicionando todos os 16 símbolos aparecerem). Não confirma nem elimina
o modelo. As buscas anteriores eliminam as pré-imagens testadas; não todas as
pré-imagens possíveis. Manter como hipótese secundária, sem ampliar dicionários
até surgir uma pista para a entrada ou para o mapa de símbolos.

**Máscaras `g→0/7` e varreduras genéricas.** O teste da sessão anterior já exclui
a conversão decimal→ASCII nas leituras especificadas. Ele não exclui a pista de
zerar caracteres em outros sentidos. Novas tentativas devem explicar uma pista
ainda não explicada, não apenas acrescentar combinações a uma busca.

## Próxima investigação escolhida

**Resolver a ligação entre cores/primos e `matrixsumlist`, usando `dbbi` como
primeiro objeto de análise e SMALL como primeiro teste final.**

Os dados fixos disponíveis são a matriz de 101 uns, suas duas listas de somas,
as cores originais e as cadeias verbatim da página. A recontagem confirmou:

- Linhas: `[6,10,8,7,6,6,5,4,9,9,7,8,7,9]`.
- Colunas: `[8,10,8,10,8,7,3,6,7,5,9,6,6,8]`.
- As 24 células coloridas marcam exatamente o último bit de cada byte da URL.
- As somas hexadecimais das cores são 47 e 54, cuja soma é 101. A igualdade é
  real; sua intenção e utilidade como operação ainda não estão demonstradas.

A palavra `list` recomenda preservar as listas, não reduzir imediatamente tudo
ao total 101. Mas leituras diretas dessas listas já foram testadas. Para retomar
essa frente é necessário formular uma regra que conecte **explicitamente**
cores, primos e lista, indicando a origem de cada parâmetro e a diferença em
relação aos experimentos existentes. Outra máscara arbitrária não resolve isso.

`lastwordsbeforearchichoice` deve funcionar como restrição textual adicional,
confrontada com a cena do Arquiteto e com os textos já decifrados. A frase não
diz “últimas palavras do poema da página 39”. A gramática SHA256→AES das fases
anteriores serve como primeiro teste da resposta obtida, nos três blobs. Priorizar
EVP-SHA256; manter MD5 como controle secundário, pois os blobs desconhecidos não
têm KDF provado.

O critério de avanço é recuperar uma instrução coerente ou uma estrutura
verificável que permita prosseguir. Padding, palavras soltas e checksums BIP39
isolados não bastam. Uma chave candidata só resolve o prêmio se gerar o
endereço esperado. A ausência de ASCII também não elimina automaticamente uma
saída binária que tenha outra estrutura verificável.

Artefatos desta revisão em `_work/review_2026-09-11/` (diretório local: `_work/review_2026-09-11/`):
inventário dos scripts, mensagens primárias, proveniência da capa, controles
estruturais e auditoria da hipótese de hash. **Nenhuma senha final foi encontrada.**

## Investigação executada em 11/09/2026

A linha escolhida foi executada em
[`prime_geometry_constraints.cjs`](../../solver/prime_geometry_constraints.cjs).
Os 24 primos até 91 e os dígitos de `dbbi` que eles indexam foram recolocados
nas 24 coordenadas coloridas e somados por linha/coluna. As 80 matrizes geraram
320 listas e 45.064 senhas distintas, testadas nos três blobs com EVP-SHA256 e
MD5: **nenhuma abertura validada**. A conferência independente examinou as
1.078 saídas com padding e 525.982 janelas binárias de chave, sem atingir o prêmio.

Uma restrição de estrutura também excluiu `dbbi` como soma ou distância entre
14 valores escalares nas oito leituras triangulares examinadas, mesmo permitindo
qualquer ordem dos valores e renomeação bijetiva dos símbolos.

**Correção adicional:** as 14 últimas palavras de linha antes de `SELECT`
dependem do layout do README. O bloco original recuperado tem 1.539 bytes sem
espaços ou quebras internas; Beaufort reproduz as 1.539 letras da fala, não suas
14 divisões editoriais. Esse alinhamento não deve ser tratado como pista
autenticada. Detalhes, controles e limites no
[relatório de execução](../../_work/prime_geometry_2026-09-11/RELATORIO.md).

## ENDGAME lido integralmente

A revisão posterior cobriu as 2.923 linhas do ENDGAME e reconciliou suas
conclusões históricas. O script original de X, antes dado como ausente, foi
recuperado e comparado com a reconstrução: mesmos dados e mesmas três saídas.
Isso fecha a lacuna de fonte, sem produzir senha nova. O teste de `dbbi` como
somas de pares não refuta a receita inversa de X, que usa `dbbi` como pesos.
A prioridade de SalPhaseIon/SMALL permanece, com os limites e correções no
[registro da leitura integral](../../_work/endgame_review_2026-09-11/LEITURA_ENDGAME.md).

## Continuação da receita original de X

Foram executadas quatro famílias adicionais: alfabeto a partir dos dígitos
azuis; alfabeto a partir dos pesos binários `8,2,1,4` obtidos dos primos
azuis; valores numéricos anteriores ao módulo 26 de X; e concatenação dos
novos candidatos com matriz, `faed` e últimas palavras. **5.346 senhas,
32.076 tentativas AES nos três blobs, nenhuma abertura validada.**

O elo `17,47,163,193 → 8,2,1,4 → 16 valores hexadecimais` é aritmeticamente
exato, mas sua aplicação aos tokens `b/g` não foi autenticada. A prioridade
SalPhaseIon/SMALL permanece. O [relatório desta continuação](../../_work/blue_hex_2026-09-11/RELATORIO.md)
preserva as fórmulas, as pré-imagens e os limites, evitando repetir essas buscas.

## ASCII 127: fonte recuperada e modelos delimitados

A frase “I think I'll be going for ASCII 127 myself. But not overly
dramatic.” é de Jrk Bgrt, #32613, em 29/11/2024, no export local. Sua
resposta é à pergunta de ArchOptic sobre qual personagem imaginar.
X associou a fala a DEL na #32615; essa interpretação já constava de
sua #25419, em 06/05/2024. **A autoria da frase está confirmada; o
algoritmo de remoção, zeragem ou conversão de base continua hipotético.**

Foram testadas as 55 bases primas até 257 para o inteiro decimal
original, com cada `g` independentemente 0/7 e os dígitos resultantes
interpretados como ASCII direto (32–126, TAB, LF, CR). DBBI não admite
saída nesse conjunto em nenhuma delas; FAED foi excluído em 54 bases.
**FAED/base127 permanece incompleto**, com 177 candidatos encontrados.
As 1.416 senhas derivadas desses candidatos passaram por 8.496 testes
AES nos três blobs: nenhuma abertura validada.

A leitura `b/g` também não admite **um único mapa hexadecimal bijetivo**
para ambos os campos: DBBI tem 16 tipos, FAED tem 25. Isso restringe a
hipótese do mapa compartilhado, sem refutar funções ou mapas diferentes.
A prioridade continua SalPhaseIon → SMALL. A próxima ligação precisa
explicar como as pistas selecionam a transformação e usam os campos
completos; ampliar listas de senhas por si só não resolve essa lacuna.
[Fontes, resultados completos e ponto de retomada](../../_work/shared_numeric_2026-09-11/RELATORIO.md).

## Plano executado: dependências de X e consequências delimitadas

A primeira rodada do [plano](PLANO_PROXIMA_ETAPA.md) foi concluída. Os 5.288
controles de símbolos e as 135 trocas de cores conferiram com o programa
original. Os fragmentos publicados não dependem de 420 posições de FAED;
uma colisão construída altera quatro posições de DBBI e 442 de FAED sem
mudar as somas ou as três saídas. Isso demonstra a perda de informação da
receita, sem refutar o uso intencional de somas no puzzle.

Três consequências específicas — OR dos valores zerados, bits das quatro
colunas e combinação das duas zeragens — geraram 55 senhas e 330 testes
AES. Nenhuma abertura validada. Duas extrações textuais foram documentadas;
o roteiro consultado coloca Hope depois do movimento de escolha de Neo.
A identificação das últimas palavras pretendidas pelo puzzle permanece aberta.

**Decisão:** manter SalPhaseIon → SMALL, rebaixando novas variações de
alfabetos baseadas somente nos fragmentos de X. Priorizar a fonte que
determine a operação entre cores/primos e `matrixsumlist`, incluindo o
contexto da resposta #6509 sobre uma pista imprevista. FAED/base127 continua
secundário e parcial. [Evidências, código e verificação](../../_work/recipe_audit_2026-09-11/RELATORIO.md).

## Continuação: contexto de #6509 e exclusões exatas

A pista imprevista não foi identificada de forma única: o contexto anterior
contém tanto primos quanto `Infrared`. As sugestões específicas de valores,
XOR e soma vieram de participantes. Não há uma resposta do criador que
selecione uma dessas operações.

Modelos com dois inteiros fixos, um por cor, foram invertidos usando os
campos completos. As 14 somas diretas de linhas/colunas não podem gerar
DBBI ou FAED por concatenação decimal mínima, para quaisquer inteiros
maiores ou iguais a 2. Outros 90 casos declarados também foram negativos.
Multiplicação/divisão por primos até 196 não produz bytes inteiramente de
sete bits em nenhum dos 176 casos; cinco operações conjuntas entre os
campos também foram excluídas nesse formato de saída.

As duas famílias tiveram conferência independente. Esses resultados não
excluem o uso das somas como chave, fatores fora da faixa pesquisada,
dados binários ou outras transformações. SMALL permanece o alvo, mas a
operação anterior ao hash continua desconhecida. Não ampliar buscas já
contraditas pelos limites. [Fontes, provas e código](../../_work/matrix_hint_2026-09-11/RELATORIO.md).

## Continuação: representação compactada

O teste seguinte aceitou bytes binários, sem filtro ASCII. Na conversão
decimal original com `g→0/7`, os cabeçalhos zlib/gzip/ZIP/bzip2/XZ/7z são
incompatíveis com DBBI e FAED. DEFLATE sem dicionário também foi excluído
em ambos; FAED falha com qualquer dicionário de até 38 bytes. As exclusões
cobrem todas as máscaras e foram conferidas por um leitor independente
dos bits do formato.

Dicionários de 91 e 32.768 bytes receberam sondagens parciais; não estão
excluídos. Nenhum payload ou senha foi recuperado. Outros formatos, mapas,
bases e deslocamentos continuam fora do escopo. SMALL permanece o alvo,
sem uma transformação nova sustentada pelas pistas nesta rodada.
[Implementação, controles e limites](../../_work/compressed_payload_2026-09-11/RELATORIO.md).
