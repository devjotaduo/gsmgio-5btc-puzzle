# Oráculo de dois endereços e revisão dos plaintexts salvos

**Resultado em 17/09/2026: zero correspondências com os dois alvos.**
Foram examinados 592.339 conteúdos únicos preservados, por meio de
58.357.232 tentativas raw32, 674 hex64 e 3 WIFs com checksum válido.
Todas as 58.357.909 ocorrências de escalares válidos foram conferidas
com as duas serializações de chave pública. A fase final segue sem solução.

## Isolamento da investigação

Esta investigação foi movida para a worktree
`C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle-oraculo-duplo`, na branch
`codex/oraculo-duplo`, criada de `15db4e1` em 17/09/2026.
O módulo implementado está em `solver/oraculo_duplo_2026_09_17/oracle.py`.
Os dois arquivos migrados tiveram seus hashes SHA256 conferidos.

O corpus histórico ignorado pelo Git continua em
`C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle`; foi acessado somente
para leitura. Novos scripts, checkpoints e resultados desta investigação
foram gravados nesta worktree. As pastas `operador_ensinado` na origem
pertencem a outros trabalhos e foram preservadas.

## Hipótese e escopo, antes da implementação

O oráculo histórico compara chaves apenas com
`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`. A hipótese finita é que algum
plaintext já salvo contém uma chave de 32 bytes, em bytes brutos, hex64
ou WIF, que gera esse endereço ou
`17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`, usando P2PKH com chave pública
comprimida ou não comprimida. Cada correspondência exige derivação
criptográfica e comparação integral do hash160/endereço, seguida de
conferência independente. Padding e legibilidade não decidem este teste.

A cobertura textual inclui ASCII nos bytes originais, EBCDIC cp273
(as letras/dígitos relevantes são iguais aos de cp1141) e UTF-16 LE/BE
nos dois alinhamentos de byte. Nessas visões só hex64/WIF são candidatos;
as janelas raw32 continuam limitadas aos bytes originais, sem hashes
ou novas transformações de chave.

O segundo endereço recebeu 250.000.000 satoshis na transação
`2aa9a4a90be819d5122d70c993280785a0508f163521e7b38cebb4db0b071b13`
e 125.000.000 na
`88cdb3cdca12b471551b1b26188508a14ca5fd8a415223ffb7c190381c9b9df3`,
ambas gastando o endereço publicado do puzzle. Consulta inicial à API
do mempool.space: 375.055.856 satoshis recebidos, zero gastos, 45 transações.
É um alvo adicional relacionado aos halvings; o vínculo on-chain e a
frase no plural da fase 3.2.2 **não provam** que seja outro prêmio.

### O que o criador confirmou, e o que deixou em aberto

Conferência pontual no export local (datas, autores e IDs preservados aqui;
o export não integra o Git):

- 11/05/2020: x7x7x7x6 escreveu que metade do prêmio foi para a “better
  half” (#3901); Jrk Bgrt respondeu “Well spotted” (#3902).
- 02/08/2020: Detective Froz publicou `17ucy…` como destino da metade
  (#4587); no mesmo contexto, Jrk respondeu “Or the same puzzle, or just
  not at all” (#4589), sem reply explícito para uma mensagem específica.
- 12/01/2023: à pergunta direta se o solucionador também pode receber os
  fundos de `17ucy…` (#8365), Alex respondeu “Who knows...” (#8367) e Jrk
  respondeu a Alex com um dedo apontando para cima (#8368).

Isso fundamenta a escolha do segundo alvo para o teste, mas mantém
incerta a condição de prêmio. A expressão no plural da fase 3.2.2 não
nomeia os endereços. As falas #3923 e #8360 têm edições posteriores;
não são usadas como prova cronológica de sua redação original.

Esta é uma correção da cobertura do oráculo descrito em ENDGAME §3.7,
não uma nova hipótese de decodificação das famílias já refutadas.
O kit ativo e os arquivos de outros agentes foram preservados.

## Controles executados

- Reproduzir fase 2 com SHA256(causality) e o checkerboard da fase 3.2.2.
- Plantar duas chaves conhecidas como alvos de teste separados: o primeiro
  em P2PKH não comprimido e o segundo em P2PKH comprimido, invertendo
  também as serializações. Usar uma implementação independente.
- Cobrir offsets inicial/intermediário/final, hex64 e WIF, checksum,
  comprimento e intervalo secp256k1, inclusive escalar zero e ordem da curva.
- Nulo com pelo menos 100 embaralhamentos do mesmo multiconjunto de bytes.
- Manifesto dos arquivos, hashes dos dados, origem de cada plaintext,
  deduplicação, contagem exata de janelas/candidatos e limites explícitos.

## Resultado e cobertura exata

Controles do oráculo, codecs e scanner paralelo passaram: duas chaves
plantadas, vetor Bitcoin de escalar 1, extremos da curva, 16 escalares
conferidos por python-ecdsa, 100 embaralhamentos preservando contagens
(4.900 candidatos; zero hits), retomada sem dupla contagem e recusa de
corpus SQLite com WAL pendente. Fase 2 e checkerboard 3.2.2 reproduzidos.

O inventário abrangeu `_work/` e `solver/` da origem. A coleta principal
selecionou 1.834 de 2.641 arquivos inventariados e leu snapshots de
2.256.590.344 bytes. Começou às 20:49:10 e terminou às 20:56:46 de
17/09/2026, horário de Brasília. Cada arquivo tem seu tamanho-limite e
SHA256; isso não constitui um snapshot simultâneo dos escritores ativos.

O corpus principal contém 592.321 conteúdos únicos (76.680.140 bytes),
com 614.942 origens: 381.161 não marcadas como prefixo e 233.781 prefixos.
Conteúdos podem ter várias origens e incluir controles e representações
alternativas. Não são 592 mil chaves distintas nem necessariamente
592 mil plaintexts completos.

| Lote | Conteúdos | Janelas raw32 | Hex64 | WIF válido | Hits |
|---|---:|---:|---:|---:|---:|
| A | 26.306 | 12.052.379 | 0 | 0 | 0 |
| B | 460.322 | 37.885.761 | 189 | 1 | 0 |
| C | 105.693 | 8.418.011 | 485 | 2 | 0 |
| Suplemento `telegram_miner.jsonl` | 19 | 323 | 0 | 0 | 0 |
| Prefixo recuperado de JSONL cortado | 1 | 758 | 0 | 0 | 0 |
| **Tentativas totais** | **592.341** | **58.357.232** | **674** | **3** | **0** |

A união A+B+C é exatamente o corpus principal, sem sobreposição, com
comparação dos bytes e dos hashes. Dois conteúdos do suplemento já
existiam no principal: a união final tem **592.339 conteúdos únicos e
76.681.745 bytes**. As duas repetições acrescentam 34 tentativas raw32
ao total de execução. Offsets/conteúdos distintos podem repetir o mesmo
escalar; os números acima não contam chaves distintas.

Todos os lotes chegaram a `status: complete`. O finalizador conferiu
os totais contra os checkpoints, os hashes do corpus/código e a união
exata das partes; o hash do kit original permaneceu
`e188b18f7b48ffa1dc89869f16e22877a95855a59a2798ee11de815b2ed9f43a`.
Resumo publicável em [`summary.json`](summary.json) e controles/conferência
em [`final_qa.json`](final_qa.json). O SQLite, as origens e os checkpoints
volumosos permanecem locais e ignorados pelo Git.

## Auditoria da coleta e correções

Uma conferência independente verificou os hashes de todos os 1.834
snapshots e encontrou no corpus os **49.849 campos explicitamente
rotulados como plaintext hexadecimal, com valor entre aspas**, dentro
do escopo de sua regex. Zero campos ausentes e zero fontes impossíveis
de conferir. Esse teste não valida sozinho os campos genéricos `hex`,
as representações textuais nem caudas de gzip irrecuperáveis.

A revisão separada das 219 ocorrências `unparsed_plaintext_signal` e
dos quatro erros JSONL identificou uma lacuna recuperável:
`critico_familia5.jsonl:6215`, com 789 bytes hex antes do corte da linha.
`recover_partial.py` conferiu o snapshot de 8.716.188 bytes e o hash
do prefixo, recuperou-o e o lote complementar testou suas 758 janelas.
A cauda de 538 bytes do plaintext declarado de 1.327 bytes não estava
preservada nesse snapshot e permanece fora do negativo.

Os outros erros JSONL correspondiam a certificados binários de busca,
uma linha de zeros de arquivo refeito e um fragmento órfão de 20 bytes,
insuficiente para os formatos pesquisados. As 219 ocorrências foram
classificadas em 143 conversas Telegram, 37 frequências, 15 trechos de
código/documentação, 9 trechos de pesquisa, 5 OCR e 10 logs. Desses logs,
só o prefixo recuperado acrescentava bytes relevantes ausentes.

O coletor também sinalizou 65 erros de decodificação (64 em OCR e um
em arquivo de senhas UTF-16), um gzip incompleto de enumeração de busca,
oito quadros de log incompletos, um exemplo de código com hex inválido,
três linhas finais sem terminador e três fontes modificadas durante a
coleta. São limites registrados, não uma alegação de que todo arquivo
local contém apenas formatos conhecidos. Os três escritores ativos eram
`critico_familia5`, `critico_rab_a1z26` e `familia4_codecs`.

`telegram_miner.jsonl` havia sido excluído pelo nome como se fosse export:
foi coletado separadamente, com 26 origens e 19 prefixos únicos de 48 bytes,
sem erros. O coletor final v5 corrige essa seleção, aceita logs `[123] {…}`
e preserva as exclusões de contêineres de senhas/materiais durante o parse.
O corpus principal congelado foi criado pela v3 e o suplemento pela v4;
a revisão confirmou que o ajuste de exclusão da v5 não afeta os registros
reais do suplemento. Os manifests locais preservam as versões executadas.
A coleta preliminar `corpus_v1` foi interrompida e **não serve de evidência**.

## O que o negativo exclui e o que permanece aberto

Exclui que os bytes preservados e selecionados contenham uma chave dos
dois alvos como janela raw32, hex64 ou WIF nas codificações declaradas.
Não exclui senhas, sementes, chaves derivadas por hash, outras permutações
ou codificações, fragmentos cuja cauda se perdeu, dados fora do inventário
ou dados escritos depois do limite de cada snapshot.

As antigas campanhas de centenas de milhões de candidatos **não foram
reexecutadas**. Candidatos descartados sem salvar bytes não são recuperáveis
por este teste; seus negativos de privkey continuam restritos ao endereço
efetivamente usado. Em particular, a busca MITM 16! baseada na pubkey
exposta do primeiro endereço não passa a cobrir o segundo, cuja pubkey
não é fornecida por seu endereço P2PKH.

A correção amplia a cobertura dos bytes salvos e fornece um oráculo
isolado para trabalhos futuros. Não estabelece uma nova decodificação,
não confirma um segundo prêmio e não resolve o puzzle.

## Reprodução

Comandos e formatos em
[`solver/oraculo_duplo_2026_09_17/README.md`](../../solver/oraculo_duplo_2026_09_17/README.md).
`finalize.py` reconcilia os cinco lotes locais e grava os resumos finais.
Para repetir exatamente a campanha, preserve os SQLite com hashes de
`summary.json`; uma nova coleta da origem ativa pode ter conteúdo diferente.
