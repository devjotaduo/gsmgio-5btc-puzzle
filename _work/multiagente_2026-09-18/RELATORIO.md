# Rodada multiagente — recuperação de cobertura e hipóteses finitas

**Estado: concluída; puzzle não resolvido.** Trabalho restrito à worktree
`gsmgio-5btc-puzzle-oraculo-duplo`, branch `codex/oraculo-duplo`. O checkout
principal fornece somente fontes de leitura. Nenhuma transação foi construída.

## Método e critério de resultado

Seis frentes independentes confrontaram fontes, código, corpus e negativos;
achados foram compartilhados antes de selecionar os experimentos. Revisores
independentes conferem controles e cobertura. Correspondência integral de chave
com um dos dois endereços ou uma abertura AES semanticamente verificável é
necessária; padding, escore textual e contagens previstas não constituem solve.
`17ucy…` é destino dos halvings; sua condição de prêmio permanece não confirmada.

Esta rodada não parte de uma nova fala do criador. Reabre apenas lacunas concretas
de implementação, material recuperável e duas operações finitas identificadas
pela crítica dos relatórios anteriores. Não conclui impossibilidade do puzzle.

## Correções reproduzidas

1. **EBCDIC inverso.** O oráculo isolado cobria `decode(cp273)`, mas o antecedente
   autêntico da fase 3.2 usa `ASCII.decode(cp273).encode(latin-1)`. Todos os 1.539
   bytes do Beaufort coincidem no offset 447 do plaintext autenticado. A nova
   visão inverte essa transformação, preserva offsets e usa delimitador para
   caracteres não representáveis. Controles de tabela completa, hex64/WIF,
   cortes internos e nulos passaram. [Auditoria](codecs/RELATORIO.md).
2. **COSMIC com scanner interrompido.** Os binários completos estavam disponíveis,
   mas o log Go registra falta de memória e arquivos de resultado vazios. O total
   de janelas no relatório antigo era calculado previamente, não comprovação
   de conclusão. Foram recuperados os dois binários, sem repetir as buscas AES.
3. **Bifid com caudas descartadas.** Dois logs preservam senha, comprimento e
   `head48`; 49.232 registros AES foram reproduzidos com prefixo e comprimento
   exatos. As caudas entram no novo corpus. Uma linha órfã de 17 bytes foi
   demonstrada redundante, já contida no payload 191126.
4. **Filtro de modos de fluxo.** O código histórico rejeita binário pouco legível
   antes de varrer raw32 interior. Controles de CTR/CFB/OFB/ChaCha20 reproduzem
   falsos negativos. A campanha ampla não foi refeita: cobrir todas suas saídas
   exige aproximadamente 14,2 bilhões de janelas, não apenas reexaminar os logs.
   [Reprodução e custo](audit_stream/RELATORIO.md).
5. **Decodificadores do resíduo.** O pipeline antigo enviava só top-20 por família
   ao AES e identificava marcadores pelo conteúdo `b`/`be`, alterando também `b`
   não primo. O complemento usa a posição lógica e testa todas as saídas, sem
   gate linguístico; preserva o scorer limpo quando utilizado para descrição.

## Corpus recuperado e varreduras

O corpus novo contém **225.854 plaintexts completos**, **260.180.711 bytes** e
**253.179.237 janelas raw32 por orientação**, sem igualdade integral com os três
bancos do primeiro levantamento. A comparação é por SHA256 e bytes exatos.
178.354 conteúdos vêm dos binários COSMIC e 47.500 adicionais dos logs Bifid.
Há 231.979 origens e 6.125 repetições entre os conteúdos novos.
Ausência de igualdade entre payloads completos não significa ausência de
prefixos ou janelas de 32 bytes repetidos entre corpora. As contagens abaixo
são tentativas por janela/orientação, não chaves distintas.

Banco SHA256: `4637c0722090360376b20392234674689ebacc3417bc5c97f33fd6b3d433820f`.
[Resumo da coleta](recovered/summary.json). Fontes e snapshots ficam locais.

O novo scanner registra apenas lotes efetivamente concluídos, reconcilia os
totais com o SQLite imutável e verifica novamente hashes de código e corpus
antes de declarar conclusão. Hits são confirmados com python-ecdsa e ficam em
arquivo local; stdout contém somente contagens. Controles confirmaram chave
plantada BE, LE e hex64, retomada idêntica e rejeição de corpus adulterado.

- Corpus anterior: revisão textual ampliada concluída em 592.339 conteúdos
  únicos; 674 hex64 + 3 WIF já conhecidos; **nenhum candidato no novo codec e
  nenhum hit**. Não repetiu os 58 milhões de janelas raw32 já testadas.
- Corpus recuperado: **varredura concluída** nos 225.854 plaintexts. Foram
  verificadas 253.179.237 janelas raw32 big-endian e o mesmo número em
  little-endian, total de **506.358.474 tentativas**, sem chave dos dois alvos.
  Não surgiram hex64 ou WIF adicionais. O scanner terminou com 2.506 lotes; a
  auditoria independente reconciliou lotes, bytes, hashes, banco SQLite e
  `hits.jsonl` vazio sem repetir ECC. [Resumo](scan_recovered/summary.json) e
  [auditoria final](scan_recovered/final_qa.json).
- A revisão textual separada dos 225.854 conteúdos recuperados já terminou:
  **nenhum candidato hex64/WIF** nas visões implementadas. A triagem semântica
  examinou 677.562 visões — bytes originais e as duas direções de cp273 — e não
  encontrou candidatos por `G.semantic`, trechos ASCII de pelo menos 48 bytes
  ou cabeçalhos de blobs aninhados. Isso não decodifica formatos arbitrários.
  [Relatório da triagem](recovered_semantic/RELATORIO.md).

## Hipóteses pequenas

- **Reinserção dos primos:** inserir o próprio primo nos marcadores lógicos
  L83/L84 antes das somas de todas as grades retangulares exatas. São 2.016
  ocorrências de material, 1.620 materiais únicos e **24.192 decisões AES**
  efetivas, incluindo repetições, nas formas raw e SHA256-hex. Resultado:
  98 paddings, nenhum candidato semântico ou chave. As composições usam os
  textos literais `lastwordsbeforearchichoice` e `thispassword`, **não as falas
  do Arquiteto**. Os 100 nulos completos deram média de 97,48 paddings e nenhum
  candidato. [Escopo da execução v2](reinsert_primes_v2/RELATORIO.md).
- **Decodificadores do resíduo:** 23.164 configurações, corrigindo a máscara e
  retirando o filtro linguístico antes do AES. 9.068 saídas mudam; 71.599
  materiais geram 143.198 senhas únicas e **859.188 decisões AES**. Nenhuma
  abertura semântica ou chave em 3.420 paddings completos, 1.635.534 janelas
  raw32 BE e 143.242 escalares derivados únicos. O nulo usa 100 réplicas de
  uma amostra fixa de 64 configurações estratificadas, total de 178.116 AES;
  não equivale a cem campanhas completas, não inclui ECC e não fornece
  p-value global. Uma implementação independente reproduziu as 46.328 saídas
  dos dois geradores e todos os 3.420 paddings.
  [Relatório e limites](residue/RELATORIO.md).
- Geometria da capa: o arquivo tratado como ausente já existia e tem hash
  `3a9b0a6ecacef83e1ef9f688303105570b3dcae95fd82be75f1fcbd2f5fddd04`.
  Os dois centros são compatíveis com olhos convencionais de yin-yang. A busca
  pequena usa quatro limiares predefinidos, coordenadas inteiras/duas grades,
  soma/diferença e 100 rotações rígidas como nulo. É uma hipótese de baixo prior,
  sem evidência de que o autor tenha cifrado coordenadas nessa imagem. A execução
  final cobriu 192 materiais, 384 senhas e **2.304 decisões AES**, produzindo
  14 paddings e nenhum candidato semântico ou chave. Foram conferidos também
  384 brainwallets e 6.911 janelas raw32 BE. Os nulos preservam rigidamente
  a geometria medida; não incluem ECC e podem gerar números distintos de
  senhas após deduplicação. [Relatório final](cover_final/RELATORIO.md).

- **Listas seguidas de cláusulas do Arquiteto:** a crítica da reinserção levou
  a um complemento restrito de 270 bases numéricas + duas cláusulas fixas.
  Os 540 materiais geram 1.080 senhas sem coincidências em 14 corpora comparáveis
  de 13 campanhas. As **6.480 decisões AES** produziram 31 paddings, nenhum
  candidato semântico ou chave em 16.464 janelas raw32 BE. Cem nulos, sem ECC,
  deram 647.808 AES e 2.515 paddings sem candidato semântico. A primeira cláusula
  vem da fase 3.2 e tem recorte interpretativo; a segunda é de roteiro anterior
  ao filme. [Resultado e limites](reinsert_architect_v2/RELATORIO.md).

As quatro campanhas acima somam **892.164 decisões AES reais**. As execuções
preliminares de reinserção, composição e capa não são somadas novamente. Nenhuma
dessas contagens equivale a senhas únicas entre campanhas ou inclui o grande scanner.

## Fontes: contexto que corrige inferências anteriores

As datas e IDs abaixo referem-se à versão do export local; versões anteriores
de mensagens editadas não estão disponíveis. Os exports não são publicados.

- Jrk Bgrt, 21/05/2020, #4105: “First or zero” responde à numeração da primeira
  peça/fase zero. Não especifica origem 0/1 para indexar primos.
- Jrk Bgrt, 26/12/2021, #8000: exige primos e caracteres a zerar; não identifica
  os caracteres nem afirma que os próprios marcadores primos devem ser zerados.
- Jrk Bgrt, 28/04/2025, #39237: em resposta à pergunta sobre yin-yang após AES,
  descreve-o como a próxima fase. Favorece buscar uma abertura antes dessa etapa.
- Jrk Bgrt, 06/08/2023, #9607: afirma que os participantes já têm a informação.
  Negativos de famílias finitas não demonstram necessidade de insumo externo.
- `half/better half` é usado pelo autor para si e sua parceira. O plural da fase
  3.2 não estabelece sozinho dois endereços de prêmio.

## Frente on-chain

As duas transações dos halvings foram conferidas a partir dos bytes brutos e
respeitam a ordenação BIP69, sem OP_RETURN próprio. A inversão da posição das
saídas acompanha seus valores. Foram verificadas 18 serializações correspondentes
a Q, -Q, Q/2, 2Q, Q/4, 4Q, Q-G, Q+G e (2^256-1)G-Q, em duas bibliotecas; nenhuma
produz `17ucy…`. Isso cobre essas relações apenas, não relações arbitrárias.

## Limites

As lacunas de modos de fluxo e CBC sem padding binário não estão fechadas.
`Salted__` sozinho não determina KDF, número de iterações ou uso de padding.
O custo estimado de uma campanha não é autorização para afirmar que ela rodou.
O scanner cobre janelas de 32 bytes já preservadas, nas duas orientações; não
reconstrói plaintexts descartados por scripts históricos, não cobre a lacuna
grande dos modos de fluxo/CBC sem padding, nem prova que nenhuma representação
ou KDF fora dos parâmetros declarados seja a solução.
