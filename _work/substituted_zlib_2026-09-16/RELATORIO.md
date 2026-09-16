# Fluxos zlib após substituição decimal

**Nenhuma senha final foi obtida.** A leitura sem zeros foi excluída por duas
implementações. A ampliação com letras zeráveis foi interrompida com estados
pendentes e permanece inconclusiva; nenhum processo desta busca continua ativo.

## Leitura sem zeros: concluída

DBBI e FAED, nos dois sentidos, representam inteiros decimais completos, com
qualquer bijeção entre `a..i` e `1..9`. Os bytes mínimos são lidos do mais
significativo para o menos significativo. O formato exigido é zlib com
DEFLATE, sem dicionário prévio, consumindo todos os bytes. Sua estrutura vem
dos [RFC 1950](https://www.rfc-editor.org/rfc/rfc1950.html) e
[RFC 1951](https://www.rfc-editor.org/rfc/rfc1951.html).

O [teste anterior dos cabeçalhos](../substituted_format_headers_2026-09-16/RELATORIO.md)
deixou nove intervalos nesta leitura. A busca por prefixos examinou 1.391 nós
e rejeitou os nove. Oito inteiros plantados, fornecidos como intervalos exatos,
foram recuperados nos controles. Esses controles verificam consistência da
busca, não a descoberta cega do método do puzzle.

Uma segunda implementação, em Python, enumerou diretamente as `9!` bijeções
em cada campo/sentido: **1.451.520 configurações**. Recalculou cada inteiro e
seus bytes, verificou o cabeçalho e chamou zlib independentemente do buscador.

| Campo | Sentido | Bijeções | Cabeçalhos sem FDICT compatíveis | Fluxos válidos |
|---|---|---:|---:|---:|
| DBBI | Original | 362.880 | 0 | 0 |
| DBBI | Inverso | 362.880 | 720 | 0 |
| FAED | Original | 362.880 | 600 | 0 |
| FAED | Inverso | 362.880 | 0 | 0 |

Todos os 1.320 inteiros com cabeçalhos compatíveis causaram erro de dados na
descompactação. Não houve estouro do limite de saída nem classificação
inconclusiva nesta enumeração. [Conferência exaustiva](pilot_independent.json).

## Letras zeráveis: investigação parcial

A ampliação permite que cada ocorrência de até duas letras selecionadas
valha zero ou o dígito atribuído. Há **546 intervalos** com cabeçalhos sem
FDICT compatíveis. Cada intervalo recebeu limites de 100.000 nós, quinze
segundos e 1 MiB de saída. Um limite atingido não significa rejeição.

Os primeiros doze registros completos de execução chegaram ao limite de
nós. Eles abrangem seis intervalos de DBBI original com `b` zerável e seis
com `a,b` zeráveis: **1.200.000 nós**, 599.978 certificados de rejeição e
**502 estados pendentes**. Nenhum desses doze intervalos foi encerrado.
Outros 534 intervalos não foram pesquisados integralmente. Um intervalo em
execução ao interromper não entra nas contagens preservadas.

A expansão foi interrompida porque os primeiros casos já geravam grandes
árvores inconclusivas. Os registros permanecem preservados. O arquivo de
progresso é histórico, não evidência de processo vivo. O buscador não possui
retomada automática e recusa sobrescrever seu diário existente.

Uma verificação independente dos doze registros reconstruiu todas as
ramificações e conferiu os 502 estados pendentes. Para os extremos numéricos,
usou programação dinâmica de atribuição de dígitos, em vez da ordenação de
pesos usada pelo buscador. Validou todos os certificados numéricos e
**599.846 decisões sobre prefixos zlib** com a interface Python. Isso
certifica o trabalho parcial; não encerra os estados que faltam.
[Verificação parcial](partial_verification.json).

## Limites e arquivos

Não foram testados fluxos com dicionário prévio, DEFLATE bruto, bytes em ordem
inversa, partes removidas ou prefixos adicionados. Os negativos sem zeros não
se estendem ao caso com zeros. Nenhum material descompactado foi gerado para
testar como senha AES ou chave privada.

- [Especificação do piloto](pilot_spec.json), [resultados](pilot_summary.json).
- [Especificação da ampliação](spec.json).
- [Estado da interrupção e hash do diário](interrupted.json).
- [Busca por prefixos](../../solver/substituted_zlib_search.cjs).
- [Programa da ampliação interrompida](../../solver/substituted_zlib_campaign.cjs).

O piloto foi executado por `node solver/substituted_zlib_search.cjs pilot`.
A ampliação foi iniciada por `node solver/substituted_zlib_campaign.cjs` e
interrompida com saída 1. Não reiniciar esses comandos sobre os mesmos arquivos.
Os artefatos distinguem explicitamente o piloto concluído da ampliação aberta.
