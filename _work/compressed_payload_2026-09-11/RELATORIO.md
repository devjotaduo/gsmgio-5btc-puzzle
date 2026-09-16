# DBBI/FAED como dados compactados — 11/09/2026

**Implementado e executado. Nenhum conteúdo compactado válido foi recuperado
nos modelos concluídos; nenhuma senha nova foi derivada.** A pesquisa aceita
saída binária e verifica o término do fluxo, sem exigir texto ASCII.

## Hipótese e escopo

A página representa outros trechos como números decimais inteiros. Isso
motivou investigar se DBBI/FAED, em vez de texto direto, representam bytes
compactados. Compressão é uma hipótese de trabalho, não uma dica confirmada
do criador.

O modelo fixa `a..i = 1..9`, permitindo que cada `g` seja independentemente
0 ou 7. Converte o campo original inteiro, em ordem original, de decimal
para sua representação mínima em bytes big-endian. DBBI tem 10 posições
ambíguas e resulta em 38 bytes; FAED tem 107 e resulta em 237 bytes.
Não são removidos prefixos, cabeçalhos ou bytes aparentemente ilegíveis.

## Resultados completos

| Modelo | Cobertura | Resultado |
|---|---|---|
| Cabeçalhos zlib, gzip, ZIP, bzip2, XZ e 7z | Seis formatos em cada campo; todas as máscaras 0/7 | Os 12 casos contradizem o primeiro byte obrigatório |
| DBBI como DEFLATE sem cabeçalho e sem dicionário | Todas as 1.024 máscaras | Comprimento e complemento do bloco incompatíveis |
| FAED como DEFLATE sem cabeçalho e sem dicionário | Todas as `2^107` máscaras | Referência a bytes anteriores inexistentes |
| FAED como DEFLATE com qualquer dicionário de até 38 bytes | Todas as `2^107` máscaras | Referência além do histórico disponível |

Os cabeçalhos foram descartados antes de existir um candidato que precisasse
ser descompactado: DBBI começa sempre por `21` hexadecimal e FAED por `1B`.
Esses bytes não satisfazem os formatos declarados. As referências usadas
foram as especificações de [zlib](https://www.rfc-editor.org/rfc/rfc1950.html),
[gzip](https://www.rfc-editor.org/rfc/rfc1952.html),
[ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT),
[bzip2](https://sourceware.org/bzip2/manual/manual.html),
[XZ](https://tukaani.org/xz/xz-file-format.txt) e
[7z](https://www.7-zip.org/recover.html).

### Por que DEFLATE falha

Em DBBI, o prefixo fixo `21 38 0D 66 46` indica um bloco sem compressão
com comprimento 3.384 e campo complementar 18.022. Eles não são
complementos de 16 bits, como exige esse tipo de bloco.

Em FAED, bastam as quatro combinações dos dois primeiros `g` para obter
a contradição sem dicionário:

| Primeiros dois `g` | Prefixo fixo, hexadecimal | Primeira cópia: comprimento | Distância para trás |
|---|---|---:|---:|
| 00 | `1bd4b0e6ea0007` | 157 | 2 |
| 07 | `1bd4c5a608bf06` | 157 | 1.335 |
| 70 | `1bd5805e1d75fa` | 258 | 49 |
| 77 | `1bd5951d3c34f9` | 258 | 54 |

Nesse ponto, nenhum byte foi produzido. Cada cópia pede dados anteriores
ao início do histórico. A regra e a interpretação dos códigos vêm da
[especificação DEFLATE, RFC 1951](https://www.rfc-editor.org/rfc/rfc1951.html).

### DBBI poderia ser o dicionário?

Foi testada essa possibilidade porque DBBI aparece junto de FAED. Sua
representação decimal convertida em bytes mede sempre 38 bytes.

Com esse histórico, os casos 07, 70 e 77 já falham na primeira cópia. No
caso 00, a primeira cópia passa; depois surgem distâncias 319, 323, 363 ou
369, quando apenas 197 bytes estão disponíveis. Essas quatro alternativas
dependem dos dois `g` seguintes. Assim, sete ramos cobrem todas as máscaras.

Essa exclusão vale para **qualquer conteúdo de dicionário com até 38 bytes**.
Os valores copiados mudam a saída, mas não os comprimentos nem as distâncias
do fluxo comprimido. O programa usa um dicionário de zeros apenas para
verificar a estrutura. Ele não apresenta esses zeros como plaintext.

## Como a cobertura foi provada

Cada ramo fixa algumas escolhas 0/7 e calcula um intervalo inteiro contendo
todas as escolhas restantes. Bytes iguais no início dos dois extremos
são fixos em todo o intervalo. Um erro estrutural nesse prefixo elimina
todas as continuações desse ramo.

Foram necessários 1, 7 e 13 nós para os três modelos DEFLATE completos,
respectivamente. **Isso não é uma enumeração física de `2^107` arquivos.**
Os certificados registram escolhas, limites decimais, prefixos, erro e
quantidade de máscaras eliminadas. A conferência verifica que os ramos
não se sobrepõem e cobrem exatamente todas as máscaras.

## Validação independente

O programa principal usa a descompactação completa do Node, sem flush
parcial, e confere o consumo de todos os bytes. Limites de memória ou
tempo geram estado incompleto, nunca uma exclusão. As opções foram
conferidas na [documentação da versão 24.13.0](https://raw.githubusercontent.com/nodejs/node/v24.13.0/doc/api/zlib.md)
e em controles executados localmente.

Passaram:

- Nove recuperações de arquivos conhecidos, incluindo conteúdo binário e
  os três tipos de bloco DEFLATE: armazenado, Huffman fixo e dinâmico.
- Nove buscas com máscaras plantadas, comparadas com enumeração completa
  do espaço limitado desses controles.
- Nove rejeições de truncamentos e nove de bytes excedentes.
- Seis recuperações zlib/gzip e seis rejeições de checksum alterado.
- Controles com dicionário, candidato estrutural e limites de recursos.

O segundo programa não importa o solucionador e lê os bits de blocos
DEFLATE armazenados/fixos diretamente. Ele confirmou os 12 certificados
das buscas completas, os 12 impedimentos de cabeçalho e uma enumeração
separada das 1.024 máscaras de DBBI. Seus controles incluem cinco casos
positivos e 1.109 prefixos truncados.

O leitor independente não implementa blocos dinâmicos. Nenhum certificado
de exclusão desta rodada depende deles; o descompactador principal os
aceita e os exercita nos controles.

## Sondagens que permanecem parciais

Dicionários de **91 bytes** — tamanho do DBBI literal — e de **32.768 bytes**
também receberam sondagens limitadas a 256 nós cada. Nenhum candidato foi
encontrado nessa janela, mas ambas as buscas ficaram **incompletas**.
Não se afirma que esses modelos sejam impossíveis.

A fronteira pendente foi salva em
[larger_dictionary_probes.json](larger_dictionary_probes.json). O verificador
independente também conferiu os ramos já eliminados dessas sondagens e
sua separação dos ramos pendentes: 177 certificados no total, dos quais
12 pertencem às três buscas completas. A existência dessa fronteira não
é evidência de que uma solução esteja nela.

## Reprodução e artefatos

```powershell
node solver/compressed_payload_constraints.cjs --probe-dictionaries
node solver/verify_compressed_payload.cjs
```

Sem `--probe-dictionaries`, o primeiro comando executa apenas os modelos
principais. Os programas usam módulos nativos do Node e a entrada local
já validada. Não fazem requisições externas nem modificam as cifras.

- [Solucionador](../../solver/compressed_payload_constraints.cjs)
- [Verificador independente](../../solver/verify_compressed_payload.cjs)
- [Especificação e hashes](spec.json)
- [Controles](controls.json)
- [Resultados e certificados](results.json)
- [Resumo](summary.json)
- [Conferência independente](verification.json)

## Consequência para o puzzle

O passo proposto foi implementado e executado, mas não recuperou uma
instrução ou componente de senha. Por isso, não gerou novas tentativas AES.

Foram excluídas somente as representações e os formatos declarados.
Brotli, LZMA sem cabeçalho, outros mapas/bases, transformações adicionais,
fluxos em outros deslocamentos e dicionários maiores não foram excluídos.
Ampliar essas possibilidades exige uma pista ou previsão adicional;
esta rodada não identifica uma delas como a correta.
