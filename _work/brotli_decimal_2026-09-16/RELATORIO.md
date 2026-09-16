# Brotli e cabeçalhos Zstandard na conversão decimal

**Nenhuma senha ou mensagem recuperada.** Brotli foi excluído para DBBI nos
dois sentidos e para FAED na ordem original, no modelo abaixo. FAED invertido
foi pesquisado parcialmente: não há candidato encontrado nem processo ativo,
mas há configurações não examinadas. Não se afirma exclusão desse quarto caso.

## Modelo

Usar os campos originais completos, `a..i=1..9`, permitindo cada ocorrência
de `g` representar independentemente 0 ou 7. Converter o número decimal
inteiro em seus bytes mínimos big-endian e exigir um único fluxo Brotli
completo, sem bytes restantes. O conteúdo descompactado pode ser binário;
não há filtro de inglês ou ASCII.

Esta é uma hipótese de representação, não uma operação indicada pelo criador.
Ela amplia a [rodada anterior de compressão](../compressed_payload_2026-09-11/RELATORIO.md),
que explicitamente não cobria Brotli. Não altera cifras, bases, posições dos
símbolos ou endianness para favorecer uma saída.

O formato usado é o Brotli da [RFC 7932](https://www.rfc-editor.org/rfc/rfc7932.html),
com seu dicionário estático padrão, sem dicionário externo ou extensão Large
Window. Um prefixo que ainda precisa de entrada não é tratado como inválido.
Erros de formato são separados de falta de entrada e de problemas de recurso,
seguindo as categorias da
[API do decodificador](https://github.com/google/brotli/blob/v1.1.0/c/include/brotli/decode.h).

## Resultados e cobertura

| Campo | Sentido dos símbolos | Decisões da árvore | Resultado |
|---|---|---:|---|
| DBBI | Original | 1 | Todas as 1.024 máscaras excluídas |
| DBBI | Invertido | 7 | Todas as 1.024 máscaras excluídas |
| FAED | Original | 275 | Todas as `2^107` máscaras excluídas |
| FAED | Invertido | 200.000 | Parcial, sem candidato |

Cada ramo fixa algumas escolhas de `g`; as restantes definem limites
inteiros exatos. Os bytes iniciais comuns aos extremos são iguais em todo
o intervalo. Se esses bytes já violam o formato, todas as máscaras do ramo
são rejeitadas. Isso permite cobrir `2^107` sem enumerar cada máscara.

Em FAED original, 138 certificados encerram a árvore: 127 rejeições da
estrutura Huffman e onze dos comprimentos de códigos. Não houve recurso
esgotado ou prefixo incompleto convertido em exclusão nessa árvore.

Em FAED invertido:

- Total: `162259276829213363391578010288128` máscaras.
- Excluídas: `83664939615063140498782411655066`.
- Pendentes: `78594337214150222892795598633062`, em 97 ramos salvos.
- O limite de 200.000 nós encerrou a execução, sem fluxo completo encontrado.

O cabeçalho inicial fixo de FAED invertido declara um último meta-bloco de
**4.366.425 bytes**. A contagem vem dos bits do cabeçalho; não comprova que
o restante seja um fluxo válido. As entradas completas verificadas nessa
sondagem produziram no máximo 1.755 bytes antes de erro ou falta de entrada.

O teto de saída do buscador é 1 MiB. Se ele fosse atingido, o ramo seria
marcado pendente, nunca excluído. Nenhum erro desse tipo ocorreu nos
certificados salvos.

## Conferências e controles

- Python reconstruiu os limites decimais sem reutilizar os pesos do programa
  Node, refez os prefixos e verificou que os intervalos de máscaras são
  disjuntos e cobrem exatamente cada domínio, incluindo os ramos pendentes.
- Todos os certificados foram reexaminados pelo decodificador Brotli em
  modo de fluxo do Python. As entradas completas classificadas como
  truncadas continuam sem terminar; os prefixos classificados como inválidos
  geram erro de formato.
- Node e Python usam bindings separados da mesma biblioteca Google Brotli
  1.1.0. Essa comparação não constitui dois algoritmos independentes de
  descompressão.
- Uma leitura direta dos bits, sem biblioteca Brotli, conferiu os cinco
  certificados de DBBI: os bits de alinhamento de um meta-bloco sem
  compressão são não zero, contrariando a seção 9.2 da RFC.
- Foram verificados 1.028 prefixos de controles válidos em Node e 812 em
  Python. A primeira bateria de buscas plantadas recuperou sete de doze;
  as cinco restantes atingiram limite e permaneceram parciais, sem exclusão
  falsa. Uma bateria adicional de **42 construções curtas**, todas concluídas,
  recuperou os controles e comparou o conjunto integral de resultados com
  **1.536 enumerações de máscaras**.

## Zstandard

Os mesmos quatro domínios também não contêm o cabeçalho de um frame
Zstandard nem os dezesseis cabeçalhos de frames ignoráveis especificados
na [RFC 8878](https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1).
Os prefixos fixos que fornecem a contradição são, respectivamente:

```text
DBBI original:  21 38 0d 66 46
DBBI invertido: 28 f7 3f
FAED original:  1b
FAED invertido: 12 0b 54 a8 2e c2 74 b3 b6 00 37 4b 4f
```

Essa exclusão de cabeçalhos vale para todo o domínio nos dois sentidos;
não equivale a excluir blocos sem frame, dados em offsets diferentes ou
outras transformações anteriores à descompressão.

## Artefatos e reprodução

- [Especificação](spec.json)
- [Árvores, certificados e pendências](cases.json)
- [Verificação Python](verification.json)
- [Leitura dos cabeçalhos e controles adicionais](header_and_controls.json)
- [Conferência independente dos cabeçalhos](header_verification.json)
- [Buscador](../../solver/brotli_decimal_constraints.cjs)

SHA256 de `cases.json`:
`d6b9f78b57b02c0ff2759b4167987a25ed1fef838056248590bf12f101223688`.

`node solver/brotli_decimal_constraints.cjs` reproduz a rodada em uma cópia
sem `cases.json` no diretório de saída. O programa recusa sobrescrever o
resultado existente e exporta `search`, `domain` e `classify` para consultas
sem escrita. A verificação Python foi executada inline. Seu módulo Brotli
está isolado em `_runtime/`, fora do versionamento; o ambiente do puzzle
não foi alterado.

Não houve senha candidata para testar em AES nesta rodada. A negativa da
ordem original enfraquece essa representação específica de FAED; ampliar
indiscriminadamente os limites da ordem invertida não determina a operação
pretendida de `matrixsumlist`.
