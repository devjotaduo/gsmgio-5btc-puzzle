# Auditoria de sobreposição: lista lógica seguida de cláusula

**Lacuna finita sustentada nos geradores e corpora examinados.** Esta auditoria
não executou AES, ECC nem rede. Apenas leu código e comparou conjuntos de bytes.
O checkout original examinado estava em `0ce41855e00ec92a9d63bd91b4dd86cba3a121fb`.

Dos 336 registros isolados de `reinsert_primes_v2/materials.jsonl`, existem
270 bases numéricas distintas. Acrescentar uma de duas cláusulas fixas produz
540 materiais e 1.080 senhas distintas, literal ou SHA256 hexadecimal minúsculo.
Nenhuma coincide com o conjunto conservador de 172.143 valores comparados dos
14 artefatos preservados, distribuídos por **13 diretórios de campanhas**.
Não se trata de 14 campanhas distintas nem de 172.143 tentativas AES comprovadas.

Os hashes, contagens por artefato e método exato estão em
[comparison.json](comparison.json). O conjunto anterior inclui também SHA256
hexadecimal de cada campo de bytes, mesmo quando já era uma senha derivada;
essa ampliação é conservadora para uma interseção vazia. Os 42 candidatos de
`unbounded_zero_integer` foram compostos em memória conforme o gerador histórico,
sem acionar seu oráculo.

## Fontes e limites das cláusulas

- `reinsertingtheprimebasicsafterwhichyouwillberequiredto`: letras autenticadas
  da paráfrase do puzzle na fase 3.2, `README.md:554`. Começar em REINSERTING e
  parar antes de SELECT é uma interpretação registrada; as quebras de linha
  editoriais não entram na extração. Não substituir BASICS por PROGRAM, palavra
  da fala original usada como referência.
- `sheisgoingtodieandthereisnothingyoucandotostopit`: roteiro de 27/10/2001,
  página impressa 122A/folha 130 do PDF; o movimento de Neo à porta vem na página
  123/folha 131. Fonte local: `recipe_audit_2026-09-11/FRONTEIRA_TEXTUAL.md:19`.
  É um roteiro anterior ao filme, não uma transcrição autenticada da montagem
  final. A escolha dessa oração também é interpretativa.

## Por que não estava na cobertura próxima

`operador_ensinado_2026-09-17/RELATORIO.md:90` exclui explicitamente o resíduo
de DBBI/FAED da família RAB. Seus geradores de falas compõem textos com rótulos
fixos, não com as novas listas: `familia2_lastwords.py:208` e
`critico_familia2.py:206`. O total amplo de tentativas da rodada não implica o
produto cartesiano entre famílias independentes.

`prime_host_delta.cjs:149` já reinsere p e, em `:170`, compõe as duas cláusulas,
mas coloca os primos nas células coloridas da imagem 14×14, com fundo zero.
As grades lógicas de `:130` não recolocam p. Já
`matrixsumlist_struct__msl_struct.py:125` usa marcadores zero ou bit e suas
somas em `:191` não são combinadas com essas cláusulas.

Assim, o complemento estreito é **base numérica + uma cláusula**, nas duas formas
de senha já fixadas. São 6.480 decisões AES previstas para três blobs e dois KDFs;
esta auditoria não as executou. Não há necessidade demonstrada de acrescentar
prefixos, outros recortes ou novas normalizações.

Esta evidência não prova ausência em toda busca histórica: não existe aqui uma
união completa preservada das senhas de `operador_ensinado`, cuja verificação foi
feita pelo fluxo dos geradores. Os hashes dos 14 corpora comparados permaneceram
idênticos antes e depois da leitura.
