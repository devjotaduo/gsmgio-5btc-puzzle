# Triagem semântica dos plaintexts recuperados

## Hipótese e cobertura

Hipótese finita, registrada antes da execução em `spec.json`: um plaintext
recuperado integralmente pode conter uma abertura textual ou blob OpenSSL
aninhado em região ausente dos prefixos históricos. Este teste examina
essas possibilidades sem repetir a busca ECC em execução separada.

As três visões preservam uma posição por byte: original, cp273 convencional
decodificado para Latin-1 e cp273 inverso da fase 3.2. A visão convencional
não converte todos os caracteres altos em ASCII `?`, pois isso fabricaria
legibilidade em dados aleatórios. No sentido inverso, o único byte Latin-1
não mapeável (`af`) vira um delimitador `?` e mantém seu offset.

Critérios fixados antes de ler os resultados:

- `G.semantic` sobre a visão inteira, sem alterar seus limiares.
- `G.nested_blob` no início da visão.
- Uma sequência contínua de pelo menos 48 bytes em TAB/LF/CR ou ASCII
  imprimível (`20..7e`), em qualquer posição.
- `Salted__` em qualquer posição, desde que restem pelo menos 32 bytes;
  ou armadura Base64 validada que decodifique esse cabeçalho e tamanho.

Cada candidato preservaria payload, visão, offsets e motivos em
`candidates.jsonl`, arquivo local ignorado pelo Git. O stdout e os JSONs
publicáveis contêm somente contagens, parâmetros e hashes. Os critérios
são de triagem: nenhum deles, isoladamente, autentica uma solução.

## Controles

- Self-test do kit: fase 2 e checkerboard 3.2.2.
- Fase 3.2 autenticada, 2.422 bytes: o mixed ASCII/EBCDIC dispara
  `G.semantic`; a visão inversa recupera o trecho contínuo de 1.539 bytes.
- Blob AES sintético, corretamente cifrado com EVP-SHA256: `Salted__`
  cru e armadura Base64, no início e após 19 bytes binários.
- Instrução textual sintética na região interior, nas três codificações.
- 600 buffers uniformemente aleatórios: 100 para cada comprimento real
  do corpus (77, 78, 79, 1.325, 1.326 e 1.327 bytes). **Zero sinais**.
- 100 embaralhamentos preservando as contagens do plaintext real da
  fase 3.2: **100 disparos de `G.semantic` na visão original**. A assinatura
  de frequências é preservada, mostrando por que esse sinal não é prova
  de instrução coerente. Os critérios de trecho longo/blob não dispararam.

O `python-reviewer` revisou código e controles somente para leitura e
não encontrou falha concreta. O código ficou congelado durante a
execução, SHA256:

`4afb902e21a8ef1090003d2df930ca22e725f4ebf90bbe13dbcbb79493b73160`.

## Resultado da execução

**Execução concluída: 225.854 payloads, 260.180.711 bytes, zero candidatos
nos critérios e nas três visões declaradas.** Foram 677.562 inspeções de
visões, sem operação ECC. Tempo da varredura: 210,797 segundos, além dos
controles e hashes de abertura. O arquivo local de candidatos ficou vazio.

[`summary.json`](summary.json) foi gravado somente após igualdade de
contagens/bytes, validação SHA256 de cada payload e confirmação dos hashes
finais do corpus e código. [`controls.json`](controls.json) preserva os
positivos, os nulos e os hashes. Não houve abertura textual identificada
nos bytes recuperados por esta triagem. O resultado não altera os limites
de formatos, limiares e snapshots listados neste relatório.

## Limites e reprodução

Não cobre todos os codecs, texto curto, fragmentação arbitrária, compressão
ou uma camada criptográfica adicional. A busca de chaves pertence ao
scanner independente. A ausência de sinais não demonstra que os bytes
sejam destituídos de qualquer significado.

Execute `solver/multiagente_2026_09_18/audit_recovered_semantic.py` com
o Python 3.12 indicado no projeto, opção `-B`, `--corpus <SQLite-fechado>`
e `--out <pasta-nova>`. SQLite é aberto com `mode=ro&immutable=1`, journals
pendentes são recusados e a saída existente não é sobrescrita.
