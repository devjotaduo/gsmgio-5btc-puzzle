# Correção da direção cp273 do oráculo de chaves

## Hipótese registrada antes da alteração

O plaintext autenticado da fase 3.2 contém os 1.539 bytes do Beaufort
publicado sob a transformação `ASCII.decode('cp273').encode('latin-1')`.
O oráculo de 17/09 cobria a transformação EBCDIC convencional, no sentido
oposto. Hipótese finita: acrescentar a inversão exata dessa transformação
recupera chaves hex64/WIF plantadas nesse formato, conservando offsets e
sem juntar trechos separados por bytes não codificáveis.

Isso corrige a cobertura do oráculo; não reabre uma família criptográfica
nem afirma que os plaintexts históricos contenham uma chave real.

## Cobertura e controles planejados

- Reprodução integral dos 1.539 bytes da fase 3.2, com senha autenticada,
  AES-256-CBC e EVP-SHA256; a posição esperada no plaintext é 447.
- Fase 2 e checkerboard 3.2.2 pelo self-test do kit, executado sem bytecode.
- Duas chaves sintéticas, pubkeys comprimidas/não comprimidas, hex64 e
  WIF nos dois sentidos cp273; posições inicial e após bytes não mapeáveis.
- Byte Latin-1 `0xaf`, não codificável em cp273, vira um delimitador de
  um byte. Fragmentos dos dois lados não são concatenados.
- Nulo com 100 embaralhamentos preservando as contagens do buffer codificado.
- Nenhuma chave real será publicada; registros contêm apenas contagens,
  offsets, endereços sintéticos e hashes dos artefatos públicos.

## Resultado

Antes da alteração, o self-test do kit passou. Uma reprodução em memória
encontrou a transformação inversa dos 1.539 bytes no offset 447, enquanto
a convencional não apareceu. Hex64 plantado nessa representação não foi
encontrado pelo oráculo anterior e foi encontrado após restaurar os bytes.
Os controles persistidos da correção passaram em 18/09/2026:

- 24 casos positivos: dois alvos sintéticos, dois sentidos cp273,
  hex64/WIF comprimido/WIF não comprimido e offsets 0/2.
- Os 256 valores de byte foram conferidos contra chamadas estritas do codec.
  Somente `0xaf` não é mapeável e vira `?` ASCII. Usar `errors='replace'`
  diretamente seria inadequado: o codec geraria `0x6f`, a letra ASCII `o`,
  que pertence ao alfabeto WIF.
- 12 candidatos partidos por `0xaf` foram rejeitados: não houve concatenação
  de fragmentos nem deslocamento dos offsets.
- 100 embaralhamentos do hex64 codificado mantiveram as contagens e
  produziram 100 tentativas reais de escalar, com zero hits.
- O controle sintético que antes falhava teve zero hits nas visões antigas
  e um hit pela nova visão `cp273-inverse`, no offset 0.
- Fase 2, checkerboard 3.2.2 e a restauração integral dos 1.539 bytes da fase
  3.2 foram reproduzidos. O trecho começa no offset 447 do plaintext de
  2.422 bytes e não aparece em EBCDIC convencional.

O módulo manteve o caminho cp273 convencional e acrescentou apenas a nova
visão textual. Não acrescenta janelas raw32 sobre bytes transformados.
SHA256 de `oracle.py` congelado para a nova varredura:

`1b927716a5339a5a8cabe8527f1d7197e9bf539fdb508f25562dabafd45eec8d`.

Evidência em [`controls.json`](controls.json) e [`summary.json`](summary.json).
O resumo não contém chaves privadas. Esta execução não varreu o corpus
histórico; cabe à campanha complementar medir o efeito nos dados reais.

A revisão independente de `oracle_review`, somente leitura, conferiu
também os 63 cortes internos possíveis de um hex64 plantado, offsets
0/1/2, a tabela completa e o trecho real. Não encontrou falha de
cobertura ou deslocamento; esses testes adicionais não substituem os
artefatos reproduzíveis acima.

## Reprodução

Execute `solver/multiagente_2026_09_18/audit_codecs.py --out <pasta-nova>`
com o Python 3.12 indicado em AGENTS.md e a opção `-B`. O script usa somente
arquivos locais, recusa sobrescrever controles/resumo existentes e registra
hashes do oráculo, controles, auditor e fontes públicas. O antecedente da
fase 3.2 é reproduzido por derivação SHA256 e AES independentes do kit.
