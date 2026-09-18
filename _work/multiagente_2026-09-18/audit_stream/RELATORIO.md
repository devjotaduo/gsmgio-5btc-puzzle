# Falso negativo na triagem histórica de cifras de fluxo

## Hipótese e resultado

Hipótese finita, registrada em `spec.json`: o ramo STREAM da campanha
multicipher descarta uma chave binária interior quando a saída tem menos
de 60% de ASCII e não dispara os demais sinais textuais. A chamada ao
scanner completo de privkey e a persistência ficam depois desse filtro.

**Confirmado em dados sintéticos:** 32 casos com chave interior foram
descartados; os mesmos formatos nas pontas passaram em 32 controles.
O oráculo amplo encontrou a chave em todos os 64 casos. Nenhuma chave
real foi encontrada ou procurada por esta auditoria.

## Reprodução da implementação exata

`audit_stream.py` importa `solver/premissas_2026_09_17/multicipher_attack.py`
e executa sua `_work_loop` original, sem chamar `main`, `work` ou os
controles históricos que escrevem arquivos. A saída usa `StringIO`.
As constantes de blobs, KDF e alvo são substituídas somente em memória.
Cada caso configura a pubkey do próprio alvo sintético no código antigo:
o falso negativo não é explicado pela ausência do segundo endereço.

O arquivo coincide byte a byte com a cópia arquivada junto aos logs,
SHA256 `8955f85fa301d88d10e8e697916076a658fde2f46bdcc641d7c757d06075af48`.
Os campos e bytes das chaves sintéticas não são publicados nos JSONs;
estes registram endereços sintéticos, contagens e offsets.

## Cobertura dos controles

- Quatro modos: AES-256-CFB, AES-256-OFB, AES-256-CTR e ChaCha20.
- EVP-SHA256 e EVP-MD5, cada um com roundtrip exato da cifra.
- Dois alvos sintéticos independentes, P2PKH comprimido/não comprimido
  no oráculo amplo.
- Plaintext de 80 bytes nos offsets 0, 16 e 48; plaintext de 1.328 bytes
  no offset 512. Os bytes externos à chave são `ff`, evitando ASCII alto.
- Fase 2 e checkerboard 3.2.2 reproduzidos pelo kit com `-B`.
- 100 embaralhamentos do multiconjunto de bytes da fixture de 80 bytes,
  cifrados novamente e testados pelos dois pipelines: 4.900 tentativas
  raw32, zero hits.

O controle interior de 80 bytes é diretamente análogo ao tamanho de
SMALL/TAIL32; o de 1.328 bytes exercita o tamanho de COSMIC. Essa semelhança
não demonstra que tais blobs realmente contenham uma chave binária.

## Quanto ficou fora da persistência

O log histórico registra 1.272.149 formas, quatro modos STREAM, três blobs,
dois KDFs, nenhum erro e nenhum hit. Seus 558 registros SOFT se dividem em
554 STREAM e quatro de cifras com padding. Assim:

| Medida | Quantidade |
|---|---:|
| Decifrações STREAM | 30.531.576 |
| Saídas STREAM emitidas como registros completos | 554 |
| Saídas sem registro STREAM completo | 30.531.022 |
| Todas as janelas raw32 dessas decifrações | 14.197.182.840 |
| Verificações nas duas pontas já tentadas | 61.063.152 |
| Janelas interiores | 14.136.119.688 |

“Sem registro completo” não significa chave real perdida nem ausência de
todo fragmento: o histórico também guardava alguns prefixos `best`.
A revisão retroativa de plaintexts preservados não cobre integralmente
as 30,5 milhões de saídas descartadas. O cálculo acima não afirma que
cada janela contenha um escalar diferente.

## Custo medido antes de sugerir outra campanha

O benchmark usou 24 buffers sintéticos dos tamanhos 80/1.328, repetidos
três vezes: 16.152 janelas por repetição. A mediana foi 0,3634 segundo,
aproximadamente **44.445 janelas/s por processo**, com o oráculo amplo
atual, dois alvos e duas serializações de pubkey.

A extrapolação é de **88,7 horas de trabalho de um processo** para todas
as janelas, ou 88,4 horas só para interiores. Não inclui reconstrução do
corpus, geração, nova decifração ou I/O. A máquina estava sob carga de
outros trabalhos; não foi medida a escalabilidade com múltiplos processos.
O tempo histórico de 1.462 segundos refere-se à campanha com o filtro
antigo e não estima o custo de remover esse filtro.

Não foi disparada nova busca histórica. Antes de propô-la, é necessário
localizar/reconstruir exatamente o corpus de formas e decidir se esse
custo é justificado. A correção do critério para campanhas futuras pode
ser feita independentemente, com escopo de formatos explicitamente
registrado. Este trabalho não alterou o script histórico.

## Evidência e reprodução

[`controls.json`](controls.json) registra os 64 casos e o nulo;
[`summary.json`](summary.json) contém contagens, hashes e medições.
Execute `solver/multiagente_2026_09_18/audit_stream.py` com `-B`,
`--source-root <checkout-com-logs>` e `--out <pasta-nova>`. O script
recusa sobrescrever controles/resumo e acessa a origem somente para leitura.
O único material cifrado ou varrido nesta execução foi sintético.
