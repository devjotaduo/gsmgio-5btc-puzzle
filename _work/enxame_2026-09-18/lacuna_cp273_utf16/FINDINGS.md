# Frente `lacuna_cp273_utf16` — visões cp273 e UTF-16 sobre o corpus da §3.11

**Resultado: negativo.** Zero hits e zero candidatos depois da triagem, nos 1.894.673
conteúdos únicos do corpus da §3.11. Fecha a lacuna declarada em `ENDGAME.md` §3.13.
Script: [`solver/enxame_2026_09_18/lacuna_cp273_utf16/scan.py`](../../../solver/enxame_2026_09_18/lacuna_cp273_utf16/scan.py).
Saídas locais: `summary.json`, `controls.json` e `candidates.jsonl` (9 MB, 13.970 artefatos
triados, ignorado pelo git).

## Hipótese e contra-hipótese

Algum conteúdo já guardado no corpus da §3.11 teria hex64, WIF, blob openssl aninhado, texto
ASCII de 48 B ou mais, ou sinal `G.semantic` visível apenas numa destas visões: cp273 inversa
(a direção autêntica da fase 3.2), cp273 direta, UTF-16 LE ou UTF-16 BE. A contra-hipótese era
que o corpus fosse padding aleatório e que nenhuma visão bijetiva por byte criasse estrutura.
A contra-hipótese se confirmou.

## Fato observado e cobertura

- **Recoleta.** A recoleta usou cópia fiel das duas funções `collect()`
  (`retro_dois_alvos.py`, `v4_rodada_dois_alvos.py`), com leitura em streaming e deduplicação
  por bytes. O corpus não foi gravado.
- **v4 (operador ensinado).** Recoletados 1.448.949 conteúdos e 120.664.743 janelas. Os 25
  arquivos do `v4_resultado.json` batem arquivo por arquivo. O único arquivo extra,
  `critico_sete_final/pads_o5up.jsonl.gz` (117.794 conteúdos), é posterior ao v4. Descontado
  ele, a reconciliação com 1.331.155 é exata.
- **Retro.** Recoletados 837.728 conteúdos. Os arquivos de fora do operador ensinado somam
  693.556, todos anteriores à retro. A diferença de 830 para os 694.386 históricos vem de
  arquivos que ainda eram escritos durante a retro, que os leu pela metade. Como esses arquivos
  só recebem acréscimos, o conteúdo daquela hora está contido no atual. A cobertura depende de
  nenhum arquivo ter sido apagado desde então.
- **União varrida.** 1.894.673 conteúdos únicos e 211.776.899 B: 445.724 só da retro, 1.056.945
  só do v4 e 392.004 nos dois. Impressões do multiconjunto (Σ sha256 mod 2²⁵⁶): retro `d7e164e5…`,
  v4 `e6a434d5…`.
- **Visões.** Foram seis instâncias por conteúdo:
  - cp273 inversa, pelo `cp273_inverse_view` do oráculo duplo;
  - cp273 direta, pelo `decode(cp273).encode(latin-1)`;
  - UTF-16 LE e UTF-16 BE, cada uma nos alinhamentos 0 e 1.
- **Busca em cada visão.** hex64 em todo offset de nibble; WIF com checksum; conferência dos dois
  alvos pelo kit; `G.semantic` com as subcausas; trechos ASCII de 48 B ou mais; `Salted__` e
  `U2FsdGVk` em qualquer offset.
- **Resultados.**
  - Nas seis visões novas: 0 hex64, 0 WIF e 0 blob aninhado. Os trechos ASCII de 48 B ou mais
    foram 60, todos coincidentes com texto já legível na visão original.
  - Na visão original, refeita em todo offset como folga: 710.313 hex64 e 3 WIF, com 706.250
    escalares válidos e **0 hits**.
  - A única subcausa nova foi `sem:ebcdic`, em 13.970 conteúdos. Todos foram triados como
    artefato por duas regras:
    - na cp273 direta, um byte da imagem de a–z corresponde exatamente a uma minúscula ASCII da
      original, com prova nos 256 bytes;
    - na cp273 inversa, a original já era texto legível.
  - Restaram 0 conteúdos a examinar.

## Fato novo sobre o corpus

O `collect()` da §3.11 recolhe todo campo `hex`, `plain_hex`, `plaintext_hex` e `pt_hex` de
`_work/**`, o que inclui materiais de decodificadores e pré-imagens de senha. Por isso o rótulo
"694.386 plaintexts" é impreciso: o corpus é de **conteúdos hex**, e só parte deles é plaintext AES.

## Controles

Todos passaram pelo mesmo `processar()` da varredura.

1. O self-test do kit abre a fase 2 só por EVP-SHA256 e reproduz o checkerboard da 3.2.2.
2. Uma chave sintética em hex64, em WIF não comprimido e em WIF comprimido foi plantada em cada
   família de visão, nos dois alinhamentos (24 casos). Todas foram recuperadas no formato e no
   offset esperados. Sem o alvo plantado, os mesmos casos deram 0.
3. Texto ASCII de 82 B e blob aninhado, cru e em base64, em cada família e alinhamento (24
   casos): todos detectados.
4. No plaintext autêntico da fase 3.2 (sha256 `b82afeb8…`), `ebcdic_sig` vale 1,0. Na visão
   inversa, o trecho ASCII de 1.548 B no offset 442 cobre os 1.539 B do Beaufort.
5. A visão UTF-16 vetorizada coincidiu com o codec Python em 1.600 comparações.

Nulo: N/A. A cobertura é determinística e finita, e nenhum motivo sobreviveu à triagem.

## Hashes

| Arquivo | sha256 |
|---|---|
| `scan.py` | `c1c264e44a53c39b8a41cb73c2e552d5cc4f998e3b6e7e15ecad0f36163a58c5` |
| kit `gsmg_common.py` | `3810cbafa1936652bd6c30fc36b908453036d7d685ecd7f3ec0b33dba9cc1e67` |
| `summary.json` | `f64a8e5da4c52aad4258473d3d0ac3b492b37227dcc1b2b7695077e914a3e958` |
| `candidates.jsonl` | `9346b0994041a276a7b0425113aca5c2c4046e4e1d168a15a5d0855b1e2b01a6` |

Execução em 72,8 s com 6 processos, sobre HEAD `5f12b71`. O `candidates.jsonl` é determinístico:
duas execuções deram arquivos idênticos byte a byte.

## Limites

- (a) As janelas raw32 dentro das visões transcodificadas não foram varridas; as da visão
  original são as da §3.11.
- (b) Na UTF-16, code units acima de 0xFF viram 0x00, então texto não latino não é examinado.
- (c) Bytes sem imagem cp273 viram `?`.
- (d) A cobertura da retro depende de nenhum arquivo ter sido apagado desde 2026-09-17 23:34 UTC.
- (e) O oráculo cobre só P2PKH dos dois alvos, e esta frente não tentou nenhum AES.
- (f) O escopo é só o corpus da §3.11. Os corpora da §3.12 e da §3.13 já tinham passado pela
  cp273 inversa.

## Inferência e próxima pergunta

Nenhuma das representações examinadas esconde estrutura no corpus da §3.11. Os sinais
encontrados são consequência algébrica da bijeção cp273 aplicada a conteúdos que já eram texto.
Dentro deste escopo, nenhuma pergunta nova sai daqui sem insumo novo do criador.
