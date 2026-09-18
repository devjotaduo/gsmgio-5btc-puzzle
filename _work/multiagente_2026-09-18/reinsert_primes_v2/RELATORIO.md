# Reinsercao dos primos em L83/L84

## Hipotese

Recolocar o proprio primo p nos marcadores logicos b/be de DBBI, manter a1z26 nos nao-primos, somar todas as grades retangulares exatas e testar as listas como senhas numericas compostas com as duas clausulas internas ja decodificadas.

## Diferenca para cobertura anterior

A rodada matrixsumlist estrutural testou residuos, sequencias com marcadores zerados/como bits e preenchimentos da matriz. Este teste usa p como valor numerico do marcador antes das somas.

## Fontes das clausulas

1. `lastwordsbeforearchichoice` — README.md: segmento z #1 da pagina final, a-i,o -> decimal -> hex -> ASCII.
2. `thispassword` — README.md: segmento z #2 da pagina final, a-i,o -> decimal -> hex -> ASCII.

Estas clausulas foram usadas como rotulos literais ja decodificados da pagina
final. Nao sao "ultimas palavras" extraidas de falas reais do Arquiteto, nem
dependem do layout editorial do monologo no README.

## Escopo

- Segmentacoes: L83 e L84.
- Modos de marcador: ambos (`b` e `be` recebem o proprio primo), so `b` com `be=0`, so `be` com `b=0`.
- Grades exatas: todos os retangulos fatoraveis de 83 e 84.
- Listas: somas de linhas e colunas, diretas e reversas.
- Serializacoes: decimal concatenado e decimal com virgulas.
- Composicoes: material isolado; material antes/depois de cada clausula; `lastwordsbeforearchichoice + material + thispassword`.
- Formas de senha por material: `raw` e `sha256hex` minusculo.

## Controles

```json
{
  "phase2_evp_sha256": true,
  "checkerboard_3_2_2": true,
  "planted_rectangular_sums": {
    "passed": true,
    "values": [
      2,
      3,
      5,
      7,
      11,
      13
    ],
    "expected": {
      "rows": [
        10,
        31
      ],
      "rows_rev": [
        31,
        10
      ],
      "cols": [
        9,
        14,
        18
      ],
      "cols_rev": [
        18,
        14,
        9
      ]
    }
  },
  "matched_null_conservation": {
    "passed": true,
    "checks": {
      "83": {
        "same_marker_bits": true,
        "same_residue_counts": true,
        "same_physical_length": true,
        "physical_length": 91
      },
      "84": {
        "same_marker_bits": true,
        "same_residue_counts": true,
        "same_physical_length": true,
        "physical_length": 91
      }
    }
  }
}
```

## Resultado

```json
{
  "status": "complete",
  "real": {
    "materials": 2016,
    "aes_decisions": 24192,
    "padding_hits": 98,
    "semantic_hits": 0,
    "key_hits": 0,
    "max_printable": 0.5063291139240507,
    "unique_material_sha256": 1620
  },
  "null": {
    "runs": 100,
    "materials_per_run": 2016,
    "aes_decisions_per_run": 24192,
    "padding_hits": {
      "min": 80,
      "max": 125,
      "mean": 97.48,
      "real": 98,
      "expected_per_run": 94.5
    },
    "semantic_hits_total": 0,
    "key_hits_total": 0,
    "max_printable": 0.5822784810126582
  },
  "hard_hits": 0,
  "elapsed_seconds": 283.75
}
```

O campo `materials=2016` conta ocorrencias de superficie: grade/lista/
serializacao/composicao. Dessas ocorrencias, `unique_material_sha256=1620`
sao materiais textuais distintos; duplicatas surgem de grades degeneradas e
listas simetricas que geram a mesma string.

### Correcao estatistica pos-rodada

A execucao v2 preservada em `summary.json` reportou `expected_per_run=94.5`,
isto e, `24192 / 256`. A expectativa historicamente correta para padding
PKCS#7 valido e a soma geometrica:

```text
24192 * sum(256^-k for k=1..16) = 94.87058823529412
```

Essa correcao altera somente a estatistica esperada. Os 2.016 materiais, as
24.192 decisoes AES reais, os 98 paddings reais, os 100 nulos e os 9.846
plaintexts com padding preservados nao mudam. A rastreabilidade fica em
`post_run_correction.json`: o script executado foi
`8463ed68c6f952ebf83229ff743d4055963eeb91c112439e484b3fc9f4469a8b`; o script
final, com a formula de expectativa corrigida e guardas `--out`, e
`c335e1aea6df75b8efbf9e3ce5e11831760075c4175c38057bdc69eab4b4aa9b`.

### Revisao independente

`campaign_review` reproduziu independentemente os 98 paddings reais usando
`raw` e `sha256hex`, confirmou 24.192 decisoes AES, 100 nulos e 9.748 paddings
nos nulos, e verificou que os 9.846 registros de `paddings.jsonl` conferem com
o resumo. Tambem confirmou que o script final resolve `--out` sob `_work`,
exige destino novo e nao apaga evidencias antigas. O delta entre o hash
executado e o hash final foi reproduzido como apenas a correcao estatistica
`/256` -> PKCS#7.

`oracle_review` tambem revisou por inspecao, sem alterar nem reexecutar. Nao
encontrou falha que invalide o negativo, mas registrou quatro limites:

- Proveniencia incompleta: `gsmg_common.py` importa `oracles.py` por caminho
  fixo do checkout principal; esse modulo e o README lido por ele nao estao
  em `spec.source_hashes`.
- `--nulls` nao e validado antes da busca; a v2 nao foi afetada porque usou
  exatamente 100 nulos.
- Se algum hit de chave existisse, `semantic_hits` e `key_hits` poderiam
  sobrepor contagem em `hard_hits`; a v2 tem ambos zero.
- O nulo embaralha L83 e L84 separadamente. Ele conserva cada segmentacao, mas
  nao conserva a relacao conjunta `residuo84 = residuo83 + "e"`.

Todos os plaintexts com padding valido foram preservados em `paddings.jsonl`,
com corpo completo em hexadecimal. Hits semanticos ou de chave ficam em
`hard_hits.jsonl`. O nulo embaralha apenas os residuos, preservando posicoes e
tipos dos marcadores logicos e as contagens de letras do residuo.

Conclusao: nenhum material desta cobertura finita produziu plaintext semantico,
blob aninhado ou chave para os alvos do oraculo dual. Isto refuta somente a
familia especificada acima; nao prova a familia total de `matrixsumlist` ou de
`yellowblueprimes`.
