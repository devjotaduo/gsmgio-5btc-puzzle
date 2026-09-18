# Reinsercao dos primos em L83/L84

## Hipotese

Recolocar o proprio primo p nos marcadores logicos b/be de DBBI, manter a1z26 nos nao-primos, somar todas as grades retangulares exatas e testar as listas como senhas numericas compostas com as duas clausulas internas ja decodificadas.

## Diferenca para cobertura anterior

A rodada matrixsumlist estrutural testou residuos, sequencias com marcadores zerados/como bits e preenchimentos da matriz. Este teste usa p como valor numerico do marcador antes das somas.

## Fontes das clausulas

1. `lastwordsbeforearchichoice` — README.md: segmento z #1 da pagina final, a-i,o -> decimal -> hex -> ASCII.
2. `thispassword` — README.md: segmento z #2 da pagina final, a-i,o -> decimal -> hex -> ASCII.

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
    "runs": 1,
    "materials_per_run": 2016,
    "aes_decisions_per_run": 24192,
    "padding_hits": {
      "min": 97,
      "max": 97,
      "mean": 97.0,
      "real": 98,
      "expected_per_run": 94.5
    },
    "semantic_hits_total": 0,
    "key_hits_total": 0,
    "max_printable": 0.4810126582278481
  },
  "hard_hits": 0,
  "elapsed_seconds": 5.047
}
```

Todos os plaintexts com padding valido foram preservados em `paddings.jsonl`,
com corpo completo em hexadecimal. Hits semanticos ou de chave ficam em
`hard_hits.jsonl`. O nulo embaralha apenas os residuos, preservando posicoes e
tipos dos marcadores logicos e as contagens de letras do residuo.
