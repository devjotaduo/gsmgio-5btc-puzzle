# F4 — `faed_256_aes`: equalizar o braço AES da seleção de 256 bits de `faed`

Campanha `enxame_2026-09-19` (contrato em `../spec.json`). Frente de recuperação de cobertura.

**Nota de procedência.** A frente foi executada por uma subagente, que ficou impedida pelo harness
de escrever arquivos de relatório ("Subagents should return findings as text, not write report
files"). Este `FINDINGS.md` foi materializado pelo coordenador a partir do texto devolvido pela
frente, **conferido campo a campo** contra `summary.json`, que é a saída de execução. O script
reproduzível é `solver/enxame_2026_09_19/faed_256_aes/aes_arm.py`.

## Hipótese

A tabela §4-E do `ENDGAME.md` registra a seleção de 256 bits de `faed` por índices principiados
como **parcial**, nestes termos: "3,77 M privkeys; **parcial**: o braço AES ficou ~200× mais fino".
Ou seja, as seleções foram fartamente testadas como **chave privada direta**, e muito pouco como
**material de senha**. A hipótese desta frente é que uma seleção de 256 bits de `faed` (por índices
primos, pelas cores da espiral, pelos símbolos `g`/`i`, por múltiplos, ou pelo par i / i+285) seja a
**senha** de um dos blobs, e não a chave — caso em que o desequilíbrio entre os dois braços teria
deixado o acerto passar.

## Cobertura exata

| Grandeza | Valor |
|---|---|
| candidatos `u` (com repetição) | 10.808 |
| candidatos `u` distintos | 10.536 |
| senhas distintas testadas | 32.182 |
| decisões AES totais | 193.092 |
| privkeys testadas (`u` e `sha256(u)`, 2 alvos) | 21.072 |
| blobs | SMALL, COSMIC, TAIL32 |
| KDF | EVP_BytesToKey SHA256 **e** MD5 (`kdf="both"`) |

Famílias de seleção e contagem de `u`: `primos_b0` 512, `primos_b1` 512, `cores_colored` 3,
`cores_blue` 3, `cores_yellow` 3, `gi` 1.900, `gi_complemento` 7.144, `multiplos_7` 191,
`multiplos_15` 9, `multiplos_23`/`31`/`39`/`47`/`55`/`63`/`71` 3 cada, `par_i_i285_soma` 255,
`par_i_i285_xor` 255.

Cada seleção virou `u` (32 B) por `pack_b9`, `ascii32`, janelas ascii e janelas de 256 bits
(5 predicados de 1 bit + 3 larguras multibit — as mesmas que o `select_bits.py` histórico
alimentava **só** no braço de privkey). Formas de senha cobertas: `u_raw`, `u_sha256hex`, `u_hex`,
`texto_raw`, `texto_sha256`.

## Controles

- **Positivo estrutural:** chave plantada nas 104 posições primas, recuperada exata.
- **Positivo do braço AES:** envelope plantado com senha `sha256hex(K)`, com
  `K = 14e1aeab343296209d9e1565cf388dcd167e09107c80612f567c043e82842423`, **aberto pelo próprio
  pipeline de senha** (forma `u_sha256hex`, KDF SHA256) e `u` recuperado idêntico a `K`. É este
  controle que dá sentido ao negativo: prova que, se a senha estivesse no conjunto varrido, o
  pipeline a teria achado.
- **Nulo casado:** 100 embaralhamentos na célula `sha256hex × {SMALL, TAIL32} × 2 KDF`.
  Observado 0; média 0,19; desvio 0,443; **z = −0,429**, dentro da faixa de ruído normal que o
  `ENDGAME.md` §3.9 calibra (−1,2 a +2,1).

## Resultado no oráculo duro

**0.** Zero candidatos semânticos e zero hits de privkey contra os dois alvos.

772 paddings PKCS7 válidos isolados foram registrados com o plaintext em hex, como manda a regra 5
do `AGENTS.md` — e são **ruído**, não achado: a taxa de referência em escala é 1/255.

## Limitação declarada

A frente **não equalizou plenamente** o braço AES, e isso precisa ficar dito com precisão:

- 10.536 `u` distintos são ≈ **0,28 %** dos 3,77 M do braço de chave. O braço AES saiu de
  "~200× mais fino" para cerca de 10× o tamanho do braço fino anterior (~18.850 implícito), o que
  **reduz** o desequilíbrio sem eliminá-lo.
- Ficaram fora, por escopo: seleções via `dbbi`, concatenações, e `mod_k`.
- Os scripts e logs históricos dos 3,77 M **não existem neste clone**, de modo que a reconciliação
  exata entre os dois conjuntos não pôde ser feita — a fração acima é estimada contra o número
  publicado no `ENDGAME.md`, não contra o conjunto original.

Portanto a linha §4-E permanece **parcial**, com o desequilíbrio medido e reduzido, e não deve ser
reclassificada como fechada.

## Reprodução

```
python3 solver/enxame_2026_09_19/faed_256_aes/aes_arm.py
```

Saída de execução: `_work/enxame_2026-09-19/faed_256_aes/summary.json`.
