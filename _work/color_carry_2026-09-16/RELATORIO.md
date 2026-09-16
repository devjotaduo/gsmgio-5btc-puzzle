# Chaves das cores com transporte decimal

16/09/2026. **Nenhuma senha final recuperada.** A família de todos os
pesos inteiros fixos de azul/amarelo foi examinada com soma e subtração
de inteiros, incluindo transporte entre casas. FAED não produz bytes
de sete bits; os candidatos de DBBI não deram uma decifração autenticada
nem a chave pública do prêmio.

## Diferença em relação à rodada anterior

O [teste anterior](../color_residue_2026-09-16/RELATORIO.md) operava em
cada dígito separadamente. Por exemplo, `18 + 05` produz `13` sem
transporte, mas `23` na soma inteira. Não se pode usar aquele resultado
para excluir automaticamente a segunda operação.

Mantém-se a mesma família de listas da matriz 14×14 original:

- Azul e amarelo recebem quaisquer inteiros fixos por cor.
- Preto e branco recebem, independentemente, 0 ou 1.
- As 14 somas de linhas ou colunas são reduzidas módulo 10.
- A lista é usada nas duas direções e em todos os alinhamentos cíclicos.

Como as somas são reduzidas **antes** da operação seguinte, os cem pares
de restos para azul/amarelo ainda cobrem todos os pesos inteiros,
incluindo todos os primos sem teto numérico. Essa afirmação não abrange
concatenar os valores completos das somas antes de reduzi-los.

As 22.400 construções produzem **22.038 listas distintas**, idênticas às
da rodada anterior. Cada lista de 14 dígitos é repetida e cortada para
ter a mesma largura decimal `L` do campo. Esse é o inteiro `K`.

## Duas interpretações do transporte

São examinadas as três operações `C + K`, `C - K` e `K - C`:

1. **Módulo `10^L`:** conserva a largura decimal, descartando o transporte
   final e convertendo resultados negativos para seu resto não negativo.
2. **Inteiro comum não negativo:** conserva o transporte final. Um
   resultado negativo não tem a representação de bytes sem sinal deste
   modelo e é rejeitado.

`C` é todo DBBI ou FAED, nas ordens original e inversa, com `a=1..i=9`.
Qualquer **uma** das nove letras pode também valer zero por ocorrência,
independentemente. Os zeros à esquerda não alteram `L`, que continua
definido pelo campo original. O resultado precisa ter todos os bytes
mínimos abaixo de 128.

## Resultado e conferência

| Família e campo | Casos completos | Caminhos que produzem bytes de sete bits |
|---|---:|---:|
| Módulo `10^L`, DBBI | 1.190.052 | 29 |
| Inteiro não negativo, DBBI | 1.190.052 | 26 |
| Módulo `10^L`, FAED | 1.190.052 | 0 |
| Inteiro não negativo, FAED | 1.190.052 | 0 |
| **Total** | **4.760.208** | **55** |

Não houve casos interrompidos. Foram percorridos 13.677.754 nós e
produzidos **9.218.926 certificados de exclusão**. As contagens são de
configurações declaradas; algumas operações podem coincidir, como somar
ou subtrair uma chave zero.

Os 55 caminhos de DBBI correspondem a **38 sequências de bytes distintas**,
todas com a letra `b` representando 0 ou 2. Nenhuma é formada somente por
ASCII imprimível e TAB/LF/CR; a maior fração imprimível é 89,19%.
Nenhuma dessas 38 sequências coincide com as 39 da rodada sem transporte.

Um verificador independente reconstruiu as matrizes e todas as chaves.
Para conferir cada intervalo, ele calcula os quocientes inteiros e divide
o intervalo nas fronteiras de `10^L`, em vez de reutilizar a transformação
do buscador. Nos resultados comuns, confere a parte não negativa.
Conta os inteiros de sete bits em cada intervalo e verifica a cobertura
completa, sem sobreposição, de todas as máscaras. Todos os casos,
certificados e candidatos foram reproduzidos sem divergência.

Controles: 1.350 comparações com enumeração direta de máscaras, 204
recuperações de mensagens plantadas, 2.640 verificações independentes de
imagens de intervalos, 65.536 inteiros pequenos e 300 larguras maiores.

## Validação dos candidatos

As duas ordens de bytes geraram 76 materiais distintos. Cada um foi usado
diretamente e como SHA256 hexadecimal, nos blobs SMALL, TAIL32 e COSMIC,
com EVP-SHA256 e EVP-MD5:

- **152 senhas distintas e 912 decisões AES**.
- Três paddings aceitos, todos com EVP-MD5: um TAIL32 e dois SMALL. Os
  corpos de 79 bytes têm frações imprimíveis de 35,44%, 39,24% e 44,30%.
  Nenhum apresentou uma estrutura que autentique a abertura.
- **342 escalares válidos distintos**, provenientes dos SHA256 dos
  materiais e de todas as janelas de 32 bytes, sem coincidência com a
  chave pública do prêmio ou sua negação.

PyCryptodome 3.23.0 e coincurve 21.0.0 reproduziram todas as decisões AES,
inclusive rejeições, os três corpos completos e todos os pontos da curva.
A fase 3.2 conhecida, o gerador secp256k1 e a conversão da pubkey para
`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` serviram como controles.

## Limites e reprodução

Esta rodada fecha a lacuna do transporte **para essas chaves reduzidas e
essa conversão em bytes de sete bits**. Não identifica os valores corretos
das cores. Não cobre concatenação das somas completas, pesos diferentes
por célula, outros valores de preto/branco, outra substituição de dígitos,
várias letras zeráveis simultaneamente ou uma representação binária
diferente. Padding isolado continua sem valor de autenticação.

```powershell
node solver/color_residue_carry.cjs
node solver/verify_color_residue_carry.cjs
```

Artefatos: [especificação](spec.json), [chaves](keys.json.gz),
[casos e certificados](cases.jsonl.gz), [resumo](summary.json),
[candidatos](candidates.json), [oráculos](oracles.json),
[verificação estrutural](verification.json),
[verificação criptográfica independente](oracle_verification.json).

Programas: [buscador](../../solver/color_residue_carry.cjs) e
[verificador](../../solver/verify_color_residue_carry.cjs).
