# Primos das cores e RSA por caractere

**Nenhuma senha encontrada.** A leitura delimitada abaixo foi excluída,
incluindo todas as separações de números e escolhas de zeros permitidas.
Busca e verificador terminaram com saída 0 em 16/09/2026.

## Hipótese e domínio

As cores originais dão `#3F48CC = 4.147.404 = 2²·3·37·9341` e
`#FFF200 = 16.773.632 = 2⁹·181²`. A hipótese usa um fator primo distinto
de cada cor como `p,q`, e escreve `c = m^e mod (p·q)` em decimal, onde
`m` é um caractere. A comunidade cogitou RSA; isso não é uma indicação
confirmada do criador.

O [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html) especifica
primos ímpares distintos para RSA. O teste relaxa esse requisito e inclui
o fator 2, além de examinar todas as classes de expoentes invertíveis,
inclusive a classe identidade. Não implementa OAEP ou outro preenchimento.

| p | q | n | λ(n) | Classes invertíveis |
|---:|---:|---:|---:|---:|
| 2 | 181 | 362 | 180 | 48 |
| 3 | 2 | 6 | 2 | 1 |
| 3 | 181 | 543 | 180 | 48 |
| 37 | 2 | 74 | 36 | 12 |
| 37 | 181 | 6697 | 180 | 48 |
| 9341 | 2 | 18682 | 9340 | 3728 |
| 9341 | 181 | 1690721 | 84060 | 22368 |

São 26.253 pares de módulo/classe. Para cada um, os 368 modelos cobrem
DBBI e FAED completos, nos dois sentidos; decimal mínimo ou com zeros à
esquerda até a largura do módulo; `a=1,…,i=9`; e nenhuma, uma ou duas
letras podendo valer zero independentemente em cada ocorrência. Há 46
conjuntos de letras zeráveis. O repertório de texto é TAB, LF, CR e
ASCII 32–126, sempre com `m<n`.

## Resultado e comprovação

**9.661.104 modelos; nenhum caminho completo no repertório declarado.**
Consequentemente não há candidato desta leitura para testar em AES.

A busca constrói os números possíveis por trecho e usa programação
dinâmica. O verificador reconstrói os códigos por exponenciação BigInt e
confere cada decisão usando uma árvore de palavras decimais e percorrendo
o texto de trás para a frente. O produtor passou por 12 mensagens plantadas
e 24 casos pequenos enumerados; o verificador tem mais 12 controles.

Uma terceira conferência, em Python, calculou 2.572.060 cifras de caracteres
e as recuperou pelos expoentes inversos. O hash do fluxo de códigos coincide
com o das outras implementações:
`1561102f64bfe283e2f69f0f1b7cf8ae49e5568ad1bac2b12459ea52877ee4b3`.

- [Especificação](spec.json) e [resumo](summary.json).
- [Verificação de todas as decisões](verification.json).
- [Conferência aritmética independente](independent_arithmetic.json).
- [Buscador](../../solver/rsa_color_blocks.cjs) e
  [verificador](../../solver/verify_rsa_color_blocks.cjs).

Para conferir o registro existente: `node solver/verify_rsa_color_blocks.cjs`.
O produtor recusa sobrescrever resultados.

O negativo não cobre blocos com vários caracteres, outros módulos,
outros alfabetos, permutação dos dígitos ou transformações anteriores.
A [extensão com blocos de vários bytes](../rsa_color_multibyte_2026-09-16/RELATORIO.md)
trata a primeira dessas lacunas explicitamente.
