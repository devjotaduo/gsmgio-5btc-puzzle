# Bases primas como alfabetos — 2026-09-16

**Nenhuma senha final.** Esta rodada distinguiu duas operações: converter
um inteiro para dígitos que são códigos ASCII, como nos testes anteriores,
e converter para dígitos que indexam um alfabeto de letras. A segunda foi
testada nas bases 29, 31 e 37. Não é uma receita confirmada pelo criador.

## Modelo declarado

Usamos DBBI e FAED completos, em ambos os sentidos, com `a=1,…,i=9` e
cada ocorrência de `g` podendo valer 0 ou 7. Isso dá `2^10` escolhas por
DBBI e `2^107` por FAED. O número decimal resultante é representado na
base escolhida, sem dígitos zero iniciais, e cada dígito indexa um símbolo:

| Base | Ordem dos símbolos, desde o índice zero |
| --- | --- |
| 29 | espaço, `a..z`, ponto, vírgula |
| 29 | `a..z`, espaço, ponto, vírgula |
| 31 | espaço, `a..z`, ponto, vírgula, hífen, apóstrofo |
| 31 | `a..z`, espaço, ponto, vírgula, hífen, apóstrofo |
| 37 | espaço, `a..z`, `0..9` |
| 37 | `0..9`, `a..z`, espaço |

As bases são primas e comportam o alfabeto latino com separadores. As
ordens e a pontuação são hipóteses explícitas, não escolhas determinadas
pelas pistas. O insumo é `../prime_geometry_2026-09-11/inputs.json`, SHA256
`2e58c16a953bc22c2361adb5124f43d8fe624d15e3c90858349dcb25ecefedc6`.

## Palavras separadas: 24 modelos completos

Cada sequência máxima de letras precisa ser uma palavra do corpus local,
com comprimento até 32; palavras de uma letra são somente `a` ou `i`.
Pontuação e dígitos separam palavras. Também são admitidas saídas contendo
apenas separadores. O corpus tem 333.296 entradas após esses filtros,
incluindo nomes, siglas e abreviações; não representa toda a língua inglesa.

Todas as 24 combinações de campo, direção e alfabeto terminaram, **sem
candidatos**: 54 nós e 39 intervalos excluídos. Cada prefixo de escolhas
`g→0/7` fornece limites numéricos; o próximo inteiro que poderia satisfazer
a gramática fica acima do limite superior desses intervalos.

O produtor passou por 12.336 comparações exaustivas de sucessor, 18 textos
plantados e 24 casos pequenos com todas as máscaras enumeradas. Outro
programa reconstruiu o vocabulário usando prefixos de strings e verificou
os 39 intervalos diretamente entre seus dois limites, sem usar o algoritmo
de sucessor. Também enumerou as 12.288 escolhas DBBI desta família e passou
258 controles.

Código: `solver/prime_alphabet_words.cjs` e
`solver/verify_prime_alphabet_words.cjs`. Resultados completos neste diretório.

## Palavras concatenadas: resultado parcial explicitamente preservado

Como o puzzle usa expressões como `matrixsumlist`, a extensão permite
concatenar palavras sem separadores. Para limitar as siglas raras, usa as
26.264 entradas com contagem de pelo menos um milhão no mesmo corpus.
Mesmo esse vocabulário admite muitas abreviações e sequências sem sentido.
Todos os nomes ausentes do vocabulário continuam fora do modelo.

**19 dos 24 modelos terminaram.** Os doze DBBI foram enumerados integralmente
e forneceram 33 saídas compatíveis; sete modelos FAED terminaram sem saídas.
Cinco FAED atingiram o limite declarado de 15 segundos e permanecem parciais:
direção original nos quatro alfabetos de bases 29/31 e direção inversa
no alfabeto de base 31 que começa com espaço.

Os registros contêm 541.938 nós, 271.163 folhas e **35.965 textos distintos**.
As folhas distinguem exclusões, candidatos e estados pendentes. Outro programa
reproduziu DBBI por força bruta, conferiu as 13 exclusões dos modelos FAED
completos, reencodificou cada candidato e verificou sua segmentação em palavras
por uma programação dinâmica diferente. Conferiu também a cobertura e ausência
de sobreposição das máscaras em todos os modelos parciais.

**Limite da conferência:** as 234.842 exclusões internas dos cinco modelos
parciais não foram certificadas pelo segundo algoritmo. Nenhuma conclusão
global é atribuída a esses cinco modelos; não foram retomados após a sondagem.
Os 18 controles plantados do produtor e 150 do verificador passaram.

Artefatos e código da extensão:
`../prime_joined_words_2026-09-16/`, `solver/prime_joined_words.cjs` e
`solver/verify_prime_joined_words.cjs`.

## Candidatos e autenticação

Todos os 35.965 candidatos obtidos foram usados nas formas original,
maiúsculas, sem espaços e sem espaços em maiúsculas. Após eliminar materiais
iguais, restaram 143.856 textos e 287.712 casos de senha direta/SHA256-hex.

- **1.726.272 decisões AES:** SMALL, COSMIC e TAIL32, EVP-SHA256 e EVP-MD5.
- **6.644 paddings**, nenhum plaintext autenticado. A maior fração de
  ASCII imprimível, admitindo TAB/LF/CR, foi 62,03%; padding não é solução.
- Uma implementação com hashlib/PyCryptodome regenerou todos os materiais
  e reproduziu todas as decisões, comparando os plaintexts completos.
  Digest da sequência de decisões:
  `9b959203d623a2e67b3c363a7f2430bf361e716c3d6b84d57af8c486404d5a54`.
- **294.356 hashes SHA256 distintos** das senhas e corpos com padding foram
  conferidos como escalares com coincurve, sem correspondência com a chave
  pública do prêmio ou sua negação.

O controle AES da fase 3.2 conhecida passou. Detalhes em
`../prime_joined_words_2026-09-16/oracles.json` e `oracles_verification.json`.

## Reprodução e limites

Na raiz do repositório, os diretórios de saída precisam ser novos:

```powershell
node solver/prime_alphabet_words.cjs _work/prime_alphabet_reproduction
node solver/verify_prime_alphabet_words.cjs _work/prime_alphabet_reproduction
node solver/prime_joined_words.cjs _work/prime_joined_reproduction
node solver/verify_prime_joined_words.cjs _work/prime_joined_reproduction
node solver/prime_joined_word_oracles.cjs _work/prime_joined_reproduction
```

A extensão tem limite de tempo: a quantidade de candidatos parciais pode
variar entre execuções. Nenhum processo desta rodada continua em execução.
O negativo não cobre outros alfabetos, outros caracteres zeráveis, símbolos
iniciais perdidos, outras línguas ou transformações adicionais. Os testes
AES cobrem todos os candidatos obtidos, não as máscaras ainda pendentes.
