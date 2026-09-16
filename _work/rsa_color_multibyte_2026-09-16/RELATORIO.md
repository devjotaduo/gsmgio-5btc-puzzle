# Primos das cores: blocos modulares com vários bytes

**O filtro de texto tem caminhos compatíveis; isso não é uma decifração.**
Busca e verificação completa terminaram com saída 0. Nenhuma senha é
estabelecida por passar nesse filtro.

## O que foi testado

O domínio anterior de fatores primos RGB foi ampliado com `p=47,q=23`, os
primos nas posições 15 e 9, correspondentes às contagens das duas cores.
Este par adicional fornece `n=1081`, `λ=506` e 220 classes invertíveis.

Cada número cifrado `c` vira `m=c^d mod n`, convertido em seus bytes mínimos.
Todos os bytes devem pertencer a TAB/LF/CR/ASCII 32–126. A separação em
blocos e o tamanho de cada bloco são livres. Isso inclui blocos uniformes
de um, dois ou três bytes, com um possível bloco final menor. Nenhum módulo
selecionado comporta quatro bytes cujo primeiro byte pertença ao repertório.

Inverter a ordem dos bytes dentro de cada bloco não altera a possibilidade
de pertencer a esse repertório; as testemunhas originais foram salvas em
big-endian. O domínio de letras zeráveis, sentidos e formatos decimais é
o [mesmo da busca anterior](../rsa_color_blocks_2026-09-16/RELATORIO.md).
Foram examinados todos os expoentes invertíveis, não apenas 3, 17 ou 65537.

## Resultados completos do filtro

São **26.473 pares de módulo/expoente e 9.742.064 modelos**.

| Módulo | Modelos com caminho ASCII | Com caminho só imprimível | Só letras/espaços |
|---:|---:|---:|---:|
| 362, 6, 543, 74, 6697 e 1081 | 0 | 0 | 0 |
| 18682 = 9341·2 | 9914 | 4068 | 0 |
| 1690721 = 9341·181 | 10 | 0 | 0 |
| Total | 9924 | 4068 | 0 |

As dez compatibilidades de `n=1690721` pertencem a **DBBI com `d=1`**,
a transformação identidade. Nenhuma classe não identidade dos módulos
com dois primos ímpares selecionados tem um caminho ASCII completo.
FAED não possui caminho algum nos módulos ímpares selecionados.

Os modelos restantes usam o fator 2, fora da definição de módulo RSA do
[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html). Eles continuam sendo
transformações modulares matematicamente válidas e não foram descartados
por essa razão.

| Campo | Modelos compatíveis | Modelos imprimíveis | Menor/maior texto possível |
|---|---:|---:|---:|
| DBBI | 9913 | 4068 | 41–156 bytes |
| FAED | 11 | 0 | 363–875 bytes |

Todos os onze modelos FAED usam `n=18682`. Há parâmetros compartilhados
compatíveis com os dois campos. Portanto não se pode rejeitar toda a família
com o fator 2. Alguns modelos possuem quantidades enormes de caminhos;
a contagem inclui segmentações e escolhas de zeros, e não necessariamente
textos distintos.

## Verificação independente

O produtor passou por doze controles plantados com blocos de 1/2/3 bytes,
dois formatos decimais e dois conjuntos de letras zeráveis.

Outro programa reconstruiu os trechos decimais no sentido inverso, calculou
as potências com BigInt e conferiu todas as 9.742.064 decisões. Nos casos
positivos, também conferiu as três contagens de caminhos e os comprimentos
extremos. Todas as 9.924 testemunhas foram recifradas, encontrando uma
separação que reproduz exatamente os símbolos e escolhas de zeros.

- [Especificação](spec.json) e [resumo](summary.json).
- [Verificação integral](verification.json).
- [Buscador](../../solver/rsa_color_multibyte.cjs) e
  [verificador](../../solver/verify_rsa_color_multibyte.cjs).
- [Formatos de chave, tamanhos fixos e candidatos selecionados](../rsa_color_candidates_2026-09-16/RELATORIO.md).

O hash do registro de modelos compatíveis é
`9ba1e7f8bd3b01b81ee01923447e28f0530ea99c3d943798ff6e5a353aae6f2d`.
Para conferir: `node solver/verify_rsa_color_multibyte.cjs`.

As conclusões dependem dos módulos selecionados, do alfabeto numérico fixo
e da conversão em bytes mínimos. Não cobrem outros módulos, texto binário,
NULs de preenchimento, outro mapeamento de dígitos, índices de letras em
vez de ASCII, ou transformações anteriores ao campo observado.
