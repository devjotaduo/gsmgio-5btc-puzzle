# Continuação da receita de X — 11/09/2026

**Resultado: nenhuma abertura validada de SMALL, TAIL32 ou COSMIC.** Foram
testadas 5.346 senhas distintas, com 32.076 tentativas AES. A conferência
cruzada reproduziu todos os sucessos e insucessos de padding. Os 129 resultados
com padding não forneceram texto coerente, chave do prêmio ou formato binário
validado nos verificadores empregados.

Esta rodada parte do script original de X, recuperado no export do Telegram:
[original_dbbi_sum_faed.py](../endgame_review_2026-09-11/original_dbbi_sum_faed.py),
mensagem #63518, 22/05/2026. Seus três fragmentos são reproduzíveis; a leitura
`SEND THE BLUE TO SET HEX` é uma interpretação do participante, sem endosso
demonstrado do criador. `NET` é uma extensão posterior da comunidade.

## Duas construções de alfabeto hexadecimal

As posições azuis em leitura por linhas, contando a primeira célula como 1, são:

```text
6,17,25,36,47,58,88,99,118,126,129,163,170,185,193
```

Em bytes hexadecimais:

```text
061119242f3a5863767e81a3aab9c1
```

**Construção A:** a ordem de primeira ocorrência dos dígitos é
`061924f3a587ebc`; falta somente `d`. Acrescentá-lo fornece o alfabeto
`061924f3a587ebcd`. A tokenização gulosa de `dbbi`, usando `b/g` como prefixos
de tokens de dois caracteres, produz 64 tokens de 16 tipos. Associar esses
tipos ao alfabeto azul dá uma hipótese concreta de 64 dígitos hexadecimais.

O candidato canônico, com tipos ordenados por primeira ocorrência, foi:

```text
0619244f31a5ff1af87ef6eaa72abc90afbb406b4443bf7874f04199bd37775f
```

Foram examinadas 144 combinações: ordem das células por linha, coluna ou
espiral conhecida da URL; percurso normal ou invertido; índices por linhas
com base 0 ou 1; dígitos ausentes acrescentados antes ou depois; três ordens
de tipos de token; sequência de tokens normal ou invertida. As três ordens
de tipos são primeira ocorrência, lexicográfica e símbolos simples antes
dos pares em ordem lexicográfica. Não houve busca pelas 16! substituições.

**Construção B:** os primos dessa lista azul são `17,47,163,193`. A redução
usada pelo próprio X, `(p-1)%9+1`, fornece **`8,2,1,4`**. Eles correspondem
às letras `h,b,a,d` na escala `a=1..i=9`, e são exatamente os quatro pesos
binários que permitem obter todos os números de 0 a 15 por somas de subconjuntos.

Enumerando as máscaras binárias de 0 a 15 e associando o primeiro peso ao bit
menos significativo, surge o alfabeto `082a193b4c6e5d7f`. Seu candidato canônico é:

```text
082a1993b24c332436e538544e14d7a043dd908d999bd3e6e93092aadfbeeec3
```

Foram testadas todas as 24 permutações desses quatro pesos, as mesmas três
ordens de tipos e os dois sentidos da sequência: mais 144 mapeamentos.
A igualdade com os pesos binários é um fato aritmético. Interpretá-la como
instrução para essa substituição continua sendo hipótese.

Não confundir o índice azul `163` **por linhas, base 1**, com o índice `163`
**da espiral, base 0**, anteriormente associado ao pixel `FEFEFE`: são
convenções e células distintas.

Em ambas as construções, cada candidato foi testado como senha em hex
minúsculo, hex maiúsculo e 32 bytes crus; também como SHA256 hexadecimal
de cada uma dessas três formas. Os bytes, sua inversão e hashes derivados
foram confrontados com a chave pública do prêmio e sua negação. Nenhum bateu.

## Valores descartados pelo módulo 26

A receita de X soma os pesos de `dbbi` e as linhas de 15 símbolos de `faed`,
aplica XOR e transforma cada resultado em letra com `valor % 26`.

Foram preservadas 17 listas numéricas: duas chaves de 14 somas, duas listas
de 38 somas de `faed`, suas contribuições removidas, XOR bruto/resto/quociente
das três saídas e duas concatenações das três saídas. Cada lista foi
serializada em bytes, hex minúsculo/maiúsculo, decimal concatenado e decimal
com vírgulas. Após deduplicação: 81 materiais e 162 senhas, incluindo SHA256.
O teste foi negativo nas formas declaradas. Não foi realizada uma busca
por cortes ou permutações dessas listas.

As listas completas estão em [rail_values/lists.json](rail_values/lists.json);
a receita e o escopo, em [rail_values/spec.json](rail_values/spec.json).

## Candidatos como parte da senha

A página também sugere uma montagem de respostas seguida de SHA256. Por
isso, os 288 valores hexadecimais distintos das duas construções foram
testados na ordem hipotética:

```text
SHA256(dbbi_mapeado + soma_da_matriz + faed + últimas_palavras)
```

As opções foram limitadas a três representações da matriz (total 101,
somas das linhas concatenadas ou somas das colunas concatenadas), duas de
`faed` (literal e dígitos `a=1..i=9`) e duas leituras antes de `SELECT` no
texto já decifrado: `to` ou
`reinsertingtheprimebasicsafterwhichyouwillberequiredto`.
Todos os componentes foram concatenados sem separadores, com letras
minúsculas. O SHA256 hexadecimal foi usado como senha.

Isso gerou 3.456 senhas adicionais. **O teste pressupõe essas leituras de
`faed` e das últimas palavras; não resolve nem elimina suas outras leituras.**
Os componentes efetivos e cada pré-imagem estão em
[composite/spec.json](composite/spec.json) e
[composite/passwords.jsonl](composite/passwords.jsonl).

## Resultados e controles

| Família | Senhas distintas na família | Tentativas AES | Paddings válidos |
|---|---:|---:|---:|
| Dígitos azuis como alfabeto | 864 | 5.184 | 16 |
| Pesos binários dos primos azuis | 864 | 5.184 | 32 |
| Somas, XOR, restos e quocientes de X | 162 | 972 | 6 |
| Concatenação com matriz, `faed` e últimas palavras | 3.456 | 20.736 | 75 |
| **Total, também deduplicado entre famílias** | **5.346** | **32.076** | **129** |

Cada senha foi testada nos **três blobs originais**, com AES-256-CBC e
EVP_BytesToKey SHA256/MD5. Não foram usados os 35 blocos da cadeia comunitária.
Sob saída aleatória, seriam esperados aproximadamente 125,8 eventos de
padding nesse volume; os 129 observados não constituem evidência de abertura.
Essa comparação é apenas uma referência de contagem, não um teste de
independência entre candidatos.

O maior percentual de bytes ASCII imprimíveis, incluindo TAB/LF/CR, foi
50,63%. Além dessa triagem, houve busca da chave alvo e sua negação em
janelas binárias BE/LE, candidatos hexadecimais e derivados. Os 129
plaintexts completos foram examinados também para WIFs com checksum e
formatos binários comuns. Dois pares `1f8b` casuais foram encontrados,
mas ambos falharam como gzip por método de compressão inválido. Não houve
stream zlib/gzip completo nem ocorrência da chave pública alvo.

Controles: fase 3.2 original aberta com sua senha conhecida; 12 recuperações
AES de mensagens binárias de comprimentos relevantes nos dois KDFs; chave
pública conhecida do escalar 1. Python/PyCryptodome/coincurve e Node/OpenSSL
concordaram nas verificações cruzadas. O verificador reproduziu **todas as
32.076 tentativas**, inclusive as que falharam, e os 129 plaintexts completos.

Reproduzir as duas famílias de alfabetos e conferir todas as senhas salvas:

```powershell
node solver/blue_hex_constraints.cjs
node solver/blue_hex_constraints.cjs --prime-bits
node solver/verify_blue_hex.cjs
```

Arquivos de auditoria: [verification.json](verification.json),
[independent_checks.json](independent_checks.json),
[prime_bits/independent_checks.json](prime_bits/independent_checks.json) e
[binary_format_checks.json](binary_format_checks.json).

## Consequência para a prioridade

**SalPhaseIon → SMALL permanece a frente escolhida**, com TAIL32 e COSMIC
testados em paralelo. A receita original de X continua reproduzível, mas
nenhuma das consequências criptográficas examinadas nesta rodada a validou.
Os negativos não descartam todo uso de cores/primos, todo alfabeto de
`dbbi`, nem uma interpretação ainda desconhecida de `faed`.

Antes de ampliar substituições, falta explicar a escolha dos prefixos `b/g`
e uma regra que fixe o valor de cada token a partir das pistas. Primeira
ocorrência e ordem alfabética são convenções de teste, não respostas já
deduzidas do puzzle. Os casos acima ficam registrados para não repeti-los.
