# Inteiro decimal com qualquer ocorrência zerável

**Nenhuma senha final recuperada.** Vinte modelos completos deixam somente
42 saídas distintas, de até 15 bytes. Todas exigem zerar ocorrências das nove
letras, inclusive longos prefixos. Suas composições declaradas foram testadas
nos três blobs, sem resultado validado. Dois alfabetos mais amplos receberam
sondagens parciais; todos os candidatos encontrados nessas sondagens também
foram testados, mas os domínios restantes continuam abertos.

## Lacuna examinada

A pista do criador fala em caracteres que precisam ser zerados, sem nomear
uma única letra. As rodadas anteriores distinguiram duas operações:

- converter o campo inteiro de decimal para bytes, com poucas letras zeráveis;
- concatenar códigos individuais de caracteres, permitindo depois todas as
  letras como zero.

Esta rodada amplia **a primeira operação**. Para cada posição de DBBI ou
FAED, o dígito é independentemente zero ou o valor conhecido `a=1,...,i=9`.
Não se limita a quantidade de letras ou ocorrências zeradas. O campo completo
vira um inteiro decimal, e todos os seus bytes mínimos big-endian precisam
pertencer ao repertório declarado.

Zeros iniciais são permitidos e desaparecem na conversão do inteiro. Isso
torna o modelo mais permissivo; não transforma letras em caracteres apagados
no meio do número. Não há mapa desconhecido, transposição, cifra adicional
ou escolha de offset.

## Modelos completos

Foram usados cinco repertórios, em ambos os campos e sentidos dos símbolos:

1. `a..z` com TAB/LF/CR, espaço e `! " ' ( ) , - . / : ; ?`.
2. `A..Z` com a mesma pontuação e os mesmos espaços.
3. Dígitos com TAB/LF/CR, espaço e `( ) , - . : ; [ ]`, como filtro permissivo
   para uma lista numérica textual.
4. Hexadecimal `0..9,a..f`.
5. Hexadecimal `0..9,A..F`.

Os dois repertórios de prosa **não contêm dígitos** nem permitem misturar
maiúsculas e minúsculas. Os filtros não exigem palavras de dicionário.

| Campo e sentido | Minúsculas/pontuação | Maiúsculas/pontuação | Lista numérica | Hex minúsculo | Hex maiúsculo | Maior saída |
|---|---:|---:|---:|---:|---:|---:|
| DBBI original | 3 | 6 | 0 | 1 | 0 | 12 B |
| DBBI invertido | 3 | 2 | 0 | 0 | 0 | 7 B |
| FAED original | 3 | 11 | 1 | 0 | 0 | 12 B |
| FAED invertido | 4 | 10 | 1 | 0 | 0 | 15 B |

As colunas podem conter a mesma saída. A união tem **42 textos distintos**.
As únicas saídas no filtro numérico de FAED são `]` e LF; não formam uma
lista de somas. A única saída hexadecimal de DBBI é `d`, não um hash.

Todos os candidatos usam as nove letras como zero em alguma posição. Assim,
**qualquer restrição a oito ou menos letras zeráveis elimina todas as saídas
desses vinte modelos**, sem precisar repetir cada subconjunto de letras.
Os candidatos de DBBI têm pelo menos 62 zeros decimais iniciais; os de FAED,
pelo menos 534. Sua compatibilidade resulta de preservar apenas uma pequena
parte final do número, não de recuperar uma instrução longa.

## Cobertura e conferência

Cada modelo de DBBI cobre exatamente `2^91` escolhas; cada modelo de FAED,
`2^570`. Esses são tamanhos lógicos dos domínios, não quantidades de senhas
AES testadas fisicamente.

O buscador limita cada ramo por dois inteiros e calcula o menor inteiro
permitido maior ou igual ao limite inferior. Se ele excede o limite superior,
o ramo inteiro é excluído. Foram preservados **18.215 certificados terminais**.

Uma implementação Python independente contou quantos inteiros permitidos
existem em cada intervalo, sem reutilizar o algoritmo de sucessor. Conferiu
as exclusões, a cobertura disjunta de todos os padrões de máscaras, cada
candidato e a união final. Também confirmou os limites de comprimento e a
necessidade de todas as nove letras zeráveis.

Os controles do produtor incluem 20 comparações com enumeração de 3.200
atribuições, 884 comparações do sucessor com um conjunto explícito e cinco
mensagens plantadas recuperadas, incluindo `matrixsumlist` e `[2,3,5,7]`.

## Autenticação dos 42 candidatos

Cada saída foi usada em ordem normal ou inversa dos bytes, sozinha ou seguida
por uma das duas cláusulas já fixadas na investigação:

- `reinsertingtheprimebasicsafterwhichyouwillberequiredto`
- `sheisgoingtodieandthereisnothingyoucandotostopit`

Os 234 materiais distintos geraram 468 senhas diretas/SHA256 hexadecimal.
SMALL, TAIL32 e COSMIC, com EVP-SHA256/MD5, deram **2.808 decisões AES**,
sete paddings e nenhuma abertura validada. A maior proporção de ASCII
imprimível/TAB/LF/CR foi 43,04%. Os 468 escalares declarados não atingiram
a chave pública do prêmio nem sua negação. PyCryptodome e coincurve
reproduziram os resultados e os controles conhecidos.

## Alfabetos amplos: sondagens parciais

Para FAED original, duas ampliações também foram sondadas:

| Repertório | Limite atingido | Candidatos encontrados | Maior saída | Busca completa? |
|---|---:|---:|---:|---|
| ASCII 32–126 e TAB/LF/CR | 100.000 nós | 22.858 | 15 B | Não |
| Minúsculas/pontuação acrescidas de `0..9` | 200.000 nós | 3.713 | 80 B | Não |

Uma verificação independente conferiu os limites, máscaras pendentes e
candidatos dessas duas sondagens. Elas não permitem excluir seus domínios
completos. Os candidatos não foram selecionados por qualidade linguística;
são os primeiros encontrados na ordem declarada de busca.

A união encontrada contém **26.562 saídas distintas**. Suas formas direta e
SHA256 hexadecimal geraram **53.124 senhas**, sem inversão de bytes ou
cláusulas adicionais nesta autenticação. Foram **318.744 decisões AES**,
1.236 paddings sem resultado validado e **53.124 escalares** sem acerto.
PyCryptodome e coincurve reproduziram todas as decisões. A maior proporção
de ASCII dos corpos com padding foi 53,16%.

Esses testes esgotam os candidatos **encontrados**, não as máscaras ainda
pendentes nem outras formas de senha. As contagens desta seção não devem
ser somadas às da anterior como se fossem conjuntos globalmente distintos.

## Artefatos e limites

- [Especificação e controles](spec.json)
- [Resumo dos vinte modelos completos](summary.json)
- [42 candidatos, máscaras e procedência](candidates.json)
- [Conferência por contagem de inteiros](verification.json)
- [Testes AES/secp256k1](oracles.json) e [conferência](oracle_verification.json)
- [Conferência dos pilotos parciais](pilot_verification.json)
- [Autenticação dos candidatos dos pilotos](pilot_oracles.json) e [conferência](pilot_oracle_verification.json)

Programas:
[unbounded_zero_integer.cjs](../../solver/unbounded_zero_integer.cjs),
[autenticação principal](../../solver/unbounded_zero_integer_oracles.cjs) e
[autenticação dos pilotos](../../solver/unbounded_zero_integer_pilot_oracles.cjs).
As árvores principais são arquivos JSON gzip referenciados no resumo. As
sondagens e as verificações Python foram executadas inline; as máscaras e
os parâmetros de cada sondagem foram preservados nos respectivos artefatos.
Os programas recusam sobrescrever seus resultados existentes.

SHA256 de `summary.json`:
`e4dcc27f5575ea61fb0d5c06cc9118bb1ef6057e406c836ee19ae37a8a138f8c`.

SHA256 da autenticação dos pilotos:
`0fcc2b5a0c60a494d91cfea85c7dad7f0885c47c4f9a7308c73866232c1d8100`.

A conclusão completa vale apenas para os cinco repertórios listados, o mapa
`a..i=1..9` e a conversão do inteiro. Não exclui mistura de caixa, prosa com
dígitos, hexadecimal de caixa misturada, Unicode, dados binários, outras
cifras ou outras funções de DBBI/FAED. O mecanismo de `matrixsumlist` e a
senha final continuam desconhecidos. Não há processo desta rodada em execução.
