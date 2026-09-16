# DBBI nas células zero, primos das cores e listas de somas

**16/09/2026 — nenhuma senha final encontrada.** A auditoria corrigiu uma
contagem rejeitada por engano no histórico. A combinação de pistas testada
abaixo não abriu SMALL, TAIL32 ou COSMIC nem forneceu a chave do prêmio.

## Correção da geometria e alcance do teste antigo

A matriz atual tem 196 células: **101 uns e 95 zeros**. Seu trecho espiral
`0..191` decodifica exatamente os 24 bytes de `gsmg.io/theseedisplanted`:
**101 uns e 91 zeros**. Os quatro bits restantes são `0000`.

A única diferença entre `MATRIX_IMG` do auxiliar histórico
`gsmg_common.py` e a matriz atual é a célula `[7,6]`, índice espiral 193.
Ela fica fora dos 192 bits da URL. Portanto, a declaração antiga de
“102 uns” é incorreta, mas **não invalida a distribuição de DBBI nas
91 células zero dessa região**. As coordenadas usadas nessa distribuição
são idênticas. Não foi necessário repetir a busca antiga por esse motivo.

A nota histórica que mandava descartar “91 zeros nos índices 0..191”
também estava errada e foi corrigida em ENDGAME. Isso corrige a documentação;
não é descoberta de uma nova mensagem oculta.

## Hipótese nova e delimitada

O script antigo `dbbi_in_zeros.py` testava as somas da matriz preenchida
com valores uniformes 0, 1 ou 9 nos uns restantes. Nesta rodada, as duas
cores recebem valores primos derivados dos respectivos RGB:

1. Preencher os 91 zeros do trecho da URL, em ordem espiral, com DBBI
   completo sob `a=1,...,i=9`; considerar DBBI direto ou invertido.
2. Substituir as células azuis e amarelas pelos fatores primos de suas
   somas de dígitos hexadecimais, somas de canais ou inteiros RGB completos.
   São os mesmos **14 pares** declarados na
   [rodada dos fatores das cores](../color_factor_sums_2026-09-16/RELATORIO.md).
3. Preservar os bits pretos e os quatro zeros centrais. Os nove dígitos de
   DBBI colocados em células amarelas são sobrescritos nessa hipótese.
4. Preservar o dígito colocado no quase branco `[7,4]`, índice espiral 163,
   ou zerá-lo. Essa célula corresponde à posição 76 de DBBI, em base zero
   e antes da eventual inversão do campo.
5. Somar as linhas e colunas.

São **56 matrizes**, combinando dois sentidos, 14 pares e duas escolhas
para o quase branco. Essa fórmula não é uma instrução confirmada do criador.
A igualdade de comprimentos permite a distribuição, mas não prova sua intenção.

## Listas como ingredientes diretos de senha

Linhas, colunas, suas duas concatenações e intercalação, cada uma em ambos
os sentidos, produziram **560 listas**. Foram usadas seis representações
exatas: dígitos concatenados, vírgula, espaço, LF, JSON compacto e colchetes
com espaço após vírgula.

Para cada representação, usaram-se a lista isolada, lista seguida de uma
das duas cláusulas abaixo e amarelo + azul + lista + cláusula:

```text
reinsertingtheprimebasicsafterwhichyouwillberequiredto
sheisgoingtodieandthereisnothingyoucandotostopit
```

As **16.800 pré-imagens distintas** produziram **33.600 senhas**, diretamente
e como SHA256 hexadecimal. Nos três blobs, com EVP-SHA256 e EVP-MD5, foram
**201.600 decisões AES**. Houve 751 paddings válidos; a maior proporção de
ASCII imprimível/TAB/LF/CR foi 53,16%, sem conteúdo autenticado.

SHA256 das senhas e dos corpos com padding, além dos corpos completos
que tivessem formato de escalar de 32 bytes ou 64 caracteres hexadecimais,
produziram **34.351 escalares distintos válidos**. Nenhum correspondeu à
chave pública do prêmio ou à sua negação.

Uma implementação Python separada reconstruiu a espiral por anéis e os bits
a partir da URL, comparou as matrizes antiga/atual, refez os fatores, matrizes,
listas, pré-imagens e senhas. PyCryptodome reproduziu todas as decisões AES,
inclusive rejeições; coincurve conferiu todos os escalares. A fase 3.2
conhecida e o gerador secp256k1 passaram como controles.

## Listas como chaves numéricas para FAED

As 112 listas básicas de 14 somas, de linhas ou colunas das 56 matrizes,
geraram **10.392 chaves decimais distintas**: valores módulo 10 ou seus
dígitos concatenados, ambos os sentidos e todas as rotações cíclicas.

Foram testados dois modos de operação: adição/subtração/Beaufort dígito a
dígito módulo 10, ou as mesmas operações sobre o inteiro módulo `10^L`.
Cada ocorrência de `g` em FAED pode valer zero ou sete; as outras letras
mantêm seu valor. Usam-se o campo completo nos dois sentidos e os bytes
mínimos em big-endian ou little-endian, exigindo UTF-8 estrito. Caracteres
de controle são permitidos e não se usa um classificador de idioma.

**249.408 casos completos, 855.896 nós, 552.652 certificados de exclusão,
zero candidatos e nenhum estado pendente.** Cada prefixo de escolhas
define um intervalo inteiro; a ausência de qualquer UTF-8 nesse intervalo
elimina todas as continuações. Isso cobre todas as `2^107` máscaras por
modelo, sem enumerar fisicamente cada uma.

O verificador reconstruiu as chaves e os extremos dos intervalos. Em vez
do algoritmo de sucessor do produtor, contou os inteiros UTF-8 por padrões
de bytes dos escalares Unicode. Conferiu todos os certificados e a
cobertura sem sobreposição. Passaram 36 controles por enumeração, 12
mensagens plantadas e 16 intervalos pequenos do contador independente.

## Artefatos e limites

- [Especificação e auditoria histórica](./spec.json),
  [matrizes](./matrices.json), [listas](./lists.json),
  [pré-imagens](./materials.json), [oráculos](./oracles.json),
  [conferência criptográfica](./verification.json).
- [Modelo das chaves numéricas](./stream_spec.json),
  [resultados](./stream_summary.json),
  [conferência integral](./stream_verification.json);
  certificados em `stream_cases.jsonl`.
- [Gerador e testes de senha](../../solver/zero_cells_prime_sums.cjs),
  [busca de chaves numéricas](../../solver/zero_cells_prime_stream.cjs),
  [verificador dos intervalos](../../solver/verify_zero_cells_prime_stream.cjs).
- [Manifesto final](./final_qa.json).

O negativo vale para as regras e formatos declarados. Não elimina outras
operações com as listas, mapas diferentes de dígitos, mais letras zeráveis,
outros valores das cores ou outros modos de relacionar DBBI e FAED.
A autenticação direta não examinou toda composição possível de senha.
Não há processo desta rodada em execução.
