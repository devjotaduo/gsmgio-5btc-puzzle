# DBBI como SHA256 das somas da matriz

16/09/2026. **Nenhuma senha final foi encontrada.** Esta rodada testa uma
função distinta para DBBI: um hash codificado, cuja pré-imagem seria uma
lista calculada da matriz inicial. A hipótese combina o uso de SHA256 nas
fases anteriores, o trecho `matrixsumlist` e as pistas de cores e primos.
Nenhuma dessas fontes confirma por si só essa montagem.

## Restrição de hash sem conhecer a substituição

A leitura gulosa de DBBI com `b/g` como prefixos de tokens de dois
caracteres produz 64 tokens de 16 tipos. Os demais caracteres são tokens
de um caractere. Esse formato é compatível com um SHA256 hexadecimal sob
substituição bijetiva de símbolos.

Foram conferidos os 36 pares possíveis de prefixos, nos dois sentidos da
sequência: **72 análises**. Somente `b/g` no sentido original tem 64 tokens
e 16 tipos. A sequência de tokens foi examinada em suas duas ordens.

Se uma pré-imagem for correta nesse modelo, todas as igualdades e
desigualdades entre os 64 nibbles de seu hash precisam coincidir com as
dos tokens. Isso permite testar o hash sem enumerar as 16! substituições.
Uma coincidência parcial não é aceita. Mesmo uma coincidência completa
exigiria reconstrução e consequência verificável nos blobs ou na chave
antes de ser apresentada como solução.

Esse teste não exige que FAED use o mesmo alfabeto ou tenha a mesma função.
O uso de `b/g` como prefixos continua hipotético.

## Pré-imagens examinadas

As células azuis e amarelas recebem valores constantes por cor; as outras
células mantêm seus bits originais ou são zeradas. Os valores por cor vêm
de dois conjuntos declarados:

1. Todas as combinações de `0`, `1` e dos 44 primos até 196, o número de
   células da matriz. São 46² = 2.116 pares. Zero e um são controles e
   escolhas de zeragem, não números primos.
2. Divisores primos dos inteiros RGB das respectivas cores:

```text
azul:    0x3F48CC = 4.147.404  = 2² × 3 × 37 × 9341
amarelo: 0xFFF200 = 16.773.632 = 2⁹ × 181²
```

As combinações de divisores acrescentam somente dois pares novos:
`azul=9341, amarelo=2` e `azul=9341, amarelo=181`. Total: **2.118 pares de
valores e 4.236 configurações de matriz** nos dois fundos.

A faixa até 196 é um limite desta experiência, não uma faixa indicada
pelo autor. Os divisores RGB são uma leitura aritmética das cores; sua
relevância criptográfica permanece hipotética.

De cada matriz foram calculados:

- Somas das 14 linhas e das 14 colunas.
- Linhas seguidas de colunas e colunas seguidas de linhas.
- Linhas e colunas intercaladas.
- Soma total.

Cada lista foi usada no sentido direto e inverso, nas representações:

- Decimal concatenado, com vírgulas, com espaços ou com quebras LF.
- Lista entre colchetes, compacta ou com espaço após cada vírgula.
- Bytes de oito bits, somente quando todos os valores cabem.
- Inteiros sem sinal de 16 e 32 bits, nas duas ordens de bytes, somente
  quando todos os valores cabem. Nenhum valor foi truncado.

O SHA256 foi calculado sobre os bytes exatos de cada representação. Não
foram acrescentadas frases, senhas ou palavras escolhidas depois dos
resultados.

## Resultado e verificação

**525.468 avaliações SHA256 e 1.050.936 comparações de padrões completos:
zero correspondências.** Os números contam construções e representações,
não pré-imagens necessariamente distintas. Por exemplo, inverter uma
lista que contém apenas o total não muda seus bytes.

O buscador gera as somas por coeficientes de contagens de células. O
verificador reconstrói cada matriz numericamente, soma suas linhas e
colunas e regenera todos os bytes das pré-imagens. O primeiro compara
uma bijeção entre símbolos e nibbles; o segundo compara padrões
normalizados por primeira ocorrência. Os 4.236 resumos criptográficos
das sequências de avaliações coincidiram integralmente, incluindo bytes,
hashes e decisões.

Controles: SHA256 conhecido de `abc`, exemplos positivos e negativo da
comparação de padrões e conversão de inteiros para bytes e de volta.

Nenhum candidato passou pela condição necessária do hash. Portanto, não
houve testes AES ou de chave privada nesta rodada. Isso não afirma que
essas listas não possam ter outra função na senha; afirma que **nenhuma
é a pré-imagem de DBBI no modelo de hash substituído descrito aqui**.

Continuam fora do alcance outros pesos, representações, componentes
adicionais, hashes diferentes, homofonia e outras tokenizações. A simples
compatibilidade 64/16 não estabelece que DBBI seja um hash. Uma retomada
dessa hipótese precisa justificar outra pré-imagem ou uma regra que fixe
a substituição, em vez de ampliar dicionários sem uma pista adicional.

## Reprodução

```powershell
node solver/dbbi_matrix_hash.cjs
node solver/verify_dbbi_matrix_hash.cjs
```

Artefatos: [especificação](spec.json), [resumos por configuração](groups.json),
[correspondências](hits.json), [resultado](summary.json),
[conferência independente](verification.json),
[buscador](../../solver/dbbi_matrix_hash.cjs) e
[verificador](../../solver/verify_dbbi_matrix_hash.cjs).

SHA256 dos resumos por configuração:
`9d10d8cf36c8cc5afc26c326a8ca8ebd58306422a4b1fbca890837a0f51c82fb`.
