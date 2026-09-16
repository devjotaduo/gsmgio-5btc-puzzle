# Leitura decimal em EBCDIC 1141 — 16/09/2026

**Nenhuma senha final encontrada.** As três leituras delimitadas abaixo foram
concluídas e conferidas por algoritmos independentes, sem candidatos. Não houve
teste AES ou de chave privada nesta rodada, pois nenhuma saída passou pelo
repertório de caracteres declarado.

## Pista e hipótese

A fase 3.2 associa “One for one, four for one” a IBM EBCDIC 1141. A pista já tem
uma aplicação na fase resolvida; reutilizá-la em SalPhaseIon é uma hipótese,
não uma instrução adicional confirmada. Ela motiva verificar uma limitação dos
negativos anteriores: bytes EBCDIC de letras normalmente não são bytes ASCII.

Segundo a [tabela de páginas de código da Microsoft](https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers),
1141 é a variante alemã com euro. A tabela local foi obtida de
`System.Text.CodePagesEncodingProvider`, página 1141, em .NET 10.0.11.

O teste aceita **98 caracteres de texto**: ASCII 32–126, TAB, LF e CR,
representados pelos respectivos bytes EBCDIC. Por exemplo, `ABCabc012` usa
`c1 c2 c3 81 82 83 f0 f1 f2` em hexadecimal. Não se exige inglês plausível;
a restrição é apenas o repertório, aplicado ao campo inteiro.

A tabela foi comparada byte a byte com `cp273` do Python. Para esses 98
caracteres, os bytes e caracteres coincidem integralmente. Fora do repertório,
há duas diferenças registradas: `0x9f` (moeda/euro) e `0xbc`
(overline/macron). Portanto, esta comparação **não** afirma equivalência
das tabelas Unicode completas.

- [Tabela 1141 e proveniência](./encoding.json).
- [Conferência independente do repertório](./encoding_verification.json).

## Modelos completos

DBBI e FAED são usados integralmente, nas ordens original e invertida.
Em cada modelo de alfabeto, as ocorrências das letras escolhidas podem
independentemente valer zero ou o seu dígito positivo.

1. Alfabeto literal `a=1,…,i=9`, com zero, uma ou duas letras zeráveis:
   `4 × (1+9+36) = 184` configurações por leitura.
2. Todas as `9!` bijeções de `a..i` com `1..9`, com qualquer uma das nove
   letras zerável: `4 × 9 × 362.880 = 13.063.680` configurações por leitura.

Os números abaixo contam configurações, não senhas únicas. Há sobreposição
entre modelos que permitem zero, mas escolhem manter todos os dígitos.

| Leitura dos dígitos | Configurações | Resultado |
|---|---:|---|
| Inteiro decimal completo → bytes mínimos EBCDIC | 13.063.864 | 0 candidatos |
| Concatenação dos códigos decimais mínimos de cada byte | 13.063.864 | 0 segmentações completas |
| Concatenação dos códigos decimais de cada byte, sempre com três dígitos | 13.063.864 | 0 segmentações completas |

A primeira leitura cobre as duas ordens de bytes: pertencer ao repertório
é uma condição invariante pela reversão. A busca por inteiros visitou
**19.018.074 nós**, sem interrupção ou limite atingido. A busca por códigos
considerou todas as máscaras de zero e todas as fronteiras de códigos.
Seu autômato decide viabilidade exata; não usa classificador linguístico.

## Conferência e controles

Para os inteiros, o buscador usa o menor inteiro permitido acima do extremo
inferior de cada intervalo. O verificador usa outra operação: conta inteiros
permitidos até cada extremo e confirma se o intervalo está vazio. Reconstrói
coeficientes e mapas independentemente e percorre os ramos na ordem inversa.
Os **13.063.864 casos e 19.018.074 nós** coincidiram, com zero resultados.

O sucessor foi conferido em todos os 65.536 inteiros abaixo de 2¹⁶; a busca
teve 81 comparações com máscaras enumeradas e 30 recuperações de textos
plantados. O contador independente teve outros 65.536 controles e 260
fronteiras de comprimento. O verificador só aceita uma execução terminada;
a primeira chamada, antecipada durante a busca, foi recusada por essa guarda.
A chamada posterior terminou normalmente e produziu o artefato abaixo.

Para os códigos, o buscador acompanha prefixos possíveis de palavras decimais.
O verificador acompanha posições onde um novo byte pode começar, usando
tabelas numéricas de um, dois e três dígitos. Ele usa outra enumeração das
bijeções e confirma todos os **26.127.728 casos**, sem importar o buscador.
Foram recuperadas 162 mensagens plantadas; a busca também teve 162 comparações
de gramática, e o verificador conferiu 34.992 entradas de suas tabelas.

- Inteiros: [especificação](./spec.json), [resultado](./summary.json),
  [verificação](./verification.json).
- Códigos: [especificação](./codepoints/spec.json),
  [resultado](./codepoints/summary.json), [verificação](./codepoints/verification.json).

## Reprodução

Com Node.js e os arquivos de entrada locais preservados:

```powershell
node solver/ebcdic_decimal.cjs
node solver/verify_ebcdic_decimal.cjs
node solver/ebcdic_codepoints.cjs
node solver/verify_ebcdic_codepoints.cjs
```

Os verificadores devem rodar após os respectivos buscadores terminarem.
As tabelas já estão preservadas; não há acesso à rede nos quatro programas.

| Fonte | SHA256 |
|---|---|
| [Busca de inteiros](../../solver/ebcdic_decimal.cjs) | `b1a14c3caf511dc4c9b080df6c39c0342c12bc29568f567acaf5636a5c930f0d` |
| [Verificador de inteiros](../../solver/verify_ebcdic_decimal.cjs) | `5a091a40f62cbf18e2dd15cdfc112519141bb927a3efca63f1e6eb457c7dbd43` |
| [Busca de códigos](../../solver/ebcdic_codepoints.cjs) | `874f1ecce50d0edbea7dc8b3846b03617df17dbc725c885bfd17adb3f864f742` |
| [Verificador de códigos](../../solver/verify_ebcdic_codepoints.cjs) | `b4f235f668ae07eef24ddd0b5c9f7fc85659a63e942a73d0d1f142fffae273a6` |

Entrada canônica: SHA256
`2e58c16a953bc22c2361adb5124f43d8fe624d15e3c90858349dcb25ecefedc6`.
Os artefatos também vinculam os hashes dos auxiliares e da tabela.

## Limites

Isso exclui as três leituras diretas no repertório especificado. Não exclui
EBCDIC com outros caracteres, compressão, uma cifra adicional, remoção de
símbolos, outras transposições ou outras convenções de códigos numéricos.
Com alfabeto desconhecido, duas letras zeráveis não foram cobertas; com
alfabeto literal, três ou mais também não. O significado operacional de
`yellowblueprimesmatrixsumlist` e a senha dos blobs finais permanecem abertos.
