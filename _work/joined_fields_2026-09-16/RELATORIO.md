# DBBI e FAED como um único número

16/09/2026. **Nenhuma senha final encontrada.** A concatenação direta dos
dois campos não produz bytes de sete bits no modelo abaixo. A família
mais ampla de UTF-8 foi parcialmente excluída e continua inconclusiva
em 270 configurações.

## Hipótese e cobertura

O trecho binário `matrixsumlist`, situado entre DBBI e FAED, poderia ser
uma instrução inserida entre duas partes do mesmo número decimal.
Testamos ambas as ordens dos campos e a inversão independente de cada
um, conservando `a=1..i=9`. Cada campo escolhe independentemente uma ou
duas letras que podem representar zero ou seu dígito por ocorrência.

Há 45 escolhas de letras por campo. Com duas ordens dos campos, duas
direções para cada campo e duas ordens dos bytes, são **32.400 modelos**.
Os zeros à esquerda não acrescentam bytes à representação mínima do
inteiro. Não se permite apagar caracteres ou bytes problemáticos.

## Prova completa para bytes de sete bits

Escrevendo os campos como `A` e `B`, o inteiro é `A × 10^L + B`, com `L`
igual ao comprimento decimal do segundo campo. Podemos relaxar `B` para
qualquer inteiro de `0` a `10^L−1`, em vez de escolher suas máscaras.
Se esse intervalo não contém nenhum inteiro formado por bytes abaixo de
128, nenhuma interpretação do segundo campo consegue corrigir o primeiro.

Foram **180 árvores completas**, cobrindo as escolhas do primeiro campo:
**1.274 nós, 727 certificados, zero intervalos sobreviventes**. Como a
propriedade de sete bits independe da ordem dos bytes, o resultado cobre
todos os 32.400 modelos originais. Na verdade, admite qualquer conteúdo
numérico do segundo campo, uma hipótese mais permissiva que a original.

Um programa independente reconstruiu os extremos de cada intervalo por
concatenação de dígitos e contou os inteiros válidos dentro dele. Conferiu
também que os certificados cobrem todas as máscaras, sem sobreposição.
Os controles recuperaram 24 mensagens plantadas; o contador foi conferido
em 65.536 inteiros pequenos e 300 larguras de bytes.

[Especificação ASCII](ascii_prefix_spec.json), [certificados](ascii_prefix_cases.json),
[resumo](ascii_prefix_summary.json), [verificação](ascii_prefix_verification.json).

## UTF-8: exclusão parcial, com limite explícito

Repetimos a análise dos prefixos aceitando UTF-8 estrito, incluindo
caracteres de controle, em ambas as ordens dos bytes. As **360 árvores**
terminaram: 95.284 nós e 34.966 certificados, verificados por contagem
independente baseada nos padrões de bytes Unicode.

Somente três configurações do primeiro campo deixam intervalos possíveis:

| Primeiro campo | Direção | Letras zeráveis | Ordem dos bytes | Atribuições sobreviventes |
|---|---|---|---|---:|
| DBBI | Original | `b,d` | Big-endian | 5 |
| DBBI | Inversa | `b,e` | Big-endian | 11.050 |
| DBBI | Inversa | `b,e` | Little-endian | 1.801 |

Cada configuração corresponde a 90 modelos do segundo campo. Logo,
os prefixos excluem **32.130 modelos** e deixam **270** sem exclusão
por essa prova. Todo modelo que começa por FAED foi excluído, mesmo
permitindo qualquer segundo campo de 91 dígitos.

As 12.856 atribuições sobreviventes permitem algum preenchimento
numérico livre; elas **não são mensagens decifradas**, e não demonstram
compatibilidade com as letras reais do segundo campo.

A busca residual examinou combinações reais, mas foi interrompida após
uma configuração exigir muito processamento. Foram preservados 9.837
registros completos, com 178.563 árvores do segundo campo, 866.205 nós,
522.384 certificados e nenhum candidato registrado. Esses registros
residuais **não passaram pela verificação independente completa** e não
aumentam a contagem autoritativa de exclusões acima. O arquivo comprimido
original interrompido também foi preservado.

[Prova dos prefixos UTF-8](prefixes.json.gz),
[resumo](prefix_summary.json), [verificação independente](prefix_verification.json),
[registro da interrupção](partial_summary.json),
[registros completos preservados](completed_cases.jsonl.gz).

## Limites e reprodução

O resultado ASCII não se estende automaticamente a texto Unicode ou a
dados binários. A hipótese também não cobre outras bases, substituição
dos nove dígitos, mais de duas letras zeráveis no primeiro campo,
intercalação, outros segmentos da página ou operações adicionais.
Não houve teste AES nem de chave privada: nenhuma mensagem candidata
foi produzida pelas partes registradas desta busca.

```powershell
node solver/joined_ascii_prefix.cjs
node solver/verify_joined_ascii_prefix.cjs
node solver/verify_joined_decimal_fields.cjs prefixes
```

O [buscador UTF-8](../../solver/joined_decimal_fields.cjs) executa a família
mais ampla e pode levar muito tempo nos casos residuais. Não é necessário
reexecutá-lo para conferir as duas provas de prefixos preservadas.
Programas ASCII: [buscador](../../solver/joined_ascii_prefix.cjs) e
[verificador](../../solver/verify_joined_ascii_prefix.cjs).
Verificador UTF-8: [código](../../solver/verify_joined_decimal_fields.cjs).
