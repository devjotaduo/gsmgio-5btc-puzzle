# Remoção opcional de símbolos e zeros na conversão decimal

16/09/2026. **Nenhuma senha final ou chave do prêmio validada.** Foram
concluídos três modelos de remoção/zero, cobrindo 360 configurações e
todas as escolhas por ocorrência dentro de cada modelo.

O criador mencionou que alguns caracteres precisariam ser “zeroed out”
na mensagem #8000, de 26/12/2021, preservada nas
[pistas primárias](../review_2026-09-11/primary_clues.json). Isso não
especifica quais caracteres nem confirma remoção. A interpretação como
símbolos nulos é uma hipótese adicional, distinta de substituir por zero.

## Modelos e resultados

Todos usam DBBI e FAED completos, nos dois sentidos, com `a=1,…,i=9`
salvo as mudanças explicitamente descritas. O resultado é interpretado
como um único inteiro decimal e convertido em bytes mínimos. O filtro
aceita qualquer byte entre 0 e 127, incluindo controles; portanto é mais
permissivo que exigir uma mensagem ASCII legível. As duas ordens de bytes
obedecem à mesma condição de sete bits.

| Modelo | Configurações | Nós verificados | Certificados de exclusão | Saídas distintas |
|---|---:|---:|---:|---:|
| Uma letra: manter ou remover cada ocorrência | 36 | 4.013 | 2.614 | 0 |
| Uma letra: manter, zerar ou remover cada ocorrência | 36 | 25.971 | 17.033 | 22 |
| Uma letra sempre zero; outra pode ser mantida ou removida | 288 | 32.703 | 21.155 | 0 |

Na terceira linha, as duas letras são diferentes; todas as 72 escolhas
ordenadas foram examinadas para cada campo/sentido. O zero é fixo nessa
família, não uma escolha independente entre zero e valor positivo.

As 22 saídas da segunda linha vêm apenas de DBBI original com `b` como
letra ambígua. Todas contêm controles não usuais e nenhuma é integralmente
imprimível, mesmo permitindo TAB/LF/CR. FAED não possui saída de sete bits
em nenhum dos três modelos.

## Como a busca cobre todas as escolhas

Se há `m` ocorrências opcionais, agrupamos a busca pelo número de remoções
`k`, de 0 a `m`. Para cada sufixo e cada `k`, programação dinâmica calcula
o menor e o maior inteiro decimal possível. O prefixo já decidido e esses
extremos delimitam um intervalo que contém todas as continuações.

Um intervalo é descartado somente quando não contém nenhum inteiro cujos
bytes sejam todos menores que 128. Se não puder ser descartado, a busca
se divide pelas escolhas manter/remover e, quando permitido, zerar.
Estados idênticos são compartilhados; todos os filhos e raízes foram
preservados nos arquivos compactados. Nenhum caso atingiu o limite de nós.

O verificador independente usa outra programação dinâmica, caractere a
caractere com strings decimais, para reconstruir os extremos. Em vez do
sucessor usado pelo buscador, conta diretamente os inteiros de sete bits
até cada extremo, usando os dígitos em base 256 e contagens em base 128.
Verifica cada certificado, cada transição, cada resultado terminal e a
cobertura completa das máscaras. Para cada raiz, a contagem esperada é
`C(m,k)` ou `C(m,k)×2^(m−k)`, conforme haja a alternativa zero. Somar as
raízes cobre respectivamente `2^m` ou `3^m` escolhas.

Foram conferidos **62.687 nós e 40.802 certificados**, com 13.580 raízes.
O contador passou por enumeração dos primeiros 65.536 inteiros; 40
comparações exaustivas conferiram os extremos dos sufixos. Os controles
do buscador incluíram 130 máscaras binárias, 818 ternárias e mensagens
plantadas. A família de zero fixo também recuperou `enter`, `hello` e
`matrix` com símbolos de zero e nulos explicitamente codificados.

## Validação das 22 saídas

As duas ordens dos bytes produziram 44 materiais e 88 senhas, usando os
bytes diretamente e seu SHA256 hexadecimal. SMALL, TAIL32 e COSMIC foram
testados com EVP-SHA256 e EVP-MD5:

- **528 decisões AES**, dois paddings, nenhum plaintext autenticado;
  a maior proporção imprimível foi 40,51%.
- **352 escalares distintos**, incluindo hashes dos materiais/corpos e
  janelas contíguas de 32 bytes, sem correspondência com a pubkey do prêmio
  ou sua negação.

PyCryptodome e coincurve reconstruíram os materiais, todas as decisões AES
e corpos, o conjunto de escalares e todas as comparações de pontos. O
programa principal validou a decifração conhecida da fase 3.2 como controle.

## Limites e reprodução

Não se excluem outras bijeções letra/dígito, remoções opcionais de várias
letras, uma letra nula e outra independentemente zero/positiva, UTF-8 com
bytes acima de 127, transformações anteriores ou outras interpretações
dos campos. Caracteres de controle e padding isolado não são solução.

```powershell
node solver/optional_null_decimal.cjs
node solver/optional_null_decimal.cjs --with-zero
node solver/fixed_zero_optional_null.cjs
node solver/verify_optional_null_decimal.cjs
node solver/verify_optional_null_decimal.cjs --with-zero
node solver/verify_optional_null_decimal.cjs --fixed-zero
node solver/optional_null_decimal_oracles.cjs
```

Remoção: [especificação](spec.json), [controles](controls.json),
[resumo](summary.json), [verificação](verification.json).
Remoção/zero: [especificação](with_zero/spec.json),
[resumo](with_zero/summary.json), [verificação](with_zero/verification.json),
[candidatos](with_zero/candidates.json), [oráculos](with_zero/oracles.json),
[conferência criptográfica](with_zero/oracle_verification.json).
Zero fixo: [especificação](fixed_zero/spec.json),
[controles](fixed_zero/controls.json), [resumo](fixed_zero/summary.json),
[verificação](fixed_zero/verification.json).

Programas: [buscador](../../solver/optional_null_decimal.cjs),
[família de zero fixo](../../solver/fixed_zero_optional_null.cjs),
[verificador](../../solver/verify_optional_null_decimal.cjs),
[oráculos](../../solver/optional_null_decimal_oracles.cjs).

SHA256 do buscador:
`95a0026cf0052ef950fd95cf7486a4b0928ea89a77691773757eb85eedb84044`.
SHA256 do verificador:
`3c2eb641bf52955f2a839fcda99c295e10d17f242f6805348066a1bb7768ea3c`.
Os resumos identificam e registram os hashes de cada grafo compactado.
