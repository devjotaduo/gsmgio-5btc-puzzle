# Somas das cores como chave decimal: todos os pesos inteiros

16/09/2026. **Nenhuma senha final ou chave do prêmio recuperada.** Esta
rodada cobre todos os pesos inteiros fixos de azul e amarelo numa operação
específica: somas de linhas/colunas, usadas como chave aditiva periódica
dígito a dígito, antes da conversão do número decimal inteiro em bytes.

FAED não tem nenhuma saída de sete bits nesse modelo. DBBI tem 39 saídas,
todas com controles além de TAB/LF/CR. Elas foram conferidas e submetidas
aos blobs originais e à chave pública-alvo, sem resultado autenticado.

## Motivação e redução finita

As fontes primárias locais dão três motivos para examinar essa composição:
`matrixsumlist` na página, a associação de números a azul/amarelo na
mensagem #1710 do criador, de 14/01/2020, e a confirmação de primos e
zeragem na #8000, de 26/12/2021. Elas **não estabelecem a operação de
adição decimal**. Os trechos estão em
[primary_clues.json](../review_2026-09-11/primary_clues.json).

Os testes de chaves decimais anteriores usavam conjuntos finitos de listas
e pesos particulares, incluindo códigos de cores e primos selecionados.
Aqui, não é necessário escolher um teto para os números das cores.

Uma soma de linha ou coluna tem a forma

```text
S_i = B_i × p + Y_i × q + K_i × b + W_i × w
```

`B_i`, `Y_i`, `K_i` e `W_i` contam células azuis, amarelas, pretas e brancas.
Os números `p` e `q` são fixos por cor. Os valores de preto e branco,
`b` e `w`, pertencem independentemente a `{0,1}`. Isso considera os bits
originais, invertidos, todos zero ou todos um, nas células sem cor.

Se a soma é usada módulo 10, apenas `p mod 10` e `q mod 10` importam.
Portanto, os **100 pares de restos de 0 a 9** cobrem todos os pares de
inteiros, inclusive primos de qualquer tamanho e valores negativos.
Não se está afirmando que números compostos sejam primos: testa-se um
conjunto maior que inclui todos os possíveis pesos primos.

Essa redução vale para **essa operação modular**, não para concatenar as
representações decimais das somas completas, calcular seu SHA256 ou usar
as somas como outros tipos de chave.

## Modelo completo

Usa-se a matriz original 14×14, com 101 bits um e as posições de cores
conferidas. Para cada combinação de quatro fundos e cem pares de restos:

1. Calcular as 14 somas de linhas ou as 14 somas de colunas.
2. Reduzir cada soma módulo 10, considerar ambas as direções da lista e
   todos os 14 alinhamentos cíclicos.
3. Repetir essa lista ao longo de todo DBBI ou FAED.
4. Aplicar `P = C + K`, `P = C - K` ou `P = K - C`, dígito a dígito,
   sempre módulo 10. Não há transporte entre casas decimais.
5. Usar `a=1..i=9` em `C`, permitindo que qualquer **uma** das nove letras
   também represente zero, independentemente por ocorrência.
6. Examinar o campo inteiro original e invertido. Interpretar `P` como
   um único número decimal e exigir que todos os bytes mínimos estejam
   abaixo de 128. Nenhuma posição é descartada.

As operações iguais são reunidas na forma `P_i = s × C_i + t_i (mod 10)`,
com `s` igual a 1 ou −1 e `t` de comprimento 14. Essa deduplicação preserva
todos os resultados possíveis da família declarada.

## Resultados completos

| Medida | Total |
|---|---:|
| Construções de chave | 22.400 |
| Chaves distintas | 22.038 |
| Operadores distintos após reunir equivalências | 60.695 |
| Operador × campo × sentido | 242.780 |
| Casos incluindo as nove letras zeráveis | 2.185.020 |
| Casos completos | 2.185.020 |
| Nós de busca | 6.888.788 |
| Certificados de exclusão | 4.536.865 |
| Saídas de sete bits de FAED | 0 |
| Saídas de sete bits de DBBI | 39 |
| Casos interrompidos | 0 |

As 39 saídas são bytes distintos: 18 na ordem original de DBBI e 21 na
inversa, sempre permitindo `b=0/2`. Nenhuma consiste somente em ASCII
imprimível e TAB/LF/CR. A melhor fração imprimível, 94,74%, ainda corresponde
a uma sequência de símbolos desconexos com controles; não é uma mensagem.

A condição de sete bits não muda com a inversão da ordem dos bytes.
Por isso, as 39 saídas foram consideradas nas duas ordens para os testes
seguintes, dando **78 materiais distintos**.

## Verificação e oráculos

O verificador independente reconstruiu matrizes numéricas explícitas,
todas as listas e todos os operadores. O buscador usa coeficientes de
contagens; o verificador soma as células da matriz. Os dois concordam
sobre a família completa.

Para cada caso, o verificador regenerou os domínios de dígitos, contou os
inteiros de sete bits em cada intervalo excluído e conferiu que os prefixos
de máscara não se sobrepõem e cobrem todas as atribuições. Também refez
cada um dos 39 candidatos. **Todos os 2.185.020 casos e 4.536.865
certificados foram conferidos, sem divergência.**

Controles: 90 comparações do buscador otimizado com o algoritmo anterior,
54 recuperações de mensagens plantadas, enumeração independente de
65.536 inteiros pequenos e contagens em 300 larguras maiores.

Cada material foi usado diretamente e como SHA256 hexadecimal nos blobs
SMALL, TAIL32 e COSMIC, com EVP-SHA256 e EVP-MD5:

- **156 senhas distintas, 936 decisões AES**.
- Dois paddings aceitos: COSMIC/MD5 e TAIL32/SHA256. Seus corpos completos
  têm, respectivamente, 37,23% e 46,84% de bytes imprimíveis ou whitespace.
  Não foi identificada estrutura que autentique essas aberturas.
- **356 escalares distintos válidos**, provenientes dos SHA256 dos
  materiais e de todas as janelas contíguas de 32 bytes, foram confrontados
  com a chave pública do prêmio e sua negação: zero correspondências.

Uma segunda implementação com PyCryptodome 3.23.0 e coincurve 21.0.0
conferiu **todas as decisões AES**, inclusive rejeições, os dois corpos
com padding e todos os pontos da curva. A fase 3.2 conhecida e o gerador
secp256k1 serviram como controles positivos. A chave pública-alvo foi
convertida independentemente para `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`.

O padding isolado não demonstra uma senha correta. Da mesma forma, a
ausência de texto de sete bits não exclui um intermediário binário ou
uma representação diferente.

## Alcance e reprodução

O resultado elimina a leitura de FAED como texto de sete bits nesta
família, independentemente dos pesos inteiros fixos escolhidos para azul
e amarelo. Não identifica o papel pretendido de `matrixsumlist`.

Continuam fora do alcance pesos diferentes por célula, outros pesos de
preto/branco, alfabetos diferentes de `a=1..i=9`, mais de uma letra
zerável, concatenação das somas completas, transporte decimal, operações
não aditivas, outras rotas e representações finais diferentes.

```powershell
node solver/color_residue_decimal.cjs
node solver/verify_color_residue_decimal.cjs
```

Artefatos: [especificação](spec.json), [operadores](operators.json.gz),
[casos e certificados](cases.jsonl.gz), [resumo](summary.json),
[39 candidatos](candidates.json), [testes AES e escalares](oracles.json),
[verificação estrutural](verification.json),
[verificação com bibliotecas independentes](oracle_verification.json).

Programas: [buscador](../../solver/color_residue_decimal.cjs) e
[verificador](../../solver/verify_color_residue_decimal.cjs).
