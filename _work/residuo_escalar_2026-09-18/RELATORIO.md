# O resíduo como escalar direto, em bases 2–19

**Estado: negativo.** Nenhuma chave validada. Resultado de uma continuação independente; o que o
coordenador verificou está marcado como tal.

## A hipótese e como ela difere do histórico

O resíduo, lido como **inteiro posicional**, seria o próprio escalar da chave de `1GSMG…`. Isso é
diferente do que `source_prime_radix_2026-09-16` fechou: aquele relatório exigia que todos os bytes da
conversão caíssem em 0–127 (hipótese **textual**) e, por isso, nunca chegou a acionar comparação de
chave privada. Seu negativo é sobre linguagem, não sobre chave.

Também é objeto distinto do MITM histórico sobre os 64 tokens `b`/`g` de `dbbi` (§4-B): ali o material
é `dbbi` inteiro sob bijeções 16!, aqui são os resíduos L83/L84.

## Modelo

Para cada base `b` de 2 a 19: resíduo L83 (60) ou L84 (61), em ordem original ou com os símbolos
invertidos; cada letra `a…i` recebe um dígito de `0…b−1`, **constante em todas as ocorrências**;
**colisões permitidas** (duas letras podendo receber o mesmo dígito) e zeros à esquerda livres — o que
torna o espaço mais amplo que uma substituição bijetiva. Lê-se como inteiro posicional, reduz-se
mod `n` e aceita-se **apenas igualdade exata** de ponto: `kG = P` ou `kG = −P`.

São **72 configurações** (18 bases × 2 resíduos × 2 sentidos).

## A álgebra que torna isso viável — verificada pelo coordenador

O que evita testar trilhões de escalares um a um é a decomposição por pesos posicionais. Para cada
símbolo `c`, com `L` o comprimento:

```
W[c] = Σ b^(L−1−i)  sobre as posições i onde s[i] = c     (mod n)
k    = Σ d[c] · W[c]                                       (mod n)
```

e portanto `kG = Σ d[c] · (W[c]·G)`, o que permite separar os nove símbolos em dois grupos e casar
pontos (encontro no meio). Assim `b⁹` atribuições custam `b⁴ + 2·b⁵` pontos.

**Conferi essa identidade**: `k = Σ d[c]·W[c] mod n` bate com Horner puro em **5000/5000** casos
aleatórios, nas bases 2–19 e nos quatro resíduos.

*(Meu primeiro teste deu 1071/2000 por bug meu: para base > 10 eu montava a string com `str(d[c])`, e um
dígito 12 vira dois caracteres. Refeito com Horner, que é inequívoco.)*

## Resultados (aceitos do relato)

| Medida | Principal | Verificador |
|---|---|---|
| Configurações concluídas | 72 | 72 |
| Pares configuração/atribuição cobertos | 3.148.621.119.756 | mesmo conjunto |
| Pontos do lado esquerdo gerados | 2.250.660 | 36.533.196 |
| Pontos consultados (dois sinais) | 73.066.392 | 4.501.320 |
| Conferências por multiplicação escalar | 9.552 | 5.148 |
| **Correspondências** | **0** | **0** |

Duas implementações em C com construção e busca diferentes (incrementos com transporte e tabela hash
contra Horner com vetor ordenado e busca binária); ambas usam OpenSSL para a aritmética, então a
independência está na estrutura, não na biblioteca. **Controles:** 22 positivos em cada programa,
incluindo dígitos repetidos, zeros à esquerda, os dois sinais e inteiros maiores que `n` (que exercitam
a redução modular); mais 80.780 atribuições enumeradas literalmente em oito instâncias pequenas, com
comparação do **conjunto completo** de soluções, e duas instâncias com alvo fora do conjunto admissível,
corretamente rejeitadas.

A contagem de 3,1 trilhões é **cobertura combinatória**, não número de multiplicações escalares nem de
chaves distintas — há colisões e sobreposição entre bases e variantes. O relato declara isso.

## Por que só `1GSMG…` — ressalva correta, conferida aqui

O método exige o **ponto público completo** do alvo. `1GSMG…` já gastou, então sua pubkey está
publicada e consta do kit. **`17ucy…` nunca gastou**, logo sua pubkey é desconhecida e o encontro no
meio simplesmente não se aplica a ele. Conferi: a ressalva do relato é correta e não é uma omissão de
escopo.

## Alcance

**Exclui:** o resíduo ser *diretamente* o escalar de `1GSMG…`, em qualquer base de 2 a 19, sob qualquer
atribuição global de dígitos (com colisões) e nos dois sinais.

**Não exclui:** bases acima de 19 (a faixa 2–19 é escopo escolhido, não deduzido das pistas); dígitos
variáveis por ocorrência; SHA256 ou outra derivação a partir do resíduo; uso como chave AES, semente ou
material de outra camada; `matrixsumlist` como operador; permutações de posições, recortes ou inversão
de **bytes** (inverter símbolos não é inverter bytes); e o alvo `17ucy…`.

Também **não decide L83 versus L84** — mas esse ponto foi resolvido por outro caminho, em
[`DISCRIMINANTE.md`](../l83_cosmic_2026-09-18/DISCRIMINANTE.md).
