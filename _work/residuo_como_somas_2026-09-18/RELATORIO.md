# O resíduo *como* a lista das 28 somas, e os acertos isolados da PR #6

**Estado: ambos negativos.** Resultado de uma continuação independente. Este relatório separa
explicitamente **o que o coordenador reproduziu** do **que foi aceito do relato** — os scripts dessa
continuação não estão neste repositório.

## 1. Inverter o papel do rótulo

A hipótese é boa porque muda a função de `matrixsumlist` em vez de variar a operação:

> em vez de `matrixsumlist` ser a operação que decifra o resíduo, **o resíduo seria o objeto que o
> rótulo nomeia** — a lista das 14 somas de linha e 14 de coluna da matriz.

Ou seja: tirar os marcadores primos de `dbbi` produziria diretamente a representação das 28 somas.

**A abertura é real e estava declarada.** O relatório `symbolic_color_sums_2026-09-16` fechou o modelo
de 14 valores e registrou nos limites, textualmente: *"Continuam fora do modelo: … combinar linhas e
colunas em uma lista de 28 valores, outras bases…"*. Ninguém tinha voltado nisso.

### Por que o espaço de pesos é finito (reproduzido pelo coordenador)

O ponto forte do teste é que os limites dos pesos **saem dos dados**, não de uma escolha. Conferi a
contagem na matriz do kit (`G.COLORED`, 15 azuis + 9 amarelas + 1 `#FEFEFE`):

| | somas de 28 que contêm a cor | linhas | colunas |
|---|---|---|---|
| azul | **22** | 12 | 10 |
| amarelo | **15** | 8 | 7 |

Daí o argumento de contagem de dígitos, que confirmei:

- peso azul de 3 dígitos ⇒ no mínimo `22×3 + 6 = 72` dígitos;
- peso amarelo de 4 dígitos ⇒ no mínimo `15×4 + 13 = 73` dígitos.

O resíduo tem 60 (L83) ou 61 (L84) símbolos. Logo **azul ≤ 99 e amarelo ≤ 999** são limites forçados,
e o espaço fica finito por construção — incluindo todos os pares de primos possíveis.

### Cobertura declarada (aceita do relato)

Resíduos L83 e L84, nos dois sentidos; `a=1…i=9` com **todas as 512** escolhas globais de letras
zeráveis (o modelo de 16/09 cobria só até duas); preto e branco em {0,1}; a célula quase branca testada
à parte como 0, 1, peso do azul ou peso do amarelo; 16 ordens naturais (linhas antes/depois das colunas,
inversões dos dois eixos, concatenação e intercalação).

**Resultado: 0.** 524.288 combinações pelo método que resolve os sistemas lineares, e 1.564.864
combinações de pesos e perfis pelo segundo método, que soma as células diretamente. 64 controles
positivos no primeiro, 32 no segundo.

**Alcance:** descarta essa **concatenação decimal direta** nas formas declaradas. Não descarta outras
bases, correspondência arbitrária letra→dígito, permutações quaisquer das 28 somas, nem as somas
participando de outra transformação.

## 2. Os acertos isolados da PR #6 (reproduzido pelo coordenador)

A correção de `ef55ccf` já havia feito os dois scripts registrarem acerto isolado, e a reexecução deu
`hits_isolados: []`. Esta continuação chegou ao mesmo ponto por reimplementação independente, e eu
reproduzi o núcleo:

```
caminhos = 144   escalares distintos = 136
escalares que batem isoladamente com algum alvo: []
```

Confere com o relato (144 caminhos, 136 escalares distintos, nenhum acerto individual).

### O que a continuação acrescenta além da correção

Fecha o limite que eu havia **declarado** e não coberto — "não testa abertura AES das saídas":

| Teste | Cobertura | Resultado |
|---|---|---|
| Intermediários como senha de SMALL/TAIL32/COSMIC | 1.496 senhas, 8.976 decifrações | 0 candidatos |
| Todas as saídas AES como chave binária, inclusive com padding inválido | 8.347.680 janelas de 32 B | 0 |
| Intermediários e representações diretas como chave | 61.086 verificações | 0 |

Com as duas ordens de byte, pubkey comprimida e não comprimida, os dois alvos, e sem descartar saída
por "não parecer texto". As 8.976 decifrações foram reproduzidas pelo EVP nativo do OpenSSL (chave, IV
e bytes completos coincidentes, inclusive com senha binária); duas chaves plantadas em posições não
iniciais foram recuperadas, uma em cada ordem de byte. Os 35 paddings válidos estão na expectativa
(35,2) — não são avanço.

*(As três linhas da tabela e a reprodução por OpenSSL vêm do relato; não foram reexecutadas aqui.)*

## O que isto decide e o que não decide

**Decide:** a leitura literal de `matrixsumlist` como concatenação decimal das 28 somas está fechada
nas formas declaradas, com o espaço de pesos limitado pelos próprios dados. E a possibilidade de um
acerto isolado ter passado despercebido na PR #6 está examinada para as saídas reproduzidas — não
havia acerto nelas.

**Não decide:** nada sobre L83 versus L84, nada sobre qual é a transformação pretendida, e **não
autoriza** concluir que seja necessária informação pessoal externa.
