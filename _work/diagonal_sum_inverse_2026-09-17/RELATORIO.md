# Somas diagonais: inversão aritmética com alfabeto desconhecido

17/09/2026. **A senha final continua desconhecida.** Os 128 modelos
de somas diagonais definidos abaixo foram excluídos. Uma segunda
implementação reproduziu a enumeração e demonstrou a incompatibilidade
usando apenas os dois últimos dígitos das somas.

## Pergunta examinada

O campo binário da página original decodifica literalmente `matrixsumlist`.
Isso sugere uma operação com somas, mas não determina quais linhas somar
nem prova que DBBI seja uma lista. Esta rodada testa uma interpretação
específica que complementa os testes anteriores de linhas, colunas e anéis:
DBBI ou FAED seria a concatenação decimal das somas das diagonais da matriz
inicial, depois de substituir dígitos por letras e ocultar alguns zeros.

A construção parte da matriz e dos campos originais preservados nas
[entradas canônicas](../prime_geometry_2026-09-11/inputs.json).
Nenhuma palavra extraída por uma receita da comunidade é usada como alvo,
chave ou critério de sucesso.

## Modelo

- Diagonais comuns: `r-c+13` e `r+c`, com 27 somas cada.
- Diagonais que continuam na borda oposta: `(r-c+14)%14` e `(r+c)%14`,
  com 14 somas cada. Coordenadas começam em zero.
- Cada célula azul tem peso inteiro `p>=2`; cada amarela, `q>=2`.
  As células não coloridas de cada classe binária têm peso 0 ou 1,
  escolhido independentemente.
- Cada soma usa sua representação decimal mínima, incluindo `0` quando
  necessário. As representações são concatenadas sem separador.
- O mapa dos nove dígitos não nulos para `a..i` é uma bijeção desconhecida.
  Ocorrências de até duas letras também podem representar zero;
  essa escolha é independente por ocorrência.
- São examinados DBBI e FAED completos, ambos os sentidos dos campos
  e ambos os sentidos da lista de diagonais.

São `4 × 4 × 2 × 2 × 2 = 128` configurações. A bijeção e as letras
zeráveis são resolvidas conjuntamente, sem escolher um alfabeto por
legibilidade. Não há teto arbitrário para os pesos. Permitir todos os
inteiros inclui, como subconjunto, qualquer escolha de dois primos.

## Como a inversão evita uma busca cega

Cada soma tem a forma `a*p+b*q+c`. Ao escrever `p=x+2` e `q=y+2`,
com `x,y>=0`, comparações entre os três coeficientes limitam as diferenças
de comprimento decimal. Por exemplo, se uma forma é sempre menor ou igual
a dez vezes outra, seu comprimento não pode exceder o da outra em mais
de um dígito. O comprimento total precisa ser exatamente 91 ou 570.

Diagonais sem células coloridas fornecem valores constantes. Seus dígitos
fixam partes da mesma bijeção e limitam quais letras podem esconder zeros.
Depois dessas condições, restam **542 partições** dos campos.

O produtor resolve as colunas decimais simultaneamente, incluindo os
transportes entre colunas. Nenhuma partição aceita valores inteiros de
`p` e `q`. Todos os 128 casos terminaram sem atingir o limite de nós.

O verificador reconstrói a geometria e enumera comprimentos por classes
de expressões iguais, com propagação de intervalos e do comprimento total.
Ele não importa o produtor nem usa seu algoritmo de transportes.
Recupera as mesmas 542 partições. Entre elas, há **42 pares de resíduos
compatíveis módulo 10** e **nenhum módulo 100**. Uma solução inteira teria
de satisfazer essas congruências; portanto, não existe neste modelo.

## Controles e artefatos

Os dois programas recuperaram os 48 casos plantados, usando os 16 perfis
e três pares de pesos: `(2,3)`, `(47,113)` e `(1000003,1000033)`.
Há controles para interrupção por limite de nós e para consistência da
bijeção e dos aliases de zero. Uma revisão independente não encontrou
erro de correção no modelo declarado nem problema de segurança nos
scripts locais.

- [Especificação final](final/spec.json), [controles](final/controls.json)
  e [resumo](final/summary.json).
- [128 casos completos](final/cases.jsonl).
- [Conferência independente](final/independent_verification.json).
- [Produtor](../../solver/diagonal_sum_inverse.cjs),
  [geometria e triagem](../../solver/diagonal_sum_constraints.cjs) e
  [verificador](../../solver/verify_diagonal_sum_inverse.cjs).

SHA256 de `final/cases.jsonl`:
`8b7bd42019fe28db4f09ff34d098eb2735d3dfe7fd2a56f045e9209cd5bbf49d`.

Uma triagem anterior, baseada apenas em comprimentos e igualdade de
substrings, teve casos compatíveis e casos interrompidos. Ela permanece
local como histórico e **não é a base deste negativo**. A execução em
`final/` usa o inversor aritmético e foi completamente conferida.

## Reprodução e limites

Na raiz do repositório, com Node.js e uma pasta de saída ainda inexistente:

```powershell
node solver/diagonal_sum_inverse.cjs _work/diagonal_reproduction
node solver/verify_diagonal_sum_inverse.cjs _work/diagonal_reproduction
```

Como nenhuma lista numérica é compatível, esta rodada não gera candidatos
para AES. Não exclui permutações arbitrárias das diagonais, outras origens
cíclicas, pesos diferentes por célula, um peso próprio para o pixel quase
branco, separadores, zeros à esquerda ou uma transformação posterior das
somas. Também não prova que `matrixsumlist` descreva DBBI ou FAED.
O significado operacional dessa pista e a senha final continuam abertos.
