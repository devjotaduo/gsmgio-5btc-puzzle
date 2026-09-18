# A coincidência 83 = L83 = blocos do COSMIC, testada

**Estado: sem sinal.** A correspondência numérica não tem lastro detectável no ciphertext, e portanto
**não serve como discriminante** entre L83 e L84. Junto, uma verificação independente do único fato
estrutural do puzzle.

## Por que valia testar

O `ENDGAME.md` registra dois números lado a lado sem nunca ligar um ao outro:

- o COSMIC tem **83 blocos AES** (1328 B);
- uma das duas segmentações de `dbbi` tem **83 tokens**.

Isso importa porque o gargalo declarado da §6 é exatamente **qual segmentação é a pretendida**. Se a
correspondência fosse real, L83 teria um campo de 83 unidades a que corresponder e L84 não teria campo
de 84 — seria o discriminante que falta.

## Subproduto: a segmentação reconstruída do zero e validada

Reimplementei a regra da §6 (posição lógica prima consome `b` ou `be`, as demais um símbolo, consumo
integral dos 91 símbolos) sem olhar o resultado publicado. Saem **exatamente duas** segmentações:

| | tokens | marcadores | `b` | `be` | resíduo | bits dos tipos |
|---|---|---|---|---|---|---|
| **L83** | 83 | 23 | 15 | 8 | 60 | `00001000110000100110011` |
| **L84** | 84 | 23 | 16 | 7 | 61 | `00001000110000100110010` |

O resíduo de L84 confere **byte a byte** com o publicado na §6, e os bits diferem apenas no último —
como o ENDGAME descreve ("em L83 o `e` final vira o 23.º `be` e o último bit vira 1"). O fato
estrutural do puzzle está verificado por implementação independente.

**Armadilha encontrada no caminho:** a primeira versão contou 25 marcadores em vez de 23, porque tratou
todo token `b` como marcador. Marcador se define pela **posição prima**, não pelo conteúdo — e o resíduo
contém símbolos `b` legítimos em posições não primas. Corrigido antes de qualquer conclusão.

## O teste

Só L83 admite a correspondência (83 tokens ↔ 83 blocos). Se o autor construiu o COSMIC com essa
estrutura, os 23 blocos em posições **primas** deveriam diferir dos outros 60.

| estatística | diferença observada | p bicaudal |
|---|---|---|
| média dos bytes | −2,079 | 0,631 |
| variância | +211,94 | 0,485 |
| bits por byte | +0,024 | 0,829 |
| entropia | −0,393 | 0,433 |

**Nulo casado:** 20.000 partições aleatórias de 23 dos 83 blocos. Menor p = **0,433**; com Bonferroni
para as quatro estatísticas, **1,0**.

## Conclusão

Sem sinal. Isso era o esperado — um ciphertext AES é indistinguível de aleatório por construção —, mas o
resultado é informativo em dois sentidos:

1. a coincidência 83 = 83 **cai de "pista" para "número"**: não há evidência de que o autor tenha
   construído o COSMIC com a estrutura de L83;
2. portanto ela **não discrimina** L83 de L84, e o gargalo da §6 continua exatamente onde estava.

Vale registrar o limite do teste: ele só detectaria estrutura no **ciphertext**. Se os marcadores
dizem algo sobre os blocos que só faz sentido **depois** de decifrar, nenhum teste estatístico sobre o
CT poderia vê-lo. Esta é uma refutação de lastro observável, não da correspondência em si.
