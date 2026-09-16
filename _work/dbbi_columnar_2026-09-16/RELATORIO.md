# DBBI como chave de transposição de FAED

16/09/2026. **Nenhuma senha final encontrada.** Foram examinadas 250.400
permutações de FAED que não constavam do teste colunar anterior. Nenhuma
permitiu a conversão do número decimal completo em bytes de sete bits,
mesmo liberando a escolha de zero por ocorrência para uma letra de FAED.

## Hipótese e diferença em relação às buscas anteriores

A palavra decodificada `matrixsumlist` e as dimensões `91 = 7×13 = C(14,2)`
motivam usar DBBI como uma lista ou como valores de uma matriz. Nesta
experiência, a lista determina a ordem das colunas de uma transposição.
Depois dessa operação, aplica-se a conversão de número inteiro usada nos
trechos conhecidos `lastwordsbeforearchichoice` e `thispassword`.

O teste anterior de transposição seguido de decimal→bytes usava listas
da matriz inicial e palavras literais. Já `dbbi_geometry.py` usava listas
de DBBI com outras decodificações, como Bifid e checkerboard. Nenhuma
dessas observações confirma que a nova composição seja a cifra pretendida.

## Família declarada antes da execução

DBBI mantém sua ordem original e o mapa `a=1..i=9`. Cada uma de suas dez
ocorrências de `g` pode valer 0 ou 7, independentemente: **1.024 máscaras**.
Não há pista confirmada que escolha `g` em DBBI; essa é uma limitação
explícita da experiência, não uma conclusão sobre o mapeamento correto.

Para cada máscara, são obtidas oito listas:

- A própria sequência de 91 valores.
- Somas das linhas e colunas das grades 13×7 e 7×13, preenchidas por linhas.
- Somas de linhas e colunas do triângulo superior estrito 14×14, preenchido
  por linhas, com diagonal e triângulo inferior iguais a zero.
- Somas por vértice da versão simétrica desse triângulo.

Cada lista é considerada também na ordem inversa. Os seus elementos
continuam inteiros: não são concatenados para gerar outra chave decimal.
As **16.384 construções** se reduzem a **5.694 padrões distintos de ordem
e igualdade**. Substituir valores por seus postos preserva exatamente a
ordenação das colunas e todos os empates.

Em FAED, são examinadas a transposição colunar incompleta, com empates
pela esquerda ou direita, e Myszkowski. Incluem-se ordenação crescente ou
decrescente, operação direta ou inversa e reversões independentes da
entrada e saída. Nenhum símbolo é descartado e nenhum padding é inserido.

Para cada permutação, cada uma das nove letras de FAED é escolhida, por
vez, como representante adicional de zero. Todas as escolhas por
ocorrência dessa letra são consideradas. As demais letras conservam seus
valores de 1 a 9. O número decimal resultante deve ter **todos** os seus
bytes mínimos em big-endian abaixo de 128. A condição inclui caracteres
de controle, sendo mais ampla que exigir texto inglês imprimível.

## Resultado

| Medida | Total |
|---|---:|
| Construções de chave | 16.384 |
| Padrões distintos de chave | 5.694 |
| Permutações propostas, com repetições | 273.312 |
| Permutações distintas | 250.400 |
| Sobreposição com o teste colunar anterior de FAED | 0 |
| Casos permutação × letra zerável | 2.253.600 |
| Casos completos | 2.253.600 |
| Nós de busca | 6.710.826 |
| Certificados de exclusão | 4.482.213 |
| Candidatos de bytes de sete bits | 0 |
| Casos interrompidos | 0 |

Esses números contam modelos e certificados, **não senhas testadas**.
Como nenhum candidato passou pela condição necessária dos bytes, esta
rodada fez zero tentativas AES e zero testes de chave privada.

## Verificação

O buscador elimina um conjunto de máscaras quando o intervalo numérico
que as contém não alcança o próximo inteiro com bytes de sete bits.
O verificador usa outro mecanismo: conta exatamente os inteiros aceitos
até os dois extremos de cada intervalo e exige diferença zero.

Também confere que os prefixos de máscaras não se sobrepõem e cobrem
todas as atribuições possíveis. Isso inclui as `2^107` atribuições da
letra `g` em FAED para cada permutação, sem enumerá-las uma a uma.

As listas são reconstruídas por matrizes explícitas e por uma fórmula de
índice triangular, independentemente das somas incrementais do buscador.
As permutações são regeneradas ordenando posições da grade, e o conjunto
completo é comparado com o registro da busca. O programa não importa os
helpers de cifra nem o teste ASCII do buscador.

Controles do buscador: exemplos conhecidos das duas cifras, 72 inversões
e 54 recuperações de mensagens plantadas. O verificador confronta seu
contador com 65.536 inteiros pequenos e 300 larguras maiores, além dos
exemplos de transposição. O resultado da conferência está em
[verification.json](verification.json).

**Conferência concluída:** todas as 250.400 permutações, os 2.253.600 casos
e os 4.482.213 certificados foram reproduzidos e conferidos, sem
divergências. A cobertura das máscaras é completa em todos os casos.

## Limites e reprodução

O resultado exclui somente esta composição com estas listas. Não exclui
outro alias de zero em DBBI, outro mapeamento de dígitos, outra disposição
da matriz, chaves arbitrárias, dupla transposição, transformações
aritméticas adicionais ou uma saída binária que não seja texto de sete
bits. Em particular, não demonstra que DBBI seja uma chave nem que a
próxima etapa deva começar com uma transposição.

```powershell
node solver/dbbi_columnar_decimal.cjs
node solver/verify_dbbi_columnar_decimal.cjs
```

O registro foi compactado sem alterar seus bytes. O verificador aceita
`models.jsonl` ou, na ausência dele, `models.jsonl.gz`. Uma reprodução da
busca cria novamente a versão descompactada.

Artefatos: [especificação e chaves](spec.json), [resumo](summary.json),
[registro comprimido](models.jsonl.gz), [integridade da compactação](archive.json),
[candidatos](candidates.json), [oráculos](oracles.json).

Programas: [buscador](../../solver/dbbi_columnar_decimal.cjs) e
[verificador independente](../../solver/verify_dbbi_columnar_decimal.cjs).
