# Operações da receita de X e suas fontes

Auditoria de 11/09/2026. O [script original](../endgame_review_2026-09-11/original_dbbi_sum_faed.py), mensagem #63518 de X, 22/05/2026, foi reproduzido anteriormente. Sua autoria é comunitária. As mensagens citadas abaixo estão em [primary_clues.json](../review_2026-09-11/primary_clues.json).

| Operação / parâmetro | Evidência disponível | O que continua inferido |
|---|---|---|
| Voltar à matriz inicial e usar cores | Criador #1710, 14/01/2020: relaciona números a amarelo/azul e manda voltar à primeira peça | Não especifica RGB, coordenadas, índices lineares ou a operação numérica |
| Usar primos e zerar caracteres | Criador #8000, 26/12/2021; #8330, 09/01/2023 | Não identifica posições, símbolos ou etapa da zeragem |
| Relacionar cores, primos, `matrixsumlist` e últimas palavras | Fluxo binário #8446, 23/02/2023, decodificação #8448 e endosso #8483 | O texto ordena os termos, mas não define uma fórmula de concatenação |
| Investigar `matrixsumlist` nas dicas anteriores | #6509 responde diretamente à pergunta #6508 sobre esse termo | A resposta diz que houve uma pista imprevista; não nomeia uma soma ou matriz |
| `a=1..i=9` | A codificação de outros segmentos da mesma página foi reproduzida dessa forma | Reutilizar o mapa em DBBI/FAED ainda é uma hipótese, embora motivada |
| Matriz simétrica 14×14, diagonal zero, DBBI no triângulo superior | `len(DBBI)=91=14×13/2`; a imagem inicial mede 14×14 células | Escolha do triângulo, simetria e ordem dos pesos vêm da receita de X |
| Chave de 14 somas dos pesos incidentes | Significado literal possível de `matrixsumlist` | Nenhuma fonte primária consultada manda somar os pesos de DBBI dessa maneira |
| FAED em 38 linhas de 15 símbolos | `570=38×15`; existem 15 células azuis | Dimensão compatível, mas orientação e o uso de 15 não estão definidos pelo criador |
| Contagem linear por linhas iniciada em 1 | Permite reproduzir as posições usadas no script | Outras contagens existem; a escolha aqui está fixada pelo script, não por uma regra geral comprovada |
| Posições azuis reduzidas módulo 38 | Produzem 14 linhas distintas de FAED | O módulo e o uso dessas linhas como máscara são escolhas de X |
| Posições amarelas reduzidas módulo 15 | Produzem quatro colunas: `2,6,13,14` | O módulo e a projeção entre as duas matrizes são escolhas de X |
| Primos entre os índices azuis e redução módulo 9 | `17,47,163,193 → 8,2,1,4` pela redução de X | Aritmética exata, sem prova de que esses sejam os primos e a redução pretendidos |
| Zerar FAED quando linha, coluna e valor passam pelas três condições | Zera 26 posições no original | O cruzamento das condições não aparece como instrução explícita nas fontes consultadas |
| Zerar arestas de DBBI nas coordenadas amarelas | Retira nove pesos da matriz simétrica | Interpretar coordenadas coloridas como pares de vértices é outra escolha da receita |
| XOR entre soma de FAED e chave repetida a cada 14 linhas | Reproduz as três saídas publicadas | Não foi encontrada uma instrução primária específica para XOR ou repetição da chave |
| Resto módulo 26, depois `A=0` | Produz os fragmentos `SENDTHE`, `BLUE`, `TOSETHEX` | O alfabeto e o módulo fazem parte do procedimento comunitário; os fragmentos não validam o restante |
| Ignorar os bits das células não coloridas | O script só consulta as posições `b/y` da matriz inicial | Isso descreve o código; não prova que esses bits sejam irrelevantes ao puzzle completo |
| ASCII 127 | Criador #32613, 29/11/2024, recuperado com resposta e contexto | Não especifica remoção, máscara `g→0/7` ou base numérica; ver [investigação anterior](../shared_numeric_2026-09-11/RELATORIO.md) |

As identidades dimensionais e os três fragmentos justificam investigar a receita, mas não eliminam suas escolhas livres. A auditoria não fornece uma probabilidade de intenção. Os controles de embaralhamento antigos condicionam o algoritmo e as palavras já selecionadas; não corrigem toda a seleção de hipóteses anterior à publicação.

Após os controles e testes desta rodada, nenhuma dessas escolhas ganhou uma validação criptográfica independente. A decisão é preservar a receita como hipótese, reduzir a prioridade de novas variações de seus alfabetos e buscar uma fonte que determine a operação ainda ausente.
