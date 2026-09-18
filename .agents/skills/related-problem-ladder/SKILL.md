---
name: related-problem-ladder
description: "Constrói e resolve um problema relacionado, menor ou controlável, para testar o mecanismo de uma hipótese antes da campanha principal. Use em pesquisa aberta; não use para substituir a verificação do alvo real."
---

# escada de problemas relacionados

Use quando a hipótese envolve um mecanismo difícil de observar diretamente — por
exemplo, uma cifra, uma construção combinatória, uma recorrência ou uma regra de
seleção. O problema-ponte serve para aprender sobre o mecanismo, não para
declarar o resultado do alvo original.

## Escolha do degrau

Defina um problema estritamente mais simples que preserve a propriedade cuja
importância está sendo testada. Declare:

- qual mecanismo é preservado e o que foi deliberadamente removido;
- um caso positivo conhecido ou uma instância sintética controlada;
- a previsão que diferencia a hipótese de alternativas;
- o critério que permite transportar uma conclusão de volta ao problema real.

Evite degraus decorativos. Se a versão reduzida não pode eliminar uma hipótese,
calibrar um parâmetro ou revelar um invariante útil, ela não justifica trabalho.

## Execução

Resolva ou caracterize primeiro o degrau simples, com controles positivos e
nulos casados quando houver estatística. Compare a previsão com o resultado
antes de aumentar o espaço de busca. Registre explicitamente quais conclusões
não podem ser transferidas, pois simplificações podem introduzir simetrias falsas.

No GSMG, mantenha o oráculo duro do prêmio separado do oráculo do problema-ponte:
um teste em DBBI, uma fase anterior ou uma construção sintética pode validar a
operação, mas não é uma abertura AES nem uma privkey do prêmio.

## Saída

Entregue uma recomendação curta: promover a hipótese a uma campanha finita,
alterá-la com base em evidência ou encerrá-la. Inclua entradas, transformações,
contagens, controles e a razão exata da decisão.
