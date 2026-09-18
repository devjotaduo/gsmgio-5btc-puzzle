---
name: related-problem-ladder
description: "Constrói e resolve um problema relacionado, menor ou controlável, para testar o mecanismo de uma hipótese antes da campanha principal, sem transferir conclusões além do demonstrado. Use em pesquisa aberta; não use para substituir a verificação do alvo real."
---

# Escada de problemas relacionados

Use quando o problema principal for caro ou ambíguo e a hipótese envolver um mecanismo difícil de
observar diretamente (cifra, construção combinatória, recorrência, regra de seleção), mas uma versão
menor conservar uma propriedade decisiva: codificação, simetria, limite, invariante, oráculo ou modo de
falha. O problema-ponte ensina sobre o mecanismo; não transforma analogia em solução nem declara o alvo.

## Definição da ponte

Escreva antes de executar:

1. problema principal e pergunta aberta;
2. problema relacionado, estritamente mais simples, com entradas e saídas completas (um caso
   positivo conhecido ou uma instância sintética controlada);
3. propriedade/mecanismo preservado, sua relevância e o que foi deliberadamente removido;
4. diferenças que bloqueiam transferência automática;
5. a previsão que diferencia a hipótese de alternativas e o experimento, prova ou contraexemplo
   que decide a ponte, com o critério que permite transportar a conclusão ao problema real.

Use uma escada curta — controle conhecido, problema relacionado, problema-alvo — com critério
independente de sucesso por degrau. Evite degraus decorativos: se a versão reduzida não pode eliminar
uma hipótese, calibrar um parâmetro ou revelar um invariante útil, ela não justifica trabalho.

## Execução

Resolva ou caracterize primeiro o degrau simples, com controles positivos e nulos casados quando
houver estatística; documente cobertura, parâmetros e sementes. Busque a regularidade e a construção
que a quebre. Compare a previsão com o resultado antes de aumentar o espaço de busca. Registre
explicitamente quais conclusões não podem ser transferidas: simplificações podem introduzir
simetrias falsas.

No GSMG, mantenha o oráculo duro do prêmio separado do oráculo do problema-ponte: um teste em
`dbbi`, uma fase anterior ou uma construção sintética pode validar a operação, mas não é uma
abertura AES nem uma privkey do prêmio.

## Conclusão e saída

Classifique o resultado como **transferível** (mecanismo demonstrado igual), **orientador**
(prioriza a hipótese sem decidir o alvo) ou **não transferível** (uma diferença bloqueia a
inferência). Nunca apresente resultado orientador como prova do problema principal.

Entregue uma recomendação curta — promover a hipótese a uma campanha finita, alterá-la com base
em evidência ou encerrá-la — com a definição executável dos problemas, a tabela de preservações
e diferenças, entradas, transformações, contagens, controles, cobertura, resultado, classificação
e a razão exata da decisão. Encaminhe alegações finais para proof-certificate.
