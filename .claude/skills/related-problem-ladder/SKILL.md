---
name: related-problem-ladder
description: Define e resolve um problema relacionado menor para orientar uma campanha, sem transferir conclusões além do demonstrado.
---

# Escada de problemas relacionados

Esta skill aplica o protocolo de `AGENTS.md` a um problema-ponte. Ela reduz incerteza sobre um mecanismo; não transforma analogia em solução.

## Quando usar

Use quando o problema principal for caro ou ambíguo, mas uma versão menor conservar uma propriedade decisiva: codificação, simetria, limite, invariante, oráculo ou modo de falha.

## Definição da ponte

Escreva antes de executar:

1. problema principal e pergunta aberta;
2. problema relacionado, com entradas e saídas completas;
3. propriedade preservada e relevância;
4. diferenças que bloqueiam transferência automática;
5. experimento, prova ou contraexemplo que decide a ponte.

Use uma escada curta: controle conhecido, problema relacionado, problema-alvo. Cada degrau precisa de critério independente de sucesso.

## Execução e conclusão

Rode controles positivos e nulos compatíveis com o degrau. Documente cobertura, parâmetros e sementes. Busque regularidade e construção que a quebre.

Classifique o resultado como **transferível** (mecanismo demonstrado igual), **orientador** (prioriza hipótese sem decidir o alvo) ou **não transferível** (uma diferença bloqueia a inferência). Nunca apresente resultado orientador como prova do problema principal.

Entregue a definição executável dos problemas, a tabela de preservações e diferenças, controles, cobertura, resultado e classificação. Encaminhe alegações finais para `proof-certificate`.
