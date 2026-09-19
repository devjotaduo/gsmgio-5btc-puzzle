# FINDINGS — ideação

## Hipótese ativa
A lacuna de fluxo/CBC sem padding binário pode esconder chave em janela interior raw32 que não passou pelo filtro textual dos scripts históricos.

## Cobertura desta frente
- Conferência da tabela de famílias refutadas em `ENDGAME.md` (foco em §4.D).
- Levantamento de sobreposição com `multiagente_2026-09-18` e `lacunas_2026-09-18`.

## Resultado atual
- A lacuna ainda está aberta por declaração explícita de limite em `multiagente_2026-09-18/RELATORIO.md`.
- Não há candidato novo nesta frente; saída é apenas gate para execução reproduzível.

## Próxima pergunta
Qual o menor subconjunto reproduzível que valida a remoção do filtro textual com controles completos e custo auditável?
