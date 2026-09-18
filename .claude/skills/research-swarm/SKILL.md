---
name: research-swarm
description: Organiza pesquisa paralela com hipóteses falsificáveis, cobertura sem duplicação e síntese auditável.
---

# Pesquisa em enxame

Esta skill espelha o protocolo canônico de `AGENTS.md`, na seção **Modo de investigação em enxame**. Leia também as regras, os relatórios e a cobertura existente antes de iniciar uma campanha.

## Quando usar

Use quando a pergunta puder ser dividida em trilhas independentes, cada uma com hipótese, cobertura finita e resultado combinável. Não paralelize antes de definir pergunta, oráculo e cobertura.

## Contrato da campanha

Registre antes da execução:

1. pergunta exata e oráculo que decide um acerto;
2. hipótese e construção contrária a produzir ou refutar;
3. domínio, partição sem sobreposição e limite de cada trilha;
4. fontes, dados, ferramentas e limitações;
5. controle positivo, nulo casado e critério de encerramento;
6. artefatos obrigatórios por trilha.

Sem esse contrato, uma saída é pista, não conclusão.

## Organização

Distribua papéis complementares: sustentar a regularidade, procurar contraexemplo, verificar controles e reproduções, e resolver um problema relacionado que preserve o mecanismo relevante. Cada trilha tem responsável, arquivos próprios e uma faixa única do espaço de busca.

Registre cada achado em `FINDINGS.md` ou no relatório: hipótese, conjunto coberto, comando reprodutível, artefatos, resultado, limitação e próximo teste. Compartilhe evidência verificável, nunca só interpretação.

## Síntese e entrega

Compare os conjuntos exatos cobertos: declare concordâncias independentes, contradições e sua reprodução decisiva, lacunas e inferências que não passam pelo oráculo duro. Não some tentativas sobrepostas.

Feche com relatório reproduzível: hipótese, comandos, versões de dados, controles, nulo, cobertura, resultados, limitações e decisão. Encaminhe alegações fortes para `proof-certificate`.
