---
name: research-swarm
description: "Organiza uma investigação aberta em frentes independentes e finitas, com tese, antítese, troca de evidências reproduzíveis e síntese auditável. Use quando uma questão exige mais de uma hipótese falsificável; não use para uma edição ou teste isolado."
---

# Pesquisa em enxame

Aplica o "Modo de investigação em enxame" de `AGENTS.md`: leia antes a tabela de famílias refutadas
do `ENDGAME.md` e a cobertura já registrada. O objetivo é aumentar cobertura sem transformar
paralelismo em volume de tentativas sem critério; não paralelize antes de definir pergunta, oráculo
e cobertura.

## Contrato da campanha

Registre em `_work/<campanha>_<data>/spec.json`, antes de abrir frentes (sem esse contrato, uma saída
é pista, não conclusão):

1. pergunta exata e oráculo que decide um acerto;
2. hipótese central, o que a refutaria e a construção contrária a produzir ou refutar;
3. domínio, partição e limite de cada frente; sobreposição só quando deliberada (verificação
   independente) e declarada;
4. fontes, corpus, dados, ferramentas, parâmetros e limitações;
5. controle positivo, nulo casado (ou N/A justificado, em prova determinística) e condição de parada;
6. dono de cada arquivo e a evidência mínima que justifica passar à síntese.

## Frentes

Uma frente pode ser analítica, experimental, de recuperação de cobertura ou de auditoria.
Distribua papéis complementares: sustentar a regularidade/invariante, procurar a falha/construção
que a viole, verificar controles e reproduções, e resolver um problema relacionado que preserve o
mecanismo. Não force simetria artificial: a frente oposta deve atacar a mesma afirmação por um
mecanismo realmente diferente. Cada frente escreve só nos próprios arquivos
(`solver/<campanha>/<frente>/`, `_work/<campanha>_<data>/<frente>/`). Pare uma frente quando ela
atingir a cobertura declarada, reproduzir um negativo ou perder a premissa; não abra variantes
ilimitadas sem novo sinal.

## Troca de achados

Cada frente publica em `_work/<campanha>_<data>/<frente>/FINDINGS.md` só achados reproduzíveis:
hipótese, conjunto coberto, fontes/hashes, comando, artefatos, controles, resultado, limitação e
próximo teste. Separe fato observado, inferência e próxima pergunta. Compartilhe evidência
verificável, nunca só interpretação; material sensível ou volumoso fica fora do Git.

## Síntese e entrega

Quem coordena (dono do `spec.json` e do `RELATORIO.md`) compara conjuntos, parâmetros e oráculos
antes de combinar: declara concordâncias independentes, contradições e sua reprodução decisiva,
cobertura conjunta, a lacuna precisa que permanece e as inferências que não passam pelo oráculo
duro. Não some tentativas sobrepostas nem converta triagem em prova. Feche com relatório
reproduzível: hipótese, comandos, versões de dados, controles, nulo, cobertura, resultados,
limitações e decisão. Encaminhe uma possível solução ou alegação forte para proof-certificate;
encaminhe um mecanismo promissor porém ainda amplo para related-problem-ladder antes de ampliar a
busca principal.
