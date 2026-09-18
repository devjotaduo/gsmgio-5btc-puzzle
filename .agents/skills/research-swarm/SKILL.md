---
name: research-swarm
description: "Organiza uma investigação aberta em pistas independentes, com tese, antítese, compartilhamento de evidências e síntese verificável. Use quando uma questão exige mais de uma hipótese finita; não use para uma edição ou teste isolado."
---

# pesquisa em enxame

Use quando a questão ainda não tem um caminho único. O objetivo é aumentar cobertura
sem transformar paralelismo em volume de tentativas sem critério.

## Contrato da campanha

Antes de abrir frentes, registre em `spec.json` ou no relatório:

- a pergunta e o oráculo que define êxito;
- a hipótese central e o que a refutaria;
- uma pista de **regularidade/invariante** e outra de **falha/construção** quando
  ambas forem sensatas;
- fontes, corpus, parâmetros e limites de cada pista;
- a evidência mínima que justifica passar para síntese.

Uma pista pode ser analítica, experimental, de recuperação de cobertura ou de
auditoria. Não force simetria artificial: a pista oposta deve atacar a mesma
afirmação por um mecanismo realmente diferente.

## Organização e troca de avanços

Cada responsável declara os arquivos que possui e publica somente achados
reproduzíveis: hipótese, fontes/hashes, controles, resultado, cobertura e
limites. Mantenha material sensível ou volumoso fora do Git conforme o projeto.

Ao compartilhar um avanço, separe fato observado, inferência e próxima pergunta.
Quem sintetiza compara conjuntos, parâmetros e oráculos antes de combinar
resultados; não some contagens sobrepostas nem converta triagem em prova.

Quando houver trabalho paralelo, prefira frentes independentes e finitas. Pare
uma frente quando ela atingir sua cobertura declarada, reproduzir um negativo ou
perder a premissa. Não abra variantes ilimitadas sem novo sinal.

## Fechamento

A síntese deve dizer o que as pistas concordam, o que elas contradizem, a
cobertura conjunta e a lacuna precisa que permanece. Encaminhe uma possível
solução para `$proof-certificate`; encaminhe um mecanismo promissor porém ainda
amplo para `$related-problem-ladder` antes de ampliar a busca principal.
