---
name: proof-certificate
description: "Transforma uma alegação de pesquisa em certificado reproduzível e, quando cabível, prova formal verificável. Use antes de declarar solução, teorema ou cobertura fechada; não use para resultados exploratórios sem uma afirmação precisa."
---

# certificado de prova

Use quando a investigação chega a uma afirmação que precisa sobreviver à revisão
independente: uma solução, um contraexemplo, uma cobertura finita ou uma
equivalência matemática.

## Especifique a afirmação

Escreva definições, hipóteses, domínio, conclusão e exclusões. Diga qual parte é
teorema, qual é resultado computacional e qual é inferência. Uma estatística,
padding válido ou escore de linguagem não deve ser promovido a certificado do
puzzle.

## Escolha o verificador adequado

- Para uma chave ou plaintext: um oráculo independente que reconstrói o endereço
  ou valida o conteúdo sem depender do gerador.
- Para enumeração: entradas imutáveis com hash, particionamento, checkpoints,
  reconciliação de contagens e reprodução de hits.
- Para uma afirmação matemática geral: uma prova legível e, quando as definições
  estiverem maduras e a ferramenta estiver disponível, uma formalização em Lean
  ou outro assistente de prova. A formalização confere a lógica; ainda é preciso
  justificar que o modelo formal representa a pergunta real.

Use implementações independentes onde uma falha compartilhada seria plausível.
O verificador não pode reutilizar silenciosamente a conclusão que deveria testar.

## Entrega e limites

Publique instruções de reprodução, versões, hashes, controles e o resultado do
verificador. Preserve dados sensíveis localmente. Declare o limite mais próximo:
por exemplo, quais parâmetros, representações ou instâncias ficaram fora da
prova. Só marque uma solução como confirmada quando o certificado atender ao
oráculo definido pela campanha.
