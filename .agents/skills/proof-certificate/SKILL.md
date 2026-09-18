---
name: proof-certificate
description: "Transforma uma alegação de pesquisa em certificado independente e reproduzível e, quando cabível, em prova formal verificável, distinguindo teorema, cálculo e inferência. Use antes de declarar solução, teorema ou cobertura fechada; não use para resultados exploratórios sem uma afirmação precisa."
---

# Certificado de prova

Use quando a investigação chega a uma afirmação que precisa sobreviver à revisão independente:
uma solução, um contraexemplo, uma busca completa ou uma equivalência matemática.

## Classe da alegação

Escreva uma frase precisa, com definições, hipóteses, domínio, conclusão e exclusões, e classifique-a:

- **teorema:** decorre de definições, hipóteses e regras lógicas declaradas;
- **cálculo exaustivo:** decorre de domínio finito, implementação identificada e cobertura verificável;
- **inferência empírica:** resume evidência e limites, sem provar universalidade;
- **solução de puzzle:** exige o oráculo duro da regra 1 de `AGENTS.md` (chave que gera um dos
  alvos, ou abertura AES que leva adiante e é lida igual por duas implementações).

Diga qual parte é teorema, qual é resultado computacional e qual é inferência. Não mude a classe por
linguagem persuasiva: estatística, padding válido ou escore de linguagem não se promove a certificado.
Um candidato do oráculo semântico (ASCII alto, WIF/hex plausível, blob aninhado, assinatura EBCDIC)
continua candidato até este certificado.

## Verificador e certificado

- chave ou plaintext: oráculo independente que reconstrói o endereço ou valida o conteúdo sem
  depender do gerador, preservando a evidência que permite refazer a verificação sem expor
  segredos desnecessários;
- enumeração: entradas imutáveis com hash, particionamento, checkpoints, reconciliação de
  contagens e reprodução de hits; as faixas cobertas devem formar exatamente o domínio anunciado,
  sem lacunas nem sobreposições;
- afirmação matemática geral: prova legível e, quando as definições estiverem maduras, a
  ferramenta disponível e a alegação justificar o custo, formalização em Lean ou outro assistente.
  A formalização valida a derivação dentro do modelo, não que o modelo representa o objeto real:
  ainda é preciso justificar que o modelo formal representa a pergunta real, e registrar essa fronteira.

Use implementações independentes onde uma falha compartilhada seria plausível. O verificador não
pode reutilizar silenciosamente a conclusão que deveria testar.

O certificado inclui: (1) enunciado, definições e hipóteses; (2) entradas e hashes ou fontes
imutáveis; (3) programa, ambiente, commit e comando de verificação; (4) prova, traço de execução ou
partição do domínio; (5) controles positivos, nulos (ou N/A justificado) e resultados brutos
necessários; (6) limites explícitos do que não foi demonstrado.

## Entrega e decisão

Publique instruções de reprodução, versões, hashes, controles e o resultado do verificador; preserve
dados sensíveis localmente. Declare o limite mais próximo: quais parâmetros, representações ou
instâncias ficaram fora da prova. Declare a alegação comprovada somente quando o certificado
independente a reproduzir e atender ao oráculo definido pela campanha; se falhar, reduza-a à
evidência que sobreviveu e registre a correção.
