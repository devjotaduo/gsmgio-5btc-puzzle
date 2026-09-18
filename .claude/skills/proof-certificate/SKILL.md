---
name: proof-certificate
description: Converte uma alegação final em certificado independente e verificável, distinguindo prova, cálculo e inferência.
---

# Certificado de prova

Use antes de declarar hipótese provada, busca completa ou solução. Esta skill aplica a exigência de certificado verificável de `AGENTS.md`.

## Classe da alegação

Escreva uma frase precisa e classifique-a:

- **teorema:** decorre de definições, hipóteses e regras lógicas declaradas;
- **cálculo exaustivo:** decorre de domínio finito, implementação identificada e cobertura verificável;
- **inferência empírica:** resume evidência e limites, sem provar universalidade;
- **solução de puzzle:** exige o oráculo duro definido pelo repositório.

Não mude a classe da alegação por linguagem persuasiva.

## Certificado

Inclua:

1. enunciado, definições e hipóteses;
2. entradas e hashes ou fontes imutáveis;
3. programa, ambiente e comando de verificação;
4. prova, traço de execução ou partição do domínio;
5. controles positivos, nulos e resultados brutos necessários;
6. limites explícitos do que não foi demonstrado.

Para busca, demonstre que as faixas cobertas formam exatamente o domínio anunciado, sem lacunas ou sobreposições. Para oráculo criptográfico, preserve a evidência que permite refazer a verificação sem expor segredos desnecessários.

## Formalização e decisão

Use Lean ou outro verificador formal quando houver modelo adequado e a alegação justificar o custo. A formalização valida a derivação dentro do modelo, não que o modelo representa o objeto real; registre essa fronteira.

Declare a alegação comprovada somente quando o certificado independente a reproduzir. Se falhar, reduza-a à evidência que sobreviveu e registre a correção.
