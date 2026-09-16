# Priorização por linguagem nos cinco modelos parciais — 2026-09-16

**Nenhuma senha final.** A sondagem anterior de palavras concatenadas em
bases primas aceitava muitas siglas e abreviações. Esta rodada retirou o
filtro de dicionário e ordenou escolhas `g→0/7` pela pontuação do texto
completo. Não retomou nem esgotou os estados pendentes da busca anterior.

## Modelo e método

Mantivemos os cinco modelos FAED parciais já declarados: os dois alfabetos
de base 29 e os dois de base 31 no sentido original; no sentido inverso,
somente o alfabeto de base 31 com espaço no índice zero. Consulte os
[alfabetos e a sondagem anterior](../prime_alphabet_words_2026-09-16/RELATORIO.md).

A cada uma das 107 escolhas `g→0/7`, a máscara parcial determina um
intervalo de inteiros possíveis. O prefixo comum das representações dos
dois extremos na base escolhida fica fixado para todas as continuações.
Pontuamos esse prefixo e conservamos as 1.024 máscaras de maior pontuação.
Empates são resolvidos pela ordem lexicográfica das máscaras.

A pontuação soma os log-escores dos grupos de quatro letras, ignorando
separadores, e subtrai a média uniforme da tabela por grupo avaliado. Essa
correção permite comparar prefixos de comprimentos ligeiramente diferentes.
A tabela geral de inglês é a mesma já preservada em `general_english`, SHA256
`d2a64e70154725a0c0d1901690df47c73086e0bfc112ad419aad2eb069f89a43`.

Trata-se de **busca heurística**: uma máscara eliminada pode ter uma
continuação melhor. Nem o ótimo global nem a inexistência de uma mensagem
foram demonstrados. Não há limiar de pontuação declarado como senha correta.

## Calibração e comparação

Dois textos conhecidos foram codificados nos quatro alfabetos, produzindo
oito controles de 637–653 dígitos e 119–144 escolhas ambíguas. O método
recuperou integralmente todos: sete em primeiro lugar e um em segundo.
Esse último caso demonstra que pontuação maior não garante o texto exato.
As médias de quadgramas dos textos conhecidos ficaram entre −4,259 e −4,076.

Também fizemos uma comparação embaralhada por modelo. Ela conserva os
primeiros 16 caracteres decimais, todas as posições de `g` e a frequência
dos demais símbolos, embaralhando somente suas posições após o prefixo.
As mesmas 1.024 posições da busca foram usadas nas entradas reais e
embaralhadas. Uma amostra por modelo **não fornece um valor-p**.

| Modelo | Melhor média real | Melhor média embaralhada |
| --- | ---: | ---: |
| Base 29, espaço primeiro, original | −6,397 | −6,358 |
| Base 29, letras primeiro, original | −6,394 | −6,402 |
| Base 31, espaço primeiro, original | −6,244 | −6,375 |
| Base 31, letras primeiro, original | −6,320 | −6,227 |
| Base 31, espaço primeiro, inverso | −6,359 | −6,368 |

Os melhores textos reais completos foram inspecionados; continuam sem
mensagem coerente identificada. As pontuações se sobrepõem às comparações
embaralhadas e estão abaixo dos controles. Isso não justifica apresentar
seus fragmentos ocasionais como instruções do puzzle.

As dez execuções real/embaralhada avaliaram 2.007.020 extensões de máscara;
1.003.510 pertencem às cinco entradas reais. São estados parciais avaliados,
não essa quantidade de máscaras completas. As cinco entradas reais retiveram
**5.120 candidatos distintos**, nenhum presente na lista lexical anterior.

## Conferência e autenticação

Outro programa reconstruiu os inteiros, converteu as bases por divisão,
recalculou os escores por substrings e conferiu os 18.432 candidatos finais
das oito calibrações e dez execuções. Doze controles pequenos compararam
o algoritmo com todas as 704 atribuições possíveis. Isso verifica os
resultados registrados, sem transformar a busca heurística em exaustiva.

Somente os 5.120 candidatos das entradas reais foram usados como senhas;
controles e dados embaralhados ficaram fora desse teste. Nas quatro formas
de texto anteriormente declaradas, houve 20.480 materiais, 40.960 casos
de senha direta/SHA256-hex e **245.760 decisões AES** nos três blobs e
dois KDFs. Os 982 paddings não forneceram abertura autenticada; a maior
fração de ASCII imprimível foi 56,96%.

Hashlib/PyCryptodome regeneraram todos os materiais e reproduziram todas
as decisões e plaintexts. Digest da sequência de decisões:
`7fded398083aa77b5e74b1b42b69ce7ba76387840800cd2e2950c72559d08ca9`.
Os **41.942 hashes SHA256 distintos** de senhas e corpos foram conferidos
como escalares com coincurve, sem atingir o ponto público do prêmio ou
sua negação. Padding, escore de linguagem e palavras isoladas não autenticam
uma solução.

## Reprodução e estado

Na raiz do repositório, com um diretório de saída novo:

```powershell
node solver/prime_radix_beam.cjs _work/prime_beam_reproduction
node solver/verify_prime_radix_beam.cjs _work/prime_beam_reproduction
node solver/prime_joined_word_oracles.cjs _work/prime_beam_reproduction
```

As execuções são determinísticas, com largura fixa e sem limite de tempo
interno. `controls.json`, `summary.json`, os 18 registros de execução,
`independent_verification.json`, `oracles.json` e `oracles_verification.json`
preservam os resultados. Nenhum processo desta rodada continua em execução.

Os cinco modelos lexicais anteriores **continuam parciais**. Esta rodada
não exclui máscaras eliminadas pela busca, outros alfabetos, outros mapas
de zeros ou outras transformações. SMALL, COSMIC e TAIL32 continuam sem
abertura validada.
