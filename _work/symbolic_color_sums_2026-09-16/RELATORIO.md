# Exclusão das 14 somas decimais, sem escolher os primos ou a ordem

16/09/2026. **Nenhuma senha ou chave final validada.** Foi excluída uma
interpretação direta de `matrixsumlist`, com alcance maior que a antiga
busca baseada em `a=1,…,i=9` e `g=0/7`.

## Modelo coberto

- Um inteiro uniforme `p≥2` para todas as células azuis e outro `q≥2`
  para todas as amarelas. Isso inclui todos os pares de primos, sem teto
  arbitrário escolhido para a busca.
- Cada célula sem cor recebe o valor associado ao seu bit original;
  os pesos de preto e branco são independentemente 0 ou 1. A célula
  quase branca segue o bit original, sem peso separado.
- Somam-se as 14 linhas ou as 14 colunas. Cada soma é escrita em decimal
  mínimo, sem zeros à esquerda, e as 14 representações são concatenadas.
- Os dígitos positivos podem corresponder a **qualquer bijeção fixa** das
  letras `a..i`. Até duas dessas letras também podem representar zero,
  independentemente em cada ocorrência.
- Usa-se DBBI ou FAED completo, em qualquer sentido. A extensão final
  cobre **qualquer permutação das 14 somas**.

Não foram presumidos os valores dos primos, a bijeção de dígitos ou qual
letra seria zerada. A prova usa condições necessárias e pode admitir
combinações numericamente impossíveis; excluir até essa versão relaxada
exclui o modelo declarado.

## Por que o teste é finito

Para cada linha ou coluna, a soma é `a·p + b·q + c`, com os coeficientes
determinados pela matriz. Há triplas de coeficientes que se repetem;
elas necessariamente produzem números iguais e blocos de mesmo tamanho.

Substituímos as letras zeráveis por um símbolo comum. Essa normalização
perde informação, mas preserva a igualdade obrigatória entre blocos
iguais, mesmo se dois zeros foram representados por letras diferentes.
O maior par de substrings iguais e não sobrepostas limita o número de
dígitos de qualquer soma repetida.

Se esse comprimento máximo é `R`, uma tripla repetida impõe
`a·p+b·q+c ≤ 10^R−1`. Usando `p,q≥2`, obtemos limites explícitos para
cada peso. O comprimento total fornece outro limite: se um peso aparece
em `k` somas e possui `D` dígitos, a concatenação tem pelo menos
`k·D + (14−k)` caracteres. Ambos são limites derivados do campo completo.

Com os pesos limitados, cada uma das 14 somas tem um comprimento máximo.
Em grande parte dos casos, nem a soma desses máximos atinge os 91 ou 570
caracteres observados.

## Resultados e extensão para qualquer ordem

Há 46 conjuntos de até duas letras zeráveis, oito perfis da matriz e
dois campos. Com os dois sentidos do campo e das somas, são **2.944
configurações**:

- **2.896** falham somente pelo comprimento máximo.
- As **48** restantes falham na segmentação com igualdade dos blocos
  repetidos. A busca completa percorreu 620 nós, sem sobreviventes.

Uma segunda implementação reconstruiu os coeficientes e os limites,
calculou as repetições por dicionários de substrings e refez a segmentação
em largura. Concordou em todos os casos. Foram conferidas 2.046 strings
binárias curtas por enumeração para cada uma das duas rotinas, além de
24 controles com somas plantadas, bijeção invertida e dois aliases de zero.

A ordem também pode ser removida da hipótese. Das **736 combinações** de
campo, aliases e perfil, 724 já falham pelo comprimento. Nas 12 restantes,
foram enumerados todos os posicionamentos possíveis dos grupos de blocos
repetidos que poderiam alcançar o comprimento necessário. Seus intervalos
precisam ser disjuntos, independentemente da permutação das somas.

**Nenhuma das 12 combinações admite esse posicionamento.** Os demais
blocos foram até relaxados para usar toda a sua capacidade máxima, sem
exigir que preenchessem lacunas corretamente. Duas implementações
independentes — máscaras de bits com busca em profundidade e intervalos
com busca em largura — enumeraram os mesmos posicionamentos e chegaram
ao mesmo negativo. Oito controles de posições, 24 de empacotamento e um
caso positivo plantado passaram. Inverter o campo preserva os mesmos
comprimentos, igualdades e relações de sobreposição.

Assim, nenhuma bijeção dos nove dígitos, nenhum par de pesos inteiros
`≥2`, nenhum conjunto de até duas letras zeráveis e nenhuma ordem das
14 somas resolve DBBI ou FAED **por essa concatenação decimal direta**.
Nenhum candidato foi produzido para AES ou para chave privada.

## Limites e reprodução

Continuam fora do modelo: somas usadas como chave de outra transformação,
combinar linhas e colunas em uma lista de 28 valores, outras bases,
operações posicionais, pesos independentes para a célula quase branca,
três ou mais letras zeráveis, separadores, padding e substituição variável
por posição. O resultado não exclui outras leituras de `matrixsumlist`.

```powershell
node solver/color_sum_symbolic.cjs
node solver/verify_color_sum_symbolic.cjs
node solver/color_sum_any_order.cjs
```

[Especificação](spec.json), [controles](controls.json), [casos](cases.json),
[resumo](summary.json), [verificação independente](verification.json),
[posicionamentos para qualquer ordem](any_order_cases.json),
[verificação para qualquer ordem](any_order_verification.json).

Programas:
[gerador](../../solver/color_sum_symbolic.cjs),
[verificador independente](../../solver/verify_color_sum_symbolic.cjs),
[extensão de ordem](../../solver/color_sum_any_order.cjs).

SHA256 dos casos originais:
`8af07e3d7e630e9470a11604a465658fd6f35ac8172b7f239aeda7370c6a27a9`.
SHA256 dos casos para qualquer ordem:
`e830fa9c6111bc79d998ec17261205bd89edcaf5b9572688cc21a22e9a918453`.
Os manifests de verificação registram os hashes dos três programas.
