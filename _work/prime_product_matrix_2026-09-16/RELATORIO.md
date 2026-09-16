# Matriz como expoentes de um produto de primos

**Nenhuma senha encontrada.** Esta interpretação delimitada foi excluída
com limites exatos, e a conferência independente terminou com sucesso.

## Hipótese

Atribuir o primeiro primo à primeira célula de uma rota, o segundo à
segunda, até os primeiros 196 primos. Cada célula fornece um expoente:
preto/branco valem 0 ou 1, enquanto azul/amarelo valem dois primos uniformes
desconhecidos, cada um pelo menos 2. Multiplicar todas as potências fornece
um único inteiro, cuja representação decimal seria DBBI ou FAED.

Isso permite expoentes zero, ao contrário da variante de listas
estritamente positivas rejeitada anteriormente por paridade. É uma
hipótese motivada pela matriz e pelos primos, não uma instrução comprovada
do criador.

O inteiro tem a forma `N = A·B^p·Y^q`: A é o produto das posições de
fundo com expoente 1; B e Y são os produtos das posições azuis e amarelas;
p e q são os primos desconhecidos das cores.

## Cobertura e limites

Foram consideradas todas as rotas distintas obtidas por reflexões,
rotações e reversões de leitura por linhas, linhas alternadas e espiral
horária para dentro. São **32 rotas**, incluindo as espirais inversas.
As quatro atribuições 0/1 ao fundo e os dois campos formam **256 casos**.

O limite dos expoentes não é arbitrário. Para um campo de L dígitos,
`A·B^p·Y² < 10^L` limita p; para cada p, `A·B^p·Y^q < 10^L` limita q.
As desigualdades são avaliadas por inteiros exatos. Todos os primos dentro
dos limites são examinados, incluindo a possibilidade de p=q.

Para cada inteiro de comprimento correto, foram permitidas qualquer
bijeção de `a,…,i` para `1,…,9`, até duas letras também podendo valer
zero por ocorrência, e os dois sentidos completos do campo. A consistência
dessas relações pode ser decidida diretamente, sem enumerar as 9! bijeções.

## Resultado

DBBI não tem sequer um par de expoentes primos com o comprimento necessário.
FAED tem **11 combinações de rota, fundo e par de primos com comprimento compatível**. Suas
**22 comparações de padrão**, contando ambos os sentidos, falharam.
O arquivo de verificação aponta a posição e a contradição de cada uma.
Não há candidato para AES nem estado pendente.

O produtor passou por 36 modelos numéricos pequenos, conferidos por
enumeração, e quatro controles de substituição. Outra implementação,
em Python, gerou os primos por divisão, a espiral por movimento célula a
célula e as simetrias por transposição/reflexão. Recalculou a cobertura,
os produtos, todos os limites e as contradições de dígitos.

- [Especificação](spec.json), [casos e limites](cases.jsonl), [resumo](summary.json).
- [Conferência independente e certificados](verification.json).
- [Buscador](../../solver/prime_product_matrix.cjs).

Hash dos casos:
`9de2c1340e0d95ea4306e776c90858918660ed77e35f0d351410b07e3340d854`.

O negativo não cobre outros expoentes de fundo, primos iniciais deslocados,
ordenações arbitrárias de células, listas de somas usadas como expoentes
ou transformações do inteiro antes de escrevê-lo. A senha final permanece
sem confirmação.
