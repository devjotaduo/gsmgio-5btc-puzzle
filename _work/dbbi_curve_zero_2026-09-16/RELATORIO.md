# DBBI como escalar secp256k1 com zeros ocultos

**16/09/2026 — nenhuma senha ou chave final encontrada.** A hipótese abaixo
foi esgotada e conferida por uma segunda implementação. Nenhuma combinação
produziu a chave pública do prêmio ou sua negação. Este resultado não
decifra SMALL, COSMIC ou TAIL32.

## Hipótese examinada

As pistas mencionam primos e caracteres a zerar. Elas não especificam
secp256k1 nem demonstram que DBBI representa uma chave. Esta rodada testa
essa interpretação adicional, sem classificadores de idioma ou padding AES:

1. Usar DBBI completo, com `a=1,...,i=9`, como um inteiro decimal.
2. Escolher um par entre as nove letras. Cada ocorrência dessas letras pode
   valer zero ou seu dígito original, independentemente. As demais ficam fixas.
3. Ler o campo na ordem original ou na ordem inversa.
4. Reduzir o inteiro pela ordem `n` do grupo ou pelo primo `p` do campo
   secp256k1. Exigir um escalar válido: `1 <= k < n`.
5. Comparar `kG` com a chave pública conhecida do prêmio e com sua negação.

Os 36 pares incluem todas as escolhas com nenhuma letra ou somente uma
letra zerada: basta manter os dígitos das outras letras. As interseções entre
pares são intencionais. Não se alterou o mapa de dígitos e não se aplicou
hash, truncamento, inversão de bytes ou cifra adicional.

As constantes usadas são as de [SEC 2, seção 2.4.1](https://www.secg.org/sec2-v2.pdf).
A chave pública não comprimida confere com o HASH160
`a9553269572a317e39f0f518cb87c1a0ee1dbae4`, do endereço
`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`.

## Cobertura e resultado

| Medida | Resultado |
|---|---:|
| Modelos: par × sentido × módulo | 144 |
| Escolhas binárias no maior modelo | 43 |
| Maior tabela de uma metade | 4.194.304 |
| Registros das tabelas esquerdas, somados | 20.499.712 |
| Consultas de pontos, somadas | 31.374.048 |
| Correspondências válidas | **0** |

A soma dos espaços binários dos modelos é **35.538.237.967.872**.
Esse número inclui sobreposições e não é uma contagem de chaves distintas,
de senhas AES testadas ou de multiplicações de curva realizadas.

## Por que a busca dividida cobre as escolhas

Escrevendo cada posição decimal zerável como um peso, divide-se a lista em
duas metades. Para o módulo `m`, sejam:

- `L = soma dos pesos escolhidos à esquerda (mod m)`;
- `R = base fixa + soma dos pesos escolhidos à direita (mod m)`;
- `k = (L + R) mod m`.

Para `m=n`, procura-se `LG = ±P - RG`. Para `m=p`, procura-se
`LG = ±P - RG + c*pG`, com `c=0` ou `c=1`.
Ao encontrar uma coincidência, a reconstrução precisa confirmar o transporte
`c=floor((L+R)/p)`, o intervalo válido do escalar e o ponto resultante.
Resíduos entre `n` e `p-1` não são aceitos como chaves válidas.

O ponto no infinito tem representação explícita. Se vários subconjuntos
produzirem o mesmo ponto da tabela, todas as máscaras são preservadas.
A busca não perde alternativas ao usar pontos como chaves do dicionário.

## Conferências

O produtor percorre cada metade por código Gray, atualizando resíduos e
pontos. O verificador percorre uma árvore binária com ramos zero/um.
Ele reconstruiu os 144 modelos da fonte e repetiu integralmente as buscas.

Para cada metade, foram comparadas contagens e impressões digitais
comutativas dos registros completos: máscara, resíduo, identificação do ramo
e ponto comprimido. Cada registro recebe SHA256; os resumos somam esses
digests módulo `2^256`. As máscaras fazem parte do digest para preservar
a distinção entre caminhos. Também foram comparadas todas as correspondências.

Ambas as implementações completas usam coincurve/libsecp256k1 para a
aritmética de curva. A independência aqui está na reconstrução dos modelos
e no algoritmo de enumeração; não são duas bibliotecas de curva distintas.

Uma conferência adicional, em Node/OpenSSL e adição afim em JavaScript,
reproduziu **todas as 7.452 amostras** salvas pelo produtor. Ela também
reconstruiu as especificações e conferiu os hashes dos 144 arquivos.
Passaram 128 controles de aritmética de pontos nessa implementação.

Os controles das buscas incluem 17 problemas plantados, comparados com
enumeração integral de **16.392 atribuições**: módulo pequeno com colisões,
reduções em `n` e `p`, escalar inválido acima da ordem, zero e quatro
casos positivos derivados do próprio DBBI com `g` zerável.

## Artefatos e limites

- [Especificação](./spec.json), construída por
  [dbbi_curve_zero_spec.cjs](../../solver/dbbi_curve_zero_spec.cjs).
- [Controles do produtor](./controls.json) e
  [resumo dos 144 casos](./producer_summary.json); casos individuais em `cases/`.
- [Conferência integral por árvore binária](./verification.json).
- [Conferência das amostras](./sample_verification.json), reproduzível por
  [dbbi_curve_zero_samples.cjs](../../solver/dbbi_curve_zero_samples.cjs).
- [Manifesto final](./final_qa.json), com hashes dos artefatos.

Os dois percursos completos foram executados como comandos Python nesta
sessão; seus resultados e controles estão preservados. Não foi criado um
executável Python persistente para esses percursos.

A conclusão vale para esta representação direta de DBBI e até duas letras
zeráveis. Não exclui três ou mais letras, FAED, outro mapa de dígitos,
pré-processamento, hash, senhas de AES ou operações diferentes sugeridas por
`matrixsumlist`. Não há processo desta rodada em execução.
