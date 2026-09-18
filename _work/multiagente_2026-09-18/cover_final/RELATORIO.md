# Capa: coordenadas das duas estrelas

**Negativo na família finita declarada; nenhum avanço autenticado no puzzle.**

A imagem recuperada estava disponível e foi erroneamente tratada como ausente
na rodada `operador_ensinado`. O endosso do criador é uma resposta ao anexo da
capa; não demonstra uso criptográfico de coordenadas. Proveniência: semaj #8310
e resposta de Jrk Bgrt #8311, dezembro de 2022; encaminhamento posterior #48646.
Não há hash do arquivo original de 2022 no export, portanto a identidade daquele
original não pode ser afirmada por comparação criptográfica. A cópia recuperada
tem 377×499 pixels e SHA256
`3a9b0a6ecacef83e1ef9f688303105570b3dcae95fd82be75f1fcbd2f5fddd04`.

## Hipótese fixada antes do AES

Centros da estrela branca e da amarela, coordenadas inteiras ou em uma grade
14×14, poderiam fornecer números para senha. Testados dois sentidos de leitura
dos pontos/eixos, bases 0/1, concatenação decimal, vírgula e espaço, coordenadas,
somas e diferenças. Materiais entram como senha literal ou SHA256 hexadecimal.
Nenhum limiar foi ajustado em função do resultado criptográfico.

O código mede os maiores componentes de conectividade 8 em uma região fixa
que exclui a moldura. Usa quatro limiares de luminosidade predefinidos
(140/170/200/220) e máscaras de branco/amarelo declaradas no script. As quatro
medidas independentes foram reproduzidas pelo orquestrador.

| Limiar | Centro branco (x,y) | Centro amarelo (x,y) |
|---:|---|---|
| 140 | 202,601881; 248,620690 | 203,006637; 349,347345 |
| 170 | 202,884259; 248,592593 | 202,873563; 349,183908 |
| 200 | 202,817460; 248,515873 | 203,024490; 349,746939 |
| 220 | 202,833333; 249,200000 | 202,864865; 349,805405 |

O alinhamento é quase vertical e a separação é aproximadamente o raio do disco:
geometria esperada dos olhos de yin-yang. Não há inteiro privilegiado derivado
independentemente. A linha da estrela amarela arredonda para 349 ou 350 conforme
o limiar, e o modelo por extremos pode deslocar a linha branca entre células.
As discretizações são aplicadas aos centroides originais, antes de arredondar
pixels; isso evita criar um empate artificial em 6,5.

## Cobertura efetiva

- **192 materiais únicos**, **384 senhas únicas**, **2.304 decisões AES**:
  SMALL, TAIL32 e COSMIC, EVP-SHA256 e EVP-MD5.
- 14 plaintexts com padding, todos preservados integralmente; zero sinais
  semânticos. Maior fração imprimível: 0,4430.
- 384 hashes de senha testados como escalares e 6.911 janelas raw32 big-endian
  dos plaintexts, contra os dois endereços e ambas serializações P2PKH: zero.
- 100 nulos por rotação rígida conjunta dos quatro pares, preservando a geometria
  medida e aplicando o mesmo gerador. O número de senhas distintas varia após
  discretização; não se apresenta um p-value de populações artificialmente iguais.
  Nulo sem ECC, com plaintexts de padding integralmente preservados.

Controles: fase 2/causality; checkerboard real da 3.2.2; AES plantado pela mesma
derivação das coordenadas; células 14×14 medidas com asserts; hashes das fontes
e do código conferidos antes e depois. Revisor Python independente examinou o
gerador, a rotação do nulo e a confirmação ECC dos positivos.

[Especificação](spec.json) · [Controles](controls.json) · [Resultados](summary.json).

## Reprodução e limites

```
python solver/multiagente_2026_09_18/cover_geometry.py --image CAMINHO_DA_CAPA --out _work/repro_cover
```

Use o Python e dependências descritos em AGENTS.md, dentro desta worktree.
Exige diretório novo. O arquivo da capa fica local. A rodada anterior `cover/`
produziu números idênticos; `cover_final/` acrescenta rastreabilidade completa
e é a execução de referência. Não se somam as duas como novas tentativas.

Este negativo não exclui outras leituras da capa, nomes de estrelas ou geometrias
arbitrárias. Sem indício de uma operação específica, não ampliaremos essa família
apenas por haver outros parâmetros possíveis. Raw32 little-endian e ECC dos nulos
não fazem parte deste experimento.
