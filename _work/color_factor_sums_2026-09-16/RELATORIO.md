# Fatores primos das cores como pesos da matriz — 16/09/2026

**Nenhuma senha ou chave final encontrada.** Foi testada uma fórmula
explícita para relacionar cores, primos, `matrixsumlist` e últimas palavras.
As pistas citam esses elementos; não determinam a fórmula abaixo.

## Números derivados da imagem

O PNG preservado em `_work/gsmg_live_2026-09/body_puzzle`, 1048×1556,
contém exatamente as cores azul `#3F48CC` e amarelo `#FFF200`. A conferência
usou esse PNG válido; `_work/archive/puzzle.png` não foi reconhecido como
PNG e não entrou no cálculo. A geometria e os 101 bits ativos vêm do
arquivo de entradas previamente conferido.

| Projeção da cor | Azul | Fatores primos | Amarelo | Fatores primos |
|---|---:|---|---:|---|
| Soma dos dígitos hexadecimais | 54 | 2, 3 | 47 | 47 |
| Soma dos canais R+G+B | 339 | 3, 113 | 497 | 7, 71 |
| Inteiro RGB de 24 bits | 4.147.404 | 2, 3, 37, 9.341 | 16.773.632 | 2, 181 |

A tabela mostra fatores distintos; as multiplicidades e a reconstrução
dos números completos constam da especificação. Foi escolhido cada fator
possível para sua própria cor, produzindo **14 pares**. Não houve troca
arbitrária das cores nem busca de primos fora dessas fatorações.

## Composição das senhas

Cada célula colorida recebe o fator escolhido. As demais mantêm o bit
original ou passam a zero. Somam-se linhas e colunas, com cinco ordens:
linhas, colunas, linhas seguidas de colunas, colunas seguidas de linhas e
intercalação. Cada lista também é testada na ordem inversa: **280 listas**.

As seis serializações exatas são decimal concatenado, vírgulas, espaços,
quebras de linha, array JSON compacto e array com espaços após vírgulas.
Não há redução módulo 10/26, truncamento de bytes ou corte de lista.

Para cada texto, testam-se:

- lista sozinha;
- lista seguida por uma das duas cláusulas abaixo;
- primo amarelo, primo azul, lista e cláusula, concatenados nessa ordem.

As cláusulas já haviam sido delimitadas na [análise textual](../recipe_audit_2026-09-11/FRONTEIRA_TEXTUAL.md):

```text
reinsertingtheprimebasicsafterwhichyouwillberequiredto
sheisgoingtodieandthereisnothingyoucandotostopit
```

A primeira vem do texto autenticado da fase 3.2, sem usar as quebras
editoriais do README. A segunda vem da cena do Arquiteto no roteiro
consultado anteriormente. Sua escolha continua uma hipótese sobre
`lastwordsbeforearchichoice`; outras fronteiras não foram testadas aqui.

## Resultado e conferências

Os **8.370 materiais distintos** geraram 16.740 senhas diretas/SHA256-hex.
Nos três blobs, com EVP-SHA256 e EVP-MD5: **100.440 decisões AES**, 411
aceitações de padding e nenhum resultado autenticado. A maior proporção
de bytes textuais foi 54,43%. Padding isolado não valida uma senha.

Foram comparados **455.646 escalares distintos** com a chave pública do
prêmio e seu negativo, sem correspondência. Incluem SHA256 das senhas e
SHA256/todas as janelas de 32 bytes dos corpos com padding, nas duas
ordens de bytes. A contagem vale para esta rodada, sem afirmar unicidade
global em relação aos testes anteriores.

Uma implementação Python refez as três projeções, fatorações, cada célula
das somas, as 280 listas e todos os materiais. PyCryptodome refez todas
as decisões AES, inclusive as negativas, e comparou os corpos completos;
coincurve refez todos os escalares. Passaram os controles da fase 3.2,
do gerador secp256k1 e do HASH160 da chave pública de referência.

O resultado exclui somente as combinações declaradas. Não prova que os
primos das cores sejam fatores, nem esgota usos de `matrixsumlist`.

## Ajuste da documentação histórica

O README ainda apresentava `54+47=101` como o significado de
`matrixsumlist` e como explicação de marcadores de uma cadeia binária
sem autenticação. O texto foi corrigido: a igualdade é verificável;
essa interpretação não está confirmada. As associações BIP39
`blood`/`blind`/`movie` e os fragmentos `HASH`/`YIN` continuam preservados
como hipóteses. O teste de embaralhamento condicionado a uma receita
escolhida não cobre a seleção anterior de hipóteses e palavras.

## Evidências e reprodução

- [Especificação](spec.json), [cores no PNG](image_verification.json).
- [Listas](lists.json), [materiais](materials.json),
  [reconstrução independente](material_verification.json).
- [Decisões criptográficas](oracles.json),
  [conferência PyCryptodome/coincurve](oracle_verification.json).
- [Programa](../../solver/color_factor_sum_passwords.cjs).

```powershell
node solver/color_factor_sum_passwords.cjs
```

O produtor recusa sobrescrever resultados completos. SHA256 dos materiais:
`af0faecaff7621936905c77d8c54a807563384b550e777a569e478e49d14b04b`.
SHA256 das decisões criptográficas:
`b55d59ec6d4aa7a6823a6de5d98c46139126ff83ca3b0480fbdede53fad87baf`.
