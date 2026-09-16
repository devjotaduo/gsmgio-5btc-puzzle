# Blocos modulares: formatos de chave e autenticação de amostras

**Nenhuma senha ou chave final encontrada.** Todos os processos desta
rodada terminaram com saída 0. O filtro exato de formatos e a seleção de
amostras têm alcances diferentes, descritos abaixo.

## Formatos de chave — teste exato

Partindo dos 9.924 modelos ASCII compatíveis da
[campanha de blocos modulares](../rsa_color_multibyte_2026-09-16/RELATORIO.md),
o teste procura quatro formatos, em BE e LE **dentro de cada bloco**:

- 64 dígitos hexadecimais, aceitando letras em ambas as caixas;
- `0x` ou `0X`, seguido de 64 dígitos hexadecimais;
- WIF de 51 caracteres, começando por `5`, usando o alfabeto Base58;
- WIF de 52 caracteres, começando por `K` ou `L`, usando Base58.

São **79.392 decisões, todas negativas**, cobrindo todos os caminhos
permitidos em cada modelo. Não foi necessário conferir checksums WIF,
pois nenhuma sequência tem sequer o formato necessário. Espaços,
quebras de linha e outros prefixos/sufixos não integram essa gramática.
Uma chave binária de 32 bytes também não cabe nesses caminhos ASCII:
o menor texto DBBI tem 41 bytes e o menor FAED tem 363. Isso não exclui
decifração modular em bytes arbitrários fora do repertório ASCII testado.

O produtor usa conjuntos de comprimentos em bitsets. O verificador calcula
uma tabela de sufixos byte a byte, sem importar o produtor. Conferiu todas
as decisões. Os controles incluem dezesseis formatos plantados e seis
grafos pequenos inteiramente enumerados; controles WIF medem a gramática,
não a validade de checksum ou uma chave real.

## Tamanhos fixos — teste exato

Também foram contados todos os caminhos com blocos uniformes de 1, 2 ou
3 bytes e um possível bloco final menor. Só o tamanho 2 é compatível:

| Campo / módulo | Modelos compatíveis | Caminhos, somados entre modelos |
|---|---:|---:|
| DBBI / 18682 | 8058 | 573784123439575537 |
| FAED / 18682 | 6 | 92324258941903573264691581910131766122509124476827160536521113600000 |

As contagens incluem sobreposição entre modelos e não contam textos
distintos. Todas as contagens individuais foram conferidas por programação
dinâmica reversa. A compatibilidade não estabelece legibilidade ou intenção.

## Amostras de senha — seleção limitada

Para cada modelo compatível, foram guardados o testemunho BE anterior e
dois ótimos determinados por critérios explícitos:

1. Minimizar, em ordem, controles, caracteres fora de letras/espaços e tamanho.
2. Minimizar, em ordem, caracteres fora de letras/espaços, tamanho e controles.

Cada critério foi aplicado com tamanhos livres e, quando possível, com
blocos de dois bytes. As duas ordens de bytes foram incluídas. Os critérios
encontram ótimos exatos para essas contagens, mas **não são um modelo de
língua e não enumeram todas as senhas possíveis**.

Isso produziu 35.976 caminhos selecionados e **51.335 textos distintos**,
incluindo os testemunhos anteriores. O verificador independente confirmou
os custos ótimos, recifrou os 1.128.892 blocos selecionados e reconstruiu
todas as saídas BE/LE. Não foram removidos controles, alterada a caixa ou
extraídas palavras para fabricar candidatos.

## Testes criptográficos concluídos

Cada texto foi testado diretamente e como seu SHA256 hexadecimal minúsculo:
102.670 senhas distintas, três blobs arquivados e dois digests do
EVP_BytesToKey, SHA256 e MD5. A senha conhecida da fase 3.2 recuperou antes
o texto autenticado de controle, de SHA256
`b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34`.

- **616.020 decisões AES**, todas reproduzidas com Python/PyCryptodome.
- **2.421 preenchimentos PKCS#7 aceitos**, todos com bytes conferidos;
  a maior fração no repertório imprimível/TAB/LF/CR foi 58,23%.
- **2.389.116 registros de escalares**, todos válidos e distintos:
  SHA256 de cada candidato, SHA256 de cada corpo com padding aceito e
  cada janela de 32 bytes desses corpos, sempre nas duas ordens de bytes.
- **Nenhum ponto correspondente** à chave pública do prêmio ou ao seu
  negativo, por multiplicação secp256k1 com coincurve/libsecp256k1.

A chave pública de referência teve HASH160 e endereço Base58Check
recalculados como `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`. Houve também
controle com o escalar 1. O fluxo de todos os registros de escalares,
reconstruído independentemente, tem SHA256
`750750262f34b8fd5357b476f8e7fe8865d58e0735daa0a37121c56cedbad8b7`.

A taxa de aceitação de padding é compatível com acaso. Padding não
autentica uma senha; não houve resultado final verificável. O teste das
51.335 amostras não exclui todos os outros caminhos da família modular.

## Registros e reprodução

- [Especificação e controles](spec.json), [resumo](summary.json).
- [Decisões por modelo](models.jsonl), [caminhos selecionados](selected.jsonl),
  [candidatos distintos](candidates.jsonl).
- [Verificação independente de formatos, contagens e caminhos](verification.json).
- [Resumo AES](oracle_summary.json), [conferência independente AES](oracle_independent.json).
- [Comparações secp256k1](scalar_verification.json).
- [Seletor](../../solver/rsa_color_candidates.cjs),
  [verificador](../../solver/verify_rsa_color_candidates.cjs) e
  [testes AES](../../solver/rsa_color_oracles.cjs).

Para conferir os modelos e caminhos já registrados:
`node solver/verify_rsa_color_candidates.cjs`.
Os produtores recusam sobrescrever suas saídas. Nenhuma execução desta
rodada continua ativa.
