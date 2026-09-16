# Códigos decimais sem limite de letras zeráveis — 16/09/2026

**Nenhuma senha final encontrada.** Foi removida a restrição anterior de
uma ou duas letras zeráveis. Nesta rodada, cada ocorrência de qualquer
uma das nove letras pode valer zero ou seu dígito positivo. Todas as
`9!` bijeções de a,...,i em 1,...,9 são admitidas. Isso contém qualquer
escolha de subconjunto de letras zeráveis, sem enumerar os subconjuntos.

## Domínio e classificação exata

As treze tabelas são as dez de [primos por caractere](../prime_codepoints_2026-09-16/RELATORIO.md)
e três de códigos ASCII diretos: letras/espaço, ASCII 32–126, ou esse
repertório mais TAB/LF/CR. Cada tabela é testada com decimal mínimo ou
preenchido até três dígitos, DBBI/FAED completos e os dois sentidos.
Não há remoção de símbolos, transposição ou offsets de primos adicionais.

**104 modelos × 362.880 mapas = 37.739.520 decisões.** Há 95 modelos
incompatíveis e nove compatíveis. Todas as decisões foram reproduzidas
por uma implementação com crivo independente, códigos/fontes revertidos,
estados como conjuntos e outra enumeração de permutações. O produtor teve
1.716 controles; os nove primeiros caminhos e todas as 3.600 contagens
imprimíveis foram recodificados/recontados independentemente.

| Tabela e formato compatíveis | Campo/sentido | Mapas compatíveis |
|---|---|---:|
| A=p1,...,Z=p26; espaço=0; mínimo | DBBI original/inverso e FAED original/inverso | 362.880 em cada um dos quatro casos |
| A=p1,...,Z=p26; espaço=000; preenchido | FAED original/inverso | 362.880 em cada caso |
| ASCII 32–126; mínimo | DBBI original | 3.600 |
| ASCII/TAB/LF/CR; mínimo | DBBI original | 42.960 |
| ASCII/TAB/LF/CR; mínimo | DBBI inverso | 31.800 |

Os seis casos de espaço=0/000 aceitam a saída degenerada composta
inteiramente de espaços. Isso explica a compatibilidade universal, sem
fornecer uma mensagem. As outras tabelas de primos são incompatíveis.

**FAED não admite concatenação de códigos ASCII nos modelos testados,
mesmo permitindo zero em qualquer ocorrência de qualquer letra.** O mapa
fixo a=1,...,i=9 tampouco aceita os modelos ASCII de DBBI; isso está
registrado no campo `knownMapCompatible` dos resultados.

## Quantas letras precisam poder valer zero na exceção de primos?

Para a tabela A=2,...,Z=101 e espaço=0, decimal mínimo, o mínimo é
**cinco letras zeráveis em FAED**, nos dois sentidos, permitindo qualquer
bijeção positiva. A prova anterior excluía até duas. Agora foram
examinadas todas as combinações de três e quatro:

- três: 30.481.920 configurações por sentido;
- quatro: 45.722.880 configurações por sentido.

As **152.409.600 negativas adicionais** foram refeitas com códigos
revertidos e outra enumeração de mapas. Para cinco, uma testemunha
recodificada prova existência em cada sentido; o mapa a=1,...,i=9 com
`adfhi` zeráveis já basta. Isso não esgota os caminhos nem os mapas com
cinco letras. As testemunhas não são frases reconhecíveis.

Com esse mapa fixo, todos os 126 conjuntos de cinco letras, nos dois
sentidos, falham no filtro de palavras declarado, respeitando os espaços
realmente decodificados. Foram 252 decisões, conferidas por dois métodos.
Outros mapas positivos ou conjuntos maiores não passaram por esse filtro.

No formato preenchido até três dígitos, **todas as nove letras precisam
ser zeráveis**. O único código de primo com primeiro dígito não zero é
101. Uma letra não zerável que inicia um bloco teria, então, de ser a
letra de 1 e reaparecer na terceira posição. Cada uma das nove letras
inicia algum bloco com outra letra na terceira posição, em ambos os
sentidos. Dezoito blocos comprovam a contradição. Outra implementação
recalculou os primos e todos os pares; zerar tudo prova suficiência,
produzindo apenas espaços.

## Caminhos imprimíveis de DBBI

Os 3.600 mapas admitem uma soma exata de
**23.750.997.348.188.160 caminhos**. Essa soma não é uma contagem de textos
distintos e não representa tentativas de senha. Os caminhos foram
contados por DP; não foram enumerados por completo. As 3.600 saídas
imprimíveis antigas continuam contidas no novo domínio, e há saídas novas.

Foi examinado o texto completo como representação de uma chave de 32 bytes:
32 bytes ASCII imprimíveis diretos, Base64 padrão ou URL, com/sem padding,
incluindo as restrições dos bits não usados do último caractere. As
**18.000 decisões de formato são negativas**, também em uma DP Python
independente. Hexadecimal de 64 caracteres e WIF de 51/52 caracteres
exigiriam no mínimo 128/102/104 dígitos decimais ASCII; DBBI tem 91.
Isso não exclui uma senha que precise ser passada por SHA256.

Uma prova de comprimento também exclui a saída direta de 32 bytes para
**qualquer byte ASCII 0–127**, incluindo todos os controles: cada código
de três dígitos começa com 1, que só pode vir de uma letra do mapa. A
maior frequência de uma letra em DBBI é 25. Assim, 32 códigos ocupariam
no máximo `2×32+25 = 89` dígitos, menos que os 91 observados. Zeros
opcionais não criam novos dígitos 1. A prova foi conferida em Python e Node;
não cobre bytes 128–255 nem hashes de textos maiores.

Para selecionar senhas, foi aplicado um filtro de palavras: cada trecho
máximo A–Z/a–z deve pertencer ao vocabulário Norvig, com até 32 letras e
palavras de uma letra limitadas a A/I. Dígitos, espaços e pontuação
realmente decodificados separam os trechos; exige-se ao menos uma palavra.
A DP escolhe o maior número de letras em palavras, depois menos
não-letras, depois maior probabilidade de unigramas. Outro algoritmo
por palavras inteiras confere a contagem e o ótimo.

O vocabulário amplo aceita 106 mapas, mas inclui siglas e sequências
incoerentes. Uma restrição heurística a 26.264 entradas com frequência
de corpus >=1.000.000 aceita apenas dois mapas, também sem frase
reconhecível. Os filtros não são uma definição completa de inglês e não
excluem nomes, termos raros ou outras línguas.

## Autenticação da amostra selecionada

Os melhores textos dos dois filtros dão **107 candidatos distintos**.
Foram usadas cinco formas de caixa/espaçamento, resultando em 387 materiais
e 774 senhas diretas/SHA256-hex. Nos três blobs, EVP-SHA256 e EVP-MD5:
**4.644 decisões AES**, doze paddings aceitos e nenhum resultado
autenticado. A maior fração textual foi 43,04%.

**19.562 escalares distintos** não corresponderam à chave pública do
prêmio nem ao seu negativo. Incluem SHA256 das senhas, janelas de 32 bytes
dos materiais e SHA256/janelas dos corpos com padding, nos dois sentidos
de bytes. PyCryptodome e coincurve reproduziram todos os testes, com
controle conhecido da fase 3.2 e controles da curva. Os demais caminhos
e as testemunhas degeneradas não foram testados como senhas.

## Evidências

- [Especificação](spec.json), [classificação](results.json), [resumo](summary.json),
  [verificação integral](verification.json).
- [Contagens/caminhos imprimíveis](printable_candidates.json),
  [formatos de chave](keyformats.json), [conferência Python](keyformat_verification.json).
- [Limite para 32 bytes ASCII](ascii32_length_certificate.json),
  [conferência independente](ascii32_length_verification.json).
- [Limiar mínimo de cinco letras](prime_zero_threshold.json),
  [filtro no mapa fixo](prime_known_five_words_summary.json).
- [Prova do formato preenchido](padded_prime_alias_certificate.json),
  [verificação independente](padded_prime_alias_verification.json).
- [Filtro amplo](word_filter_summary.json), [filtro comum](common_word_filter_summary.json),
  [amostra selecionada](selected_candidates.json).
- [Testes criptográficos](candidate_auth.json), [conferência independente](candidate_auth_verification.json).

Programas principais: `unbounded_zero_codepoints.cjs`,
`verify_unbounded_zero_codepoints.cjs`, `unbounded_zero_keyformats.cjs`,
`unbounded_zero_words.cjs`, `prime_zero_threshold.cjs` e
`unbounded_zero_oracles.cjs`, todos em `solver/`. As restrições dos filtros
e os escopos de amostragem constam dos artefatos; resultados compatíveis
não são considerados senhas recuperadas.

SHA256 das decisões:
`eb787a11752b920dbbb4b361b59fca99ec213604e590671a6d23276807a74aec`.
SHA256 da autenticação:
`2b362e9764d481a5d496ea2c3ef45eace3d804478cdd6798319295d88ba47d47`.
