# Lacunas de 18/09: EBCDIC por códigos, recoleta partida, negação N−k e camadas órfãs C/D

**Estado: concluída; puzzle não resolvido.** Nenhuma chave dos dois alvos, nenhum texto legível e
nenhuma abertura. Coordenador: Claude Code, branch `claude/lacunas-2026-09-18`. Contrato em
[`spec.json`](spec.json).

## Por que houve campanha

O enxame de 18/09 (`ENDGAME.md` §3.14) fechou as lacunas reproduzidas e deixou declaradas quatro
lacunas baratas de cobertura. A regra 3 admite "lacuna de cobertura reproduzida", e cada item abaixo
fecha uma delas. Nenhum partiu de insumo novo do criador, e o prior de todos é baixo: o objetivo é
tirar essas linhas da lista de abertos, não perseguir uma pista.

## Resultados

| Item | Lacuna | Conjunto coberto | Resultado |
|---|---|---|---|
| 6 | `ebcdic_codepoints.cjs` usava o repertório da direção EBCDIC errada | 26.127.728 casos (os de 16/09) no repertório autêntico da 3.2 | 45 casos segmentáveis, 58.232.392 caminhos; nenhum caminho passa de 52 % de letras e espaço |
| 7 | a recoleta da §3.11 perdia linhas por `str.splitlines()` | 1.723 conteúdos recuperados, 1.441.760 janelas raw32 BE+LE e as 7 visões | 0 hits; 11 sinais, todos materiais de 32 B sem texto |
| 8 | negação N−k contra `17ucy` nas famílias `.cjs` e `prime_host` | 11.188.119 escalares das 17 fontes do `retro_17ucy`, como k e N−k | 0 hits em 44.752.476 h160 |
| 9C | camada C do corpus órfão (outras 15 cifras) sem `17ucy` e sem LE | 330.037 conteúdos, 305.725.358 janelas raw32 BE+LE e as 7 visões | 0 hits, 0 sinais |
| 9D | camada D (montagens de blocos) sem `17ucy` e sem LE | 797.172 sobreviventes, 12.754.752 montagens, 339.511.437 janelas únicas em BE e LE | 0 hits; contagens iguais às de 17/09 |

Ao todo, 997.378.111 multiplicações na curva contra os dois alvos (as de N−k saem da mesma
multiplicação de k), sem nenhuma chave, e nenhum texto legível na leitura EBCDIC.

## Item 6: EBCDIC por códigos decimais, direção autêntica

**Hipótese.** `dbbi` ou `faed`, originais ou invertidos, são a concatenação dos códigos decimais
(mínimos ou com 3 dígitos) dos bytes de um texto guardado como na fase 3.2: o byte `b` entra se
`latin1(b).encode('cp273')` é ASCII 32–126, TAB, LF ou CR. O alfabeto e as letras zeráveis são os
da busca de 16/09 (9! bijeções com uma letra zerável; alfabeto literal com até duas).

**Como rodou.** Os scripts históricos `solver/ebcdic_codepoints.cjs` e
`solver/verify_ebcdic_codepoints.cjs` rodaram sem edição, byte a byte iguais aos hashes do relatório
de 16/09. Um módulo pré-carregado ([`ebcdic_inverso_patch.cjs`](../../solver/lacunas_2026_09_18/ebcdic_inverso_patch.cjs))
entrega a eles a tabela inversa e redireciona as saídas. O repertório resultante tem 98 bytes, é
idêntico ao derivado pelo codec `cp273` do Python e contém os 1.539 bytes do segmento Beaufort da
3.2; só 43 bytes são comuns com o repertório antigo.

**Resultado.** Ao contrário da direção antiga, a inversa aceita segmentações completas: 45 casos,
todos em `dbbi` com códigos mínimos (18 na ordem publicada, 27 invertida), somando 58.232.392
caminhos. Aceitar só quer dizer que os dígitos se partem em códigos do repertório; o repertório
inverso inclui muitos bytes pequenos (4, 5, 6, 7…) cuja imagem ASCII é pontuação, e os textos saem
com 60 % de pontuação. Seis casos passam do limite de 100 mil textos enumerados do buscador, então
a conclusão não vem de amostra:

- [`ebcdic_inverso_verifica.cjs`](../../solver/lacunas_2026_09_18/ebcdic_inverso_verifica.cjs)
  reconta os aceitos com o `accepts()` do verificador histórico (DP por fronteiras de palavra,
  independente do autômato do buscador): os mesmos 45 mapeamentos, grupo a grupo, nos 26.127.728
  casos.
- [`ebcdic_inverso_legivel.py`](../../solver/lacunas_2026_09_18/ebcdic_inverso_legivel.py)
  reconstrói o grafo de cada caso em Python, confere a contagem de caminhos com a do buscador (45/45
  iguais) e calcula, por Dinkelbach sobre o DAG, a fração **máxima exata** de caracteres bons entre
  **todos** os caminhos:

| Classe | Caracteres | Fração máxima entre os 58,2 M caminhos |
|---|---|---|
| palavras | letras e espaço | 0,522 |
| senha | letras e dígitos (hex64, WIF, base58, base64 sem sinais) | 0,576 |
| prosa | letras, espaço, quebras e `.,;:'"!?-()` | 0,839 (o melhor caminho é pontuação solta: `/.~onk.-y .-.-Y^mm…`) |

Prosa em inglês passa de 0,95 em letras e espaço, e uma senha hex ou WIF tem fração 1. Os controles
plantados (texto em prosa, frase só de palavras e hex, codificados na mesma direção e mapeados por
bijeção com alias) saem com fração 1 nas respectivas classes.

**Inferência.** A leitura "dbbi/faed = códigos decimais concatenados de um texto EBCDIC" está
excluída também na direção autêntica, para o conjunto de 16/09. Com isso as três leituras decimais
de 16/09 ficam cobertas nas duas direções (a de inteiro completo foi refeita na §3.14).

**Limites.** Os mesmos de 16/09: outras larguras de código, separadores, símbolos pulados,
transposições, caracteres fora do ASCII, três ou mais letras zeráveis no alfabeto literal e duas
com bijeção. Nenhuma senha foi testada em AES: sem texto legível, não há candidato a senha.

## Item 7: conteúdos perdidos por `splitlines()`

**Bug.** `retro_dois_alvos.collect()` partia cada `.jsonl` com `str.splitlines()`, que também quebra
em `\x85`, U+2028 e U+2029. Os logs gravam com `ensure_ascii=False`, então esses caracteres aparecem
crus dentro das strings, e o pedaço caía no `except` silencioso. São 7.279 linhas em 32 arquivos do
checkout principal, quase todos logs de 02/09 (`b3x3_run_screen_only`, `symbol_map_variants`,
`zeroed_primes`) e das rodadas de 17/09. **Correção:** o `collect()` agora usa `split("\n")`
([retro_dois_alvos.py](../../solver/operador_ensinado_2026_09_17/retro_dois_alvos.py)).

**Varredura.** [`splitlines.py`](../../solver/lacunas_2026_09_18/splitlines.py) roda a coleta antiga
(o código do commit `2a535c6`, via `git show`) e a corrigida sobre o checkout principal: 837.728
contra 839.451 conteúdos, 1.723 só na corrigida e nenhum só na antiga. O revisor do enxame contou
772 com o estado do checkout na época da §3.11; hoje há mais arquivos. Dos 1.723, 814 estavam nos
corpora da §3.12/§3.13 e **909 nunca tinham sido varridos**. Os 1.723 passaram pela varredura da
frente `orfaos_temp`: raw32 BE e LE em todo offset contra os dois alvos (1.441.760 janelas) e as 7
visões (original, cp273 inversa e direta, UTF-16 LE/BE @0/@1), com hex64 em todo nibble, WIF com
checksum, semântica, blob aninhado e ASCII ≥ 48 B. **0 hits** e nenhum hex64 ou WIF. Os 11 sinais
são materiais de 32 B com bytes entre 0x0d e 0x63, que passam no limiar de 85 % de imprimíveis sem
formar texto; como têm 32 B, também foram testados como chave, sem hit.

**Controles.** Uma linha sintética com `\x85` e U+2028 some na coleta antiga e aparece na corrigida;
o raw32 plantado (24 casos) passa pelo mesmo `trabalhar()`; os dois h160 são os dos endereços.

**Fica de fora.** `familia4_codecs.py` e `critico_familia4_codecs.py` coletam com o mesmo padrão; as
campanhas deles estão fechadas e não foram refeitas, então esses 1.723 conteúdos também ficaram fora
dos codecs da família 4. `scan.ler_retro` da frente `lacuna_cp273_utf16` mantém o bug de propósito,
porque é a cópia fiel que reconcilia os números históricos.

## Item 8: negação N−k

**Hipótese.** N−k de algum escalar já gerado pelas 17 fontes do `retro_17ucy` é a chave de um dos
alvos. As famílias `.cjs` e o `prime_host` comparavam só a coordenada x com `1GSMG`, o que cobria k e
N−k; o `retro_17ucy` testou só k contra `17ucy`.

**Como rodou.** [`negacao.py`](../../solver/lacunas_2026_09_18/negacao.py) importa o `retro.py` sem
editá-lo e troca só o `varrer`. A pubkey de N−k é o ponto negado (x, p−y): prefixo comprimido trocado
e y → p−y, sem segunda multiplicação na curva. As 17 fontes regeneraram exatamente os mesmos fluxos
do `retro_17ucy` (os 17 `sha256_fluxo_ordenado` iguais), e cada um dos 11.188.119 escalares válidos
foi testado como k e como N−k, nas duas formas de pubkey, contra os dois alvos: 44.752.476 h160,
**0 hits**, em 192 s com 4 processos.

**Controles.** A fórmula da negação bate com `coincurve(N−k)` em 2.000 escalares aleatórios. Em cada
fonte, dentro do processo filho, o h160 de N−k de um escalar do próprio fluxo é plantado e tem de ser
achado pelo lado N−k nas duas formas; cada filho devolve a prova de que o patch estava ativo. Os dois
plantados de k e a amostra `python-ecdsa` do `retro.py` passaram. A fonte `brainwallet_inline` já
guarda k e N−k; para ela os plantados de k só contam pelo lado k.

## Item 9: camadas C e D do corpus órfão

As fontes estão no scratchpad da sessão `bd1a3ae7`, em `%TEMP%`. A frente `orfaos_temp` do enxame
varreu as camadas A e B e deixou C e D de fora, porque as premissas delas (outras cifras, blocos
fora de ordem) estão refutadas em §4-D. Na época, C e D só tinham sido vistas contra `1GSMG`, em BE
e na pubkey não comprimida. [`orfaos_cd.py`](../../solver/lacunas_2026_09_18/orfaos_cd.py) fecha as
duas contra os dois alvos, em BE e LE, nas duas formas de pubkey.

**Camada D: montagens de blocos.** O ataque `montagem_ct` de 17/09 testou o corpus de 1.272.149
formas contra todas as ordens dos 5 blocos de SMALL e TAIL32. Cada um dos 797.172 sobreviventes de
padding guarda `D_hex` (os 5 blocos decifrados em ECB) e `iv_hex`, e as 16 montagens compatíveis se
reconstroem só com XOR, com as funções copiadas de `montage_attack.py`. Toda janela única de 32 B de
cada sobrevivente foi conferida como chave em BE e LE: 339.511.437 janelas, 679.022.874
multiplicações na curva, **0 hits**, em 74 min com 10 processos.

Reconciliação com o `montage_summary.json` histórico: 797.172 sobreviventes, 12.754.752 montagens e
339.511.437 janelas únicas, os três iguais; e a montagem `best` de cada um dos 797.172 sobreviventes
foi refeita idêntica, byte a byte, ao `plain_hex` gravado na época. Controles pelas mesmas funções da
varredura: sem hit antes do plantio; com o h160 de uma janela real plantado em BE (pubkey comprimida)
e o de outra em LE (não comprimida), só essas duas voltam; 200 janelas conferidas com `python-ecdsa`
sem divergência; os 10 filhos veem exatamente os dois alvos reais. Os sinais semânticos das
montagens (texto, blob aninhado, hex64 e WIF) não dependem do alvo e já tinham sido medidos em 17/09;
as visões cp273 e UTF-16 não foram aplicadas às montagens.

**Camada C: outras cifras.** Nos 20 arquivos de `premissa_cifra`, a extração da frente `orfaos_temp`
(mesmos campos `*hex*`, mesmas exclusões) acha 330.613 campos fora de `aes-256-cbc`: 329.495 de 11
cifras com padding (aes-128/192-cbc, aes-256-ecb, camellia-256-cbc, sm4, idea, seed, des-ede3, bf,
cast5, rc2) e 1.118 de 4 modos de fluxo (aes-256-cfb/ctr/ofb, chacha20). São 330.037 conteúdos únicos
(163.093.826 B; 79 B de SMALL e 1.327 B de COSMIC). Todos passaram pelo mesmo `orfaos.trabalhar()`
das camadas A+B: 305.725.358 janelas raw32 BE+LE contra os dois alvos, **0 hits**; nas 7 visões,
nenhum hex64, nenhum WIF e nenhum sinal (texto, blob aninhado, assinatura EBCDIC ou ASCII ≥ 48 B).
Levou 22 min com 10 processos. Controles: raw32 plantado em 24 casos pelo próprio `trabalhar()`, os
dois h160 conferidos por base58check e os 10 filhos com exatamente os dois alvos reais.

**Inferência.** Com C e D, todo o corpus órfão de 17/09 (camadas A a D) está coberto contra os dois
alvos, nas duas ordens de byte; A, B e C também nas visões cp273 e UTF-16.

## O que continua aberto

- modos de fluxo, com cerca de 14,2 bilhões de janelas (§3.13);
- raw32 sem unpad do corpus de 1,27 M formas em SMALL/TAIL32 (~499 M checagens);
- os codecs da família 4 sobre os 1.723 conteúdos do item 7;
- as visões cp273 e UTF-16 sobre as 12,75 M montagens da camada D;
- o que já estava fora do escopo de 16/09 no item 6.

As fontes do corpus órfão continuam só em `%TEMP%` (scratchpad da sessão `bd1a3ae7`, 1,2 GB).

## Reprodução

```text
node -r ./solver/lacunas_2026_09_18/ebcdic_inverso_patch.cjs solver/ebcdic_codepoints.cjs
node -r ./solver/lacunas_2026_09_18/ebcdic_inverso_patch.cjs solver/lacunas_2026_09_18/ebcdic_inverso_verifica.cjs
python solver/lacunas_2026_09_18/ebcdic_inverso_legivel.py
python solver/lacunas_2026_09_18/splitlines.py
python solver/lacunas_2026_09_18/negacao.py
python solver/lacunas_2026_09_18/orfaos_cd.py --camada D --workers 10
python solver/lacunas_2026_09_18/orfaos_cd.py --camada C --workers 10
```

O `summary_completo.json` do item 6 (122,6 MB, com os 985.288 textos enumerados) fica local; o
`summary.json` versionado traz o sha256 dele. Kit `gsmg_common.py` com sha256 `3810cbaf…1e67`, HEAD
`2a535c6`. Os hashes dos scripts estão em cada `summary`.
