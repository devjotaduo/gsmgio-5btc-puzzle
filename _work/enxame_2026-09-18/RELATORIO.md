# Enxame de 18/09 — lacunas reproduzidas e hipóteses novas

**Estado: concluída; puzzle não resolvido.** Nenhuma abertura AES, nenhum candidato e nenhuma
chave dos dois alvos. Coordenador: Claude Code, branch `claude/enxame-2026-09-18`. O Codex Astra
entrou como lente independente de ideação. Contrato em [`spec.json`](spec.json).

## Por que houve campanha

Não havia insumo novo do criador: o monitor de 17/09 mostra o site sem mudança, e os exports até
17/09 não têm falas dele. A regra 3 admite duas outras entradas, e a campanha usou as duas:

- a lacuna declarada em `ENDGAME.md` §3.13;
- famílias ausentes da §4 com prior compatível com a regra 4.

## Método

1. **Ideação.** Sete lentes independentes propuseram hipóteses finitas: seis do Claude e o Codex
   via `tools/codex_pair.py`.
2. **Gate.** Um verificador adversarial por hipótese procurou cobertura prévia no repositório e
   estimou prior e custo. Tabela completa em [`ideacao/FINDINGS.md`](ideacao/FINDINGS.md).
3. **Teste.** Cada frente começou reproduzindo a lacuna ou o bug alegado e só então rodou a
   enumeração, com controle positivo, nulo e contagens reconciliadas.
4. **Revisão.** Um revisor adversarial por frente releu código e saídas e refez amostras com
   implementação independente: biblioteca `cryptography`, `openssl` 3.5.7 CLI e `python-ecdsa`.
   Cada `FINDINGS.md` traz a revisão anexada, e as correções do revisor prevalecem.

As 13 hipóteses das lentes do Claude caíram no gate, todas com prior 1 ou 2 e âncora fraca nas
fontes. Os verificadores, porém, reproduziram de passagem três lacunas de oráculo. As quatro
hipóteses do Codex eram lacunas de implementação ou de fluxo, e todas se reproduziram.

## Resultados

| Frente | Lacuna | Cobertura | Resultado | Revisão |
|---|---|---|---|---|
| [`lacuna_cp273_utf16`](lacuna_cp273_utf16/FINDINGS.md) | §3.13: corpus da §3.11 sem cp273 inversa nem UTF-16 | 1.894.673 conteúdos × 6 visões; 710.313 hex64 e 3 WIF contra os dois alvos | 0 hits; 13.970 sinais, todos artefatos provados | controles no mesmo caminho |
| [`ebcdic_decimal_inverso`](ebcdic_decimal_inverso/FINDINGS.md) | Codex I1: busca decimal→EBCDIC podava pelo repertório da direção cp273 errada (`ebcdic_decimal.cjs:11`), com falso negativo demonstrado | 33.819.184 inteiros de `dbbi` (uma letra zerável) + 13.063.864 configurações (literal e 9! bijeções) no repertório correto | 0 textos aceitos; nenhum AES a rodar | negativo confirmado |
| [`faed_selecao_sha256`](faed_selecao_sha256/FINDINGS.md) | Codex I2: seleções de 256 bits de `faed` nunca usadas como pré-imagem de senha nem contra `17ucy` | 47.862 valores → 191.364 senhas, 1.148.184 AES; 95.723 escalares | 0 candidatos; 4.434 paddings no nível do acaso | negativo confirmado |
| [`lista_mais_fala`](lista_mais_fala/FINDINGS.md) | Codex I3: lista numérica + fala antes de "choice", nunca compostas | 270 bases × 233 recortes e extensões: 474.120 senhas, 2.844.720 AES | 0 candidatos | negativo confirmado |
| [`cbc_sem_padding`](cbc_sem_padding/FINDINGS.md) | §3.13: CBC sem PKCS7; Codex I4 | (A) 10.080 senhas em SMALL/TAIL32 sem unpad, 3.951.360 checagens raw32 BE/LE; (B) COSMIC por bloco sobre 1.272.149 formas × 2 KDF | 0 sinais, 0 hits | com ressalvas: o revisor refez os controles pelo caminho real |
| [`retro_17ucy`](retro_17ucy/FINDINGS.md) | §3.11: escalares históricos comparados só com `1GSMG` | 17 fontes, 11.188.119 escalares válidos (F6 completa, brainwallets, corpus de 466.310 bases, 6 famílias `.cjs`, `prime_host`, `select256`) | 0 hits | com ressalvas de cobertura declarada |
| [`orfaos_temp`](orfaos_temp/FINDINGS.md) | plaintexts de 17/09 que ficaram em `%TEMP%` e nenhuma re-varredura leu | 152.952 conteúdos (150.381 inéditos); 150.230.638 janelas raw32 BE+LE; 6 visões; 1.153.925 testes de brainwallet | 0 hits; 177 sinais, todos explicados | com ressalvas; o revisor refez a camada A inteira |

Ao todo foram 6.577.522 decisões AES reais e cerca de 168 milhões de testes de privkey contra os
dois alvos. São testes, não chaves distintas: há sobreposição entre frentes, declarada em cada uma.

## Fatos novos

1. **Correção de rótulo.** O corpus da §3.11 não é só de plaintexts AES. O `collect()` recolhe
   todo campo `hex` de `_work/**`, o que inclui materiais de decodificadores e pré-imagens.
2. **Bug de recoleta.** A recoleta da §3.11 separa linhas com `str.splitlines()`, que também
   quebra em `\x85` e em U+2028/2029 dentro dos campos `head`, e os pedaços caem num `except`
   silencioso. São 7.279 linhas em 62 arquivos e 772 conteúdos ausentes. Todos estão nos corpora
   da §3.12/§3.13, mas não passaram pelas visões cp273 direta e UTF-16.
3. **Lacuna irmã.** `solver/ebcdic_codepoints.cjs:7` usa o mesmo repertório da direção errada,
   em 26.127.728 casos de leitura por códigos concatenados. Não foi refeita.
4. **Blobs e kit conferidos de novo.** SMALL e COSMIC reconstruídos de 7 capturas HTML são
   idênticos ao kit. A divisão do binário `enter` no SMALL é única por aritmética: só a remoção
   integral dos 40 símbolos dá 80 B. Em 720 decifrações, o kit e o `openssl` CLI não divergiram.
5. **Assimetria entre os alvos.** `1GSMG…` tem prefixo de vanidade de 5 caracteres, então sua
   chave é essencialmente aleatória e só pode vir literalmente de um envelope. `17ucy…` não é de
   vanidade: é o único alvo em que uma derivação por brainwallet é plausível, mas o gate manteve
   prior 1 para a hipótese de que ele venha do puzzle.

## O que continua aberto

Cada item é uma lacuna de cobertura, não uma pista:

- modos de fluxo, com cerca de 14,2 bilhões de janelas (§3.13);
- raw32 sem unpad do corpus de 1,27 M formas em SMALL/TAIL32, com cerca de 498,7 M checagens;
- `ebcdic_codepoints.cjs` no repertório correto;
- camadas C (330.613 campos, 1.118 deles de modos de fluxo) e D (12,75 M montagens) do corpus
  órfão, contra `17ucy` e em LE;
- negação (N − k) contra `17ucy` nas famílias `.cjs` e `prime_host`;
- as 772 linhas perdidas pelo `splitlines`, nas visões cp273 direta e UTF-16;
- GPU 16! de §5.

As fontes das camadas C e D estão no scratchpad de uma sessão antiga em `%TEMP%` e são a única
cópia. Se forem revisitadas, convém copiá-las para um local persistente, fora do git.

## Processo: o que deu errado

- **Alocação excessiva de processos.** O coordenador distribuiu 20 workers entre as seis
  frentes (3, 2, 2, 4, 4 e 5), numa máquina de 20 núcleos que também rodava os processos-pai, os
  revisores e outros aplicativos. Cada frente respeitou o próprio limite. Os revisores de
  `ebcdic_decimal_inverso`, `retro_17ucy` e `orfaos_temp` acusaram "violação do limite de 2",
  mas foi um erro do coordenador: o prompt de revisão trocava `WORKERS` por 2 no texto comum.
  Com a memória sob pressão, o pagefile chegou a 41,6 GB e o disco C: foi a 0 B livres várias
  vezes. Uma parte do `orfaos_temp` falhou com ENOSPC e foi refeita do zero, e três partes
  passaram do teto de 10 min da ferramenta e foram para segundo plano. Nenhum resultado se
  perdeu. `AGENTS.md` passa a limitar o total de processos entre frentes paralelas.
- **Controles fora do caminho real.** Em `cbc_sem_padding`, `orfaos_temp` e parte de
  `lista_mais_fala`, os controles da frente não passavam pelo mesmo caminho da enumeração. Os
  revisores refizeram os controles pelo caminho real, e todos passaram. A regra 3 já exige isso;
  a revisão adversarial foi o que pegou.
- **Relatório por subagente.** O harness recusa `.md` escrito por subagente, então o
  coordenador gravou todos os `FINDINGS.md` a partir das respostas estruturadas.

## Reprodução

Scripts em `solver/enxame_2026_09_18/<frente>/`. O executor comum
[`solver/enxame_2026_09_18/comum.py`](../../solver/enxame_2026_09_18/comum.py) roda o controle da
fase 2 e um nulo de ruído no próprio `__main__`; em três nulos de 240 mil decisões AES, o z do
número de paddings ficou em +0,68, −1,41 e +0,94. Kit `gsmg_common.py` com sha256
`3810cbaf…1e67`, HEAD `5f12b71`. Os hashes de cada frente estão no seu `FINDINGS.md`.

## Delta proposto

- `ENDGAME.md`: nova §3.14 com as lacunas fechadas e as que continuam abertas; §3.11 e §3.13
  remetem a ela; notas nas linhas afetadas de §4-B e §4-D.
- `docs/RESEARCH-INDEX.md`: uma linha para este relatório.
- `AGENTS.md`: limite de processos entre frentes paralelas, por causa do pagefile.
