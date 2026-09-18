# Rodada "operador ensinado" — 2026-09-17: seis famílias, seis negativos com nulo casado, crítica adversarial e síntese

**Nenhuma senha final. Nenhuma privkey. O prêmio segue intacto** em
`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` (1,256 BTC) e `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` (3,751 BTC;
os dois endereços somam os "5 BTC" e têm chaves distintas — ver §3.4).

A rodada atacou seis leituras das frases que o próprio criador "ensinou" (a demonstração `R=18/A=1/B=2`,
os rótulos decodificados pela página, as falas do Arquiteto, `half / better half`, "close friends") como
**operadores** sobre os objetos nomeados do puzzle, e não como palavras-senha. Cada família teve um agente
(hipótese em prosa, controle positivo, nulo casado, oráculo duro) e um ou dois críticos adversariais que
reproduziram a cobertura, re-varreram os plaintexts e completaram as lacunas mais baratas. O sintetizador
(este relatório) reproduziu do zero os pontos que os logs deixaram em aberto (§3). Três críticos morreram
por queda de rede e foram refeitos pelo orquestrador; os vereditos finais e as correções que eles trouxeram
estão no adendo (§9), que **prevalece** sobre as seções anteriores onde divergem. Nenhum agente editou `ENDGAME.md`, `README.md` ou `docs/RESEARCH-INDEX.md`.

## 0. Integridade e regras aplicadas

- Kit: `python gsmg_common.py` → `gsmg_common OK; KDF=EVP-SHA256 confirmado` (rodado pelo sintetizador).
- Todo script abre com o controle positivo obrigatório (fase 2 abre com `sha256hex("causality")` sob
  EVP-SHA256 e **não** abre sob EVP-MD5) e aborta por `assert` se ele falhar; três críticos (F2, F5, e o
  sintetizador) refizeram o controle com EVP_BytesToKey e PKCS7 **reimplementados** (hashlib puro) e o
  crítico da F5 também com o binário `openssl` 3.5.7 (`-md sha256` abre, `-md md5` dá rc=1).
- Oráculo duro único: privkey de 32 B → pubkey `04f4d1bb…bf33559` (ou h160 dos dois endereços, §3.4), ou
  plaintext semântico (≥ 85 % ASCII, WIF/hex64, blob `Salted__`/`U2FsdGVk` aninhado, EBCDIC cp273 ≥ 0,75).
  **Nenhum agente e nenhum crítico alegou hit duro.** Padding PKCS7 válido foi contado só para o nulo.
- Todo plaintext com padding válido está gravado em hex nos JSONL (regra 5 do `AGENTS.md`); o total desta
  rodada é de 1.083.580 plaintexts AES distintos (§3.5).
- Dois agentes trabalharam em paralelo no diretório; o corpus de plaintexts de um crítico (F4) cresceu
  durante a execução porque outro crítico (F6) escrevia ao mesmo tempo. Os números abaixo são os dos
  **arquivos finais em disco**, que em dois casos (F4-A1, F6-triplas) diferem dos números que os agentes
  relataram ao orquestrador; a diferença está anotada onde ocorre.

## 1. Resumo

| # | Família | Hipótese (uma linha) | Cobertura real (agente + críticos) | Nulo (z de padding) | Veredito |
|---|---|---|---|---|---|
| 1 | `matrixsumlist` como operador **RAB** (a1z26 → soma \| lista) | a demonstração `R=18/A=1/B=2 → 21 ou 1812` do criador, aplicada a 184 objetos nomeados e à saída de `yellowblueprimes` | 9.722 + 93.118 + 219.630 + 7.172 senhas; ≈ 2,0 M AES; ≈ 356 k privkeys | −2,3 … +2,4 em 24 sub-famílias (4 rodadas de 100 réplicas) | **negativo confirmado** (crítico corrigiu: L83 tem bits diferentes) |
| 2 | `lastwordsbeforearchichoice` **literal** no transcript do Arquiteto | recorte de N palavras antes de cada "choice", falas, blocos cortados; formas + RAB + codec z + composições | 70.340 senhas únicas; 473.568 AES; 211.020 brainwallets; 1,5 M janelas | +0,04 / +0,17 global; classes −0,88 … +0,98 | **negativo confirmado** (crítico: agente só janelou 1 das 5 ocorrências; corrigido) |
| 3 | "seven **intertwined** passwords" = entrelaçamento de caracteres dos 7 operandos de nível-senha | round-robin, 7! ordens × k ∈ {1..9} × 2 políticas × inversões × 2 caixas × 28 conjuntos | 8,84 M materiais distintos (agente) + 5,45 M (k 5–9); ≈ 255 M AES; 14,6 M privkeys | +0,14 global (com o denominador certo); −1,77 … +1,58 por conjunto | **negativo confirmado**; corrige o mapa (§6) |
| 4 | "over twenty-three ciphers" = família de **codecs** de byte único | 65 codecs × 2 direções sobre plaintexts, campos da página e senhas codificadas | 105.519 senhas (633 k AES) + 21.427 multi-byte (129 k AES); ≈ 100 M reinterpretações | −0,27 (A1); |z| ≤ 2,89 em 42 células (A3) | **negativo confirmado**; fato: 65 codecs → 2 imagens em [a-z0-9] |
| 5 | `yinyang` / `half & better half` como **dualidade** estrutural dos objetos | um membro do par como senha do outro; XOR; cortes; complemento; estrelas | 265.362 senhas distintas; 1,60 M AES; 268.511 privkeys; 5,76 M janelas | −2,26 … +0,39 em 7 sub-famílias (10,1 M AES de nulo) | **negativo confirmado** (crítico: cobertura inflada 6 %, nulo com cap não declarado) |
| 6 | **referência pessoal** do criador pela gramática das fases (concatenação verbatim + sha256) | inventário de 104 itens, aridade 1–3 (+4–6 na lista curta), 5 formas, 7 materiais, separadores | ≈ 1,7 M candidatos; ≈ 32,6 M AES; 454.932 brainwallets; 12,8 M janelas | −0,58 … +1,75 por sub-família; **F5 +3,7 (excesso, §3.2)** | **negativo confirmado** dentro da cobertura; triplas verbatim 67,5 % |

Total aproximado da rodada: **≈ 292 M decifrações AES reais** (fora ≈ 200 M de nulo e 6 M de calibração),
**≈ 16,4 M privkeys** diretas, **≈ 415 M janelas de 32 B** varridas nos plaintexts (incluindo o retro de
dois endereços do orquestrador e a re-varredura final do sintetizador, §3.5). Zero hits duros.

## 2. As seis famílias

### 2.1 Família 1 — `matrixsumlist` como operador RAB (`rab_a1z26.py`)

**Hipótese.** Em 2021-04-01 o criador escreveu, sem que ninguém pedisse, `R=18 / A=1 / B=2 … Could also
be 21 or 1812 bit`: é a demonstração explícita de um operador palavra → ordinais a1z26 → **soma** (21) ou
**lista** (1812). O segundo passo do roadmap chama-se `matrixsumlist` (matrix / sum / list) e a página
final usa o ramo "lista" ao contrário (codec z). Aplicar o operador a cada objeto nomeado do puzzle e
serializar o resultado (11 serializações × 10 formas número→senha, cada uma também em sha256 hex) daria a
senha de SMALL/TAIL32/COSMIC ou a privkey.

**Cobertura do agente.** 168 entradas de texto (7 tokens do roadmap isolados, janelas de 2–3 e
concatenados; 31 tokens da página; 11 respostas das fases; as 23 palavras da mensagem da 3.2 isoladas, em
82 janelas contíguas de 2–5 e a frase) + 16 entradas numéricas (bits de tipo de L84 em 3 leituras, 25
índices espirais coloridos e as duas seleções de 23, sequências de cor, bytes da URL, somas de
linha/coluna) → **9.722 senhas únicas × 3 blobs × 2 KDF = 58.332 AES; 10.994 privkeys; 230 paddings**
(todos em hex). Controle do operador: `--demo` reproduz `ordinais("RAB") = [18,1,2]`, soma `21`, lista
`1812`; assert reconstrói os bits `00001000110000100110010` a partir de `G.COLORED` omitindo os eventos
22 e 25. Nulo: 100 reamostragens preservando número e comprimento das palavras / tamanho e faixa das
listas; z por blob×KDF entre −1,08 e +1,85.

**Críticos (dois scripts, logs `critico_rab/`, `critico_rab_a1z26/`).**
- `critico_rab.py`: re-varredura dos 230 plaintexts com oráculo completo, 196.796 janelas nas duas ordens
  contra os **dois** endereços: 0 (**falso**: o script chamava `O.check_privkey`, que só testava `1GSMG`;
  refeito com os dois alvos pelo crítico final, §9). Extensão das lacunas declaradas (ordinais 0-based, janelas de 6–22
  palavras, produto/soma de quadrados/alternada/diferenças, sha256 maiúsculo e duplo, URL com `.`=27 e
  `/`=28): 680 entradas de texto + 16 numéricas → **102.840 senhas (93.118 novas), 558.708 AES, 98.467
  privkeys, 2.123 paddings**, nulo de 100 réplicas: z entre −2,30 (TAIL32/MD5) e +0,51.
- `critico_rab_a1z26.py`: recontagem independente **bate exatamente** (9.722 / 58.332 / 10.994 / 230);
  nulo com semente diferente reproduz a faixa (−0,91 … +2,01); extensão própria (0-based, serializações
  extras, encadeamento RAB∘z_method, **todas** as 276 janelas contíguas das 23 palavras, sha256 duplo e
  maiúsculo): **219.630 senhas, 1.317.780 AES, 5.033 paddings, 238.471 privkeys, 4.773.752 janelas**: 0
  (a extensão não tem nulo casado gravado — o `run.log` está vazio; z binomial exato −1,9, déficit).
- `critico_rab_l83.py` (adendo): o agente escreveu `bitsL83 = bitsL84` com o comentário "a sequência de
  tipos é a mesma". **É falso**: em L83 o `e` final do resíduo vira o 23.º marcador `be`, logo
  `BITS[83] = 00001000110000100110011` (último bit 1) e das cinco seleções de 23 células que casam com as
  cores (§6 do ENDGAME) o agente gerou só as duas de L84. O adendo rodou as saídas de `yellowblueprimes`
  em L83 (bits, 3 seleções de índices, cores) pelo mesmo operador: 21 objetos, **7.172 senhas, 43.032
  AES, 7.928 privkeys, 192 paddings**; z entre −0,23 e +2,42 (SMALL/SHA256: 37 paddings vs 27 esperados,
  p ≈ 0,04 sem correção, 6 células) — ruído; 0 hits.

**Resultado.** Negativo confirmado. O token `matrixsumlist` está agora atacado nas suas duas leituras
plausíveis (lista de somas da matriz, já histórica; operador RAB, esta rodada), ambas com zero.
**Fica de fora**: agrupamentos não contíguos das 23 palavras; o número como parâmetro de outra operação
(índice, transposição, deslocamento); o resíduo de `dbbi`/`faed` como entrada (colide com ENDGAME §4-B/§6
e foi excluído de propósito).

### 2.2 Família 2 — `lastwordsbeforearchichoice` literal (`familia2_lastwords.py`)

**Hipótese.** O rótulo nomeia um objeto externo concreto: as últimas palavras antes da "escolha" na
transcrição do Arquiteto que o criador parafraseou na fase 3.2. A senha seria um recorte literal dessa
fronteira (janela de N palavras antes de "choice", a fala das duas portas, "Hope", "We won't.", a última
fala de Neo, o trecho cortado) sob as convenções das fases (caixa, sem espaços, sem pontuação, iniciais),
cru ou sha256, também serializado por RAB e pelo codec z, e em 8 composições com tokens do roadmap.

**Cobertura do agente.** 87 materiais × 11 formas = 745 formas-base × 32 operadores → **23.352 senhas
únicas × 6 = 140.112 AES; 23.352 brainwallets; 553 paddings**. Controle end-to-end: o próprio pipeline,
alimentado com "Causality.", recupera a fase 2 (printable 0,981) e não a abre sob MD5. Nulo: 100
replicados embaralhando a ordem das palavras dentro de cada frase (preserva multiconjunto, contagem e
pontuação) numa subamostra declarada de 25/87 materiais: z_global +0,04; por classe −0,88 … +0,21.
Sobreposição medida com a campanha histórica R1 (`round3_inline.py`): 23 das 745 formas já cobertas.

**Crítico (`critico_familia2.py`, `critico_familia2_dois_alvos.py`; veredito CONFIRMADO_NEGATIVO).**
Reproduziu a cobertura função a função (87 / 745 / 23.352 / 140.112, classes 744 + 2.234 + 1.924 + 570 +
17.880) e o controle com `openssl` 3.5.7. Erros do agente: (i) "o arquivo local só traz o trecho final" é
falso — `ChatExport_2026-09-08/files/MISC.txt` tem a cena anterior com **cinco** ocorrências reais de
"choice" e três blocos marcados *skipped in puzzle*; o agente janelou só a última; (ii) o "verbatim" do
agente é ASCII, a fonte usa U+2019/U+2013; (iii) `corte_todo` era só a cauda do bloco final; (iv) o braço
privkey só olhava `1GSMG`; (v) a serialização "soma de ordinais" é invariante à permutação de palavras,
logo 26 % das senhas RAB do nulo são idênticas às reais (nulo anticonservador nessa classe; irrelevante no
resultado). Extensão: transcript completo nas duas grafias, 14 tamanhos de janela antes de **cada** uma
das 5 ocorrências, blocos cortados inteiros e por sentença, 48 pares de falas consecutivas → **348
materiais, 1.952 formas-base (1.630 inéditas), 55.576 senhas (união com o agente 70.340), 333.456 AES,
1.302 paddings (taxa 0,003905)**, nulo de 100 réplicas z_global +0,17 (classes −0,25 … +0,98). Oráculo de
**dois alvos**: 211.020 chaves brainwallet (sha256, sha256², sha256(sha256hex)) e 1.495.566 janelas nos
1.643 plaintexts únicos dos dois logs: 0.

**Resultado.** Negativo confirmado na cobertura corrigida. **Fica de fora**: transcrições além do
`MISC.txt` local (jaced.com não baixado, sem rede); nas 4 ocorrências que só o crítico janelou faltam os
tamanhos 4, 6, 9, 11, 13, 14, 17–19, 21, 22, 24, 26–29; composições de 3+ falas; qualquer caminho fora
de `openssl -pass`.

### 2.3 Família 3 — "seven intertwined passwords" como entrelaçamento (`familia3_entrelacamento.py`)

**Hipótese.** "Intertwined" é trançado, não emendado. Toda leitura histórica concatenou, XOR-ou ou
encadeou por sha256; aqui o material é o entrelaçamento round-robin (um caractere ou bloco de k de cada
fio, em rodízio, pulando os esgotados) das sete senhas de nível-senha que o puzzle produziu
(`theflowerblossoms…`, `causality`, a junção de 227 B da fase 3, a de 62 B da 3.2, `thematrixhasyou`,
`gsmg.io/theseedisplanted`, o título+endereço), cru ou sha256 hex, como senha dos três blobs ou (via
sha256) como privkey.

**Cobertura do agente (summary.json).** Fase A: 28 conjuntos de 7 operandos (S0 do atlas; 14 trocas por
`thispassword`/`lastwords…`; sha256 da URL; `theseedisplanted`; as 7 partes da fase 3 como conjunto e
como substitutas de (3); os sete como sha256; (3) e (4) como sha256) × k ∈ {1,2,3,4} × {preencher,
truncar} × {direto, invertido} × {como está, minúsculo} = 896 tarefas de 5.040 ordens. Fase B: as 128
máscaras de inversão por operando em S0 × k ∈ {1,2} × 2 × 2 = 1.008 tarefas. **9.108.000 materiais
distintos por tarefa; 109.296.000 AES (3 blobs × 2 KDF × {cru, sha256hex}); 2.113.020 privkeys
(k ∈ {1,2} da fase A); 428.706 paddings em hex (COSMIC truncado a 64 B)**; 740 s em 18 workers. Asserts de
integridade dos operandos (comprimentos `[53,9,227,62,15,24,59]`, sha256 de (3) e (7)). Nulo: 120 réplicas
embaralhando os caracteres dentro de cada operando, S0/k=1 (483.840 AES cada): taxa 0,003929 ± 0,000083
vs real 0,003916 → z −0,16. Teto de `printable` casado em número de paddings por blob: 0,633 / 0,620 /
0,436 (nulo) vs 0,646 / 0,633 / 0,428 (real).

**Crítico (`critico_familia3_entrelacamento.py`, log `critico_familia3_entrelacamento/run.log`; sem
veredito textual no bruto).** Pipeline reimplementado; verificação amostral de 24 tarefas: todas batem.
(H1) cobertura: os 9.108.000 são "distintos por tarefa"; globalmente distintos são **8.835.840** (fator
1,031) — inflação pequena, declarada. (H2) o z = +2,71 do agente vs 1/256 é artefato do denominador: vs
Σ_{p=1..16} 256^-p dá **+0,14**; o viés sistemático vale z ≈ +2,56 em n = 10⁸. (H3–H4) privkey em **todos**
os 9.108.000 materiais (o agente só em 2,1 M) + 3 formas novas (hex MAIÚSCULO, sha256 duplo, digest cru):
**76.114.080 AES, 298.283 paddings, z −0,37**; blocos k ∈ {5..9} nos 28 conjuntos: **1.120 tarefas,
5.453.280 materiais, 65.439.360 AES, 5.453.280 privkeys, z +0,01**; retro nos 428.706 plaintexts do
agente com oráculo completo e 36.856.852 janelas: semantic 0, nested 0, ebcdic máx 0,462, printable máx
0,656, privkey 0. O estágio "COSMIC inteiro" (regenerar os plaintexts de 1.328 B, já que o agente só
logou 64 B) foi **cortado a 200/1.904 tarefas** (3.876.480 AES, 15.164 paddings, 39.304.952 janelas, sem
hit); o estágio `o5up` (operando 5 em maiúsculas, `THEMATRIXHASYOU` como o README grafa) foi escrito e
**não rodou**.

**Resultado.** Negativo confirmado, com ≈ 255 M AES e 14,6 M privkeys, 0 hits. Dois achados de método
(§4): o denominador 1/255 e o teto de `printable` dependente da escala. **Correção de mapa** (§6): a linha
"entrelaçado" de ENDGAME §4-C vinha de `v3_interleave.py` sobre nove tokens de roadmap/página, k=1, sem
inversão ou caixa — interseção **vazia** com os sete operandos de nível-senha; a família agora está
coberta de fato. **Fica de fora**: entrelaçamentos não round-robin (agenda fixa, por comprimento, em
bits); k misto por fio; inversões parciais fora de S0/k ≤ 2; 13 fios (13!); o operando 5 em maiúsculas;
COSMIC inteiro nas 1.704 tarefas restantes; e a leitura em que "seven intertwined" descreve a estrutura
(7 fases, 7 partes, 7 `be`) e não uma operação — a leitura que a segmentação por primos favorece.

### 2.4 Família 4 — "over twenty-three ciphers" como família de codecs (`familia4_codecs.py`)

**Hipótese.** Na 3.2 o criador já usou "cifra" como codec (campo 3 lido em Latin-1 e re-codificado em
IBM 1141 = cp273 vira ASCII; "One for one, four for one"). "Select from over twenty-three ciphers"
nomearia a família dos ~65 codecs de byte único e o passo faltante seria escolher outro membro para
reinterpretar material do endgame. Falsa se, para todo codec C e as duas direções: (A1) nenhum plaintext
com padding já coletado vira legível sob C; (A2) nenhum campo da página vira semântico; (A3) nenhuma senha
derivada de C (nome do codec; sha256 dos bytes do token codificados em C) abre um blob; (A4) não há um
segundo segmento EBCDIC nos plaintexts autênticos.

**Cobertura do agente (log final em disco).** A0 controle específico: o segmento alto do plaintext real
da 3.2 dá `lower = 1,000` sob cp273, 0,879–0,951 nos outros 7 EBCDIC e **0,000** nos 57 não-EBCDIC; o
re-encode reproduz `vtkvplmepphl…`. A1: **112.242 plaintexts AES com padding + 684.791 blobs de material
de 98 arquivos** × 65 × 2 (o agente relatou 53.573 / 95 ao orquestrador: a execução final em disco é
posterior e absorveu como entrada os registros do crítico da própria família — ver "material" abaixo);
699 disparos do detector, todos rastreados a campanhas que gravaram EBCDIC por construção; 0 duros; nulo
de 100 randomizações dos bytes altos: z da média −0,27. A2: 19 campos × 65 × 2 = **114 imagens
distintas** (colapso: `dbbi`, `faed`, os campos z, os resíduos e os base64 dão exatamente 2 imagens; só
ciphertexts e salts crus chegam a 3–6); 1.368 AES, 4 paddings, 0. A3: 15.075 bases × formas → **105.519
senhas × 6 = 633.114 AES, 2.540 paddings (0,00401), 0 duros**; nulo 100 lotes de 3.000 senhas da mesma
forma (μ 70,98, σ 9,0 vs 70,3 esperado); 42 células com z entre −1,94 e +2,89 (2 com |z| > 2 em 42 — o
esperado). A4: fases 2 (648 B) e 3 (4.090 B) têm **zero** bytes ≥ 0x80 — segmento de codec impossível
por construção; a 3.2 tem o único que existe.

**Críticos (dois scripts; sem veredito textual no bruto).**
- `critico_familia4_codecs.py` (log de 66 MB): C1 — os "65 codecs" são 64 canônicos (`cp037` =
  `ebcdic_cp_us`); a stdlib tem 69 canônicos de byte único; faltam `cp1125`, `mac-arabic`, `mac-croatian`,
  `mac-farsi`, `mac-romanian` — nenhum é EBCDIC, logo nenhuma imagem nova sobre [a-z]; C2 — o colapso vale
  nas **duas** direções (3–11 imagens por campo contando enc e dec; as imagens "fora dos 65" são ≤ 1 por
  campo e vêm dos 5 codecs faltantes) e "fatias" são vácuas para material alfanumérico; C3 — recontagem
  105.519 = 105.519, 2.540 = 2.540 paddings, z_global +1,35; C4 — o coletor do agente lia 95 arquivos, o
  do crítico 1.302 (106.235 plaintexts AES + 684.455 de material); C5 — oráculo barato integral e gravação
  de 247.594 disparos "não tautológicos" (`ascii85+hex64`, 33 `ascii85+wif`) em registros de **material**
  de outras campanhas (`oracles.json`, `materials.json`…). A execução foi cortada antes do braço privkey
  do C5 e do C6 (multi-byte): não há `C5_resumo` nem `FIM`. **O sintetizador fechou o C5** (§3.3):
  247.536 hex64 decodificados a 32 B, testados nas duas ordens contra os dois endereços: 0; os 33 "WIF"
  são texto (`the private key is 5KJvsngHe…`) e não decodificam.
- `critico_codecs23.py` (multi-byte, o gap que o agente declarou): tokens ASCII têm 7 imagens distintas
  em UTF-16/32 (BOM+LE, LE, BE) e UTF-8-BOM; controle plantado (blob cifrado com `yellowblueprimes` em
  UTF-16LE) recuperado pelo mesmo pipeline; **613 bases, 21.427 senhas, 128.562 AES, 518 paddings, 0
  duros**; 210 células (7 codecs × 5 formas × 3 blobs × 2 KDF) com |z| ≤ 3,63 — uma única célula a +3,63
  com n pequeno; o máximo esperado de |z| entre 210 células normais é ≈ 2,9; ruído.

**Resultado.** Negativo confirmado. **Fato que fecha a família**: sobre [a-z0-9] os codecs de byte único
colapsam em duas imagens (ASCII e uma única EBCDIC) — "escolher um membro" não é um espaço de busca. A
frase do Arquiteto é paráfrase do filme ("23 individuals, 16 female, 7 male"). **Fica de fora**: codec
aplicado a fatias de um campo (vácuo sobre alfanumérico); auditoria caso a caso dos 699 disparos A1
(todos com oráculo duro 0); C6 do crítico (coberto pelo `critico_codecs23` nos tokens, não em `dbbi`/`faed`
inteiros); gramáticas de composição além de 1–3 partes e das permutações do roadmap.

### 2.5 Família 5 — `yinyang` como dualidade estrutural (`familia5_dualidade.py`)

**Hipótese.** "THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF" é instrução estrutural: o material contém
pares que o autor partiu ao meio ou publicou em duplicata (as duas linhas base64 do SMALL com `enter`
entre elas; os envelopes SMALL e TAIL32; as metades de `dbbi`/`faed`/dos 84 tokens; a matriz e seu
complemento; as duas estrelas da capa). Um membro gera a senha do outro (cru, base64, hex, sha256) ou a
combinação dual (XOR, concatenação trocada, sha dos shas) é a senha.

**Cobertura do agente.** Cinco sub-famílias (A blobs duais, 11 formas; B matriz/URL complementares +
RAB/codec z; C par de estrelas, com a célula W* da matriz como *proxy*; D 16 cortes ao meio; E produto
cruzado 51 × 50 em 3 composições): **10.920 senhas listadas × 6 = 65.520 AES; 12.864 privkeys; 246
paddings**. Controle estrutural: re-deriva por DFS a segmentação `yellowblueprimes` e assert das duas
segmentações (83/84) e do resíduo L84 byte a byte. Nulo: 100 aleatorizações por sub-família preservando
tipo, comprimento e alfabeto (3,16 M AES): z −0,69 … +0,53.

**Crítico (`critico_familia5.py`, `critico_familia5_verificacao.py`; veredito CONFIRMADO_NEGATIVO).**
Pipeline reimplementado: os 246 plaintexts são **idênticos byte a byte** aos do agente (V3: 246/246;
por sub-família 26/11/21/21/167); 40 deles reproduzidos pelo `openssl` da linha de comando. Erros do
agente: cobertura inflada 6 % (10.920 listadas = **10.279 distintas**; 3.846 decifrações redundantes);
nulo da sub-família E com `NULL_CAP=2000` não declarado (refeito sem cap: z −0,93, não −0,69); privkey
só na ordem direta e só contra `1GSMG`; C é proxy, não a capa. Extensões: X1 = **todos** os pontos de corte
de `dbbi` (1..90) e `faed` (1..569) em 8 formas (4.615 distintas, 31.632 AES, z +0,02); X2 = triplas
ordenadas 51×50×49 em cat/sha_cat (249.892 distintas, 1.499.400 AES, z binomial +0,52, sem nulo casado);
X3 = COSMIC partido em todo limite de 16 B (576 distintas, 3.948 AES, 7 paddings vs 15,4 esperados,
z −2,26 — déficit; p Poisson 0,016, P(alguma de 7 tão baixa) 0,08; déficit não é sinal). Totais:
**265.362 senhas distintas, 1.600.500 AES, 6.274 paddings re-varridos com semantic/nested/EBCDIC/WIF/hex64
e 5.761.480 janelas nas duas ordens contra pubkey e h160 (dois endereços): 0; 268.511 privkeys diretas: 0;
nulo de conjunto inteiro 10.110.000 AES, z ∈ [−2,26; +0,39]**.

**Resultado.** Negativo confirmado. "Blob como senha do outro blob", "metade + enter + melhor metade",
as estrelas como palavras/cores/índices e os cortes em todos os pontos nunca tinham sido gerados; agora
estão fechados. **Fica de fora**: as coordenadas reais das estrelas da capa de *Cosmic Duality* (não há
imagem no repositório — **insumo ausente**, não negativo); triplas em sha(sha‖sha‖sha) e quádruplas;
cortes por ponto em dígitos/codec z; nulo casado para X2.

### 2.6 Família 6 — a referência pessoal pela gramática das fases (`familia6_referencia_pessoal.py`)

**Hipótese.** Toda senha verificada é o nome/linha exata de algo do mundo do criador, alcançado por
descrição oblíqua, com as partes concatenadas verbatim sem separador e sha256 hex minúsculo do
resultado. "My close friends have the best chance … that is a hint" (2026-07-12) sugere que a senha do
último envelope é uma referência pessoal já presente no material público, composta pela mesma gramática.
Regra ética aplicada: nenhum nome civil, endereço, familiar ou cônjuge foi buscado; "the better half"
entrou só como a glosa pública dele.

**Cobertura do agente.** Inventário de **104 itens** (empresa e glosa, handles públicos da despedida,
"better half", Venus Project, Decentraland, o livro, Mr. Robot/HSM, música, ferramentas) × 5 formas
(verbatim, minúsculo-sem-espaço, minúsculo, sem-espaço-caixa, MAIÚSCULO) → F1 337; F2 pares 9.119 +
9.999; F3 triplas no recorte prioritário 79.464 + 89.760; F4 item⊕roadmap 2.898 + sanduíche 3.168; F5
permutações de aridade 4–6 da lista curta do atlas 3.600 → **198.345 candidatos × 3 materiais × 6 =
3.570.210 AES; 198.345 brainwallets; 14.002 paddings**. Controle: fase 2 injetada em `G.BLOBS` e aberta
pelo mesmo `try_password_all`; autoteste da gramática (`causalitySafenetLunaHSM11110`, sha256 da 3.2).
Nulo: 100 rodadas × 400 candidatos com caracteres permutados: z −0,15 … +0,12 (fraco: poucos ensaios por
rodada; ver crítico). Correção de dado: o criador escreve `geestveruimend` (sem o segundo r) na
msg #66976; as duas grafias entraram.

**Crítico (`critico_familia6.py`, logs em `critico_familia6/`; sem veredito textual no bruto; a
execução foi em três sessões e a consolidação final não rodou — os totais abaixo foram recompostos pelo
sintetizador a partir dos JSON e dos JSONL).**
- Reprodução: 198.345 distintos; **14.002 paddings, sub-família a sub-família idênticos** ao agente; z
  binomial exato por sub-família −0,58 … **+1,75 (F5)**; z do agente eram artefato de um nulo com 1–10
  candidatos por sub-família por rodada. Nulo refeito (100 × 2.000 candidatos, 3,6 M AES): sd observado
  = 0,99 × sd binomial — o pipeline se comporta como Bernoulli(p).
- Calibração própria: **1.000.000 senhas aleatórias × 6 = 6 M AES, 23.365 paddings** (0,003894); z por
  célula −1,11 … +0,26.
- Sobreposição medida com o corpus histórico de 466.310 senhas-base: **124** dos 198.345 candidatos já
  estavam nele (45 dos 337 singles); 198.221 são novos.
- Materiais declarados "fora" (digest cru de 32 B, sha256 dupla hex, raw+LF, sha256(raw+LF)) sobre
  singles + pares + roadmap + lista curta: 29.121 candidatos, **698.904 AES, 2.900 paddings (z +3,05,
  puxado por F5 — §3.2), 58.242 brainwallets**: 0. `sha256hex(sha256hex(s))` sobre todos os 198.345:
  1.190.070 AES, 4.652 paddings (z −0,22), 198.345 brainwallets: 0. Separadores (espaço, hífen, "and"…)
  nos pares: 77.118 candidatos, **1.388.124 AES, 5.483 paddings (z ≤ +0,75)**: 0.
- Triplas sobre o inventário **inteiro**: `T3_low_completo` = **777.816 candidatos × 18 = 14.000.688
  AES, 55.244 paddings (z +1,45)**, completa (parcial até o índice 551.284 + retomada de 226.532);
  `T3_verbatim_completo` = 970.026 planejados, **≥ 654.890 concluídos (67,5 %; último padding no índice
  654.889; 46.445 paddings vs 46.228 esperados até ali)** — cortada por contenção de CPU, sem JSON.
- Re-varredura dos 14.002 plaintexts do agente: 12.788.256 janelas nas duas ordens (só `1GSMG`), nested
  0, printable máx 0,57, EBCDIC máx 0,361. (Os plaintexts das extensões do crítico — 114.725 — não foram
  re-varridos por ele; o sintetizador os cobriu com dois endereços, §3.5.)

**Resultado.** Negativo confirmado dentro da cobertura: a forma que a síntese do atlas apontava como "a
mais provável" (reuso de um fato pessoal do material por concatenação verbatim) está esgotada até aridade
3 no inventário (minúsculo completo; verbatim a 67,5 %), aridade 6 na lista curta, 7 materiais e
separadores. **Fica de fora**: os 315.136 candidatos restantes de `T3_verbatim_completo`; aridades 4–6
fora da lista curta; glosa/paráfrase (a 3.2 reescreve "Sometimes, just one second." como
`giveitjustonesecond` — não enumerável por regra mecânica); itens do mundo dele que o repositório não
registra; e a leitura de que "close friends" aponta para o laptop escondido, e não para uma string.

## 3. Verificação do sintetizador (`solver/operador_ensinado_2026_09_17/sintese_verificacao.py`, log `sintese/`)

### 3.1 Hits alegados: nenhum
`grep` por `hard|semantic|hit: true` em todos os JSONL/JSON/gz da rodada devolve **um** registro:
`familia5_dualidade.jsonl` linha 2, `tipo: controle_positivo` — a fase 2 abrindo com `causality`. Todos os
`hits.jsonl` têm 0 bytes; todos os campos `hits_duros` são `[]`. Não há o que reproduzir como solução.

### 3.2 O excesso de padding em F5 (família 6) é contagem real e é acaso
O crítico da F6 mediu 684 paddings em 151.200 decifrações na sub-família `F5_shortlist` (3 materiais do
agente + 4 dele), contra 593 esperados: z = +3,75, p unilateral 9 × 10⁻⁵, **0/200 réplicas nulas ≥ 684**
(nulo específico embaralhando os caracteres dos 3.600 candidatos, máx 670). Reproduzi do zero com
EVP_BytesToKey e PKCS7 próprios, decifrando os blobs inteiros: **684 paddings, 25.200 senhas distintas
(sem duplicata), por material exatamente os números do agente (97/81/104) e do crítico (95/119/104/84)**,
por célula 111–118 (uniforme), comprimentos de padding 682 × 1 e 2 × 2 (a geométrica esperada). Ou seja:
não há erro de contagem nem ensaio repetido; é um desvio de +91 sobre 593 em ensaios Bernoulli
independentes. **Não é sinal**, por três razões: (a) uma senha certa produz **um** plaintext, não mais
paddings em senhas erradas — não existe mecanismo pelo qual um conjunto de chaves erradas eleve a taxa de
padding; (b) o excesso está espalhado por 7 materiais e 6 células, sem concentração; (c) a rodada testou
da ordem de 350 células blob×KDF×sub-família (30 na F1, 10 na F2, ~40 na F3, 42 na F4-A3, 210 na
F4-multibyte, 12 na F5, ~27 na F6), e o máximo de |z| entre ~350 células normais fica em 2,9–3,1; um
+3,75 tem p ≈ 0,03 corrigido pelo look-elsewhere da rodada inteira. Fica registrado como o maior desvio de padding
observado no projeto até hoje, para que ninguém o "descubra" de novo.

### 3.3 O braço C5 do crítico da F4
247.594 registros `C5_det` (247.561 `ascii85+hex64`, 33 `ascii85+wif`) sem resumo. Decodificados:
247.536 dão 32 B; testados como privkey nas duas ordens, formatos comprimido e não comprimido, contra a
pubkey de `1GSMG` e os h160 dos dois endereços: **0** (9 s). Os 33 "WIF" são frases de texto
("the private key is 5KJvsngHe…", `dbbi`, o plaintext da fase 2) e não passam no checksum base58.

### 3.4 O oráculo de dois endereços
`solver/oracles.py` e `G.fast_priv_scan` só comparam com a pubkey de `1GSMG1JC9…` (1,256 BTC, gastou,
pubkey exposta). O segundo endereço do prêmio, `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` (3,751 BTC, 45 tx,
nunca gastou, só h160), **nunca tinha sido alvo** de nenhuma varredura de privkey do projeto. O
orquestrador escreveu `oraculo_dois_alvos.py`/`retro_dois_alvos.py` e re-varreu **694.386 plaintexts
distintos** de todo o `_work/` (81.862.702 janelas nas duas ordens, controle plantado achado no offset
13): 0. Os críticos das F2 e F5 usaram o oráculo de dois alvos; os demais não. Isso é uma correção de
oráculo do mesmo tipo da de 2026-09-17 (blob aninhado / EBCDIC) e deve entrar no kit.

### 3.5 Re-varredura consolidada desta rodada (dois endereços, duas ordens)
Coleta de todo campo `hex`/`plain_hex` em 25 arquivos da rodada (JSONL, JSON e JSONL.gz, inclusive as
extensões dos críticos que ninguém re-varreu): **1.331.160 blobs distintos (1.083.580 plaintexts AES +
247.580 de material C5), 156,9 MB, 231.207.492 janelas de 32 B previstas**.
**Resultado** (a V4 original morreu no `spawn` do multiprocessing quando o processo-pai encerrou — `WinError
87`; refeita pelo orquestrador com `v4_rodada_dois_alvos.py`, que reusa o `work()` de `retro_dois_alvos.py`):
**231.207.482 verificações de curva** (toda janela de 32 B nas duas ordens + hex64 + WIF, pubkey comprimida
e não comprimida, contra os h160 dos dois endereços), 25 arquivos, **0 hits**. Log em
`orquestrador/v4.log`, resultado em `orquestrador/v4_resultado.json`.

### 3.6 `first_hint_literal.py` (orquestrador; não tinha log)
"our first hint is your last command" lido como: o primeiro hint público (22/04/2019, o sha256 de
`theflowerblossoms…` = `5ac40783…746f75`) é o argumento `-pass` do último comando. 86 materiais (o hash
nas formas de argumento, bytes crus, linhas de comando literais, composições com os rótulos vizinhos,
sha256 iterado 1–8) → 217 senhas, 1.302 AES, 0 hits, 5 paddings (esperado 5,1). Sondas de URL
(`segunda_porta_sondas.log`): 10 caminhos `sha256(título+B…)` em gsmg.io → todos 404 (`Hello :-)`),
controle 200 no caminho da fase 0.

## 4. O que a rodada corrige no método (vale para toda campanha futura)

1. **Denominador do padding.** `G.unpad` aceita comprimentos 1–16, logo a probabilidade de padding válido
   em ruído é Σ_{p=1..16} 256^-p = 0,0039216 (≈ 1/255), não 1/256 = 0,0039063. A diferença é invisível
   em n = 10⁶ (z ≈ +0,26) e vale z ≈ +2,6 em n = 10⁸ — a F3 mediu z = +2,71 vs 1/256 e +0,14 vs o valor
   certo. A banda "−1,2 … +2,1" de ENDGAME §3-9 foi calibrada em 720 k e continua válida nessa escala;
   scripts com ≥ 10⁷ ensaios devem usar o valor exato (a calibração de 6 M do crítico da F6 dá 0,003894,
   compatível com ambos).
2. **Teto de `printable` depende do número de paddings.** Com ~143 k paddings por blob de 80 B o máximo
   por acaso é 0,62–0,65 (nulo casado da F3), não ~0,60; em COSMIC (1.328 B) é 0,44. Máximos reais desta
   rodada: 0,656 (F3, 80 B), 0,57 (F6), 0,557 (F1), 0,544 (F2/F5). Nenhum acima do teto da sua escala.
3. **Oráculo de dois endereços** (§3.4): `priv_hit` deve comparar também com o h160 de `17ucy…`, nas duas
   ordens de byte.
4. **L83 ≠ L84 nos bits.** `BITS[83] = 00001000110000100110011` (último bit 1). Qualquer script que
   alimente um operador com "a saída de `yellowblueprimes`" tem de gerar as duas.
5. **Tautologias do oráculo com decoders.** (a) `printable ≥ 0,85` sobre saída de decoder é vácuo (já
   conhecido); (b) a direção *decode* de um codec EBCDIC aplicada a texto ASCII minúsculo cai na imagem
   EBCDIC de a–z por construção e faz `G.ebcdic_sig` disparar com informação zero. A F4 gerou 48 falsos
   candidatos assim antes de corrigir.
6. **Nulos com subamostra ou cap devem dizê-lo.** Dois agentes (F5-E com `NULL_CAP=2000`, F6 com 400
   candidatos por rodada) publicaram z de nulos que não correspondiam ao procedimento descrito; o z
   binomial exato contra a taxa PKCS7 é o controle barato que sempre deve acompanhar o nulo empírico.
7. **Serializações invariantes à permutação** (soma de ordinais) não podem entrar num nulo de embaralhamento
   de palavras: 26 % das senhas "nulas" da classe RAB da F2 eram idênticas às reais.
8. **Cobertura "distinta" é por conjunto global, não por tarefa** (F3: 9,11 M → 8,84 M; F5: 10.920 →
   10.279). A inflação foi pequena nos dois casos, mas a regra fica.

## 5. O que ficou declaradamente de fora (consolidado)

- F1: agrupamentos não contíguos das 23 palavras da 3.2; o número RAB como parâmetro (índice,
  transposição, deslocamento) em vez de senha; encadeamento além de RAB∘z_method.
- F2: transcrições além do `MISC.txt` local; 16 tamanhos de janela nas 4 ocorrências que só o crítico
  janelou; composições de 3+ falas.
- F3: entrelaçamento não round-robin ou em bits; k misto; inversões parciais fora de S0/k ≤ 2; 13 fios;
  operando 5 em maiúsculas (estágio `o5up`, escrito e não rodado); COSMIC inteiro em 1.704/1.904 tarefas.
- F4: codecs em fatias (vácuo sobre alfanumérico); braço privkey do C5 fechado pelo sintetizador; C6 do
  crítico coberto por `critico_codecs23` só nos tokens.
- F5: coordenadas reais das estrelas da capa (insumo ausente); triplas sha(sha‖sha‖sha) e quádruplas;
  cortes por ponto em dígitos/codec z; nulo casado para X2.
- F6: 315.136 triplas verbatim restantes; aridades 4–6 fora da lista curta; glosas/paráfrases; itens
  fora do repositório.
- Todas: qualquer caminho fora de `openssl enc -aes-256-cbc -pass pass:` com EVP-MD5/SHA256 (as
  premissas de cifra, `-K`, `-kfile` e KDF estão fechadas em ENDGAME §4-D e não foram reabertas).

## 6. O que isto muda no mapa

**Nada na fronteira.** Nenhuma família produziu hit, fato estrutural novo sobre `dbbi`/`faed` ou
desambiguação de L83/L84. O diagnóstico de ENDGAME §6 ("falta informação, não busca") sai reforçado: seis
negativos consecutivos com nulo casado e verificação adversarial, somados aos nove de 2026-09-17, deixam a
regra de parada (cinco negativos ⇒ esperar insumo do criador) satisfeita três vezes.

O que a rodada **fecha ou corrige** no `ENDGAME.md` (a editar pelo orquestrador):

| Onde | O que | Estado |
|---|---|---|
| §4-C, linha "seven intertwined … entrelaçado" | a cobertura registrada era de `v3_interleave.py` sobre 9 tokens de roadmap/página, k=1, sem inversão/caixa — **não** cobria os 7 operandos de nível-senha | agora coberta: 28 conjuntos, k 1–9, políticas, inversões, caixas, 5 formas, ≈ 255 M AES, 14,6 M privkeys. A linha deve declarar o conjunto |
| §4-C, nova linha | `matrixsumlist` como operador RAB (a1z26 → soma \| lista) sobre 184 + 680 objetos e a saída de `yellowblueprimes` em L83 **e** L84 | fechada (≈ 2,0 M AES, 356 k privkeys) |
| §4-C, nova linha | `lastwordsbeforearchichoice` literal: 5 ocorrências de "choice", duas grafias, blocos cortados, RAB/codec z/composições | fechada (70.340 senhas, dois endereços) |
| §4-C, nova linha | "twenty-three ciphers" como codec: 65 codecs de byte único **colapsam em 2 imagens** sobre [a-z0-9] na direção *encode* (3–7 por campo contando as duas direções, §9); 7 imagens multi-byte cobertas nos tokens; fases 2/3 sem bytes altos | fechada como família; fato estrutural sobre o espaço, não sobre o puzzle |
| §4-C/§4-E, nova linha | dualidade: blob como senha do outro, metades (todos os pontos de corte), XOR, complemento, estrelas (proxy), pares/triplas de 51 representações, COSMIC em todo limite de 16 B | fechada exceto a capa real |
| §4-C, nova linha | referência pessoal por concatenação verbatim: 104 itens, aridade 1–3 (minúsculo completo, verbatim 67,5 %), 4–6 na lista curta, 7 materiais, separadores; 454 k brainwallets | fechada dentro da cobertura; glosa não enumerável |
| §3-9 (ruído calibrado) | acrescentar: p de padding = Σ256^-p ≈ 1/255 (z +2,6 em 10⁸); teto de `printable` 0,62–0,65 em ~143 k paddings/blob; maior desvio já visto = F5 da F6, z +3,75, reproduzido, acaso | correção de calibração |
| §3-7 (oráculo) | acrescentar o segundo endereço `17ucy…` ao oráculo; retro 694 k plaintexts + 1,33 M desta rodada: 0 | correção de oráculo |
| §6 | explicitar que L83 e L84 diferem no **último bit** (`…011` vs `…010`) e que as três seleções de cor de L83 (omitir 22/24, 23/24, 24/25) também já foram usadas como entrada de operador | precisão |

**Fato novo:** nenhum sobre o puzzle. Os fatos novos são de método (§4) e de mapa (a célula
"entrelaçamento dos sete" estava marcada como fechada sem ter sido testada no conjunto que importava).

## 7. Células que continuam abertas (prior decrescente; custo com ≈ 150 k AES/s em 18 workers)

| # | Célula | Por que ainda vale algo | Custo estimado |
|---|---|---|---|
| 1 | **Insumo do criador**: qual segmentação (L83/L84) é a pretendida; o que "zeroed out" zera; como `matrixsumlist` consome o resíduo | é o único fio (ENDGAME §6); tudo o que é simples sobre o resíduo já deu zero; o criador disse que a resposta está num laptop escondido | 0 de computação; vigilância diária já agendada (`gsmg-monitor-pistas`) |
| 2 | `dbbi` (tokens b/g) como **senha** sha256-hex do SMALL sob as 16! bijeções | a leitura privkey já deu 0 nas 16! (ENDGAME §4-B); a leitura senha é a irmã e o kernel está validado | 132 h de GPU por variante; 4 variantes ≈ 22 dias (`solver/gpu_aes16_dbbi_hex/launch.py`) |
| 3 | F3: operando 5 em maiúsculas (`THEMATRIXHASYOU`) e COSMIC inteiro nas 1.704 tarefas restantes | lacunas mecânicas de uma família já fechada; prior baixo, custo mínimo | ≈ 30 M AES ≈ 4 min; COSMIC ≈ 30 M AES de 1,3 kB ≈ 15 min |
| 4 | F6: 315.136 triplas verbatim restantes; aridade 4 sobre o inventário inteiro | a gramática das fases é a única que o puzzle usou; mas a aposta explícita do atlas (lista curta) já caiu | 5,7 M AES ≈ 1 min; aridade 4 ≈ 96⁴ × 18 ≈ 1,5 bi AES ≈ 3 h |
| 5 | F1: agrupamentos **não contíguos** das 23 palavras; RAB como parâmetro de transposição/índice | o operador é a única demonstração explícita do criador; mas todas as leituras diretas deram zero | 2²³ subconjuntos × 11 × 10 ≈ 1 bi senhas ≈ 5,5 bi AES ≈ 10 h; como parâmetro: indefinido |
| 6 | F2: tamanhos de janela faltantes nas 4 ocorrências; transcrição jaced.com | fechamento mecânico; exige rede para a transcrição | ≈ 25 k senhas ≈ 150 k AES ≈ segundos (+ download) |
| 7 | F5: coordenadas reais das duas estrelas da capa de *Cosmic Duality*; quádruplas das 51 representações | ".... That is very specific" (2022-12-11) sobre a capa nunca foi materializado porque não há scan no repositório | obter a imagem (insumo); quádruplas 51⁴ × 2 × 6 ≈ 81 M AES ≈ 10 min |
| 8 | Herdadas de ENDGAME §5/frontier: braço AES da seleção de 256 bits de `faed`; concatenação ordenada de 7 dos 16 tokens b/g (P(16,7) = 57,7 M, 0,4 % coberto) | prior baixo; ambos sem indício positivo | ≈ 20 M AES ≈ 3 min; 57,7 M × 12 ≈ 692 M AES ≈ 1,3 h |
| 9 | F3: entrelaçamento não round-robin, em bits, k misto; 13 fios | espaço mal definido ou inalcançável (13! = 6,2 bi ordens ≈ 75 bi AES ≈ 6 dias) | de horas a semanas; prior muito baixo |
| 10 | F4: codec em fatias; F6: glosa/paráfrase | espaços não enumeráveis por regra mecânica | indefinido |

Nenhuma dessas células, sozinha, justifica reabrir campanha sem o item 1. O que o projeto pode fazer com
custo zero é manter a vigilância (site, Telegram, Reddit) e o kit corrigido (§4), para que o primeiro
insumo novo do criador seja testado no mesmo dia com oráculo completo.

## 8. Scripts e logs desta rodada

| Script (`solver/operador_ensinado_2026_09_17/`) | Log (`_work/operador_ensinado_2026-09-17/`) | Papel |
|---|---|---|
| `rab_a1z26.py`; `critico_rab.py`; `critico_rab_a1z26.py`; `critico_rab_l83.py` | `rab_a1z26/`, `critico_rab/`, `critico_rab_a1z26/` | F1 agente, dois críticos, adendo L83 |
| `familia2_lastwords.py`; `critico_familia2.py`; `critico_familia2_dois_alvos.py`; `TRANSCRIPT_ARQUITETO.txt` | `familia2_lastwords/`, `critico_familia2/` | F2 |
| `familia3_entrelacamento.py`; `critico_familia3_entrelacamento.py` | `familia3_entrelacamento/` (summary.json, paddings.jsonl.gz 60 MB), `critico_familia3_entrelacamento/` (run.log, 2 gz) | F3 |
| `familia4_codecs.py`; `critico_familia4_codecs.py`; `critico_codecs23.py` | `familia4_codecs/`, `critico_familia4_codecs/` (66 MB), `critico_codecs23/` | F4 |
| `familia5_dualidade.py`; `critico_familia5.py`; `critico_familia5_verificacao.py` | `familia5_dualidade/`, `critico_familia5/` | F5 |
| `familia6_referencia_pessoal.py`; `critico_familia6.py` | `familia6_referencia_pessoal/`, `critico_familia6/` (≈ 230 MB de paddings em hex) | F6 |
| `oraculo_dois_alvos.py`; `retro_dois_alvos.py`; `first_hint_literal.py` | `orquestrador/` | oráculo de dois endereços, retro, sondas |
| `sintese_verificacao.py` | `sintese/` (sintese.jsonl, v4_por_arquivo.json, v4_run.log) | esta síntese (§3) |

## 9. Adendo do orquestrador: críticos finais, V4 e kit

Os críticos de F1, F3 e F4 do workflow caíram por falha de rede (`ENOTFOUND`) na retomada. O orquestrador
os relançou como agentes avulsos, com o mesmo roteiro (reproduzir, auditar o oráculo, nulo, look-elsewhere,
completar, re-varrer contra os **dois** endereços). Os três deram **CONFIRMADO_NEGATIVO**. Relatórios
próprios em `critico_rab_final/`, `critico_codecs_final/` e `critico_sete_final/`.

**F1 (RAB), `critico_rab_final.py`.** Recontagem byte a byte do agente (9.722 senhas, 58.332 AES, 10.994
privkeys, paddings por célula idênticos). Correções: (i) `critico_rab.py` dizia testar "os dois endereços"
mas chamava `O.check_privkey`, que só testava `1GSMG` — **afirmação falsa**, refeita: 253.159 privkeys
únicas das quatro rodadas contra os dois h160, 0; (ii) os 23 bits dos marcadores sempre tinham sido lidos
como dígitos decimais, nunca como **inteiro binário** — fechado (L83/L84 × polaridade × ordem, 56 senhas,
64 privkeys, 0); (iii) "184 objetos" são 152 distintos sob o operador e "10 formas" são 8 (a deduplicação
já absorvia a redundância; os totais estão certos); (iv) o `critico.jsonl` do crítico anterior está
truncado com NULs, e o nulo da extensão de 219.630 senhas nunca rodou — rodado agora, 100 réplicas, z
−2,24 … +0,52. Look-elsewhere contra o binomial exato 1/255 em 30 sub-famílias: maior |z| 2,23 (um
déficit), Šidák p = 0,54. União verificada das quatro rodadas: **230.506 senhas, 1.383.036 AES**. Re-varredura
de 5.306 plaintexts únicos: 5.032.084 janelas, dois alvos, 0.

**F4 (codecs), `critico_codecs_final.py`.** Controle cp273 reimplementado caractere a caractere, sem as
tabelas do agente: a–z = 1,000 sob cp273 e 0,000 nos 57 não-EBCDIC. Correções: (i) o colapso "65 codecs →
2 imagens" vale só na direção *encode*; nas duas direções são 3–7 imagens por campo; (ii) os números A1 do
JSON (53.573 / 95 arquivos, z +3,14) são de uma execução anterior — a final dá z −0,27; o +3,14 era
estatística de máximo sem look-elsewhere; (iii) 323.591 registros do corpus final vinham de logs de
críticos, não de material novo; (iv) **furo de oráculo**: o oráculo duro do agente sobre a saída traduzida
devolve `None` para o positivo conhecido (o campo 3 da 3.2 em cp273 é Beaufort, não inglês), logo "699
disparos, 0 duros" não excluía um segmento estilo 3.2. Fechado auditando os 699 um a um com Beaufort/
`THEMATRIXHASYOU`: melhor leitura de 8 letras, p = 0,013 no nulo de máximo (o nulo produz o mesmo), 0 duros.
Censo de 22 codecs multi-byte (CJK, ISO-2022, HZ, UTF-7/8): nenhuma imagem além das 7 UTF já varridas.
Re-varredura de 3.761 plaintexts: 2.903.074 janelas, dois alvos, 0.

**F3 (entrelaçamento), `critico_sete_final.py` (+ Go para as janelas do COSMIC).** O z = +2,71 do agente é
**provado** artefato de denominador pelo histograma de comprimentos de padding do próprio log (427.022 × 1,
1.676 × 2, 8 × 3 contra 426.937,5 / 1.667,7 / 6,5 esperados; χ² 0,4 com 3 g.l.): contra 1/255, z +0,14;
corrigido pela duplicação de materiais, +0,138. Células blob × KDF × forma: χ² 13,4 com 11 g.l., p 0,34.
Cobertura nova: **o5up** (operando 5 como `THEMATRIXHASYOU`, a grafia do README) — 2.513.880 senhas,
30.166.560 AES, z −1,48, 0; **COSMIC inteiro regenerado** nas 1.904 tarefas (o agente só logou 64 B):
36.432.000 AES reproduzidos byte a byte, 143.225 paddings idênticos, 371,5 M janelas de 32 B, 0;
privkeys nas duas chaves: 9.108.000 + 2.513.880 = **11.621.880**, 0; re-varredura de 983.620 plaintexts
(84.562.790 janelas, integridade 100 %), 0. Verificação do orquestrador na fonte: o entrelaçamento
histórico (`_work/frontier_2026-09-17/rodada1_scripts/critic/v3_interleave.py`) usou os nove tokens
`yellowblueprimes, matrixsumlist, lastwordsbeforearchichoice, yinyang, thispassword, enter, sha256,
anstoo, ourfirsthintisyourlastcommand`, k ∈ {2,3,4,5,7} permutações, sem inversão, caixa ou blocos —
interseção vazia com os sete operandos de nível-senha. A correção de mapa de §6 está confirmada.

**V4** (§3.5): 1.331.155 blobs distintos, **231.207.482 verificações, 0**.

**Kit corrigido nesta rodada.** `solver/oracles.py` ganhou `PRIZE_ADDR_2`, `TARGET_H160_2`,
`PRIZE_ADDRS`, `TARGET_H160S`; `check_privkey` e `check_mnemonic` comparam os dois endereços;
`G.fast_priv_scan` compara o h160 das duas formas de pubkey com os dois alvos e mantém o retorno antigo
(tupla de 3), e o self-test do kit ganhou um controle plantado para o caminho novo. `python gsmg_common.py`
e `python oracles.py` passam.

**Totais finais da rodada, somando os críticos refeitos** (ordem de grandeza; cada número exato está no
relatório da família): ≈ 355 M decifrações AES reais, ≈ 30 M privkeys diretas, ≈ 1,1 bi janelas de 32 B,
dos quais ≈ 600 M contra os dois endereços. **Zero hits duros.**
