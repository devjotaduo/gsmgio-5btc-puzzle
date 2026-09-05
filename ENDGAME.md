# Endgame — SalPhaseIon / Cosmic Duality (estado da resolução)

Consolidação **verificada** do estado do endgame do puzzle GSMG.IO 5 BTC.
Princípio: o puzzle **tem solução** — aqui se registra o que é sinal e o que já
foi refutado, para não repetir becos. Negativos são reportados porque *estreitam*
o problema. Fontes: issues/PRs do GitHub (#68, #82, #88, #93), export do Telegram
(`result.json`), e verificação local própria.

## On-chain
Prêmio ainda **não sacado**: ~1.256 BTC em
[`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`](https://www.blockchain.com/btc/address/1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe)
(≈125 txs, todas "dust"). Nenhuma "solução" pública é real.

## A fronteira real
**Correção 2026-08-30:** Chain1→4 é uma construção reproduzível, não uma solução
validada. Os primeiros “plaintexts” têm alta entropia e passaram somente no padding
PKCS#7; recriptografar os mesmos bytes e obter os mesmos hashes não é um oráculo
independente. A [issue #104](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/104)
documenta a retratação. A fronteira verificável volta a ser a derivação da senha que
produza plaintext semântico nos blobs AES originais da página SalPhaseIon/Cosmic.

Varreduras reproduzíveis desta correção:

- `solver/salphaseion_passphrase_sweep.py`: 231.993 senhas derivadas dos tokens da
  página, da cena do Arquiteto (inclusive pontuação original) e dos hints primários;
  1.780 paddings aleatórios, nenhum plaintext com ≥85% ASCII no blob pequeno;
- `solver/architect_sum_attack.py`: pareamento das somas de linha/coluna da matriz
  14×14 com os 14 finais de linha antes de `SELECT`, e das 15 somas de `faed` com as
  últimas 15 palavras; 6.492 senhas, zero plaintext semântico;
- `solver/dbbi_repeat_attack.py` e `solver/joint_attack_v2.py`: as somas literais do
  bloco `dbbi` em 7×13/13×7, três mapeamentos e duas famílias de cifra produziram
  33.350 + 6.696 construções; o melhor score (`-6.637`) ficou abaixo de inglês (`-4.5`);
- `solver/faed_matrix_sum_attack.py`: `faed` em 15×38 com a=0 produz a lista
  `[140,171,129,168,150,174,184,176,188,179,175,179,169,164,163]`. O primeiro
  valor repete o “hundred fourty” da fase 3.2 e o último repete o índice espiral
  `163` do pixel `#FEFEFE`, um encaixe estrutural novo. Como índices BIP39, a lista
  termina em `behave` com checksum inválido; preservar os 160 bits de entropia e
  recalcular só o checksum troca a última palavra por `bike`. Cerca de 720 mil
  derivações BIP32/BIP44, com e sem checksum e com passphrases literais, não geraram
  o endereço-prêmio; 2.436 formas da lista também não abriram o AES.

As seções de 2026-08-20 abaixo ficam preservadas como histórico de hipóteses e testes,
mas suas afirmações de “canônico”, “real” ou “validado” devem ser lidas como refutadas
por esta correção.

O endgame reduz a decodificar **duas strings** sobre o alfabeto de 9 símbolos `a–i`,
ambas extraídas da página SalPhaseIon:

| String | Tamanho | Natureza (medida) |
|---|---|---|
| **`dbbi`** | 91 = 7×13 | **chave estruturada/decodificável** — IoC 0.151 (uniforme-9 = 0.111); `b`=27%,`e`=20% |
| **`faed`** | 570 = 15×38 | **payload de alta entropia** — IoC 0.118 ≈ uniforme, sem n-gramas repetidos |

- **Família da cifra = VIC / straddling checkerboard**, validada reproduzindo a fase
  3.2.2 já resolvida (`INCASEYOUMANAGE…`). `matrixsumlist` = passo de over-encryption mod-9.
- Casamento chave↔grade: `len("matrixsumlist")=13` ↔ `dbbi`(13×7);
  `len("lastwordsbeforearchichoice"+"thispassword")=38` ↔ `faed`(15×38).
- **Pipeline:** `sha256(first hint)` → decodifica a chave de `dbbi`/`faed` → **ANSWER**
  → `sha256(ANSWER)` = chave AES → abre a Cosmic Duality. (leitura de "shabef … ans too")
- **Bloqueio = interpretativo, não computacional.** Cada palpite fixa só 1 de ≥4
  incógnitas (alfabeto do checkerboard + mapeamento `a–i`→dígito + transposição +
  keystream), e não há sinal de verificação até o loop AES fechar. Busca cega não
  converge (o ataque conjunto de 4 parâmetros do PR #93 fez 4904 formas → 0 hits).

## Campanha 2026-07-14 — framework GPU/oráculo + 8 frentes control-validadas (NÃO repetir)
Construí um harness reprodutível em `solver/` (Llama local propõe, GPU criptanalisa,
oráculos DUROS julgam: endereço BTC / BIP39-checksum / padding-AES). Cada motor de GPU é
**control-validado** (recupera um texto inglês *conhecido* cifrado, então seus negativos
têm peso — não são incapacidade). Todas as frentes abaixo deram NEGATIVO por oráculo:

1. **Bifid período-curto** (`gpu_search.py`): GA na GPU, controle período-15 = 100% match.
   No faed: empaca em −5.5 (ruído). Período-570 (que dá BTCSEED) é indecifrável por busca
   de quadrado (o quadrado CANON é dado pelo dbbi, não buscável).
2. **Straddling checkerboard / VIC** (`gpu_checkerboard.py`): a cifra provada da fase 3.2.2;
   encaixe 9 símbolos → 7+9+9=25 slots. Controle 100%. No faed: −5.6 (ruído).
3. **Trifid / base-3** (`gpu_trifid.py`): 9=3², 570×2=1140=3×380. Controle 87%. No faed:
   −6.8 (pior que ruído).
4. **Chave direta** (`seed_sweep.py`): faed(base-9)/BIF(base-26)/trigramas → priv key +
   BIP39 (canônico + índices 11-bit), 2 endianidades → 50 priv + 250 BIP39, 0 hit.
5. **Keywords da comunidade** (`interpret.py`): llama3 leu 1088 msgs sobre o "first hint"
   → 96 quadrados Polybius testados vs oráculo. Nenhum supera o CANON.
6. **Prime basics** (`prime_attack.py`): fato VERIFICADO — no dbbi, `d` é a única letra só
   em posições não-primas. 104 construções (máscaras prime, zerar D, keystream de primos)
   → 0 solve, top −5.28.
7. **matrixsumlist+enter** (`matrixsum_attack.py`): a LISTA real de somas (row=[6,10,8,7,6,
   6,5,4,9,9,7,8,7,9]) como keystream mod-9 e transposição colunar, antes/depois do Bifid.
   186 construções → 0 solve, top −6.36.
8. **Frases dadas pela página** (`focused_aes.py`): sha256("our first hint is your last
   command") e todas as frases (lastwordsbeforearchichoice/thispassword/enter) com gramática
   HASHTHETEXT vs SMALL/COSMIC → 185 senhas, 0 hit.

**Correções estruturais desta campanha (releitura crua, sem assumir BTCSEED):**
- `enter` (2ª seção abba) está **embutido no blob AES**, entre os dois chunks base64
  (`...rd9` `z` `[enter]` `QvX0...`) — **não** é instrução do faed.
- o `z` entre os chunks é **necessário** para o base64 do SMALL fechar (128 chars → ct 80B).
- SMALL como `c1z` sozinho (2 blocos) também não abre com as frases dadas.

**Meta-conclusão:** o espaço computacional das hipóteses conhecidas está esgotado; tudo que
se constrói sobre o anchor BTCSEED falha. Possível que BTCSEED seja coincidência (viés
B/C/D/E favorece a palavra). O desbloqueio real = info externa nova (próximo hint do criador)
ou uma leitura do faed que a fixação no BTCSEED cegou. Controlar via skill `/gsmg-solver`.

## Becos FALSOS — verificados localmente (NÃO repetir)
1. **Afim base-9 (issue #51)**: o bloco `faed`(570) → "Cryptography is the practice…"
   via afim (a=5,b=8). **Falso**: a chave dele gera hex `29d23a21…`, não o `43727970…`
   ("Crypto…") postado; nenhuma das 54 chaves afim invertíveis dá ASCII. Alucinação.
2. **XOR key `818af53daa…`** (issues #69/#79/web): reproduz do XOR de sha256 de 7
   tokens, mas **não decifra** (padding PKCS7 do último bloco inválido; independe do IV).
3. ~~**XOR key `a795de117e4725…`** (PR #68): também falha no padding como `-K` direto no
   formato salted.~~ **CORRIGIDO 2026-07-23 — o beco estava ERRADO.** `a795de11…` **não**
   é chave `-K`: é a **PASSPHRASE** do Cosmic (os 32 bytes RAW via EVP_BytesToKey/MD5,
   como `openssl -pass`). Re-verificado localmente: padding PKCS7 **válido** (0x01) →
   **1327 bytes**, `sha256 = 4f7a1e4efe4bf6c5…a5e9c081` (anchor da comunidade, match
   exato). O corpo é 38,9% ASCII — near-random **de propósito**: é uma matriz de bits,
   não texto (por isso `aes_open`, que exige ≥90% ASCII, sempre devolveu `[]`).
   Ver seção "Cadeia GalloClaudio64" abaixo.
4. **Senhas AES diretas**: oráculo de padding sobre centenas de candidatos temáticos
   ({raw,upper,lower,sha256hex} × {sha256,md5} KDF) na Cosmic **e** no blob pequeno do
   SalPhaseIon → só falsos positivos (~esperado por acaso; todos <45% ASCII). Confirma
   que o pipeline exige decodificar `dbbi`/`faed` **antes**.
5. Refutados pelo PR #93 (com null-model): "matrixsumlist triangle" (apophenia),
   esteganografia nas PNGs, book cipher (Cosmic 0/27, Game of Logic 1/27).

## Becos FALSOS — sessão 2026-07-14 (verificados localmente, código no scratchpad)
Cinco testes, todos NEGATIVOS mas cada um estreitando o problema. Cada script é
reprodutível e usa oráculos/controles (não é palpite):
6. **Substituição monoalfabética sobre `BIF_REST`** (os 563 chars pós-BTCSEED):
   hill-climb com 40 restarts × modelo de quadgramas EN (corpus = `result.json`) e
   BIP39. **Controle validado**: um texto inglês real de 563 chars cifrado por
   substituição aleatória foi recuperado a **97,3%** (score/char −4,37). O `BIF_REST`
   real pontua **−5,45** — pior que uma string-25 aleatória (−4,56). **Não é inglês
   nem BIP39 por substituição** (coerente com o viés B/C/D/E e IoC 0,094).
7. **Período do Bifid**: varredura 2..570 do período de transposição, incluindo os
   temáticos `101`(matrixsumlist)`,91,13,38,7,15,16,140,163`. **Só o período 570
   (comprimento total) produz `BTCSEED`**; nenhum outro período dá saída legível ou
   palavra-âncora. A transposição do Bifid é de mensagem inteira, não em blocos.
8. **Método ensinado (a–i→1–9 → base-16 → hex→ASCII)** aplicado ao `faed` inteiro.
   Este é o método que o próprio README usa logo acima do faed; **reproduzi
   `lastwordsbeforearchichoice` e `thispassword` exatos** (prova de aplicação correta).
   No `faed` completo → lixo (33% ASCII). O payload longo não usa o mesmo método.
9. **`matrixsumlist` como keystream mod-9 sobre `faed`** (a "over-encryption"):
   somas de **linha** `[6,10,8,7,6,6,5,4,9,9,7,8,7,9]` e **coluna**
   `[8,10,8,10,8,7,3,6,7,5,9,6,6,8]` (ambas somam 101), soma **e** subtração, todos
   os 14 offsets, antes do Bifid — **todas destroem o BTCSEED**. Transposição colunar
   por matrixsumlist idem. **BTCSEED sai do `faed` CRU**: matrixsumlist NÃO é
   over-encryption pré-Bifid sobre o faed (elo "(a)" eliminado — seu papel, se houver,
   é em outro ponto: alfabeto, dbbi, ou pós-Bifid).
10. **`BIF`/`BIF_REST` como material de chave direto** (oráculos DUROS: endereço BTC
    comprimido/não vs. `1GSMG…` e h160-alvo `a9553269…`, BIP39 com checksum, WIF):
    refractionação base-5 das coordenadas do quadrado, A1Z26→índices BIP39, base-26→
    priv, nibble→hex, `sha256(*)`. **Zero hits reais.** O único "BIP39 válido" é um
    falso positivo degenerado (9/15 palavras distintas, todas das 26 primeiras da
    wordlist — coincidência de checksum ~1/32; não deriva endereço relacionado).

## Becos FALSOS — sessão 2026-07-19 (grafo vetorial + pistas color-prime)
Nova abordagem: criei/rodei um **grafo vetorial textual local** sobre README, docs,
solver e `result.json` (`solver/vector_graph.py`, 7456 chunks) para puxar conexões
semânticas não óbvias. O grafo destacou três leads recentes do Telegram:
`abcdefghi → 2 56 1 34 789`, `yellow blue prime sum list (17,41)` e
`24 colored squares = 24 primes < 91 = len(dbbi)`. Todos foram convertidos em testes
pequenos, falsificáveis, com oráculos duros:

11. **Permutação `abcdefghi→256134789` + `17/41` como alfabeto/quadrado/senha**
  (`solver/alphabet_group_attack.py`): 273 construções. Testei a permutação direta,
  inversa, quadrados Bifid derivados do prefixo reordenado, keywords temáticas
  `YELLOWBLUEPRIME1741`, `MATRIXSUMLIST1011741`, períodos temáticos
  `[570,285,190,114,95,57,41,38,19,17,15,13,7]` e senhas diretas/sha256.
  **Zero hits** em AES SMALL/COSMIC e privkey. Melhor candidato continuou sendo o
  baseline canônico `BTCSEED...` (`identity|canon|p570`, score −5.577).
12. **24 casas coloridas ↔ 24 primos menores que 91 aplicadas ao `dbbi`**
  (`solver/colored_prime_dbbi_attack.py`): 182 construções. Mapeei a sequência
  espiral `BBBBYBBBYYBBBBYBBYYBYYBY` aos primos 1-indexados
  `[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89]`;
  zerei/removi/substituí letras nos primos amarelos/azuis e usei o `dbbi` mutado
  como fonte de keyword Bifid. **Zero hits** em AES/privkey. Mutar amarelos não
  altera o quadrado canônico; mutar azuis piora a legibilidade.
13. **`Y=17`, `B=41` como keystream mod-9 aplicado diretamente ao `faed`**
  (`solver/color_prime_faed_shift.py`): 208 construções. Estrutura testada:
  `len(faed)=570=6×91+24`, seis blocos de 91 + cauda de 24; nos 24 primos de
  cada bloco, converter `a-i` pela pista `a→2,b→5,c→6,d→1,e→3,f→4,g→7,h→8,i→9`,
  somar/subtrair `B=41≡5` ou `Y=17≡8 (mod 9)`, com `FEFEFE`/primo 73 como
  original/neutro/azul/amarelo; depois Bifid canônico e oráculos. **Zero hits**.
  As melhores saídas com `nonprime=to_a` são artificiais (`ETET...`) e piores que
  o baseline; com `nonprime=keep`, nenhuma melhora o `BTCSEED` canônico.

**Saldo:** a frente color-prime em suas leituras naturais agora também está coberta por
negativos reprodutíveis. O lead `abcdefghi→256134789` parece útil como anotação de
comunidade, mas não como permutação direta do alfabeto/payload. Continua faltando uma
operação **inequívoca** que conecte `yellow blue primes`/`FEFEFE` ao pipeline sem destruir
o único sinal robusto (`BTCSEED`).

## Pistas do criador (Jrk Bgrt / @SoWut) — Telegram
- "At least a **prime number** is very important to get any further." (2023-01-09)
- "Some characters need to be **'zeroed out'**." + "prime positions" (2021-12-26) — no
  `dbbi`, a letra `D` é a única fora de posição prima.
- "Another door might be found on **{1},{4},{21}**" (2021-04-01). (cf. escape digits ≈ 1,4)
- "Are you really looking for **just the btc…**?" (2023-08-03) — o alvo é uma seed/chave.
- "It **can be solved**, albeit very difficult… you have to understand how to interpret
  all the hints." (2023-04-14)
- Decentraland: áudio → espectrograma → **HASHTHETEXT**.

## "btcseed" — VERIFICADO como sinal real (mas loop não fecha)
Reproduzi e testei a alegação do Sycorax de forma rigorosa (própria, 2026-07-08):
- **Bifid(`faed`, período 570)** com o alfabeto `DBIFHCEGAKLMNOPQRSTUVWXYZ` — keyword
  = ordem de 1ª ocorrência de `dbbi` (`d,b,i,f,h,c,e,g`) + filler alfabético (construção
  **canônica** de Políbio) → **`BTCSEEDDEOEMCKEAD…`**. Reprodução confirmada.
- **Teste de hipótese nula**: em 3000 alfabetos totalmente aleatórios, **0** dão "BTCSEED";
  fixando o keyword e randomizando só o filler, **1/3000**. Ou seja, o alfabeto canônico
  derivado de `dbbi` (o parceiro estrutural de `faed`) acerta um evento raríssimo e
  tematicamente perfeito. **É sinal, não apofenia** — a direção `dbbi`→keyword,
  `faed`→Bifid está muito provavelmente correta, e "btcseed" é um **cabeçalho embutido**.

**Mas o loop não fecha (ainda):**
- Os 563 chars após `BTCSEED` **não** são inglês (freq. B/C/D/E dominante); hill-climb do
  filler (ancorado no keyword de `dbbi`, sobre os 570 chars) **não** os torna legíveis.
- `sha256(saída Bifid)` (várias formas: full/rest, upper/lower, hex/raw) **não** abre nem
  o blob pequeno do SalPhaseIon nem a Cosmic Duality → o mecanismo não é
  Bifid→sha256→AES direto.
- `dbbi` como chave corrente (Vigenère mod 26, ±, sobre a saída Bifid) **não** revela o
  resto. `dbbi` via Bifid tb não dá texto.

**Implicação:** "btcseed" é um foothold REAL e verificado. O que falta é **um único passo
interpretativo** entre o cabeçalho e a seed (a natureza exata dos 563 chars pós-header —
possivelmente material de seed de alta entropia por design, ou uma 2ª camada com
parâmetro ainda desconhecido). Este é o ponto de ataque mais promissor do endgame.

## Ataque exaustivo aos 563 chars pós-"BTCSEED" (12 famílias, verificado por oráculos)
Rodei um ataque multi-agente (12 famílias × código real × oráculos duros: `aes_open`,
`bip39_valid`, `wif_valid`, `priv_to_address` vs. `PRIZE_ADDR` e `TARGET_H160`), com
re-verificação adversarial. Resultado (2026-07-08):
- **Nenhum solve.** Zero oráculos duros passaram em qualquer família: nenhuma senha abre
  `SMALL`/`COSMIC`; nenhuma extração de chave bate nos alvos; nenhum WIF/BIP39 real.
  Cobertas: BIP39, chave-direta, Vigenère/Beaufort/autokey no resto, varredura de 2760
  alfabetos×períodos, decode do `dbbi`, chave-AES-injetada, método z-segments, extração
  posicional/primos/{1,4,21}, refracionamento, matriz-keystream, combinação dbbi+faed.
- **CORREÇÃO (apofenia derrubada por verificação):** a "estrutura de 285 pares"
  (índices pares da saída Bifid ⊂ `{B,C,D,E}` = canto 2×2) **é artefato matemático** de
  período par sobre entrada A-I (que só ocupa as linhas 0-1 do quadrado). 2000 strings
  A-I aleatórias reproduzem; período ímpar 569 quebra. **Não é sinal** — não confundir.
- **Caracterização quantitativa de `BIF_REST`:** 25 letras (A-Z sem J), viés forte
  (C=95,D=86,E=76,B=65), H=3.88 bits/char, **IoC=0.094** (acima do inglês 0.067; muito
  acima de aleatório-25 0.04), χ²=779. **Não** é material de seed aleatório limpo — o viés
  é dominado pela mecânica Bifid+A-I. Assinatura compatível com uma 2ª camada de
  substituição pendente, OU com o material real não estar em `BIF_REST` cru.
- **Saldo:** o único fato robusto continua sendo o header **"BTCSEED"** (0/3000 no teste
  nulo) — real, porém **estéril**: não se estende e nenhum transform do resto fecha oráculo.
  Isso enfraquece (não mata) a hipótese Bifid: btcseed pode ser um cabeçalho real cujo
  método de payload ainda é desconhecido, ou uma coincidência rara do alfabeto canônico.

## Fase 1 — a "segunda porta" (pista real do criador, NÃO resolvida por ninguém)
O criador deixou pistas de que a matriz 14×14 da fase 1 tem MAIS que a URL
`theseedisplanted`: *"only one door... the rabbit's nest may contain a whole lot
more"*, *"Roses are White but often Red. Yellow has a number and so does Blue"*,
*"another door might be found on {1},{4},{21}"*, *"prime numbers... some
characters need to be zeroed out"*. Investigação (própria + busca na comunidade):
- **`matrixsumlist` = 101** = soma da matriz (total de 1s) — verificado. É um
  **componente de senha** do endgame (issue #32: `sha256([dbbi]+101+[faed]+[lastwords])`),
  mas o palpite exato da #32 (`gsmg101adressapril`) **não abre** os blobs. O `101`
  é o elo fase-1→endgame que faltava, mas insuficiente sem decodificar dbbi/faed.
- **Cores azul/amarelo** = paridade (blue=1/yellow=0) → redundante com a URL. As 24
  células coloridas estão exatamente nos índices espirais zero-based
  `7,15,23,...,191`, isto é, no bit 7 de cada um dos 24 bytes; a sequência
  `BBBBYBBBYYBBBBYBBYYBYYBY` coincide bit a bit com os LSBs de
  `gsmg.io/theseedisplanted`. Portanto a hipótese "posição local + sinal da cor" tem
  apenas o deslocamento constante 7: as duas orientações produzem
  `nztn'pv6malzll]pziehgml]` e `` `lf`5bh({o^l^^kblwsZu{^k ``, ambos ruído. QR =
  só o endereço. Sem vermelho oculto na matriz (a alegação de stego do `guy29278`
  não se sustenta; contestada por `wat96`). 16 mapeamentos cor→bit × travessias
  (espirais/linhas/colunas/diagonais) → só a 1ª porta aparece.
- **Leitura numérica das cores — sinal novo e reproduzível:** filtrando as 24 células
  coloridas em ordem row-major, amarelo=`1` dá `0x41D464` e azul=`1` dá o complemento
  `0xBE2B9B`. Na paleta original, azul=`#3F48CC` e amarelo=`#FFF200`; as somas dos
  dígitos hexadecimais são `54` e `47`. Assim, `54+47=101` explica `matrixsumlist` e
  `54-47=7` explica o marcador/operando `+-...7` do Chain4. O elo é forte, mas ainda
  não fixa sozinho a chave final.
- **Pixel FEFEFE** ("1 white square different", issue #14): exatamente 1 célula
  (254,254,254 em vez de 255) na posição **(7,4) = índice 163 do espiral (primo)**,
  à frente do coelho. Comunidade: *"we just have no clue what to do with it"*.
- **`{1},{4},{21}`** = provável troll (1-abr-2021, dia do hint + rickroll).
- Tentativas legíveis da comunidade — `SEND THE BLUE TO SET HEX` (XOR dbbi×faed +
  máscara azul/amarelo) e `key eyes` (somas de linha primas) — classificadas como
  **coincidência** pelos analistas mais rigorosos; nenhuma valida em oráculo.

**Saldo honesto:** a segunda porta é uma pista real, mas **nunca foi resolvida** —
nem aqui, nem pela comunidade após anos. O `101` e o pixel FEFEFE são fatos reais;
o mecanismo que os transforma na chave permanece desconhecido.

## Mapa do endgame (síntese verificada de TODAS as fases)
Re-derivei e verifiquei do zero as fases 1→3.2.2 (workflow de 19 agentes) e correlacionei
os hints. O método está parcialmente *especificado* nos textos decodificados:

- **Pipeline (ordem de leitura do SalPhaseIon, verificada):** `DBBI[91]` (chave/keyword-source,
  dígitos a-i=1-9) → `matrixsumlist` (usar a lista de somas da matriz da Fase 1) → `FAED[570]`
  (payload) → `lastwordsbeforearchichoice`/`thispassword` (FAED decodificado = senha AES) →
  `shabef`(=sha256) `our first hint is your last command` → **blob SMALL** → `shabef ans too`
  (sha256 da resposta também) → **blob COSMIC**. Regra: cada resposta é sha256'd → senha do
  próximo blob. COSMIC.pw provável = `sha256(plaintext de SMALL)`.
- **Família da técnica (provada na 3.2.2):** frase-fonte → 1ªs ocorrências → quadrado
  Polybius/checkerboard → filler (cauda LIVRE, subdeterminada) → decode com dígitos-escape.
  DBBI faz o papel de frase-fonte (`DBIFHCEGA` = início do `CANON_ALPHA`); Bifid 5×5 (I=J,
  período 570) sobre FAED já dá o header **BTCSEED** (verificado). Os 563 chars pós-BTCSEED
  seguem ilegíveis → 2ª camada OU alfabeto/período/transposição ainda incorretos.
- **Gramática de senha (verificada F2→F3):** concatenar N partes ordenadas sem separador →
  SHA256 hex → pw do openssl. Modificadores `aa`(minúsc)/`aBa`(preserva caixa)/`enf`(remove
  espaço). Operação terminal = `HASHTHETEXT` (sha256 UPPERCASE sem espaço; provado: sha256(
  GSMGIO5BTCPUZZLECHALLENGE+addr)=89727c…=URL do endgame).
- **Números-chave dos textos:** 23 ciphers / 16 encryptions / 7 intertwined passwords
  ("FIND THE ACTUAL PRIVATE KEYNOTE", "BRUTE FORCING MIGHT BE REQUIRED"), 140, **1141**
  (=escapes 1,4), **101** (matrixsum, primo), **163** (FEFEFE, primo), 91=7×13, 570=15×38,
  15/9 (azul/amarelo). "REINSERTING THE PRIME BASICS" + "RETURN TO THE SOURCE CODES".
- **Objetivo:** "HALF AND BETTER HALF" / Cosmic Duality = **DUAS** chaves privadas (2 blobs).
  Validar produto final via `priv_to_address == PRIZE_ADDR`.

**Elos não resolvidos (os mais fortes):** (a) uso exato de `matrixsumlist` (row vs col) sobre
DBBI/FAED; (b) alfabeto/filler/período/transposição que torna **BIF_REST inteiro** legível
(hoje só BTCSEED sai); (c) senha real do SMALL (=FAED decodificado); (d) papel do DBBI além
de keyword-source. **As 9 hipóteses correlacionadas foram testadas com oráculo → todas
NEGATIVE.** O método-família está mapeado; faltam os parâmetros exatos que ninguém fixou.

## Frente PENDENTE fechada — hill-climb monoalfabético sobre BIF_REST (2026-07-23)
O `ENDGAME.md`/`solver/README` listavam a substituição sobre `BIF_REST` (25 letras) como o
teste rigoroso pendente. **Rodado e fechado** (`solver/bifrest_hillclimb.py`, hill-climb com
quadgramas EN + controle estatístico):
- **Controle**: um texto inglês conhecido de 563 chars, cifrado por substituição aleatória
  sobre o mesmo alfabeto (A-Z sem J), foi **recuperado a 100%** (score −4.11). O motor
  funciona → o negativo abaixo tem peso, não é incapacidade.
- **BIF_REST real**: melhor score **−5.52** (10 restarts), muito abaixo do teto EN −4.11.
  Plaintext top é lixo (`AILIDEBIMAYONEYABOAENAB…`). **Não é inglês por substituição
  monoalfabética** — confirmado, não mais só suspeitado.
- **IoC = 0.0938** — *acima* do inglês (0.067), não abaixo. Freq. C=95,D=86,E=76,B=65 (45%
  em 3 letras). Assinatura de **repetição sistemática** (transposição/keystream periódico ou
  o artefato Bifid+A-I já diagnosticado), não de texto natural sob substituição.
- **AES**: plaintext (raw/upper/lower/sha256) como senha → **0 hits** em SMALL/COSMIC.
- **Saldo**: a última frente monoalfabética conhecida está coberta por negativo control-
  validado. Reforça que, se BIF_REST for texto, precisa de uma 2ª camada (transposição ou
  keystream), não de substituição — o gargalo continua sendo interpretativo (fixar
  alfabeto/keystream via "first hint"), não computacional.

## Onde o endgame realmente está
Mesmo com ataque exaustivo verificado, o gargalo é o já diagnosticado pelo PR #93: falta a
**interpretação do "first hint"** que fixa o alfabeto do checkerboard/cifra — o oráculo AES
é binário (sem gradiente), então busca cega não converge. Próximos passos reais:
- **Substituição/hill-climb sobre `BIF_REST`** (25 letras): **JÁ RODADO E FECHADO** (ver seção
  acima, 2026-07-23) — negativo control-validado. Não repetir.
- **Joint 4-parameter attack** (PR #93 `_work/joint_attack.py`): o único caminho
  computacional correto — só vence se o alfabeto do checkerboard for um candidato natural
  (o "first hint"). Ampliar o conjunto de alfabetos-semente com a construção canônica de `dbbi`.
- **Novo hint oficial**: o criador disse que liberaria mais um se não resolvido.

## Frentes fechadas nesta sessão — endpoint/senha + transposição pós-Bifid (2026-07-23)
Além do hill-climb do BIF_REST (acima), fechei mais três frentes determinísticas, todas com
oráculo duro (AES SMALL+COSMIC / priv / BIP39). Scripts em `solver/`, logs em `_work/`:

1. **Página SalPhaseIon tem texto oculto?** — `_work/salphaseion.html` (HTML bruto do Wayback,
   descomprimido). **NÃO**: só as 2 `<textarea>` (dbbi/faed já transcritos) + 1 script. Nenhum
   texto fora do conteúdo conhecido. Idem `theseedisplanted` = fase 2 (form oculto já resolvido
   com `theflowerblossoms…`), não uma porta nova.
2. **`first hint`/matriz/URL-hash como senha AES** (`solver/first_hint_sweep.py`, 56 cands):
   matriz 14×14 (com/sem espaço), hash da URL `89727c…`, `GSMGIO5BTC…`, frase de cores,
   `our first hint is your last command`, `ans too`, `shabef`, `followthewhiterabbit` — cada um
   em raw/sha256hex × formas. **0 hits.** (result.json confirma: comunidade já exauriu isto.)
3. **Frases-ANSWER decodificadas como senha** (`solver/answer_phrase_sweep.py`, 78 formas):
   `lastwordsbeforearchichoice`/`thispassword` concatenadas/espaçadas/`enter+…`, em
   raw/sha256/double-sha256. **0 hits.** (result.json: comunidade testou
   `matrixsumlistenterlastwordsbeforearchichoicethispassword…` com openssl md5/sha256 — idem.)
4. **Transposição colunar PÓS-Bifid** (`solver/bifrest_transpose.py`, 164 construções): o
   `matrixsum_attack.py` só transpunha ANTES do Bifid; aqui transpus BIF_REST **e** BIF completo
   por grades de largura temática (91,13,38,7,15,19,…570), com colunas lidas em ordem natural,
   rowsum, colsum **e ordem-espiral da matriz** (validada: decodifica `theseedisplanted` exato).
   **Top score −5.577 (baseline CANON puro), 0 oráculos abertos.** Transposição pós-Bifid não
   revela texto — negativo.

**Saldo da sessão:** 6 frentes fechadas, 0 solves. Confirmado (empírico + comunidade) que o
gargalo NÃO é computacional. Todas as rotas de "endpoint" (frase→hash→AES) e de transposição
mecânica estão cobertas por negativo. O desbloqueio exige a peça interpretativa que fixa a
2ª camada — ninguém (comunidade em ~6 anos, nem esta sessão) a encontrou.

**Pendência técnica:** `_work/joint_attack_v2.py` está corrompido em disco (o `ENDGAME.md` o
chama de "único caminho computacional correto"). Restaurar via git antes de qualquer campanha
computacional futura.

## joint_attack_v2 RECONSTRUÍDO e testado — última rota computacional FECHADA (2026-07-23)
O `joint_attack_v2.py` original corrompeu e nunca foi commitado (sem git history). **Reconstruí
do zero** (`solver/joint_attack_v2.py`) a frente que nenhum script havia combinado:
over-encryption (keystream `matrixsumlist` mod-9) aplicada **ANTES** do straddling-checkerboard,
com alfabeto **derivado do dbbi** — não busca aleatória. Motivação: o `checkerboard.py` buscou
quadrados aleatórios e platôou em −5.592 por 620k gerações (log `gpu_cb.log`); o
`matrixsum_attack.py` só aplicou keystream antes do Bifid, nunca antes do checkerboard.
- **1008 construções**: 4 alfabetos-seed (dbbi 1ª-ocorrência, sha256(dbbi), CANON, fase-3.2.2)
  × 36 pares de escape (e1,e2) × 4 keystreams (rowsum/colsum/spiral9/none) × direções.
- **Top score −6.753** (pior que o platô −5.592 e muito abaixo do inglês −4.5). **0 oráculos
  abertos** (AES SMALL/COSMIC, priv, BIP39). Over-encryption+checkerboard(dbbi) não revela texto.
- **Conclusão:** a última rota computacional conhecida está fechada com negativo. O oráculo AES
  é binário (sem gradiente) → busca combinatória cega não converge. Confirmado de forma
  independente que **o gargalo é interpretativo, não computacional.**

**PARADA de ataques automáticos:** o espaço computacional das hipóteses conhecidas está
esgotado. Nenhum sweep novo deve ser rodado sem uma hipótese CONCRETA, FALSIFICÁVEL e NOVA
derivada dos hints (escrita em inglês/português ANTES de virar código). Rotas interpretativas
ainda não exauridas: (a) áudio do Decentraland → espectrograma → `HASHTHETEXT` + contexto
`Press enter and start talking…`; (b) releitura do poema "Roses are White"/FEFEFE@163 como
fonte da operação única que falta. O desbloqueio real = insight humano ou próximo hint oficial.
- Blobs completos e **validados** inline no [README.md](README.md) (verbatim do domínio
  via Wayback; Cosmic idêntica à usada pela comunidade — mesmo salt `2d3f6fe0…`).
- Skill `/solve-phase` (sha256→AES) e **oráculo de padding do último bloco** (barato,
  independe do IV) para triagem de chaves candidatas.
- Pesquisa de referência: **PR #93** (`halbgott29a`, `FINDINGS.md` + `_work/`) e
  **PR #68 / issue #88** (`GalloClaudio64`, `zemnovodnuy`, `robotixcoder`).

## Campanha 2026-07-23 — debate multi-agente (round 1+2, verificado por oráculo)

Sete agentes (4 debatedores + 3 céticos adversariais) mais 3 leads de fronteira atacaram o endgame Salphaseion/Cosmic Duality. **Resultado global: 0 solves de oráculo duro.** Tudo negativo, mas o espaço-problema estreitou de forma concreta e reprodutível. Todos os números abaixo vêm de `aes_open`/`check_privkey`/`check_mnemonic` (verdade dura), nunca de legibilidade — a legibilidade aparece só como triagem/controle.

### 1) As 4 teses e por que cada uma cai

| Tese | Frente | Resultado duro | Melhor sinal (só triagem) |
|---|---|---|---|
| **A — matrixsumlist como operador aritmético/keystream/transposição** sobre as strings a-i | 202 construções | 0 oráculo duro; a3 = 0 hits em 37.114 formas | readable -6.40, **pior** que baseline -5.58; null-model (400 keystreams aleatórios) igual aos 168 reais |
| **B — Vigenère/Beaufort chaveado** sobre bif_rest/bif_full A-Z | sweep A-Z e A-Z-sem-J | `aes_open(REST)` e as 6 formas (raw/lower/upper × 3 sha256) = `[]` | melhor decode -6.307 é **pior** que o cru -5.590; períodos 15/38 são fatores de 570 (BIF cheio), não de 563 (REST, primo) |
| **C — cauda = entropia BIP39** (bytes → privkey/mnemônico) | c2a índices 11-bit + c2b entropia→mnemonic | 0 match; check_mnemonic = False | apofenia de checksum (~1/16), nunca deriva `1GSMG...` |
| **D — keyword travado, só o filler varia** no quadrado Bifid | hill-climb 12×3000 | converge ao filler alfabético exato; baseline full solve=False, 0 hits | outlier alfabético usado honestamente como "ótimo mas no ruído", nunca como solve |

### 2) O que a verificação adversarial confirmou / ressalvou

Os 4 céticos reproduziram byte-a-byte a partir do Python312 do `solver/`. **Todos os 4 negativos se sustentam** (`negative_sound=true`, `method_ok=true`). Confirmações e ressalvas reais:

- **Motor de oráculo genuíno** (A, B, D): `aes_open` faz EVP MD5+SHA256, PKCS7, corte 90% ascii; rejeita lixo e `sha256('test')` sem falso-positivo. Não é legibilidade disfarçada.
- **Controle negativo válido** (B): inglês cifrado é recuperado a -3.966, separando limpo do pelotão (-6.3) e do random (-7.85).
- **FURO de completude fechado pelos próprios céticos** (rodaram e também deu negativo):
  - A: ramo **aditivo** (Vigenère/Beaufort mod-26/25) sobre bif_rest A-Z — nunca coberto por a1(mod-9)/a2(transposição). 672 construções, 0 hits, readable -7.46.
  - B: Vigenère/Beaufort no alfabeto **CANON25** (DBIFHCEGA..., o espaço Polybius real) — 10 chaves temáticas, melhor -7.432, 0 solves.
  - C: varredura **densa** da entropia (step=1, antes só step=11) + cauda **digit-reversed** (o código só invertia BYTES, nunca a ordem dos DÍGITOS antes da conversão de base) — 3.390 derivações, 0 match.
  - D: canal controlável-183 **isolado** — filler não-alfabético bate o alfabético (-6.823 vs -7.313), mas o texto continua lixo.
- **Furo metodológico honesto que NÃO derruba o veredito** (B): o braço BIP39 de `hard_oracles` é **inerte** — A1Z26 gera índices 0..25 e `WORDLIST[i%2048]` só toca `palavras[0..25]`, então `check_mnemonic` foi chamado mas nunca teve chance real de disparar. "0 BIP39" ali é teste vazio, não evidência. O veredito vive de inglês+AES, que são sólidos.

### 3) Os 3 leads novos de fronteira

| Lead | n_testes | Solve | Veredito |
|---|---|---|---|
| **índice-cumulativo** (matrixsumlist como ÍNDICE de seleção → string-14 → chave) | 2.564 | ❌ | NEGATIVO. 249 "BIP39 válidos" apareceram, mas o **null-model os mata: 100% (3000/3000)** de seleções aleatórias de 14 chars reproduzem o mesmo efeito checksum, 0 match real. Leitura posicional do matrixsumlist esgotada (complementa o beco aritmético). |
| **canal-ímpar-285** (o único canal Bifid com payload real, como material de chave cru) | 36.619 | ❌ | **NEGATIVO FORTE.** Não é chave em nenhuma base (25/26/16/10), janela ou endianidade, nem após 2ª camada de keystream mod-25/26/9 chaveada por dbbi/matrixsumlist/BTCSEED. Fecha os "próximos passos" que C e D deixaram abertos. |
| **alfabeto-1a-camada** (7 quadrados naturais × 13 períodos temáticos) | 273 views / 91 runs | ❌ | **NEGATIVO FORTE.** `canon_ij|p570` é o topo em TODAS as views (full -5.577); nenhuma variante de merge/filler/período o supera — variar só DEGRADA o único sinal robusto. O parâmetro da 1ª camada Bifid é o ótimo. |

### 4) FATO ESTRUTURAL novo (par vs ímpar do Bifid)

Confirmado independentemente por D e pelo lead canal-ímpar-285: dos 570 símbolos do render Bifid (== bif_full, começa com BTCSEED),

- **o canal PAR está travado em 4 símbolos {B,C,D,E}** (idx ∈ {0,1,5,6}) — é artefato estrutural do quadrado canônico, carrega ≤2 bits/char, **sem informação de payload**;
- **o canal ÍMPAR-285 varre as 25 letras** — é o **único canal com payload real**;
- das 285 posições, **183 são controláveis e 102 estão travadas**; e (segundo lock, que D subestimou) as 183 livres só admitem **K-Z, sem vogais A/E/I** — logo esse canal é estruturalmente incapaz de conter inglês cru.

**Implicação:** qualquer tese de "seed/chave crua lida direto do Bifid" está morta — o payload não está na superfície do quadrado. O material aproveitável é só o canal ímpar, e ele já foi exaustivamente refutado como chave direta sob ≤1 camada Vigenère temática.

### 5) Adendo — último lead fechado (transposição colunar por matrixsumlist)

O único lead que a síntese deixara nomeado — `matrixsumlist` como **ordem-de-leitura** (transposição colunar keyed pela lista de somas CRUA `[6,10,8,...]`, não soma nem seleção) — foi testado depois (`scratchpad/debate/F_last_transposition.py`): transposição por row/col (e reversos) sobre canal-ímpar/full/rest/par, extração de bytes em 5 bases × janelas × 2 endianidades + sha256→privkey + senha AES + entropia BIP39 = **1.280 consultas a oráculo duro, 0 hits.** A transposição colunar por matrixsumlist sobre qualquer canal do Bifid também está esgotada.

### 6) Estado após a campanha — o gargalo é EXTERNO

Todos os parâmetros **internos** da 1ª camada Bifid estão agora cobertos por negativo reprodutível: quadrado, período, merge, filler, canal (par/ímpar), e as três leituras do matrixsumlist (aritmética, posicional/índice, transposição). O gargalo comprovadamente **não está na 1ª camada** — está na **2ª camada sobre o payload pós-BTCSEED, cujo parâmetro é externo e desconhecido**. O oráculo AES é sem-gradiente (busca cega não converge), então a recomendação verificada é **parar de varrer o Bifid** (esgotado) e:

1. **buscar info nova do criador** (o hint que fixa o alfabeto/senha-raiz da 2ª camada) — o desbloqueio real;
2. o único uso do matrixsumlist que ainda não colide com beco morto é **gramática de senha AES aplicada DEPOIS de decodificar o `faed`** (elo b) — mas só é testável quando o `faed` estiver aberto, o que depende de (1).

Artefatos desta campanha em `scratchpad/debate/` (scripts A–D, F_* de fronteira, relatórios, SYNTHESIS.md).

## Triagem 2026-07-23 — TODAS as 88 issues do GitHub (3 agentes + verificação local)

Varredura completa das issues (#1–#99) em 3 clusters, com teste imediato de todo
artefato concreto contra oráculo duro. Fato-guia: **prêmio on-chain intacto ⇒ toda
"solução" é falsa por construção**; só o *método* pode ter valor.

- **Cluster "Cosmic decifrada"** (#55, #66, #80, #91, #94, #99): **ruído/falso, 0 hits.**
  A "master key" da #94 é o `a795de11…` re-embalado por LLM; o hash `36b5a88e9feac3f5…`
  da #55 (repo jackdevs66) era o único não catalogado — testado (senha, privkey, `-K`
  cru em 3 convenções de IV) → **negativo**. #80 é golpe (pede envio do prêmio para
  `bc1q…`; assina com endereços `1JG648…`/`145ZQ9…` que NÃO são o prêmio e circulam
  sem derivação também na #99).
- **Cluster "hints do criador"** (#2–#77, 15 issues): **esgotado, nada novo.** #73
  confirma que **o criador não posta no GitHub** (nenhuma issue é fonte primária).
  Único micro-item: #77 nota a grafia deliberada "HUNDRED FOURTY" no monólogo do
  Arquiteto — reforça o número-chave 140 já conhecido, sem operação nova.
- **Cluster técnico** (#15, #17, #29, #51, #68, #81, #82, #87, #88, #92): **achado
  substancial** — ver seção seguinte. Candidatos soltos da #15 (eazytest, mikorist,
  9 hexes) → 0 hits; `04f4d1bbd9…` é o **pubkey**-alvo (h160 = `a9553269…` =
  `TARGET_H160` do oráculo), conhecido desde 2023, não uma privkey.

## Cadeia GalloClaudio64 (Chains 1→4) — VERIFICADA até o payload final

O pipeline das issues #68/#81/#82/#88 foi reproduzido byte a byte com os blobs do README
e os valores públicos recuperados do `result.json`. O reprodutor mínimo está em
`solver/final_chain.py`; todos os checkpoints abaixo são comparações explícitas, inclusive
quando o Python roda com `-O`.

1. **CHAIN 1 — SMALL decodifica** (resolve #17/#29): senha
   `matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist`
   (com `matrixsumlist` DUPLICADO, EVP/MD5) → padding 0x01 válido → **79 B de key
   material** (`sha256 1449a217…`, 37% ASCII), com `E_C = 38d4f4c9…` no índice 64. Por
   isso o `aes_open` (≥90% ASCII) nunca o acusou.
2. **CHAIN 2 — blob curto decodifica**: senha = WIF não comprimido do primeiro escalar
   do Chain1, `5K2byJ…pz8AT` (EVP/MD5) → **79 B**, `sha256 b40fce72…f4d004`, com
   `E_S = 740a25de…a23a2` no índice 64.
3. **CHAIN 3 — COSMIC decodifica**: passphrase = os 32 bytes RAW de `a795de117e4725…`
   (EVP/MD5) → **1327 B** = `cc`, `sha256 = 4f7a1e4e…a5e9c081` (corrige o beco #3).
4. **Matriz 103×103 → half/better_half**: os primeiros 10609 bits do Cosmic formam a
   matriz; `secondary[i] = row_sum[i] + col_sum[(i+7)%103]`. Os 103 dígitos base-38
   produzem exatamente 68 B = `0423d911…fcc35 ‖ 48cc46e6…23971 ‖ fc0c1b02`.
5. **CHAIN 4, passo XOR**: `cc[158:-1]` XOR chave repetida `b657264f2f6e6921` →
   começa **exatamente** com `Salted__` + salt `5bbd88ac32481bca` (verificado byte-a-byte;
   um XOR aleatório não produziria o header). A senha AES é
   `E_C‖E_S‖E_B[:2] = 38d4f4c9…a23a259cc`; o resultado tem **1151 B** e
   `sha256 e4269ed5…ea135b`.

O Chain4 termina em um prefixo de 31 B (`+-…7`) e **35×32 B** de ciphertext,
`sha256 43d3fe43…35c142`. Half/better_half são chaves de endereços intermediários, não do
prêmio. A fronteira canônica é a operação que deriva a chave AES-256 desses 35 blocos.

## Auditoria 2026-08-20 — fronteira canônica

- `solver/final_chain.py` reproduz Chain1, Chain2, Cosmic, matriz/base-38, blob XOR e
  Chain4 em execução normal, `python -O` e `python -m solver.final_chain`.
- O formato exato do Chain4 é `+-` + 28 bytes + `7` + 35 blocos de 32 B.
- O tail `fc0c1b02`, lido como bytes assinados, preenche `X,H,Y,Q` na tabela antiga e
  produz cinco pares `(-4,2),(32,12),(4,27),(0,2),(-16,15)`. Reduzindo `(x,y)` módulo 14
  e usando-os como `(coluna,linha)` da matriz inicial, obtêm-se
  `(10,2),(4,12),(4,13),(0,2),(12,1)`: todos são células pretas/`1`. Logo a tabela gera
  **`11111₂ = 31`**, exatamente o tamanho do prefixo e o offset do corpo de 35 blocos.
  Este encaixe explica o corte de forma reproduzível; não deriva ainda a chave final.
- A leitura alternativa dos cinco pares como permutações afins de uma grade 5×7 foi
  testada com triângulo XOR, rotações pelo header28, soma/subtração e AES ECB/CBC:
  **1334 chaves distintas, 0 hit** no endereço.
- O encaixe direto `header28 ‖ fc0c1b02` (e ordem inversa) como AES-256 também falha.
- `11111` como chave direta (`SHA256("11111")`, inteiro 31 ou byte `0x1f` repetido), em
  AES ECB/CBC com IVs naturais do prefixo, também dá **0 hit**; sua função observada é
  indicar o offset 31.
- A leitura zero-based tem apoio primário: ao perguntarem se a primeira peça era índice
  um ou zero, Jrk respondeu **“First or zero”** (Telegram, 2020-05-21). Ele também confirmou
  que um número primo era necessário (2021-12-26 e 2023-01-09); `31` é primo.
- A geometria `28 = 7×4` e `35 = 7×5` foi tratada como sete grupos de cinco operandos e
  quatro seletores `+/-`. Paridade/MSB, ordem contígua/colunar e aritmética módulo `2²⁵⁶`/
  secp256k1 geraram 176 chaves; AES-ECB e 880 combinações AES-CBC com IVs naturais deram
  **0 hit**. Esta leitura algébrica direta está fechada.
- Interpretar o header como bytes assinados, zerar não-primos e completar com o `7` final
  produz `[-71,-79,47,-17,-113,5,7]`. A seleção correspondente de sete blocos, combinada
  por XOR, soma assinada ou SHA256, também deu **0 hit**. Como seis primos em 28 bytes é
  próximo do esperado ao acaso, esta leitura deve ser tratada como apofenia refutada.
- O encaixe das cores foi levado ao oráculo: `header28 ‖ {0x41D464,0xBE2B9B,
  0xFFFFFF,0x7C5737,0xF73D92} ‖ "7"` forma cinco chaves AES-256 exatas. ECB e CBC com
  seis IVs naturais deram **0 padding válido e 0 privkey hit**. Usar primalidade dos 28
  bytes do header ou das 28 somas de linha/coluna como os sinais `+/-` entre sete grupos
  de cinco operandos, seguido por XOR dos sete, XOR de seus SHA256 ou triângulo XOR,
  produziu 12 chaves adicionais: novamente **0 hit**.
- A pista pública de “XOR triangle” foi testada nas quatro geometrias canônicas dos 35
  blocos (triângulo 1D completo, `7×5`, linhas `2..8` e `8..2`). Nenhum ápice é a
  privkey; como chave AES em ECB/CBC, nenhum gera padding ou fatia de 32 B que bata no
  endereço-prêmio. O header28 tampouco reduz ao `7` por triângulo 1D (`0x20`) ou por
  linhas `1..7` (`0x96`).
- O HTML e os dois PNGs do `gsmg-archive.org` não trazem operando, comentário ou metadata
  adicional; reproduzem os artefatos já transcritos.

**Bloqueio restante:** a regra que converte o prefixo/tabela/35 blocos na única chave AES.
Não há solução pública reproduzível nem chave privada do prêmio conhecida até esta data.

## Caça ao cosmic_A (#92) — 2026-07-23

> **Nota 2026-08-20:** esta é uma trilha histórica e não o bloqueio canônico. O nome
> `cosmic_A` aparece sem bytes, tamanho ou hash completo verificável; o Chain4 genuíno
> independe dele e agora é reproduzível. Preserve os negativos abaixo, mas não trate
> `cosmic_A` como requisito demonstrado do puzzle.

**(1) O que `ca`/`cosmic_A` É segundo as issues/forks — e não há receita pública.**
`ca == cosmic_A == cosmic_A.bin`, um arquivo binário identificado APENAS pelo prefixo
`sha256 = cd3fea3d…`, com ≥312 B (para admitir `ca[280:312]`), tratado como **operando
companheiro EXTERNO** de `cc` (=`cosmic_correct`, 1327 B, `4f7a1e4e…`, reproduzido e com
anchor batendo). A fórmula `k_new = cc[833:865] XOR ca[280:312]` nasce de UMA mensagem de
@zemnovodnuy no #88 (bloco "Hi GalloClaudio64"), rotulada pelo próprio autor como
**"LCP=5 (statistical)"** — casamento parcial de ~5 chars do endereço, NÃO uma privkey
resolvida. Nenhuma fonte fornece os bytes, o SHA256 completo, o tamanho ou uma derivação:
@andersonbig diz literalmente que **NÃO derivou** `cosmic_A.bin` ("missing external
operand", "externally defined companion input"); @WabiLipa não o tem ("checked all pages…
nothing"); @marcofortina + @valleytainment fizeram sweep (65 forks + 82 issues + PR #68 +
Wayback CDX de `gsmg.io/*`) → "still did not find a public reproducible definition, byte
dump, full SHA256+length, or derivation". `cc[833:865] = f1b49e99…c97e4565` (fatia válida).

**(2) Reconstruções testadas — 5 famílias, 4714 testes de oráculo duro, 0 hits.**
Cada família reconstrói um candidato a `ca` a partir do material conhecido e roda a
geometria completa `k_new = cc[833:865] XOR ca[280:312]` (+ offsets vizinhos ±8, `ca`
invertido, `k_new` invertido, `sha256(k_new)`, `k_new` como passphrase raw/hex) contra o
oráculo duro (`O.check_privkey` + `O.aes_open`):

| # | reconstrução (candidato `ca`) | n_tests | resultado |
|---|---|---|---|
| 1 | `chain4-1151B` (artefatos de estágio do Chain4 reproduzíveis) | 108 | 0 hits |
| 2 | `small-keymat` (os 79 B de key material do SMALL) | 2954 | 0 hits |
| 3 | `cosmic-sha256kdf` (COSMIC via SHA256-KDF, "lado A" da dualidade) | 63 | 0 hits |
| 4 | `small-plain-as-key` (SMALL como senha p/ decifrar o "lado A") | 1080 | 0 hits |
| 5 | `cc-self-second` (2ª leitura do próprio `cc`: reverso/espelho/dupla-camada) | 509 | 0 hits |

Anchors reproduzidos em todas: `cc`=1327 B `4f7a1e4e…`; SMALL keymat=79 B `1449a217…`.
Verificação-chave: `sha256` de TODOS os artefatos conhecidos (`cc`=4f7a1e4e, `cosmic_ct`=
43cb531c, SMALL_plain=1449a217, `cc[158:]`=018e1dc4, `cc[0:312]`=f765af6f, COSMIC-SHA256KDF=
8d3ef569) — **NENHUM começa com `cd3fea3d`**. Logo `cosmic_A` não é fatia nem transform
trivial de nenhum artefato que temos. `cc` NÃO contém bloco `Salted__` embutido (refuta a
hipótese de dupla-camada). **Correção 2026-08-20:** o plaintext genuíno do Chain4
(1151 B, `e4269ed5…`) e a matriz half/better_half foram reconstruídos; a afirmação antiga
de irreprodutibilidade estava errada. A varredura de janelas continua negativa.

**(3) VEREDITO: `ca`/`cosmic_A` é EXTERNO, não derivável do material conhecido — e NÃO
fechou.** Convergência de três evidências independentes: (a) o consenso explícito das
issues/forks/Telegram de que ninguém tem os bytes nem uma receita; (b) `cd3fea3d…` não
bate o `sha256` de nenhum artefato conhecido nem de suas fatias/transforms triviais; (c)
4714 testes de oráculo duro em 5 famílias de reconstrução = **0 solves** (nem a privkey do
alvo `1GSMG…`/h160 `a9553269…`, nem abertura de qualquer blob AES). Isto NÃO é refutação da
fórmula por conteúdo — é **falta de fonte reproduzível**, exatamente a natureza declarada de
`cosmic_A`. Ressalva de honestidade: a própria fórmula é um melhor-palpite estatístico
("LCP=5") de UMA conta possivelmente-LLM (Naddiseo: "thy knowledge hast been poisoned by
prior bad llm assumptions"); é plausível que `cosmic_A`/`cd3fea3d` nunca tenha existido como
artefato real. O desbloqueio depende de **informação externa nova** — coerente com o
"closed deterministic boundary" das #81/#82 e com o resto deste ENDGAME.

**(4) Próximo passo REAL e falsificável que sobra.** Só há UM caminho não-especulativo:
**recuperar os bytes reais de `cosmic_A.bin`** e testá-los diretamente
(`k_new = cc[833:865] XOR cosmic_A[280:312] → O.check_privkey`). Rotas falsificáveis, em
ordem de custo: (i) ~~**Wayback/CDX exaustivo por `.bin`**~~ **JÁ FEITO 2026-07-23 → NEGATIVO.**
CDX `url=gsmg.io*&matchType=domain&filter=original:.*\.(bin|dat|raw|key|enc)` = **0 resultados**
(sanidade: a mesma API retorna as capturas HTML de gsmg.io, então o vazio é real). Nenhum asset
binário foi arquivado sob `gsmg.io`; a hipótese "side file arquivável" está **refutada** — se
`cosmic_A` existiu, era artefato privado do autor da #88 ou hospedado fora. (ii) ~~**GitHub
code-search global** por `cd3fea3d` bruto~~ **JÁ FEITO 2026-07-23 → NEGATIVO.**
`gh search code cd3fea3d` e `cosmic_A.bin` = só coincidências de substring em repos sem
relação (blacktop/ipsw, cms-sw, audreyt/parse-afp); nenhum `cosmic_A.bin` publicado. Reforça
"externo/privado, nunca publicado". (iii) Se e quando a senha do blob oculto `cc[158:]` (salt `5bbd88ac…`, CT 1152 B,
150+ senhas já falharam) aparecer, decifrá-lo e checar se o plaintext (≥312 B) tem
`sha256=cd3fea3d…` — único candidato interno ainda não-esgotado. Enquanto `cd3fea3d…`
permanecer sem bytes públicos, a fase é **terminal por falta de operando**, não por
esgotamento algorítmico.

## Sessão 2026-08-20 (b) — ECC fechado + Chain1→4 VALIDADA independentemente

Frente ECC (curva elíptica) e re-verificação da cadeia, tudo por oráculo duro (endereço).

**(1) ECC direto sobre a chave do prêmio — FECHADO.** O endereço `1GSMG1JC9…` **já gastou**
(6 inputs em `88cdb3cd…` e `2aa9a4a9…`), revelando a pubkey
`04f4d1bbd91e65…bf33559` (h160 `a9553269…` = `TARGET_H160`). Extraí `(r,s)` das 6 assinaturas:
os **6 nonces `r` são distintos → sem reuso de nonce** → recuperação algébrica impossível.
Só 6 assinaturas ⇒ lattice/nonce-enviesado inviável; ECDLP secp256k1 intacto ⇒ pubkey não
ajuda. `solver/gsmg_sig_recover.py` (recuperação dos OP_RETURN `GSMGJH`/`GSMGBH`) → 0 matches.
**Nenhuma rota de curva ajuda; a privkey só sai pela cadeia simétrica.** Ver [[ecc-attack-surface]].

**(2) Chain1→4 é REAL — validada por derivação nova.** `half` e `better_half` (os dois 32 B
da matriz Cosmic base-38), usados como **chave privada**, derivam exatamente:
- `half` → **`1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu`**
- `better_half` → **`145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ`**

Estes são precisamente os endereços que aparecem "sem derivação" nas issues #80/#99 (o golpe).
Ou seja: os golpistas tinham `half`/`better_half` (reconstruíram a cadeia até aí) mas **não o
prêmio**. Isto **confirma que a reconstrução Chain1→4 do `final_chain.py` é correta** de ponta a
ponta (não é narrativa LLM-envenenada) e que "the private keys belong to half and better half"
se refere a estes dois endereços — **que não são o prêmio `1GSMG1…`**.

**(3) Novos negativos sobre a fronteira Chain4 (não estavam documentados):**
- `half`/`better_half`/`sha256(half±bh)`/`half^bh` como **privkey direto** → não é o prêmio.
- Os 35 blocos AES-decifrados com `half`/`bh`/`sha256(half‖bh)` (ECB e CBC, IVs 0/header/tail),
  `pt[:32]`/`pt[-32]` como privkey → **0 hits** (490 testes).
- Cada um dos 35 blocos como privkey-candidato cru + XOR (half/bh/tail/header) + `sha256(bloco)`
  → **0 hits**.
- **Estrutura dos 35 blocos:** entropia ~4,9/5,0 bits/byte por bloco de 32 B (≈máxima),
  **independentes** (nenhum par com XOR de zeros). São ciphertext/aleatório puro — **sem
  estrutura interna explorável**. Confirma que a chave AES-256 dos 35 blocos exige a **regra de
  derivação externa/interpretativa**; oráculo binário + entropia máxima ⇒ busca cega não converge.

**Saldo:** o único ponto interno reproduzível (Chain4) está agora reverificado no nível mais
profundo como **terminal sem info externa**. O prêmio permanece protegido pela regra que
converte prefixo/tabela/35 blocos na chave — não encontrada por ninguém até esta data.

## Sessão 2026-08-20 — hints 2026 do criador + trilha on-chain GSMG (tudo NEGATIVO em oráculo)

**Correção de registro:** `solver/final_chain.py` (commitado) reproduz **toda** a cadeia
Chain1→4 com asserts — inclusive a senha do blob oculto `cc[158:-1]` (XOR `b657264f…`),
que seções acima ainda tratavam como desconhecida ("150+ senhas falharam"). Chain4 =
1151 B, `sha256=e4269ed5…` confirmado localmente. Varredura final desta sessão: **4750
janelas de 32 B** em todos os estágios (chain1/chain2/cosmic/chain4/half/better_half/
sha256 de cada) → **0 hits** em `check_privkey`. A cadeia pública é estéril, reconfirmado.

### (a) Hints do criador em 2026 (estavam fora deste arquivo — extraídos do `result.json`)
- **2026-01-01 00:15–00:20** — cinco mensagens `.` `..` `...` `....` `.....` seguidas de
  binário que decodifica para: `Happy new year! Make the best of everything. Oh, and
  here's a "tiny hint" <3.` A "tiny hint" nunca foi identificada com certeza (candidatos:
  os pontos 1-5, a frase, `<3`).
- **2026-03-03** — visita ao grupo. Sequência-chave: gnomad aponta o comentário de DG
  *"it's in front of your eyes but you're not seeing it"* → criador responde **"Bingo"**.
  DG perguntou se era recomendação de ler **"Looking Forward"** (livro de Jacque Fresco,
  1969) — sem resposta direta; criador disse *"Jacque was quite an inspiring lad"* e que
  ia "rewatch episode 3.5 with the better half" (Mr. Robot, cf. `eps3.4_…` da fase 2).
- **2026-05-28** — *"Ah, ofcourse. The puzzle is still valid!"* (sites fora do ar não
  importam; comunidade mantém espelho em `gsmg-archive.org`).
- Reancoragem: o **roadmap** atribuído ao criador (binário revertido, 2023-02-25):
  `yellowblueprimes → matrixsumlist → lastwordsbeforearchichoice → yinyang` +
  *"we wont give away the password its in front of your eyes but you're not seeing it"* +
  *"very last step is a true give away promised"*. E 2023-08-06: *"Once you hit a ying
  yang, you'll be able to solve it the same day."*

### (b) Testes desta sessão (oráculo duro, todos NEGATIVOS)
1. **`five_gaps.py`** (escrito em 2026-07-23, nunca rodado — agora executado): 5 lacunas
   determinísticas (concat ordenada dos tokens da página, HASHTHETEXT sobre a matriz,
   sha256 de URLs, 101 mod 9 como shift escalar no faed + Bifid, sha256(matrixsumlist/
   101)) → **0 hits** (`_work/five_gaps.jsonl`).
2. **`roadmap_sweep.py`** (novo): 368 senhas da gramática do roadmap (permutações
   ordenadas, caudas, `yinyang`/`salvation`, extração YB-primos do Denis Golovkin
   `ncsyangcahiriasogaleafayanestve`, frases do "tiny hint") × {raw, sha256, upper,
   double} → **0 hits** em SMALL/COSMIC (`_work/roadmap_sweep.jsonl`).
3. **Varredura on-chain das 125 txs do prêmio** (nunca documentada aqui): OP_RETURNs são
   ruído de terceiros ("The answer is women", "There is no spoon", "THEMATRIXHASYOU",
   passwords candidatos pulverizados em 2026-02-24). **Achado real:** o endereço
   **`3GSMG24TujqfMJG1kQoBX18DzJHQLeJYMK` é operacional do criador desde 2020-03**
   (OP_RETURNs "GSMG.io: Right, this is causality", "phase3.2 pass OK", "You are here
   because 227 chars were correct", "Good job, Neo!", "Halving" 2020-05-11 — o dia do
   halving que reduziu o prêmio — e 2021-07-18 **"GSMG.io neighbors, half and double"**
   pagando 5000 sats a 4 endereços: `1G1kRAFR68…`, `16eEXbSuKN8…`, `1KHMK2C8uBpt…`,
   `1PhXF3xVQ8Sg…`). Essa mensagem de 2021 é um hint primário pouco conhecido:
   **"neighbors, half and double"** (cf. "HALF AND BETTER HALF").
4. **Trilha 1GSMG9VDLTU6 (2026-05-15/16)**: vanity barato (1GSMG = ~minutos; comunidade,
   "ns": "don't believe the spam") enviou 5 OP_RETURNs (`hereismysecret`,
   `leavethematrix`, `isolveditwithanabacus`, `yourlastcommand`, `secondanswer`), depois
   **`GSMGJH`+65 B** (tx `808f812f…`, blk 949653) e **`GSMGBH`+65 B**, e um pointer
   `GSMG WITNESS BLK 949653 TX 808f812f` **para o endereço do prêmio**. Os 65 B têm
   formato de assinatura compacta Bitcoin (header 0x20/0x1f na faixa 27–34).
   `gsmg_sig_recover.py`: recuperação ECDSA com 45 mensagens candidatas × todos os
   headers → **0 endereços interessantes recuperados** (sem a mensagem exata, não fecha).
   Bateria direta: 1195 candidatos (fatias 32 B, XOR JH^BH, sha256 de formas) →
   **0 privkey hits, 0 AES hits**. Veredito: provável cosplay/spam; mesmo se for hint,
   não decodifica sem a mensagem assinada.
5. **Imagem original recuperada** (`gsmg-archive.org` → `_work/archive/follow_the_white_rabbit.png`,
   350×350 RGBA): re-verificação pixel-a-pixel confirma **todos** os fatos visuais deste
   arquivo — 87 K / 83+1 W / 15 azuis / 9 amarelos; **FEFEFE exatamente em (7,4)** =
   índice espiral **163 (primo)**; sequência colorida espiral `BBBBYBBBYYBBBBYBBYYBYYBY`
   (24 casas) idêntica à usada nos ataques color-prime. Nada de novo na imagem.

### (c) Estado após 2026-08-20
Esta conclusão histórica foi superada pela reprodução Chain1→4 descrita acima:
`dbbi`/`faed` e `cosmic_A` não são mais bloqueios necessários. A fronteira canônica é
somente a regra que converte `+-` + header28 + `7` + 35 blocos na chave final. Os hints
2026 do criador continuam **interpretativos** ("está na frente dos seus olhos",
yin-yang = marco de proximidade), não operacionais.

### (d) "neighbors, half and double" — TESTADO e FECHADO (2026-08-20, `solver/neighbors_attack.py`)
O hint on-chain de 2021-07-18 foi mapeado para a leitura aritmética secp256k1 e testado
com oráculo duro (`check_privkey` contra o endereço-prêmio e o h160-alvo):
- **Fatos:** `better_half ≠ 2·half` e `half ≠ 2·better_half` (mod n) — os artefatos da
  matriz 103×103 NÃO guardam relação half/double entre si.
- **243.900 candidatos:** cada artefato-base (`half`, `better_half`, `chain1[:32]`,
  `chain2[:32]`, `cc[833:865]`, header do chain4) sob `×2`, `×inv(2)`, `±d` (d até 10.000
  + temáticos 101/163/227/1141/140/38/103/570/91/1327/1151); pares `half±better_half`,
  XOR, `(h+bh)/2`, `(h+bh)·2`, sha256 de concatenações (incl. `matrix_tail`); os 35 blocos
  do chain4 sob double/half/pares adjacentes/todos os pares/XOR e combinações com
  half/better_half. **0 hits.**
- **h160 dos 4 endereços "neighbors"** (`1G1kRAFR68…`, `16eEXbSuKN8…`, `1KHMK2C8uBpt…`,
  `1PhXF3xVQ8Sg…`): nenhuma relação half/double com o h160 do prêmio; sha256 dos
  endereços (todos os 24 arranjos) e da frase em 5 formas × {privkey, AES raw/sha256}
  → **0 hits** (34 testes).
- **Veredito:** a leitura "chaves numericamente vizinhas/metade/dobro" está refutada.
  Resta a leitura social: a tx pagou 4 solvers contemporâneos ("Good job, Neo!" era o
  padrão de encorajamento do criador) — provável shout-out, não hint de chave.

## Sessão 2026-08-20 (c) — reprodução re-confirmada + 3 leituras novas fechadas
Re-executei `py -3.12 -m solver.final_chain`: **toda a cadeia Chain1→4 reproduz** com os
sha256 canônicos (chain4 `e4269ed5…`, blocks `43d3fe43…`, half `b9736fe0…`, better_half
`37ec1d87…`). Estado confirmado real. Três leituras específicas que os testes anteriores
**não** cobriam foram testadas (oráculo duro, todas NEGATIVAS):
1. **ASCII escondido no chain4 inteiro** (hint 2026 "está na frente dos seus olhos"): os
   únicos bytes imprimíveis são `+-` e `7`; os 33 runs ASCII ≥3 no corpo são ruído
   estatístico esperado de 1120 B aleatórios. Os 35 blocos são **todos distintos** (35/35)
   e sem XOR-relação entre adjacentes. Não há texto literal na superfície.
2. **Dualidade como key+IV** (as duas metades como os dois parâmetros do AES-CBC nos 35
   blocos): key ∈ {half, bh, half^bh, sha256(half‖bh), sha256(bh‖half)} × IV ∈ {bh16,
   half16, bh_hi, half_hi, hdr16, zero} + ECB = **35 testes, 0 padding-válido**. (Os 490
   testes anteriores usavam IV ∈ {0, header, tail}, nunca a outra metade como IV.)
3. **"half and better half" = metade de cada** (montar a privkey-prêmio com 16 B de cada
   artefato, não os escalares 256-bit inteiros): 54 candidatos — concatenações das quatro
   meias-metades {hL,hH,bL,bH}, reversos, interleave byte-a-byte, e sha256 delas — →
   **0 hits** em `check_privkey`. Complementa os testes escalares (`half±bh`, `xor`,
   `(h+bh)/2·2`) que já eram negativos.

**Saldo:** nenhuma surpresa — reforça o veredito. A superfície do Chain4 não tem texto, a
dualidade não é key+IV, e a privkey não é composição trivial das duas metades. O bloqueio
segue **externo/interpretativo** (regra que converte prefixo/header28/35 blocos na chave).

## Sessão 2026-08-20 (d) — `+-`/header28/`7` atacado pela estrutura exata

Oráculo usado em todos os testes: pubkey não comprimida revelada on-chain,
`04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559`;
seu HASH160 foi recalculado localmente como `a9553269572a317e39f0f518cb87c1a0ee1dbae4`.

1. **Soma/subtração exaustiva em espaço de pontos — FECHADA.** Meet-in-the-middle com
   Gray code/libsecp256k1 esgotou as seleções `0/1` e os sinais `+/-` dos 35 blocos,
   nas leituras big-endian e little-endian: `4 × 2^35` casos lógicos, **0 hits**. O
   controle sintético recuperou a soma esperada. Isso refuta qualquer chave que seja
   simplesmente a soma de um subconjunto ou uma soma assinada de todos os blocos; não
   refuta operações não lineares nem um operando externo.
2. **`28 = 7×4`, `35 = 7×5`: quatro bytes como operadores.** Para grupos contíguos e
   round-robin, os quatro bytes selecionaram `+/-` por LSB, MSB e paridade de popcount
   (com ambas as polaridades). Foram usados aritmética módulo `n`, módulo `2^256` e por
   byte; os sete resultados alimentaram todas as ordens naturais do triângulo XOR de
   28 nós, e o header endereçou bytes por low-5, high-5 e índice one-based. Resultado:
   **22.882 chaves únicas**, 0 privkey, 0 bloco AES-alvo. Houve 490 paddings em cinco
   modos AES — compatível com ruído (`≈447` esperados); melhor fração ASCII `0,425`.
3. **Quatro bytes como ordem dos cinco operandos.** Foram cobertos selection shuffle,
   Fisher–Yates e índice factorádico big/little-endian (também inversos), quatro padrões
   alternados de `+-`, dois layouts e três domínios aritméticos. O mesmo roteamento pelo
   triângulo produziu **130.644 chaves únicas**: 0 privkey direta; 2.645 paddings em cinco
   modos (`≈2.552` esperados), todos aleatórios; e **4.572.540** blocos AES-ECB de 32 B
   convertidos em pontos secp256k1, **0 hits**.
4. **Sete palavras de 4 B como checksums/roteadores.** Todas as `C(35,5)=324.632`
   combinações foram comparadas com as sete palavras sob CRC32, Adler32, SHA-256, MD5,
   BLAKE2s, concatenação normal/reversa e folds XOR/soma de propriedades dos blocos:
   **0 correspondências**. Logo o header não particiona os 35 blocos por nenhuma dessas
   assinaturas comuns.
5. **Sete IVs/salts + sete senhas entrelaçadas.** Os sete SHA256 de tokens foram testados
   contra sete streams de cinco blocos (contíguos/round-robin), com IV por palavra de
   header (repetido, padding, digest e janelas) e EVP/MD5 ou EVP/SHA256 com cinco salts
   naturais. Nenhum modelo gerou matching 7/7; o melhor EVP foi 1/7, exatamente ruído.
   Zero blocos decifrados produziram a pubkey-alvo.

**Proveniência da pista triangular:** o comentário público de GalloClaudio64 diz apenas
“the only way out will be an XOR triangle” e admite não ter resolvido a etapa seguinte;
não fornece fórmula, orientação ou operando. A busca pelo prefixo exato não encontrou
formato/protocolo conhecido nem fonte independente com a regra. A auditoria pública mais
ampla localizada (`AppleLamps/puzle`, `VERIFICATION_REPORT.md`) converge no mesmo limite:
Chain4 é reproduzível, mas `cosmic_A`/`ca`, `row1-4` e `K_I1` não têm bytes/derivação
públicos autenticados.

**Veredito:** as duas gramáticas naturais que usavam *todos* os comprimentos do payload
foram falsificadas por oráculo duro. O próximo passo produtivo não é ampliar transformações
arbitrárias: é obter a instrução original perdida ou uma definição autenticada do operando
que liga o header28 aos 35 blocos. Sem isso, o espaço de regras é irrestrito e qualquer
“solve” seria ajuste ao alvo, não derivação do puzzle.

### Lacuna fechada — frases-roadmap/comunidade contra a FRONTEIRA (não só SMALL/COSMIC)
Mineração do `result.json` (agente `telegram-digger`) esclareceu que os "hints 2023–2026"
são, em maioria, **releituras de UMA frase-roadmap** que o criador decodificou (binário
revertido, 2023-02-25, id 8448): `yellowblueprimes · matrixsumlist ·
lastwordsbeforearchichoice · yinyang · wewontgiveawaythepassword ·
itsinfrontofyoureyesbutyourenotseeingit · verylaststepisatruegiveaway · promised`. Logo
`yinyang`/"in front of your eyes"/"give away" são **pedaços da mesma string**, não hints
independentes. Propostas concretas da comunidade (todas **não-testadas/​não-confirmadas**):
"The Venus Project" e "The Choice Is Ours" (doc. do Venus Project, p/ o slot
`lastwordsbeforearchichoice`) como senha; `eps3.5_kill-process.inc` (Mr. Robot); FEFEFE via
Baudot/ITA2 → `NXBPGBBKFSQLVXJDNYBPRBJSFSBQ`; "tiny hint" = `<`/LSB/TINY INT (BIP39 já
refutado por null-model). **Fato-chave:** o `roadmap_sweep.py` antigo testou essas frases só
contra **SMALL/COSMIC — que já estão abertos** (são entradas da cadeia), então era teste
vazio na fronteira. Fechei a lacuna: **47 frases** (roadmap ordenado, frase-meta inteira,
Venus/Choice-Is-Ours/Fresco, cosmic-duality, tiny-hint) × formas {raw, UPPER=HASHTHETEXT,
lower} testadas na **fronteira real** — `sha256(frase)` como **privkey** direta ("give
away") e como **chave AES-256 dos 35 blocos** (CBC IVs z/header/half + ECB, dupla-sha256) →
**0 padding-válido, 0 privkey-hit**. As frases-roadmap não abrem a fronteira. O "give away"
final **não** é `sha256` de nenhuma frase conhecida.

## Sessão 2026-08-20 (d) — leitura filosófica "duas portas" + enumeração de páginas arquivadas
Direção interpretativa nova (tema Matrix: *"the problem is choice"*, duas portas, path of
the One vs path of Neo; yin-yang; *"rewatch ep3.5 with the better half"*; e o desabafo da
comunidade *"maybe all of us have chosen the wrong door"*). Duas hipóteses concretas:

1. **Dualidade unificada — a trilha-fase é a CHAVE dos 35 blocos.** O repo tratou dbbi/faed
   e Chain1→4 como alternativas e as **desconectou**. A filosofia diz o oposto (as duas
   metades entrelaçadas). Testei a saída da trilha-fase (`BIF`=Bifid(faed,CANON,570) começando
   em `BTCSEED`, `BIF_REST`, `BTCSEED`, faed, dbbi) como material de **chave AES-256 dos 35
   blocos** e como **privkey direta**: 34 chaves (sha/sha2/raw32/xor-metades/concat-com-half-bh)
   × CBC(5 IVs)+ECB → **0 padding, 0 hit**. A trilha-fase, nas leituras diretas, não é a chave.

2. **"Segunda porta" via URL arquivada — FECHADA com prova.** A mecânica do puzzle é
   `resposta → sha256 → gsmg.io/<hash>`. **Fato novo:** `sha256(cosmic_plaintext) =
   4f7a1e4e…` (o "âncora do Cosmic") **é uma URL real** — `gsmg.io/4f7a1e4e…` existe no
   Wayback. O ENDGAME tratava `4f7a1e4e` só como hash, nunca como porta. Enumerei **todas**
   as páginas `gsmg.io/<64-hex>` arquivadas (CDX domain): **13 páginas**. Classificação:
   - `89727c…` = SalPhaseIon/endgame (conhecida; capturas 2023→2026, ~4.6 KB de conteúdo real).
   - `4f7a1e4e…` = hash do Cosmic; **só captura 2026 = gate FingerprintJS → domínio parqueado**
     (`abovedomains.com/forsale`); sem conteúdo da era ativa; 404 no espelho.
   - **11 páginas não-documentadas** (`0b0f37, 10d6a2, 21ef05, 53616c, 673e3b, a2aefdb,
     aca20a, c1780c, c2eef3, e24bd2, f9719d`): **todas só com capturas 2025-2026 de ~12 KB =
     app-shell de parking**, nenhuma da era ativa. **Teste decisivo:** `sha256` de **61
     artefatos conhecidos** (chain1-4, os 35 blocos individuais, BIF, BTCSEED, dbbi, faed,
     endereços…) → **nenhum** bate as 11 (só `cosmic→4f7a1e4e`). Logo as 11 **não são portas
     derivadas de artefatos** — são probes de outros solvers (que também testam
     "resposta→sha256→URL") arquivados por acaso como parking. A `53616c7465645f5f…` decodifica
     literalmente para `Salted__`+salt`74c974e3…`+16 B — provável brinquedo de solver, não porta.
   - Espelho `gsmg-archive.org` = site curado (não serve por hash-path; 404 até na 89727c).

**Saldo:** a leitura filosófica "duas portas" era sólida e foi executada com rigor, mas a
rota concreta (porta escondida no arquivo) está **morta**: não há página da era ativa além do
endgame conhecido; o domínio morreu e virou parking; o único hash-artefato real (`4f7a1e4e`)
leva a parking sem conteúdo. Se a "outra porta" existiu, seu conteúdo se perdeu com o domínio
(nunca arquivado na era ativa). Reforça que o desbloqueio é a **regra de derivação dos 35
blocos**, não uma URL/página a mais.

## Sessão 2026-08-20 (e) — BIP39 `blood→blind`, anomalia 163 e matriz DBBI

Uma construção nova e reproduzível surgiu da discussão de `gnomad` no Telegram
(2024-10-22, ids 28055–28087): as 24 casas coloridas podem ser separadas em dois grupos de
12 com soma 1188 ao mover `7,15,31`; o índice BIP39 zero-based 1188 é `nest`. Mais forte:
os 11 índices **primos** coloridos
`[7,23,31,47,71,79,103,127,151,167,191]`, acrescidos da anomalia FEFEFE=`163` na ordem
numérica, dão as palavras BIP39
`abstract actual advance album angry antique artefact avocado base behave belt blood`.
O checksum é inválido; recomputá-lo altera somente o último índice `191→190`, isto é,
**`blood→blind`**, literalmente zerando o último bit. A mnemonic corrigida é válida e a
soma de seus índices é 1159, cuja palavra BIP39 zero-based é **`movie`**. O encaixe é
coerente com *"in front of your eyes but you're not seeing it"* e com o passo seguinte do
roadmap, *"last words before archi choice"*. Não há mensagem no export do Telegram que
registre essa correção de checksum ou a saída `movie`.

Teste falsificável (`solver/anomaly_dbbi_attack.py`): interpretei *"the anomaly revealed as
both beginning, and end"* como a lista de 13 colunas
`[163,7,23,31,47,71,79,103,127,151,167,191,163]` (também com `191→190`). O produto
`DBBI(7×13) × lista(13×1)` fornece sete escalares, que foram alinhados às sete palavras de
quatro bytes do header e aos sete grupos de cinco blocos do Chain4. Foram cobertas somente
as leituras motivadas: `a=0/1`, lista raw/mod-9, ordem direta/reversa, cores B/Y opostas,
alternância, metades opostas e os sete sinais `+/-` do prefixo.

- **288 hipóteses estruturais**, **71.922 chaves AES únicas**, 71.922 testes de privkey
  direta e **2.517.270** plaintexts AES-ECB de 32 B comparados à pubkey do prêmio:
  **0 hard hits e 0 soft hits**.
- Os DBBIs deslocados produziram só 44 quadrados Bifid distintos; o melhor plaintext
  pontuou −6,2899, pior que o baseline canônico `BTCSEED…` (−5,5770). Nenhum abre a
  fronteira.
- Na leitura mais natural (checksum corrigido, `a=1…i=9`, sinais alternados), os sete
  produtos são `[-140,258,1568,-507,-573,2545,256]`. O `−140` da primeira linha é raro:
  num null-model de **1.000.000** de embaralhamentos do mesmo multiconjunto DBBI,
  `|dot|=140` na primeira linha ocorreu 509 vezes (0,0509%); em qualquer linha, 3.396
  (0,3396%). É sugestivo, mas foi observado após explorar várias leituras, portanto não é
  prova isolada.
- Um sinal ainda mais forte aparece ao reduzir esses sete produtos módulo 26. Antes de
  corrigir o checksum, a polaridade alternada oposta dá **`PHASHFG`**; depois de
  `191→190`, dá **`QYINZXW`**. Logo `HASH` e `YIN` estão literais, sem corrigir ou
  permutar letras. No mesmo milhão de nulls, `HASH` surgiu 10 vezes (0,001%), `YIN` 269
  (0,0269%) e **ambos juntos, zero vezes**. A busca exata no Telegram também não encontra
  `PHASHFG`, `QYINZXW`, `HASH YIN` ou `blood blind`: a observação parece inédita. O
  null-model é condicionado à leitura natural escolhida e não corrige todo o viés de
  seleção retrospectiva; por isso sustenta a pista, mas não a transforma sozinho em prova.
- O Telegram já interpreta `HUNDRED FOURTY` como o comprimento, incluindo `0x`, do hex do
  headline do bloco gênese usado na fase anterior (ids 6144, 13453 e 26099). Como
  `140=35×4`, os 140 caracteres foram divididos em 35 quartetos, um por bloco final, nas
  orientações 7×5/5×7: 288 famílias, 10.080 testes de chave direta e 20.160 decifrações
  AES-ECB/CBC com header. Novamente **0 hard/soft hits**.
- `HASH(YIN)` foi testado como SHA-256 literal e como o hash do lado BIP39 corrigido
  (`…belt blind`: frase, entropia e seed), junto de `hash(YANG)`, XOR, soma/subtração,
  concatenações, meias-metades e operações por bloco: 545 chaves, 76.300 candidatos AES e
  7.280 candidatos algébricos, **0 hits**. A leitura **sete letras = sete senhas**
  (`HASHYIN`, `YINYANG`, `PHASHFG`, `QYINZXW`) sobre os sete grupos de cinco blocos também
  falhou: 288 famílias, 696 chaves, 20.160 plaintexts e 10.944 agregações, **0 hits**.

Reprodução: `./puzzle-env/Scripts/python.exe solver/anomaly_dbbi_attack.py`; relatório
completo em `_work/anomaly_dbbi_attack.json`.

**Veredito — CORRIGIDO por verificação de oráculo (Claude, 2026-08-20).** O veredito
anterior ("null-model forte, provavelmente instrução autêntica") **não se sustenta**: as
próprias taxas medidas são **nível-acaso**, não enriquecidas. Analiticamente, num string de
7 letras A-Z: `P('HASH')=8,75e-6` (medido 1,0e-5) e `P('YIN')=2,84e-4` (medido 2,69e-4) —
**idênticas ao aleatório** ⇒ a matriz real NÃO produz HASH/YIN mais que uma embaralhada. O
`joint=0/1M` é o esperado (prob. conjunta ~2,5e-9), não raridade reveladora. Some-se a isso:
(i) a seed é **auto-construída** da "prime list" (índices `[7,23,31,47,71,79,103,127,151,163,
167,190]`, todos primos + `blood→blind` só força o checksum ~1/16); (ii) **incoerência** —
`HASH` sai de `PHASHFG` (leitura PRÉ-correção, descartada) e `YIN` de `QYINZXW` (PÓS-correção):
mistura rascunho com resposta; (iii) o oráculo **já falsificou** toda mecanização (`HASH(YIN)`,
mnemonic, `HASH(YANG)`, XOR, ±, 7 senhas, header/35-blocos = 0 hard/soft hits). A saída "YIN =
algum artefato, não a palavra" é **mover a trave** (unfalsificável). **Conclusão: apofenia,
FRENTE FECHADA.** Preservar só `140` como checkpoint numérico e `movie` como curiosidade — não
reabrir `blood→blind→HASH(YIN)` sem uma regra com **predição-antes-do-teste + zero graus de
liberdade + fechamento de oráculo** (os três juntos; nenhum presente aqui).

## Sessão 2026-08-20 (f) — hints 2026 do criador atacados na FRONTEIRA (4 hipóteses, 0 solves)

Quatro hipóteses **novas** derivadas dos hints primários de 2026 do criador, todas
falsificadas por oráculo duro (`matches_pubkey` vs pubkey on-chain `04f4d1bbd…bf33559`,
e `aes_open`/padding-PKCS7 sobre os 35 blocos). Scripts novos em `solver/`, logs em
`_work/`. Cada uma preenche um gap concreto que os testes anteriores **não** cobriam.

**Gap fechado em cada uma:**
- O `first_hint_sweep.py` testou `89727c…` (hash do 1º hint / URL do endgame) **só
  contra SMALL/COSMIC** (já abertos → teste vazio). A lacuna posterior testou **47
  outras** frases na fronteira dos 35 blocos, **nunca** o `89727c…` em si.
- `eps3.5_kill-process.inc` estava registrado acima como proposta "não-testada/não-
  confirmada"; nenhuma das 47 frases da fronteira o incluiu.
- `CHAIN4_PASSWORD` (`E_C‖E_S‖E_B[:2]`, **32 bytes exatos**) só abria o chain4,
  nunca foi aplicada aos 35 blocos.
- Os testes `28=7×4`/`35=7×5` usaram as 7 palavras como **operadores/checksums/
  ordem**, nunca como **índices de seleção direta** de 7 blocos.

### 1) "rewatch episode 3.5 with the better half" (criador, 2026-03-03) — FECHADA
Episódio Mr. Robot S03E06 = `eps3.5_kill-process.inc`, **28º da série** (header do
Chain4 = 28 bytes). Temas que ecoam o puzzle: **HSM + roubo de certificados de
code-signing** (fase 3 = Thales HSM), `shred -uzn3` → **zero out** (hint "some
characters need to be zeroed out"), **misdirection** ("in front of your eyes but
not seeing it", confirmado por Bingo), 71 prédios / Red Wheelbarrow.
`solver/eps35_attack.py`: ~40 strings do episódio (título em 4 grafias, kill-process,
process.inc, Red Wheelbarrow, 71, 28, "rewatch…with the better half", eps3.4+3.5)
+ combinações com `better_half` (concat/XOR/sha) + leitura "kill-process = zerar
header" + "28o ep = header28 como chave" + "71 como escalar/offset".
**469 chaves únicas × ~10 IVs × {CBC-stream, CBC-perblock, ECB} = 200.370 testes
AES + 316.099 privkey → 0 HARD, 0 SOFT.** Top printabilidade 0,433 (≈ruído).

### 2) "our first hint is your last command" — `89727c…` como chave dos 35 blocos — FECHADA
A frase literal da página SalPhaseion + "give away" + "in front of your eyes" sugere:
o hash do 1º hint = chave do último passo. `sha256(GSMGIO5BTCPUZZLECHALLENGE
1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe) = 89727c…` tem **32 bytes exatos** = AES-256.
`solver/first_hint_frontier.py`: `89727c…` em bytes/hex/UPPER, sha256/double-sha256,
HASHTHETEXT sobre textos visíveis (matrixsumlist/enter/lastwords…/thispassword/
endereço/URL), "our first hint is your last command" e variantes, XOR/concat com
half/better_half/tail, e EVP_BytesToKey (MD5+SHA256) com salts chain4/cosmic.
**89 chaves × ~15 IVs × {stream, perblock, ECB} = 51.086 AES + 135.903 privkey →
0 HARD, 0 SOFT.** A leitura mais elegante ("o hash que todos conhecem é a última
chave") está refutada.

### 3) Senha do Chain4 (32 B) como chave dos 35 blocos — FECHADA
"First hint is your last command" lido como auto-referência: a senha/comando já
usada para abrir o chain4 é reusada na última camada. `CHAIN4_PASSWORD =
chain1[64:79]‖chain2[64:79]‖cosmic[64:66]` = **32 bytes**. `solver/chain4pw_frontier
.py`: a senha, sha256/sha256hex dela, as chaves AES EVP/MD5 e EVP/SHA256 reais que
decifraram o chain4, fatias de chain1/chain2/cosmic, `chain4[:32]`, `sha256(chain4)`.
**7.456 AES + 19.424 privkey → 0 HARD, 0 SOFT.**

### 4) Leituras DIRETAS (sem AES) dos 35 blocos como privkey — FECHADA
`solver/direct_combine.py`: XOR/soma de todos os 35, índices primos, **ápice do
triângulo XOR 1D** (C(34,i) ímpar → posições 0,2,32,34), **header28 como 7 uint32
→ índices mod 35 → selecionam 7 blocos** (leitura não coberta antes), header28 como
28 índices, grupos 7×5 e round-robin, sha256 de concatenações, e combinações com
half/better_half (yin-yang). **40 candidatos → 0 matches_pubkey.**
`header7words mod 35 = [13,5,26,21,14,18,19]_big / [23,15,11,16,29,3,34]_little`
(o little termina em 34, mas sem hit).

**Saldo:** quatro leituras primárias novas (eps3.5, 89727c-como-última-chave, senha-
chain4-reusada, combinações-diretas-incl.-header-como-índice) fechadas com oráculo
duro. Reforça o veredito consolidado: o gargalo da fronteira canônica (regra que
converte `+-`+header28+`7`+35×32B na chave final) é **interpretativo/externo**, não
computacional. Nenhuma string visível do material, nenhum hint 2026 do criador, e
nenhuma combinação direta dos blocos fecha o oráculo. O desbloqueio real continua
sendo ou um próximo hint oficial, ou o insight interpretativo que 6 anos de
comunidade + automação extensa + esta sessão não encontraram.

## Sessão 2026-08-20 (g) — leitura filosófica "the SEED is PLANTED" + BIP39/BIP32 (~973 testes, 0 solves)

Hipótese interpretativa NOVA, derivada da metáfora botânica do puzzle:
*"the **seed** is **planted**"* (fase 1) → *"the flower **blossoms**"* (fase 2) →
*"**return** to the source"* (endgame) → *"very last step is a true **give away**"*.
Se a SEED BIP39/HD-wallet está PLANTADA nos bits da matriz 14×14 (a primeira
coisa que todos veem = "in front of your eyes"), e "return to the source" =
voltar a essa seed, então o endereço do prêmio é uma folha da árvore BIP44
derivada da matriz. Ninguém havia testado os **bits da matriz como entropia
BIP39** — o ENDGAME só testou BIP39 dos *índices coloridos* (primos), que era
apofenia refutada por null-model.

Quatro frentes, todas com oráculo duro (`check_privkey` / `aes_open` / BIP44
→ `PRIZE_ADDR`), todas NEGATIVAS:

### 1) Matriz 14×14 → entropia BIP39 → BIP44 → endereço (`seed_return_attack.py`)
- 4 leituras dos 196 bits (row-major, col-major, espiral CW, espiral CCW) × 3
  tamanhos de entropia (128/160/192 bits = 12/15/18 palavras) × {BIP39→BIP44,
  SHA256→privkey, int-mod-N→privkey, SHA256→AES-35-blocos}.
- **Confirmado:** espiral CCW do upper-left produz exatamente
  `gsmg.io/theseedisplanted` (validação da leitura).
- 48 testes → **0 hard, 0 soft.** O mnemonic da URL (18 palavras:
  "guess opinion flush fresh notice nut spider arrow inflict clinic flip spray
  damage curtain mad soldier grace canyon") não deriva o prêmio.

### 2) BIP39 da matriz + passphrase temática (`bip39_passphrase_attack.py`)
- "Press **enter** and start talking" (Decentraland) → passphrase = "enter"?
- 20 entropias (4 leituras × {16/20/24B + SHA256-32B} + URL + senhas das fases 2/3)
  × 24 passphrases temáticas (enter, HASHTHETEXT, matrixsumlist, yinyang,
  hash-89727c, endereço, causality, flor, shabefanstoo, 7, +-, 101, etc.).
- 456 combinações → **0 hard.** A "25ª palavra" temática não revela o prêmio.

### 3) "Cosmic Duality" = BIP32 child derivation half × better_half
- `half` como parent_priv + `better_half` como chain_code (e vice-versa), índices
  0-9 + hardened 0-4 + temáticos (44', 0', hardened-root).
- HMAC-SHA512(half, better_half) [:32] e [32:] como privkey e AES key.
- 85 testes → **0 hard, 0 soft.** O "casamento" yin-yang não gera o filho-prêmio.

### 4) Dualidade como entropia BIP39 + passphrase (72 combinações)
- `half`, `better_half`, `sha256(half+bh)`, `sha256(bh+half)`, `half^bh`,
  `sha256(half^bh)` como entropia BIP39 (32B → 24 palavras) × 12 passphrases
  (a outra metade em hex, enter, yinyang, etc.) → BIP44 + master-priv + AES.
- 72 combinações → **0 hard.**

**Saldo:** a leitura filosófica mais elegante do puzzle ("a seed está plantada
na fase 1; retorne à fonte; a dualidade cósmica casa as metades; o último passo
é um give-away do que está na frente dos olhos") está **refutada por oráculo**.
A matriz 14×14 como entropia BIP39, com ou sem passphrase, em qualquer leitura
ou tamanho, não deriva o endereço do prêmio. A dualidade half/better_half em
BIP32 também não. A ideia era forte o suficiente para merecer teste — e o
negativo estreita o problema: **a "seed" do puzzle não é uma seed BIP39 dos
bits da matriz, nem uma derivação BIP32 das metadas.** Scripts em `solver/
seed_return_attack.py` e `solver/bip39_passphrase_attack.py`.

## Sessão 2026-09-01 — VIC/checkerboard: lacunas residuais atacadas (`solver/vic_full_attack.py`)

Varredura das lacunas de VIC/checkerboard que o mapa de ataques anteriores deixou
abertas. Log completo em `_work/vic_full_attack.jsonl`; validação cruzada do
decoder vetorizado contra o decode exato + `Scorer` real (|Δ| médio 0,019).
**Resultado: 0 hits de oráculo em ~104,5 milhões de decodes.**

- **F1 — dbbi: mapeamento a–i→dígitos EXAUSTIVO × checkerboard.** Todos os 9!
  mapeamentos × 2 universos de dígitos (0–8, 1–9) × 36 pares de escape × 4
  alfabetos (1ª ocorrência DBIFHCEGA+filler, VIC 3.2.2, A–Z sem J, ETAOIN-first)
  = **104.509.440 decodes (espaço 100% coberto)**. Melhor score **−4,902**, mas
  os top-50 são sopa de ETAOIN (o alfabeto etaoin infla o score por construção,
  não por estrutura recuperada) — abaixo de inglês real (−4,1 a −4,5) e sem
  disparar o gatilho de oráculo. **Conclusão: dbbi não é straddling checkerboard
  com alfabeto fixo conhecido e escapes simples.** Se for checkerboard, o quadrado
  é keyed (espaço de hill-climb, já coberto por `checkerboard.py`/`gpu_checkerboard.py`)
  ou a camada a–i→dígitos não é permutação simples.
- **F2 — dbbi transposto por `matrixsumlist` (13 letras ↔ 13 colunas).** Grades
  7×13 e 13×7, chave em ordem alfabética ± reversa, in/out = 12 streams × 3
  mapeamentos × checkerboard + uso como keystream→Bifid = 3.840 construções;
  melhor −5,532 (checkerboard) / −6,945 (Bifid). NEGATIVO.
- **F3 — chain-addition VIC (lagged Fibonacci).** 13 sementes temáticas (101,
  163, 140, 1141, 7, 28, 35, 256134789, dígitos do dbbi, sha256 do first-hint…)
  × mod 10/9 × ± × a=0/a=1 × universos = 29.952 construções; melhor −6,155 (ruído).
  NEGATIVO.
- **F4 — faed 15×38 transposto por `lastwordsbeforearchichoicethispassword`
  (38 letras ↔ 38 colunas) + boustrophedon + espiral.** 2.592 construções;
  melhor −6,188. NEGATIVO.
- **F5 — melhor plaintext de F1 como senha AES/sha256/keyword Bifid/chave de
  transposição.** Tudo < −7,3; nenhum oráculo.

**Saldo:** as três maiores lacunas de modelagem VIC apontadas na revisão
(mapeamento exaustivo, transposição keyed pelas strings-casamento de
comprimento, chain-addition) estão **fechadas por oráculo**. A fronteira
permanece a mesma: falta a regra que deriva a senha; o espaço de cifras de
substituição simples sobre a–i está esgotado nos dois sentidos.

## Sessão 2026-08-30 — 6 camadas de hipóteses novas sobre os 35 blocos (0 solves)

`final_chain.py` reproduzido (todos os checkpoints OK). Seis scripts (`solver/
new_hypotheses.py` … `new_hypotheses_6.py`), ~2.000 chaves únicas testadas contra
o oráculo duro (`matches_pubkey` vs pubkey on-chain; padding+ASCII como soft):
**0 HARD hits, 0 SOFT hits** em todas as camadas.

1. **Camada 1** (157 chaves): SHA256 do prefixo31 e variantes com `+-7`;
   alterna `+/-` em grupos de 7 e em 35 blocos (sinais por paridade/MSB do
   header); step-7; header7words mod 5 (`[3,0,1,1,4,3,4]`) e mod 35 como
   seletores; chaves triviais (`0x07`, 7); `half·bh mod N`; header28+padding
   (16 formas); EVP_BytesToKey (MD5+SHA256); XOR cycling; EBCDIC; BIP39 dos
   blocos; ~40 senhas temáticas (fases 2/3/3.2/roadmap).
2. **Camada 2**: decodificações do Bifid output (base-26, base-9, WIF
   base58, fatias como AES key, 2ª camada Bifid); 7 senhas das fases por
   grupo de 5 blocos; cifras alternativas (3DES, RC4, ChaCha20, XOR 0x07);
   BIF_REST como passphrase EVP; blocos reversed/wordswap; SHA256/dblsha256
   por bloco; bits da matriz 14×14 como chave; fatias de half‖bh; grupos de
   5 em ECB com half/bh.
3. **Camada 3**: encodings binários do BIF_REST (A-M/N-Z, A-I/K-Z,
   vogal/cons, offsets 0-96); base-25 do BIF_REST/BIF (offsets 0-55);
   coordenadas do quadrado Bifid em base-5; **Bifid ENCRYPT correto** de faed
   (13 períodos); 7 primos como seletores → XOR/soma → AES; interleave das 7
   partes da fase 3; 16 rounds de AES-ECB com mesma chave; half±bh escalares
   (15 combinações mod N); row/col sums da matriz como keystream.
4. **Camada 4**: Bifid encrypt correto (p=570 dá `BCEEDCB…` — diferente do
   decrypt, nada legível); double/triple Bifid decrypt; "BTCSEED" e 9
   variantes como senha (AES/EVP nos 35 blocos); EVP no chain4_blob com 8
   senhas; BIP39 entropy por bloco (12/24 palavras); XOR/soma de todos os 35;
   pares consecutivos e simétricos XOR/ADD.
5. **Camada 5** (ordens de leitura): **transposta** — colunas j=0..31 dos 35
   blocos (3 subsets de 32); diagonais/anti-diagonais; strides 35/33/34/36/37/
   7/5/23/16/17/19 com offsets (no body e no blob 1151); header28 como
   posições no body; interleaves (grupos 2/4/7/8); reversed (body/blocos/blob);
   bloco i como chave do bloco i+1; **primeiros 32 primos como bytes**;
   7/16/23 primos; header28+16 paddings; prefix31+9 pads; XOR/soma de subsets
   (prime/múltiplos de 5/7/first7/last7); 7 grupos de 5 e 5 grupos de 7
   (XOR/soma/concat 4-6-7 bytes de cada); rotações de bits; 7º byte de cada
   bloco; byte 23/16; header28 como índices de blocos.
6. **Camada 6** ("7 intertwined passwords" literal): as 7 palavras uint32 do
   header28 como senhas (sha256 raw/hex/decimal, word×8, EVP/MD5 com 5 salts)
   para 7 grupos de 5 blocos (contíguo/round-robin, CBC+ECB); palavra g como
   senha do bloco i (ciclismo); palavras concatenadas + padding como chave;
   palavras como escalares; 23 blocos ± XOR/add com palavras ciclando; 16
   rounds AES com chaves rotativas das 7 palavras; concat/XOR dos 7 sha256.

**Saldo:** ~2.000 hipóteses estruturais adicionais fechadas por oráculo duro
(sem privkey-hit, sem padding+ASCII, top printability 0,44 ≈ ruído). As
famílias mais naturais que restavam (transposta/colunas, strides, primos como
bytes e seletores, header-palavras-como-senhas, Bifid bidirecional, BIP39 por
bloco) estão agora cobertas. Coerente com o veredito consolidado: o gargalo é
**interpretativo/externo** — a regra que converte `+-`+header28+`7`+35 blocos
na chave final não é nenhuma combinação estrutural conhecida do próprio
payload. Não reabrir estas famílias sem hipótese nova derivada de hint real.

## Sessão 2026-08-30 — pop-cultura + diff do Arquiteto (2 frentes, 0 solves)

Duas leituras "não-óbvias" derivadas das referências culturais das fases,
ambas falsificadas por oráculo (`matches_pubkey`, padding+ASCII, EVP SMALL/
COSMIC ≥85%). Scripts: `solver/pop_culture_attack.py`, `solver/architect_diff.py`.

1. **Títulos/nomes como keyword do quadrado Bifid** (64 keywords: SALPHASEION,
   COSMICDUALITY, ALPHANOESIS — `SALPHASEION` é anagrama exato de
   `ALPHA+NOESIS` —, KEYMAKER, TEMETNOSCE, MEROVINGIAN, NEBUCHADNEZZAR,
   WHITERABBIT, GOASKALICE, HAL9000/SAL9000, QU4RTZ, WHITEROSE etc.), períodos
   570/91/38/13/7 no faed e 91/13/7 no dbbi + top-5 como senha AES/EVP.
   **Melhor keyword: −6.078** (NEBUCHADNEZZAR:dbbi p7), bem **pior** que o
   canônico (−5.577). Resultado útil: *reforça* que o quadrado `DBIFHCEGA…`
   derivado do dbbi é o único com sinal (BTCSEED não é coincidência de keyword).
2. **O mapeamento literal do discurso ORIGINAL do Arquiteto**: "select from
   the matrix 23 individuals — 16 female, 7 male — to rebuild Zion" ↔ "select
   from over twenty-three ciphers, sixteen encryptions and or seven
   intertwined passwords". Lido como 7 senhas (palavras do header28) × 16
   "receptivas" (IV de 16 B): 8 chaves-7palavras × 15 IVs (metades half/bh,
   XOR, blocos 0/34, header, cosmic, chain1/2[64:80], c4pw) + direção inversa
   (chave=dualidade × IV=7 palavras) = ~140 combinações CBC/scan → **0 hits**.
3. **~120 frases canônicas** (Matrix: "no one can be told what the Matrix is/
   you have to see it for yourself" — espelho exato do hint "in front of your
   eyes" com "Bingo" do criador —, TEMETNOSCE, KNOCKKNOCKNEO, duas portas,
   METACORTEX, MARK3NO11, MOBILAVE, DUJOUR; 2001/HAL; eps3.5 dupla
   `qu4rtz.decr1p7.nd4c0de.perl`, poema Red Wheelbarrow completo, BONSOIR
   ELLIOT, FSOCIETY00DAT; Jefferson Airplane; Venus Project; grafias "erradas"
   do próprio monólogo FOURTY/WAISTING/THROPHIES/YINGYANG) como senha nos 35
   blocos, SMALL e COSMIC (raw+sha256hex) → **0 hits**.
4. **Diff palavra-a-palavra monólogo vs roteiro do filme** (matrixfans/
   scottmanning, concordantes; reproduzível no script). Desvios únicos:
   inserções **YOU / ME / WELL / NOT / CODES / HOPEFULLY**, "WE"→"I" (2×),
   SIXTH→LAST, ONE→YOU, MATRIX→PUZZLE, PROGRAM→BASICS, ZION→"YOUR WILL TO
   LIVE AND", "ENTIRE HUMAN RACE"→"ENTIRENESS OF YOURSELF **SELF** … CIAO
   BELLA O", + a súplica GSMG com HUNDRED FOURTY/WISEMAN ABOVE. Testes
   mecânicos do diff: palavras inseridas/duplicadas como senha; letras extras
   das grafias (U,I,H + G de THINGKY do pré-texto — 24 permutações "UIHG");
   mapa de letras ONE→YOU (O→Y,N→O,E→U) aplicado ao Bifid; posições das
   duplicadas como índices de blocos; seleções 7+16=23 blocos (7 do header +
   16 complementos, XOR/soma); fatias char/word 140 do monólogo e do faed →
   **0 hits**.

**Saldo:** as leituras pop-culturais naturais (keywords de nomes, o 16+7 do
filme, frases canônicas, o diff mecânico) estão fechadas. Fatos que sobrevivem
como **pistas interpretativas não-mecanizadas**: os três ecos "YOU"/"ME"/"SELF"
(+ "AND WILL") parecem deliberados e não fecham oráculo como fórmula — sugere
papel semântico (pessoas da dualidade?), não aritmético; o "O" final de "ciao
bella o" e a grafia "ying yang" seguem sem explicação. Nenhum reabrir sem
predição-antes-do-teste + zero graus de liberdade.

## Sessão 2026-09-01 (b) — composição checkerboard↔Bifid FECHADA + hints inéditos do criador minerados

**Composição (`solver/composition_attack.py`, log `_work/composition_attack.jsonl`,
Bifid validado pela reprodução do baseline BTCSEED −5,577):**

- **G1** checkerboard→Bifid e Bifid→checkerboard sobre faed (2 mapeamentos × 36
  pares × 5 alfabetos × 14 períodos) = 18.000 construções; melhor −5,577 = o
  próprio BTCSEED re-emergindo pela composição identidade (valida o pipeline,
  não é sinal novo). NEGATIVO.
- **G2** dbbi como keystream ± mod 25/26 sobre as top-200 saídas de checkerboard
  = 2.400 construções; melhor −7,356. NEGATIVO.
- **G3** dbbi como chave de transposição colunar (larguras 91/13/7/38, letras e
  dígitos) sobre faed → checkerboard = 5.184 construções; melhor −6,479. NEGATIVO.

Com isso, as lacunas de composição VIC listadas na revisão estão esgotadas.

**Mineração do `result.json` (427 mensagens do criador, 2019–2026) — hints NÃO
documentados antes neste arquivo:**

- 2021-04-01: **"R=18 / A=1 / B=2. Could also be 21 or 1812 bit 🧐."** — confirma
  a1z26 (coerente com shabef=sha256) e sugere os números 21 e 1812 (bits?).
- 2023-12-26 **"Have you tried the purple pill already?"** + 2025-09-15
  **"Carrots were originally purple, until the Dutch turned them orange in the
  1600s…"** (resposta direta a "anything else for us?") — tema ROXO = vermelho+azul,
  possível ponte com as cores da fase 1 (amarelo #FFF200 / azul #3F48CC, somas
  hex 47/54) e o poema "Roses are White but often Red".
- 2021-12-31 + 2023-05-02: **a data de expiração do passaporte do Neo**
  (Matrix: 11 SEP 2001) apontada duas vezes como "a única data" dada.
- 2023-08-04: **GSMG = "Globally supporting my generation"**.
- 2024-01-26: **"Regular Bitcoin Private key"** — o alvo é uma privkey comum
  (tensiona com as linhas BIP39/seed já refutadas).
- 2023-01-09: **"@barrystyle provided a very specific hint already"** (refere-se
  ao post do barrystyle sobre a imagem/livro "Cosmic Duality", 2022-12-11:
  "you'll see how scary specific that is") + "prime number is very important".
- Confirmações do criador: mensagens OP_RETURN na blockchain **não são dele nem
  parte do puzzle** ("Correct", 2023-08-29); SHA256 do texto da fase 1 confirmado
  com "the author is a bit picky what he considers to be text" ("Good point");
  "Has anyone passed the salvation part?" → **"Partly"** (2023-08-06).

## Sessão 2026-08-30 — hint confirmado: p.39 "Le Miroir de la Vie et de la Mort" + oráculo-espelho (0 solves, 1 gap fechado)

**Evidência primária NOVA (mineração própria do `result.json`, via citação de
Diego Schmidt 2025-06-13):** Jrk Bgrt, **2023-01-08**: *"@barrystyle, provided
a very specific hint already. **(Cosmic Duality Book Page — Life and Death)**"*.
O parêntese com a página exata não estava documentado — só a referência genérica
ao post do barrystyle.

1. **O livro identificado:** Time-Life Books, série *Mysteries of the Unknown*,
   volume **Cosmic Duality** (1991). Sinopse da editora: "pairs of opposites such
   as life and death, **male and female**, and especially, evil and good" (a
   mesma dualidade do "16 female, 7 male" do Arquiteto). Scan: archive.org
   `cosmicdualitymys0000time` (baixado em `_work/cosmic_duality.pdf`, 152 pp.,
   não versionado — regenerável do identifier). **p.39 do livro = p.43 do PDF** =
   gravura francesa do séc. XVII **"Le Miroir de la Vie et de la Mort"** (a
   "ultimate duality" citada na legenda da p.38; crédito do livro: Bayerische
   Staatsbibliothek, Munich; versão colorida no Musée Carnavalet via Bridgeman
   ID 419521). Tradução impressa na p.38: *"To love beauty is unwise, for time
   destroys it. In this world of contrasts, everything changes, and the moment
   we start to live, we start to die."*
2. **Verso francês (reconstrução parcial, consenso multi-OCR)** — engines:
   camada tesseract do scan + Windows.Media.Ocr (en-US e pt-BR) via
   `_work/winrt_ocr.ps1` sobre recortes 600 DPI:
   `LE MIROIR DE LA VIE ET DE LA MORT / [?] la beauté d'un [vis]age, / [?]
   aymer; ce n'est point estre sage, / le temps en moins d'une heure [?] /
   tout ce monde et nostre [?] à peu [estre,] / qu'on commençons à vivre, on
   commençons à mourir.` Inícios das linhas 1–2 não recuperados (tipo itálico
   antigo no limite do OCR); salvo em `_work/miroir_verse.txt`. Rotas para o
   verbatim completo: tesseract local, digitalização BSB, asset Bridgeman 419521
   (MeisterDrucke 403 no fetch; portal Paris Musées não filtra por frase — 451k
   resultados — e busca site: não achou registro com esse título).
3. **Testes do material** (`solver/miroir_attack.py`, 56 senhas): verso
   (parcial/reconstrução/tradução EN) em raw/UPPER/sem-espaços como EVP
   SMALL/COSMIC (≥85% ASCII), sha256→privkey, AES-256 nos 35 blocos (IVs
   zero/header/half); títulos FR/EN; **cifra-de-livro com índices primos** sobre
   o verso (letras 1/0-based, iniciais e palavras em posições primas);
   mecânica do espelho **pré-Bifid** (atbash do faed/dbbi, reversões, quadrado
   derivado do dbbi-espelhado, atbash do output) → **0 hits**; todas as
   variantes de espelho pontuam −6,8 a −8,3, **pior** que o canônico −5,577 — o
   espelho não é camada pré-Bifid (mais um negativo que reforça o quadrado
   canônico como único sinal).
4. **ORÁCULO-ESPELHO (novo — nunca testado em todo o campaign;**
   `solver/mirror_attack.py`): a gravura ensina a ver uma coisa através do seu
   oposto; em secp256k1, para cada x há dois y (y e p−y) e a privkey do
   ponto-espelho é **N−k**. Se o puzzle *entrega* N−k, todo scan histórico
   (oráculo = pubkey exata) teria errado por um sinal. Ponto-espelho do alvo:
   `04f4d1bbd9…464638c2da…dd40cc6d6` — endereço-"morte"
   **`1LzLrZVkafbXLpam3qibRDdMe5sttUoCq4`**. Resultados:
   - **better_half ≠ N−half** e as duas metades **não compartilham x** — as
     "duas metades" NÃO são gêmeas-espelho (refuta a leitura estrutural mais
     elegante do yin-yang);
   - ~3.704 janelas de 32 B em todos os estágios + N− de todos os artefatos
     base + 35 blocos e N−blocos + sha256 por bloco + combos das camadas
     (XOR/soma de subsets, pares simétricos, seleções por header) + plaintexts
     AES das chaves naturais — todos contra o oráculo-espelho **e** o direto →
     **0 hits**. Gap fechado para as famílias naturais; o oráculo-espelho entra
     no toolkit permanente (todo candidato futuro deve checar ambos os pontos).

**Saldo:** a página exata do hint confirmado está identificada e reproduzível;
o material dela não fecha oráculo nas leituras naturais; a mecânica-espelho
formalizada (EC-negação) está refutada nas leituras estruturais e naturais. O
"scary specific" da página permanece interpretativo — as leituras mecânicas
óbvias do espelho estão mortas. Próximos passos reais nesta frente: (i) verbatim
completo do verso para expandir a bateria (verso/cifra-de-livro); (ii) páginas
vizinhas do livro (p.18: Jung, "liberation from opposites", já citada pelo
gnomad; contracapa/sumário).

## Sessão 2026-08-30 — RECEITA PROVADA do passphrase do Cosmic ("intertwined = XOR") + imagem completa forense

**1. A GRAMÁTICA DOS "SEVEN INTERTWINED PASSWORDS" ESTÁ PROVADA (positivo!).**
Mineração do `result.json` (mensagem do k1ng, 2025-08-23): *"the combined
passwords produce what he said, but you need to **hash them individually and
then xor them together**"*. Verificado localmente com zero graus de liberdade
(`solver/intertwine_attack.py`):

```
a795de117e4725…50735 = sha256("enter") ⊕ sha256("lastwordsbeforearchichoice")
  ⊕ sha256("thispassword") ⊕ sha256("yourlastcommand") ⊕ sha256("secondanswer")
```

Equivalente ao XOR das 7 partes da senha combinada
(`matrixsumlist·enter·lastwords…·thispassword·matrixsumlist·yourlastcommand·
secondanswer`) — o `matrixsumlist` duplicado **cancela** no XOR ("7 intertwined
passwords"). Os tokens vêm TODOS da página (`yourlastcommand` = *"our first hint
is your last command"*; `secondanswer` = *"shabef ans too"*). **Implicação
estratégica:** o passphrase do Cosmic tem derivação significativa dos tokens da
página — a etapa cosmic da cadeia NÃO é falso-positivo de padding (reabilita
parcialmente a cadeia contra a retratação #104); a gramática XOR-of-sha256 é a
mecânica real do puzzle.

**2. A mesma gramática NÃO fecha os 35 blocos** (baterias v2–v4:
`intertwine_attack2/3/4.py`, ~1.900 seleções): pool cronológico das 31 senhas
do puzzle (seleções por índices primos 0/1-based, first-7/16/23, header-words
como índices), **todas as C(12,7)=792 7-subsets** do núcleo da página, receita
+ 1 token (todas as extensões), **16+7=23** do filme (16 partes-senha página+
fase-3; 7 senhas das 7 etapas em 3 formas), janelas deslizantes de 7/16/23
palavras sobre o monólogo e o texto 3.2.2, as 7 palavras de *"our first hint is
your last command"* (como senha do SMALL — a de 69 chars segue sendo a única
que abre), palavras inseridas do diff (YOU/ME/WELL/NOT/CODES/HOPEFULLY),
frases do Arquiteto, `a795de11` raw como chave AES. **0 hits** (oráculo duplo
alvo+espelho, CBC 6 IVs + ECB + scan de privkey). A seleção final da chave dos
35 blocos não é XOR-of-sha256 de nenhuma seleção natural.

**3. Imagem completa do puzzle recuperada e forense total (fechada).** CDX do
Wayback revelou `gsmg.io/Puzzle` = **PNG real da era ativa** (2020-11-12,
29.931 B, 1048×1556; salvo em `_work/archive/Puzzle_full.png`, nunca presente
no repo — o ENDGAME só conhecia o recorte da matriz). Geografia completa
(System.Drawing, scripts `_work/pixel_*.ps1`/`zone_map.ps1`): matriz 14×14
(75 px/célula, FEFEFE em (7,4) = x300–374/y525–599 ✓), **linha vermelha
y=1047–1061** (15×1047 px 100% sólidos de #ED1C24, zero variação), rodapé
cinza (y1065–1552) com: logo GSMG azul, banner "GSMG.IO 5 BTC PUZZLE
CHALLENGE" (OCR), QR preto (o conhecido — decodifica para o endereço), e o
endereço-prêmio (OCR da segunda faixa). **Zero pixels roxos, zero anomalias
além do FEFEFE documentado, linha vermelha sem esteganografia.** A "purple
pill" não esconde canal em nível de pixel — a conclusão do k1ng ("500 hours…
nothing relevant") confirmada programaticamente. As faixas de texto abaixo da
linha vermelha = banner + endereço (o "texto" cujo sha256 = 89727c…).

**4. Varrida de imagens/páginas arquivadas do domínio (CDX completo).**
- `img/red_*/blue_*/black_*` (crypto_gic, n_you, open_lock_n_ing, t, ca,
  dig_i, lock_lo, banking-war): ativos da homepage (2020-11-15), **rebus de
  marketing** ("crypto logic", "digital", "banking war"…), não-puzzle. Salvos
  em `_work/archive/` para o registro.
- `gsmg.io/door.png` e `img/puzzle.png`: capturas **parking-era** (2025/26,
  HTML comprimido) — probes de solvers, beco.
- `gsmg.io/choiceisanillusion…averyspecialdessertiwroteitmyself`
  (2020-11-12, ativa): **é a página da fase 3 conhecida** (README §3) — os dois
  FENs (w = posição dada; b = resposta do "buddhist move") e o blob PHASE 3
  batem com o documentado. Re-verificação independente, nada novo.
- `/merovingian`, `/final_stage`, `/followthewhiterabbit`, `/phase1..3`,
  `/eps3.4_runtime-error.r00` etc.: capturas parking-era (probes).
- `follow_the_white_rabbit.png` do Wayback = byte-idêntico ao local.

**Saldo da sessão:** o único POSITIVO é a receita do Cosmic (acima) — primeira
derivação significativa de uma senha do puzzle fora da concatenação literal;
ela muda o mapa: a gramática "intertwined = XOR de sha256 individuais" está
provada e o pipeline "shabef ans too" fecha semanticamente. O negativo: a
chave dos 35 blocos não usa essa gramática em seleção natural alguma, a imagem
completa não tem canal oculto, e as portas arquivadas novas são marketing ou
probes. A fronteira permanece: a regra que converte `+-`+header28+`7`+35
blocos na chave final — agora com a hipótese forte adicional de que ela deve
ser **uma gramática derivável dos tokens** (como SMALL=concat e COSMIC=XOR),
ainda não encontrada.

## Sessão 2026-08-31 — candidato DBBI/FAED: `SEND THE BLUE TO SET HEX`

Um script compartilhado no Telegram por **X** em 2026-05-22 (mensagens 63504–63520,
cópia pública em [Ideone fZkIsw](https://ideone.com/fZkIsw)) revelou um checkpoint
estrutural ainda não documentado. A construção tem dois encaixes exatos:

- `len(dbbi)=91=C(14,2)`: `a=1…i=9` preenche o triângulo superior de uma matriz
  simétrica 14×14; suas 14 somas de linha formam uma chave periódica;
- `len(faed)=570=38×15`: o FAED vira 38 linhas de 15 caracteres; cada soma de linha
  é XORada com a chave e reduzida módulo 26.

A saída-base contém `SENDTHE` no offset zero-based 11:

```text
JLIQFOPGVBLSENDTHECZAGJJYDSWCGUDJNFTWB
```

O zero-mask azul/amarelo/primo aplicado ao FAED produz `BLUENET` no offset 9;
zerar na matriz-chave as arestas indicadas pelas células amarelas produz `TOSETHEX`
no offset 11:

```text
JLUPFLPGLBLUENETDICZAGAJQDSWCGUDONFHWB
OLIQUBROVQLTOSETHEXQYOJSSICJFGUDCCVBWQ
```

O autor do script publicou a interpretação **`SEND THE BLUE TO SET HEX`**. O `NET` foi
acrescentado depois por outros solvers: os três marcadores não começam na mesma coluna e
não houve confirmação de Jrk. Portanto `SENDTHE`, `BLUE` e `TOSETHEX` são os marcadores
reproduzidos; `BLUENET` é uma extensão comunitária. O encaixe `91=C(14,2)` explica
naturalmente o tamanho do DBBI e dá ao hint “zeroed out” uma aplicação concreta, mas a
receita completa permanece pós-selecionada.

Reprodução e null-model: [`solver/blue_net_attack.py`](solver/blue_net_attack.py),
relatório em `_work/blue_net_attack.json`. Em 2×20.000 permutações com contagens de
símbolos preservadas, nenhuma igualou os marcadores publicados; limite superior unilateral
de 95% condicionado à receita ≈`1,50e-4`. Esse número **não** corrige os graus de liberdade
do pesquisador nem a escolha post-hoc das palavras.

Bateria curta na fronteira final: 27 materiais estruturais, 58 chaves e 79 passphrases;
ECB mais cinco decifrações CBC por chave, EVP com key+IV reais, scan escalar byte a byte e
oráculos direto/espelho. Resultado: **0 private-key hits, 0 plaintexts semânticos e 0
paddings na camada final**. Um padding casual apareceu no SMALL com imprimibilidade 0,418,
corretamente classificado como ruído. Logo, nenhuma interpretação testada equivale a “usar
as posições/cor/rede azul diretamente como chave AES”. A próxima fronteira é determinar
o verbo técnico **SEND** e o destino **SET HEX**, sem promover `NET` a pista confirmada.

### Operacionalização do verbo `SEND`/`SET HEX` — 5 leituras, 0 solves (`send_blue_sethex_attack.py`)

Tratei `SEND THE BLUE TO SET HEX` como o "first hint" que fixa a 2ª camada e testei
operacionalizações concretas do verbo NÃO cobertas pela bateria anterior. Script:
[`solver/send_blue_sethex_attack.py`](solver/send_blue_sethex_attack.py) (reusa
`oracles`/`final_chain`/`blue_net_attack`), relatório em `_work/send_blue_sethex_attack.json`.
**73 chaves de 32B + 20 passphrases + 6 IVs**; oráculo duro = pubkey-alvo `04f4d1bbd9…`
+ espelho, endereço-prêmio, BIP44/BIP32 e blobs SMALL/COSMIC. Resultado: **0 hits em
privkey/endereço, 0 seed BIP32, 0 pubkey-markers nos 35 blocos, 0 opens semânticos**. Um
único padding PKCS7 casual (ECB sob `sha256(faed@amarelo)`, ratio 0,389) = ruído ~1/256.

- **H1 — "SET HEX" = decode a-i→dígito→HEX de FAED/DBBI é o valor hex.** FAED (570 chars
  a-i) decodifica para 570 dígitos, todos em 1-9 (nibbles hex válidos; o próprio prefixo
  `faed`→`6154`). Testei os dígitos lidos como hex (`[:32]`/`[-32:]`, mapas a=1..i=9 e
  a=0..i=8), `sha256(dígitos)` e `sha256(raw)` de faed/faednp/dbbi como privkey, seed
  BIP32 (inclusive o hex longo de 285B) e chave AES dos 35 blocos. **Nada.**
- **H2 — "SEND THE BLUE" = selecionar pela máscara azul.** Subsequência de FAED nas 15
  posições azuis lineares e as 15 letras DBBI nas arestas azuis (`bbbhibeeehefbfe`), mais
  a amarela (9). Decode→hex/sha256 → mesmos oráculos. **Nada.**
- **H3 — cores como VALOR hex direto.** `0xBE2B9B` (azul) e `0x41D464` (amarelo) — que são
  **complementos exatos** (`BE2B9B ⊕ 41D464 = FFFFFF`) — como chave (repetição→32B,
  `sha256` do raw/ascii-hex/decimal, pares concatenados) e como **IV** dos 35 blocos.
  **Nada.**
- **H5 — string-instrução como senha.** `sha256` de `SENDTHEBLUETOSETHEX`/`SET HEX`/etc.
  como chave AES dos blocos; cores e dígitos faed/dbbi como passphrase EVP em SMALL/COSMIC.
  **Nada** (confirma e amplia o que `blue_net_attack.py` já vira).

Incorporando o chão-verdade garimpado do `result.json` (correções do coordenador):

- **Receita verbatim de X (id 63520):** "dbbi row sums = chave repetida; faed 570=38×15 →
  38 linhas de 15, somadas; XOR com a chave; zero-masks azul/amarelo → SENDTHE, BLUE,
  TOSETHEX". É **exatamente** o que `blue_net_attack.py` já reproduz byte-a-byte. O
  `ideone fZkIsw` NÃO é o script de X (é um gerador de primos de outro user); o
  `dbbi_sum_faed.py` real não está no export.
- **Reframe dos solvers seniores:** *gnosis* (id 64922) — os marcadores leem como
  **verificadores**, não a chave AES final; faltaria "um último passo de composição binária
  que Jrk chamou de **yinyang**". *Vasilis Dragon* (id 65629) — "the s15 / P-M 'set hex'
  readings are curve-fit, they're dead" e já rodou todos os valores retidos como chave sob
  EVP-md5/sha256 → nada. **Meus 0 em H1-H5 são confirmação independente desse veredito.**
- **H6 — hipótese "yinyang"/verificador (nova frente).** Se os marcadores só validam o
  alinhamento dbbi/faed, a chave viria de compor binariamente as duas metades. Testei
  duplas concretas do endgame: `HALF ⊕ BETTER_HALF` (as duas metades já decodificadas do
  cosmic), `sha256(half‖better_half)`, `bluepos ⊕ yellowpos`, `blue ⊕ set-hex`, e as rails
  base/blue/yellow XORadas → privkey + AES-35-blocos. Também testei `half` e `better_half`
  **sozinhas** como privkey. **Nada** — nenhuma composição binária óbvia rende a chave.
- **H7 — lead EI E (id 66216).** `BLUENET as hex = 061119242f3a5863767e81a3aab9c1` (15B =
  as 15 posições azuis); o único dígito hex faltante é **`d`** (0x0d); em DBBI `d` aparece
  4× (pos. 1,48,55,74; soma **178** → row 13 col 10 = último amarelo em row-major). Testei
  o hex de 15B e as completações com `d` (pad-0, `+0x0d`, repetição→32B, `sha256`, e `178`
  como material) como chave/privkey. `blue_net_attack.py` já cobria `sha256`/`repeat16` de
  `blue16` e do set `0123456789abcdef`; as formas de 32B diretas aqui adicionadas também
  dão **0**.

**Saldo:** as leituras "set hex → chave" estão agora exaustivamente NEGATIVAS em oráculo
duro, corroborando o veredito de Vasilis de que são curve-fit. O que **não** consigo fixar
sem mais informação: (a) o "yinyang"/último passo de composição binária que Jrk citou — não
há no material publicado uma definição única de QUAIS dois operandos compor nem COM QUAL
operação (testei as duplas mais literais; o espaço de composições arbitrárias é grande
demais para busca cega sem gradiente); (b) o script real `dbbi_sum_faed.py` de X e a imagem
associada (fora do export do Telegram). A frente permanece interpretativa: os marcadores são
provavelmente **verificadores de alinhamento**, e falta a regra — ainda não publicada — que
transforma o material verificado na chave AES dos 35 blocos.

## Sessão 2026-08-31 (b) — campanha multi-agente: verificação dos positivos + 4 frentes fechadas + inteligência do Telegram

Campanha de 4 agentes paralelos, com re-verificação independente dos achados
"load-bearing" e da suspeita de erro no oráculo. **Saldo: 0 solves, mas os
positivos verificados e o gargalo re-confirmado como EXTERNO.**

### 1) Positivos re-verificados (independente, byte-a-byte)
- **`intertwined = XOR`**: `sha256("enter") ⊕ sha256("lastwordsbeforearchichoice")
  ⊕ sha256("thispassword") ⊕ sha256("yourlastcommand") ⊕ sha256("secondanswer")`
  == passphrase Cosmic `a795de117e472590…52e50735` **(match exato reproduzido)**.
  Como acertar 256 bits exatos não é força-brutável, a gramática XOR-of-sha256 é
  real (não coincidência de padding). Reforça a reabilitação parcial vs. #104.
- **Cadeia canônica**: `final_chain.reproduce()` dá `half=0423d911…`,
  `better_half=48cc46e6…`, header `+-`+28B+`7`, 35×32B. Os checkpoints sha256
  batem com os do solver sênior Vasilis Dragon (Telegram id 65629): cosmic
  `4f7a1e4e`, chain4 pós-AES 1151B `e4269ed5`, 35 blocos 1120B `43d3fe43`.
  **Confirmado que atacamos a cadeia canônica**, não a derivação quebrada da #68
  (`a80a399a`, "wrong bytes").

### 2) SUSPEITA DE ERRO investigada — pontos-cegos do oráculo (reais, porém benignos)
`solver/strong_oracle_35.py` + `solver/strong_recheck.py`. O detector antigo
(`intertwine_attack.full_battery`) tinha 3 pontos-cegos REAIS: (a) scan de privkey
só em offsets múltiplos de 16 (perdia privkey não-alinhada); (b) sem WIF, BIP39
nem privkey em HEX-ASCII; (c) só 5 IVs. **Mas remover os três NÃO revelou nada**:
38 famílias já "esgotadas" × 6 IVs CBC + ECB × varredura byte-a-byte + WIF +
BIP39 + hex-ASCII (alvo+espelho) → **0 hard, 0 soft**. Nuance importante: o gate
de 80% ASCII do `valid_pt` só afetava o reporte SOFT — o scan de privkey crua já
rodava independente, então nunca escondeu uma privkey crua. **Os negativos antigos
dos 35 blocos se sustentam mesmo sem os pontos-cegos** — a dúvida "e se o detector
estava fraco?" está fechada. `strong_oracle_35.py` vira o detector canônico.

### 3) Terceira gramática sobre artefatos-bytes — FECHADA
`solver/third_grammar_attack.py`. Aplicou as gramáticas PROVADAS
(`XOR(sha256_individual)` / `sha256(concat)` / seletor-header) aos **artefatos
intermediários da cadeia** (half, better_half, E_C, E_S, keymat79, cc[833:865],
header28, XOR dos 35 blocos) — lacuna que o `intertwine_attack.py` deixara (só
testara strings de token). **103 chaves, 0 hard, 0 soft** sob o detector forte.
As chaves a priori mais fortes (`sha256(half‖better_half)`, `XOR(sha(half),sha(bh))`,
`XOR(sha(E_C),sha(E_S))`) todas negativas. As duas metades **não** formam a privkey
por XOR/mul/sha/and/or/add-bytewise nem ±mod N (verificado à parte).

### 4) SEND THE BLUE TO SET HEX — FECHADA (ver seção detalhada acima)
`solver/send_blue_sethex_attack.py`, 7 hipóteses, 73 chaves + 20 passphrases, 0
hits. Confirmação independente de que "set hex" é curve-fit (veredito de Vasilis)
e de que os marcadores SENDTHE/BLUE/TOSETHEX são **verificadores de alinhamento**,
não a chave (reframe do gnosis). Fato novo: FAED → 570 dígitos **todos em 1-9**
(nibbles hex válidos); cores complementares exatas (`BE2B9B ⊕ 41D464 = FFFFFF`).

### 5) Inteligência do Telegram (garimpa read-only do `result.json`) — INÉDITA aqui
- **Criador (Jrk Bgrt / @SoWut), 2025–2026 — NENHUM hint operacional.**
  2026-03-03: *"No hints, only free will."*; único ponteiro social: *"Looks at
  gnomad. 👀"* (aponta o usuário **gnomad** como quem estaria no caminho);
  *"I only need to look at the address. If any of you reaches the next phase, the
  price is taken in no-time."*; *"I'm going to rewatch episode 3.5 with the better
  half."* (Mr. Robot + companheira). 2026-05-28: *"The puzzle is still valid!"*.
  Mensagem binária de Ano-Novo (2026-01-01) decodifica a *"…here's a 'tiny hint'
  <3"* — provável gozação. "better half" = **companheira dele** (confirmado
  2025-04-28), não um artefato criptográfico.
- **Hint decisivo de enquadramento (2024-01-26): "Regular Bitcoin Private key"** —
  o alvo é uma **privkey comum de 32 B**, não seed/BIP39. Reorienta: o plaintext
  final dos 35 blocos deve *conter uma privkey crua*; as linhas BIP39 são
  provavelmente ruído (coerente com todos os negativos BIP39).
- **Estado-da-arte da comunidade (Vasilis Dragon, id 65629):** já rodou TODOS os
  valores retidos como chave (8 K-values, 4 E-fields, cosmic key, header28, C32,
  faed s15 rail + completações, yellow-prime+blue, o "68-byte half/better-half
  thing", two-primes) sob a KDF EVP exata → nada. Diagnóstico dele do bloqueio:
  *"either it's a transform nobody's hit in seven years, or the missing piece died
  with the site"* — e o que falta publicamente é **a página salphaseion/cosmic ao
  vivo (texto de instrução ao redor dos blobs) e o primeiro hint de 2019 verbatim.**
- **gnosis (id 64922):** falta *"um último passo de composição binária = yinyang"*.

### Veredito da campanha
As 4 frentes atacadas fecham com negativo control-validado; a suspeita de erro no
oráculo foi investigada e é **benigna** (negativos se sustentam). Nenhum caminho
computacional novo abriu. O gargalo é re-confirmado **externo/interpretativo**: a
regra que converte `+-`+header28+`7`+35 blocos na privkey regular do prêmio não é
derivável do material público — precisa da página live original ou do primeiro hint
de 2019 verbatim (convergente com o solver sênior da comunidade). **Não reabrir
sweeps sobre os 35 blocos sem hipótese nova derivada de hint externo real.**

## Sessão 2026-08-31 (c) — arqueologia web exaustiva: a teoria do "desbloqueio externo" REFUTADA

Workflow de 6 agentes de recuperação + síntese (Wayback CDX + `id_`, decompile do
`app.js`, cross-check no `result.json` e Reddit). Motivação: o solver sênior da
comunidade (Vasilis Dragon) diagnosticou que faltariam duas peças EXTERNAS — a
página SalPhaseIon/Cosmic *live* com "instruction text ao redor dos blobs", e o
primeiro hint de 2019 *verbatim*. **Ambas foram investigadas até o fim; nenhuma
existe. A teoria do desbloqueio externo está refutada.**

### (a) Página live tem instrução oculta? — NÃO (refutado)
Os 6 snapshots / 5 digests distintos de `gsmg.io/89727c…` (2023-06-01 → 2026-04-05)
foram baixados e diffados byte-a-byte. Em TODOS, o único texto fora das duas
`<textarea>` é: `<title>GSMG Puzzle</title>`, meta description, `meta robots
noindex`, os dois `<h1> SalPhaseIon </h1>` / `<h1> Cosmic Duality </h1>`, e
`body{font-family:'arial'}`. **Zero comentários, zero `<p>/<div>/<a>`, zero
payload.** Mudanças na linha do tempo são só cosméticas (caixa da tag, reindentação)
e, a partir de out/2025, um `<script>` que é apenas o beacon do Cloudflare (não lê as
textareas, não decodifica, não redireciona). A rota `/salphaseion` da SPA só tem
captura de 2026 = shell Vue vazio. **VERIFICAÇÃO PRÓPRIA ADICIONAL:** a transcrição
do repo (README) das duas textareas bate **byte-a-byte** com a página live 2023-06-01
(SalPhaseIon 1075 chars, Cosmic 1792 chars base64, whitespace-normalizado) — não há
erro de transcrição na base do endgame.

### (b) Primeiro hint de 2019 verbatim — RECUPERADO
Em 2019 o `gsmg.io` era a plataforma de trading (SPA Vue); o puzzle vivia na rota
`/puzzle`, com markup embutido no bundle `app.js`. O componente tem `script: null`
(markup 100% estático). O primeiro hint verbatim é **apenas**:
```
<h1 class="headline">GSMG MEGANIGMA || 5 BTC</h1>
<img src="/img/follow_the_white_rabbit.png" alt="Follow the white rabbit">
```
- Fonte: `app.js` de 2019-04-28; a função `render` da rota `/puzzle` é byte-idêntica
  em 2019 e 2020 (md5 `a7dda948140b3619ef2e9336edd0b282`).
- `follow_the_white_rabbit.png` (350×350) = a própria matriz 14×14 da Fase 1; sem
  chunks tEXt/iTXt/zTXt; digest imutável 2019→2026.
- Corroboração verbatim: o solver `silver_anth` (1º a resolver a Fase 1, 2019-04-20)
  postou a foto do anúncio: *"originally was just this image"*; Reddit
  `r/bitcoinpuzzles/comments/dfwcqk` (OP `Sandalphon69`, 2019-10-10) descreve a Fase
  1 igual ao README.
- **O primeiro hint NÃO tem prosa/instrução ao redor** — é só a imagem-matriz sob o
  heading. Nada oculto faltante.

### Inéditos (menores, sem payload de puzzle)
1. **Título original "GSMG MEGANIGMA || 5 BTC"** (o README anotava "GSMG.IO 5 BTC
   PUZZLE CHALLENGE"; note que `GSMGIO5BTCPUZZLECHALLENGE` continua sendo a string
   HASHTHETEXT que gera a URL do endgame — fato separado e intacto).
2. **Comentário `<!-- Nice to see you around! Good luck little bunny hunter ;) -->`**
   em `theseedisplanted`, presente só nos snapshots de 2026 (ausente em 2020/2022) —
   era de domínio morto, sabor Matrix, sem carga.
3. Todos os hash-paths e quote-paths Matrix (`merovingian`, `whiterose`,
   `hopeisthequintessential…`, e o `4f7a1e4e…` = sha256 do plaintext Cosmic) só têm
   captura 2025-2026 = shell Vue vazio / erro 530 / página "for sale". **Nenhum stage
   pós-Cosmic genuíno existe no arquivo.** O `app.js` de 2025 tem zero ocorrências de
   `salphaseion/cosmic/89727c/choiceisanillusion`.

### Teste das strings novas (ultracode, bounded, inédito)
`GSMG MEGANIGMA` (todas as formas), `MEGANIGMA`, e o comentário "bunny hunter"
(15 strings × {raw, upper, sem-espaço}) como: sha256→chave AES dos 35 blocos
(oráculo forte alvo+espelho, 6 IVs CBC+ECB, scan byte-a-byte) e raw→passphrase EVP
em SMALL/COSMIC. **0 hits, 0 soft.** As strings novas não são chave/senha.

### Veredito
A arqueologia web **não produziu alavanca externa nova**. As duas peças supostamente
faltantes não existem: a página live sempre foi só as duas textareas (byte-correta no
repo), e o primeiro hint sempre foi só a imagem-matriz. A web está morta e à venda;
não há página, stage, prosa de instrução ou artefato externo não capturado.
**Implicação (mudança de mapa):** a peça que falta — se existe — é **INTERNA à
decifração dos próprios 35 blocos** (ou uma releitura da cadeia Chain4→35-blocos
que #104 marcou como "construção reproduzível, não validada"), **não** um hint/página
perdido na web. Isso refuta a hipótese dominante de "desbloqueio externo" e reorienta
todo trabalho futuro para dentro do payload já em mãos.

## Síntese multi-agente A1–A4 (2026-08-31) — veredito e critério de parada

Campanha de 4 agentes (auditor-cadeia, mask-hunter, releituras H1–H3, cético)
consolidada e **reverificada byte-a-byte** nesta sessão. Scripts runnable:
`solver/a1_integrity_checks.py`, `solver/mask_provenance.py`,
`solver/a3_rereads_attack.py`, `solver/a4_controls.py`.

### 1. Oráculo duro — NADA abriu
Nenhum candidato produziu a pubkey-alvo `04f4d1bb…f33559`, seu espelho EC, nem o
endereço-prêmio `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` (h160 `a955…bae4`).
`_work/a3_rereads_attack.jsonl` = **0 bytes** (0 hits em 87 chaves). **Não há SOLVE.**

### 2. Cadeia — os 35 blocos (`43d3fe43…`) são **SUSPEITOS**, não bytes-certos
Reprodutibilidade (`final_chain.py`) prova só que o pipeline é **determinístico**, não
correto. As **duas únicas âncoras fortes** — (a) senha COSMIC `a795de11…` = XOR de
sha256 de 5 frases; (b) `half`/`better_half` → `1JG648…`/`145ZQ9…` (match externo,
CHECK 5) — vivem no ramo **COSMIC→matriz**, que é **TERMINAL** (não alimenta os 35
blocos e não dá o prêmio). O ramo que PRODUZ os 35 blocos (Chain1→Chain2→Chain4) tem
seu nó decisivo, o **Chain4**, classificado como **só-padding com âncora circular**.

**Chain4 mask = CONSTRUÍDO (não derivado), byte-exato:**
`CHAIN4_MASK = b657264f2f6e6921 == cosmic[158:166] XOR "Salted__"` (`equals_mask=True`,
A1-CHECK1 e A2-TESTE1). Os 8 bytes do mask são **integralmente consumidos** ao forçar o
header de 8B `Salted__`; salt (`5bbd88ac…`) e corpo ficam determinísticos. O header,
portanto, é **tautológico — imposto, não âncora independente**. A busca por derivação do
mask (A2 D1–D8: sha256/md5 slice, XOR de subsets, fatias de artefatos, salts; + A4:
concat→sha256/md5, reverso, auto-XOR) veio **toda vazia**. Único sinal residual não
tautológico: PKCS7 pad = `0x01` (1/256, fraquíssimo). **A crítica #104 PROCEDE.**
Amarras não-triviais do ramo dos 35 blocos são fracas: WIF-não-comprimido único (CHECK3,
~2%), offset-64 único no Chain4 (CHECK4, mas ~25% de acerto por acaso), e só 2 bytes
ancorados (`cosmic[64:66]`). **Confiança nos 35 blocos com base no header = ZERO.**

### 3. Releituras H1–H3 — FECHADAS sob oráculo forte
87 chaves (H1 header28-como-privkey = 20; H2 sha256 dos plaintexts = 41; H3 XOR-sha256
dos plaintexts = 26), **0 hits duros, 0 soft**. O controle **POSITIVO** que faltava foi
escrito e roda (`a4_controls.py`, `ALL_PATHS_FIRE=true`): o detector recupera uma needle
plantada nos 6 caminhos (offset não-alinhado, pipeline AES-CBC, keyself, WIF, hex-ASCII,
BIP39-derivado). **Os negativos têm peso — não são incapacidade do motor.**

### 4. CRITÉRIO DE PARADA → **(c)** um elo provado só-padding/suspeito
Não é (b): (b) exige "todos os elos ANCORADOS", e o **Chain4 é comprovadamente
só-padding/circular** (A1+A2, confirmado A4). O passo construtivo nomeado é
**re-ancorar o Chain4 com âncora dura** — porém isto **NÃO autoriza sweep cego**; a
circularidade só quebra com fonte independente para `b657264f…`/offset-64/fatia
`[158:-1]`, e essa fonte hoje **não existe no repo** (todas as derivações plausíveis já
deram vazio). Ações concretas, falsificáveis, sem sweep:
- **(c1) — a mais decisiva, arqueologia externa:** verificar se `CHAIN4_SHA256`
  (`e4269ed5…`) e `BLOCKS_SHA256` (`43d3fe43…`) foram **publicados pelo criador/Vasilis
  ANTES** deste pipeline. Se sim, o Chain4 é genuíno; se nasceram do próprio pipeline,
  são auto-referenciais e o Chain4 fica **não-falsificado** (fora do alcance byte-exato
  do repo). Único item capaz de mudar a classificação do Chain4.
- **(c2) — sonda interna bounded (única não coberta por H1–H3):** header28 `ca9e…e705`
  sob **endianness/byte-invertido** como privkey crua de 32B — defensável pelo hint do
  criador 2024-01-26 ("Regular Bitcoin Private key" = 32B crua, não seed). A3 só testou
  ordem direta. É hipótese nova (não repete família H1), testável contra o oráculo forte.

**Fora disso: PARAR.** Espaço computacional interno esgotado; sem hipótese concreta
derivada de hint/insight real, nenhum sweep novo se justifica.

### 5. Itens em aberto registrados (não verificáveis do repo / blind spots reais)
- Atestação externa de `CHAIN4_SHA256`/`BLOCKS_SHA256` (item c1).
- Blind spot BIP39: `oracles.check_mnemonic` exige ≥60% palavras distintas → um mnemonic
  degenerado/baixa-diversidade seria **silenciosamente perdido** (ortogonal a H1–H3, que
  são saídas de alta entropia).
- Variante endianness do header28 em H1 (item c2).

## Sessão 2026-08-31 (d) — REDIREÇÃO: os "35 blocos" são fabricação comunitária; a fronteira real é o plaintext Cosmic `cc`

Fecho do plano `.claude/plans/endgame-internal-frontier.plan.md` (Fase 0→2, time A1–A4
+ arqueologia de proveniência + verificações próprias). **Conclusão estratégica que muda
o mapa:** o alvo "35 blocos" que a comunidade (e sessões anteriores deste repo) vinha
atacando **não é o caminho do criador** — é uma construção auto-referencial. A fronteira
VERIFICADA recua para o plaintext Cosmic `cc`.

### Evidência (3 ângulos independentes, todos verificados byte-a-byte)
1. **Chain4 mask CONSTRUÍDO:** `b657264f2f6e6921 == cosmic[158:166] XOR "Salted__"` — os 8
   bytes do mask são engenharia-reversa exata para impor o header `Salted__`. O header é
   tautológico, **não** âncora independente → a crítica da issue #104 **procede**. Toda
   busca por derivação dura do mask (A2 D1–D8 + A4) deu vazio; ele nunca apareceu no
   Telegram (`b657264f` = 0 ocorrências no `result.json`).
2. **Proveniência auto-referencial:** os hashes `e4269ed5` (chain4) e `43d3fe43` (35 blocos)
   aparecem **uma única vez** no export inteiro (Vasilis, 2026-06-21), rotulados pelo próprio
   autor como vindos "dos issue dumps" — sem precedente, sem atestação independente, ~10 meses
   DEPOIS do `4f7a1e4e`. O criador **nunca** mencionou "35 blocos"/"Chain4"/matriz-103²/
   `Salted__` intermediário. (A frase "half and better half" é genuína do texto do puzzle; a
   *mecânica* da matriz é derivação de solver.)
3. **Ramo terminal → endereços de golpe:** a matriz 103² → `half`/`better_half` deriva (pubkey
   comprimida, verificado nesta sessão) `1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu` e
   `145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ` — exatamente os endereços das issues #80/#99, que
   **não são o prêmio** e não têm derivação legítima até ele. Esse ramo é TERMINAL.

### O endpoint genuíno: `cc` (plaintext Cosmic)
- **Duplamente ancorado:** a passphrase `a795de11…` (derivação XOR-de-sha256 dos 5 tokens,
  provada) decifra o blob Cosmic em **1327 bytes com `sha256 = 4f7a1e4e…`** — a âncora
  independente e multiplamente atestada (Cuevabit 2025-08-09, antes de tudo). Verificado agora.
- **Caracterização:** 1327 bytes e **1327 é PRIMO** (criador: "a prime number is very
  important"); entropia 7,87 bits/byte (alta, cifrado/denso); 0,48 imprimível; 255/256 bytes
  distintos; `1327×8 = 10616 ≈ 103² = 10609` (sobra 7). É bit-material de alta entropia.

### Testes bounded desta sessão (todos negativos, control-validados)
- **(c2) header28 em endianness invertida** como privkey crua (11 formas): 0 hits.
- **cc varrido por privkey/WIF do prêmio:** 1296 offsets + WIF embutido + sha de fatias
  naturais + row/col-sums do 103² → **0 hits**. A privkey NÃO está embutida crua em `cc`.
- **half/better_half** e combinações diretas como privkey: 0 (sessão b).
- **H1–H3 releituras internas** (87 chaves) + strong_oracle_35: 0 (com controle positivo
  `a4_controls.py ALL_PATHS_FIRE=true`).

### Veredito e próxima fronteira (honesto)
Nada abriu; **não está resolvido**; o prêmio segue on-chain intacto. Mas o mapa mudou: parar
de atacar os "35 blocos" (alvo fabricado). **A fronteira real é a interpretação correta de
`cc` (1327 B, primo, alta entropia) que produza a "Regular Bitcoin Private key" do prêmio** —
uma leitura DIFERENTE da matriz-103²-comunitária (que é terminal). Isso exige uma hipótese
nova, concreta e falsificável sobre `cc` (2ª camada de cifra? outra geometria do 1327/103²?
o papel do primo 1327?) — **não** outro sweep. O gargalo permanece interpretativo/externo
(novo hint do criador ou insight humano), agora com o alvo re-centrado no artefato certo.

## Sessão 2026-08-31 (e) — time em `cc` (0 solve) + BTCSEED CONFIRMADO real → o prêmio vem do ramo faed, não do Cosmic

Rodada INV1/INV2/INV3 + cético (workflow `gsmg-cc-frontier`) sobre o plaintext Cosmic `cc`,
mais resolução própria de H-NEXT-1. **0 SOLVE**, negativos control-validados. Mas o mapa
do endgame ficou coerente pela primeira vez.

### Frentes fechadas nesta rodada
- **half/better_half = os endereços DONOS, não a chave (on-chain, ao vivo):** `1JG648…`
  recebeu 1.756.275 sats em 101 txs, **saldo 0**; `145ZQ9…` idem — pó de ~90 depósitos, chaves
  **queimadas** (privkeys vazaram no golpe #80/#99, "Donate to my btc"). São a dualidade
  "half and better half … also need funds to live" tornada pó por terceiros, NÃO o prêmio.
- **half/bh ≠ chave da 2ª camada do faed** (INV1): como keystream sobre o BIF_REST (563 chars),
  12 saídas, todas piores que o cru; null-model de 500 keystreams aleatórios → half/bh caem
  DENTRO do ruído (média −7,86). Refutado, não-apofenia.
- **Geometria do primo 1327 (INV2): 37 leituras, 0 hits** (bits 8·1327, bytes 2·3·13·17,
  7 bits sobrando, cc mod N, base-38). Transpor alta-entropia continua alta-entropia.
- **2ª camada em cc por gramática derivada (INV3): 284 chaves únicas, 1420 decifrações, 0 hits**
  (SMALL=concat→sha256, COSMIC=XOR(sha256), sha/sha² da resposta, half/bh). cc não abre.

### H-NEXT-1 RESOLVIDO — BTCSEED é sinal REAL, não circular
Dúvida do cético: o alfabeto CANON do Bifid faed foi ajustado à palavra "BTCSEED" (circular)?
**Não.** Verificado byte-a-byte:
- A ordem de 1ª ocorrência dos 9 símbolos no `dbbi` é **`dbifhcega`** = exatamente o keyword do
  `CANON_ALPHA` (`DBIFHCEGAKLMNOPQRSTUVWXYZ`). O alfabeto é **forçado deterministicamente** pelo
  artefato dbbi — zero liberdade para encaixar a palavra.
- `solver/skeptic_btcseed_null.py`: só **8 de 362880** permutações A–I dão prefixo "BTCSEED"
  (2,2e-5); 200k permutações aleatórias → 7 hits (3,5e-5). BTCSEED é genuinamente raro, e o
  alfabeto CANON (não-ajustado) acerta esse evento. **Sinal real, foothold legítimo.**

### MAPA FINAL COERENTE do endgame (síntese de todas as sessões)
- **Página SalPhaseIon/Cosmic** (byte-verificada, sem instrução oculta) tem DOIS ramos:
  1. **Ramo faed/BTCSEED (SalPhaseIon)** = o caminho PRETENDIDO do prêmio `1GSMG`. BTCSEED é
     header real; a **2ª camada sobre o BIF_REST (563 chars pós-BTCSEED) → a "Regular Bitcoin
     Private key"** é a FRONTEIRA. Travada por um parâmetro externo (alfabeto/cifra da 2ª camada)
     que a busca cega não fixa — exaustivamente atacada, espaço computacional fechado.
  2. **Ramo Cosmic/cc/matriz-103² (Cosmic Duality)** = BECO. Produz half/better_half (os "donos",
     agora pó queimado); o "Chain4/35-blocos" a jusante é FABRICAÇÃO comunitária (mask construído,
     hashes auto-referenciais, criador nunca atestou). NÃO é o caminho do prêmio.
- **Conclusão:** anos de esforço da comunidade e de sessões anteriores foram gastos no ramo
  ERRADO (Cosmic/35-blocos). O prêmio depende de decifrar a 2ª camada do **BIF_REST**, e o
  desbloqueio real = o hint externo do criador que fixa o parâmetro dessa camada (ou insight
  humano). Confirmado o padrão: gargalo interpretativo/externo, agora com o ramo certo isolado.

### Threads concretos ainda não esgotados (para a próxima, sem sweep)
- **H-NEXT-2:** o blob SMALL (`U2FsdGVk…QvX0…`) da textarea SalPhaseIon é `Salted__` GENUÍNO;
  atacá-lo com material derivado do pipeline **faed** (não a passphrase XOR do Cosmic) é finito.
- **2ª camada do BIF_REST:** o alvo real, mas precisa do parâmetro externo (alfabeto/keystream)
  — nomear a fonte do parâmetro (hint) antes de qualquer novo código.

**Veredito:** não resolvido; prêmio intacto. Ganho desta sessão: o ramo do prêmio foi
ISOLADO (faed/BTCSEED), o beco (Cosmic/35-blocos) foi provado fabricado, e o único sinal
positivo (BTCSEED) foi confirmado real. O que falta é externo.

## Sessão 2026-09-01 — 3 tries diretos na 2ª camada (todos negativos, control-validados)

Ataque direto aos dois threads nomeados na sessão (e), + 1 cruzamento inédito. Tudo com
oráculo duro (privkey alvo/espelho, AES SMALL/COSMIC ≥85% ASCII) e Scorer de inglês.

1. **Blob SMALL genuíno (H-NEXT-2):** 216 senhas principiadas — concat→sha256 e
   XOR-de-sha256 (gramáticas provadas) sobre os tokens da página + frases decodificadas do
   faed + "our first hint is your last command" + BTCSEED — via EVP. **0 plaintext legível,
   0 link SMALL→COSMIC (sha256(pt) não abre COSMIC), 0 privkey.** O SMALL não abre para
   instrução/resposta sob nenhuma gramática de senha derivada.
2. **dbbi decodificado como keystream da 2ª camada (BIF_REST):** dbbi (a-i→1-9), cumsum,
   matrixsumlist e dbbi+matrixsum como keystream mod-25 (vig_dec/enc/beaufort) sobre os 563
   chars. **Todas as saídas PIORAM** (melhor −7,56 vs REST cru −5,59); 0 oráculo duro. O 2º
   parâmetro NÃO é o dbbi decodificado.
3. **`cc` RAW cruzando o ramo faed (Cosmic Duality = combinar, INÉDITO):** o plaintext Cosmic
   `cc` (1327B) como keystream mod-9 sobre o faed PRÉ-Bifid (então Bifid canônico) e mod-25
   sobre o BIF_REST (offsets 0/7/158/163/833), + fatias de cc como chave AES. **0 hits duros,
   todas as saídas piores que o cru.** As duas metades da "dualidade" não se combinam no nível
   bruto para revelar o payload.

**Saldo:** os threads concretos que restavam estão fechados. Confirmado de forma decisiva e
multiplamente que **o parâmetro da 2ª camada do BIF_REST NÃO é derivável de nenhum artefato em
mãos** (dbbi, faed, cc, half/bh, matrixsumlist, tokens da página) por nenhuma operação de
combinação testada. O prêmio vem do ramo faed/BTCSEED (identificado), mas o passo final exige
**informação externa** (o hint do criador que fixa alfabeto/keystream da 2ª camada) — nem a
comunidade em ~6 anos, nem as campanhas multi-agente desta sessão, a encontraram. Parar de
varrer; o desbloqueio é externo.

## Sessão 2026-09-01 (continuação) — auditoria externa pós-commit e critério de retomada

O termo **“desbloqueio externo”** acima precisava ser desambiguado, pois a sessão (c) já
refutara duas versões fortes da hipótese: não existe texto de instrução perdido na página
live/Wayback e não existe um “primeiro hint de 2019” diferente do material preservado. A
conclusão correta é mais estreita: **todo o corpus histórico público conhecido foi esgotado**;
somente um hint primário realmente novo do criador (ou um artefato primário novo e
proveniente) pode fixar o parâmetro que falta.

### Fontes verificadas nesta continuação

- O export local `result.json` termina em **2026-07-08**. A mineração anterior já cobre as
  427 mensagens atribuídas ao criador até esse corte; as últimas mensagens do grupo não
  contêm novo post de Jrk/@SoWut. Logo, o único blind spot temporal concreto é conteúdo
  publicado **depois de 2026-07-08**.
- Busca pública atual por GSMG/SalPhaseIon/BTCSEED/“Regular Bitcoin Private key” não revelou
  hint primário posterior ao export. Reddit, Bitcointalk e o repositório público principal
  repetem material já arquivado ou alegações sem proveniência.
- O repositório recente `jackdevs66/GSMG5_CDuality`, apresentado como “reproducible
  solution”, **não é solução do prêmio nem traz a 2ª camada do FAED**. Ele somente reproduz
  o ramo Cosmic já conhecido: as sete palavras, a passphrase `a795de11…` e o plaintext de
  `sha256=4f7a1e4e…`. Não publica privkey do endereço `1GSMG`, não fecha o oráculo on-chain e
  não acrescenta material primário. É confirmação independente do endpoint `cc`, nada além.

### Regra operacional (evita reabrir sweeps mortos)

**RETOMAR somente se** aparecer ao menos um destes sinais falsificáveis:

1. mensagem primária de Jrk/@SoWut posterior a 2026-07-08;
2. artefato original com proveniência verificável que altere `dbbi`, `faed` ou a instrução
   ao redor deles;
3. hipótese humana que nomeie explicitamente a cifra da 2ª camada **e** derive seu parâmetro
   de uma pista ainda não testada.

Repos, posts ou scripts que apenas reproduzam `a795de11…`, `4f7a1e4e…`, half/better_half,
Chain4 ou os 35 blocos devem ser classificados como **duplicação do ramo Cosmic/beco**, não
como progresso. Até um dos três sinais acima existir: **STOP — monitorar fonte primária, não
varrer.**

## Sessão 2026-09-01 (h) — `BTCSEED` tomado literalmente (5 hipóteses novas, 0 solve)

Esta retomada satisfaz excepcionalmente o item 3 acima: em vez de variar novamente o Bifid,
foram escritos antes do teste cinco significados concretos para o header `BTCSEED`, cada um
com espaço finito e oráculo duro. Os controles positivos verificam as implementações; nenhum
score de idioma foi aceito como solução.

1. **Padrões Bitcoin (`solver/btcseed_standard_attack.py`).** `BTCSEED` foi interpretado como
   a operação normativa BIP32 `HMAC-SHA512(key="Bitcoin seed", data=seed)`. O vetor BIP32 #1
   bate byte a byte. Foram testados **109 materiais** naturais (FAED/BIF/REST, base-9/hex,
   metades 285 intercaladas, subsequências primas e o canal B/C/D/E), **21.578** consultas de
   privkey direta e **82.790** filhos em 85 caminhos comuns. As 104 posições primas zero-based
   do BIF completo também foram preservadas cruas: `104=2×52`, portanto suas metades e canais
   alternados entram como WIF/seed sem remapeamento. Dos **28** materiais com 51/52 caracteres,
   **0 são WIF Base58Check válidos**. Resultado global: **0 hits**.
2. **Dualidade de primo seguro (`solver/btcseed_duality_attack.py`).** A observação do Telegram
   id 43442 foi confirmada: `len(BIF_REST)=563`, 563 é o 103º primo e, mais especificamente,
   **`563=2×281+1`**, com 281 também primo. Remover o header separa deterministicamente
   `rest[0::2]` em 282 símbolos base-25 e `rest[1::2]` em 281 símbolos `{B,C,D,E}`. Estes quatro
   são exatamente o canto 2×2 do quadrado CANON, isto é, um dígito base-4; emparelhar os canais
   dá base-100 sem chave livre. As duas ordens de coordenadas, duas posições do símbolo excedente,
   base-100 direta/inteira e as operações geométricas `+/-/reflexão` produziram **52 textos** e
   **70 streams binários únicos**, com **29.976** janelas de privkey: **0 AES/privkey hits** e
   todos os scores textuais piores que o baseline.
3. **Sete letras entrelaçadas (`solver/btcseed_intertwine_attack.py`).** A gramática autêntica
   `XOR(SHA256(parte_i))` reproduz primeiro o controle Cosmic exato
   `a795de117e472590…52e50735`. Aplicada às sete letras de `BTCSEED`, gera
   `e0b6613e9db7370d2e45aa68b55e23b67fbbc6aa10d689804bf44f1e635b7c82`; não é a privkey do
   prêmio e não abre SMALL/COSMIC em raw/hex. A forma minúscula diagnóstica também falha.
4. **Bazeries (`solver/btcseed_bazeries_attack.py`).** O relato imediatamente posterior ao
   achado (Telegram id 43274) dizia que o REST tinha “full match” com Bazeries no dCode; esta
   era uma cifra nomeada e ainda não implementada no repo. O vetor público
   `UNIVERSITY --900004--> QMHATRMGXS` valida a implementação. Chaves numéricas estritamente
   ancoradas em `563`, `103`, `570` e `matrixsumlist=101`, com keyword tradicional,
   `BTCSEED` ou `DBIFHCEG`, deram **16 candidatos**, **0 hits**; o melhor score foi −7,35,
   muito pior que REST cru −5,59. O classificador comunitário era falso positivo.
5. **Canal útil e título (`solver/btcseed_payload_attack.py`).** O canal base-25 de 282 símbolos
   foi atacado por recuperação estatística Vigenère/Beaufort nos períodos 1–50,57,91,94,141:
   **216 candidatos**, 0 oráculos. O score artificial −4,22 em período 141 usa só duas
   observações por símbolo da chave e é sobreajuste; períodos sustentáveis não mostram inglês.
   Como `SALPHASEION` é anagrama exato de `ALPHA NOESIS`, a lacuna “título como parâmetro da
   2ª camada” também recebeu **72** testes diretos (`SALPHASEION`, `ALPHANOESIS`, `NOESIS` e
   `SAL/PHASE/ION`, três direções, dois alfabetos, REST/canal). **0 hits**; melhor −7,38.

Relatórios completos: `_work/btcseed_standard_attack.json`,
`_work/btcseed_duality_attack.json`, `_work/btcseed_intertwine_attack.json`,
`_work/btcseed_bazeries_attack.json` e `_work/btcseed_payload_attack.json`.

**Veredito:** `BTCSEED` continua sendo sinal autêntico e o ramo do prêmio, mas não significa
BIP32/WIF direto, as sete letras na gramática XOR, Bazeries, a fusão base-100 dos canais, nem
Vigenère/Beaufort com o título. **0 solve.** O parâmetro inequívoco da segunda camada continua
ausente do corpus público. STOP desta receita: não ampliar a enumeração sem novo hint primário
ou uma cifra+parâmetro derivados antes do teste.

---

## Auditoria 2026-09-02 — a cadeia comunitária é MIRAGEM; o KDF real é EVP-SHA256; nenhum blob foi aberto

Duas rodadas multi-agente (18 + 8 famílias concluídas, ~14 milhões de testes de oráculo duro,
**0 hits**) reviraram as premissas deste arquivo. Três resultados invalidam trechos anteriores e
devem ser lidos antes de qualquer trabalho novo.

### 1. Chains 1→4 / `cc` / half / better_half / "35 blocos" são falsos positivos de padding

Todos os quatro "decrypts" da cadeia (Chain1 79 B, Chain2 79 B, Cosmic `cc` 1327 B, Chain4 1151 B)
terminam com padding `0x01`. Uma mensagem real teria pad = 1 em apenas 1 de 16 casos; quatro
seguidas dão 1 em 65.536. Os plaintexts são de alta entropia, sem estrutura. A passphrase
`a795de11…` que abre o Cosmic foi **construída** por XOR de SHA-256 de tokens, e com uma senha
construída a chance de cair um padding válido é 1/256 por tentativa entre milhares. A seção
"Cadeia GalloClaudio64 (Chains 1→4) — VERIFICADA até o payload final" descreve, portanto, ruído.

### 2. O criador usa EVP_BytesToKey com SHA-256, não MD5

Os blobs autênticos das fases 2, 3 e 3.2 foram reabertos localmente: cada um decifra **somente**
com `EVP_BytesToKey`-SHA256 (openssl ≥ 1.1.0) e nunca com MD5. A cadeia comunitária usava MD5 —
segunda evidência independente de que ela é miragem. Toda varredura futura deve usar SHA-256 como
padrão.

A família `kdf_variants` fechou o KDF em definitivo com 1,21 milhão de testes: PBKDF2-HMAC-SHA256
(1.000 / 2.048 / 10.000 / 100.000 iterações), PBKDF2 com SHA-1 e SHA-512, `EVP_BytesToKey` com
md5/sha1/sha224/sha384/sha512/ripemd160, chave crua `-K` em nove variantes de IV, e AES-128/192,
todos negativos, com nove controles positivos gerados pelo openssl real reabrindo exatamente na
derivação esperada. O argumento decisivo é estrutural: os três blobs carregam o cabeçalho
`Salted__` seguido de 8 bytes de salt, e `openssl enc -K` **não escreve esse cabeçalho**. Logo o
criador usou `-pass`/`-k` com EVP-SHA256. **O desconhecido é a senha, não o KDF.**

### 3. A "matriz de 102 uns" é artefato de amostragem

A leitura de que a imagem original teria 102 células pretas, com a célula (7,6) no índice espiral
193 (primo), está errada. Medindo a fração de pixels escuros por célula na imagem
`_work/archive/follow_the_white_rabbit.png` (350×350, célula de 25 px), 189 das 196 células dão
exatamente 0,00 ou 1,00; as sete restantes, todas no centro, dão valores intermediários:

| célula | (6,6) | (6,7) | (7,6) | (7,7) | (7,8) | (7,9) | (8,6) |
|---|---|---|---|---|---|---|---|
| fração preta | 0,16 | 0,36 | 0,24 | 0,12 | 0,36 | 0,16 | 0,08 |

O centro contém o **desenho de um coelho branco em resolução de 5 px** (orelhas, olho, corpo, cauda)
que atravessa a grade de 25 px — o "white rabbit" do título da imagem. Não é dado binário de célula. A matriz de bits real é a do README, com
**101 uns**. Descarte todo raciocínio construído sobre "102 uns", "espiral 193 é primo", "cauda
central 0100" e "91 zeros nos índices 0..191". O bitmap do pictograma (270 bits) foi testado como
bits, bytes, decimal, SHA-256 e chave privada: negativo.

### 4. O TAIL32 é real, nunca foi aberto, e agora está esgotado no vocabulário conhecido

O bloco AES no fim da fase 3.2 (80 B de ciphertext) nunca entrou no `oracles.aes_open`, que só
tinha SMALL e COSMIC. O criador confirmou em 2023-06-10 que ele é real e que não é o hint da
SalPhaseIon. A família `tail32_history` regerou 466.310 senhas-base — 308.031 de todos os scripts
históricos em `solver/` mais 158.279 da gramática da fase 3.2 — em três formas cada, contra o
TAIL32 com SHA-256 e MD5, mais 933 mil verificações de chave privada. Os paddings válidos ficaram
exatamente na taxa de ruído de 1/256, sem nenhum plaintext com 60% de bytes imprimíveis. Se o
TAIL32 usa a gramática `sha256(concatenação)`, suas palavras não estão no vocabulário da
comunidade nem nos tokens da fase 3.2.

### 5. O que a estatística de `faed` já exclui

`faed` (570 símbolos a–i) comporta-se como fonte independente e identicamente distribuída, com
unigrama enviesado (g e i somam 32%, a forma típica de escapes de checkerboard) mas **sem memória
serial**. Duas famílias independentes confirmaram, cada uma com controle positivo que recupera o
sinal plantado:

- `checkerboard_keystream` construiu 18.426 streams re-chaveados (41 keystreams × rotações ×
  soma/subtração/Beaufort/autokey) e filtrou por entropia condicional e índice de coincidência
  contra embaralhados. O maior desvio real foi 5,57 sigmas, dentro da cauda do modelo nulo; a chave
  correta no controle produz −31, e mesmo uma rotação errada da chave certa deixa −5,5. Camada
  aditiva com chave de três ou mais resíduos está refutada.
- `permutation_search` testou 3.381 permutações estruturadas de `faed` e 2.900 de `dbbi` (primos,
  índices coloridos, resíduos módulo k, 16 grades com 24 leituras cada, metades, transposição
  colunar com 50 chaves × larguras 5 a 40, todas com inversas). O maior desvio foi 3,67 sigmas,
  igual ao máximo esperado de 3.381 amostras normais. O controle recupera a permutação inversa
  exata do checkerboard da fase 3.2.2. O hill-climb não tem poder discriminativo: dá 76,8 em `faed`
  e 75,3 em `faed` embaralhado.

Corolário: checkerboard e VIC diretos **e permutados** sobre `faed` estão excluídos, com poder
estatístico quatro vezes maior que o do controle da fase 3.2.2. O `BTCSEED` do Bifid-570 depende
apenas de `faed[0:4]` e `faed[285:289]` e deve ser tratado como coincidência provável, não como
ramo do prêmio.

### 6. Outras famílias fechadas nestas duas rodadas

`hashthetext`; `brainwallet` (3.246 frases × 10 formas); aritmética das metades; checkerboard com
60 alfabetos de frase × 72 escapes; Bifid 5×5 com 120 alfabetos e todos os períodos; Bifid 3×3 com
6 quadrados; Polybius 9×9/27/T9; a matriz como keystream, transposição e senha; 27 listas de somas
geométricas do `dbbi`; z-method com primos zerados; estrutura dos blobs; 99 keystreams × 7 modos;
765 leituras geométricas do `faed` e 136 do `dbbi`; extração de seed do Bifid; mineração do
Telegram; `dbbi` preenchendo as células-zero da espiral; bits em posições primas e canais
R/G/B/infravermelho/XOR da imagem; hash do próprio texto base64 dos blobs e formas de entrada de
shell (incluindo `sha256hex` + newline e UTF-16-LE); e a tabela da fase 2 na gramática da fase 3
(2.304 sequências × 5 formas, 80 alfabetos keyed, 1.920 keystreams).

Sobre a tabela `# X 2 S H 4 Y 0 Q B 15 #`: S = 32 (klingon `cha' + vagh × jav`), B = −16, H = −42
(o criador respondeu "42" em 2023-01-25). Para Q as leituras mais defensáveis são *phishing/phish*
(swordfish sem *sword*, grafia hacker `ph`, "extend" = `+ing`) e *Twofish* → 2 (extensão do
Blowfish); 82 seria o ASCII de `R`, casando com "worst gear" = ré. "The I and W are below" segue
sem leitura firme.

### 7. Onde a fronteira está agora

Decodificar `dbbi` (91 símbolos) ou `faed` (570) até uma senha, e abrir SMALL (80 B), COSMIC
(1328 B) ou TAIL32 (80 B) com EVP-SHA256. Nenhum blob do endgame jamais foi aberto. As leituras
principiadas que sobreviveram a tudo acima estão no briefing da campanha (`BRIEFING.md` no
scratchpad da sessão): seleção de bits por índice em vez de permutação, o resíduo fraco de índice
de coincidência de dígrafos, chaves aditivas de dois ou três resíduos, e a tabela da fase 2 lida
como bytes, teclado ou programa de transposição.

### 8. Segunda metade da rodada 2 (retomada após limite de sessão) — 0 hits em mais 30 M testes

| família | testes | o que fechou |
|---|---:|---|
| `select_bits` | 3.011.429 | 32 bytes / 256 bits **selecionados** de `faed`/`dbbi` por índices (primos base 0/1, coloridos, azuis/amarelas, células 0/1 da matriz README, i mod k para k=2..19, posições de g/i, 1ª/última ocorrência, saltos do `dbbi`, janelas de 32–256 em todo offset) em base 9/10, pares/trios decimais, nibbles, 1–4 bits por símbolo, reverso, sha256 — nenhuma é a chave nem abre blob. Não existe seleção "natural" de exatamente 256 bits. |
| `computed_lists` | 5.160.965 | `dbbi`/`faed` **não** são listas calculadas da matriz (pares de linhas/colunas em 5 ordens × 8 operações × 5 reduções), nem dígitos de constantes (π, e, √2, φ, ln2, γ, Champernowne, com/sem zeros), nem dígitos de hashes/pubkey/endereço, nem base58; como número, `faed` não tem estrutura (não é quadrado, potência de 2, nem tem cofator útil). |
| `residue_autocorr` | 1.095.534 | O resíduo de índice de coincidência de dígrafos é **deslocamento de baseline** do viés unigrama, não assinatura de chave (p family-wise 0,44–0,71). Camada aditiva de **poucos resíduos** (25 chaves nomeadas + 8.030 chaves binárias de período ≤ 12, ±k, 4 configurações) fica dentro do nulo de `faed` embaralhado. Controle: checkerboard + chave binária ainda dá H_cond z≈−6 com a chave errada; `faed` cru dá −0,45. |
| `phase2_table_bytes` | 798.572 | Tabela `# X 2 S H 4 Y 0 Q B 15 #` como bytes/nibbles/hex/decimal com X,Y varridos em 0..99 e temáticos, Q em 6 leituras, como senha/-K/IV/privkey; cifra de teclado em 3 layouts × 5 direções; 8ª parte nas 6 juntas internas da senha da fase 3 (27.648 senhas); alfabetos fill+kw e dot-style das 39 frases da fase 2; tabela como ordem das 7 partes (5.040 permutações). |
| `yinyang_interleave` | 99.008 | A distribuição conjunta 9×9 de (A[i], B[i]) e das outras 4 pareações é **independente** (z entre −0,75 e +0,66; um quadrado 9×9 keyed real dá z=+131). `faed` não é (linha, coluna) de um quadrado 9×9 nem código de 2 dígitos sobre 81 símbolos. |
| `pop_culture_exact` | 102.104 | "Últimas palavras antes da escolha" extraídas programaticamente do próprio puzzle (README, ENDGAME, mensagens do criador) e nomes/títulos curtos do universo Matrix/Alice/Mr. Robot, em 8 formas × 3 blobs + brainwallet. |
| `dutch_german_scorer` | 22.920 | Modelos de quadgramas nl/de calibrados: o scorer de **inglês** já dá −5,45 em holandês real contra −6,66 em texto embaralhado, logo as triagens das rodadas 1–2 **não eram cegas** a holandês/alemão; hill-climb de checkerboard e de substituição sobre `dbbi`, REST563 e canal ímpar com nulo casado por classe de paridade: ruído. |
| `bifid3x3_exhaustive` | 19.754.906 | **Todas** as 60.480 classes de quadrados 3×3 (= os 362.880 por conjugação linha/coluna, verificada) × todos os períodos × 2 modos, em `faed` e `dbbi` = 2,18 M saídas, cada uma como senha crua e sha256 nos 3 blobs, como privkey e via z-method; triagem invariante ao rótulo com nulo próprio (melhor z real −8,2 está dentro do nulo −6,3..−8,0); texto plantado recuperado em 1º entre 1,81 M. Ganho de ferramenta: teste de padding com um único AES-ECB no último bloco, 30× mais rápido. |
| `permutation_search` (2ª passada) | 469.073 | Rotas de dois lados, colunar dupla e metades com rotas diferentes; controle recupera a permutação verdadeira em 1º entre 26.680. |

Testes inline desta sessão, também negativos: inserção de zeros nas posições primas seguida do
z-method (1.836); `faed`/`dbbi` com coringa em cada letra dentro dos 100 mil primeiros dígitos de
13 constantes; cada símbolo como delimitador com comprimentos e campos octais pontuados contra
nulo (360 leituras); "follow the white rabbit" e 51 frases vizinhas como senha em 5 formas (896).

Dois fatos estatísticos novos para orientar o próximo passo:

- O unigrama de `faed` (a54 b49 c52 d49 e69 f57 **g107** h58 i75) é incompatível com base 9
  uniforme (χ²=43,7, df 8) e com um mapa hexadecimal 16→9 (χ²≈41), mas **compatível com dígitos
  decimais uniformes em que `g` representa dois dígitos** (χ²=11,5, p≈0,17). A contagem 107 de
  `g` é a única prima entre os nove símbolos e está 5,7 sigmas acima do esperado.
- As metades diferem em composição (χ²=17,4, p≈0,02 no corte a priori em 285), mas o melhor corte
  livre cai em 220 e não sobrevive à correção pela busca (p≈0,06). A não-estacionariedade é fraca.

O veredito operacional das duas rodadas: `faed` não é saída de nenhuma cifra clássica de texto
(fracionação, substituição chaveada, transposição, checkerboard, Bifid, aditiva de poucos ou muitos
resíduos), nem seleção ou leitura posicional de uma chave, nem lista calculada. O que sobrevive é
um objeto **serialmente i.i.d. com viés unigrama** cuja função no puzzle ainda não foi identificada.

### 9. Síntese do crítico da rodada 2 e leads da rodada 3

Balanço: 16 famílias, 36,1 M testes nesta rodada, ~50 M acumulados, **0 hits**. Piso de padding
válido medido de forma independente por três famílias grandes: 0,00387 a 0,00388 contra 1/256 =
0,00391. Nenhum plaintext AES passou de 53% de bytes imprimíveis; nenhum texto decodificado passou
de −5,2 em quadgramas (inglês real ≈ −3; o controle plantado marcou −3,9).

**Resultado documental positivo:** a tabela `# X 2 S H 4 Y 0 Q B 15 #` da fase 2 está resolvida
sem resíduo (Q=82 pelo peixe Qwerty de Mr. Robot, B=25 pelo i5, H=42, S=32, X=E, Y=N; a string
invertida dá 51°52'28.0"N 4°24'23.2"E, zona da SafeNet em Roterdã). O trabalho é do grupo do
Telegram (2020–2023) e nunca tinha entrado no README; agora está na seção da fase 2. Corolário:
**B=−16, usado em todo trabalho anterior, está errado.** A tabela existe para confirmar "Safenet"
na senha da fase 3 e não alimenta o endgame.

**Modelo que sobrevive a tudo:** `faed` é material de alta entropia, não mensagem. Assinatura:
MI no lag 285 ≈ 0, entropia condicional no nulo, nenhuma dependência conjunta em duas metades,
autocorrelação de n-gramas no nulo. Isso é (i) expansão de hash / material de chave, ou (ii)
ciphertext de cifra de fluxo com **running key aperiódica de alta entropia**, a única camada
aditiva que o diagnóstico de potência não exclui (chave binária: 0% das 685 amostras plantadas
ficam tão planas quanto `faed`; ternária: 2,9%). O único traço estrutural é o unigrama compatível
com dígitos decimais uniformes em que `g` vale 0 ou 7, e `faed` não tem `o` (o zero da página):
o único fio que liga a estatística ao hint "some characters need to be zeroed out".

**Segundo olhar humano recomendado pelo crítico:**

- `faed[438:446]` = `bbeibbei` e `faed[453:461]` = `ieeeieee`: dois repeats em tandem de 4
  símbolos a 15 posições um do outro. Esperado 0,12 em todo o `faed`; observar 2 dá p≈0,006, mas
  foram 1.250 estatísticas varridas, então não é significativo em conjunto. É a única estrutura
  local do `faed`.
- `aedgg` aparece 3 vezes (índices 1, 36, 215) e `faed` começa com `f`+`aedgg`; um 5-grama com
  3 ocorrências tem probabilidade ≈3%. O início do `faed` é a região com mais coincidências.
- Nenhuma seleção principiada de `faed` tem 32/64/128/256 bits (primos=104, uns da matriz=101,
  escapes g/i=182, complemento=388, saltos do `dbbi`=91). Isso reforça "`faed` → senha de texto"
  e enfraquece "`faed` → chave crua".

**Leads da rodada 3 (ordenados pelo crítico), com o estado ao fim desta sessão:**

1. R1: `lastwordsbeforearchichoice` com as falas reais da cena do Arquiteto. Agentes foram
   bloqueados duas vezes por filtro de conteúdo. Testado inline nesta sessão com frases curtas
   (ver adendo abaixo).
2. R2: TAIL32 × componentes da senha da fase 3 × tokens de xadrez da frase "fubcd-king &
   oracle-queen … as wide as the first one seen". Testado inline (adendo abaixo).
3. R3: "our first hint is your last command" = a linha de comando `openssl` literal. Testado
   inline (adendo abaixo).
4. R4: mapa símbolo→valor não-identidade (CANON, frequência, alfabeto da 3.2, reverso) antes de
   qualquer materialização. Em execução por agente (rodada 3).
5. R5: `g` como zero seletivo, com seletores por cor/matriz/ordinal, seguido do z-method. Testado
   inline (adendo abaixo).
6. R6: running key aperiódica com gate de entropia condicional. Em execução por agente (rodada 3).

**O que o crítico recomenda a um humano:** a fronteira mudou de "qual cifra?" para "qual insumo
falta?". Depois de ~50 M testes com nulos casados e controles positivos recuperados em primeiro
lugar, toda leitura de `faed`/`dbbi` como mensagem está refutada com poder medido, e o vocabulário
de senhas da comunidade (>1,3 M formas) está queimado contra os três blobs. Ações fora do alcance
de um agente: perguntar ao criador se o TAIL32 abre com material da fase 3 ou da SalPhaseIon;
varrer as variantes de whitespace do parágrafo "Raising the stakes…" no snapshot vivo do Wayback;
e examinar o livro físico *Cosmic Duality* (Time-Life), p. 39, "Le Miroir de la Vie et de la
Mort", já que `yinyang` é o único dos quatro passos do roadmap sem referente decodificado.

**Calibrações que passam a valer como regra:** qualquer z entre 5 e 8 num funil grande é ruído
(o nulo empírico chega a 5,5 com 25–60 mil permutações e a −8,0 com 2 M candidatos de Bifid);
nulos devem preservar a estrutura (classes de posição no Bifid, marginais no símbolo-par, paridade
no hill-climb); e o teste de padding com um único AES-ECB no último bloco é 30× mais rápido que
decifrar o blob inteiro.

**Adendo — R1, R2, R3 e R5 executados inline nesta sessão (0 hits):**

| leitura | testes | cobertura |
|---|---:|---|
| R1 falas finais da cena do Arquiteto | 62.760 AES + 20 k privkeys | 96 frases curtas (últimas falas do Arquiteto e de Neo, as duas portas, "the problem is choice", esperança, "we won't") × 11 grafias × 4 formas, mais prefixo `giveit`, sufixos dos tokens da página e a composição do roadmap `yellowblueprimes`+`matrixsumlist`+frase+`yinyang` |
| R3 linha de comando `openssl` | 43.656 AES + 14 k privkeys | 3.638 variantes da linha (`enc -aes-256-cbc`, `-d -a`, `-in` com 11 nomes, `-pass pass:`/`-k` com os sha256 das fases 2, 3, 3.2 e a URL), cruas, sem espaços e só alfanuméricas, × 4 formas |
| R2 TAIL32 × fase 3 × xadrez × 3.2 | 569.370 AES + 190 k privkeys | 126 tokens (as 7 partes da senha da fase 3 com o hex do genesis e os dois FENs, peças e casas do tabuleiro, `fubcd`/`king`/`oracle`/`queen`/`thingky`/`mvps`/`sadboard`/`aswideasthefirstoneseen`, tokens da 3.2) em 1, 2 e 3 partes, com 4 partes no núcleo de 12, com e sem separador `.` |
| R5 `g` como zero seletivo | 704 z-methods + 8,4 k AES | 88 seletores (primos base 0/1, ordinal primo, azuis/amarelas/coloridas, células 0/1 da matriz README em espiral e row-major, paridade, resíduos mod 2..9, primeiros/últimos k, metades, todos/nenhum) × 2 polaridades × faed/metades/reverso; melhor imprimível 0,49 |

Padding válido nas varreduras AES: 2.486 em 624.408 e 2.277 em 569.370, ambos ≈ 1/251 = ruído.
Com isso, das seis leituras do crítico restam apenas R4 (mapa símbolo→valor) e R6 (running key
aperiódica), ambas em execução por agentes ao fim desta sessão.

**Adendo — R4 e R6 executados por agentes (rodada 3, 0 hits):**

- R4 `symbol_map_variants` (1.647.689 testes): 14 mapas símbolo→valor (CANON, 1ª ocorrência do
  `faed`, frequência crescente/decrescente, alfabeto keyed da 3.2, reverso, cada um em 1..9 e 0..8,
  mais `g`=0 e `g`=7 globais) × 9 fontes × 57 seleções × 26 materializações, com janelas de
  32/64/77/78/80/81 símbolos em todo offset: 890 k checagens de privkey e 757 k de padding, tudo no
  piso 1/256. Três controles plantados recuperados. Se `faed`/`dbbi` codificam a chave, não é por
  mapa global fixo símbolo→dígito.
- R6 `running_key_gate` (18.972 streams reais): 51 running keys ≥ 570 dígitos derivadas do corpus
  (Arquiteto, plaintexts das fases 2/3/3.2, `dbbi` repetido, sha256 dos tokens, URL, π/e/√2,
  matriz, binários da página, `faed` como autokey) × 4 configurações × 31 alinhamentos × 3 modos,
  com gate de entropia condicional |z| ≥ 10. O controle (checkerboard + π) passa em rank 1 com
  z=−30,5 e 0 falsos positivos na varredura cega; `faed` real só aprova o artefato self-simétrico do
  lag 285 e, fora dele, fica em 7,7 = cauda do nulo (5,7–5,9). A última camada aditiva aberta está
  refutada para chaves ancoradas no corpus; restam apenas chaves correntes externas.

Total acumulado da campanha 2026-09-02: **~54 M testes de oráculo duro, 0 hits.**

**Adendo — running key EXTERNA: o texto do livro *Cosmic Duality* (inline, 6,4 M streams, 0):**
o OCR completo do livro (`_work/cosmic_duality.txt`, 265 mil letras) como chave corrente em
a1z26 e a0z25, todos os 265.156 alinhamentos × 4 configurações × 3 modos, com pré-filtro
vetorizado de entropia condicional e gate completo nos 150 menores de cada combinação; o mesmo
pipeline sobre um `faed` embaralhado como nulo. Controle: checkerboard 3.2.2 + chave do livro no
offset 12345 dá z=−24,9 na chave certa e −1,4 deslocada de 1. Resultado: um único stream real
passou o gate de 30 embaralhamentos (z=−10,5, offset 252770, `m10i0`/Beaufort), mas com 3.000
embaralhamentos o z estabiliza em **−5,4**, o nulo casado chega a −7,8, o trecho do livro nesse
offset é o índice remissivo, e os decodes (checkerboard −6,5, Bifid −7,2, z-method 38% imprimível)
são ruído. Lição: z de gate com 30 embaralhamentos infla extremos; confirmar sempre com ≥1.000.
Com isso, das seis leituras do crítico, **as seis estão fechadas**; o lead "livro Cosmic Duality"
como running key está negativo para o texto OCR (resta apenas a gravura da p. 39 como imagem).

**Adendo — parágrafo "Raising the stakes…" em variantes (inline, 6.360 oráculos, 0):** 16 fatias
do parágrafo (inteiro, cada sentença, cada segmento entre vírgulas, "fubcd-king", "oracle-queen",
"the first one seen"…) × 31 variantes de whitespace/entidade HTML/quebra de linha/pontuação/caixa/
tags × 6 formas (crua, sha256hex, SHA256HEX, sha256², digest cru, UTF-16-LE), mais concatenações
com a gramática da 3.2 e os tokens do endgame. Paddings válidos 19 em ~4.800 = ruído.

## Sessão 2026-09-04 — máscara ASCII `matrixsumlist` × posições primas

Nova leitura derivada diretamente dos artefatos primários, sem vocabulário comunitário: a camada
a/b que decodifica `matrixsumlist` tem **104 bits**, exatamente a quantidade de índices primos
menores que `len(faed)=570`. A gravura da p.39 de *Cosmic Duality* foi extraída diretamente do
PDF (página física 43): a divisão vertical vida/morte motivou tratar a/b como polaridade e testar
ordem direta/espelhada. Hipótese: alinhar os 104 bits, um a um, às 104 posições primas de `faed`,
nas bases 0 e 1, e zerar a polaridade “morta” indicada por a ou b.

`solver/prime_ascii_mask_attack.py` cobriu base 0/1 × máscara direta/espelhada × ambas as
polaridades, materializando o fluxo completo zerado, somente os primos zerados, primos vivos,
primos mortos e fluxo sem os mortos; cada um em dígitos, alfabeto `o=0,a=1…i=9`, caixa alta,
z-method e reverso. As 256 saídas únicas foram verificadas como sha256→privkey e como senha
hexadecimal nos três blobs via EVP-SHA256 (**768 testes AES**). Controle positivo: o mesmo código
abriu a fase 2 com `sha256(causality)` e recuperou plaintext 98,1% imprimível.

Resultado: **0 hits duros, 0 textos semânticos**. Um único padding válido apareceu no COSMIC
(38,9% imprimível), abaixo do esperado por acaso e claramente ruído. A coincidência estrutural
104 bits ↔ 104 primos é real e fica registrada, mas a interpretação literal “máscara que zera
posições primas” está fechada nessas polaridades e ordens. Relatório completo:
`_work/new_approach_page39/prime_ascii_mask_attack.json`.

### Adendo — os 104 bits como rota/permutação

A alternativa seguinte preservou todos os caracteres: os bits ASCII de `matrixsumlist` passaram
a ordenar os 104 caracteres extraídos das posições primas de `faed`. Foram cobertas partição
estável 0→1/1→0, grupos invertidos, intercalação, roteamento por deque e ordenação local dos 13
bytes × 8 bits em leitura por linha/coluna. Cada rota foi executada nos dois sentidos, com quatro
orientações justificadas do bitstream (direta, espelho, bytes invertidos e bits invertidos dentro
de cada byte), posições primas base 0/1 e duas saídas: fluxo primo isolado ou reinserido em `faed`.

Após deduplicação, `solver/prime_ascii_permutation_attack.py` produziu **96 rotas**, 384 streams e
7.440 materializações (símbolos, caixa, dígitos, z-method, reverso e Bifid canônico em períodos
ancorados). Todas foram verificadas por SHA256→chave pública — incluindo o ponto secp256k1 negado
— e por sha256hex→AES nos três blobs: **22.320 testes AES, 0 hits duros e 0 candidatos Bifid no
limiar semântico**. Os 82 paddings válidos batem o acaso (87,19 esperados); o melhor plaintext
aleatório teve só 51% de bytes imprimíveis. Controles: os 96 pares rota/inversa fizeram round-trip,
as duas convenções têm 104 primos e o pipeline abriu a fase 2 com `sha256(causality)`.

Conclusão: a leitura “um bit por posição prima” continua uma coincidência estrutural forte, mas
as famílias naturais em que o bit **zera** ou **ordena** o caractere estão fechadas. Relatório:
`_work/new_approach_page39/prime_ascii_permutation_attack.json`.

## Sessão 2026-09-04 — perícia da p.39 e `lastwordsbeforearchichoice`

A gravura de *Cosmic Duality*, p.39 (página física 43 do PDF), foi reextraída em vez de depender
do OCR parcial. A página é uma composição MRC com JPEG RGB de 963×1214, uma camada JPEG RGB de
2889×3641 e máscara JBIG2 de mesma resolução. `qpdf --check` não encontrou dano estrutural; os
JPEGs não têm EXIF nem tabelas DQT não utilizadas, e depois do último `%%EOF` há somente CRLF.
Assim, não apareceu payload oculto simples em metadados, quantização JPEG, overlay pós-EOF ou
camada PDF separada. O render combinado de 300 DPI está em
`_work/new_approach_skills/page43_render_300dpi.png`.

O render tornou legível o verso completo de **Le Miroir de la Vie et de la Mort**. A transcrição
verbatim usada no ataque está em `_work/miroir_verse.txt`; ela preserva inclusive `n'auons` e
`Quen`. A pista já decodificada `lastwordsbeforearchichoice` produz a seleção objetiva:

`visage sage perir asseurée durée mourir`

Também foram testados os primeiros termos (`Mondains Scachez Puis Nous Tout Quen`), o acróstico
`MSPNTQ`, o teléstico `VSPADM`, extremos de cada linha e o texto integral. A geometria do espelho
limitou as rotas a direta, reversa, fora→dentro e dentro→fora, além dos subconjuntos primos base
0/1. Para cada leitura, `solver/miroir_verbatim_attack.py` cobre separadores, caixa, retirada de
acentos/pontuação, reverso textual e XOR dos SHA-256 individuais — este último reaproveita o
operador já demonstrado por `intertwined` em fase anterior.

Após deduplicação foram 583 candidatos textuais, 20 chaves XOR e 603 chaves finais únicas. Os
três blobs foram testados com senha crua, SHA-256 hexadecimal e digest cru, tanto em EVP-MD5
quanto em EVP-SHA256: **10.494 tentativas AES**. Cada chave final também passou por **3.618
decifrações** dos 35 blocos (ECB e CBC com cinco IVs ancorados) e varredura de toda janela de 32
bytes contra a chave pública secp256k1 alvo e seu ponto negado. Controles positivos abriram a
fase 2 com `sha256(causality)` e reproduziram o SHA-256 conhecido do plaintext COSMIC.

Resultado: **0 hits duros**. Houve 49 paddings válidos contra ~41 esperados ao acaso; nenhum foi
semântico e o melhor teve só 48,1% de bytes imprimíveis. Portanto, a leitura literal das últimas
palavras do poema — incluindo suas combinações naturais de espelho e XOR — está fechada. O
relatório completo está em `_work/new_approach_skills/miroir_verbatim_attack.json`.

## Sessão 2026-09-04 — último commit Claude × ambiguidade `g=0/7`

A proveniência foi auditada antes do novo ataque. O último commit do Claude é `6315bca`
(`raising_variants`, 6.360 oráculos, negativo); ele está em `master`. Não há outra branch local,
stash ou worktree. O snapshot e a memória originais da sessão foram recuperados em
`solver/experiments/claude_endgame_2026_09_02/`. O plaintext completo da fase 3.2.2 já constava
na gramática de `tail32_history.py`, portanto não havia uma omissão simples de “answer too”.

O fato novo aproveitável da memória era estatístico: `faed` tem 107 ocorrências de `g` e seu
unigrama é compatível com dígitos decimais uniformes se `g` representar **0 ou 7**. Isso foi
cruzado com os 104 bits a/b que decodificam literalmente `matrixsumlist`. A hipótese testada foi:
os bits escolhem 0/7 nas ocorrências de `g`; os três `g` excedentes são os “extra” removidos ou
recebem todas as 8 combinações binárias possíveis.

`solver/g_ambiguity_matrixsum_attack.py` cobriu 8 rotas naturais (linear e grades 15×38/38×15,
colunas e boustrophedon), 4 orientações da máscara, 2 polaridades, máscara alinhada ao início/fim,
as 8 terminações de 3 bits e descarte dos 3 símbolos iniciais/finais. Foram **1.152 atribuições**,
29.592 materiais únicos, **532.656 testes AES** (senha crua, SHA-256 hexadecimal e digest cru;
EVP-MD5/SHA256; SMALL/COSMIC/TAIL32) e **1.317.336 janelas** secp256k1 contra o alvo e seu ponto
negado. O controle abriu a fase 2 com `sha256(causality)` e 98,1% de bytes imprimíveis.

Resultado: **0 hits duros**. Os 2.084 paddings válidos coincidem quase exatamente com os
2.080,69 esperados ao acaso. A melhor saída decimal→hex teve 53,3% de bytes imprimíveis e score
−7,90 (texto real ≈ −3), portanto também é ruído. Fica fechada a leitura em que a máscara ASCII
`matrixsumlist` resolve diretamente a ambiguidade 0/7 dos `g`. Relatório:
`_work/new_approach_claude/g_ambiguity_matrixsum_attack.json`.

## Sessão 2026-09-04 (b) — varredura do Telegram Desktop pós-export e o "YOUWON" da comunidade

O export `result.json` termina em 2026-07-08. O grupo foi lido diretamente no Telegram Desktop
(filtro "From: Jrk Bgrt"); o criador voltou em **12/07, 16/07 e 01/09/2026**. Transcrição das
falas relevantes em `_work/tg2026_scan_attack.jsonl` (campo `creator_msgs`). O que muda o mapa:

- **"My close friends have the best chance of solving it (a few tried). But they don't have the
  skills some of you do." → "NOTE: that is a hint."** (12/07). Leitura direta: o passo final exige
  algo que os amigos próximos sabem e a comunidade não — conhecimento pessoal, não criptoanálise.
  Combina com "THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF" (3.2.2) e com o criador chamando a
  parceira de "the better half" (2025, 2026): *half & better half* = o criador e a parceira.
- **"Couple hours, and no."** (01/09) para "quanto tempo levou para criar o puzzle / estava
  sozinho?". A mecânica do endgame foi montada em poucas horas, com ferramentas online (como as
  fases 1–3.2: sha256, openssl, dcode, CyberChef). Isso desfavorece qualquer família de decodificação
  elaborada e favorece: substituição dígito→letra (como `shabef` e os z-segmentos), sha256 de palavras.
- "salphaseion is 100% solveable?" → **"Yes"**; "it's all still solvable" (12/07). "I have a hidden
  laptop which I haven't touched in years. On that thing... is the actual answer." "The '5' btc was
  never the actual prize. That was only a tiny fraction." "Some already found it. And understood not
  to risk it..." — o prêmio real não é (só) o endereço 1GSMG; não é acionável.
- Perguntado se `dbbi`/`faed` devem ser decodificados como os outros segmentos ou são só
  "ingrediente": respondeu com o emoji de boca fechada (01/09). Sem informação.
- 16/07 é conversa sobre BIP360/drogas ("Lately, I'm working with many NOTES", "You have to be in
  your prime for that", "Meta hunting. Like it.") — sem conteúdo.

**Achado comunitário avaliado — "YOU WON" (Vasilis Dragon, 12–13/07).** `M91` = plaintext da
3.2.2 (`INCASEYOUMANAGE…FUNDSTOLIVE`) tem **exatamente 91 letras = len(dbbi)** (notado desde 2023).
`(dbbi[a=0..i=8] − M91) mod 26` = `VOZIJBDTIQBRGVEOMZNBC**YOUWON**XCPKWGBNAXDGJGDUNNVMPABTAFPAAXMJYLZBUWERDNXYDESKUOBXCAMVDJLQTSGA`
(índice 21). Reproduzido em `solver/tg2026_youwon_m91.py`. Nulo sem rótulo
(`solver/tg2026_youwon_null.py`): melhor score de quadgramas nas 8 variantes naturais (±chave, ±M,
a=0/1) = **−5,63**; 3.000 embaralhamentos de `dbbi` → máximo nulo −7,00 (p < 3,3·10⁻⁴); 3.000 de
`M91` → idem. Mas o estatístico é dominado pelas 6 letras: P(alguma palavra BIP39 ≥6 letras em
alguma das 8 variantes) = 0,001 por acaso, e escalando para as ~20 mil palavras/frases de 6 letras
que um humano aceitaria, **p ≈ 3%**. Os 85 caracteres restantes são ruído (−7,7 a −8,1 nas outras
variantes); `dbbi` tem 9 símbolos, logo `dbbi = (P + M91) mod 26` não pode ser cifra de um P
arbitrário; e o criador respondeu **"Pfff. Coincidence."** (01/09). Os passos seguintes da cadeia
("borrow rail" → DEL, `KMODEST` → "BE MODEST", sha256(YOUWONBEMODEST)) são numerologia. Fechado
como senha: 72 formas × 3 blobs = 216 AES (3 paddings = acaso) + sha256(frase)→privkey: **0**.
Derivados de Diego Schmidt (31/08: "Yellow BLUE primes = DEL FE", `enter`→13224→EO 13224) vêm da
mesma cadeia.

**Três leituras baratas do material novo (todas negativas):**
- `firsthint_hash` (27): "our first hint" = o primeiro hint literal do criador no Telegram
  (2019-04-20), o hash `5ac407…` = sha256(`theflowerblossomsthroughwhatseemstobeaconcretesurface`);
  cru/upper/sha256/digest/+\n nos 3 blobs: 0 paddings.
- `matrix_zeros_fill` (1.024): "zeroed out" como *os 1s da matriz viram 0 e os 91 zeros dos 192 bits
  recebem dbbi* (4 ordens × 2 matrizes × 192/196 × polaridade × a=0/1 × preenchimento × alinhamento ×
  reverso) → z-method + senha: melhor 54% imprimível, 0 hits.
- `base9_int` (168): dbbi/faed/metades/concatenações como inteiro em base 9/10/16/26 → bytes,
  privkey em toda janela e senha crua/hex: 0 hits (o 0,83 do base-16 é tautologia de nibbles 1–9).

**Leads que sobram (não computacionais):** (1) o hint "close friends" aponta para conhecimento
pessoal do criador — o único vocabulário público é o do próprio Telegram (Jacque Fresco/Venus
Project, Mr. Robot, Cyberpunk 2077, GSMG = "Globally supporting my generation", "the better half",
Ibiza/Roterdã, Blueprint/NAD, passaporte do Neo), já minerado em `brainwallet`/`pop_culture` sem
hits; identidade real do criador ou da parceira **não** deve ser perseguida. (2) "Couple hours"
impõe um teto de complexidade: qualquer nova hipótese deve ser executável em minutos com CyberChef/
dcode/openssl.

### Adendo — cadeia "23 / 16 / 7 / &8 / Hb_m!%D" (sessão Codex, 2026-09-04)

Origem: não é do Telegram, é de uma sessão do Codex Desktop. Cadeia: `dbbi` nas posições primas
(base 1) filtrado pelos LSB da URL → inteiro em base 9 → `17 6c386f4f4b` (1º byte 23); `faed` nas
posições primas filtrado pelos bits de `matrixsumlist` → base 9 → `10 eb5a8d…842c` (1º byte 16);
5 + 18 = 23 bytes; `l8oOK` lido como "look 8"; `byte & 8` separa 16 + 7 bytes; remover o bit 3 dos
7 dá `Hb_m!%D`. Reproduzido bit a bit em `solver/tg2026_codex_hbm_null.py`.

Nulo construído sobre o **próprio espaço de variantes do Codex** (24 fluxos de dbbi × 80 de faed):
4 pares têm 1º bytes em {7,16,23}; 394 pares têm 23 bytes; 94 admitem algum bit que corta 16/7; **15
desses produzem 7 bytes todos imprimíveis** após remover o bit — `Hb_m!%D` é um entre ≥15 artefatos
equivalentes. P(7 valores de 7 bits todos imprimíveis) = 12%. Cada elo tem p de dezenas de por cento;
o produto é o que se espera de uma busca com ~2 mil pares e regras escolhidas a posteriori.

Oráculos: `Hb_m!%D` + 13 derivados × 3 blobs (EVP-SHA256 e MD5) = 42 AES, 0 paddings; privkey 0.
O próprio Codex reportou BIP38 (comum e EC-multiply) nos 35 blocos e o bloco de 16 bytes como
OpenSSL: 0. Os 35 blocos são a cadeia-miragem (pad 0x01, EVP-MD5) — ver "A fronteira real".
**Fechado.** Aviso operacional: Codex e Claude controlando o mesmo desktop ao mesmo tempo disputam
a janela do Telegram; rodar um de cada vez.

## Sessão 2026-09-05 — o "Bingo" de 2026-03-03 = *Looking Forward* (Fresco & Keyes, 1969)

**Releitura do hint primário.** A sequência exata do Telegram em 2026-03-03 é: Denis Golovkin
pergunta *"Wasn't 'it's in front of your eyes but you're not seeing it' a recommendation to read
**Looking Forward** btw.?"* (22:22) → criador: *"Looks at gnomad 👀"* (22:27) → gnomad: *"Looks at
DG's comment 'its in front of your eyes but you're not seeing it'"* (22:27) → criador: **"Bingo"**
(22:29). Três minutos antes ele havia dito *"Jacque was quite an inspiring lad"*. Ou seja, o "Bingo"
endossa o comentário do DG, e o comentário do DG **é** a sugestão do livro. Nenhum membro do grupo
levou isso adiante em nenhum momento (48 menções a Fresco/Venus Project no export, zero testes do
livro), e "running key EXTERNA ao corpus" era a única família principiada que sobrevivera às
rodadas 1–3. Texto obtido do PDF público da Universidade de Edimburgo (121 páginas, 294.341 letras,
`_work/looking_forward.txt`).

**As três leituras naturais do livro, todas com nulo casado, todas negativas:**

1. `looking_forward_password` (`solver/lf_password_attack.py`) — a gramática provada da fase 1 é uma
   frase **verbatim** de uma obra (letra de *The Warning*), minúscula e sem espaços → sha256. Foram
   varridas todas as 3.298 sentenças, todos os n-gramas de 2 a 12 palavras e os títulos de capítulo:
   **641.668 candidatos × 3 formas × 3 blobs = 5.775.012 testes AES** (oráculo rápido de 1 AES-ECB no
   último bloco; controle positivo abriu a fase 2 com `sha256(causality)`, 98,1% imprimível).
   Paddings válidos **22.710 contra 22.559 esperados** ao acaso (razão 1,007) e **0 hits duros**.
2. `looking_forward_runningkey` (`solver/lf_runningkey_attack.py`) — o livro como chave corrente
   sobre `faed`, reaproveitando o gate calibrado da rodada 3: 2 mapas × 4 configs × 3 modos ×
   293.772 alinhamentos = **7.050.528 streams**. Melhor z de entropia condicional **−9,35** contra
   **−8,03** do nulo casado (`faed` embaralhado) e −30,5 do controle com a chave certa. Nenhum passou
   o gate |z| ≥ 10.
3. `looking_forward_bookcipher` (`solver/lf_bookcipher_attack.py`) — a leitura nova: `faed` são
   570 dígitos 1..9 e comporta-se como i.i.d., que é o que se espera de um fluxo de **índices**;
   570 = 3×190 = 2×285. Grupos de 2 e 3 dígitos, decimal e base 9, base 0/1, direto e reverso,
   sobre palavras/linhas/sentenças/letras, iniciais e palavras inteiras = 168 leituras. Melhor
   quadgrama −4,25, mas o nulo casado (200 embaralhamentos do `faed`, mesmo pipeline) dá média −4,26
   e máximo −4,15: **z = +0,26, p = 0,375**. O texto "legível" é artefato de concatenar sentenças
   inteiras de um livro em inglês, independente dos índices. 480 AES nos 40 melhores: 0.

**Conclusão.** O melhor hint objetivo disponível do criador está testado e fechado nas três formas
em que um livro pode servir a este puzzle. O livro também não tem sobreposição de vocabulário: zero
ocorrências de *yang*, *salvation*, *matrix*, *rabbit*, *architect*; *cosmic* aparece 1 vez. Se
*Looking Forward* é mesmo a resposta ao "in front of your eyes", o elo que falta não é o texto do
livro, mas algo específico dentro dele (uma ilustração de Fresco, uma página nomeada por um hint)
que nenhuma fonte pública identifica.

### Adendo — as ilustrações de *Looking Forward* e "lookingforward" como palavra

O PDF (Edimburgo) contém **16 imagens únicas**, todas referenciadas como recurso compartilhado
por todas as 121 páginas; é texto recomposto, sem numeração de página impressa (0 números
detectados), logo o teste "número do puzzle = página do livro" (101, 163, 193, 42, 140…) não é
possível com esta fonte. Folha de contato e as duas gravuras relevantes em
`_work/looking_forward_img/`. Leitura com olhos de puzzle: **u04** é uma cúpula de projeção com uma
grade de quadrados claros/escuros e duas pessoas olhando para cima — tematicamente "a matriz em
frente aos seus olhos", mas é um desenho de 1969 em scan de 455×292 px, sem grade regular
extraível; **u11** é um veículo com o número **243** (243 = 3⁵; 285 − 243 = 42 é numerologia);
**u15** são três engrenagens "VALUES / METHOD OF THINKING / TECHNOLOGY". Nenhuma contém dado do
puzzle, e esteganografia neste PDF seria do digitalizador, não do criador — não foi rodada.

"lookingforward" como **palavra** (o "Bingo" pode endossar só o trocadilho de Denis Golovkin, "to
see what's in front of your eyes you need to be looking forward"): 1.064 textos = permutações de
1–3 tokens do roadmap/página/livro contendo `lookingforward`, em 3 caixas e 3 separadores × 4
formas (crua, sha256hex, SHA256HEX, digest) × 3 blobs × 2 KDF = 25.536 AES; paddings 105 contra
100 esperados; privkey por sha256(frase): 0. **Negativo.**

Números do puzzle como **páginas** do scan real de 1969 (archive.org, `page_numbers.json` +
`djvu.xml`, 92 de ~165 páginas mapeadas; `_work/looking_forward_pages_1969.json`): páginas 7, 9,
14, 15, 16, 23, 24, 39, 42, 163 (101, 140, 193, 243, 285 fora do mapeamento ou do livro) × {página
inteira, 1ª/última sentença, 1ª/última palavra, 5 primeiras/últimas, 1ª+última} × 4 formas × 3 blobs
× 2 KDF = 1.920 AES, paddings 8 = esperado, privkey 0. **Negativo.** Com isto o livro está fechado
em todas as leituras públicas: texto (senha, running key, cifra de livro), gravuras, palavra-título
e páginas.

## Sessão 2026-09-05 (b) — roadmap `yellowblueprimes → matrixsumlist` e leituras literais da linha do blob

**`roadmap_yb_matrixsum`** (`solver/roadmap_yb_matrixsum_attack.py`). O roadmap do criador é
sequencial e os dois primeiros passos têm um encaixe numérico exato: as 24 células coloridas
(índices espirais 7,15,…,191) são exatamente 24 = quantidade de primos < 91 = `len(dbbi)`, e a
ordem espiral `BBBBYBBBYYBBBBYBBYYBYYBY` marca cada primo como azul (15) ou amarelo (9) — sendo
15 a largura da grade `faed` 15×38 e 9 o tamanho do alfabeto.

Primeiro um teste sharp: `dbbi` nas 9 posições primas amarelas seria uma **permutação de a–i**?
Base 0 dá `ebedggdfb` (5 símbolos distintos), base 1 dá `bhgfceeba` (7 distintos) — **não**. A
chance ao acaso seria 0,00022, então o negativo é informativo: a camada cor→substituição não
existe nessa forma (soma-se ao já sabido de que azul/amarelo não dão permutação de coluna única).

Depois o pipeline completo: azul/amarelo/todos como **chave de transposição colunar** (ordem
estável, letras repetidas permitidas) sobre `faed` 15×38 e 38×15, direta e inversa, leitura por
linha e por coluna, base 0/1, direto e reverso; sobre cada saída o passo 2 `matrixsumlist` como
soma das listas de linhas/colunas mod 9, passo 101 e seleção mod 101. São 112 candidatos.
**Nulo casado: 300 reatribuições aleatórias de 15 azuis entre os 24 primos, mesmo pipeline** —
média −5,740, sd 0,102, máx −5,415; real −5,80 → **z = −0,59, p = 0,693**. Oráculos: 1.776 AES
(fast-padding, controle abre a fase 2), 3 paddings contra 6,9 esperados, privkey 0. **Fechado.**

**`first_hint_literal`** (inline). A linha `shabef our first hint is your last command` lida ao pé
da letra: "our first hint" = o primeiro hint do puzzle (a matriz → `gsmg.io/theseedisplanted`, e o
endereço-prêmio/HASHTHETEXT) e "your last command" = o último `openssl` que você rodou (senha da
fase 3.2 `250f37…`/`jacquefresco…`, e as das fases 2 e 3). 255 textos = as duas listas isoladas,
todos os pares concatenados nas duas ordens e cada um com a própria linha e com `ans too` →
1.501 formas (crua, caixa alta, sha256hex, SHA256HEX, digest cru, sha256²) × 3 blobs × EVP-SHA256
e MD5 = **9.006 AES**; paddings 32 contra 35,2 esperados; privkey 0. **Negativo.**

## Sessão 2026-09-05 (c) — RESOLVIDO: a verificação Wayback que estava em aberto

A rodada 3 fechou `raising_variants` com a ressalva *"sem o snapshot vivo do Wayback, que só um
humano pode conferir"*. Essa pendência agora está **resolvida por programa**, em duas partes.

**(1) A página do endgame, cinco snapshots, byte a byte.** A CDX API dá 5 capturas de
`gsmg.io/89727c…` com digests distintos: 2023-06-01, 2023-11-27, 2024-11-23, 2025-10-31 e
2026-04-05 (4.556, 4.556, 4.588, 5.092 e 5.092 bytes após descomprimir o gzip). Diferenças:

- **2023-06 → 2023-11: `<h1> SalPhaseIon </H1>` virou `<H1> SalPhaseIon </H1>`.** O criador
  **editou a página** nessa janela, normalizando a tag de abertura para casar com o fechamento.
  Corrige o mapa: a "assimetria única `<h1>…</H1>`" registrada na rodada 1 existiu só até 2023 e
  foi removida por ele; `<h1> Cosmic Duality </h1>` continua todo minúsculo. É uma faxina, não um
  hint, mas é o único toque documentado do criador no HTML.
- 2023-11 → 2024-11: só indentação (minificação do servidor ligando/desligando).
- 2024 → 2025 → 2026: inserção e bump de versão do beacon do Cloudflare.

**Conteúdo idêntico nas cinco.** Verificado contra o repositório: `dbbi` e `faed` presentes e
iguais byte a byte, blob SMALL presente, binários de `matrixsumlist` e `enter` presentes, `shabef`
presente. Fora das duas `<textarea>` a página tem **apenas** doctype, head com `<title>GSMG
Puzzle</title>`, quatro metas, um `<style>` de `font-family: arial`, os dois `<h1>` e `</body>`.
Sem comentários HTML, sem atributos extras, sem terceiro campo. **O README é fiel; a página não
esconde nada.** Cópia em `_work/salphaseion_wayback_20241123.html`.

**(2) Os plaintexts exatos, em vez de whitespace adivinhado.** O parágrafo "Raising the stakes" e o
blob TAIL32 não vivem numa página: são o texto decifrado da fase 3.2. Decifrando na hora (fase 2 =
648 B, sha256 `e2f9dd65…`; fase 3.2 = 2.422 B, sha256 `b82afeb8…`, salvo em
`_work/phase32_plaintext.bin`) obtêm-se os **CRLF verdadeiros**. Os blocos são separados por
`\r\n\r\n` e o plaintext termina no blob, sem newline final. `solver/exact_plaintext_tail32_attack.py`
usa esse material verbatim — texto inteiro, cada bloco, cada linha, cada run ASCII ≥25, prefixos e
sufixos cumulativos e o encadeamento entre fases — em 173 formas × 3 blobs × 2 KDF = **1.038 AES**;
paddings 2 contra 4,1 esperados, privkey 0. **Negativo**, mas agora sem a ressalva de whitespace.

**Nota interpretativa.** "on a sad board but as wide as the first one seen" foi testado como
parâmetro de grade: nenhum comprimento relevante (149 dígitos, 91 do M91, 80 do CT, 570 do faed)
é divisível por 14. A frase já está consumida pelo checkerboard conhecido, que decodifica os 149
dígitos para o texto de 91 letras. Não sobra parâmetro nela.

## Sessão 2026-09-05 (d) — varredura completa do domínio no Wayback: nenhuma página inédita

Varredura da CDX API em `matchType=domain` sobre `gsmg.io` (618 capturas, 489 com status 200;
lista bruta em `_work/wayback_gsmg_domain_cdx.txt`). Objetivo: descobrir se existe alguma página do
puzzle que nunca entrou no README.

**Resultado: não existe.** As únicas páginas de puzzle são as cinco já documentadas (`/puzzle`,
`/theseedisplanted`, `/phase1verification`, `/choiceisanillusion…iwroteitmyself`, `/89727c…`).

O que parecia promissor e foi verificado um a um:

- **`alpha.gsmg.io/89727c…`** (2026-05-18, 4.843 B) — é um **espelho vivo** da página do endgame.
  Baixado e comparado: **idêntico** ao `gsmg.io` byte a byte, exceto pelo `<script>` do beacon do
  Cloudflare. Fato útil: quando o criador diz "the puzzle is still valid" (2026-05-28), a página
  segue servida — em `alpha.gsmg.io`, não no domínio raiz.
- **`gsmg.io/4f7a1e4e…`** — esse hash é o SHA-256 do plaintext "Cosmic" da cadeia comunitária, e a
  URL responde 200. Parecia poder reabrir a questão da miragem. **Não reabre**: o corpo de 1.224 B
  é a página de *fingerprinting* do estacionamento (`FingerprintJS` + redirect com `tr_uuid`/`fp`).
  A cadeia histórica continua refutada.
- **`gsmg.io/53616c7465645f5f74c974e3…`** — `53616c7465645f5f` é "Salted__" em hex, parecia um blob
  AES publicado como URL. É sondagem de algum solver: o servidor devolve a SPA.
- Dezenas de caminhos temáticos (`/salphaseion`, `/merovingian`, `/TheArchitectChoice`,
  `/whiterose`, `/whiteroseredqueen`, `/final_stage`, `/thepuzzlestartshere`, `/followthewhiterabbit`,
  `/phase1`…`/phase3_2_2_2`, `/hopeisthequintessentialhumandelusion…`, `/youme{,i,is,iz}andself`,
  `/eps3.4_runtime-error.r00`, `/digitallogiccryptography`, 10 URLs com cara de sha256, e as
  variantes de `banking-war`/`crypto-gic`/`dig-i`/`lock-io`/`n-you`/`open-lock-ning`) — **todas
  falso-200**. Verificado em `/whiterose`: devolve a aplicação de trading da GSMG (36.627 B, título
  `GSMG`), que responde 200 em qualquer rota por roteamento no cliente. O tamanho comprimido
  uniforme de ~12 kB é a assinatura desse falso-200.
- `beta.`, `help.`, `stats.`, `slack-invite.`, `wishes.` — produto/documentação da plataforma de
  trading, sem relação com o puzzle.

**Conclusão.** O arquivo público do domínio está esgotado e verificado: nenhuma página, nenhum
comentário HTML, nenhum campo escondido além do que o README já traz. Somado às sessões (c) e (d),
as quatro fontes públicas — página, livro apontado pelo "Bingo", Telegram e plaintexts das fases —
estão todas conferidas na origem. O que falta ao endgame não está em lugar nenhum que se possa ler.

## Sessão 2026-09-05 (e) — pesquisa pública: estado on-chain, issues do repositório original

**Fato duro primeiro.** O endereço-prêmio `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` tem **126
transações, 8,7599 BTC recebidos e saldo de 1,25635374 BTC**, nunca gasto (última movimentação
2026-08-29, entradas de poeira). **O puzzle continua aberto**; nenhuma das dezenas de "SOLVED"
publicadas moveu um satoshi.

### Issue #108 ("o blob pequeno tem DOIS typos na página ao vivo") — **REFUTADA**

Alegação: a página ao vivo teria `R` na posição 18 e `k` na 51 do base64, e corrigir para `J` e
`s` faria o blob abrir. Verificado contra as **seis capturas** que baixei (5 do `gsmg.io` +
`alpha.gsmg.io`): a página ao vivo já traz **`J` e `s`** — exatamente os valores que a issue chama
de "corrigidos". Extraindo o base64 do `<textarea>` e removendo o marcador `enter` (40 caracteres
a/b entre as duas linhas) e o `shabefanstoo` seguinte, o blob ao vivo é **byte a byte idêntico** ao
do repositório: zero diferenças em 128 caracteres. **Não há typo nenhum.**

A decifração que a issue apresenta é a miragem já documentada: com a senha
`matrixsumlistenter…matrixsumlist` e **EVP-MD5** o padding é válido, 79 bytes, **último byte de pad
= 0x01**, 38% imprimível, e o resultado é o `9fa9db91…` da cadeia comunitária. Sob **EVP-SHA256** —
o KDF que abre de fato as fases 2, 3 e 3.2 — o padding é **inválido**. Varredura de privkey em toda
janela de 32 B do plaintext: nenhuma. Issue #103 constrói sobre a mesma cadeia (chave XOR
`a795de11…`, EVP-MD5) e cai junto.

### Issue #106 (eliooooooot) — séria, e converge com este repositório

Relatório independente de ~2,5 bilhões de testes que **confirma quatro achados nossos**: o KDF real
é EVP-SHA256 (as varredura feitas com MD5 em `open-crypto-puzzles` são nulas); a mensagem binária
do criador de 2023 é ASCII com bits invertidos por byte; a moldura de cores nos índices espirais
{8,16,…,192} prova a convenção de leitura; e as "soluções" de 2026 se apoiam num único padding
PKCS7 válido, com taxa medida de **1/236** em 49.664 tentativas (nós medimos ~1/256). Também
confirma o que a sessão (d) achou: as URLs temáticas `/followthewhiterabbit`,
`/TheArchitectChoice`, `/hopeisthequintessentialhumandelusion…` **não têm captura da era ativa** —
só 2025–2026, no falso-200 da SPA.

**Correção necessária a essa issue.** Ela lista como *"author-confirmed red herring (2021-02-12):
'#…# wasn't used' → a tabela da fase 2 NÃO faz parte da solução"*. No export do Telegram essa frase
aparece em **2021-02-13**, num **resumo escrito por um membro** (conta depois apagada):
`"summary: / #..# wasnt used. / 2nd way from start wasnt founded (shared). / blobs in mp3 didnt
recovered. / 'salphaselon' is unknown from where was taken and didnt confirmed."` Não é fala do
criador. Quando perguntado diretamente sobre a tabela (2024-12-02), o criador respondeu **"Can't
say anything about this"** — recusa, não descarte. Portanto a tabela da fase 2 **não está
confirmada como red herring**, e a resolução documentada no README (Q=82, B=25 → coordenadas da
SafeNet) segue de pé como leitura da comunidade.

**Lead novo e não perseguido** (mesma fonte de 2021, ainda sem confirmação do criador):
*"2nd way from start wasnt founded"* — existiria um caminho alternativo a partir da imagem inicial,
nunca encontrado. Bate com "Roses are White… go back to the first puzzle piece… the rabbits nest
may contain a whole lot more" e com a "segunda porta" já registrada neste arquivo.
