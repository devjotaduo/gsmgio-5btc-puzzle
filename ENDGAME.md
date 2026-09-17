# Endgame — SalPhaseIon / Cosmic Duality (estado da resolução)

> **Guia de leitura — revisão integral de 11/09/2026:** este arquivo preserva
> conclusões históricas incompatíveis entre si. “Validado”, “provado” e “fechado”
> devem ser lidos com o alcance dos testes e suas correções posteriores. Não há
> abertura demonstrada de SMALL, TAIL32 ou COSMIC. A leitura das 2.923 linhas
> anteriores a esta nota recuperou o script original de X e confirmou que ele
> coincide com a reconstrução local. Ver
> [reconciliação, fontes e limites](_work/endgame_review_2026-09-11/LEITURA_ENDGAME.md).

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
os seis valores `r` são distintos, portanto não fornecem o ataque usual por
nonce reutilizado. Isso não demonstra impossibilidade de todo ataque algébrico
nem identifica o caminho final. **Correção 2026-09-16:** o negativo antigo de
`solver/gsmg_sig_recover.py` era inválido por erro de API e omissão do cabeçalho
de `GSMGJH`. A repetição corrigida de 43 mensagens também teve zero correspondências;
ver [auditoria](_work/signature_audit_2026-09-16/RELATORIO.md).

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
   **`3GSMG24TujqfMJG1kQoBX18DzJHQLeJYMK` aparece em transações desde 2020-03**
   (OP_RETURNs "GSMG.io: Right, this is causality", "phase3.2 pass OK", "You are here
   because 227 chars were correct", "Good job, Neo!", "Halving" 2020-05-11 — o dia do
   halving que reduziu o prêmio — e 2021-07-18 **"GSMG.io neighbors, half and double"**
   pagando 5000 sats a 4 endereços: `1G1kRAFR68…`, `16eEXbSuKN8…`, `1KHMK2C8uBpt…`,
   `1PhXF3xVQ8Sg…`). **Correção 2026-09-16:** a autoria dessas mensagens não foi
   autenticada. A frase **"neighbors, half and double"** não pode ser promovida
   a hint primário somente por mencionar o puzzle.
4. **Trilha 1GSMG9VDLTU6 (2026-05-15/16)**: vanity barato (1GSMG = ~minutos; comunidade,
   "ns": "don't believe the spam") enviou 5 OP_RETURNs (`hereismysecret`,
   `leavethematrix`, `isolveditwithanabacus`, `yourlastcommand`, `secondanswer`), depois
   **`GSMGJH`+65 B** (tx `808f812f…`, blk 949653) e **`GSMGBH`+65 B**, e um pointer
   `GSMG WITNESS BLK 949653 TX 808f812f` **para o endereço do prêmio**. Os 65 B têm
   formato de assinatura compacta Bitcoin (header 0x20/0x1f na faixa 27–34).
   **Correção 2026-09-16:** `gsmg_sig_recover.py` tinha 43 mensagens, um argumento
   de API inválido e o cabeçalho JH ausente. Seu resultado era inválido. A repetição
   corrigida teve 688 configurações e 344 chaves recuperadas, todas conferidas por
   verificadores independentes: **zero endereços procurados** nesse conjunto.
   [Dados, limites e reprodução](_work/signature_audit_2026-09-16/RELATORIO.md).
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
- Confirmações do criador: as mensagens na blockchain discutidas em agosto de 2023
  **não eram dele nem parte do puzzle** ("Correct", 2023-08-29, resposta #12653
  à #12580); isso não determina a autoria de posts posteriores. SHA256 do texto da fase 1 confirmado
  com "the author is a bit picky what he considers to be text" ("Good point");
  "Has anyone passed the salvation part?" → **"Partly"** (2023-08-06).

## Sessão 2026-08-30 — hint confirmado: p.39 "Le Miroir de la Vie et de la Mort" + oráculo-espelho (0 solves, 1 gap fechado)

> **Correção de proveniência, 11/09/2026:** o anexo #8310 ao qual o criador
> respondeu foi recuperado: é a **capa de Cosmic Duality com um yin-yang**, não
> a página 39. O parêntese “Cosmic Duality Book Page — Life and Death” abaixo
> aparece na compilação de Diego Schmidt (#43344), mas está ausente da mensagem
> original do criador (#8328). Portanto, a página e o poema não são uma indicação
> explícita dele. Ver [evidência e nova prioridade](docs/notes/ANALISE_PRIORIDADES.md).

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

> **Atualização de fonte, 11/09/2026:** o arquivo original `dbbi_sum_faed.py`
> foi recuperado do export de Downloads: X, #63518, 22/05/2026, 1.899 bytes.
> Sua matriz e suas três saídas coincidem exatamente com `blue_net_attack.py`.
> A pendência histórica de código ausente está encerrada. Isso confirma a
> reprodução, não a interpretação criptográfica dos fragmentos. Ver
> [verificação](_work/endgame_review_2026-09-11/original_script_check.json).
> O teste posterior que exclui `dbbi` como somas de pares de 14 valores não
> exclui esta outra receita, que usa `dbbi` como pesos e depois soma as arestas.

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
**101 uns**. Descarte todo raciocínio construído sobre "102 uns", "espiral 193 é primo" e "cauda
central 0100". O bitmap do pictograma (270 bits) foi testado como
bits, bytes, decimal, SHA-256 e chave privada: negativo.

**Correção de escopo em 16/09/2026:** os índices espirais `0..191` têm,
de fato, **91 zeros e 101 uns**, os 24 bytes de `gsmg.io/theseedisplanted`.
Os quatro bits centrais são zero; a matriz completa tem **95 zeros**.
A diferença entre a matriz antiga e a atual fica somente em `[7,6]`,
índice espiral 193, fora desse trecho. Portanto, ela não invalida a
distribuição de DBBI nas 91 células zero da região da URL. A redação
anterior deste parágrafo rejeitava também essa contagem correta.
[Comparação das matrizes e testes subsequentes](_work/zero_cells_prime_sums_2026-09-16/RELATORIO.md).

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

> **Ressalva de contexto, 11/09/2026:** “Pfff. Coincidence.” (#70307) não tem
> `reply_to_message_id`. A conversa imediatamente anterior trata da numerologia
> derivada por Diego Schmidt (#70303, incluindo 13224), não de uma pergunta
> isolada sobre o YOUWON original. Não tratá-la como refutação formal desse
> fragmento pelo criador; preservar separadamente os testes negativos abaixo.

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

## Sessão 2026-09-05 (f) — a "segunda via desde o início" e o ninho do coelho

Lead da sessão (e): *"2nd way from start wasnt founded (shared)"* (resumo de membro, 2021-02-13) +
*"Go back to the first puzzle piece… It might have shown you only one door, beware that the rabbits
nest may contain a whole lot more."* (criador, 2020-01-14). Duas frentes, ambas fechadas.

### (1) Outra travessia da matriz — FECHADO (`solver/second_door_traversals.py`)

Se há uma segunda porta na mesma grade, ela é outra ordem de leitura das mesmas 196 células. Espaço
enumerado por inteiro: **20 travessias** (espirais nos 4 cantos × 2 sentidos × 2 eixos iniciais,
linhas/colunas com reverso e bustrofédon, 4 diagonais) × 2 matrizes × inversão de bits × ordem de
bits por byte = **160 leituras**. Exatamente **duas** dão texto 100% imprimível, e as duas são a URL
conhecida `gsmg.io/theseedisplanted` (espiral anti-horária de (0,0), vertical primeiro, MSB) — o
controle positivo. A terceira melhor leitura tem 75% e é lixo. **Não existe segunda travessia
legível.**

### (2) O ninho: medição exata da imagem — estrutura confirmada, sem sinal

`_work/archive/Puzzle_full.png` (1048×1556) medida em sub-pixels de 15 px (**5×5 por célula de
75 px**; confirmado porque `#FEFEFE` ocupa 5.625 px = exatamente uma célula, azul 15 células,
amarelo 9). Controle: das 196 células, **189 são perfeitamente uniformes**; apenas **7 não são** —
e seus índices espirais são **172, 184, 187, 192, 193, 194, 195**. Ou seja, as **4 células que a URL
não usa (192–195) estão entre elas**, e o desenho transborda para 3 células que a URL usa. É
literalmente o ninho. O desenho isolado (15×20 sub-pixels, 137 pretos) é um coelho com duas orelhas,
cabeça e corpo.

Consequência dura: as 4 células do ninho valem **0** na matriz de bits (a cauda é `0000`, não
`0100`) — a leitura `MATRIX_IMG[7][6]=1` continua sendo amostragem do desenho. **As 4 células
não carregam bit; o que há ali é o traço.**

Testado (`solver/rabbit_nest_attack.py`): as contagens de tinta por célula — espiral 172=4, 184=2,
187=9, 192=4, 193=6, 194=3, 195=9, todas em 1..9 como o alfabeto a–i — em 7 ordens (espiral,
row-major, ninho isolado, reversos) como dígitos, letras, caixa alta e z-method; mais o bitmap de
300 bits em leituras linha/coluna/reverso/invertido × MSB e LSB; mais os 100 bits só do ninho. São
50 materiais → 200 formas × 3 blobs × 2 KDF = **1.200 AES**, paddings 6 contra 4,7 esperados,
privkey em toda janela: **0**. E o nulo desmonta a coincidência aparente: para um traço com a
densidade medida (0,211), **P(as 7 contagens caírem todas em 1..9) = 0,82** — não é sinal.

**Conclusão.** O "whole lot more" no ninho do coelho não é dado extraível: nem bit, nem contagem,
nem bitmap. Junto com (1), a primeira peça do puzzle está exaurida — a única mensagem que ela
carrega é a URL. Se a "segunda via" existe, ela não está na imagem inicial.

## Sessão 2026-09-08 — dois exports novos do Telegram, o site revivido e o lead "dbbi = 64/16"

### Insumo

- **Export A** (`ChatExport_2026-09-08/` no repositório, JSON truncado no fim): 2.553 mensagens de
  2025-09-01 a 2025-11-05 — **100 % já estavam no `result.json`**. O que era novo eram os 24 anexos
  (Mind Map do Alex, `puzzle.xlsx` do Человек, `MISC.txt` do k1ng, scripts `*Hush.py` do Septa, o
  PDF da cifra MadHatter, o `-.js` do puzzle-rickroll de 2019, relatórios de bitplane do Jacob).
- **Export B** (`Downloads/Telegram Desktop/ChatExport_2026-09-08/`, íntegro, 114 anexos): 19.711
  mensagens de 2025-09-01 a **2026-09-08**; **4.416 posteriores ao `result.json`** (que parava em
  2026-07-08), com **65 do criador**, agora verbatim em `_work/creator_msgs_2026-07_09.txt` (a sessão
  de 04/09 só as tinha lido por tela). Resumos completos por subagente, com id de mensagem para tudo:
  `_work/tg_2026-07_09_summary.md` (período novo) e `_work/tg_2025-09_11_summary.md`.

### Criador — o que é novo verbatim (Export B)

- 12/07 #66589: *"And IIFF I'm somehow still wrong, which I'm most likely not as I've verified many
  times back then after some sad rushed mistakes, it's all still solvable with a few stable qubits."*
- 12/07 #66592/#66593/#66600: *"I held quite a secret in my head which I seriously wanted to share
  with the planet"*; *"The '5' btc was never the actual prize. That was only a tiny fraction."*;
  *"Some already found it. And understood not to risk it... 🤐"* → #66604 *"Iykyk"*.
- 16/07 #66903 (sobre o laptop): *"it's hidden in a room with a hidden door."*; #66961: *"Give
  yourself yourself and yourself will be given yourself."* (resposta a um pedido de 1 BTC); #66962:
  *"Latetly, I'm working with many NOTES."* — conversacionais, não operacionais.
- 01/09 #70311 (a "como pôde bancar isso?"): *"A. I rushed (t)it. B. Yes, have quite some time for
  stupid stuff."*; #70325: 🤐 para "dbbi/faed devem ser decodificados como os outros segmentos ou são
  só ingrediente?"; #70336 *"Couple hours, and no."*; #70377 *"Same same"* (vs. "two sloppy days").
- Nenhum hint técnico. Nenhuma alegação de blob aberto foi validada por ele (as de Anderson #69905,
  MrNobody #68249–#68259, Andy "DBBI & FAED Research" — que vende "ZION" por 1 ETH — e Kashin caem
  sozinhas; ver o resumo).

### O site voltou — fato duro, verificado byte a byte (`_work/gsmg_live_2026-09/`)

O criador **renovou o domínio** (gnomad #68869, whois) e `gsmg.io` responde de novo desde
**2026-08-15 23:16 UTC** (`Last-Modified` das páginas; a raiz é de 17/08 03:22). O que existe:

| caminho | bytes | conteúdo |
|---|---|---|
| `/` | 35.785 | "shutdown sequence": logo azul se estilhaça → terminal `WARNING: carrier anomaly` / `Trace program: running` → 80 grades aleatórias 14×14 → `finalGrid` + `SYSTEM FAILURE` → chuva Matrix → finale: logo dourado "restored", **"2017 — 2026 / The lights are off. / Nine years of chaos ended. One mystery remains. / Follow the white rabbit →"** (link para `/puzzle`) |
| `/puzzle` | 29.931 | o PNG completo 1048×1556, **sha256 `38125bbd…` = `_work/archive/Puzzle_full.png`** |
| `/theseedisplanted` | 832 | idêntico ao arquivo de jan/2026, incl. `<!-- Nice to see you around! Good luck little bunny hunter ;) -->` |
| `/choiceisanillusion…` | 9.207 | textareas idênticas ao Wayback 2020-11-12; **comentário novo** `<!-- You made it to the next step! Good luck little bunny hunter ;) -->` |
| `/89727c…` (endgame) | 4.536 | `dbbi`, `faed`, blobs e binários **idênticos** ao Wayback 2024-11-23; `<H1>` voltou a `<h1>`; sem comentário |
| `/img/follow_the_white_rabbit.png` | 1.958 | idêntico ao Wayback (`5e8d84b8…`) |
| `/img/logo_GSMG.png` / `_restored.png` | 8.590 / 8.128 | mesmo alfa em 310.000 px; "restored" = recoloração dourada (505 deltas RGB, todos tonais) — é o logo de 2017 |
| `/font/vt323-regular.ttf` | 149.688 | VT323 v2.000 de Peter Hull; vs. cópia do Google só diferem `f_i`, `f_l`, `zero.zero` (ligaduras padrão) e a tabela `name` |
| `/robots.txt` | 1.379 | coelho em ASCII + banner "Follow the white rabbit"; `Disallow: /` |
| `/sitemap.xml`, `/register`, `/help-center`, `/phase1verification` | 9 | **404** — o corpo do 404 é `Hello :-)` (o "sitemap = Hello ;)" do grupo era isso) |

- O `finalGrid` do JavaScript é **a matriz original** (101 uns; espiral anti-horária → `gsmg.io/theseedisplanted`; diff célula a célula contra a matriz do README: **nenhuma** diferença).
- Chuva de glifos = `"0101…01" + "GSMG.IO5BTCPUZZLECHALLENGE"` (o texto da fase 0 já consumido). Constantes: 3400, 1441, 2442, 13950, 5000, 4100 ms.
- O nginx novo dá **404 limpo** (o antigo dava falso-200 em tudo), então sondagem de caminhos passou a valer: **71 caminhos temáticos** (`/salphaseion`, `/yinyang`, `/anotherdoor`, `/hint`, `/2026`, `/thelightsareoff`, `/btcseed`, `/img/door.png`, `/.well-known/`, o endereço-prêmio…) → **todos 404**.
- **Conclusão:** o "new hint on the main page is crazy" (#69031) é a encenação de despedida. Nenhum byte de puzzle mudou; nenhuma página nova existe. O `CLAUDE.md` foi corrigido (o domínio não está mais parqueado).

### Lead novo testado e FECHADO — `dbbi` como digest SHA-256 (PROGRESS.md de X, #70983, 04/09)

Alegação: lendo `dbbi` (91) com `b` e `g` (2 e 7, primos) como prefixos de 2 caracteres, saem **64
tokens com 16 códigos distintos** = forma de um SHA-256 em hex sob substituição.

- **Reproduzido.** Tokens: `d bb i bf bh c c be gb i h a be be i h be gg e ge be bb ge h h e bh h f
  ba bf d h be f f c d bb f c c c gb f be e gg e c be d c i bf bf f gi gb e e e a be`; padrão de
  igualdade `01234556728966286abc61c88b48de3086dd501d5557d6bab5605233df7bbb96`. Entre os 36 pares,
  `b/g` é o **único** com 64 tokens **e** 16 distintos. Nulo próprio (20.000 embaralhamentos que
  preservam contagens): P(b/g dar 64) = 10,1 %, P(b/g dar 64 e 16) = **0,05 %**, P(algum par dar
  64 e 16) = 0,27 %. A estrutura é real e rara.
- **Pré-imagem por padrão de igualdade** (`solver/dbbi_hash_preimage.py`, `dbbi_hash_direct.py`): se
  `dbbi = sha256(X)` sob bijeção token→nibble, a partição dos 64 nibbles de `sha256(X)` tem de ser a
  mesma — teste sem falso-positivo (P ≈ 1e-50) e sem precisar do mapa. Candidatos: 81 curados +
  serializações de `matrixsumlist` (linhas `[6,10,8,7,6,6,5,4,9,9,7,8,7,9]`, colunas
  `[8,10,8,10,8,7,3,6,7,5,9,6,6,8]`, total 101, 5 separadores) + 2.048 BIP39 + **4,19 M pares BIP39**
  + 7.472 termos do vocabulário do criador/plaintexts, singles e pares (**≈55,8 M**). Total ≈ 60 M
  sha256, **0 padrões iguais** (nas duas orientações).
- **Tokens como chave direta**: 7 mapeamentos naturais token→nibble (1ª ocorrência, alfabético,
  frequência, rank a1z26, e reversos) × 2 sentidos → 64 hex como senha AES (SMALL/COSMIC, 2 KDF,
  lower/upper), como privkey de 32 B e como entropia BIP39-24: **0**.
- **Straddling checkerboard** (a MESMA família provada na 3.2.2, escapes 1 e 4): sob `b/g`, `faed`
  dá **451 tokens com exatamente 25 símbolos** — capacidade cheia de um tabuleiro 7+9+9 = alfabeto
  de 25 letras. Hill-climb de substituição (quadgramas, `solver/straddle_bg_attack.py`) com controle
  de **387 caracteres**, não 451 como antes anunciado (correção 2026-09-16): `faed` não sai
  (`OTENDEENOAXTPIDATNAOENN…`). Varredura completa (`solver/straddle_sweep.py`): **todos** os
  conjuntos de escape de 1–3 dígitos (99 para `dbbi`, 37 para `faed`) com nulo casado de 8
  embaralhamentos → `dbbi` −0,0558 vs nulo-máx −0,0546, `faed` −0,0105 vs −0,0103: **dentro do
  nulo, sem sinal**. Se os tokens forem material de chave (não inglês), o teste é cego por
  construção — mas então a bijeção de 16! só sai com a pré-imagem, que não apareceu.

### MadHatter (Kaeding 2020, `2020-301.pdf`, postado por E em 2025-09-03) — FECHADO

Cifra que esconde **dois** textos num só cifrado com símbolos A–I (radices 2,2,2,3 → blocos de 4
com exatamente um símbolo de cada grupo). Tema perfeito (Alice, dualidade, A–I), mas: `dbbi` tem
runs `ccc`/`eee`, `faed` tem 7 runs ≥ 3 (até `ggggg`), e 91 e 570 não são múltiplos de 4. Teste
exaustivo das **7.560 partições (2,2,2,3) × 4 offsets × 2 strings = 60.480 configurações: 0 válidas**.
Denis Golovkin (#48711) tinha razão.

### Textos do site novo como senha — FECHADO

477 candidatos (finale, terminal, comentários, robots, glifos, falas novas do criador, permutações
de E #71180/#71197 `título+enter+endereço`, minikey de Che #50514 `SDnA8pZCnGFRoEbAr4SWUQrF5v5Lpb`)
como senha crua, sha256 (lower/upper) e HASHTHETEXT, nos **3 blobs (SMALL, COSMIC e TAIL32 da fase
3.2, salt `b45a5e3d…`) × 2 KDF**: 9 paddings válidos (esperado 11,2), **0 legíveis**; minikey →
privkey não bate. `solver/live_site_2026_attack.py`.

### Também no material novo (para não reabrir)

- `-.js` (Slack, 2019): puzzle-rickroll anterior do mesmo autor. Camadas: binário → palavras
  invertidas ("HOW DID CAESAR SEND HIS MESSAGES? … 13 IS DEFAULT AND THE NUMBER C IS THE 2ND HINT?")
  → César −3 (`removethecorrecthinttoproceedtothenextstage`, `reverse`) → binário interno invertido
  → `BASE64aHR0cHM6…` → `https://www.youtube.com/watch?v=dQw4w9WgXcQ`. Confirma o estilo "ferramenta
  online, poucas camadas", mas não é parte do puzzle (E #50192).
- k1ng: blocos 75×75/72×72 da imagem e "QR de 25×25 do privkey na grade" — a grade é a URL, já
  medida em sub-pixels na sessão 2026-09-05 (f). Bitplanes do Jacob: lixo (próprio autor).
- Alegações de "solve" do período (Worldmaker `17CY5…`, Stake VIP, Jay Gudic — retratado em #50346,
  jackdevs66 "XOR 7 passes → 1327 B" = a cadeia-miragem com pad 0x01 + MD5): nada validado.
- Ideias baratas ainda não testadas, listadas nos resumos (A007522 vs índices espirais, filter
  bytes/Adam7 do PNG, formato ckey do Core, "salphaseion" deduplicado = 9 letras, LSB `0xf73d92` do
  Denis, leitura por colunas 16763473 do X, 6 salts do Kashin): numerologia sem predição — só rodar
  se alguém escrever a hipótese em prosa com nulo antes.

### Veredito

Prêmio intacto: `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` com **1,25635374 BTC** (126 tx, mempool.space
em 2026-09-08). Os dois exports acrescentam **um** fato duro (o site voltou, byte a byte igual, com
uma despedida) e **um** lead estrutural real (dbbi 64/16), que foi fechado com ~60 M pré-imagens,
mapas diretos e a família straddling inteira sob nulo. O criador reafirmou que a resposta está num
laptop escondido, que "close friends" têm a melhor chance e que os 5 BTC "nunca foram o prêmio de
verdade". A regra de parada (5 famílias negativas com nulo ⇒ esperar insumo novo) continua válida;
o insumo desta vez chegou, foi consumido e não mudou o mapa.

## Sessão 2026-09-08 (b) — abordagens novas: Decentraland, passphrase-XOR como chave, dbbi/faed como senha

Pedido "tente outras abordagens". Três ângulos distintos dos sweeps anteriores, todos com
oráculo duro; artefatos em `_work/decentraland/` e `solver/xor_key_attack.py`.

**1. Decentraland (parcela −41,−17) — fonte primária recuperada; mensagem conhecida confirmada.** Baixada do
catalyst (`peer.decentraland.org/content/entities/scene?pointer=-41,-17`, entity
`QmRK2YoLei9…`, deploy 2020-02-20, owner `0x5D801b2B…`): `scene.json`, `bin/game.js` (164 KB) e
`sounds/puzzlepiece.mp3` (212 KB, 5,2 s). O `game.js` desminificado contém o `game.ts` inteiro (via
sourcemap): **9 cubos** decorativos nas posições `(8,{1,3,4,5,6,6,7,7,7.5},{8,8,8,9,6.75,9.5,7,9,8})`,
um `AudioSource` que toca o mp3 ao clicar e um `TextShape("GSMG.IO \n5 BTC PUZZLE CHALLENGE")`. Sem
hash, sem URL, sem `fetch`. **O mp3 é o hint conhecido**: canal MID = ruído de banda larga; canal
SIDE (L−R) tem a mensagem **pintada no espectrograma na banda 0–300 Hz** = os bytes hex
`48 41 53 48 54 48 45 54 45 58 54` = **HASHTHETEXT** (já no README como solução do áudio). Espectros
por canal em `py_SIDE_*.png`. Essas inspeções não identificaram outra mensagem no sinal.
Isso não constitui uma exclusão geral de esteganografia. A auditoria do contêiner em
2026-09-16, descrita no fim deste arquivo, delimitou separadamente metadados e áreas não alocadas.
- Único subproduto: a assinatura ECDSA do deploy (`0xd0fce2cc…`) e o endereço do deployer
  `0x5D801b2B0B216790A49898b322246282547b546b` (a carteira ETH do criador em 2020) — não é
  acionável para o prêmio BTC (curva/uso diferentes) e perseguir identidade é fora de escopo.

**2. "Seven intertwined passwords" como CHAVE AES crua (não senha) — FECHADO.** O XOR provado
`a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735` (32 B) é exatamente uma chave
AES-256. Todos os sweeps o usaram como *senha* via EVP; aqui como `-K` cru contra SMALL/COSMIC/TAIL32
com 8 IVs (zero, salt‖salt, salt‖zero, ct[:16], sha(key)[:16], key[:16], key[16:], ECB) × K5/K7
(idênticos, o `matrixsumlist` duplicado cancela): **0**. Como privkey cru, sha256(key) e
sha256(hexstr): **0**. Controle (blob cifrado por nós com a mesma chave) abre 100%. O header
`Salted__` do COSMIC já implicava `-pass`, não `-K` — confirmado empiricamente.

**3. `dbbi`/`faed` como o TEXTO que vira senha (não algo a "decodificar") — FECHADO.** O criador deu
🤐 quando perguntaram se são ingrediente ou decodificáveis (#70325). Testado o mais literal: `dbbi`,
`faed`, concatenações, formas a1z26 e decimais (g=0), e a transcrição inteira, cada uma crua +
sha256 hex (lower/upper) + digest, nos 3 blobs × 2 KDF (48 testes): **0 paddings legíveis**;
sha256(dbbi/faed)→privkey: **0**.

**Veredito da sessão (b):** os três ângulos "novos" que restavam no material fresco estão fechados.
O áudio da Decentraland era HASHTHETEXT (conhecido); a chave-XOR não é chave de bloco; dbbi/faed não
são senha literal. Consistente com o resto: o que falta não é uma cifra a quebrar, é a informação que
o criador guarda ("hidden laptop… the actual answer", "close friends have the best chance", "the 5
btc was never the actual prize"). Sem um hint oficial novo que NOMEIE a operação/insumo final,
nenhum sweep adicional tem valor esperado positivo.

## Sessão 2026-09-11 — teste exaustivo condicional de g→0/7

**Resultado: não resolvido.** Nenhuma nova senha nem chave do endereço-prêmio foi
encontrada. O negativo abaixo é uma exclusão de um modelo específico; não prova
que falte informação pública, que o criador precise intervir, ou que todas as
cifras possíveis tenham sido descartadas.

### Fonte e controles

A página final foi baixada novamente por HTTPS: 4.536 bytes, SHA256
`a83d3de7810f26b19b4965339b76d403e44f6b6877e5d7de2555480ca1779d77`,
idêntica à cópia local de 08/09. Fontes extraídas: `dbbi` 91 símbolos,
`faed` 570; ciphertexts SMALL/TAIL32 com 80 bytes cada e COSMIC com 1.328.
O self-test de `gsmg_common.py` passou. A fase 3.2 foi decifrada novamente com
`SHA256(jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple)`:
EVP-SHA256 recupera o início publicado e padding válido; EVP-MD5 não.
Isso confirma o controle conhecido, sem estabelecer o KDF dos blobs não abertos.

### Hipótese → algoritmo → resultado

**Hipótese explícita:** cada `g` representa, independentemente, 0 ou 7;
os demais símbolos mantêm `a=1,…,i=9`. A sequência decimal inteira é convertida
em bytes big-endian mínimos pelo método decimal→hex da própria página.
Os testes anteriores escolheram máscaras; este teste cobre todas as escolhas
sob duas restrições de saída: (1) ASCII imprimível mais TAB/LF/CR;
(2) qualquer byte de 7 bits, inclusive todos os caracteres de controle.

O algoritmo usa inteiros exatos. Em cada ramo, os `g` ainda indefinidos delimitam
um intervalo mínimo/máximo. Calcula-se o menor inteiro desse intervalo cujos
bytes pertencem ao alfabeto permitido. Se ele ultrapassa o máximo, nenhum
descendente pode servir, e o ramo inteiro é descartado. Não há amostragem nem
heurística de inglês. O limite de nós não foi atingido em nenhum caso.

Leituras examinadas: `dbbi`, `dbbi[4:]`, `faed`, `faed[4:]`, as duas metades de
285 símbolos, os símbolos pares e os ímpares de `faed`, cada uma também com
a ordem de símbolos invertida: **16 leituras × 2 restrições, zero candidatos**.
Os cortes e reversos são hipóteses auxiliares, não operações confirmadas do puzzle.

Uma prova curta explica o caso mais importante. Para `faed` inteiro, todas as
`2^107` escolhas estão entre números cujos bytes começam por
`1bd4b0e6ea00079f…` e `1bd5951d3c34f95f…`. Portanto, o segundo byte é sempre
`d4` ou `d5`: jamais ASCII de 7 bits. Em `dbbi`, os limites começam por
`21380d6646a1dd3f…` e `21380d6646de5143…`; o sexto byte está sempre entre
`a1` e `de`, também fora de ASCII. Isso independe da máscara de primos, cores
ou matriz que se escolha para decidir quais `g` zerar.

**Validação:** comparação com enumeração completa de cinco padrões pequenos nas
duas restrições; testes independentes do sucessor de inteiros; recuperação de
uma mensagem-controle com **59 posições ambíguas** entre `2^59` escolhas
(o controle também admite duas variantes ASCII no final, distinguíveis pelo
texto conhecido). Uma implementação independente enumerou as 1.024 escolhas
de `dbbi` e confirmou zero saídas de 7 bits.

Reprodução, sem dependências externas:

```powershell
node solver/zero_decimal_constraints.cjs
```

Código: [`solver/zero_decimal_constraints.cjs`](solver/zero_decimal_constraints.cjs).
Relatórios locais: `_work/session_2026-09-11/zero_decimal_constraints.json` e
`independent_checks.json`. **Limites:** não cobre UTF-8 com bytes altos, material
binário, cabeçalhos removidos após a conversão, outros mapas símbolo→dígito,
outras transposições, nem conversão em blocos de outros tamanhos. Não é uma
refutação geral da pista de “zerar caracteres”. Nenhum candidato passou a ser
testado em AES porque não houve saída que atendesse às restrições declaradas.

### Atualização pública

A discussão pública foi conferida até a mensagem de 11/09 às 01:43 UTC.
Na [issue #99](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/99#issuecomment-5628153255),
um participante voltou a alegar solução, mas ainda prometia apresentar uma
assinatura; a alegação não veio acompanhada de prova verificável nessa consulta.
Ela não altera o estado local. Tampouco se pode concluir, só pela ausência de
prova pública, que ninguém possua a solução em privado.

## Sessão 2026-09-11 — receita original de X: azul, primos e hexadecimal

Após recuperar `dbbi_sum_faed.py` (#63518, X, 22/05/2026), foram testadas
consequências novas da leitura comunitária `SEND THE BLUE TO SET HEX`.
**Nenhuma abertura validada de SMALL, TAIL32 ou COSMIC.**

1. As posições azuis por linhas/base 1 viram
   `061119242f3a5863767e81a3aab9c1` em hex. Deduplicando por primeira
   ocorrência e acrescentando o único dígito ausente, `d`, obtém-se
   `061924f3a587ebcd`. Usar esse alfabeto nos 64 tokens/16 tipos da leitura
   `b/g` de `dbbi`, com 144 variantes declaradas: 864 senhas, negativo.
2. Os primos azuis `17,47,163,193`, reduzidos por `(p-1)%9+1` como no
   script de X, dão **`8,2,1,4`**: quatro pesos binários. As somas de
   subconjuntos fornecem o alfabeto `082a193b4c6e5d7f`. Todas as 24
   ordens dos pesos × três ordens de tipos × dois sentidos dos tokens:
   outras 864 senhas, negativo. A igualdade é real; sua intenção não foi
   confirmada. O `163` por linhas é diferente do `163` espiral do pixel
   `FEFEFE`.
3. As somas, os XORs brutos e seus restos/quocientes antes da conversão
   em letras de X geraram 17 listas, 81 materiais e 162 senhas: negativo.
4. Os 288 hashes mapeados também foram inseridos na hipótese
   `SHA256(dbbi + matriz + faed + últimas_palavras)`: 3.456 senhas,
   negativo. Só cobre matriz total/linhas/colunas, `faed` literal ou
   `a=1..i=9`, e `to` ou a oração iniciada por `reinserting` antes de
   `SELECT`; essas interpretações não estão resolvidas.

**Total:** 5.346 senhas distintas, 32.076 tentativas nos três blobs
originais com EVP-SHA256/MD5, 129 paddings válidos, zero correspondências
com a chave alvo ou sua negação. O máximo de ASCII foi 50,63%; nenhum
dos formatos binários examinados validou as saídas. Os dois falsos
marcadores gzip encontrados falharam na descompressão.

Controles incluem a fase 3.2 original, 12 mensagens AES binárias e a
chave pública conhecida do escalar 1. A conferência cruzada reproduziu
todas as tentativas, positivas e negativas, e os plaintexts completos.
Padding continua sendo apenas triagem. Estes resultados não refutam
toda a receita de X, nem as pistas de cores/primos.

Código: [`blue_hex_constraints.cjs`](solver/blue_hex_constraints.cjs),
com opção `--prime-bits`, e
[`verify_blue_hex.cjs`](solver/verify_blue_hex.cjs).
Fórmulas, candidatos, pré-imagens e limites no
[relatório](_work/blue_hex_2026-09-11/RELATORIO.md).

A prioridade permanece **SalPhaseIon → SMALL**. Para avançar este ramo,
falta deduzir das pistas o mapa dos tokens e o papel de `faed`; ampliar
ordens de substituição sem essa ligação repetiria a mesma incerteza.

## Sessão 2026-09-11 — mapa comum, ASCII 127 e bases primas

**Sem abertura validada.** A fala sobre ASCII 127 foi localizada no export:
Jrk Bgrt, #32613, 29/11/2024, respondendo à pergunta de ArchOptic (#32600)
sobre qual personagem imaginar. X relacionou a fala a DEL na #32615, mas
já registrara a mesma interpretação na #25419, em 06/05/2024. A origem
da frase está confirmada; ela não especifica uma base numérica ou quais
caracteres apagar/zerar. Contexto preservado no relatório abaixo.

Os 36 pares de prefixos foram examinados na leitura gulosa original.
Apenas `b/g` fornece 64 tokens/16 tipos em DBBI; os mesmos prefixos dão
451 tokens/25 tipos em FAED. Isso exclui os dois campos como hexadecimal
sob **uma única substituição bijetiva compartilhada**, sem excluir
alfabetos ou funções diferentes para cada campo.

Outra hipótese usou o inteiro decimal completo com `a=1..i=9`, permitindo
cada `g` como 0 ou 7, convertido para dígitos em bases primas e depois
ASCII direto. Foram examinados todos os 55 primos até 257, aceitando
somente 32–126, TAB, LF e CR. As 55 bases de DBBI e 54 de FAED foram
excluídas integralmente nesse modelo. **FAED/base127 continua parcial**:
3.932.596 nós acumulados, ponto de retomada salvo, 177 candidatos ASCII
de 271 caracteres. ASCII foi imposto como restrição, não descoberto
como evidência de mensagem intencional.

Esses 177 candidatos geraram 1.416 senhas distintas e 8.496 tentativas
AES nos três blobs com EVP-SHA256/MD5. Houve 28 paddings válidos, nenhuma
abertura validada e zero correspondências em 206.556 testes distintos
de escalares contra o alvo ou sua negação. Um segundo verificador
reproduziu todas as tentativas AES, inclusive falhas e plaintexts completos.

Também foram excluídas todas as 1.024 máscaras de remoção/manutenção de
`g` em DBBI nas 55 bases primas e na base 256; elas representam 576
inteiros distintos. Doze máscaras determinísticas para FAED/base127,
derivadas de primos ou bits da matriz, tampouco geraram ASCII completo.
Esses resultados não excluem dados binários nem transformações diferentes.

O [relatório desta sessão](_work/shared_numeric_2026-09-11/RELATORIO.md)
reúne a fonte primária, os limites de cada exclusão, a triagem de fatores,
os candidatos e os controles. Código: [`prime_radix_constraints.cjs`](solver/prime_radix_constraints.cjs)
com `--resume` para continuar a busca parcial, e
[`verify_prime_radix.cjs`](solver/verify_prime_radix.cjs) para conferir o
conjunto já testado. Nenhum processo ficou executando em segundo plano.

## Sessão 2026-09-11 — execução do plano: dependências da receita de X

**Nenhuma abertura validada.** Foram executados os controles previstos no
[plano](docs/notes/PLANO_PROXIMA_ETAPA.md): 5.288 alterações unitárias de símbolos e
135 trocas entre uma célula azul e uma amarela. As 602.832 previsões de
posição de saída concordaram com o recálculo; as funções originais de X
confirmaram todas as alterações e trocas.

Os fragmentos `SENDTHE`, `BLUE` e `TOSETHEX` dependem somente das linhas
10–19 de FAED: 420 das 570 posições não entram nessas palavras. Das
alterações unitárias, 48 em DBBI e 3.361 em FAED preservam os fragmentos;
oito trocas de cores também os preservam. As três saídas completas são
um critério diferente: nenhuma troca de cores as preserva, enquanto três
alterações unitárias em FAED ficam escondidas pela transformação.

Foi construída uma colisão que modifica quatro posições de DBBI e 442 de
FAED, conservando as duas chaves, as duas listas de somas e todas as saídas.
O posto das restrições lineares de DBBI é 22 para 91 pesos quando ambas
as chaves são consideradas. Esses resultados medem a perda de informação
das somas; **não provam que a receita seja falsa**.

Três modelos delimitados foram implementados: OR dos valores zerados
`1,2,4,8` como dígito hex; ocupação das quatro colunas `2,6,13,14` como
quatro bits; e aplicação simultânea das duas zeragens de X. Os 11 materiais
foram testados via SHA256, isoladamente ou com as somas de DBBI e duas
extrações documentadas das últimas palavras. **55 senhas, 330 testes AES,
um padding válido e zero correspondências em 7.769 testes de escalares.**
A execução independente reproduziu os candidatos, todos os testes AES,
o plaintext completo e as verificações de chave.

O roteiro de 27/10/2001 foi consultado nas páginas digitalizadas: a fala
sobre Hope ocorre depois de Neo começar a ir à porta esquerda. Isso limita
sua interpretação como fala anterior à escolha nessa versão, sem excluir
outros papéis. As quebras de linha do README não foram usadas como pista.

O [relatório da execução](_work/recipe_audit_2026-09-11/RELATORIO.md) reúne
as fontes, as dependências, os modelos e seus limites. Código:
[`recipe_dependency_audit.cjs`](solver/recipe_dependency_audit.cjs) e
[`recipe_consequences.cjs`](solver/recipe_consequences.cjs). SMALL permanece
o alvo principal; novas variações de alfabetos de X ficam rebaixadas até
surgir uma consequência independente. FAED/base127 não foi retomado.

## Sessão 2026-09-11 — pista imprevista, somas e fatores primos

**Nenhuma decifração nova.** A resposta #6509, de 14/03/2021, aponta para
uma dica anterior sem identificá-la. O contexto recuperado contém dois
antecedentes plausíveis: primos (#5966/#5969, 01/03) e `Infrared` (#6250,
05/03). As propostas específicas de 2, 3, 5, 7, XOR e soma vieram de
participantes. Isso não as torna instruções do criador.

Foi invertido um modelo direto: um inteiro fixo por cor, células restantes
com os bits originais/invertidos/zero, somas de 14 linhas ou colunas e
concatenação decimal mínima, com 0 e 7 codificados por `g`. Os 24 casos
foram excluídos para **todos os inteiros maiores ou iguais a 2**. Somas
repetidas exigem trechos repetidos; o maior trecho repetido tem comprimento
4 em DBBI e 5 em FAED. Isso limita os valores e o comprimento possível da
saída, que fica abaixo de 91/570. Não é uma busca com teto de primos.

Mais 90 casos foram concluídos: valores posicionais binários para DBBI,
28 somas de linhas e colunas, e os grupos da espiral original. Nenhum
reproduziu um campo completo. O teste adicional de `N*p` e `N/p`, para
os 44 primos até 196, concluiu 176 casos sem saída inteiramente de sete
bits. Limites sobre divisão, produto, soma, diferença e XOR de FAED com
DBBI também forçam bytes maiores que 127, para todas as máscaras `g→0/7`.

Os programas passaram por controles plantados e enumeração limitada; uma
implementação independente reconstruiu os perfis, conferiu os limites e
as buscas. Essas exclusões não abrangem o uso das somas como chave,
fatores primos fora da faixa declarada ou saídas binárias.

[Relatório com fontes, escopos e reprodução](_work/matrix_hint_2026-09-11/RELATORIO.md).
Código: [`color_sum_constraints.cjs`](solver/color_sum_constraints.cjs),
[`color_sum_extended.cjs`](solver/color_sum_extended.cjs) e
[`prime_scale_constraints.cjs`](solver/prime_scale_constraints.cjs).
Não foram geradas novas senhas AES nesta rodada. A transformação pretendida
de `matrixsumlist` permanece desconhecida; SMALL continua a prioridade.

## Sessão 2026-09-11 — DBBI/FAED como dados compactados

**Implementado e executado; nenhuma saída válida recuperada.** O modelo
interpreta o campo original inteiro como decimal, com cada `g` podendo
ser 0 ou 7, e converte o número em bytes mínimos big-endian. A saída da
descompactação pode ser binária; não existe filtro ASCII nesta rodada.

Os cabeçalhos zlib, gzip, ZIP, bzip2, XZ e 7z são incompatíveis com o
primeiro byte fixo de DBBI (`21`) e de FAED (`1B`): 12 exclusões completas.
DEFLATE sem cabeçalho e sem dicionário também é impossível: DBBI contém
comprimento/complemento incompatíveis; FAED começa tentando copiar bytes
anteriores inexistentes. Quatro prefixos cobrem todas as `2^107` máscaras
de FAED. Não se enumeraram fisicamente todos esses arquivos.

Como hipótese adicional, DBBI poderia servir de dicionário. Sua conversão
decimal mede sempre 38 bytes. FAED continua inválido com qualquer conteúdo
de dicionário até esse tamanho; sete ramos cobrem todas as máscaras.
Dicionários de 91 e 32.768 bytes receberam sondagens de 256 nós cada,
ambas **incompletas**. Seus estados pendentes foram preservados.

O solucionador recuperou os controles de blocos armazenados, Huffman fixo
e dinâmico, e rejeitou truncamentos, bytes excedentes e checksums alterados.
Um segundo programa lê diretamente os bits dos blocos armazenados/fixos,
confere os limites decimais e a cobertura sem sobreposição. Ele confirmou
12 certificados dos modelos completos e os ramos eliminados das sondagens
parciais, além de enumerar as 1.024 máscaras de DBBI separadamente.

Código: [`compressed_payload_constraints.cjs`](solver/compressed_payload_constraints.cjs)
e [`verify_compressed_payload.cjs`](solver/verify_compressed_payload.cjs).
[Relatório, resultados e reprodução](_work/compressed_payload_2026-09-11/RELATORIO.md).
Não houve material novo para derivar senhas AES. A exclusão não abrange
todos os algoritmos de compressão, dicionários maiores, outros mapas/bases
nem bytes removidos ou reordenados.

## Sessão 2026-09-15 — qual símbolo pode ser zerado?

**Não resolvido.** A pista #8000 não identifica os caracteres a zerar. Foi
generalizado o teste anterior `g→0/7`: cada um dos nove símbolos `a..i`,
isoladamente, pode valer zero ou seu dígito original em cada ocorrência.
Os demais símbolos mantêm `a=1..i=9`. DBBI/FAED completos, originais e
invertidos, são convertidos de decimal para bytes, exigindo todos menores
que 128, inclusive controles.

Os **36 casos foram excluídos integralmente**: 144 nós de busca e 90
certificados de intervalos, sem candidatos ou ramos pendentes. Os quatro
casos com `g` reproduzem a conclusão anterior. Zeros iniciais estão incluídos;
inverter apenas os bytes não modifica a exclusão de texto de sete bits.

Controle: 54 comparações exaustivas em entradas pequenas, 27 recuperações
de mensagens plantadas e contabilização de busca interrompida. Um segundo
programa, que não importa o buscador, conta os inteiros admissíveis em cada
intervalo e confirma os limites, a ausência de sobreposição e a cobertura
total. Passaram os 90 certificados, 65.536 controles pequenos e 600 controles
de mudança de comprimento.

Não surgiram senhas para testar em AES. A exclusão não abrange múltiplos
símbolos ambíguos simultâneos, outras bases/mapas, listas, remoções, inserções
ou camadas adicionais. FAED/base127 continua com o estado parcial anterior.

Código: [`zero_symbol_constraints.cjs`](solver/zero_symbol_constraints.cjs)
e [`verify_zero_symbol.cjs`](solver/verify_zero_symbol.cjs).
[Relatório, limites e reprodução](_work/zero_symbol_2026-09-15/RELATORIO.md).

## Sessão 2026-09-15 — continuação: listas, chaves periódicas e nove símbolos

**Sem senha final ou decifração final validada.** A investigação acrescentou
cinco famílias explícitas, preservando as entradas verbatim de DBBI/FAED e
os três blobs originais. Os números abaixo são os modelos efetivamente
executados, não uma alegação de esgotar todas as interpretações do puzzle.

| Família | Espaço concluído | Resultado |
|---|---:|---|
| Listas da matriz, aritmética decimal por dígito | 2.012 chaves; 24.144 casos | Zero saídas inteiras em bytes de sete bits |
| Listas/cores, aritmética decimal com transportes | 3.326 chaves; 39.912 casos | Zero saídas; 1.600 pré-imagens adicionais testadas em AES sem validação |
| Todas as chaves decimais de comprimentos 1–6 em FAED | 4.444.440 combinações de chave/direção/operação | Zero saídas e zero casos pendentes |
| Morbit/Pollux diretos, todas as substituições | 1.530.252 decodificações | Zero Morbit; 12 Pollux sem consequência validada |
| Mapas fixos para 0/1/remoção, ASCII/Bacon | 629.856 decodificações | 23.350 saídas distintas; nenhuma abertura AES validada |

As famílias decimais cobrem todas as escolhas independentes de `g=0/7`;
exigem conversão do inteiro decimal para bytes mínimos big-endian menores
que 128. As listas incluem cores, somas, posições e pesos primos declarados
nos arquivos `spec.json`. Espectro e código de resistores são hipóteses de
numeração das cores, não instruções confirmadas pelo criador.

Os candidatos produzidos pelas três famílias com senhas resultaram em
**567.084 tentativas AES**, usando SHA256 e MD5 no EVP_BytesToKey, e 2.229
aceitações de padding. Nenhuma apresentou conteúdo coerente que confirmasse
uma senha. As senhas foram deduplicadas dentro de cada família; não se alega
deduplicação global. Não foram enviados candidatos a serviços externos.

Um verificador de intervalos independente confirmou os 64.056 casos das
listas, 91.519 certificados de exclusão e as 9.600 tentativas AES associadas.
A busca de chaves curtas passou 240 comparações com outro buscador e recuperou
12 mensagens plantadas; não recebeu uma segunda enumeração integral.
Morbit/Pollux reproduziram os exemplos publicados pela ACA, além de controles
próprios. A fase 3.2 conhecida é o controle positivo de AES.

Outro verificador reenumerou todos os mapas Morse/binários e confirmou as
557.484 tentativas AES restantes, inclusive os bytes das 2.198 saídas com
padding aceito. Foram comparados hashes candidatos, pré-imagens de 32 bytes
e todas as janelas consecutivas de 32 bytes das saídas com a coordenada x da
chave pública do prêmio: **1.074.236 verificações, zero correspondências**,
incluindo a possibilidade de chave negada. A comparação não abrange toda
derivação possível nem afirma que os escalares verificados sejam distintos.
[Conferência independente](_work/binary_partition_2026-09-15/independent_verification.json).

[Relatório completo, scripts, fontes e reprodução](_work/decimal_keystream_2026-09-15/RELATORIO.md).
A fronteira permanece a transformação operacional de `matrixsumlist` e a
abertura autêntica de SMALL/TAIL32/COSMIC. Não há chave privada recuperada.

## Sessão 2026-09-15 — substituição decimal desconhecida e segmentação

**Objetivo final ainda não alcançado.** A skill `find-skills` solicitada foi
usada para pesquisar criptanálise. `classical-cipher-analysis` já estava
instalada; seu passo de identificar a representação motivou o teste de uma
premissa que as rodadas anteriores mantinham fixa: `a=1..i=9`.

Foram esgotadas todas as `9!` bijeções entre os símbolos e os dígitos 1–9,
com qualquer um dos nove símbolos também podendo valer zero independentemente
em cada ocorrência. Campos inteiros, originais e invertidos, convertidos de
decimal para bytes mínimos big-endian menores que 128: **13.063.680 casos
completos, 42.443.886 nós, sem casos pendentes**.

FAED não tem candidatos. DBBI tem 183, todos com `b` ambíguo, nenhum totalmente
imprimível mesmo admitindo TAB/LF/CR. Foram testados como 366 senhas diretas
ou SHA256-hex nos três blobs e dois KDFs: 2.196 tentativas, seis paddings,
zero decifrações validadas. Hashes e janelas binárias forneceram 7.509
comparações com a pubkey, sem acerto. Um verificador com outro gerador de
permutações e contagem aritmética de intervalos confirmou todos os casos e
os 183 candidatos; outro caminho CBC/PKCS#7 confirmou os testes AES.

Separadamente, conservando `a=1..i=9`, todas as larguras possíveis de blocos
decimais e cada símbolo como possível zero foram examinados: **11.898
modelos excluídos**, com 15.464 certificados conferidos por contagem.
A leitura de códigos ASCII decimais de tamanho variável também não tem
segmentação válida em nenhum dos 36 casos. Esses testes não combinam
substituição desconhecida e segmentação simultaneamente.

Uma hipótese adicional, numeração de Gödel de listas estritamente positivas,
falha por paridade para os campos originais com o mapa conhecido e `g=0/7`:
terminam em 5 e 3, enquanto a codificação usual contém uma potência positiva
de 2. Não se excluem as variantes de lista/base/ordem não declaradas.

[Relatório, controles, código e limites](_work/substituted_decimal_2026-09-15/RELATORIO.md).
Não retomar simplesmente outras permutações ou outro símbolo para zero nessa
mesma representação. É necessária uma hipótese que explique a operação
adicional; a senha final continua pendente.

## Sessão 2026-09-15 — sementes numéricas e ordem de colunas

**Nenhuma senha final recuperada.** Foram concluídos e conferidos dois modelos
adicionais do papel de `matrixsumlist`, mantendo como teste a representação do
resultado decimal inteiro em bytes mínimos big-endian menores que 128.

- **Chaves que crescem:** 43 listas produziram 156 sementes; as 1.024 máscaras
  `g=0/7` de DBBI, diretas/invertidas, forneceram outras 2.048 para FAED.
  Adição em cadeia com/sem semente inicial, realimentação pelo plaintext ou
  ciphertext, três operações módulo 10, campos completos diretos/invertidos:
  **56.640 casos**, 105.178 nós, 80.909 certificados, zero candidatos.
- **Transposição:** as 43 listas e três rótulos decodificados produziram 168
  chaves. Colunar incompleta com dois desempates e Myszkowski, ordens
  ascendentes/descendentes, permutação/inversa e reversões de entrada/saída
  deram 6.240 permutações distintas de DBBI e 6.184 de FAED. Qualquer um dos
  nove símbolos pode, isoladamente, ser também zero em cada ocorrência:
  **111.816 casos**, 357.956 nós, 234.886 certificados, zero candidatos.

Não houve casos parciais. Dois verificadores sem importar os buscadores
confirmaram todos os certificados por contagem aritmética, a completude dos
modelos e, na segunda família, todas as permutações por outro algoritmo.
Passaram controles com exemplos publicados pela ACA e 162 recuperações de
mensagens plantadas. A fase 3.2 conhecida foi o controle positivo de AES.

Não houve novos candidatos nem tentativas AES. As exclusões não cobrem chaves
arbitrárias, todas as ordens de colunas, transposição dupla, outra base ou
dados binários. O uso desses mecanismos é hipótese nossa, não orientação
confirmada pelo criador. Não retomar as mesmas famílias apenas mudando as
posições zeradas, já cobertas integralmente no modelo.

[Relatório, fontes, controles, programas e reprodução](_work/feedback_decimal_2026-09-15/RELATORIO.md).

## Sessão 2026-09-15 — XOR repetido após a conversão decimal

**Nenhuma senha nem chave do prêmio recuperada.** Hipótese: campo inteiro
como decimal com `a=1..i=9` e um único símbolo opcionalmente zero, convertido
em bytes e decifrado por XOR repetido para obter sete bits por byte.

Para plaintext de sete bits, os bits altos do ciphertext precisam repetir
o padrão dos bits altos da chave. Isso permite excluir todas as chaves de
um período, sem enumerar palavras ou bytes de chave. Campos originais e com
a ordem dos símbolos invertida, períodos 1–32:

- FAED: todos os nove símbolos isoladamente zeráveis, **576 casos excluídos**.
- DBBI: `g=0/7`, **62 casos excluídos** nos períodos 1–31. No período 32,
  32 máscaras diretas e 16 invertidas passam somente a condição de bits altos.
- Todos os 640 casos terminaram, com 2.361.112 nós e 1.180.828 certificados.
  Contagem aritmética independente confirmou todos os intervalos; enumeração
  integral das máscaras de DBBI confirmou as 48 compatibilidades.

Nenhum dos 48 casos de DBBI permite plaintext só com minúsculas, dígitos e
whitespace. Letras maiúsculas/minúsculas são compatíveis, mas não revelam
uma chave. Foram testadas 14.042 chaves SHA256 cruas de pré-imagens antigas
derivadas de matrizes: nenhum dos 674.016 pares com essas máscaras gerou sete
bits completos. Outra implementação conferiu os corpos XOR diretamente.

DBBI foi então examinado com **qualquer um dos nove símbolos zerável** e as
mesmas chaves: **252.756 casos completos**, 588.584 nós, 420.668 certificados.
Só dois corpos de sete bits, ambos com `b=0/2`, nenhum imprimível. A chave
vem da pré-imagem `OCSILOTAKOUTEZ`, uma extração histórica dependente das
quebras editoriais já desautenticadas. Isso não valida uma mensagem.
Quatro senhas derivadas dos corpos deram **24 testes AES, zero padding**;
dez escalares candidatos não correspondem à pubkey. Um verificador separado
confirmou toda a cobertura, candidatos, AES e comparação de escalares.

Os dois testes com chaves fixas se sobrepõem no caso `g`; suas contagens não
representam famílias disjuntas. Não foram excluídos XOR geral de período
maior, outros alfabetos/bases, dados binários ou vários símbolos zeráveis.
Para DBBI com símbolo diferente de `g`, a exclusão se limita às chaves fixadas.

[Relatório, algoritmos, fontes, controles e reprodução](_work/xor_period_2026-09-15/RELATORIO.md).

## Sessão 2026-09-15 — potências inteiras

**Nenhuma senha nem chave do prêmio recuperada.** Hipótese: DBBI/FAED como
decimal inteiro `N=P^e`, onde `e>=2` é inteiro e os bytes mínimos big-endian
de `P` são todos menores que 128. A relação com primos como expoentes é
conjectura; o teste inclui todos os expoentes inteiros possíveis.

Com qualquer um dos nove símbolos isoladamente zerável e ambas as ordens
dos símbolos, o limite aritmético dos expoentes é 301 em DBBI e 1.892 em
FAED. **39.438 casos completos, 42.960 nós, 41.199 certificados, zero
candidatos e zero tentativas AES.** Um verificador sem importar o buscador
usou raízes por busca binária e contagem de inteiros de sete bits, confirmando
todos os intervalos e a cobertura das máscaras. Passaram controles de raízes,
mensagens plantadas e enumeração direta.

Não exclui exponenciação modular/RSA, blocos, transposição ou outra codificação.
[Relatório e reprodução](_work/integer_power_2026-09-15/RELATORIO.md).

## Sessão 2026-09-15/16 — checkerboard com zeros ambíguos e viés do classificador

**Nenhuma senha final ou chave do prêmio recuperada.** A leitura de
checkerboard usada na fase 3.2 foi aplicada a DBBI/FAED mantendo as escolhas
de zero dentro do parser. Foram examinados 38.880 modelos diretos (12
alfabetos, todos os pares ordenados de prefixos, qualquer alias, ambas as
direções/campos) e 16.848 modelos com 156 chaves decimais das listas da matriz,
três operações módulo 10 e a tabela conhecida da fase 3.2. Alinhamento fixo;
não é a cifra VIC completa com transposições.

O classificador histórico treinado no Telegram **inclui as próprias cifras**:
65 mensagens com fragmento longo de DBBI e 25 com início de FAED passam seu
filtro. Reconstruir o treino reproduziu todos os valores do cache. A mesma
busca foi então repetida com estatísticas gerais de inglês independentes.
Não somar os dois perfis como famílias criptográficas distintas.

Por perfil: **55.728 casos, 47.080 leituras completas de nota máxima e 8.648
sem leitura completa**. Programação dinâmica cobre todas as escolhas de zero
para maximizar a média de quadgramas. Uma implementação separada confirmou
os caminhos, notas, limites ótimos e impossibilidades de leitura.
Maximizar a nota não garante a frase verdadeira: o perfil geral recuperou
exatamente só 25 das 72 mensagens plantadas. Os outros caminhos não foram
todos enviados aos oráculos. Nenhuma leitura dos campos reais é coerente.

A união dos dois perfis produziu **946.400 senhas distintas, 5.678.400 testes
AES e 473.200 escalares**, sem correspondência com a pubkey ou decifração
validada. Os 22.153 paddings isolados têm no máximo 59,50% de bytes imprimíveis/
whitespace. Todos esses corpos foram reproduzidos integralmente com
PyCryptodome; essa segunda conferência não repetiu as rejeições nem os pontos
da curva. O controle positivo AES foi a fase 3.2 conhecida.

Esta rodada não cobre alfabetos arbitrários, todas as fases do VIC, todos os
deslocamentos das chaves, descarte de padding da cifra clássica ou todas as
leituras de nota menor. Usar o novo modelo geral em futuras classificações;
preservar o antigo para reproduzir resultados históricos.

[Relatório, fontes, controles e reprodução](_work/ambiguous_checkerboard_2026-09-15/RELATORIO.md).

## Sessão 2026-09-16 — alfabeto desconhecido junto com os zeros

**Nenhuma senha final ou chave do prêmio recuperada.** Foi implementada
busca conjunta do alfabeto A–Z com duas posições reservadas e das escolhas
independentes `g=0/7` em FAED. Usa o modelo geral de inglês, todos os 45
pares não ordenados de prefixos e ambas as direções. Permutar as linhas
absorve a troca de ordem dos prefixos. Não inclui outras chaves/transposições.

O protótipo que ignorava pontos favorecia apagar letras raras. A campanha
principal exige texto A–Z contínuo. O otimizador de zeros passou 288 modelos
pequenos comparados com enumeração de 816 máscaras. Nos três controles
longos, as distâncias de edição foram 0,72%, 29,50% e 73,86%: **o método não
é confiável para excluir as configurações difíceis de separação ambígua**.

Com oito reinícios de 20.000 iterações por configuração, foram executadas
90 configurações reais e 270 de embaralhamentos de controle. As 47.831.645
avaliações e 1.312.343 otimizações de máscaras são busca heurística, não
enumeração integral dos alfabetos. Melhor nota real: `-5,082816`; melhores
notas dos três embaralhamentos: `-5,061486`, `-5,051942`, `-5,114248`.
Não há separação útil nem mensagem coerente. Outro programa conferiu os
18.449 caminhos salvos, suas notas e a viabilidade das posições reservadas.

Os 4.269 textos reais de melhorias globais/melhores reinícios produziram
17.076 senhas, **102.456 testes AES e 8.538 escalares**. Nenhuma correspondência
com a pubkey e nenhuma decifração validada. Os 412 paddings isolados têm
no máximo 56,97% de bytes imprimíveis/whitespace. PyCryptodome e coincurve
reproduziram todas as decisões AES, incluindo rejeições, e todas as
comparações de pontos. Não foram testados textos dos embaralhamentos como senhas.

Não prolongar esta mesma busca apenas porque ela é incompleta. A operação
entre as pistas e os campos continua ausente; VIC completo e outros
mapeamentos permanecem fora da exclusão.
[Relatório, controles, limites e reprodução](_work/joint_checkerboard_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — leitura decimal, UTF‑8 e dois símbolos zeráveis

**Nenhuma senha encontrada.** Os testes de leitura decimal anteriores
restringiam a saída a sete bits. Esta rodada admite toda a gramática UTF‑8,
inclusive acentos, pontuação Unicode e controles, sem decoder permissivo.
Compara a representação mínima do inteiro em big-endian e little-endian,
para os campos completos nas duas ordens de símbolos. Não é uma busca de
variantes de senha normalizadas nem de texto truncado.

Todas as ocorrências de uma letra escolhida, ou de duas letras escolhidas,
podem independentemente virar zero ou manter seu dígito `a=1..i=9`.
As nove escolhas isoladas e os 36 pares produzem **360 casos completos**,
318.942 nós e 126.243 intervalos excluídos. FAED não admite UTF‑8. As 33.408
sequências UTF‑8 de DBBI contêm controles C0/C1 além de TAB/LF/CR; nenhuma
forma texto comum sem esses controles. Não houve descarte desses bytes.

Um verificador por contagem de sequências de valores Unicode, sem importar
os autômatos do buscador, conferiu cada intervalo e a cobertura das máscaras.
O buscador recuperou 270 controles conhecidos, incluindo texto não ASCII,
e passou 270 comparações com enumeração; ambas as implementações também
foram comparadas com decoders estritos para entradas curtas.

Os bytes completos e seus hashes SHA256 hexadecimais geraram **66.816 senhas,
400.896 decisões AES e 33.408 comparações secp256k1**. Nenhuma decifração
validada nem chave-alvo. Os 1.487 paddings aceitos tiveram no máximo 56,97%
de bytes ASCII imprimíveis/whitespace. PyCryptodome e coincurve reproduziram
todas as decisões, incluindo rejeições e comparação com a negação do alvo.

Essa exclusão é condicionada ao mapa decimal e à zeragem especificados;
não cobre outra cifra, três ou mais letras zeráveis ou outro charset. A falta
de ASCII por si só não explica os resultados anteriores de FAED. Não ampliar
automaticamente a zeragem: o modelo mais flexível multiplicou candidatos de
DBBI sem produzir uma mensagem. A operação anterior continua desconhecida.
[Relatório e reprodução](_work/utf8_decimal_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — números primos das contagens amarelo/azul

**Nenhuma senha final.** A consulta pública não encontrou comentários novos
após o último item de 11/09 já examinado. O fork de Naddiseo, fixado no commit
`81f68e5073a7ad0a002acd2a2db0b6bcfa0570ac`, também deixa DBBI e FAED sem
solução. [Escopo da consulta](_work/public_recheck_2026-09-16/RELATORIO.md).

Testou-se a inferência `9 amarelos → 9º primo = 23`, `15 azuis → 15º primo = 47`,
atribuindo os pesos às células e somando linhas/colunas. Os demais pixels
mantêm seus bits ou viram zero. As quatro listas deram 352 chaves decimais
distintas, sem coincidências com as chaves das 43 listas anteriores.

Adição/subtração/Beaufort digitais e com transporte, todos os alinhamentos
cíclicos, ambas as ordens dos campos e dos bytes e todas as escolhas `g=0/7`
deram **16.896 casos completos, 32.740 certificados e zero saídas UTF‑8**.
Um contador independente verificou cada intervalo e a cobertura das máscaras,
além de reconstruir as cores, primos, listas e chaves.

As representações diretas das listas e composições explícitas com as últimas
palavras foram também conferidas: **500 pré-imagens, 1.000 senhas, 6.000
decisões AES e 500 escalares**, sem abertura validada nem chave-alvo. Os 18
paddings não passaram de 49,37% ASCII/whitespace. PyCryptodome e coincurve
reproduziram todas as decisões, inclusive rejeições e comparações de pontos.

Essas exclusões não eliminam os pesos 23/47 sob outros algoritmos nem a
pista de cores/primos em geral. Não ampliar automaticamente dicionários ou
valores: a operação que falta continua sem identificação.
[Relatório e reprodução](_work/count_prime_matrix_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — substituição de dígitos e códigos ASCII variáveis

**Nenhuma senha final.** A rodada combinou duas escolhas antes examinadas
separadamente: qualquer bijeção `a..i → 1..9` e uma concatenação dos códigos
decimais de TAB/LF/CR/ASCII 32..126, permitindo uma letra também significar
zero por ocorrência. Inclui ambos os campos completos nas duas direções.

Foram decididos **13.063.680 modelos** com cobertura de todas as máscaras
e segmentações. **FAED é incompatível com todos**; DBBI admite 50.808 modelos.
Um decoder aritmético independente, percorrendo as permutações em outra
ordem, conferiu todas as decisões e todas as contagens.

A contagem de DBBI é 1.208.192.544 pares modelo/caminho, não necessariamente
textos distintos. Nenhum caminho contém apenas letras/espaços; todos exigem
pelo menos sete outros caracteres. Somente **3.600 caminhos inteiramente
imprimíveis** existem, e foram todos enumerados. O grande restante, com
TAB/LF/CR, foi contado e não testado integralmente como senha.

As 3.600 sequências imprimíveis geraram **7.200 senhas, 43.200 decisões AES e
3.600 escalares**. Nenhuma abertura validada nem correspondência com a chave
do prêmio. Os 165 paddings tiveram no máximo 53,16% ASCII/whitespace.
PyCryptodome e coincurve reproduziram todas as decisões, incluindo falhas.

Uma codificação comum dos dois campos por esse mecanismo fica excluída
pelo resultado de FAED. Não se afirma exclusão geral de DBBI, de gramáticas
com outros caracteres ou de mais de uma letra zerável. Nenhum classificador
de linguagem foi usado para decidir a impossibilidade de FAED.
[Relatório e reprodução](_work/substituted_codepoints_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — base prima de origem e prefixos em base 127

**Nenhuma senha final.** Foi distinguida a leitura do campo numa base prima
da conversão de um inteiro decimal para essa base. A primeira hipótese foi
conferida para os 51 primos de 11 a 257, ambos os campos e sentidos e todas
as nove letras como possível zero por ocorrência. Os **1.836 casos** foram
inteiramente rejeitados sob a condição ampla de todos os bytes estarem em
0..127, incluindo controles. A prova tem 3.200 nós e 2.518 intervalos; outro
programa reconstruiu e contou os intervalos e conferiu a cobertura completa.
Não surgiram candidatos para AES ou para a chave do prêmio.

Na operação inversa já pesquisada, decimal → base127 com `g=0/7`, DBBI nos
dois sentidos começa obrigatoriamente com controle 1. FAED inverso contém
controles fixos 23/27; FAED original começa necessariamente com `9i` ou
`9j`. Isso exclui a leitura textual direta nas três primeiras situações,
mas mantém aberto FAED original com números/pontuação. Os 177 candidatos e
a busca parcial anterior foram preservados, sem nova enumeração.

Não há exclusão geral de bases primas, outras codificações ou mecanismos
com uma transformação anterior. [Relatório e reprodução](_work/source_prime_radix_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — Nihilist e o tamanho mínimo da chave

**Nenhuma senha final.** A pista `matrixsumlist` foi confrontada com uma
operação ainda não examinada nos scripts consultados: soma das coordenadas
de texto e chave numa grade 5×5, como na Nihilist da ACA. A associação é
hipotética; a cifra não foi identificada como método do criador.

Na forma de dois dígitos, os 285 pares de FAED exigem período de chave de
pelo menos **277 na ordem original ou 275 na inversa**, mesmo permitindo
qualquer bijeção `a..i → 1..9` e qualquer letra adicionalmente zerável por
ocorrência. Todos os períodos 1..285 foram decididos. Outro programa
percorreu todas as 362.880 bijeções por sentido e reproduziu integralmente
as listas de mapas viáveis; as 22 testemunhas dos períodos mínimos foram
recifradas. Elas comprovam viabilidade numérica, não uma mensagem original.

A variante de somas não reduzidas, escritas com dois ou três dígitos e
concatenadas, foi examinada sem sequer exigir repetição da chave:
**13.063.680 modelos, zero segmentações válidas** nos campos completos,
com todos os mapas, letras zeráveis e sentidos. Um parser aritmético
independente confirmou todas as decisões do autômato.

Não houve candidatos de senha nem testes AES nessa rodada. A interpretação
direta com chave curta fica excluída; outras dimensões de grade, mais letras
zeráveis e transformações anteriores permanecem fora desse alcance.
[Relatório, fonte e reprodução](_work/nihilist_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — paridade das distâncias entre vetores

**Nenhuma senha final.** Foi ampliado o teste geométrico de DBBI para
distâncias entre vetores inteiros, usando `91 = C(14,2)`. Nas oito leituras
triangulares declaradas, todas as letras são forçadas a valores pares.
Mesmo ignorando integralmente qualquer uma das nove letras, as outras
oito continuam obrigatoriamente pares. Isso é incompatível com qualquer
bijeção `a..i → 1..9`, que só dispõe de quatro valores pares.

A propriedade vale para Hamming binário, Manhattan e distância euclidiana
ao quadrado entre vetores inteiros, inclusive com pesos inteiros por
coordenada. A liberação de uma letra é mais ampla que escolher quais de
suas ocorrências viram zero. A prova cobre qualquer permutação dos 14
vértices; não cobre permutações arbitrárias das 91 arestas.

Foram gerados **648 certificados para 80 modelos**. O verificador conferiu
as somas de arestas e enumerou independentemente **655.360 atribuições de
paridade** dos vértices. Controles com vetores conhecidos passaram.

Sem letra indeterminada, até uma renomeação injetiva por valores arbitrários
exigiria dimensão de pelo menos 18 para Hamming: são nove distâncias pares
positivas distintas, e não há vértices compatíveis com vetores idênticos.
Isso exclui a matriz binária 14×14 como origem direta dessas distâncias,
sem excluir DBBI como pesos de entrada, produtos internos ou outras cifras.
[Relatório e reprodução](_work/dbbi_distance_parity_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — somas da matriz como pré-imagem do possível hash DBBI

**Nenhuma senha final.** O padrão completo dos 64 tokens/16 tipos de DBBI
foi usado como restrição de SHA256, sem adivinhar sua substituição por hex.
Os 72 parses com dois prefixos, nos dois sentidos, confirmaram somente
`b/g` original nesse formato; as duas ordens dos tokens foram consideradas.

Os pesos azul/amarelo foram todos os pares de `0`, `1` e primos até 196,
mais os pares de divisores primos dos respectivos inteiros RGB. A fatoração
azul contém 9341, acrescentando dois pares à grade finita de pesos. Foram
**2.118 pares e 4.236 matrizes**, mantendo os bits não coloridos ou zerando-os.

Listas de somas por linhas/colunas, suas concatenações, intercalação e total,
em duas direções e representações textuais/binárias declaradas, produziram
**525.468 avaliações SHA256 e 1.050.936 comparações**. Nenhuma correspondência
completa de padrão. As contagens incluem representações eventualmente iguais.

Um verificador independente reconstruiu cada matriz e pré-imagem, calculou
os hashes e comparou padrões por outro mecanismo, reproduzindo integralmente
os 4.236 resumos das avaliações. Não houve candidato para teste AES.
Isso elimina somente essas pré-imagens no modelo DBBI=hash substituído;
não elimina outras funções das listas nem confirma que DBBI seja um hash.
[Relatório e reprodução](_work/dbbi_matrix_hash_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — DBBI como chave colunar de FAED

**Nenhuma senha final.** Foi testada uma composição ausente das campanhas
consultadas: listas derivadas de DBBI ordenam colunas de FAED, e o resultado
é interpretado como inteiro decimal convertido em bytes de sete bits.
Os testes anteriores com essas listas usavam Bifid/checkerboard; o teste
colunar seguido de decimal→bytes usava listas da matriz inicial.

As dez ocorrências de `g` em DBBI receberam todas as escolhas 0/7. Para
cada máscara, a sequência literal, quatro listas das grades 7×13/13×7 e
três listas do triângulo superior 14×14 foram usadas em ambos os sentidos.
As 16.384 construções se reduziram a **5.694 padrões de chave**. Foram
incluídas transposição colunar com dois critérios de empate e Myszkowski,
ordens crescente/decrescente, operação direta/inversa e reversões de FAED.

Isso gerou **250.400 permutações distintas**, sem sobreposição com as do
teste colunar anterior de FAED. Cada uma foi examinada com todas as nove
letras como alias adicional de zero, independentemente por ocorrência:
**2.253.600 casos completos, zero candidatos, zero casos parciais**.
Consequentemente, não houve testes AES nem de escalares nesta rodada.

Um verificador independente regenerou todas as listas e permutações e
conferiu os **4.482.213 certificados de exclusão**, contando os inteiros
com bytes válidos nos intervalos e demonstrando cobertura de todas as
máscaras. Todos os resultados coincidiram, com controles positivos.

O alias `g` em DBBI, o uso das listas como chaves e a representação final
são hipóteses declaradas. O resultado não exclui outros aliases em DBBI,
alfabetos, rotas, dupla transposição ou transformações adicionais.
[Relatório e reprodução](_work/dbbi_columnar_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — todos os pesos inteiros das cores numa chave decimal

**Nenhuma senha final.** A busca foi ampliada de listas com pesos
específicos para uma classe inteira: azul e amarelo recebem quaisquer
inteiros fixos; preto e branco recebem, independentemente, 0 ou 1. As
somas das 14 linhas ou colunas são reduzidas módulo 10 e usadas como
chave periódica de adição, subtração ou Beaufort decimal.

Somente os restos dos valores das cores influenciam essa operação.
Portanto, os cem pares de restos cobrem inclusive **todos os primos,
sem teto numérico**. Essa redução não se aplica a hashes das somas ou
à concatenação de suas representações decimais completas.

As duas ordens e todos os alinhamentos das listas produziram 22.038
chaves e 60.695 operadores distintos. Com ambos os campos, seus dois
sentidos e qualquer uma das nove letras adicionalmente zerável por
ocorrência, foram **2.185.020 casos completos**, nenhum interrompido.

FAED não produziu bytes de sete bits. DBBI produziu 39 candidatos,
todos com controles além de TAB/LF/CR e todos usando `b=0/2`. As duas
ordens de bytes geraram 78 materiais e 156 senhas: **936 decisões AES**,
dois paddings sem estrutura autenticada e **356 escalares**, sem acerto
na chave pública-alvo ou na sua negação.

O verificador reconstruiu todas as matrizes e operadores e conferiu
**4.536.865 certificados**, cobertura das máscaras e todos os candidatos.
PyCryptodome e coincurve reproduziram todas as decisões AES, os dois
corpos completos e todas as comparações de pontos. Os controles passaram.

O resultado limita essa cifra aditiva com a representação declarada;
outras operações de `matrixsumlist` continuam abertas.
[Relatório e reprodução](_work/color_residue_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — transporte decimal nas chaves das cores

**Nenhuma senha final.** As mesmas 22.038 listas de resíduos, cobrindo
todos os pesos inteiros de azul/amarelo e quatro fundos binários, foram
usadas como inteiros periódicos `K` da largura de DBBI ou FAED. Examinaram-se
`C+K`, `C-K` e `K-C`, tanto módulo `10^L` quanto como resultados inteiros
não negativos. Isso cobre transporte entre casas, ausente da rodada anterior.

Foram **4.760.208 casos completos**, com ambos os campos, sentidos e
qualquer uma das nove letras adicionalmente zerável. FAED não teve saída
de sete bits. DBBI teve 55 caminhos, correspondentes a **38 sequências
distintas**, todas com controles não usuais e sem sobreposição com as
39 saídas da rodada sem transporte.

As duas ordens de bytes produziram 76 materiais e 152 senhas: **912
decisões AES**, três paddings sem estrutura autenticada e **342 escalares**,
sem correspondência com a pubkey-alvo ou sua negação. PyCryptodome e
coincurve reproduziram todas essas decisões e todos os corpos/pontos.

O verificador independente reconstruiu as chaves, dividiu intervalos nas
fronteiras aritméticas e conferiu **9.218.926 certificados**, cobertura
completa das máscaras e todos os candidatos. Controles de enumeração,
mensagens plantadas e intervalos com transporte passaram.

O resultado limita as operações com as somas já reduzidas módulo 10;
não abrange concatenar as somas completas nem outras representações.
[Relatório e reprodução](_work/color_carry_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — produtos internos como os 91 pares de DBBI

**Nenhuma senha final.** Foi examinada uma lacuna da análise de distâncias:
DBBI como os produtos internos entre as 14 linhas ou colunas da matriz
inicial, incluindo pesos independentes para azul, amarelo, preto, branco
e a célula quase branca. A codificação admite qualquer bijeção dos nove
dígitos positivos e uma letra adicionalmente zerável por ocorrência.

Para pesos inteiros não negativos, a exigência de produtos no máximo 9
impõe pesos `0..3` às quatro cores repetidas. O quase branco usa `0..9`
quando influencia os produtos e pode ser representado por zero quando
inerte. Essa redução cobre todos os pesos da família: **5.120 casos,
zero histogramas compatíveis**, mesmo permutando arbitrariamente os
91 pares. Os limites possuem testemunhas explícitas na matriz.

Módulo 10, os cinco pesos inteiros se reduzem a cem mil vetores de restos
por orientação. Dos **200.000 casos**, quatro têm frequências compatíveis,
todos nas colunas, com `b` representando zero em 13 de suas 25 ocorrências.
Os quatro vetores e todas as bijeções estão preservados no relatório.

Esses candidatos foram comparados com oito ordens triangulares. Todos
os **128 casos**, equivalentes a 32 grafos com ordem após deduplicação,
falham no conjunto de contagens de cores incidentes em cada vértice.
Esse certificado exclui qualquer permutação dos 14 vértices. Não exclui
uma permutação arbitrária e independente das 91 arestas; frequências
compatíveis sozinhas não constituem uma decifração.

Verificadores independentes reconstruíram todos os produtos por
coordenadas, regeneraram as bijeções e validaram cada certificado.
Controles positivos e dos limites passaram. Nenhum candidato a texto,
teste AES ou teste de chave privada foi produzido nesta rodada.
[Relatório e reprodução](_work/dbbi_gram_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — campos concatenados e primos espectrais

**Nenhuma senha final.** Foram examinadas duas interpretações adicionais.

Na primeira, DBBI e FAED formam um único número decimal, em qualquer
ordem e com inversões independentes. Cada campo admite até duas letras
zeráveis por ocorrência. A decomposição `A × 10^L + B` permite relaxar
todo o segundo campo para um intervalo de valores.

Uma prova de **180 árvores, 1.274 nós e 727 certificados**, conferida por
um contador independente, exclui todos os 32.400 modelos quando os bytes
da saída devem ser inferiores a 128. O segundo campo pode inclusive ser
qualquer número do comprimento declarado, não apenas uma máscara de FAED
ou DBBI.

Para UTF-8 completo, os prefixos excluem **32.130 modelos**. Restam 270,
todos começando por DBBI e usando `b,d` ou `b,e` como letras zeráveis.
As árvores de prefixos foram integralmente verificadas. A busca residual
foi interrompida por custo; seus 9.837 registros completos foram
preservados, sem candidatos, mas não receberam verificação independente
completa. Não constituem uma exclusão adicional certificada de Unicode.
[Relatório dos campos concatenados](_work/joined_fields_2026-09-16/RELATORIO.md).

Na segunda interpretação, os pesos azul/amarelo são os 21 pares de primos
nas faixas convencionais 450–495 nm e 570–590 nm. A ligação com “Infrared”
é uma hipótese, não uma instrução confirmada do criador. As 42 matrizes
geraram 168 listas e 5.880 materiais de senha, incluindo duas leituras
de `lastwordsbeforearchichoice`.

Foram **70.560 decisões AES**: 281 paddings, nenhum corpo autenticado.
Os 5.880 hashes das preimagens não atingiram a pubkey. Todas as matrizes,
senhas, decisões AES e pontos foram reconstruídos com implementação
independente. Nos corpos com padding aceito, 264.375 escalares derivados
de hashes e janelas de 32 bytes também não corresponderam à pubkey-alvo
ou à sua negação.
[Relatório dos comprimentos de onda](_work/wavelength_primes_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — frequências primas e auditoria de assinaturas

**Nenhuma senha final.** A hipótese espectral foi estendida para frequências
inteiras em THz, com limites exatos derivados das mesmas faixas de azul e
amarelo. Os 33 pares de primos produziram 264 listas, 9.240 materiais,
18.480 senhas e **110.880 decisões AES**. Houve 439 paddings sem plaintext
autenticado; os hashes das preimagens e 399.509 escalares derivados dos
corpos também não corresponderam à pubkey-alvo ou à sua negação.
Todos os limites, materiais, decisões AES e pontos receberam conferência
independente. Os 15.120 materiais das duas rodadas espectrais também
falharam no padrão condicional DBBI = hash hexadecimal por substituição.
[Relatório das frequências](_work/frequency_primes_2026-09-16/RELATORIO.md).

O teste histórico dos OP_RETURNs `GSMGJH/GSMGBH` continha dois defeitos:
argumento `recid` inválido para a API de coincurve e ausência do cabeçalho
`0x20` de JH. Os bytes das duas transações foram recuperados e seus txids
recalculados. As 43 mensagens antigas, com os oito cabeçalhos, produziram
688 configurações: 344 recuperações e 344 ramos matematicamente impossíveis.
Todas as assinaturas recuperadas foram verificadas por Python/ecdsa e
Node/OpenSSL, com endereços recalculados: **zero correspondências** no
conjunto declarado. A autoria dos OP_RETURNs continua sem autenticação;
o negativo não exclui outras mensagens. As afirmações antigas acima foram
corrigidas. [Auditoria e artefatos](_work/signature_audit_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — somas diretas com alfabetos e ordem desconhecidos

**Nenhuma senha final.** A exclusão das 14 somas decimais foi ampliada
para qualquer bijeção de `a..i` com os nove dígitos positivos e até duas
letras adicionalmente zeráveis por ocorrência. Os pesos uniformes das
cores são quaisquer inteiros `p,q≥2`, abrangendo todos os primos. Preto
e branco usam independentemente 0 ou 1.

Normalizar os aliases de zero preserva a igualdade entre somas repetidas.
O maior par de substrings iguais sem sobreposição limita essas somas e,
consequentemente, os pesos. Dos 2.944 casos com linhas/colunas e ambos os
sentidos dos campos e listas, **2.896 falham por comprimento e 48 por
segmentação**, com 620 nós e nenhum sobrevivente. Um verificador
independente conferiu todos os limites e casos, com 4.092 controles
exaustivos de rotinas e 24 controles plantados.

A extensão para **qualquer permutação das 14 somas** reduz o problema a
736 combinações: 724 falham pelo comprimento. Nas 12 restantes, nenhuma
disposição de substrings iguais permite acomodar os grupos repetidos
em intervalos disjuntos com comprimento suficiente. Dois algoritmos
independentes enumeraram os mesmos posicionamentos e validaram o negativo.

Isso exclui a concatenação decimal direta no modelo declarado; não
exclui usar as somas como chave, outras bases ou outras operações. Não
houve candidato AES ou escalar nesta rodada.
[Prova, limites e reprodução](_work/symbolic_color_sums_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — bases primas posicionais e rotas dos tokens

**Nenhuma senha final.** Foi examinada a leitura de cada linha/coluna como
um número em base prima `r`, com dígitos primos uniformes azul/amarelo
`2≤p,q<r` e fundos binários. Limites monótonos de comprimento cobrem
bases arbitrariamente grandes. DBBI falha em 14 perfis por comprimento;
nos dois restantes, `r=3` e `p=q=2`. Seus histogramas permitem no máximo
24 ou 20 ocorrências de uma letra, mesmo dando a ela todos os zeros;
DBBI possui 25 letras `b`. Isso exclui esses perfis sob qualquer bijeção
dos dígitos, ordem das 14 somas e sentido do campo. Para FAED há apenas
limites necessários, não uma busca completa. A conferência independente
reconstruiu todos os 32 conjuntos de limites e os dois histogramas.
[Relatório das bases posicionais](_work/positional_prime_bases_2026-09-16/RELATORIO.md).

Na outra frente, FAED foi tokenizado com prefixos `b,g`, nas duas direções:
451 tokens e 25 tipos em cada caso. Grades 11×41 e 41×11, com linhas,
colunas, alternância, espirais, reflexões e inversas, geraram 70 rotas.
Depois de cada rota, buscou-se um alfabeto de substituição desconhecido.
Três controles de exatamente 451 letras foram recuperados integralmente.

As 140 configurações reais e 280 embaralhamentos receberam o mesmo esforço:
**96.921.451 avaliações**. Em ambas as direções, a nota real ficou entre
as notas dos dois controles. Nenhuma saída formou texto coerente. O
verificador independente conferiu os 420 casos, as rotas e 25.502 caminhos
guardados. A busca de alfabetos é heurística, não uma exclusão global.

Os 8.120 textos reais distintos geraram **194.880 decisões AES**, com 816
paddings sem plaintext autenticado, e 16.240 hashes escalares sem acerto.
Outros 723.118 escalares dos corpos também não corresponderam à pubkey-alvo
ou sua negação. PyCryptodome e coincurve reproduziram todas as decisões,
corpos e comparações declarados. O controle histórico de 387 letras,
anteriormente descrito como tendo 451, foi corrigido acima.
[Relatório das rotas de tokens](_work/checkerboard_token_routes_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — símbolos nulos opcionais e zeros

**Nenhuma senha final.** A interpretação de “zeroed out” como remoção,
não confirmada pelo criador, foi testada em três modelos decimais com
`a=1,…,i=9`, nos dois campos e sentidos. Cada ocorrência da letra escolhida
pode ser mantida/removida (36 casos) ou mantida/zerada/removida (36 casos).
Uma terceira família tem uma letra sempre zero e outra removível, cobrindo
as 72 escolhas distintas para cada campo/sentido (288 casos).

A busca agrupa pelo número de remoções e usa extremos exatos de sufixos.
Todos os **360 casos** foram concluídos: **62.687 nós, 40.802 certificados
e 13.580 raízes**. O verificador independente refez os extremos com strings,
contou inteiros de sete bits nos intervalos e conferiu cobertura completa
das máscaras, incluindo estados compartilhados. Controles exaustivos do
contador e dos extremos, além de mensagens plantadas, passaram.

FAED não teve saída de sete bits. DBBI teve **22 saídas**, somente na
direção original com `b` podendo valer 2, zero ou remoção; todas contêm
controles não usuais. As duas ordens de bytes geraram 44 materiais e
88 senhas: **528 decisões AES**, dois paddings sem plaintext autenticado,
e 352 escalares sem correspondência com a pubkey-alvo ou sua negação.
PyCryptodome e coincurve conferiram os materiais, decisões, corpos e pontos.

O negativo não cobre alfabetos diferentes, várias letras removíveis,
Unicode completo ou uma letra removível com outra independentemente
zerável. [Modelos, provas e reprodução](_work/optional_null_decimal_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — pista EBCDIC 1141 nas leituras decimais

**Nenhuma senha final.** A referência a EBCDIC 1141 da fase 3.2 motivou
verificar uma limitação dos testes de ASCII. A tabela foi obtida em .NET;
seus 98 bytes para ASCII 32–126 e TAB/LF/CR coincidem com a implementação
cp273 do Python. As duas diferenças fora desse repertório foram registradas.
Reaplicar a pista à SalPhaseIon continua sendo hipótese.

Cada leitura cobre DBBI/FAED nos dois sentidos, `a=1,…,i=9` com até duas
letras zeráveis, e todas as bijeções para `1..9` com uma letra zerável.
Como inteiro decimal completo, **13.063.864 configurações** e 19.018.074 nós
não produziram bytes integralmente pertencentes ao repertório EBCDIC.
O resultado é invariante pela ordem dos bytes. Um contador independente
de inteiros permitidos confirmou todos os casos e nós.

Duas leituras adicionais concatenam os códigos decimais de cada byte:
códigos mínimos ou sempre preenchidos para três dígitos. Seus
**26.127.728 casos** não tiveram segmentação completa. Outro algoritmo,
baseado em fronteiras de códigos e tabelas numéricas, confirmou a cobertura
e o negativo. Controles exaustivos das rotinas e mensagens plantadas passaram.

Não houve candidato para AES. Os testes não excluem EBCDIC com outros
caracteres, transformações adicionais ou os modelos de zero fora do escopo.
[Resultados, fontes e reprodução](_work/ebcdic_decimal_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — máscaras exatas e palavras no checkerboard

**Nenhuma senha final.** A baixa recuperação dos controles anteriores foi
investigada: mesmo com o alfabeto verdadeiro, o melhor caminho de quadgramas
pode conter palavras incorretas. A nova busca otimiza a máscara em cada
proposta de alfabeto e depois usa um vocabulário independente do Telegram
para otimizar simultaneamente palavras, fronteiras e zeros. O alfabeto é
refinado por até vinte rodadas completas de trocas entre posições.

Dos três controles antigos, dois foram recuperados integralmente; o terceiro
ficou a nove edições do texto correto. Três recortes com exatamente 570
símbolos tiveram distâncias 0, 7 e 274. Portanto, ainda há falha importante
de recuperação; o método continua sendo heurístico para o alfabeto.
O verificador independente conferiu 12 modelos pequenos por 303 máscaras,
184 saídas com palavras, 376 caminhos de quadgramas e 18 ótimos com
alfabeto fixo. A mensagem conhecida da fase 3.2 também foi recuperada
exatamente quando seu alfabeto foi fornecido ao decodificador de palavras.

Foi iniciada uma campanha de 180 configurações: 45 pares de prefixos,
duas direções, FAED real e um embaralhamento, com os mesmos parâmetros.
Os 90 casos reais já foram conferidos: 4.745 saídas com palavras, 4.986 caminhos
de quadgramas e 314 ótimos para alfabetos fixos, incluindo a calibração.
Os 10.330 textos distintos geraram **247.920 decisões AES**, com 954 paddings
sem mensagem autenticada, e **919.404 escalares**, sem correspondência com a
pubkey-alvo ou sua negação. PyCryptodome e coincurve reproduziram todos os
candidatos, decisões, corpos, escalares e pontos.

A campanha inteira terminou com saída 0. Foram 2.261.344 avaliações de
quadgramas e 1.041.193 de palavras. A conferência completa validou 9.468 saídas
com palavras, 9.459 caminhos de quadgramas e 610 ótimos para alfabetos fixos,
incluindo a calibração. O embaralhamento superou a nota real nos dois sentidos;
nenhuma saída formou mensagem coerente. Não há processo desta rodada ativo.
[Calibração, resultados e limites](_work/checkerboard_exact_mask_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — cabeçalhos compactados com dígitos desconhecidos

**Nenhuma senha final.** DBBI e FAED, nos dois sentidos, foram tratados como
inteiros decimais com qualquer bijeção `a..i → 1..9` e ocorrências opcionais
de zero para até duas letras. Os bytes mínimos, do mais significativo para
o menos significativo, precisariam começar pela assinatura de um arquivo.

Todos os **1.104 casos**, cobrindo seis formatos, foram conferidos por um
verificador independente de intervalos, testemunhas e certificados: 7.460
intervalos e 28.281 nós. GZIP/DEFLATE, ZIP, bzip2, XZ e 7z não são compatíveis
nesse modelo. Zlib tem 110 casos compatíveis pelo cabeçalho, o que não comprova
a existência de um fluxo válido.
[Escopo, provas e formatos](_work/substituted_format_headers_2026-09-16/RELATORIO.md).

Para zlib **sem zeros e sem dicionário prévio**, os nove intervalos restantes
foram rejeitados em 1.391 nós. Uma enumeração independente em Python conferiu
as **1.451.520 configurações** dos quatro campos/sentidos e de todas as
bijeções. Os 1.320 inteiros com cabeçalho compatível falharam na descompactação.

A ampliação com até duas letras zeráveis ficou **inconclusiva**. Doze
intervalos atingiram 100.000 nós cada, sem solução e com 502 estados pendentes;
outros 534 não foram pesquisados integralmente. A execução foi interrompida,
preservando os registros. Uma implementação independente conferiu a cobertura,
os extremos e os 599.978 certificados desses doze intervalos, incluindo
599.846 decisões zlib. Essa verificação não encerra os estados pendentes.
Não há processo zlib ativo nem conclusão negativa para o modelo com zeros.
[Piloto concluído e ampliação interrompida](_work/substituted_zlib_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — fechamento da leitura posicional de FAED

**Nenhuma senha final.** Os limites necessários das bases primas, registrados
anteriormente, foram completados por uma prova dos prefixos decimais. Cada
linha/coluna vale `A(r)·B + C(r)·Y + D(r)`. Fixar o primo de uma cor e variar
a outra por todos os seus primos delimita um intervalo. Dígitos iniciais
comuns que contradigam a bijeção de símbolos rejeitam o intervalo inteiro.

Na ordem original ou inversa das linhas/colunas, os 13.950 casos de perfil,
base e primeira linha produziram **54.620.160 certificados**. Todos foram
conferidos independentemente, inclusive os limites que cobrem bases sem teto
arbitrário. Nenhum caso permaneceu compatível. A implementação passou por
3.072 modelos pequenos e 96 números plantados.
[Prova dos prefixos](_work/positional_prime_prefix_2026-09-16/RELATORIO.md).

A extensão para **qualquer permutação dos 14 números** examinou as outras
doze possibilidades de primeira linha, além das duas já rejeitadas. Seus
83.700 casos adicionais deram 327.720.907 rejeições por intervalo. Somente
53 intervalos exigiram resolver o valor da outra cor: de 108.710 atribuições,
3.861 falharam no primeiro número e 103.693 no comprimento total. Nos 1.156
casos restantes, todas as 13 possibilidades de segunda linha contradisseram
FAED. Nenhuma ordem do restante pode reparar essas contradições.

Outra implementação conferiu todos os certificados, atribuições e árvores;
dezesseis controles de ordens plantadas também passaram. As duas buscas e
seus verificadores terminaram com saída 0. Não há processos ou casos pendentes
desta rodada, nem candidato para AES.

O negativo mantém premissas explícitas: base prima uniforme, dígitos primos
das cores menores que a base, pesos 0/1 para preto/branco, orientação interna
uniforme e concatenação decimal mínima. Cobre ambos os sentidos do campo,
qualquer bijeção dos dígitos positivos e até duas letras zeráveis. Não cobre
cores fora da base, transposições dentro de cada número ou transformações
anteriores. [Ordem livre, resultados e verificação](_work/positional_prime_order_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — RSA e fatores primos das cores

**Nenhuma senha final.** Foram testados módulos `p·q` com fatores primos
distintos dos dois números RGB, incluindo o fator 2 como relaxamento, e
todas as classes invertíveis de expoentes. A leitura por caractere cobre
ASCII 32–126, TAB/LF/CR, decimal mínimo ou preenchido, `a=1,…,i=9`, até
duas letras zeráveis por ocorrência e ambos os sentidos de DBBI/FAED.
Seus **9.661.104 modelos** não têm caminho completo. Outra implementação
conferiu todas as decisões; Python também conferiu 2.572.060 códigos e
suas inversões. [Domínio e provas](_work/rsa_color_blocks_2026-09-16/RELATORIO.md).

A extensão para blocos de vários bytes incluiu o par `47,23`, derivado
das contagens 15/9 de células coloridas. Seus **9.742.064 modelos** têm
9.924 compatibilidades pelo repertório ASCII, das quais 4.068 admitem
somente caracteres imprimíveis e nenhuma admite só letras/espaços.
Nos módulos com dois primos ímpares selecionados, as únicas dez
compatibilidades pertencem a DBBI com expoente da classe identidade.
Todos os onze modelos FAED compatíveis usam `9341·2`.

Os caminhos restantes são numerosos e não constituem uma decifração.
Todas as decisões, contagens, comprimentos e 9.924 testemunhas foram
conferidos independentemente. [Blocos de vários bytes](_work/rsa_color_multibyte_2026-09-16/RELATORIO.md).

Um filtro exato de todos esses caminhos rejeitou os formatos de chave
hexadecimal, com ou sem `0x`, e WIF de 51/52 caracteres, em BE/LE por
bloco: **79.392 decisões** conferidas. Com tamanhos uniformes e um possível
bloco final menor, apenas blocos de dois bytes ficaram compatíveis,
em 8.058 modelos DBBI e seis FAED.

A seleção delimitada por contagens mínimas de controles e caracteres
fora de letras/espaços produziu **51.335 textos distintos**. Os 616.020
testes AES de textos diretos e seus hashes, nos três blobs com SHA256/MD5,
foram reproduzidos em PyCryptodome. Os 2.421 paddings aceitos não produziram
texto reconhecível; a maior fração imprimível foi 58,23%. Os 2.389.116
escalares derivados foram comparados com a chave pública do prêmio por
libsecp256k1, sem correspondência ou negativo correspondente.

Os negativos de formato são exatos dentro do domínio; os testes de senha
são uma amostra, não uma exclusão de todos os textos possíveis. Todos os
processos da rodada terminaram com saída 0.
[Candidatos, testes e verificações](_work/rsa_color_candidates_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — dígitos desconhecidos e produto de primos

**Nenhuma senha final.** A busca RSA por caractere foi ampliada para qualquer
bijeção de `a,…,i` em `1,…,9` e até duas letras zeráveis por ocorrência.
Todos os 211.784 modelos com saída só de letras/espaços foram excluídos e
conferidos. Para ASCII/TAB/LF/CR, o estado final desta rodada é **211.666
negativas conferidas, 58 compatibilidades e 60 casos inconclusivos**.
Nenhum processo permanece ativo; os casos inconclusivos estão preservados.

Uma prova independente da busca resolveu a leitura de FAED em pares
decimais abaixo de 74: as letras dos dígitos 8 e 9 precisam consumir as
duas possibilidades de zero; a letra de 7 poderia ter no máximo cinco
vizinhas, mas todas têm pelo menos sete. A contradição vale em ambos os
sentidos e para qualquer expoente ou repertório de plaintext.

As 71 testemunhas guardadas deram 57 textos distintos: **684 decisões AES**,
um padding sem texto reconhecível e 212 comparações secp256k1, sem acerto.
Os testes foram reproduzidos independentemente. Essa conferência confirma
os resultados registrados, mas não elimina outros caminhos dos modelos compatíveis.
[Escopo, estados e evidências](_work/rsa_substituted_digits_2026-09-16/RELATORIO.md).

Outra hipótese interpreta a matriz como expoentes dos primeiros 196 primos:
expoentes preto/branco em 0/1, azul/amarelo como dois primos uniformes >=2.
O inteiro resultante seria o campo decimal completo. As 32 rotas de linhas,
linhas alternadas e espirais, com reflexões/rotações/reversões, dão 256 casos
com os fundos e campos. Limites inteiros exatos cobrem todos os expoentes
primos que poderiam caber, sem um teto de busca arbitrário.

DBBI não tem pares com o comprimento certo. FAED tem onze combinações
compatíveis pelo comprimento; todas as 22 leituras diretas/inversas
contradizem a bijeção dos símbolos ou os zeros permitidos. Os produtos,
limites, rotas e contradições foram conferidos em outra implementação.
Não há candidato AES nem caso pendente nesse modelo.
[Produto de primos da matriz](_work/prime_product_matrix_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — fechamento da busca FAED/base 127

**Nenhuma senha final.** A busca parcial registrada em 11/09 foi concluída.
O modelo mantém `a=1,…,i=9`, cada `g` como 0/7 por ocorrência, o inteiro
decimal completo e sua representação mínima em base 127, com dígitos
restritos a TAB/LF/CR/ASCII 32–126. Não há cortes ou mapas adicionais.

Uma implementação que reaproveita prefixos fixos gerou a prova do domínio
inteiro: **4.176.355 nós, 2.087.990 intervalos rejeitados e exatamente 188
saídas**, cobrindo todas as `2^107` máscaras. Outro programa usou contagem
exata de cadeias por intervalo para verificar todos os nós, a cobertura e
os candidatos. O produtor tem 1.600 intervalos de controle, dezoito casos
de máscaras e três textos plantados; o verificador tem mil controles.

Os 177 candidatos antigos foram recuperados byte a byte; os onze novos
estão depois do checkpoint anterior. Os arquivos históricos foram
preservados. As 44 formas de texto e 88 senhas novas deram **528 decisões
AES**, cinco paddings sem resultado validado e 16.276 comparações de
escalares, sem correspondência com a chave pública ou seu negativo.
PyCryptodome e libsecp256k1 reproduziram os testes.

Com a rodada anterior, as 188 saídas tiveram **1.504 senhas distintas e
9.024 decisões AES**, sem abertura autenticada. Esse resultado fecha a
enumeração do modelo, não todas as maneiras de interpretar as pistas.

A conversão decimal direta em base 128 também falha no repertório textual:
o primeiro código é fixo em 1 nos dois sentidos de DBBI, 6 em FAED original
e 4 em FAED inverso. Não houve remoção desses controles nem deslocamento
do início dos bits. Todos os processos terminaram; **FAED/base127 não tem
mais máscaras pendentes** nesta hipótese.
[Prova, candidatos e verificações](_work/radix127_completion_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — primos como códigos de caracteres

**Nenhuma senha final.** Dez tabelas de primos indexados por letras ou
códigos ASCII, duas direções, dois formatos decimais e três regras de
dígitos/zeros resultaram em 240 modelos: 238 exclusões e duas
compatibilidades, todos conferidos independentemente. Não há caso limitado
pendente. Só DBBI aceita `A=2, B=3,...`, espaço=0, com mapa desconhecido.

A exceção foi esgotada em **52.254.720 configurações** de bijeções, pares
zeráveis e campos/sentidos. Há 498 configurações compatíveis em DBBI
original, 42 em DBBI inverso e nenhuma em FAED. Outro autômato, com códigos
revertidos, reproduziu todas as decisões, contagens e testemunhas.

Nenhum caminho completo passa pelo filtro declarado de palavras do corpus
Norvig. Isso não exclui texto sem espaços, nomes, outras línguas ou outra
camada cifrada. A amostra de 530 testemunhas distintas teve 25.440 decisões
AES, 106 paddings sem resultado autenticado e 234.488 comparações secp256k1
sem acerto; tudo foi reproduzido com PyCryptodome/coincurve. Os demais
caminhos dos modelos compatíveis não foram testados como senhas.
[Modelo, limites e evidências](_work/prime_codepoints_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — conclusão dos sessenta casos RSA limitados

**Nenhuma senha final.** Os sessenta casos inconclusivos da rodada RSA
com dígitos desconhecidos foram concluídos: 58 incompatíveis e dois
compatíveis. Autômatos que representam todos os cortes e zeros examinaram
**653.184.000 configurações**. Outra implementação reverteu códigos e
fontes, refez as potências e reproduziu todas as decisões. Os registros
antigos permanecem preservados, com link para o estado atualizado.

A classificação final dos 423.568 modelos dessa família é: **423.508
excluídos e conferidos, 60 compatíveis, nenhum inconclusivo**. Os
compatíveis são 59 de DBBI e um de FAED. Este último usa n=74/e=7,
decimal mínimo e FAED inverso; suas 24 configurações admitem muitos
caminhos, mas todos contêm ao menos nove TAB/LF/CR e 363 caracteres.
Assim, nenhum modelo FAED dessa família gera somente ASCII 32–126.

A nova compatibilidade DBBI, n=362/e=133, tem três mapas e exatamente
360 caminhos, todos enumerados e conferidos. Com testemunhas e saídas
ótimas declaradas de FAED, foram autenticados 465 textos distintos:
**26.640 decisões AES**, 126 paddings sem validação e **391.340 escalares**,
sem correspondência com o prêmio. PyCryptodome/coincurve reproduziram
tudo. Os caminhos restantes de FAED não foram testados como senhas.

Não há processo desta rodada em execução. O fechamento vale para os
módulos, códigos e regras declarados, sem excluir outras cifras ou
fornecer a chave final.
[Prova e estado atualizado](_work/rsa_pending_dfa_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — códigos por caractere sem limite de letras zeráveis

**Nenhuma senha final.** Foi removido o limite de duas letras zeráveis:
qualquer ocorrência das nove letras pode valer zero ou seu dígito
positivo, com todas as 9! bijeções. Treze tabelas de primos/ASCII,
dois formatos e quatro campos/sentidos deram **37.739.520 decisões**,
reproduzidas por um segundo autômato. Dos 104 modelos, 95 são incompatíveis.
FAED não admite os códigos ASCII declarados mesmo nessa ampliação.

A exceção A=2,...,Z=101 com espaço=0 admite saídas feitas só de espaços.
Uma busca adicional, conferida em sentido inverso, mostra que FAED precisa
de **ao menos cinco letras zeráveis** no decimal mínimo. As combinações
de três e quatro deram 152.409.600 negativas adicionais; testemunhas
recodificadas provam existência com cinco. Para três dígitos preenchidos,
uma prova por pares de posições força todas as nove letras a serem
zeráveis. Esses resultados delimitam compatibilidade; não recuperam texto.

Os 3.600 mapas imprimíveis de DBBI foram contados exatamente, mas seus
caminhos não foram enumerados por completo. Nenhum texto completo cabe
nos cinco formatos declarados de chave de 32 bytes (direta ou Base64).
Filtros de palavras produziram 107 candidatos selecionados: **4.644
decisões AES**, doze paddings sem validação e **19.562 comparações
secp256k1**, sem acerto. PyCryptodome/coincurve reproduziram tudo.
Os demais caminhos continuam sem autenticação.
[Escopo, provas e amostras](_work/unbounded_zero_codepoints_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — fatores das cores e listas de somas

**Nenhuma senha final.** A revisão das fontes mantém cores, primos,
`matrixsumlist` e últimas palavras como pistas, sem uma fórmula confirmada.
Foi testada a escolha de fatores primos de três valores de cada cor:
soma dos dígitos hexadecimais, soma R+G+B e inteiro RGB. As cores foram
conferidas no PNG preservado do domínio restaurado.

Os 14 pares de fatores, dois fundos e ordens explícitas de linhas/colunas
deram 280 listas. Seis serializações e composições declaradas com as duas
cláusulas já fixadas produziram **8.370 materiais, 16.740 senhas e
100.440 decisões AES**. Houve 411 paddings sem resultado autenticado e
**455.646 comparações de escalares** sem acerto. Outra implementação
regenerou todos os materiais; PyCryptodome/coincurve reproduziram os testes.

Também foram corrigidas afirmações antigas no README que promoviam
igualdades e fragmentos da cadeia não autenticada a pistas confirmadas.
Os resultados históricos foram preservados com seus limites.
[Regras, fatores e conferências](_work/color_factor_sums_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — valores ASCII primos da URL inicial

**Nenhuma senha final.** Foi testada uma interpretação distinta das posições
primas: selecionar pela primalidade dos valores ASCII da URL que a imagem
decodifica, recolocar esses valores nas células coloridas ou zerar bytes
não selecionados e calcular listas de somas. A ligação entre células
coloridas e bytes é verificável; a operação é uma hipótese do solver.

Nove matrizes, 90 listas e composições fixas com as duas cláusulas de últimas
palavras geraram 1.625 materiais e **3.250 senhas**. Foram conferidas
**19.500 decisões AES**, com 80 paddings sem validação, e **3.250 escalares**
sem acerto no prêmio. Outra implementação reconstruiu a espiral e todos
os materiais; PyCryptodome e coincurve confirmaram os resultados.
[Derivação, escopo e conferência](_work/url_prime_reinsertion_2026-09-16/RELATORIO.md).

O plano da próxima etapa também foi atualizado para refletir o fechamento
de FAED/base127: 188 candidatos, sem máscaras pendentes. Não há processo
desta rodada em execução; a transformação que fornece a senha permanece
sem identificação.

## Sessão 2026-09-16 — Brotli e cabeçalhos Zstandard

**Nenhuma senha ou conteúdo recuperado.** A conversão decimal original,
com cada `g` independentemente 0/7, foi examinada como um fluxo Brotli
completo. DBBI nos dois sentidos e FAED original foram excluídos por
prefixos inválidos: a árvore de FAED original termina em 275 nós,
cobrindo todas as `2^107` máscaras. FAED invertido atingiu o limite de
200.000 nós e mantém 97 ramos pendentes; não foi declarado impossível.

Python reconstruiu limites e cobertura de todos os certificados e os
reexaminou via Brotli em modo de fluxo. As duas APIs usam a mesma
biblioteca de descompressão; a conferência aritmética é independente.
Uma leitura dos bits sem essa biblioteca confirmou os cinco certificados
de DBBI. Quarenta e duas construções curtas tiveram seus conjuntos de
resultados comparados com enumeração integral, incluindo controles positivos.

Os cabeçalhos Zstandard e frames ignoráveis também contradizem os prefixos
fixos nos quatro casos. Isso não cobre dados sem cabeçalho ou outras
transformações. Não há processo desta rodada em execução.
[Escopo, resultados e pendências](_work/brotli_decimal_2026-09-16/RELATORIO.md).

## Sessão 2026-09-16 — inteiro decimal sem limite de letras zeráveis

**Nenhuma senha final.** A leitura do campo decimal inteiro foi ampliada
para permitir que qualquer ocorrência de qualquer letra seja zero ou seu
valor `a=1,...,i=9`. Vinte modelos, com cinco repertórios textuais em dois
campos e sentidos, terminaram integralmente. Os repertórios e suas
limitações constam no [relatório](_work/unbounded_zero_integer_2026-09-16/RELATORIO.md).

Os 18.215 certificados cobrem `2^91` escolhas em cada caso DBBI e `2^570`
em cada caso FAED. Outra implementação contou os inteiros admitidos em
cada intervalo e conferiu cobertura e candidatos. A união tem 42 saídas
de até 15 bytes; todas precisam zerar ocorrências das nove letras e
longos prefixos. Não há lista de somas ou hash completo nesses candidatos.
Suas composições declaradas deram 2.808 decisões AES e 468 escalares,
sem resultado validado, com conferência PyCryptodome/coincurve.

Dois pilotos de repertório mais amplo em FAED original permanecem parciais:
ASCII imprimível/TAB/LF/CR e minúsculas/pontuação com dígitos. Seus 26.562
candidatos encontrados geraram 318.744 decisões AES e 53.124 escalares,
também conferidos e sem acerto. Isso não esgota as máscaras pendentes.
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — inteiro zerável com restrições de palavras

**Nenhuma senha final.** A conversão do inteiro decimal com todas as
ocorrências zeráveis foi examinada com dois vocabulários e duas regras de
caixa. Cada sequência máxima de letras deve ser uma entrada do corpus;
dígitos e pontuação explícita separam essas sequências. O corpus também
contém siglas e abreviações, portanto esse filtro não prova linguagem coerente.

Dez dos dezesseis modelos terminaram: os oito de DBBI e os dois de FAED com
vocabulário de maior contagem e caixa por palavra. As duas continuações
executadas nesta rodada terminaram; seis outros modelos FAED permanecem
parciais. Os estados atuais têm 2.754.072 certificados, incluindo máscaras
pendentes. Outra implementação reconstruiu os vocabulários e verificou
intervalos, cobertura e candidatos, sem reutilizar o algoritmo de sucessor.

As listas encontradas têm 100.404 saídas distintas. Nas formas direta e
SHA256 hexadecimal, elas geraram 200.808 senhas, **1.204.848 decisões AES**
e **200.808 comparações de escalares**, sem resultado autenticado.
PyCryptodome e coincurve reproduziram todas as decisões. As formas com
cláusulas adicionais e os ramos ainda pendentes não foram esgotados.

[Especificação, resultados atuais e conferências](_work/unbounded_integer_words_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — somas dos campos em tabelas retangulares

**Nenhuma senha final.** A leitura literal dos campos como tabelas foi
examinada em todas as dimensões retangulares exatas: 12 partições DBBI e
84 FAED, somas de linhas/colunas e ambas as direções. Cada modelo permite
zerar ocorrências de uma letra escolhida entre as nove, mantendo `a=1..i=9`.

São 2.592 modelos estruturais. Todos os 864 que interpretam as somas como
`A=2,...,Z=101`, com zero=espaço, falham antes do filtro lexical. A1Z26
também falha em DBBI. Restam 302 modelos com domínios ASCII/A1Z26 não vazios.

Dois vocabulários e regras com palavras separadas ou concatenadas deram
10.368 casos completos e 490 compatíveis, com 355 melhores textos distintos.
Uma otimização adicional por quadgramas, sem exigir o dicionário, selecionou
uma saída por domínio não vazio. Controles e implementações independentes
confirmaram as partições, somas, contagens e escores ótimos.

Os textos selecionados, listas numéricas, composições com últimas palavras
e normalizações declaradas geraram **35.328 senhas distintas**, sem abertura
validada nem acerto na chave pública. PyCryptodome/coincurve reproduziram
as decisões. Os caminhos compatíveis não foram todos autenticados; o
resultado não exclui outras leituras de `matrixsumlist`.

[Modelos, controles e resultados](_work/matrix_sum_words_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — DBBI como escalar com zeros ocultos

**Nenhuma senha final.** Foi esgotada a interpretação do campo completo
DBBI como inteiro decimal `a=1..i=9`, com ocorrências de até duas letras
independentemente zeráveis, nos dois sentidos, reduzido pela ordem `n`
ou pelo primo `p` da secp256k1. Nenhum escalar válido correspondeu à
chave pública do prêmio ou à sua negação.

Os 144 modelos somam 35.538.237.967.872 escolhas binárias, com
sobreposições. Uma busca dividida em duas metades cobriu esse espaço
usando 20.499.712 registros de tabela e 31.374.048 consultas de pontos.
Essas contagens não representam chaves distintas ou senhas AES testadas.

Uma enumeração independente por árvore binária reproduziu contagens,
impressões digitais de todos os registros e ausência de correspondências.
Ela compartilha libsecp256k1 com o produtor. Separadamente, Node/OpenSSL
e adição afim JavaScript conferiram todas as 7.452 amostras preservadas.
Os controles plantados incluem colisões, transportes e escalares inválidos.

A hipótese não é uma instrução confirmada do criador. O negativo não cobre
três ou mais letras zeráveis, FAED, hashing, outro mapa de dígitos ou
transformações adicionais. SMALL, COSMIC e TAIL32 continuam sem abertura
autenticada.

[Especificação, método, controles e conferências](_work/dbbi_curve_zero_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — preencher os zeros e aplicar primos das cores

**Nenhuma senha final.** A auditoria confirmou que os 192 bits da URL
têm 91 zeros e 101 uns; a matriz completa tem 95 zeros. O único bit
incorreto da matriz histórica fica no índice espiral 193. Corrigida a
nota que rejeitava também a contagem válida de 91 zeros; a distribuição
antiga de DBBI fora do centro não é invalidada por esse erro.

Foi testada a combinação de preencher esses zeros com DBBI e substituir
azul/amarelo pelos 14 pares de fatores primos RGB já declarados, preservando
ou zerando o quase branco. As 56 matrizes geraram 560 listas, 16.800
pré-imagens, 33.600 senhas e 201.600 decisões AES, sem abertura autenticada.
Todos os resultados foram reproduzidos por uma implementação independente;
34.351 escalares também não corresponderam à chave do prêmio.

As listas como chaves decimais repetidas de FAED deram 249.408 casos
completos, todos incompatíveis com UTF-8 nos modelos especificados.
Foram conferidos os 552.652 certificados e a cobertura de todas as escolhas
`g→0/7`. O resultado não exclui outras operações de `matrixsumlist`.

[Fórmulas, auditoria, resultados e limites](_work/zero_cells_prime_sums_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — metadados e áreas não alocadas do MP3

**Nenhuma senha final.** Os dois arquivos MP3 preservados são idênticos.
O bloco ID3 contém apenas a versão do Logic Pro X, `iTunNORM` e `iTunSMPB`,
seguido de 3.815 bytes zero. Há 199 frames contínuos, sem bytes anexados.
FFprobe conferiu todos os limites, e FFmpeg decodificou todos os frames.

Os bits privados dos cabeçalhos e de side info são zero. Os 179 bytes de
padding MPEG seguem exatamente a compensação de tamanho `44/49`, fase 43.
Os comprimentos de áudio declaram 199 regiões não alocadas, totalizando
121.875 bits: todos zero. Outra implementação reproduziu essa contagem e
todos os limites, comprimentos e backpointers; seis controles de corrupção
deliberada verificaram a detecção de alterações.

Essa auditoria não obteve outra mensagem além de `HASHTHETEXT`, já conhecida,
nem um novo candidato fundamentado para AES. Não exclui esteganografia nos
coeficientes ou outras transformações do sinal. Corrigida a caracterização
antiga de Decentraland como inteiramente fechada.

[Fonte, reprodução, resultados e limites](_work/mp3_container_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — somas decimais dos sete anéis

**Nenhuma senha final.** A espiral da primeira fase motivou testar os sete
anéis concêntricos como uma lista de somas. A leitura direta de DBBI/FAED
como essa lista foi excluída para todos os pesos inteiros azul/amarelo
`p,q ≥ 2`, incluindo todos os primos, sem teto arbitrário de busca.

O modelo mantém `a=1,…,i=9`, permite até duas letras também representarem
zero por ocorrência, ambas as direções dos campos e da lista, e quatro
tratamentos 0/1 dos bits não coloridos. São 1.472 modelos: 1.144 falham
no centro constante; os demais admitem 64.756 separações de comprimentos.
Nenhuma produz as seis somas restantes. Os limites de comprimento são
derivados das razões entre as expressões lineares dos anéis.

Outro programa reconstruiu a geometria e todas as separações. Testando
somente os restos dos pesos, rejeitou 64.749 casos módulo 10 e os sete
restantes módulo 100. Vinte controles plantados e doze comparações
exaustivas passaram no produtor; vinte controles passaram no verificador.
Não houve candidato para AES. O resultado não exclui outras funções
dos anéis ou outros mapas de caracteres.

[Hipótese, prova, controles e reprodução](_work/ring_sum_decimal_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — bases 29/31/37 como alfabetos de letras

**Nenhuma senha final.** Foi testado o inteiro decimal completo com
`a=1,…,i=9`, todas as escolhas `g→0/7`, ambos os sentidos, e seis alfabetos
explícitos nas bases 29/31/37. Isso difere de interpretar os dígitos como
códigos ASCII. Exigindo palavras separadas do corpus de 333.296 entradas,
todos os 24 modelos foram excluídos, com 39 intervalos conferidos por
outro algoritmo e 12.288 máscaras DBBI também enumeradas diretamente.

A extensão para palavras concatenadas usa 26.264 entradas de maior contagem.
Terminou 19 de 24 modelos e encontrou 35.965 textos distintos. Cinco FAED
permanecem parciais. Todos os candidatos foram reencodificados e conferidos
por segmentação independente; a cobertura das máscaras foi conferida,
mas as exclusões internas dos modelos parciais não foram certificadas
independentemente. Siglas e abreviações explicam por que compatibilidade
com esse vocabulário não é prova de mensagem legível.

As formas declaradas deram 287.712 casos de senha, 1.726.272 decisões AES
e 6.644 paddings, sem abertura autenticada. PyCryptodome reproduziu todas
as decisões e os corpos. Com coincurve, 294.356 hashes escalares também
não corresponderam ao prêmio ou à sua negação. Não foi alegada exclusão
dos candidatos ainda desconhecidos nos cinco modelos parciais.

[Alfabetos, gramáticas, cobertura, controles e resultados](_work/prime_alphabet_words_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — pontuação de linguagem nas bases primas parciais

**Nenhuma senha final.** Os cinco modelos FAED parciais em bases 29/31
foram examinados por uma busca que mantém 1.024 máscaras `g→0/7` por
etapa, pontuando o prefixo já fixado na base de saída. Essa busca não
exige o vocabulário anterior e não é exaustiva.

Oito mensagens conhecidas foram recuperadas integralmente: sete em
primeiro lugar, uma em segundo. Nas cinco entradas reais, as melhores
médias de quadgramas ficaram de −6,397 a −6,244; nas cinco comparações
embaralhadas, de −6,402 a −6,227. Os controles ficaram de −4,259 a −4,076.
Os textos reais completos continuam sem mensagem coerente identificada.
Uma comparação embaralhada por modelo não fornece significância estatística.

Os 5.120 candidatos reais retidos, todos ausentes da lista lexical anterior,
geraram 40.960 casos de senha e 245.760 decisões AES, sem abertura autenticada.
Outra implementação reproduziu todas as decisões; 41.942 hashes escalares
também não atingiram o prêmio ou sua negação. Os candidatos das calibrações
e comparações embaralhadas não entraram nos testes AES.

Foram conferidos a reconstrução e os escores de todos os 18.432 candidatos
finais das 18 execuções, mais 704 atribuições em doze controles exaustivos
pequenos. Isso não prova o ótimo global. Os cinco modelos anteriores
permanecem parciais e não foram retomados pela busca lexical.

[Algoritmo, controles, comparação, autenticação e limites](_work/prime_radix_beam_2026-09-16/RELATORIO.md).
Não há processo desta rodada em execução.

## Sessão 2026-09-16 — máscaras da capitalização dos títulos

As seis cópias HTML examinadas preservam `SalPhaseIon` (maiúsculas em
1,4,9) e `Cosmic Duality` (1,8, contando o espaço). A correspondência com
quadrados e cubos é uma observação, sem confirmação como instrução.

As máscaras dessas posições e da capitalização periódica dos títulos
geraram 224 transformações de DBBI/FAED, 3.200 materiais e 6.400 casos de
senha. As 38.400 decisões AES foram reproduzidas integralmente por outra
implementação. Nenhuma saída coerente ou chave do prêmio foi obtida;
6.554 escalares também não corresponderam ao ponto público ou à sua negação.

[Fontes, família finita, controles e limites](_work/title_position_masks_2026-09-16/RELATORIO.md).

## Sessão 2026-09-17 — somas diagonais com alfabeto desconhecido

**Nenhuma senha final.** A leitura de DBBI/FAED como concatenação decimal
de somas diagonais foi testada diretamente, sem usar palavras extraídas
por receitas da comunidade como alvo. Foram incluídas as duas direções
diagonais, com e sem continuação na borda oposta, pesos azul/amarelo
inteiros `>=2`, fundos binários 0/1, uma bijeção desconhecida dos dígitos
não nulos e até duas letras que também podem representar zero.

Todos os 128 modelos terminaram. As restrições de comprimento e das
diagonais constantes deixam 542 partições, mas nenhuma admite a aritmética
das somas. Outra implementação reconstruiu a geometria e as partições:
42 pares de resíduos sobrevivem módulo 10 e nenhum módulo 100.
Ambos os programas recuperaram os 48 controles plantados.

A conclusão cobre os pesos sem teto arbitrário, portanto também os primos,
mas somente as ordens e representações declaradas. Não foi gerada senha
AES; o significado de `matrixsumlist` permanece desconhecido.

[Modelo, demonstração, controles e reprodução](_work/diagonal_sum_inverse_2026-09-17/RELATORIO.md).

## Sessão 2026-09-17 — fronteira comunitária refutada, nove famílias novas e correção do oráculo

**Nenhuma senha final; prêmio intacto** (1,25635374 BTC, 126 tx). Dados atacados conferidos
byte a byte contra a página ao vivo (`Last-Modified` 2026-08-15, inalterado).

**Alegações da comunidade de jul–set/2026 (issues #99/#108/#110/#111) caem.** A #108 ("dois typos
no blob SMALL") está refutada com precisão de caractere: a página **já** tem `J` na posição 18 e `s`
na 51 e **já** tem o salt `3ab585348552415d` que a issue chama de corrigido; o "decrypt" é a Chain1
conhecida (só EVP-MD5, pad `0x01`, ASCII 0,38). O `gros` de 2432 B da #111 não é reproduzível
(2432 é o tamanho do **ciphertext** da fase 3.2; nenhum blob gera plaintext desse tamanho), logo
FirstHalf/BetterHalf/`Reduction` não têm ancoragem. #110/#99 operam sobre o cosmic da cadeia
não autenticada. Script: `solver/verify_community_claims_2026_09.py`.

**Rodada 1 (6 agentes + crítico, ~17,1 M AES + 6 M privkey, 0 hits):** TAIL32 por tabuleiro
(a frase "sad board… as wide as the first one seen" é autodescritiva do tabuleiro 3.2.2); seleção
de 256 bits do `faed` (fechada no braço privkey); cor como seletor sobre `dbbi` em primos (24 = 24);
inversão yin-yang/"Infrared"; gramática "our first hint is your last command"; "seven intertwined"
(concatenação, XOR, encadeado e entrelaçamento). Crítico calibrou o ruído com 720 k senhas
aleatórias: z de padding entre −1,2 e +2,1 e `printable` ≤ 0,60 são o esperado por acaso; todos os
melhores resultados ficaram dentro disso.

**Rodada 2 (3 agentes + crítico, 0 hits):**
- **Montagem do CT × corpus histórico — REFUTADA com cobertura completa.** 120 permutações dos 5
  blocos × salt cruzado SMALL↔TAIL32 × 2 KDF × 1.272.149 formas do corpus regenerado (466.310
  senhas-base, idêntico a 2026-09-02) = 1,22 bilhão de testes lógicos (203,5 M checagens de padding;
  12,75 M montagens decifradas; 339,5 M janelas de privkey). Controle recupera a ordem exata na fase 2
  embaralhada. O crítico foi além com um oráculo **por bloco**, agnóstico a IV/ordem/padding:
  10.177.192 pares chave×CT, **0** com ≥ 2 blocos limpos (esperado 7e-5). Os ~700 k negativos
  históricos são negativos de **senha**; o `enter` entre as linhas base64 não é marca de reordenação.
- Números das cores (479/484 e derivados) como largura/rotação/decimação e a célula 163 como
  ponteiro (símbolos e bits), mais 15 variantes da URL com os bits azuis zerados: negativo, dentro do
  nulo de 100 réplicas.
- Re-execução das 6 famílias com oráculo estendido: os 66.945 plaintexts com padding válido
  (contagens idênticas à rodada 1) + os 9.967 históricos de 2026-09-02 varridos por `Salted__`/
  `U2FsdGVk` em qualquer offset, base64 puro, privkey em 33 M janelas, hex64/WIF e
  `sha256(plaintext)`: **0** em tudo. "SIXTEEN ENCRYPTIONS" como encriptação aninhada com header
  está fechado.

**Fato novo (único):** `#FEFEFE` é uma **célula inteira** (25×25 px) em (7,4) = índice espiral 163 =
byte 20, bit 3 da URL — a imagem tem 25 marcas, não 24; enfraquece o pareamento "24 primos < 91".
Como ponteiro já está fechado.

**Kit corrigido (`gsmg_common.py`):** `nested_blob()` em `semantic()` (0 falsos positivos em 200 k),
`try_password_all()` varre privkey em todo padding válido e devolve o plaintext em `hex`,
`checkerboard_encode()` (inverso validado contra os 149 dígitos da 3.2.2). Scripts decisivos em
`solver/ct_montage_attack.py`, `ct_montage_corpus_collect.py`, `ct_blockscan_oracle.py`.

**Ficou de fora, declarado:** candidatos da rodada 1 (~17 M, não logados) × montagem com o
blockscan (~10 min, prior baixo); braço AES da seleção de 256 bits; P(16,7) dos tokens b/g
(0,4 % coberto); encriptação aninhada com `-nosalt` (intestável por construção).

Nove famílias negativas consecutivas com nulo casado e verificação adversarial independente: a regra
de parada está satisfeita com folga. Só insumo novo de senha move a fronteira.
[Relatório completo, tabelas e artefatos](_work/frontier_2026-09-17/RELATORIO.md).

**Adendo (mesma sessão) — `dbbi` como chave privada hex: as 16! bijeções esgotadas, 0 hits.**
Os 64 tokens `b/g` de `dbbi` (16 tipos) foram tratados como os 64 dígitos hex de uma "Regular
Bitcoin Private key" sob bijeção desconhecida. Como `d = Σ π(t)·W_t (mod n)`, um meet-in-the-middle
na curva (A = 7 tokens, 57,7 M pontos; B = 9 tokens, 4,15 bi folhas × 2 sinais; Go + dcrd/secp256k1,
20 CPUs, ~15 min por ordem) cobre as 20,9 trilhões de bijeções de forma **exaustiva**. Controle:
bijeção aleatória plantada recuperada exatamente (1 candidato = a chave plantada). Real: 4 ordens de
leitura (direta, invertida, bytes invertidos, bytes invertidos com nibbles trocados) × {d, n−d} =
**1,67 × 10¹⁴ chaves lógicas, 0 candidatos de 64 bits, 0 verificados**. Código em
`solver/mitm16_dbbi_hex/`. A leitura irmã (`dbbi` como **senha** sha256-hex do SMALL) exige força
bruta AES nas mesmas 16!: kernel OpenCL validado em `solver/gpu_aes16_dbbi_hex/`, 44 M/s → 132 h por
variante, **não disparado**.
