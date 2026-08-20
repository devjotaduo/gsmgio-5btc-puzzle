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
**Atualização 2026-08-20:** a frente `dbbi`/`faed` abaixo é histórica. A cadeia pública
agora é reproduzível até o plaintext canônico do Chain4; a fronteira atual é derivar a
única chave AES que abre os 35 blocos finais. Ver "Auditoria 2026-08-20" abaixo.

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
