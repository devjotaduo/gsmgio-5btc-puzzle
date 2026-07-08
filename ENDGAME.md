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

## Becos FALSOS — verificados localmente (NÃO repetir)
1. **Afim base-9 (issue #51)**: o bloco `faed`(570) → "Cryptography is the practice…"
   via afim (a=5,b=8). **Falso**: a chave dele gera hex `29d23a21…`, não o `43727970…`
   ("Crypto…") postado; nenhuma das 54 chaves afim invertíveis dá ASCII. Alucinação.
2. **XOR key `818af53daa…`** (issues #69/#79/web): reproduz do XOR de sha256 de 7
   tokens, mas **não decifra** (padding PKCS7 do último bloco inválido; independe do IV).
3. **XOR key `a795de117e4725…`** (PR #68): também falha no padding como `-K` direto no
   formato salted. Só reproduzível se usada com `-nopad` + IV específico do método deles
   — e mesmo assim o output é near-random (7.87 bits/byte = **outra camada cifrada**).
4. **Senhas AES diretas**: oráculo de padding sobre centenas de candidatos temáticos
   ({raw,upper,lower,sha256hex} × {sha256,md5} KDF) na Cosmic **e** no blob pequeno do
   SalPhaseIon → só falsos positivos (~esperado por acaso; todos <45% ASCII). Confirma
   que o pipeline exige decodificar `dbbi`/`faed` **antes**.
5. Refutados pelo PR #93 (com null-model): "matrixsumlist triangle" (apophenia),
   esteganografia nas PNGs, book cipher (Cosmic 0/27, Game of Logic 1/27).

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
- **Cores azul/amarelo** = paridade (blue=1/yellow=0) → redundante com a URL. QR =
  só o endereço. Sem vermelho oculto na matriz (a alegação de stego do `guy29278`
  não se sustenta; contestada por `wat96`). 16 mapeamentos cor→bit × travessias
  (espirais/linhas/colunas/diagonais) → só a 1ª porta aparece.
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

## Onde o endgame realmente está
Mesmo com ataque exaustivo verificado, o gargalo é o já diagnosticado pelo PR #93: falta a
**interpretação do "first hint"** que fixa o alfabeto do checkerboard/cifra — o oráculo AES
é binário (sem gradiente), então busca cega não converge. Próximos passos reais:
- **Substituição/hill-climb sobre `BIF_REST`** (25 letras) mirando inglês legível (não sobre
  o filler nem sobre a saída AES) — o IoC=0.094 é a assinatura clássica disso.
- **Joint 4-parameter attack** (PR #93) ampliado com a construção canônica de `dbbi`.
- **Novo hint oficial**: o criador disse que liberaria mais um se não resolvido.
- **Joint 4-parameter attack** (PR #93 `_work/joint_attack.py`): o único caminho
  computacional correto — só vence se o alfabeto do checkerboard for um candidato natural
  (o "first hint"). Ampliar o conjunto de alfabetos-semente.
- **Novo hint oficial**: o criador disse que liberaria mais um se não resolvido.

## Ferramentas / artefatos locais
- Blobs completos e **validados** inline no [README.md](README.md) (verbatim do domínio
  via Wayback; Cosmic idêntica à usada pela comunidade — mesmo salt `2d3f6fe0…`).
- Skill `/solve-phase` (sha256→AES) e **oráculo de padding do último bloco** (barato,
  independe do IV) para triagem de chaves candidatas.
- Pesquisa de referência: **PR #93** (`halbgott29a`, `FINDINGS.md` + `_work/`) e
  **PR #68 / issue #88** (`GalloClaudio64`, `zemnovodnuy`, `robotixcoder`).
