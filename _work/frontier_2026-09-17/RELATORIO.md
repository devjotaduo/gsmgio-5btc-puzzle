# Sessão 2026-09-17 — fronteira comunitária refutada, duas rodadas multi-agente e correção do oráculo

**Nenhuma senha final. Nenhuma privkey. O prêmio segue intacto** (`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`,
1,25635374 BTC, 126 tx, mempool vazio em 2026-09-17).

Esta sessão fez três coisas, nesta ordem: (1) testou com oráculo duro as alegações mais recentes da
comunidade (issues #99, #108, #110, #111 do repositório original, jul–set/2026); (2) atacou, em duas
rodadas multi-agente com crítico adversarial, nove famílias que os registros marcavam como não
cobertas; (3) descobriu e corrigiu um buraco de oráculo que atravessava todas as campanhas anteriores.
Tudo abaixo é reproduzível a partir dos scripts preservados nesta pasta.

## 0. Integridade dos dados atacados

- `dbbi`, `faed`, SMALL e COSMIC do README são **byte a byte** os da página ao vivo
  `gsmg.io/89727c…` (baixada nesta sessão; `Last-Modified` 2026-08-15 23:16:42, inalterado).
- Raiz do site: sha256 igual à captura de 2026-09-08. Nenhum byte novo de puzzle.
- Kit `gsmg_common.py`: self-test verde (BTCSEED, z-method, espiral, checkerboard 3.2.2, KDF).

## 1. Alegações da comunidade (jul–set/2026) — todas caem

Script: [`solver/verify_community_claims_2026_09.py`](../../solver/verify_community_claims_2026_09.py).

| Issue | Alegação | Resultado |
|---|---|---|
| **#108** ("[SOLVED] dois typos no blob SMALL") | a página teria `R` na posição 18 e `k` na 51 do base64; corrigindo para `J`/`s` o blob abriria | **REFUTADA com precisão de caractere.** O blob publicado (site ao vivo, README e 6 capturas) **já** tem `J` em 18 e `s` em 51 e **já** tem o salt `3ab585348552415d` que a issue chama de "corrigido". Não houve alteração nenhuma; o "decrypt" é a Chain1 conhecida, que abre só sob EVP-**MD5** com pad `0x01` e ASCII 0,38 (falso-positivo), e não abre sob EVP-SHA256, o KDF de todos os blobs autenticados. |
| **#111** (FirstHalf/BetterHalf/`Reduction(SOURCE_4)`) | `gros_decrypted.bin` (2432 B) daria FH = `8048c428…`, `gros[1161:1177] = 3be6ecf1…` | **NÃO REPRODUZÍVEL.** 2432 é exatamente o tamanho do **ciphertext** da fase 3.2; nenhum blob publicado pode gerar um plaintext de 2432 B (exigiria ct ≥ 2448). Usando o cosmic comunitário (1327 B) os valores não batem. As 5 aberturas com padding válido sob `sha256^k("theseedisplanted")` são ruído (ASCII ≈ 0,38). `SOURCE_4` é apenas a 2ª linha base64 do SMALL. |
| **#110 / #99** (12 endereços extraídos de `cosmic_decrypted.bin`) | `CC[X*32+16:X*32+32] ‖ BE32(X)` → P2PKH | Operam sobre o mesmo cosmic de 1327 B da cadeia comunitária, cuja abertura nunca foi autenticada (pad `0x01` + MD5 + máscara construída). Os endereços não são o prêmio. |

Consequência: o "insumo novo" externo de 2026 não move o mapa. A fronteira continua sendo
decodificar `dbbi`/`faed` → senha(s) → abrir SMALL/TAIL32/COSMIC.

## 2. Rodada 1 — seis famílias não cobertas (6 agentes + crítico)

Cada agente escreveu a hipótese em prosa antes de codar, usou o kit e o oráculo duro (privkey vs
pubkey on-chain; plaintext ≥ 85 % ASCII ou WIF/hex64), rodou controle positivo e nulo casado.
Resultado bruto em `rodada1_resultado_bruto.json`; scripts em `rodada1_scripts/`; logs em `rodada1_logs/`.

| Família | Hipótese (resumo) | n_tests | Veredito do crítico |
|---|---|---|---|
| TAIL32 por tabuleiro | a frase "Raising the stakes… on a sad board but as wide as the first one seen" é especificação de tabuleiro (largura 14/8, Polybius sem escapes) para o material de senha do TAIL32 | 21.244 senhas / 127.464 AES | **CONFIRMADO NEGATIVO**. A frase é autodescritiva do tabuleiro 3.2.2 (8 casas úteis, 2 mortas). O `.`-em-8-e-22 (distância 14) é forçado pelo layout 8+10+10, não é pista. |
| Seleção de 256 bits do `faed` | subconjunto principiado de posições (primos, coloridas, `g`/`i`, múltiplos, pares i/i+285) materializado como chave crua | 3,77 M privkey + ~17 k AES | **NEGATIVO PARCIAL**: fechado no braço privkey (o braço certo para "regular private key"); braço AES ~200× mais fino e denominador mal reportado. |
| Cor como seletor sobre `dbbi` em primos (24 = 24) | os 24 símbolos de `dbbi` em posições primas alinhados às 24 células coloridas; cor = zerar/sinal/bit | 2,73 M + 724 k AES | **CONFIRMADO NEGATIVO** (z de padding +1,02 e +2,23, dentro da calibração). |
| Inversão yin-yang / "Infrared" | complemento da matriz, azul↔amarelo, canais de cor como números | 945 k AES | **NEGATIVO PARCIAL** — mas trouxe o único fato novo da rodada (ver §4). |
| "our first hint is your last command" como gramática | composição (primeiro hint × forma × último comando openssl × forma × ordem) | 7,34 M AES | **CONFIRMADO NEGATIVO**. `\n` final na senha refutado no openssl 3.5.7; `enter` dentro do base64 refutado estruturalmente (CT de 110 B). |
| "SEVEN INTERTWINED PASSWORDS" literal | 7 componentes nomeados pelo puzzle por concatenação, XOR de sha256, sha256 encadeado (+ entrelaçamento round-robin, rodado pelo crítico) | 6,68 M + 2,40 M AES | **CONFIRMADO NEGATIVO**. "23/16/7" não têm referente objetivo nos dados (inventário de ~30 contagens). |

Calibração independente do crítico (720 k senhas aleatórias): z de padding por sub-família entre
−1,2 e +2,1 é ruído normal; `printable` máximo por acaso ≈ 0,60 (p99,9 = 0,53). Todos os
`best_readable` da rodada (0,47–0,61) ficaram dentro desse teto.

## 3. Rodada 2 — as três segundas rodadas que o crítico priorizou (3 agentes + crítico)

Resultado bruto em `rodada2_resultado_bruto.json`; scripts em `rodada2_scripts/`; logs em `rodada2_logs/`.

### 3.1 Montagem do ciphertext × corpus histórico — **REFUTADA, cobertura completa**

A única hipótese que, se verdadeira, resgataria todos os negativos anteriores: o `enter` binário
entre as duas linhas base64 do SMALL marcaria uma reordenação dos 5 blocos de CT.

- Corpus regenerado com o coletor de `tail32_history.py`: **466.310 senhas-base → 1.272.149 formas**
  (idêntico ao run de 2026-09-02; classe identidade do TAIL32 reproduz bit a bit os 9.967 paddings).
- Cobertura **completa**: 120 permutações × 4 combos salt/CT (SMALL↔TAIL32 cruzados) × 2 KDF ×
  1.272.149 formas = **1,22 bilhão de testes lógicos**, realizados como 203,5 M checagens de padding
  (truque: em CBC o padding do último bloco depende só do par (último, anterior) → 20 classes por chave).
  797.172 sobreviventes → 12,75 M montagens decifradas com oráculo estendido; 339,5 M janelas de 32 B
  varridas por privkey.
- Controles: fase 2 real (41 blocos) embaralhada → o pipeline recupera a ordem **exata** e o plaintext;
  blob sintético de 5 blocos → uma única permutação semântica = a verdadeira; senha errada → 0.
- Nulo: 100 réplicas × 60 k formas aleatórias; taxa real 0,0039165 vs 1/255; máx |z| por classe 2,57,
  abaixo da média do nulo (2,91).
- **O crítico foi além**: oráculo **por bloco** (`critic2/blockscan.py`), agnóstico a IV, ordem e
  padding — conta, entre os 25 candidatos `D_i⊕iv` e `D_i⊕C_j`, quantos são 100 % limpos; chave certa
  dá ≥ 4 qualquer que seja o IV. Corpus inteiro, **10.177.192 pares chave×CT: 0 com ≥ 2 limpos**
  (esperado por acaso 7e-5), 49 com 1 (esperado 54,1).

**Conclusão dura:** os ~700 mil negativos históricos são negativos de **senha**, não de montagem,
para qualquer ordem de blocos e qualquer IV. O `enter` não é marca de reordenação.

### 3.2 Números das cores como parâmetro + célula 163 como ponteiro — **CONFIRMADO NEGATIVO**

479/484 (somas dos primos < 91 por cor), 22, 5, 963, 9, 15, `3F48CC`, `FFF200`, 47, 54, 101 como
largura/rotação/decimação sobre `dbbi`/`faed`; 163/102/72 como início de janela de chave e corte
"half/better half"; 15 variantes da URL com os bits azuis zerados ("zeroed out" onde as cores estão —
nunca antes rodado). 21.997 senhas, 132.252 AES, 986.874 checks de privkey, 100 réplicas de nulo:
tudo dentro do nulo (z −1,59 a −0,43). O crítico fechou também 163 como ponteiro nos **192 bits** da
espiral (140 senhas, 0). Os agentes nem o crítico alegam significância estatística para 479/484
(p = 0,43 após look-elsewhere); foi rodado pelo texto do hint.

### 3.3 Re-execução das seis famílias com oráculo estendido — **CONFIRMADO NEGATIVO**

Os 66.945 plaintexts com padding válido da rodada 1 (66.933 + 12 do caminho `-K` nunca contados)
foram regenerados com contagens **idênticas** por script e varridos por: `Salted__`/`U2FsdGVk`
(blob aninhado — o que "SIXTEEN ENCRYPTIONS" prevê), base64 puro, privkey em toda janela de 32 B
(33 M janelas), hex64/WIF, `sha256(plaintext)`/`sha256d` como privkey, e `Salted__` em **qualquer**
offset. **71.409 plaintexts únicos: 0 em tudo.** Máximo `printable` 0,608. Os 9.967 plaintexts
históricos de 2026-09-02 (`tail32_history.jsonl`) receberam a mesma varredura retroativa: 0.

## 4. O único fato novo e a correção do kit

- **`#FEFEFE` é uma célula inteira** (25×25 px, cor deliberada, exatamente 625 px em três capturas
  idênticas), não "um pixel". A imagem tem **25** marcas, não 24: 15 azuis + 9 amarelas na moldura
  8k+7 (LSB de cada byte da URL) **mais** a célula (7,4) = índice espiral 163 = byte 20, bit 3 — a
  única marca fora da moldura de verificação. Isso enfraquece o pareamento "24 primos < 91 = 24
  células" em que várias famílias se apoiaram. Como ponteiro (símbolos e bits), já está fechado (§3.2).
- **Buraco de oráculo corrigido em `gsmg_common.py`**: `nested_blob(p)` (True para `Salted__` cru ou
  base64 `U2FsdGVk`; 0 falsos positivos em 200 k aleatórios) entrou em `semantic()`;
  `try_password_all()` agora varre privkey em todo padding válido e devolve o plaintext em `hex`
  (antes os plaintexts eram descartados e não podiam ser varridos retroativamente).
- **`checkerboard_encode()`** (inverso exato de `checkerboard_decode`, validado contra os 149 dígitos
  da fase 3.2.2) entrou no kit com assert no self-test. Permite re-codificar qualquer texto em
  qualquer tabuleiro para gerar material numérico.
- Subproduto reutilizável: corpus de 71.409 plaintexts únicos com padding válido
  (`rodada2_logs/rerun_ext__*`); qualquer oráculo futuro pode ser testado sobre ele em ~90 s.

## 5. O que ficou declaradamente de fora

- Candidatos das rodadas 1 (~17 M senhas, não logadas) × montagem do CT com o `blockscan`
  (~10 min); prior baixo — a hipótese não tem nenhum indício positivo e caiu com cobertura completa
  no corpus histórico.
- Braço AES da família "seleção de 256 bits" (o braço privkey, que é o certo para o alvo, está fechado).
- Concatenação ordenada de 7 sobre os 16 tokens b/g de `dbbi` (P(16,7) = 57,7 M ordens; 0,4 % coberto).
- Encriptação aninhada com `openssl -nosalt` (sem header não há oráculo; intestável por construção).

## 6. Estado do endgame após esta sessão

Nove famílias negativas consecutivas em dois dias, ~40 M decifrações AES + ~1,3 bilhão de testes
lógicos de montagem + ~350 M janelas de privkey, todas com nulo casado e verificação adversarial
independente, e as três alegações comunitárias mais recentes refutadas com precisão de caractere.
A regra de parada do projeto (5 negativas com nulo ⇒ esperar insumo novo) está satisfeita com folga.

O gargalo continua sendo **informação, não busca**: o roadmap `yellowblueprimes → matrixsumlist →
lastwordsbeforearchichoice → yinyang` é o único fio, e o próprio criador (2026-07-12) disse que
"close friends have the best chance… NOTE: that is a hint" e que a resposta está num laptop
escondido. Sem uma senha ou operação **nova** vinda do criador, re-testar corpora contra variantes
de oráculo, montagem ou parâmetro está esgotado.
