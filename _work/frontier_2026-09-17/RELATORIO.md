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

## 4b. `dbbi` como chave privada hex sob bijeção: as 16! bijeções esgotadas (0 hits)

O sinal estrutural mais forte da página é que `dbbi` (91 símbolos), tokenizado com `b` e `g`
como prefixos, dá **64 tokens de 16 tipos** (p = 0,05 % sob nulo que preserva contagens): a forma
exata de uma chave de 32 bytes em hex. Até aqui só 7 mapas "naturais" token→dígito tinham sido
testados (2026-09-08). Esta rodada esgotou **todas as 16! = 20.922.789.888.000 bijeções**, nas duas
leituras que o criador autoriza — "Regular Bitcoin Private key" e "brute forcing might be required" —
usando a linearidade da chave nos tokens:

`d = Σ_t π(t)·W_t (mod n)`, com `W_t = Σ 16^(63−j)` sobre as posições `j` do token `t`, logo
`pub = Σ_t π(t)·(W_t·G)`. Meet-in-the-middle no grupo da curva: lado A = 7 tokens (57.657.600
somas, tabela ordenada por x-low64 + bitmap de 2³² bits, 14 s), lado B = 9 tokens (4.151.347.200
folhas × 2 sinais, uma adição jacobiana por folha, inversão em lote de Montgomery, 20 CPUs,
~15 min por ordem). Cada colisão de 64 bits é reconstruída em π, convertida em `d` e verificada
por `d·G == pub`. Código: `solver/mitm16_dbbi_hex/` (Go + dcrd/secp256k1; `make_config.py` gera os
pesos e o controle).

| Execução | Alvo | Candidatos de 64 bits | Verificados | Tempo |
|---|---|---|---|---|
| **Controle** (bijeção aleatória plantada, seed 163) | pub da chave plantada | **1** | **1 = a chave plantada** `b06a811c…773c`, π idêntica | 915 s |
| `fwd` (dígito 0 = 1.º token) | pub do prêmio e −pub | 0 | 0 | 971 s |
| `rev` (dígitos invertidos) | idem | 0 | 0 | 895 s |
| `byterev` (bytes invertidos) | idem | 0 | 0 | 923 s |
| `byterev_swap` (bytes invertidos, nibbles trocados) | idem | 0 | 0 | 929 s |

Cobertura: 4 ordens × 2 sinais × 16! = **1,67 × 10¹⁴ chaves lógicas**, exaustiva (não amostrada).
Falsas colisões esperadas por acaso ≈ 0,013 por ordem; observadas 0. **Veredito:** sob a
tokenização `b/g`, `dbbi` **não** é uma chave privada em hex sob nenhuma bijeção, em nenhuma
dessas ordens. A leitura irmã — `dbbi` como **senha** sha256-hex do SMALL (a página diz `shabef`
= sha256 logo antes do blob) — não tem estrutura linear e exige força bruta AES nas mesmas 16!
bijeções: o kernel OpenCL foi construído e validado ponta a ponta (`solver/gpu_aes16_dbbi_hex/`,
controles A e B exatos, blob aninhado incluído), mas rende 44 M/s sustentados nesta RTX 5060 →
**132 h por variante**; não foi disparado (decisão do usuário; `python launch.py` retoma por checkpoint).

## 4c. Rodada de premissas: cifra, `-pass file:`, espectro, Unicode, forense de bytes (0 hits)

A pedido do usuário ("sem seguir a comunidade, tente caminhos diferentes"), cinco agentes
questionaram premissas que nenhuma campanha havia tocado, em vez de decodificar `dbbi`/`faed`.
Resultado bruto em `rodada3_resultado_bruto.json`; scripts em `rodada3_scripts/`; logs em
`rodada3_logs/`. O crítico reproduziu cada cadeia com o kit e com o `openssl` 3.5.7 real.

| Premissa atacada | Cobertura | Resultado |
|---|---|---|
| **A cifra é aes-256-cbc** (o `Salted__` só prova `-pass`) | corpus histórico de 1.272.149 formas × 3 blobs × 16 cifras/modos (aes-128/192/256-cbc, ecb, cfb, ofb, ctr, chacha20, bf, des-ede3, cast5, rc2, camellia, seed, idea, sm4) × 2 KDF = **122.126.304 testes**; controle por cifra com o CLI real (32/32) | 0 hits; 359.520 paddings vs 359.194 esperados; máx |z| 2,95 no envelope do nulo (2,99); fluxo: printable máx 0,675 vs 0,65 do nulo |
| **A senha é texto digitado** (`-kfile`/`-pass file:` usa a 1.ª linha de um ARQUIVO) | 89 arquivos públicos (site, arquivo, Wayback, Decentraland), 138 chunks PNG e frames ID3, 934 materiais, 7 leituras de "1.ª linha" validadas contra o `openssl` real, digests dos bytes; mais 128.345 linhas de 57 arquivos de texto → **127.842 formas, 767.052 decifrações, 64.653 privkeys** | 0 hits; paddings no nulo (z < 1,6). Todo PNG dá `\x89PNG`; a fonte TTF é recusada (1.ª linha começa com NUL) |
| **"Infrared" é tema, não operação** (a–i ↔ IR, R, O, Y, G, B, I, V, UV; valores em nm/THz; `len(faed)=570` = amarelo em nm) | 13 tabelas nomeadas + 1.152 combinações, 4 ordens, IR/UV zerados ou não, listas/somas/z-method → **11.879.120 testes**, nulo de 100 embaralhamentos | 0 hits; 39.310 paddings vs 39.311 esperados; tudo dentro de ±1,4σ |
| **A senha é ASCII** (☯, trigramas, 陰陽/阴阳/太極/음양, taijitu, emojis do criador, UTF-8/UTF-16, NFC/NFD, combinações com os tokens) | agente morreu a 3,6 %; o crítico completou: **223 bases, 754.446 senhas únicas, 4.526.676 AES, 266.108 privkeys** | 0 hits; z +0,55; printable máx 0,595 |
| **Os plaintexts autênticos escondem algo nos bytes** (fases 2, 3, 3.2; HTMLs) | todo byte fora de ASCII, whitespace/Bacon, trailing, BOM/zero-width, estrutura de linhas, o segmento EBCDIC cru, typos do Arquiteto como senha (630 bases × 6 formas) → **8.537.880 testes** | 0 anomalias exploráveis: só CRLF e o segmento EBCDIC; o segmento é bijeção exata cp273 de a–z; o `enter` do SalPhaseIon está inline numa única linha de 2.149 B |

**Achado metodológico real (forense):** o plaintext autêntico da fase 3.2 tem `printable` 0,589
por causa do segmento EBCDIC e **era descartado pelo oráculo histórico como ruído**. O kit ganhou
`ebcdic_sig()` (fração dos bytes ≥ 0x80 na imagem cp273 de a–z; real ≈ 1,0, máximo em ruído 0,46)
dentro de `semantic()`. O crítico re-varreu **431.164 plaintexts** com padding válido desta rodada
com essa assinatura: 0.

**Inspeção visual (orquestrador):** QR do rodapé = URL do endereço no blockchain.com; faixa
vermelha uniforme (os 15 pixels brancos são a última coluna da imagem); alfa uniforme; matriz com
exatamente 5 cores; coelho = pixel-art simples; capa endossada = yin-yang de campos estelares com
uma estrela branca e uma amarela. HTML da página final: título, dois `<h1>`, dois `<textarea>`,
nada mais.

Conclusão desta rodada: a cadeia "senha-texto + `openssl enc`" está esgotada nas três dimensões
(senha, cifra, KDF) para todo o insumo público. Ficaram de fora, com prior baixa: `aria-256-cbc`
(só via ctypes em libcrypto), o produto cifra × KDF fora de MD5/SHA256 nas 15 cifras novas, rc4 e
des simples, capturas Wayback de imagens (CDX fora do ar).

## 4d. Lead novo do export de 17/09: `dbbi` segmentado por marcadores nos primos

O usuário forneceu ao agente paralelo um export do Telegram até 17/09 (1.209 mensagens, nenhuma do
criador). Nele, o atlas comunitário (Doober, 15/09) traz uma regra que **reproduzi e verifiquei**:
numerando as posições lógicas de `dbbi` a partir de 1, em posição **prima** consome-se `b` ou `be`
do texto físico, nas demais um símbolo, e exige-se consumo integral dos 91 símbolos. Há exatamente
**duas** segmentações (L83 e L84, que diferem só no `e` final) e **0 em 20.000 embaralhamentos**
preservando contagens. Na L84: 23 primos, **16 `b` + 7 `be`**, os números do Arquiteto
("twenty-three ciphers, sixteen encryptions and or seven intertwined passwords"). Os 23 tipos
(b=0, be=1 → `00001000110000100110010`) coincidem posição a posição com as cores dos 25 eventos da
matriz em ordem espiral (`BBBBYBBBYYBBBBYBBYYBWYYBY`, #FEFEFE contado como azul) omitindo os eventos
22 e 25: é o passo `yellowblueprimes` do roadmap. Resíduo L84 (61):
`difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae`.

Testes rápidos do orquestrador sobre o resíduo, todos negativos: base 10 (a=1) e base 9 (a=0) →
bytes, reversos; cada letra isolada como zero; keystream `matrixsumlist` (linhas, colunas, ambas,
101; add/sub; mod 9/10) → bytes/decimal; resíduo cru/sha256 como senha; todas as grades exatas do
resíduo e dos 84 tokens (marcadores = 0/2/5/25) contra as somas da matriz (nenhuma igualdade; o
resíduo soma 337, a matriz 101); "coluna j = letra j do rótulo" em 7×13/13×7 e 15×38/38×15 (nenhum
grupo idêntico para letras repetidas; coincidências mod 9 no nível do nulo). A campanha sobre o
resíduo (decoders clássicos no resíduo, a regra aplicada a `faed`, `matrixsumlist` estrutural,
marcadores/omissões) está registrada no adendo seguinte.

## 5. O que ficou declaradamente de fora

- Candidatos das rodadas 1 (~17 M senhas, não logadas) × montagem do CT com o `blockscan`
  (~10 min); prior baixo — a hipótese não tem nenhum indício positivo e caiu com cobertura completa
  no corpus histórico.
- Braço AES da família "seleção de 256 bits" (o braço privkey, que é o certo para o alvo, está fechado).
- Concatenação ordenada de 7 sobre os 16 tokens b/g de `dbbi` (P(16,7) = 57,7 M ordens; 0,4 % coberto).
- Encriptação aninhada com `openssl -nosalt` (sem header não há oráculo; intestável por construção).
- `dbbi` (tokens b/g) como **senha** sha256-hex do SMALL sob as 16! bijeções: kernel pronto e
  validado, 132 h de GPU por variante (fwd/minúsculo/SMALL); reverso, maiúsculo, TAIL32 e COSMIC
  são só parametrização. Não disparado.

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
