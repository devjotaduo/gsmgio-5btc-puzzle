# Endgame do GSMG.IO 5 BTC — relatório único

**Estado em 2026-09-17: a fase final não está resolvida.** Nenhum dos três blobs AES foi
aberto de forma autenticada e o prêmio segue intacto em
[`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`](https://mempool.space/address/1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe)
(1,25635374 BTC, 126 transações). Este documento substitui o caderno cronológico
(`docs/historico/ENDGAME_cronologico_2026.md`) como fonte de verdade: aqui está o que é dado,
o que está provado, o que foi refutado e com que cobertura, e o único lead aberto. Os relatórios
de cada experimento estão em `_work/<experimento>/RELATORIO.md`, indexados em
[`docs/RESEARCH-INDEX.md`](docs/RESEARCH-INDEX.md). Regras de trabalho em [`AGENTS.md`](AGENTS.md).

## 1. Os dados (verbatim, conferidos byte a byte contra o site ao vivo)

A página `gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32` (o SHA256 de
`GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`, o "hash the text" da fase 0) tem
título `GSMG Puzzle`, dois `<h1>` (`SalPhaseIon`, `Cosmic Duality`) e dois `<textarea>`. Nada mais:
sem script, comentário ou atributo escondido. Em ordem de leitura:

| # | Conteúdo | Tamanho | Estado |
|---|---|---|---|
| 1 | `dbbi` — símbolos a–i | 91 = 7×13 | **não decodificado** (ver §6) |
| 2 | binário a/b (a=0, b=1, 8 bits) | 104 | = `matrixsumlist` |
| 3 | `faed` — símbolos a–i | 570 = 15×38 | **não decodificado**; estatisticamente i.i.d. |
| 4 | `z` + a–i,o (a=1..i=9, o=0 → decimal → hex → ASCII) | | = `lastwordsbeforearchichoice` |
| 5 | `z` + idem | | = `thispassword` |
| 6 | `z` + `shabef` (a1z26 = `sha256`) + texto | | `our first hint is your last command` |
| 7 | blob **SMALL** (`Salted__`, salt `3ab585348552415d`) | 80 B de ciphertext | fechado; o binário a/b `enter` fica **inline** entre as duas metades do base64 |
| 8 | `shabef ans too` | | `sha256 answer too` |
| 9 | blob **COSMIC** (salt `2d3f6fe06dc950e6`) | 1328 B | fechado |

Há ainda o blob **TAIL32** (salt `b45a5e3d827593ca`, 80 B) no fim do plaintext da fase 3.2, após
"Raising the stakes without extra chances of winning. A fubcd-king & oracle-queen, thingky mvps,
on a sad board but as wide as the first one seen." O criador confirmou (2023-06-10) que é real e
nunca foi aberto.

Strings (as transcrições completas estão no `README.md`, seção Salphaseion):

```
dbbi = dbbibfbhccbegbihabebeihbeggegebebbgehhebhhfbabfdhbeffcdbbfcccgbfbeeggecbedcibfbffgigbeeeabe
faed = faedggeedfcbdabhhggcadcfeddgfdgbgigaaedggiafaecghggcd… (570)
```

**Matriz da fase 0** (`follow_the_white_rabbit.png`, 14×14, 350 px; a página `/puzzle` é o PNG
1048×1556 com a matriz, uma faixa vermelha, o logo, o QR do endereço e o texto do banner): 101 uns;
lida em espiral anti-horária a partir de (0,0) dá `gsmg.io/theseedisplanted`. Exatamente cinco
cores: preto, branco, azul `#3F48CC` (15 células), amarelo `#FFF200` (9) e **uma célula inteira**
`#FEFEFE` em (linha 7, coluna 4) = índice espiral 163. As 24 células azuis/amarelas estão nos
índices espirais 7, 15, …, 191: o último bit de cada byte da URL (azul = 1, amarelo = 0), uma
moldura de verificação desenhada pelo autor. O centro contém um coelho branco em pixel-art
(decoração; a "matriz de 102 uns" era erro de amostragem). Somas de linha
`[6,10,8,7,6,6,5,4,9,9,7,8,7,9]`, de coluna `[8,10,8,10,8,7,3,6,7,5,9,6,6,8]`.

## 2. O que o criador disse (Jrk Bgrt / @SoWut, Telegram)

| Data | Fala | Uso |
|---|---|---|
| 2020-01-14 | "Roses are White but often Red. Yellow has a number and so does Blue. Go back to the first puzzle piece without further ado. It might have shown you only one door, beware that the rabbits nest may contain a whole lot more." | levou ao "hash the text" da fase 0 → URL do endgame |
| 2020-05-21 | "First or zero" | índice base 0 ou 1 (base 0 **mata** a segmentação de §6) |
| 2021-03-05 | "Infrared" (a "xor black/white/yellow/blue? or sum for red") | sem operação que renda senha (§5-F) |
| 2021-04-01 | "R=18 / A=1 / B=2. Could also be 21 or 1812 bit" | a1z26 |
| 2021-12-26 | "prime numbers … definitely required to proceed. … some characters need to be 'zeroed out'" | primos = §6; "zeroed out" ainda sem operação |
| 2023-01-09 | "At least prime number is very important to get any further." | idem |
| 2023-02-23 | binário invertido: `yellowblueprimes matrixsumlist lastwordsbeforearchichoice yinyang wewontgiveawaythepassword itsinfrontofyoureyesbutyourenotseeingit verylaststepisatruegiveawaypromised` | o roadmap |
| 2023-06-10 | TAIL32 "Correct" (nunca aberto), "No" (não é o hint da SalPhaseIon) | |
| 2023-08-06 / 2025-04-28 | "Once you hit a 'ying yang', you'll be able to solve it the same day"; "when yingyang is reached, 2 hours max" | yinyang é uma etapa, não a senha |
| 2024-01-26 | "Regular Bitcoin Private key" | alvo = privkey crua de 32 B |
| 2022-12-11 | ".... That is very specific" sobre a **capa** do livro *Cosmic Duality* (yin-yang de campos estelares, uma estrela branca e uma amarela) | a "página 39" foi acréscimo da comunidade |
| 2026-07-12 | "My close friends have the best chance of solving it … NOTE: that is a hint"; "hidden laptop … on that thing is the actual answer"; "The 5 btc was never the actual prize"; "salphaseion 100% solvable: Yes" | o passo final pode depender de referência pessoal |
| 2026-09-01 | "Couple hours, and no." — resposta a "quanto tempo levou? trabalhou sozinho?", ou seja **não** sozinho; a "two sloppy days" ele respondeu "Same same". "Pfff. Coincidence." (YOUWON) | **teto de complexidade**: ferramentas online, poucas camadas |

Exports do Telegram até 2026-09-17: nenhuma fala do criador depois de 2026-09-01 (o export de
04 a 17/09, com 1.209 mensagens, não tem nenhuma dele).

## 3. Fatos provados

1. **KDF.** Os blobs autenticados das fases 2, 3 e 3.2 abrem **só** com `openssl enc` EVP_BytesToKey
   **SHA256** (openssl ≥ 1.1.0), nunca com MD5. O cabeçalho `Salted__` prova `-pass`/`-k`; PBKDF2,
   todos os digests EVP e `-K` com 9 IVs foram excluídos. O desconhecido é a **senha**.
2. **A "cadeia comunitária" é miragem.** Chain1 (SMALL com a senha dos cinco tokens), Chain2
   (TAIL32 com o WIF resultante), `cc` (COSMIC com a passphrase XOR `a795de11…`), Chain4, os "35
   blocos", `half`/`better_half` e `BTCSEED`: todos abrem só sob EVP-**MD5**, têm padding `0x01` e
   plaintext de alta entropia (a assinatura de falso-positivo), a máscara de Chain4 é construída
   (`cosmic[158:166] XOR "Salted__"`), e `BTCSEED` depende de só 8 dos 570 símbolos de `faed`
   (mantidos esses 8 e alterados os outros 562, o prefixo sobrevive em 1.000/1.000 casos). Os
   endereços `1JG648…`/`145ZQ9…` derivados dela são os de um golpe, não o prêmio.
3. **`faed` é material i.i.d.** (entropia condicional e informação mútua no lag 285 dentro do
   nulo; 3.381 permutações estruturadas sem sinal): exclui Bifid-570 real e checkerboard direto ou permutado sobre `faed`.
4. **Evidência estatística forte de que `dbbi` foi construído com marcadores `b`/`be` nas posições
   lógicas primas** (§6): 0 em 20.000 embaralhamentos e uma única família em 2.925 regras. A
   intenção do autor é inferência, não medida.
5. **A célula `#FEFEFE` é uma célula inteira e uniforme** (25×25 px, exatamente 625 px em três
   capturas idênticas), não antialiasing: a imagem tem 25 marcas, não 24. A origem exata do RGB
   não é verificável no JPEG de referência.
6. **Site revivido em 2026-08-15**: os dados do puzzle (matriz, `dbbi`, `faed`, blobs) são
   idênticos às capturas do Wayback; o HTML tem diferenças cosméticas (um comentário novo em
   `/choiceisanillusion…`, `<H1>` voltou a `<h1>` no endgame). A raiz é uma animação de despedida;
   404 = `Hello :-)`; 71 caminhos temáticos = 404.
7. **Oráculo.** O plaintext autêntico da fase 3.2 tem só 58,9 % de ASCII (segmento EBCDIC cp273)
   e era descartado como ruído pelo oráculo histórico. `G.semantic` agora reconhece blob openssl
   aninhado (`Salted__`/`U2FsdGVk`, 0 falsos positivos em 200 k) e a assinatura EBCDIC; 431 k
   plaintexts de 2026-09-17 e 9.967 de 2026-09-02 foram re-varridos: 0.
8. **Scorer.** `solver/scorer.py` treinou no export do Telegram e aprendeu os quadgramas do próprio
   `dbbi` (DIFH = −5,13 vs THEQ = −4,06); a leitura identidade do resíduo de §6 pontua z +6,9 com
   ele e z 1,5 com o scorer limpo. Todo escore histórico sobre saídas ricas em a–i está inflado.
9. **Ruído calibrado** (720 k senhas aleatórias): z de padding entre −1,2 e +2,1 por sub-família e
   `printable` até ~0,60 em 80 B são o comportamento normal do acaso. Em escala ≥ 10⁷ a taxa de
   referência é Σ_{j=1..16} 256⁻ʲ = 1/255 (o `unpad` aceita 1–16), não 1/256: contra 1/256 um lote de
   10⁸ nasce com z ≈ +2,6 (provado pelo histograma de comprimentos de padding da rodada de
   2026-09-17). O teto de `printable` sobe com o número de paddings: 0,62–0,65 com ~143 k por blob de
   80 B. Maior desvio já visto: z +3,75 numa sub-família de 151 k decifrações, reproduzido, sem
   mecanismo possível e p ≈ 0,03 após look-elsewhere — acaso.
10. **Superfície ECC nula:** pubkey exposta, 6 assinaturas com `r` distintos, nonces pequenos ou
    relacionados excluídos (BSGS), ECDLP intacto.
11. **Oráculo de dois endereços.** As duas transações de gasto de `1GSMG…` (`2aa9a4a9…`, 2,5 BTC;
    `88cdb3cd…`, 1,25 BTC) mandaram os halvings para
    [`17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`](https://mempool.space/address/17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa),
    que guarda 3,75055856 BTC, nunca gastou (pubkey não exposta) e é chave **distinta** (a forma
    comprimida da pubkey de `1GSMG` dá `1cc6xa…`; a comunidade já notara, #69284). Que a chave de `17ucy`
    esteja em algum envelope **não** está provado: o endereço é de 2020 e o criador glosou "better half"
    como a esposa. Mas até 2026-09-17 `solver/oracles.py` e `G.fast_priv_scan` comparavam só com
    `1GSMG`: toda varredura de privkey do projeto era cega para 3/4 dos fundos. O kit agora testa os dois
    (`O.PRIZE_ADDRS`, `O.TARGET_H160S`; `fast_priv_scan` compara o h160 das duas formas de pubkey, com
    controle plantado no self-test). Re-varredura retroativa de todo plaintext com padding guardado:
    694.386 anteriores (81.862.702 verificações) + 1.331.155 da rodada "operador ensinado"
    (231.207.482): **0**. O MITM de 16! (§4-B) exige a pubkey do alvo e **não** pode ser refeito para
    `17ucy`; os demais negativos históricos de privkey valem só para `1GSMG`.

## 4. O que foi refutado, por família

Cada linha tem cobertura declarada, oráculo duro e, quando há escore, nulo casado; os números
exatos e os scripts estão nos relatórios linkados em `docs/RESEARCH-INDEX.md` e nos scripts de
`solver/`. **Nenhuma dessas famílias deve ser reaberta sem insumo novo do criador.**

### A. Alegações públicas
| Alegação | Teste | Resultado |
|---|---|---|
| Issue #108: "dois typos no blob SMALL" (2026-08) | a página **já** tem `J`@18 e `s`@51 e o salt `3ab58534…` que a issue chama de corrigido | refutada com precisão de caractere |
| Issue #111: FirstHalf/BetterHalf de um `gros` de 2432 B | 2432 é o tamanho do **ciphertext** da fase 3.2; nenhum blob gera plaintext desse tamanho | irreproduzível |
| Issues #110/#99: 12 endereços extraídos do cosmic | operam sobre a cadeia-miragem | sem valor |
| "YOUWON" (`(dbbi − M91) mod 26`) | look-elsewhere ≈ 3 %; 216 AES + privkey | coincidência ("Pfff. Coincidence.") |
| Cadeia "23/16/7/&8/Hb_m!%D" (Codex, 2026) | ≥ 15 artefatos equivalentes no espaço enumerado | ruído |
| *Looking Forward* (o "Bingo" de 2026-03-03) | senha (5,77 M AES), running key (7,05 M), cifra de livro, 16 gravuras, páginas do scan | 0 |

### B. Decodificação de `dbbi` e `faed`
| Família | Cobertura | Resultado |
|---|---|---|
| Decimal → hex → ASCII (o método da página) com zeros: cada letra, até duas, **todas** as ocorrências, `g→0/7`, UTF-8, EBCDIC 1141, bases primas 11–257, base 127, bases 29/31/37 com alfabetos, potências, Brotli/Zstd/zlib/gzip | certificados de cobertura integral (2^107 máscaras etc.) | 0 |
| Straddling checkerboard / VIC direto e permutado, Bifid 3×3 exaustivo (60.480 classes) e 5×5, Trifid, Bazeries, Nihilist, Polybius, MadHatter | 104 M decodes + hill-climb GPU com controles | 0 |
| Transposições por `matrixsumlist`/`lastwords…`/`dbbi`, keystreams mod 9/10 (listas, tokens, cores, primos), running keys do corpus e do livro (6,4 M alinhamentos) | | 0 |
| RSA por caractere com primos das cores, `dbbi` como escalar secp256k1, `dbbi` como SHA256 de listas (525 k pré-imagens), somas de linhas/colunas/anéis/diagonais/retângulos em todas as dimensões, produtos internos, distâncias | | 0 |
| Codificações sem zero (base 9 bijetiva, códigos com zeros apagados, trits) | 11,6 M modelos; **cobertura parcial**: DBBI admite 192.969 modelos compatíveis e só o melhor caminho de cada foi testado | 0 |
| `dbbi` (64 tokens `b`/`g`) como **chave privada hex** sob **todas** as 16! bijeções | MITM na curva, 4 ordens × 2 sinais = 1,67 × 10¹⁴ chaves; controle plantado recuperado exato | 0 |

### C. Senhas
| Família | Cobertura | Resultado |
|---|---|---|
| Corpus histórico (tokens da página, roadmap, Arquiteto, Matrix, Mr. Robot, Venus Project, site novo, Cosmic Duality OCR, fase 3.2) | 466.310 senhas-base × 3 formas = 1,27 M, nos 3 blobs × 2 KDF | 0 |
| "our first hint is your last command" como gramática de composição; "seven intertwined" (concatenação, XOR de sha256, encadeado; entrelaçado só sobre 9 tokens do roadmap/página, k=1); tokens do roadmap em 1–3 partes, com o resíduo de §6 | ~7 M + 6,7 M + 60 k | 0 |
| Senhas Unicode (☯, trigramas, 陰陽/阴阳/太極/음양, emojis; UTF-8/16, NFC/NFD) | 754 k senhas | 0 |
| `matrixsumlist` como o operador que o criador demonstrou (`R=18/A=1/B=2 → 21 \| 1812`): ordinais a1z26 → soma \| lista sobre 152 objetos nomeados e a saída de `yellowblueprimes` em L83 e L84 (bits como dígitos e como binário) | 230.506 senhas, 1,38 M AES, 253 k privkeys (dois alvos) | 0 |
| `lastwordsbeforearchichoice` literal: janelas antes das 5 ocorrências de "choice" no transcript do Arquiteto, falas, blocos cortados, com RAB e codec z | 70.340 senhas, 474 k AES, 211 k brainwallets | 0 |
| "seven intertwined" como entrelaçamento de caracteres dos 7 operandos de nível-senha (fase 1, `causality`, junções de 227 B e 62 B, `thematrixhasyou`, URL, título+endereço): 28 conjuntos × 7! ordens × k 1–9 × inversões × caixa | ≈ 285 M AES (COSMIC inteiro), 11,6 M privkeys (dois alvos) | 0 |
| "twenty-three ciphers" como família de codecs: 65 de byte único e os multi-byte (UTF, CJK), nas duas direções, sobre plaintexts guardados, campos da página e senhas | 762 k AES, ≈ 100 M reinterpretações | 0 |
| Dualidade (`half / better half`, yin-yang): um blob como senha do outro, metades do SMALL em torno de `enter`, cortes em todos os pontos, XOR, complemento da matriz, estrelas da capa (proxy) | 265 k senhas, 1,6 M AES | 0 |
| Referência pessoal pela gramática das fases: 104 itens públicos do mundo do criador, aridade 1–3 (4–6 na lista curta), 7 materiais, separadores | ≈ 1,7 M candidatos, 32,6 M AES | 0 (triplas verbatim a 67,5 %) |
| "our first hint is your last command" literal: o sha256 publicado em 22/04/2019 como argumento `-pass`; "segunda porta" = `sha256(título + 17ucy…)` e variantes | 217 senhas; 10 URLs (todas 404) | 0 |
| Senha como **arquivo** (`-kfile`/`-pass file:` = 1.ª linha; 89 artefatos, chunks PNG, digests dos bytes, 128 k linhas de texto) | 767 k decifrações | 0 |
| Textos do site revivido, capa/livro, falas do criador, linhas de comando openssl | | 0 |

### D. Premissas da ferramenta
| Premissa | Cobertura | Resultado |
|---|---|---|
| A cifra é aes-256-cbc | 16 cifras/modos do `openssl enc` × corpus 1,27 M × 3 blobs × 2 KDF = 122 M, controle por cifra com o CLI real | 0 |
| Os blocos do ciphertext estão publicados fora de ordem (o `enter` como marca) | 120 permutações × salt cruzado SMALL↔TAIL32 × 2 KDF × 1,27 M = 1,22 bi lógicos; oráculo por bloco agnóstico a IV/ordem/padding: 0/10,18 M pares com ≥ 2 blocos limpos | refutada; os negativos são de **senha** |
| KDF/IV alternativos, `-K` cru, chave = passphrase XOR | | 0 |

### E. Chave direta e seleção
| Família | Cobertura | Resultado |
|---|---|---|
| BIP39/BIP32 de listas, matriz, índices coloridos, BTCSEED | ver o caderno histórico | 0 |
| Seleção de 256 bits de `faed` por índices principiados (primos, cores, `g`/`i`, múltiplos, i/i+285) | 3,77 M privkeys; **parcial**: o braço AES ficou ~200× mais fino | 0 |
| Números das cores (479/484 e derivados) como parâmetro; célula 163 como ponteiro (símbolos e bits); URL com bits azuis zerados | 1,1 M | 0 |
| Cor como seletor sobre `dbbi` em primos; inversão yin-yang (**parcial**); espectro (a–i ↔ IR…UV, nm/THz) | 3,5 M + 0,9 M + 11,9 M | 0 |

### F. Mídia e forense
PNGs (alfa, LSB, sub-pixel, chunks, QR = URL do endereço, coelho central), MP3 do Decentraland
(frames, metadados, áreas não alocadas; só `HASHTHETEXT`), HTMLs (byte a byte), plaintexts
autênticos das fases (nada além de CRLF e do segmento EBCDIC, que é bijeção exata cp273),
Wayback do domínio inteiro (nenhuma página inédita): **nada oculto**.

## 5. Trabalho pronto e não executado

`dbbi` como **senha** sha256-hex do SMALL sob as 16! bijeções não tem estrutura linear e exige força
bruta AES. O kernel OpenCL está construído e validado ponta a ponta
(`solver/gpu_aes16_dbbi_hex/`, controles exatos, blob aninhado incluído), mas rende 44 M/s
sustentados na RTX 5060: **132 h por variante** (direta/minúsculo/SMALL; reverso, maiúsculo, TAIL32
e COSMIC são só parametrização). Não foi disparado; `python launch.py` retoma por checkpoint.

## 6. O lead aberto: `yellowblueprimes` em `dbbi`

Regra (atlas comunitário, 2026-09-15; reproduzida e verificada aqui): numerando as posições
**lógicas** de `dbbi` a partir de 1, em posição **prima** consome-se `b` ou `be` do texto físico,
nas demais um símbolo, e exige-se consumo integral dos 91 símbolos.

- Existem exatamente **duas** segmentações (L83 e L84, diferem só no `e` final); **0 em 20.000**
  embaralhamentos preservando contagens; **única família em 2.925 regras** (outras letras, sufixos,
  primos 0-based, contados do fim, físicos, compostos, quadrados, Fibonacci: nenhuma). `faed` não
  admite segmentação sob 4.248 variantes.
- L84: 23 primos, **16 `b` + 7 `be`** — os números do Arquiteto ("twenty-three ciphers, sixteen
  encryptions and or seven intertwined passwords"). Tipos como bits (`b`=0, `be`=1):
  `00001000110000100110010` (em L83 o `e` final vira o 23.º `be` e o último bit vira 1: `…0110011`). Coincidem posição a posição com as cores dos 25 eventos da matriz em
  ordem espiral (`BBBBYBBBYYBBBBYBBYYBWYYBY`, `#FEFEFE` = azul) omitindo dois eventos — 22 e 25,
  ou 23 e 25: p familiar 6,3 × 10⁻⁴. Só a ordem espiral casa. **Mas L83 também casa** (omitindo
  22/24, 23/24 ou 24/25): as cores confirmam a segmentação e não a desambiguam nem trazem
  informação nova. São 5 casamentos no total, não 4.
- Resíduo L84 (61 símbolos fora dos primos):
  `difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae` (L83 = sem o `e` final).
  **É indistinguível de i.i.d.** (χ² p 0,11, autocorrelação p 0,20, bigramas p 0,67).
- Esgotado sobre o resíduo e os 84/83 tokens (0 em tudo): decimal/base 9 com todas as escolhas de
  zero; checkerboard (todos os escapes, 27 alfabetos), Polybius/Bifid 3×3, a1z26, bases, índices
  em textos; keystream `matrixsumlist` (mod 9/10); todas as grades vs somas da matriz (com a=1..i=9 o
  resíduo soma 341 em L84 e 336 em L83; a matriz soma 101); resíduo nas células da matriz; somas como ordem de leitura; 60/61 como
  parâmetros; marcadores como chave/seleção/XOR/número; omissões como parâmetro; 16/7/23
  como partições e iterações; entrelaçamento das 7 palavras da 3.2.2; âncoras no Bifid de `faed`;
  grade 7×12; resíduo como chave sobre `faed`; gramática SHA256 das fases 2–3.2 com 60.005
  concatenações; "coluna j = letra j do rótulo" (7×13, 15×38).

**O que falta é informação, não busca:** qual segmentação é a pretendida, o que "zeroed out"
zera, e como `matrixsumlist` consome o resíduo. Sem isso, qualquer decoder novo sobre um resíduo
aleatório é gasto sem prior.

## 7. Como trabalhar

Ver `AGENTS.md`. Em resumo: oráculo duro único; KDF SHA256; hipótese em prosa, finita, com
controle positivo e nulo casado (≥ 100 embaralhamentos); scorer limpo para texto; plaintexts em
hex; conferir esta tabela antes de codar; relatório em `_work/`, script em `solver/`, linha no
índice; entrada aqui só se mudar o mapa. Regra de parada adotada: cinco famílias negativas
consecutivas com nulo ⇒ esperar insumo do criador.

## 8. Scripts reproduzíveis (principais)

| Script | O que prova |
|---|---|
| `solver/experiments/claude_endgame_2026_09_02/gsmg_common.py` | kit: dados, oráculos, decoders com self-test |
| `solver/verify_community_claims_2026_09.py` | issues #108/#111/#110/#99 |
| `solver/final_chain.py` | reprodução da cadeia-miragem (para auditoria, não solução) |
| `solver/ct_montage_attack.py`, `ct_blockscan_oracle.py`, `ct_montage_corpus_collect.py` | montagem do ciphertext × corpus; oráculo por bloco |
| `solver/mitm16_dbbi_hex/` (Go) + `make_config.py` | 16! bijeções de `dbbi` como privkey |
| `solver/gpu_aes16_dbbi_hex/` (OpenCL) | 16! bijeções como senha (pronto, não rodado) |
| `solver/premissas_2026_09_17/` | cifras/modos, `-kfile`, espectro, Unicode, forense, retro-EBCDIC |
| `solver/primos_2026_09_17/`, `solver/prime_host_*.cjs` | segmentação por primos, resíduo, `faed`, `matrixsumlist`, marcadores; scorer limpo |
| `solver/zero_free_*.cjs`, `solver/diagonal_sum_*.cjs`, demais `*.cjs` | famílias de codificação/somas fechadas com verificação independente |
| `solver/prize_nonce_bsgs/`, `solver/prize_*.cjs`, `solver/gsmg_sig_recover.py` | superfície ECC do prêmio |
| `solver/operador_ensinado_2026_09_17/` | operador RAB, últimas palavras, sete entrelaçadas, codecs, dualidade, referência pessoal; oráculo de dois alvos e re-varreduras (`retro_dois_alvos.py`, `v4_rodada_dois_alvos.py`) |

Taxonomia completa em `solver/README.md`; histórico cronológico em
`docs/historico/ENDGAME_cronologico_2026.md`.
