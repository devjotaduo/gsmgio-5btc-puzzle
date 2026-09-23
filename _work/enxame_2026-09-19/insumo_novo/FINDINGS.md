# F7 — insumo_novo — FINDINGS.md

**Campanha:** enxame_2026-09-19 · **Frente:** F7 (gate de insumo novo, somente leitura)
**Data/hora da coleta:** 2026-09-19 03:45–03:47 UTC
**Coletor:** Claude Code (sessão remota, Linux, container isolado; saída HTTPS via proxy pré-configurado)

## Pergunta

O gate (a) da regra 3 do `AGENTS.md` — "campanha nova só abre com insumo novo do criador" —
está satisfeito? Esta frente cobre **só** o que é verificável deste container: o site
`gsmg.io` ao vivo e o estado on-chain dos dois endereços. Ela **não** cobre o Telegram
(ver Limitação, abaixo).

## Método

`curl` contra `https://gsmg.io/...` (headers em arquivo separado do corpo, `-D`/`-o`), comparado
byte a byte (`diff -q` + `sha256sum`) contra as capturas já commitadas em `_work/gsmg_live_2026-09/`
(coletadas 2026-09-08) e `_work/archive/` (Wayback). Os dados internos do puzzle (`dbbi`, `faed`,
blobs SMALL/COSMIC) foram extraídos do HTML baixado agora e comparados contra `G.DBBI`, `G.FAED`,
`G.BLOBS` do kit (`solver/experiments/claude_endgame_2026_09_02/gsmg_common.py`). O estado on-chain
foi lido da API pública `mempool.space`. Nenhum arquivo grande foi salvo no repositório; os corpos
baixados ficaram só no scratchpad da sessão (`/tmp/.../scratchpad/f7/`, fora do repo, não commitado).

## Fato observado — site ao vivo, 2026-09-19 ~03:45–03:47 UTC

| URL | HTTP | SHA256 do corpo | Comparação |
|---|---|---|---|
| `https://gsmg.io/` (raiz) | 200 | `2f896807a859e2f71a2f6e1e8277986af73b80dc0dd79a685a67c7f7f8c3303b` | idêntico byte a byte à captura de 2026-09-08 |
| `https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32` (endgame) | 200 | `a83d3de7810f26b19b4965339b76d403e44f6b6877e5d7de2555480ca1779d77` | idêntico |
| `https://gsmg.io/theseedisplanted` | 200 | `7cb766d406008a397f8ae32b3a38ca68b42724bb07b3481deb84baad5c725183` | idêntico |
| `https://gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself` | 200 | `06fbd4461ab20d45c54a7053c7c0cfa256ba82a5ad4c73a47fac67f3f1cdf7d9` | idêntico |
| `https://gsmg.io/robots.txt` | 200 | `17ccdd08e8d3fd2d343f0a6c6b6751114cca0fa1885a606813b71ee8c0c04144` | idêntico |
| `https://gsmg.io/puzzle` (imagem 1048×1556, é a página `/puzzle`, não `/puzzle.png`) | 200 | `38125bbdf1ea58b9b30b075bc6bf71e4089d04bba37098317e47097e2f2a1830` | idêntico a `_work/archive/Puzzle_full.png` (não havia captura própria em `gsmg_live_2026-09/` sob esse nome — ver nota abaixo) |
| `https://gsmg.io/img/favicon.png` | 200 | `ca079023065e3d92167d0040987087decb2ddee9308e9ea763556f255ff5d9ec` | idêntico |
| `https://gsmg.io/img/follow_the_white_rabbit.png` | 200 | `5e8d84b88f8f829428df5d2a8bf36c7268346f169b799ac7570b6223990d204f` | idêntico |
| `https://gsmg.io/img/logo_GSMG.png` | 200 | `073446e9259530c329bc148cef57813edae6c92e459d781afbfab331609dc718` | idêntico |
| `https://gsmg.io/img/logo_GSMG_restored.png` | 200 | `1843afbb251b556e4251d4ff0fdb739d84bece92a4a0cc33cd438f3c81c40ce5` | idêntico |
| `https://gsmg.io/font/vt323-regular.ttf` | 200 | (não comparado a captura anterior; `Content-Length` 149688 bate com `hdr_font_vt323-regular.ttf.txt`) | consistente |
| `https://gsmg.io/sitemap.xml`, `/puzzle.png`, caminho inexistente, e o nome de arquivo truncado `/choiceisanillusioncreatedbetweenthosewit` | 404 | corpo `Hello :-)` (9 B) | igual ao documentado em `ENDGAME.md` §3 fato 6 |

**Nota sobre `/puzzle`:** a pasta `_work/gsmg_live_2026-09/` tem `hdr_puzzle.txt` (200, 29931 B,
`image/png`) mas o corpo correspondente nunca foi salvo com esse nome — só existe
`body_puzzle.png` (9 B, na verdade o 404 de `/puzzle.png`, caminho diferente). É uma lacuna da
captura de 2026-09-08, não uma divergência real: o SHA256 do meu download de hoje bate
exatamente com `_work/archive/Puzzle_full.png` (captura antiga do Wayback), e o
`Content-Length`/`Last-Modified` batem com o `hdr_puzzle.txt` salvo em 2026-09-08.

**`Last-Modified` de todo recurso 200** continua `Sat/Sun/Mon 15–17 Aug 2026` — igual ao que a
captura de 2026-09-08 já registrava. O servidor não recebeu novo deploy entre 2026-09-08 e
2026-09-19.

## Fato observado — dados internos do puzzle (dbbi/faed/blobs) na página do endgame

Extraí os dois `<textarea>` do HTML baixado hoje e comparei com o kit:

- `G.DBBI` (91 símbolos) **== substring exata** do primeiro textarea, na posição esperada (índice 0). Igual.
- `G.FAED` (570 símbolos) **== substring exata** do primeiro textarea, imediatamente após `dbbi` + o binário a/b. Igual.
- Blob **SMALL**: reconstruí `base64(Salted__ + salt + ciphertext)` a partir de `G.BLOBS["SMALL"]`
  e achei as duas metades como substrings do primeiro textarea, com o marcador binário `enter`
  (`abbaabababbabbbaabbbabaaabbaabababbbaaba`, 41 símbolos a/b) exatamente entre elas — reproduz
  o que o `README.md` já transcreve (linha ~644) e o que `ENDGAME.md` §1 descreve ("o binário a/b
  `enter` fica inline entre as duas metades do base64"). Igual.
- Blob **COSMIC**: reconstruí a mesma forma a partir de `G.BLOBS["COSMIC"]` — **igualdade exata de
  string completa** (não só substring) com o segundo `<textarea>` inteiro (1792 caracteres).
  Igual.
- Blob **TAIL32** não aparece nesta página (está no plaintext da fase 3.2, não aqui) — não há
  como confirmá-lo pelo site sem antes abrir a fase 3.2, o que está fora do escopo desta frente
  (que é read-only e não faz criptoanálise). Não comparado; sem divergência a reportar porque não
  há fonte nova para comparar.

**Nenhuma divergência encontrada nos dados do puzzle.** Cada achado foi conferido duas vezes (uma
via busca de substring, outra via comparação de string completa/hash) antes de registrar, como
pedido pela tarefa.

## Fato observado — estado on-chain (mempool.space API, 2026-09-19 03:47 UTC)

| Endereço | funded (sats) | spent (sats) | saldo (BTC) | tx_count | Comparação com `ENDGAME.md` |
|---|---|---|---|---|---|
| `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` | 875 988 872 | 750 353 498 | **1,25635374** | **126** | idêntico ao registrado (1,25635374 BTC, 126 tx) |
| `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` | 375 055 856 | 0 | **3,75055856** | 45 | idêntico (3,75055856 BTC, nunca gastou) |

`mempool_stats` de ambos zerado (sem transação pendente no momento da consulta). Sem transação
nova, sem gasto novo de `17ucy` — nenhum insumo on-chain novo.

## Limitação declarada (obrigatória)

**O Telegram não é acessível deste container.** `result.json` e os `ChatExport_*` citados no
`AGENTS.md` ("Dados locais") existem só no checkout principal do mantenedor
(`C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle` e as pastas `Downloads/Telegram Desktop/`),
não neste clone. Portanto **esta frente não pode afirmar** "não houve fala nova do criador": ela
só cobre o site e a cadeia. A afirmação do `ENDGAME.md` ("nenhuma fala do criador depois de
2026-09-01") não foi e não pôde ser reconferida aqui.

## Veredito

No escopo coberto por esta frente (site `gsmg.io` ao vivo + endereços on-chain), **nenhum insumo
novo do criador foi encontrado em 2026-09-19**: HTML, imagens, fonte e `robots.txt` são idênticos
byte a byte à captura de 2026-09-08; os dados do puzzle (`dbbi`, `faed`, blobs SMALL e COSMIC) são
idênticos ao kit já em uso pelas outras frentes; `Last-Modified` de todos os recursos não mudou
desde o revive de 2026-08-15/17; e os dois endereços do prêmio não tiveram transação nova nem
gasto novo. O gate (a) da regra 3 do `AGENTS.md` **permanece fechado** neste escopo — sujeito à
limitação do Telegram acima, que não foi e não pôde ser verificada por esta frente.
