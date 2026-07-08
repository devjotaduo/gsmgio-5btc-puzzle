# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## O que é este repositório

Arquivo público de **hints** do desafio criptográfico *GSMG.IO 5 BTC puzzle*
(https://gsmg.io/puzzle). Não é um projeto de software: **não há código-fonte,
build, lint nem testes**. O conteúdo é documentação de pesquisa colaborativa
sobre como resolver as fases do puzzle. O prêmio original de 5 BTC está no
endereço `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` (o criador reduz o valor a cada
halving do Bitcoin).

## Estrutura

- **`README.md`** — o artefato central. Documenta, fase a fase, cada hint, a
  senha/decodificação usada e o resultado. Toda mudança relevante acontece aqui.
- **`result.json`** (~27 MB, **não versionado**) — export do Telegram do grupo
  "GSMG Puzzle Solvers". É a fonte primária das discussões da comunidade; use
  como material de consulta, não o commite (é grande demais e sensível).

As imagens de cada fase foram **removidas** — o texto/cifra que elas mostravam
agora está inline no README, transcrito verbatim do domínio via Wayback Machine
(o `gsmg.io` original morreu e virou página parqueada). Para reobter o conteúdo
de uma página: `curl "http://web.archive.org/web/<timestamp>id_/https://gsmg.io/<path>"`
(use a CDX API `web.archive.org/cdx/search/cdx?url=gsmg.io/<path>` para achar um
snapshot da era ativa, 2019–2021).

## Como o puzzle se resolve (padrão recorrente)

O fio condutor de quase todas as fases é o mesmo, e entendê-lo evita reinventar:

1. Um hint (imagem, texto ou referência cultural — Matrix, Alice, Bitcoin
   genesis block, xadrez, HSM Thales...) revela uma ou mais **palavras-chave**.
2. As palavras são **concatenadas** numa ordem específica (respeitando
   maiúsculas/minúsculas e espaços — o README anota isso como `/(aBa, connected enf)`)
   e passadas por **SHA256**. O hash resultante é a **senha** da próxima etapa.
3. O texto cifrado da próxima etapa é **AES-256-CBC em base64** (blocos que
   começam com `U2FsdGVk...`), decifrado com essa senha via OpenSSL.

Exemplo (fase 3): `SHA256(causalitySafenetLunaHSM11110<hex>B5KR/...)` → senha do
`openssl enc -aes-256-cbc -d -a`.

### Ferramentas usadas nas soluções
- **OpenSSL** para AES-256-CBC: `openssl enc -aes-256-cbc -d -a -in <arquivo> -pass pass:<sha256>`
- **SHA256** (ex.: https://xorbin.com/tools/sha256-hash-calculator)
- **CyberChef** (gchq.github.io/CyberChef) — o README já embute receitas prontas
  em URLs (binário→ASCII, `Substitute`, `From_Hex`, etc.).
- Cifras clássicas: **Beaufort** (ciphertools.co.uk) e **VIC** (dcode.fr) na
  fase 3.2; **IBM EBCDIC 1141** como pista de encoding.

## Estado do puzzle

As fases 1 a 3.2 estão decodificadas no README. A fase final **Salphaseion /
Cosmic Duality** (`https://gsmg.io/89727c...`) está **parcialmente resolvida** —
há blocos AES e sequências ainda não decifrados no fim do README. Trabalho novo
normalmente significa avançar essa fase ou documentar melhor as anteriores.

## Ao contribuir

- Mantenha o formato do README: por fase, mostre o **hint → raciocínio → senha/
  comando → resultado**, para que outro solver reproduza o passo.
- Preserve verbatim strings sensíveis a formatação (blobs base64, hashes, FENs
  de xadrez, alfabetos de cifra) — um espaço ou caixa trocados quebram o SHA256.
