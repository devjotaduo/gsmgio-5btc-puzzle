# A1 e A2: os dois últimos abertos baratos, fechados

**Estado: ambos negativos.** Nenhum candidato, nenhuma chave. Com isto, o único aberto declarado que
sobra na §3.14 são os **modos de fluxo**.

## A1 — raw32 sem unpad do corpus de 1,27 M em SMALL/TAIL32

**A lacuna.** A frente `cbc_sem_padding` do enxame (18/09) fechou duas metades e deixou o cruzamento:
a parte A testou os 7 operandos (10.080 senhas) contra SMALL/TAIL32 sem exigir PKCS7, e a parte B
testou o corpus histórico de 1.272.149 formas contra o COSMIC por bloco. Faltava o corpus **inteiro**
contra SMALL/TAIL32 sem unpad, varrendo os 80 B do plaintext como janelas de 32 B.

**Como rodou.** [`raw32_corpus_nopad.py`](../../solver/lacunas_2026_09_18/raw32_corpus_nopad.py) reusa
`_a_um` de `cbc_sem_padding/scan.py` **sem editá-lo** — a mesma função que rodou na parte A: decifra sem
unpad, chama `scan_raw32` (janelas BE e LE, h160 comprimido e não comprimido, confirmação por
`G.priv_hit` com `python-ecdsa`) e `semantic_extra`, e registra todo padding válido com o plaintext em
hex (regra 5). Roda em 12 partes determinísticas (classes `k::12`) com checkpoint por parte.

| | |
|---|---|
| Formas do corpus | 1.272.149 (de 466.310 bases) |
| Decifrações (2 blobs × 2 KDF) | 5.088.596 |
| Janelas raw32 (49 × BE/LE) | **498.682.408** |
| **Candidatos** | **0** |
| Paddings observados | 19.833 |
| Paddings esperados (1/255) | 19.955,28 |
| **z** | **−0,87** |
| Tempo | 1.577 s, 10 processos |

O z de −0,87 é ruído. O `corpus.pkl` confere com o sha256 que a parte B registrou
(`a8dc8c5d…b350`), então é exatamente a mesma população de formas.

**Controles.** Sem alvo plantado, `_a_um` não devolve candidato. Com a chave de uma janela real
plantada no offset 17 de um plaintext **sem unpad**, ela é achada em BE — o caminho inteiro, incluindo
a confirmação pelo oráculo duro. Os dois h160 são os dos endereços do prêmio.

## A2 — codecs da família 4 sobre os conteúdos recuperados pelo `splitlines`

**A lacuna.** O item 7 (PR #4) corrigiu `retro_dois_alvos.collect()`, que perdia linhas de `.jsonl` por
`str.splitlines()`. Os 1.723 conteúdos recuperados passaram por raw32 BE/LE e pelas 7 visões, mas
ficaram fora dos codecs da família 4 (§4-C, "twenty-three ciphers") — porque `familia4_codecs.py` e
`critico_familia4_codecs.py` coletam com o mesmo padrão de `splitlines()` e suas campanhas estão
fechadas.

**Como rodou.** [`codecs_1723.py`](../../solver/lacunas_2026_09_18/codecs_1723.py) reusa a lógica exata
da família 4 (`CODECS`, `scan_bytes`, `traduz`, `duro_traduzido`, `varre`) importando o módulo com
`open` redirecionado durante a importação — ele abre o log em modo escrita no import, e sem isso o
artefato de 17/09 seria sobrescrito.

| | |
|---|---|
| Conteúdos | 1.723 (774.293 B) |
| Com ≥ 8 bytes altos | 1.706 |
| Codecs × direções | 65 × 2 |
| Reinterpretações | 223.990 |
| **Detector disparou** | **0** |
| **Oráculo duro** | **0** |
| Melhor `lower` de todo o conjunto | 0,457 (`cp037`/`dec`) — limiar é 0,75 |

O `sha256` do conjunto de conteúdos (`a50eef75…f4d`) é idêntico ao registrado no item 7, o que
reconcilia as duas campanhas. Acrescentei o que a família 4 não fazia: todo hex64/WIF da saída
traduzida vira privkey testada contra os **dois** alvos — nenhum apareceu.

**Controle.** Um conteúdo construído para que a tradução por `cp273`/`dec` produza um cabeçalho
`Salted__` é detectado como `nested_blob` pelo oráculo duro, e a tradução é reversível.

## Efeito no mapa

`ENDGAME.md` §3.14 listava dois abertos: modos de fluxo e o raw32 do corpus. **Sobra só o primeiro.**
A linha de §4-D que marcava "raw32 do corpus em SMALL/TAIL32 aberto" passa a fechada.

Nada aqui muda a conclusão de fundo: o que resta na §6 são as duas perguntas de interpretação (qual
segmentação é a pretendida e como `matrixsumlist` consome o resíduo), e nenhuma delas é um espaço para
varrer.
