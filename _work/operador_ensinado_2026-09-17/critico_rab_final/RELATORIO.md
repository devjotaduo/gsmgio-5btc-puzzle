# Crítico final — família `matrixsumlist_rab` (operador RAB: a1z26 → SOMA | LISTA)

**Data:** 2026-09-17 · **Script:** `solver/operador_ensinado_2026_09_17/critico_rab_final.py`
(`--demo` = self-check) · **Veredito: CONFIRMADO_NEGATIVO** (com duas correções de cobertura).

Audita o ataque (`rab_a1z26.py`, relatório `ataque_rab.json`) e os dois críticos anteriores
(`critico_rab.py`; `critico_rab_a1z26.py` + `critico_rab_l83.py`, que morreu antes do nulo da
extensão). Não repete o que já estava reproduzido e verificável — confere e completa.

## Hipótese do crítico (falsificável)

O negativo do agente não se sustenta por uma destas vias: **H1** cobertura inflada; **H2** oráculo
incompleto (só 1GSMG, nunca 17ucy); **H3** lacuna do operador — bits dos marcadores lidos como
número **binário** (todos leram a string de bits como dígitos decimais); **H4** o maior z de padding
é real e não look-elsewhere; **H5** a extensão de 219.630 senhas ficou sem nulo casado.
Falsificação: qualquer hit duro. Nenhuma via derrubou o negativo.

## Controles

- Fase 2 abre com `sha256hex("causality")` sob EVP-SHA256 (`assert`, aborta se falhar).
- Chave **plantada** invertida no offset 13 é achada pelo oráculo de dois alvos; ruído não dispara.
- O contador rápido de padding (só o último bloco CBC) reproduz **exatamente** `G.aes_try` em
  1.500 senhas (e 300 no `--demo`) antes de ser usado no nulo.
- `H160_A = a9553269…` (1GSMG), `H160_B = 4bc46844…` (17ucy) conferidos por base58.

## Resultados

| Passo | Medida | Resultado |
|---|---|---|
| H1 recontagem | 9.722 senhas únicas, 10.994 privkeys, 58.332 decifrações, padding {44,33,32,51,37,33} | **bate byte a byte** com o relatório dele |
| H2a privkeys | **253.159** chaves únicas das 4 rodadas × 2 endereços × comp/uncomp | **0 hits** |
| H2b re-varredura | 7.578 registros → **5.306 plaintexts únicos**, **5.032.084** janelas de 32 B nas duas ordens + hex64/WIF, contra os **dois** h160 | **0 hits**; semantic 0, nested 0, EBCDIC≥0,75 0; printable máx **0,557** |
| H3 bits binários | L83/L84 × polaridade × ordem como inteiro binário: 56 senhas, 336 decifrações, 64 privkeys | 0 hits duros, 2 paddings (esperado 0,2), 0 no oráculo |
| H4 look-elsewhere | 30 sub-famílias; z contra o binomial exato p₀ = Σ₁¹⁶256⁻ᵏ ≈ 1/255 | máx \|z\| = 2,23 (esperado ~2,5 em 30 testes), p Šidák = **0,54** → ruído |
| H5 nulo da extensão | 100 réplicas × ~272 k senhas, forma preservada | z ∈ [−2,24, +0,52]; recontagem do padding **idêntica** ao log dele |

## Erros encontrados (nenhum muda o veredito)

1. **Oráculo cego para metade do prêmio.** O agente declarou "privkeys testadas contra a pubkey do
   prêmio" — `G.priv_hit`/`fast_priv_scan`/`O.check_privkey` só comparam com 1GSMG (`TARGET_H160`
   é o h160 do próprio 1GSMG). O `critico_rab.py` diz "h160 dos DOIS endereços" e chama
   `O.check_privkey`, que também só testa 1GSMG: a afirmação dele é **falsa**. Além disso
   `fast_priv_scan` varre só a ordem direta. Corrigido aqui (253 k chaves + 5,03 M janelas, 0).
2. **"184 objetos nomeados" é contagem inflada.** São 168 entradas de texto + 16 numéricas, mas o
   operador ignora caixa e não-letras: **152** objetos de texto distintos (157 contando o `split`).
   "10 formas número→senha" são **8** distintas (`zmethod` ≡ `be_bytes`, e o mesmo par sob sha256).
   O número de **senhas únicas (9.722) e privkeys (10.994) está correto** — a dedup salva a conta.
3. **`bitsL83 = bitsL84` é falso** (`rab_a1z26.py` l. 107, com `assert` que apenas reafirma a
   própria premissa). `BITS[83] = …0011`, provado em `solver/primos_2026_09_17/matrixsumlist_struct__msl_struct.py`.
   Logo o passo `yellowblueprimes` entrou no operador **só na segmentação L84**, com 2 das 5
   seleções de cor compatíveis. Já fechado pelo `critico_rab_l83.py` (7.172 senhas, 0 hits),
   re-varrido aqui contra os dois alvos.
4. **Bits nunca lidos como binário** (só como dígitos decimais). Fechado aqui: 0.
5. O `critico.jsonl` do crítico anterior tem NULs no início (truncamento concorrente): os eventos
   `repro`/`revarredura` se perderam e o `nulo_extensao` nunca rodou. Reconstruí ambos (H1, H5).
   **O arquivo não foi tocado** (mtime/tamanho antes e depois em `mtime_antes.txt`).

## Cobertura real sustentada

União verificada das quatro rodadas: **230.506 senhas únicas** (o conjunto do agente é subconjunto
próprio das duas extensões) = **1.383.036 decifrações AES-256-CBC** (3 blobs × 2 KDF), **253.159
privkeys** contra **dois** endereços em comp+uncomp, **5.306 plaintexts** com padding válido
re-varridos em **5,03 M** janelas de 32 B nas duas ordens. Mais 56 senhas/64 privkeys da leitura
binária. **0 hits duros em tudo.** Padding indistinguível de 1/255 em 30 sub-famílias (Šidák 0,54).

## Fora do escopo (declarado)

Encadeamento RAB(RAB(x)) além do `z_method` já testado; o número como **parâmetro** (índice,
chave de transposição, deslocamento) em vez de material de senha; agrupamentos não contíguos das 23
palavras; resíduo de `dbbi`/`faed` como entrada (colide com ENDGAME §4B/§6); KDF/cifra fora de
EVP-MD5/SHA256 + aes-256-cbc (ENDGAME §4D).
