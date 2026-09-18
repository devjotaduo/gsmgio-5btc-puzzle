# Crítico adversarial — família "sete_entrelacados" (entrelaçamento dos 7 operandos de nível-senha)

**Data:** 2026-09-17 · **Alvo da crítica:** campanha `familia3_entrelacamento` (atacante) e o crítico
parcial `critico_familia3_entrelacamento` (morreu no meio; o que ficou pronto foi reaproveitado e
reconferido). **Veredito: CONFIRMADO_NEGATIVO** (com uma correção de contagem e uma correção de
oráculo que valem para o repositório inteiro).

Scripts: `solver/operador_ensinado_2026_09_17/critico_sete_final.py` (stages `verif`, `dedup`,
`retro`, `o5up`), `critico_sete_extra.py` (stages `cosmic`, `extra`),
`critico_sete_estatistica.py` (auditoria fechada do z), `critico_sete_analise_log.py`,
`critico_sete_janelas/` (scanner Go de janelas de 32 B nas DUAS chaves do prêmio).

## Hipótese adversarial (escrita antes de codar)

- **H1** — a cobertura "9,1 M materiais" é *distinta por tarefa*, não global: o número real é menor.
- **H2** — o z=+2,71 é artefato do denominador (a regra de `G.unpad` aceita padding 1..16, logo
  p = Σ 256⁻ʲ = 1/255, não 1/256); duplicatas de material só alteram a variância.
- **H3** — o oráculo do atacante (`G.priv_hit`) testa **só** o 1GSMG; o segundo endereço do prêmio
  (17ucy, h160 `4bc46844…`) nunca foi testado, nem por ele nem pelo kit.
- **H4** — fechadas as lacunas declaradas e re-varridos todos os plaintexts logados com o oráculo
  completo e as duas chaves, o resultado continua 0.

Todas as quatro se confirmaram. H1 e H3 exigem correção do que ele escreveu; H2 e H4 confirmam o
negativo dele.

## Controles

- **Positivo (em toda etapa):** fase 2 abre com `sha256hex("causality")` sob EVP-SHA256 →
  `The ironic 2name of the keymakers trying to protect`. EVP e unpad **reimplementados** aqui com
  `hashlib` puro — um bug do kit não passa nas duas pontas.
- **Entrelaçamento reimplementado** (terceira implementação independente: o atacante usou fatias de
  blocos, o crítico anterior `zip`, esta usa `zip_longest`), com autoteste de `tranca`, das máscaras
  de inversão e das colisões conhecidas (4320/2520/5040).
- **Oráculo:** privkey de 32 B → `1GSMG` (pubkey `04f4d1bb…`) **ou** `17ucy` (h160 `4bc46844…`,
  comprimida e não comprimida); plaintext com ≥85 % ASCII, WIF/hex64 plausível, blob `Salted__`
  aninhado ou assinatura EBCDIC cp273 ≥ 0,75. **Padding válido sozinho é ruído** e não conta em lugar
  nenhum. Autoteste com positivos sintéticos nos dois ramos (chave conhecida posta como alvo) e
  rejeição de 0 e de escalares ≥ n.
- **Go ↔ Python:** o scanner Go valida contra valores do coincurve (`sha256("teste")`, chave 1),
  confere que `h160(pubkey do prêmio) == a9553269…` (o h160 do 1GSMG) e acha chave embutida em
  janela direta e invertida num buffer sintético.

## 1. Reprodução por amostra — e por um terço inteiro da campanha

| o que | resultado |
|---|---|
| 10 tarefas amostradas (S0 k1 pad/trunc, k2 rev127 lo, rev45, rev100, S_todos_hash k3, S_p3_partes k4, S_joins_hash k2, S_url_hash k3, S_lastword_3 k4) | `n_pw` **e o conjunto de `pt_sha`** idênticos aos do log dele — não só as contagens (557.280 AES) |
| as 1.904 tarefas, contagem de materiais | 9.108.000, **zero** tarefas divergentes |
| **todas as 143.225 células COSMIC das 1.904 tarefas, regeneradas** | 36.432.000 AES; 143.225 paddings — exatamente os dele; **zero** tarefas com conjunto de `pt_sha` divergente |
| integridade do log | dos 428.706 registros dele, os **285.481 não truncados** (SMALL 142.606 + TAIL32 142.875) têm `len` e `pt_sha` conferindo com o `hex`: **0 falhas** |

**Fração de fato reproduzida: 33,3 % das 109,3 M decifrações byte a byte** (todo o ramo COSMIC,
regenerado do zero com EVP/AES próprios), mais 10 tarefas completas dos ramos SMALL/TAIL32, mais a
contagem de materiais de 100 % das tarefas. Não reproduzi byte a byte os ramos SMALL/TAIL32 das
1.894 tarefas restantes — mas eles estão integralmente logados e foram re-varridos (§6).

## 2. O z global de +2,71 é artefato do denominador — conta fechada

A regra de `G.unpad` aceita comprimento de padding de 1 a 16, logo

    p = Σ_{j=1..16} 256^-j = (1 - 256^-16)/255 = 1/255 = 0,00392156862…  (e não 1/256 = 0,00390625)

| | valor |
|---|---|
| esperado sob 1/255 | 428.611,8 |
| observado | 428.706 |
| desvio | **+94,2** (σ = 653,4) |
| **z correto** | **+0,144** |
| z sob 1/256 (o dele) | +2,712 — viés puro do denominador: **+2,568** |

O **histograma de comprimentos de padding do log dele decide sozinho**, sem rodar nada:

| padding | observado | esperado (geométrico) |
|---|---|---|
| 1 byte | 427.022 | 426.937,5 |
| 2 bytes | 1.676 | 1.667,7 |
| 3 bytes | 8 | 6,5 |

χ² = 0,40. O "excesso" de 1.768,5 sobre n/256 é 1.674,3 de cauda j≥2 + 94 de ruído. Não sobra sinal.

**Duplicatas não explicam nada, e ele as tinha reportado como cobertura.** Os 9.108.000 materiais
distintos-por-tarefa são **8.835.840 globalmente distintos** (inflação 1,0308): 70.560 aparecem em 2
tarefas, 40.320 em 3 e 40.320 em 4 (conjuntos já minúsculos colapsam `lo`≡`as`; conjuntos de fios
equicomprimentos colapsam `pad`≡`trunc`). O efeito é só na variância — Var = 12·p(1−p)·Σmᵢ²,
inflação 1,0952 — e o z corrigido por duplicatas é **+0,138**, ainda nulo.

**Dependência entre KDFs:** não há. As 12 células (3 blobs × 2 KDF × 2 formas) dão χ² = 13,43 com 11
gl (**p = 0,27**), com esperado 35.717,6 por célula. SHA256 e MD5 sobre a mesma senha produzem
chaves independentes; `raw` e `sha256hex` são senhas diferentes. Nenhuma célula puxa o total.

**Teto de `printable` (cauda binomial exata, p = 95/256 por byte):** em 142.606 registros SMALL de
79 B, o maior k com esperança ≥ 1 é 49/79 = **0,620**; o observado 0,646 (51/79) tem esperança 0,099
(≈ 9 % de chance de aparecer). Em TAIL32, 0,633 tem esperança 0,30. Ou seja: o teto que ele propôs
(0,62–0,65) está certo em magnitude, e os 12 plaintexts com printable ≥ 0,60 são cauda esperada. Em
COSMIC, os 143.225 plaintexts **inteiros** (1.327 B) que regenerei têm printable máximo **0,428** e
assinatura EBCDIC máxima 0,196 — abaixo do teto 0,436 que ele citou.

## 3. Auditoria do oráculo — uma falha real

1. **O segundo endereço do prêmio nunca foi testado.** `G.priv_hit` → `oracles.check_privkey` compara
   com `PRIZE_ADDR` (1GSMG) e `TARGET_H160` = `a9553269…`, que é o h160 **do próprio 1GSMG**. O
   17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa (h160 `4bc46844…`, 3,751 BTC) está **fora** do oráculo do kit.
   Todo o braço privkey dele (2,11 M chaves) cobriu uma só das duas chaves. Refiz **9.108.000**
   escalares testando as duas: 0 hits. (Ele também não varreu privkey em k∈{3,4} nem na fase B: essa
   lacuna some, porque testei o escalar de **todo** material das 1.904 tarefas.)
2. **Privkey dentro do plaintext nunca foi procurada.** `G.semantic` não varre janelas de 32 B; o
   `v3_interleave.py` da rodada anterior varria. Fechado aqui: 84,56 M janelas (duas ordens de byte,
   duas chaves) sobre os 983.620 plaintexts logados.
3. **O log do COSMIC é truncado em 64 B** (143.225/143.225 registros) quando printable < 0,50 — logo
   nenhuma varredura retroativa sobre o arquivo dele consegue ver o plaintext COSMIC inteiro. Só se
   fecha regenerando, que é o que a etapa `cosmic` faz.
4. **Correto no que ele afirmou:** a KDF (EVP-SHA256 primária, MD5 secundária), os salts dos três
   blobs, o controle positivo da fase 2, o dedup por tarefa, a armadilha estrutural `O3[:9] == O2`
   (colapso 5040→2520 no modo truncado, →4320 no preenchido) e os asserts de integridade dos
   operandos. O `printable` como triagem nunca foi usado como prova.

## 4. Conjunto de operandos vs. a rodada anterior — o que é cobertura nova

- **Entrelaçamento round-robin anterior** (`_work/frontier_2026-09-17/rodada1_scripts/critic/v3_interleave.py`):
  9 tokens de roadmap/página (`yellowblueprimes, matrixsumlist, lastwordsbeforearchichoice, yinyang,
  thispassword, enter, sha256, anstoo, ourfirsthintisyourlastcommand`), k=1, permutações de tamanho
  2,3,4,5,7, só `zip_longest`, sem inversão e sem caixa. **Interseção com os 7 do atlas: vazia.**
  A afirmação do atacante está **correta** — verificada elemento a elemento.
- **Mas** a campanha "SEVEN INTERTWINED" do frontier (`seven_intertwined.py`) usava um pool de 16
  tokens que contém `causality` e `thematrixhasyou` — **2 dos 7** operandos do atlas. Lá a operação
  era concatenação / XOR de sha256 / sha256 encadeado, **nunca entrelaçamento**, e os outros cinco
  operandos (as junções de 227 B e 62 B, `theflowerblossoms…`, a URL, título+endereço) não aparecem.
  Então a linha de `ENDGAME.md` §4-C ("seven intertwined … entrelaçado") de fato bloqueava uma
  família que não fora testada; a correção de mapa que ele pediu procede, com esta nuance.
- **Cobertura genuinamente nova desta família:** entrelaçamento dos operandos de *nível-senha*;
  blocos k = 2,3,4 (antes só k=1); as 5040 ordens completas de 7 (antes subconjuntos de um pool de
  9); política truncar-no-mais-curto; inversão por operando; caixa; 28 variantes de conjunto.

## 5. Lacunas declaradas — o que completei

| lacuna declarada | quem fechou | cobertura | hits |
|---|---|---|---|
| (b) braço privkey só em k∈{1,2} da fase A | **este crítico** | 9.108.000 escalares, **duas chaves** | 0 |
| (f) formas fora de {cru, sha256hex} | crítico anterior (reconferido: log re-varrido aqui) | HEXUP, SHA2X2, RAW32 — 76,1 M AES, 298.283 pads | 0 |
| (c) k ≥ 5 | crítico anterior (idem) | k ∈ {5..9}, 65,4 M AES, 5,45 M privkeys, 256.631 pads | 0 |
| **(e) caixa fora de {como está, minúsculo}** | **este crítico** | operando (5) **verbatim `THEMATRIXHASYOU`** (README l. 538 — a forma que o puzzle escreve; o ramo "como está" dele usava minúsculo, então essa forma nunca entrou em material nenhum): fases A+B de S0, 520 tarefas, 2.513.880 materiais, **30,2 M AES**, 117.794 pads, privkey nas duas chaves | 0 |
| oráculo completo no COSMIC inteiro | **este crítico** | 143.225 plaintexts de 1.327 B regenerados | 0 |

O pedaço escolhido como mais valioso foi (e): o puzzle escreve `THEMATRIXHASYOU` e
`GSMGIO5BTCPUZZLECHALLENGE…` em maiúsculas, e a caixa é a única dimensão em que o atacante usou uma
forma **editada** do operando em vez da verbatim. Deu zero.

## 6. Re-varredura de todos os paddings com o oráculo completo e as duas chaves

| fonte | plaintexts | resultado |
|---|---|---|
| `familia3_entrelacamento/paddings.jsonl.gz` (atacante) | 428.706 | 0 |
| `critico_familia3.../pads_formas_novas.jsonl.gz` | 298.283 | 0 |
| `critico_familia3.../pads_k59.jsonl.gz` | 256.631 | 0 |
| **total** | **983.620** | **0 achados** |

84.562.790 janelas de 32 B (duas ordens, duas chaves), mais hex64/WIF/`Salted__`/EBCDIC/ASCII≥85 %
em cada plaintext; 0 falhas de integridade; EBCDIC máximo 0,48. 18 processos, 628 s.

O `printable` máximo da re-varredura, 0,672, **é artefato da truncagem**: os três máximos por fonte
(0,656 / 0,672 / 0,672) são todos prefixos COSMIC de 64 B, e o campo `printable` do próprio log
mostra que os plaintexts **inteiros** correspondentes têm 0,384 e 0,389 — ruído comum de 1.327 B.
Como prefixo de 64 B, 43/64 tem cauda 1,03·10⁻⁶ e esperança ≈ 0,44 nos ~430 k registros COSMIC das
três fontes: exatamente o que o acaso entrega. Nenhuma leitura de "printable alto" sobrevive quando
se olha o plaintext inteiro.

Como o COSMIC vem truncado no log, o ramo COSMIC foi **regenerado** (143.225 plaintexts inteiros) e
varrido à parte, com o scanner Go (`critico_sete_janelas/`) sobre 371,5 M janelas.

## 7. O que este negativo NÃO fecha

O mesmo que ele declarou, menos o que caiu acima: entrelaçamento não-round-robin (agenda fixa,
ordem por comprimento, nível de bit); blocos de tamanho misto por fio; as 126 máscaras intermediárias
de inversão fora de S0/k∈{1,2} (e, em S0, fora de k∈{1,2}); conjuntos de sete que dependam de
material ainda não decodificado (`dbbi`, `faed`, o resíduo de 61 símbolos); a leitura em que "seven
intertwined passwords" descreve a **estrutura** do já resolvido em vez de uma operação; o
entrelaçamento como etapa intermediária; qualquer coisa fora de `openssl enc -aes-256-cbc -pass pass:`
com EVP-SHA256/MD5. Nada aqui toca o lead aberto de `ENDGAME.md` §6.

## 8. Recomendações de mapa (valem para toda campanha futura)

1. **Fixar a expectativa de padding em Σ_{j=1..16} 256⁻ʲ = 1/255.** Contra 1/256, toda campanha com
   n ≳ 10⁸ nasce com z ≈ +2,6 fabricado. (O atacante já apontou isso; aqui fica **provado** pelo
   histograma de comprimentos do próprio log dele, não só por argumento.)
2. **Corrigir `oracles.check_privkey` para testar os DOIS endereços do prêmio.** Enquanto o kit só
   testar o 1GSMG, todo braço privkey do repositório cobre metade do alvo. (Existe
   `solver/operador_ensinado_2026_09_17/oraculo_dois_alvos.py`, de outro agente; o kit em si segue
   incompleto.)
3. **Reportar cobertura globalmente distinta**, não distinta-por-tarefa: aqui a diferença foi 3,1 %,
   mas em famílias com mais simetria pode ser grande.
4. **Não logar plaintext truncado sem guardar como regenerá-lo.** Os 64 B do COSMIC custaram uma
   regeneração inteira (36,4 M AES) para permitir a varredura retroativa; os logs do crítico anterior
   (`pads_k59`) sequer registram o conjunto, então seus registros COSMIC não são regeneráveis.

## Números finais

| | |
|---|---|
| materiais verificados (contagem) | 9.108.000 por tarefa / **8.835.840 globalmente distintos** |
| AES reproduzidas byte a byte | **36.432.000** (todo o COSMIC) + 557.280 (10 tarefas) |
| AES novas desta crítica | 30.166.560 (o5up verbatim) |
| privkeys testadas nas **duas** chaves | 9.108.000 + 2.513.880 = **11.621.880** |
| janelas de 32 B varridas (duas ordens, duas chaves) | 84.562.790 (logs) + 371,5 M (COSMIC regenerado) |
| plaintexts re-varridos com oráculo completo | 983.620 |
| **hits duros** | **0** |
