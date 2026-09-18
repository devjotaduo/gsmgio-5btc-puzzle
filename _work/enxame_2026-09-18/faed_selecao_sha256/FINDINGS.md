# FINDINGS — frente `faed_selecao_sha256` (enxame 2026-09-18, hipótese I2 do Codex Astra)

## Hipótese
Os argumentos de 32 B que `select_bits.materialize(do_bits=True, do_pw=False)` e
`select_bits.multibit` mandam a `pcheck` são material intermediário de senha. O recorte são os 23
seletores de `selections(FAED, 'faed')` sem prefixo `mod`/`mult`, na subsequência e na reversa
(conjunto U). A senha seria `sha256(u).hexdigest()`, e também `u` cru e SHA256HEX. A extensão
declarada acrescenta `u.hex()`. A senha abriria SMALL, COSMIC ou TAIL32, ou `u`/`sha256(u)` seria a
privkey de `1GSMG…` ou `17ucy…`. Falsifica-se por zero candidatos no oráculo duro.

## Fato observado
- **A lacuna existia e foi reproduzida.** Em `select_bits.py`, `pcheck` (linhas 36–49) só compara
  `format(False) == TGT`, com TGT = pubkey não comprimida de 1GSMG: não há AES nem 17ucy.
  `multibit` (317–326) só chama `pcheck`. O ramo reverso usa `do_pw=False` (linha 340). Com
  `do_pw`, `materialize` (174–224) só tenta `shahex(texto)`, o texto cru e `k0.hex()`.
- **O fluxo histórico instrumentado reconcilia com o log.** Rodei os `main()`/`main2()` reais com
  gravadores: NT = 512.996 / 652.435, idênticos aos `SUMMARY`/`SUMMARY2` do `select_bits.jsonl` do
  checkout principal. O ramo AES antigo fez 1.549 chamadas de senha (928 distintas), 0 delas no
  `main2`.
- **U foi regenerado exatamente como o Codex descreve.** São 50.988 ocorrências e 47.862 valores
  distintos, todos de 32 B. O sha256 das senhas sha256hex ordenadas é
  `85eec0d5…a209`, idêntico ao do Codex.
- **As senhas novas não se sobrepõem às antigas.** A sobreposição é 0 em raw, sha256hex e
  sha256HEX. Na extensão hex há 72 coincidências (`shahex(texto)` e `k0.hex()` antigos).
- **Resultado: 0 candidatos e 0 hits.** Foram 191.364 senhas únicas × 3 blobs × 2 KDF =
  **1.148.184 AES**, com 4.434 paddings contra 4.502,68 esperados (z = −1,03). Nenhum plaintext com
  padding tem sinal semântico: printable máx. 0,557, ebcdic_sig máx. 0,364, 0 blobs aninhados,
  0 privkeys embutidas. Os **95.724 testes de privkey** (u e sha256(u)) contra os dois alvos deram
  0; o único escalar inválido é u = 0.

## Inferência
Os 32 B materializados pelos 23 seletores principiados de FAED, nas formas raw, sha256hex,
SHA256HEX e hex, não são pré-imagem de senha dos três blobs nem privkey dos dois alvos. Os antigos
negativos de privkey desse recorte, que só valiam para 1GSMG, agora cobrem também 17ucy. O
resultado é negativo **só** neste recorte e não fecha a família "seleção → 32 B → senha" nas
demais fontes e seletores.

## Fontes e hashes
- HEAD `5f12b716a67763d7cd72aec3447a15c3015bf2d4`; kit `gsmg_common.py` `3810cbaf…1e67`;
  `comum.py` `0bea9880…c7a6`.
- `select_bits.py`: worktree (CRLF) `2178925e…14a1`; checkout principal (LF, mesmo conteúdo)
  `243146c4…804d`.
- Scripts: `solver/enxame_2026_09_18/faed_selecao_sha256/teste.py` `7c0bc672…0508` e
  `recontagem.py` `95f1ceae…6d49`.
- Saídas em `_work/enxame_2026-09-18/faed_selecao_sha256/`:
  - `summary.json` `346c8a7c…d589`
  - `controls.json` `62c51dc1…3346`
  - `paddings.jsonl` `231d7bea…8441` (4.434 registros com o plaintext em hex; local, ignorado
    pelo git)
  - `recontagem.json` `53c5cba7…6280` (local)
- U ordenado: `7f12f600ff84e6d641ad58a492795ff301b1ca5fd85f847f4d4f88cf0f7187c3`.
- Hipótese de origem: `_work/codex_pair/20260918T072528Z_9808a238/response.json`, id I2.

## Cobertura exata
| Item | Quantidade |
|---|---|
| Seletores (FAED, sem mod/mult) × {subsequência, reversa} | 23 × 2 |
| Ocorrências de argumentos de pcheck / U distinto | 50.988 / 47.862 |
| Senhas raw / sha256hex / SHA256HEX / hex (extensão) | 47.862 / 47.862 / 47.862 / 47.778 (84 hex = sha256hex de outro u) |
| Senhas únicas × blobs × KDF | 191.364 × 3 × 2 = 1.148.184 AES (861.516 só nas formas pedidas) |
| Privkeys (u, sha256(u)) × {1GSMG, 17ucy} × {comp, uncomp} | 95.724 (1 inválida: u = 0) |
| Paddings (observado / esperado) | 4.434 / 4.502,68 (z = −1,03); 24 células em `summary.json` |

Uma recontagem independente (EVP com `hashlib`, último bloco AES-ECB com XOR manual) reproduz o
conjunto exato dos 4.434 (senha, blob, kdf).

## Controles
1. **Fase 2:** `C.controle_positivo()` abre com `sha256hex('causality')` pelo mesmo caminho de
   código.
2. **Privkey plantada:** K1 como u e sha256(K2) como alvos extras. `varrer_privkeys` acha
   exatamente os dois; sem plantio, 0. `O.check_privkey` acha K1; o `pcheck` antigo **não** acha
   (falso negativo do segundo alvo).
3. **Ponte:**
   - K fica em base 9 nas 104 posições primas de um faed sintético, e o gerador a recupera em
     `faed/primes_b0/b9@0`.
   - O openssl CLI 3.5.7 cifra um envelope com `sha256(K).hex` e `-md sha256` e o decifra igual.
   - Ramo novo: 193.723 senhas → **1 abertura** (sha256hex, KDF SHA256, marcada candidato).
   - Ramo antigo: os `main()`/`main2()` reais no mesmo faed sintético geram 932 senhas distintas
     → **0 aberturas**, e o `pcheck` antigo recebe K e devolve False.
4. **Reconciliação:** os NT do fluxo histórico batem com o log (512.996 / 652.435), e 508.349
   chamadas de `pcheck` + 3 × 1.549 chamadas de `try_pw` = 512.996.

## Nulo
- **Nulo casado:** 100 embaralhamentos de FAED com as contagens preservadas; U regenerado em cada
  um; sha256hex × SMALL/TAIL32 × SHA256/MD5. Observado 747; nulo 751,98 ± 27,35 (657–821);
  p(≥ obs) = 0,614; analítico 750,78.
- **Candidatos e privkeys:** N/A, porque a cobertura é determinística e finita e a decisão é pelo
  oráculo duro.

## Limites
- **Fora da cobertura:**
  - os argumentos de `pcheck` dos seletores mod/mult;
  - as fontes dbbi, faed_dbbi e dbbi_faed;
  - as janelas de 32 a 256 símbolos;
  - a "fase3" histórica (1.845.998 testes, script ausente do repositório; os rótulos no log mostram
    seletores por subconjunto de símbolos com as formas antigas de senha).

  No total, o select_bits mandou 1.160.784 argumentos a `pcheck`; aqui foram cobertos 50.988.
- **Derivações não testadas:** `sha256(u.hex())`, sha256 duplo como senha, `-K` cru, WIF de u, e
  outras cifras ou KDFs.
- **Reprodução por CLI:** a forma raw (binária) não se digita no openssl CLI; a reprodução por CLI
  só vale para as formas ASCII.
- **Nulo parcial:** o nulo casado não cobre COSMIC. A condição de prêmio de 17ucy não está
  confirmada.
- **Flutuações classificadas como ruído:**
  - COSMIC/MD5/hex com 233 contra 187,36 (z = 3,33; Bonferroni ×24 = 0,021; χ² das 24 células
    33,49 com 24 gl, p = 0,094). Os 233 são padding 0x01 de 233 senhas distintas, sem sinal
    semântico.
  - Envelope da ponte com z = −2,65, confirmado por recontagem.

## Próxima pergunta
Vale estender o mesmo teste a todos os argumentos de `pcheck` do select_bits (mod/mult, outras
fontes, janelas: cerca de 1,16 M ocorrências)? O custo seria de uns 4 min de relógio por forma, com
2 processos a ~2.800 senhas/s cada. A alternativa é declarar a família fechada pelo recorte
principiado. O prior desses seletores é menor sob a regra 4, e o próprio autor do script os excluiu
do braço AES.

## Revisão adversarial independente

**Veredito do revisor: negativo confirmado.** Onde as correções abaixo divergem do texto acima, valem as correções.

### Problemas apontados

- O recontagem.py da frente não é independente de biblioteca nem de gerador. Ele reusa T.gerar_ocorrencias e T.origem_por_forma do teste.py e a mesma AES do pycryptodome do kit; só o código de EVP e de padding é outro. Nesta revisão ele foi substituído por um gerador próprio e pela biblioteca cryptography, e o resultado foi o mesmo.
- O enquadramento como 'falso negativo' exagera. O ramo AES antigo nunca declarou testar sha256(u) como senha, e o ENDGAME §4-E já marca select_bits como 'parcial: o braço AES ficou ~200× mais fino'. A ponte vale por construção. As 932 senhas antigas (shahex(texto), texto, k0.hex) só coincidiriam com sha256(K).hex se K fosse o próprio texto. O pcheck devolve False para qualquer chave que não seja a de 1GSMG. A cegueira para 17ucy já estava registrada no ENDGAME §3.11. O que a frente mostrou é uma lacuna de cobertura real, não um bug no escopo declarado do ramo antigo.
- A inferência do findings_md não traz o modelo. O negativo depende de aes-256-cbc, EVP_BytesToKey de 1 iteração (SHA256 e MD5), padding PKCS7 válido e o oráculo semântico do kit. Um plaintext binário de etapa seguinte em SMALL/TAIL32 só seria marcado por blob aninhado, privkey embutida, hex64 ou WIF. Nesta revisão, sha256hex(plaintext) como senha e as janelas de 32 B como chave -K com IV zero deram 0 sinais.
- O nulo casado (100 embaralhamentos) mede só a taxa de padding e não tem poder contra a hipótese: uma abertura verdadeira somaria 1 padding entre ~750. Ele calibra a taxa e não testa a hipótese. O findings não diz isso.
- A contagem '95.724 testes de privkey' inclui u = 0, que é inválido. São 95.723 escalares válidos, cada um contra o h160 comprimido e o não comprimido dos dois alvos.
- Cosmético: a docstring de faed_sintetico no teste.py diz que K sai em 'b9/rpad', mas ele sai em 'faed/primes_b0/b9@0' (K tem 32 B e passa por scan_bytes). O controls.json e o findings estão certos.
- Ambiente: o C: chegou a 0 bytes livres durante a revisão (por volta das 08:40 locais) e depois voltou a ~4,9 GB. Isso não afetou os arquivos da frente, cujos hashes batem com o relatório. Outras frentes que gravavam naquele momento podem ter saída truncada e devem conferir.

### Reprodução independente

Todos os scripts estão em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\revisao_faed_selecao_sha256\ (gerador_indep.py, recontagem_cryptography.py, amostra_openssl.py, privkeys_semantica.py, ramo_antigo_indep.py, ponte_indep.py, encadeamento.py). Nenhum arquivo da frente foi editado.

(1) Hashes: todos os sha256 citados conferem com os arquivos em disco (select_bits.py 2178925e…, teste.py 7c0bc672…, recontagem.py 95f1ceae…, comum.py 0bea9880…, kit 3810cbaf…, paddings.jsonl 231d7bea…, summary 346c8a7c…, controls 62c51dc1…, recontagem.json 53c5cba7…). O select_bits do checkout principal (243146c4…) é idêntico byte a byte ao da worktree depois de CRLF→LF. O log histórico select_bits.jsonl tem SUMMARY 512.996, SUMMARY2 652.435 e SUMMARY3 1.845.998. A fase3 vem de um script ausente e os rótulos dela (sym±…/shahex|plain|hexpw) são das formas antigas. O log está intocado (mtime 2026-09-02), e nenhum arquivo versionado da worktree foi modificado.

(2) Lacuna: li o código. O pcheck (linhas 36-49) só compara format(False) == TGT, que é a pubkey de 1GSMG, e não tem AES. O multibit (317-326) só chama pcheck. A linha 340 usa do_pw=False. O materialize com do_pw só tenta shahex/plain de texto e dígitos e k0.hex(). Reimplementei o ramo antigo sem importar select_bits: 1.549 chamadas de try_pw, 928 distintas, sobreposição com as senhas novas raw 0, sha256hex 0, sha256HEX 0 e hex 72. É idêntico ao da frente.

(3) U: escrevi um gerador próprio que não importa select_bits nem teste.py e usa só os dados do kit. Deu 23 seletores, 50.988 ocorrências e 47.862 distintos, todos de 32 B. O sha256 do U ordenado é 7f12f600…87c3 e o das senhas sha256hex ordenadas é 85eec0d5…a209, os dois iguais aos da frente e do Codex. São 191.364 senhas únicas nas 4 formas (47.778 na forma hex).

(4) Recontagem completa com cryptography 46.0.7 e EVP próprio em hashlib: 1.148.184 AES deram 4.434 paddings. O conjunto (senha, blob, kdf) é idêntico ao paddings.jsonl, o plaintext completo é idêntico nos 4.434, e a forma e o u atribuídos também. COSMIC/MD5/hex tem 233. Recalculei a estatística: χ² das 24 células = 33,49 (p = 0,094), z máximo 3,34 (Bonferroni 0,020), z total −1,03. Os 233 vêm de 233 senhas e 233 u distintos, todos com padding 0x01. No total há 4.414 paddings de 1 byte e 20 de 2 bytes.

(5) openssl CLI 3.5.7 (Git for Windows): 1.199 senhas ASCII (1.000 sorteadas e 200 com padding gravado, 1 em comum) × 3 blobs × 2 KDF = 7.194 chamadas. Houve 211 rc=0, exatamente os 211 do jsonl, com 0 divergências de rc e 0 de plaintext.

(6) Privkeys: testei os 95.724 escalares (u e sha256(u)) com código próprio em coincurve contra o h160 dos dois endereços, decodificados do base58 por implementação própria (batem com O.TARGET_H160S). Deu 0 hits e 1 inválido (u = 0). Em 4.000 escalares sorteados, o python-ecdsa 0.19.2 deu h160 comprimido e não comprimido idênticos ao coincurve em 4.000/4.000, com 0 hits.

(7) Triagem semântica própria dos 4.434 plaintexts: printable máximo 0,557, maior sequência ASCII de 14, 0 Salted__/U2FsdGVk, 0 hex64, 0 WIF, letras em cp1140 no máximo 0,633 (bytes aleatórios do mesmo tamanho dão 0,658) e 0 privkeys embutidas dos dois alvos em todas as janelas de 32 B.

(8) Ponte refeita com o gerador próprio: U sintético de 48.452 valores contendo K, 193.723 senhas, 1.416 paddings no envelope (igual ao da frente) e exatamente 1 abertura (sha256hex, SHA256). O openssl CLI decifra o envelope com sha256(K).hex.

(9) Checagem extra, fora do escopo: usei os plaintexts com padding como material da etapa seguinte. sha256hex(plaintext) como senha: 26.604 AES, 129 paddings contra 104,3 esperados, distribuídos por igual entre as células; 5 controles aleatórios deram 95 a 118. Janelas de 32 B de SMALL/TAIL32 como chave -K com IV zero: 418.557 AES, 1.621 paddings contra 1.641,4. As duas deram 0 sinais semânticos.

Nenhum candidato nem hit; não há o que certificar.

### Correções ao relatório

1. "Uma recontagem independente (EVP com `hashlib`, último bloco AES-ECB com XOR manual) reproduz o conjunto exato dos 4.434 (senha, blob, kdf)." Trocar por: "Uma segunda implementação do teste de padding (EVP com hashlib e XOR manual, mas a mesma AES do pycryptodome e o mesmo gerador de U do teste.py) reproduz o conjunto. A revisão adversarial refez tudo com a biblioteca cryptography e um gerador próprio de U e obteve o mesmo conjunto dos 4.434 e os mesmos plaintexts."

2. Controles, item 2, "o `pcheck` antigo **não** acha (falso negativo do segundo alvo)", e item 3, "o `pcheck` antigo recebe K e devolve False". O mesmo vale para "(4) Falsos negativos mostrados por teste" no evidencia_lacuna. Trocar por "lacuna de cobertura demonstrada": o ramo AES antigo nunca declarou sha256(u) como senha (o ENDGAME §4-E já marca select_bits como parcial), a ponte vale por construção e a cegueira para 17ucy já estava registrada no §3.11. O pcheck devolve False para qualquer chave que não seja a de 1GSMG.

3. Inferência, "Os 32 B materializados pelos 23 seletores principiados de FAED, nas formas raw, sha256hex, SHA256HEX e hex, não são pré-imagem de senha dos três blobs nem privkey dos dois alvos." Acrescentar: "sob aes-256-cbc com EVP_BytesToKey de 1 iteração (SHA256/MD5), padding PKCS7 válido e o oráculo semântico do kit. Um plaintext binário de etapa seguinte em SMALL/TAIL32 só seria marcado por blob aninhado, privkey embutida, hex64 ou WIF. Os plaintexts ficam em paddings.jsonl para varredura retroativa, e a revisão testou sha256hex(plaintext) e as janelas como -K com IV zero, com 0 sinais."

4. "Os **95.724 testes de privkey** (u e sha256(u)) contra os dois alvos deram 0; o único escalar inválido é u = 0." Trocar por: "95.724 escalares (95.723 válidos; u = 0 é inválido e só o sha256 dele entrou), cada um contra o h160 comprimido e o não comprimido de 1GSMG e 17ucy: 0." Aplicar o mesmo ajuste à linha da tabela de cobertura.

5. "Os antigos negativos de privkey desse recorte, que só valiam para 1GSMG, agora cobrem também 17ucy." Acrescentar: "(u direto e sha256(u)); os demais argumentos de pcheck do select_bits (cerca de 1,11 M no main/main2 e os 1,85 M testes da fase3) continuam valendo só para 1GSMG."

6. Seção Nulo: acrescentar "O nulo calibra a taxa de padding e não tem poder contra a hipótese, porque uma abertura verdadeira somaria 1 padding entre ~750. A decisão é do oráculo duro."

7. "No total, o select_bits mandou 1.160.784 argumentos a `pcheck`; aqui foram cobertos 50.988." Trocar por: "O main() e o main2() do select_bits.py mandaram 1.160.784 argumentos a pcheck, fora a fase3 (1.845.998 testes de script ausente); aqui foram cobertos 50.988."

Todos os números restantes do findings_md foram reproduzidos exatamente e não precisam mudar: 50.988/47.862, 191.364 senhas, 1.148.184 AES, 4.434 paddings contra 4.502,68, as 24 células, 233 em COSMIC/MD5/hex, 1.549/928/72, NT 512.996/652.435, ponte 48.452/193.723/1.416/1 abertura e os hashes.
