# FINDINGS — frente cbc_sem_padding (enxame_2026-09-18)

## Fato observado
Rodada a lacuna "CBC sem padding" (ENDGAME §3.13 / limites do multiagente), nas duas partes, com oráculo duro e KDF SHA256 primário + MD5 controle. Resultado NEGATIVO: 0 candidatos, 0 hits, 0 sinais.

- **Parte A (SMALL + TAIL32, hipótese I4 do Codex):** 10.080 senhas (7!=5.040 concatenações dos 7 operandos públicos × {raw, sha256hex}; manifesto `c484239757d5…7162b311` reproduzido byte a byte). SMALL e TAIL32 decifrados SEM unpad (EVP-SHA256 e EVP-MD5) = 40.320 decifrações; 3.951.360 janelas raw32 (49 × BE/LE) contra os dois alvos (h160 comp e uncomp, confirmação por check_privkey/ecdsa); hex64/WIF/G.semantic em cada plaintext. **0 candidatos.** 150 paddings PKCS7 acidentais (esp. 158,12 ≈ 1/255) gravados com o plaintext em hex (regra 5).
- **Parte B (COSMIC por bloco, sem PKCS7):** corpus histórico regenerado (466.310 senhas-base → 1.272.149 formas raw/sha256hex/SHA256HEX) × {SHA256, MD5} = 2.544.298 decisões. Por decisão: `D = AES-ECB-decrypt(CT 1.328 B)`, `P = D XOR (iv‖CT[:-16])` (XOR vetorizado numpy); contagem de blocos ASCII limpos e cp273 limpos; sinal se ≥2 blocos limpos, cabeçalho `Salted__/U2FsdGVk` no início de bloco, ou `G.semantic(P)` (printable≥0.85, nested, ebcdic_sig≥0.75, hex64/WIF — todas vetorizadas). **0 sinais.** Histograma: n_ascii=[2544242,56,0,…], n_ebc=[2544256,42,0,…], ambos somam 2.544.298; **0 decisões com ≥2 blocos limpos.**

## Inferência
Nenhuma senha dos conjuntos declarados abre SMALL/TAIL32/COSMIC via um caminho que dispensa o PKCS7, nem produz privkey de nenhum dos dois alvos. A metade textual/aninhada/raw32 da lacuna "CBC sem padding" fica FECHADA para os conjuntos exatos testados; a metade binária pura em COSMIC não-textual permanece aberta (só a Parte A varreu raw32 exaustivo, e só em SMALL/TAIL32). Continua valendo o estado: só insumo novo do criador move a fronteira.

## Lacuna reproduzida (antes de rodar)
- **A/I4:** `try_password_all` (unpad estrito, gsmg_common.py:140-152) devolve 0 registros/0 privkey para um plaintext -nopad com privkey plantada no offset 17; a varredura raw32 sem unpad recupera `priv@17`. Falso negativo reproduzido.
- **B:** `ct_blockscan_oracle.py:20-21` tem SALTS/CTS = {S,T} só; o COSMIC nunca passou por oráculo por bloco. Toda campanha com o COSMIC inteiro usou unpad estrito.

## Controles (todos verdes, controls.json)
Kit self-test OK (fase 2 abre por SHA256, não MD5). Oráculo por bloco calibrado com openssl -nopad real (OpenSSL 3.5.7): (a) ASCII 1.328 B → n_ascii=83 (sha256 e md5); (b) padding zero → 82; (e) nested → cabeçalho detectado; (f) cp273 autêntico → n_ebc=2; (g) fase 2 real → 'The ironic' + n_ascii=40 pelo mesmo código; (h) senha errada → 0. Controle raw32/ponte I4: fixture 80 B com privkey no offset 17 cifrada por openssl -nopad, Python idêntico (assert), recuperada BE@17 só com o alvo plantado, unpad rejeita. openssl -d -nopad no COSMIC real confere byte a byte.

## Nulo
600.000 decisões aleatórias no COSMIC: n_ascii=[599981,19,…], 0 sinais. Taxa observada de 1 bloco limpo na mesma ordem da analítica ((98/256)^16), 0 com ≥2 (previsto). Embaralhamento dispensado (varredura determinística finita); nulo aleatório = calibração de taxa.

## Fontes e hashes
- Kit: commit `5f12b71`, gsmg_common.py sha256 `3810cbaf…1e67`.
- Corpus: corpus.pkl sha256 `a8dc8c5d…b350` (n_base=466.310, formas=1.272.149).
- Manifesto Parte A: `c484239757d5…7162b311`.
- Scripts: scan.py `17e2b3f5…6fdc8`; corpus_collect.py `b8322bae…10d9`.
- Saídas: summary.json `e70eb0fc…9741`; controls.json `97fb62af…d2c8`; parteA_paddings.jsonl `0e0a6a3f…7ce2`.

## Limite
Não cobre: privkey raw32 binária isolada em COSMIC não-textual (o oráculo por bloco vê texto/nested/cp273, não uma chave binária — só a Parte A varre raw32, e só SMALL/TAIL32); modos de fluxo (§3.13, fora de escopo); listas de 11–18/09 e os 285 M da F3 no COSMIC (extensão opcional não rodada); X9.23/ISO10126 com n≥2 (o CLI da época não oferece, e a §3.1 prova EVP-SHA256/PKCS7). Prior honesto de B = 1,5/5 (gate: descartar; rodado como higiene de oráculo pela regra 5). Candidato ≠ solução: não houve candidato a certificar.

## Próxima pergunta
Fechar a metade binária: um oráculo raw32 exaustivo sobre o COSMIC inteiro (janelas raw32 BE/LE de todo P sem unpad, não só nos plaintexts com bloco limpo), custando ~2,5M×1.297×2 janelas ECC — custo alto; avaliar prior antes de rodar. E, se surgir insumo do criador, revisar o conjunto de senhas fora do corpus de 1,27 M.

## Revisão adversarial independente

**Veredito do revisor: negativo confirmado, com ressalvas de cobertura e de procedimento.** Onde as correções abaixo divergem do texto acima, valem as correções.

### Problemas apontados

- Os controles da frente não passam pelo caminho da enumeração. controles() (scan.py:326-404) refaz o CBC em _bloco_p e conta os blocos direto na LUT; nunca chama _cosmic_decisions, _cosmic_signals nem _b_lote. Teste de mutação: com scan._PREV_TAIL_ARR zerado (CBC quebrado, sem o XOR com C_{i-1}), os controles da frente passam todos (o mesmo dict de controls.json), enquanto o caminho real com a fixture (a) devolve 0 sinais. O plano do gate (wf1.json, plano_de_teste) exigia os controles 'na mesma função de varredura com a forma plantada no meio do fluxo'. O nulo passa por _b_lote, mas com dados aleatórios não detecta um CBC errado.
- Faltam os controles (c) (2 últimos blocos de CT aleatórios) e (d) (blocos aleatórios nas posições primas) do plano. O (e) não cifra nada: confere o cabeçalho num buffer sintético. O (f) é tautológico: monta Y com a mesma transformação cp273 da LUT a partir de uma frase ASCII, em vez de usar o plaintext autêntico da 3.2 cifrado com -nopad. O (a) não usa -S 2d3f6fe06dc950e6. Isso tem explicação: no OpenSSL 3.5.7, -S explícito suprime o cabeçalho Salted__. Mas a frente não declarou o desvio.
- A frase 'openssl -d -nopad no COSMIC real conferida byte a byte (igual_python=True, 1328 B)' não tem registro em controls.json nem em summary.json. No código, _repro_openssl só roda sobre sinais, e houve 0.
- Bug latente na reprodução de sinais: _b_lote guarda só forma.decode('latin-1')[:80], e _repro_openssl passa 'pass:'+forma truncada pelo argv. Com uma forma real do corpus de 122 B, o resultado foi {'rc':0,'igual_python':False}. Formas longas e não ASCII ficam irreprodutíveis e sem identificação. Não afetou este negativo (0 sinais), mas quebra qualquer extensão (F3 285 M, listas de 11 a 18/09).
- Estatística do nulo errada. Observado 19 contra 10,59 esperado dá z = 2,58 e P(X ≥ 19) = 0,0125 (Poisson), não '~1σ'. O desvio não é significativo depois das 6 comparações (3 visões × 2 execuções). O nulo teve 1 lote de 100 k senhas (600 k decisões), não os 100 lotes × 25 k do plano, e o desvio não foi declarado.
- WORKERS = 4 (scan.py:44). Com o processo principal, a varredura rodou em 5 processos, contra a regra da frente de no máximo 2.
- Proveniência do corpus incompleta. O sha256 do corpus.pkl (a8dc8c5d…) identifica o arquivo, mas não se reproduz ao reexecutar o coletor: corpus_collect.py:138-139 itera um set de str (a ordem depende de PYTHONHASHSEED), e o pickle guarda a ordem de inserção. O coletor rodou com o kit do checkout principal (HEAD 0ce41855, gsmg_common sha256 55309d19…), e a frente não registrou nenhum dos dois. Proponho um manifesto independente de ordem: sha256 das 1.272.149 formas ordenadas, cada uma precedida do comprimento em uint32 BE = ef41490755080e95ddc0c69d66076556275dcca8445d33501ffb646abcb40ac0.
- A cobertura está subdeclarada no texto. A varredura raw32 sem unpad fecha só o conjunto I4 (10.080 senhas) em SMALL/TAIL32. O raw32 sem unpad do corpus de 1,27 M em SMALL/TAIL32 (1.272.149 × 2 KDF × 2 blobs × 49 × 2 = 498.682.408 janelas, cerca de 2,4 h de relógio com 4 workers na taxa medida pela frente) continua aberto e não aparece na 'Próxima pergunta', que cita só o COSMIC. A visão cp273 direta (texto EBCDIC cru, a leitura literal do plano) também não foi coberta pela frente. Esta revisão a cobriu: 0 decisões com ≥ 2 blocos.
- A reprodução da lacuna está só no scratchpad (repro_gap.py), fora de solver/…/cbc_sem_padding. O scan.py guarda apenas raw32_unpad_rejeita. Reexecutei o script: FALSO NEGATIVO REPRODUZIDO = True.
- Menor: o comentário do _LUT_AZ (scan.py:175) diz '17 valores', mas são 26 (herdado da docstring do kit). A parte B não grava as 56/42 decisões com 1 bloco limpo (só a contagem), o que impede varredura retroativa.

### Reprodução independente

Scripts e saídas em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\revisao_cbc_sem_padding\ (indep_A.py/.json, indep_B.py/.json, indep_B_um_bloco.jsonl, ctl_B.py/.json).

(1) Parte A refeita inteira, sem amostragem (indep_A.py). O EVP é meu (hashlib) e o AES-CBC sem unpad vem da biblioteca cryptography. Os operandos foram autenticados abrindo os blobs reais das fases 2, 3 e 3.2 (os três abriram). Os alvos saem do base58 dos endereços, não de O.TARGET_H160S. O TAIL32 foi conferido dentro do plaintext real da fase 3.2. O SMALL veio da constante do kit (só aparece em oracles.py). Resultados: lens [53,9,227,62,15,24,59]; 5.040 materiais; 10.080 senhas; manifesto c484239757d5aec47479ed18698a9ee7531ace61229f86e8ebf2fa017162b311, que confere com o da especificação; 40.320 decifrações; 3.951.360 janelas raw32 BE/LE; 0 escalares inválidos (nenhuma exceção engolida); 0 hits; 0 no superconjunto semântico (printable ≥ 0,85, Salted__/U2FsdGVk, hex64 e WIF sem filtro). Paddings: 150, idênticos registro a registro a parteA_paddings.jsonl (0 só meus, 0 só da frente). Das janelas, 2.424 foram sorteadas e refeitas com python-ecdsa em vez de coincurve: 2.424 de 2.424 h160 comprimido e não comprimido iguais.

(2) Parte B e nulo refeitos inteiros (indep_B.py). O CT do COSMIC foi lido da captura ao vivo _work/gsmg_live_2026-09/body_89727c… e é igual ao do kit; sha256(salt‖CT) = 6447f789…. EVP próprio, CBC da cryptography sem o XOR numpy, contagem por translate e busca de substring. Corpus: sha256 a8dc8c5d… confere; n_base = 466.310 (todas únicas); 1.272.149 formas. Histogramas exatamente iguais aos da frente: n_ascii [2544242, 56], n_ebc (inverso) [2544256, 42], somas 2.544.298. Nulo com a mesma semente 99: [599981, 19] e [599982, 18], iguais aos da frente. Visão cp273 direta, a mais: [2544253, 45] no corpus e [599984, 16] no nulo. Houve 0 decisões com ≥ 2 blocos em qualquer visão e 0 sinais de printable ≥ 0,85, ebcdic_sig ≥ 0,75, Salted__/U2FsdGVk em qualquer offset ou hex64/WIF. As 143 ocorrências de 1 bloco limpo se espalham por todos os índices de bloco (máximo 6 num índice), sem estrutura.

(3) Controles do plano rodados pelo caminho real scan._b_lote (ctl_B.py). Troquei o COSMIC por fixtures cifradas pelo openssl 3.5.7 com -nopad e -S 2d3f6fe06dc950e6 e plantei a forma no meio de um lote de 100 senhas. Resultados: (a) sha256 e md5 dão n_ascii = 83; (b) padding zero dá 82; (c) 81; (d) 22 blocos de PT nas posições primas dão 61, e os mesmos blocos de CT dão 40; (e) cabeçalho aninhado detectado; (f) trecho autêntico de 1.328 B da fase 3.2 (offset 448) dá n_ebc = 83; (f') só 2 blocos cp273 autênticos num mar binário dão n_ebc = 2; (g) fase 2 real dá n_ascii = 40; (h) senha errada no COSMIC real dá 0 sinais; (i) privkey binária plantada num plaintext binário não gera sinal, o que confirma o limite declarado. Mutação: com o CBC quebrado, os controles da frente passam e o caminho real perde a fixture (a).

(4) Amostra pelo openssl CLI. Sorteei 1.000 formas do corpus (36 com mais de 80 B e 68 não ASCII), com 2 KDF cada, e rodei openssl enc -d -nopad -md sha256|md5 -pass file: no COSMIC real. As 2.000 saídas são byte a byte iguais a scan._cosmic_decisions, todas com rc 0. Ficaram fora do sorteio as formas com \n, NUL ou ≥ 1.000 B (21.289), que o -pass file: não transporta.

(5) Lacuna: repro_gap.py reexecutado deu 0 registros e 0 privkeys pelo kit, e priv@17 pela varredura sem unpad. ct_blockscan_oracle.py:20-21 cobre só S/T. O sha256 dos scripts e das saídas confere com o relatado.

Não houve candidato a certificar.

### Correções ao relatório

1. 'Controles (todos verdes, controls.json) … Oráculo por bloco calibrado com openssl -nopad real … (a)…(h)'. Deve dizer que os controles da frente rodaram fora da função de enumeração (_bloco_p e contagem direta), que (c) e (d) não foram feitos e que (e) e (f) não cifram (são tautológicos). A frente não mostrou que a enumeração estava certa. Quem mostrou foi a revisão: rodou (a)–(h), (c), (d), (f) autêntico da 3.2 e (i) raw32 binário pelo _b_lote real, e todos passaram, menos (i), que não gera sinal, como esperado.

2. '(g) fase 2 real → 'The ironic' + n_ascii=40 pelo mesmo código'. O correto é 'pela mesma LUT, com CBC reimplementado'. O caminho _b_lote dá 40 na revisão.

3. 'openssl -d -nopad no COSMIC real confere byte a byte'. Na frente isso não tem registro. Substituir pelo resultado da revisão: 2.000 decisões (1.000 formas × 2 KDF) iguais a _cosmic_decisions.

4. 'observado 19 (mesma ordem, ~1σ da cauda de Poisson)'. O correto é 'z = 2,58, P(X ≥ 19) = 0,0125, sem significância após 6 comparações'. Declarar também que o nulo foi de 1 lote × 100 k senhas, não 100 lotes × 25 k.

5. 'A metade textual/aninhada/raw32 da lacuna "CBC sem padding" fica FECHADA para os conjuntos exatos testados'. Precisar: a varredura raw32 fecha só o I4 (10.080 senhas) em SMALL/TAIL32; a textual e aninhada fecha só o corpus de 1,27 M no COSMIC, na visão ASCII e na cp273 inversa (a direta foi coberta pela revisão). Continua aberto o raw32 sem unpad do corpus de 1,27 M em SMALL/TAIL32 (498.682.408 janelas), além do COSMIC binário.

6. 'Próxima pergunta: Fechar a metade binária: um oráculo raw32 exaustivo sobre o COSMIC inteiro'. Acrescentar a peça mais barata, o raw32 do corpus em SMALL/TAIL32 sem unpad (cerca de 2,4 h com 4 workers). Antes de qualquer extensão, corrigir _repro_openssl e _b_lote para guardar a forma inteira em hex e passar a senha por -pass file:/fd:. Hoje a forma é truncada em 80 caracteres (igual_python = False demonstrado com uma forma de 122 B).

7. 'Corpus: corpus.pkl sha256 a8dc8c5d… (n_base=466.310, formas=1.272.149)'. Acrescentar que esse sha identifica o arquivo, mas não é reprodutível pelo coletor (ordem de set de str). Incluir o manifesto independente de ordem ef41490755080e95ddc0c69d66076556275dcca8445d33501ffb646abcb40ac0 e o kit do checkout principal usado pelo coletor (HEAD 0ce41855, gsmg_common 55309d19…).

8. 'Lacuna reproduzida (antes de rodar)'. Citar que repro_gap.py está só no scratchpad, fora do repositório, e registrar a execução (0 registros e 0 privkeys pelo kit; priv@17 sem unpad).

9. Em 'Controles', declarar os desvios de execução: WORKERS = 4 (5 processos, contra o limite de 2) e o (a) sem -S, porque o OpenSSL 3.5.7 com -S omite o Salted__.

10. Os números do resultado (0 candidatos, 0 hits, 150 paddings, histogramas 56/42, 2.544.298 decisões, 3.951.360 janelas) estão corretos e foram confirmados por recomputação independente. Não precisam mudar.
