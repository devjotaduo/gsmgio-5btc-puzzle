# Ideação e gate — enxame_2026-09-18

Sete lentes independentes propuseram hipóteses: seis do Claude (gramática das fases, roteiro literal, ferramentas online, dualidade e cores, auditoria de implementação, falas do criador) e o Codex Astra, via `tools/codex_pair.py`, somente leitura. Cada hipótese do Claude passou por um verificador adversarial de cobertura, prior e custo. Para seguir a teste, o gate exigia cobertura não integral, prior ≥ 3 (regra 4) e custo ≤ 2 h de CPU. As hipóteses do Codex foram a teste com a obrigação de reproduzir antes a lacuna alegada; as quatro reproduziram.

## Hipóteses das lentes do Claude: todas descartadas no gate

| id | Hipótese | Cobertura prévia | Prior | Motivo do descarte |
|---|---|---|---|---|
| `gramatica-hashthetext-2o-endereco` | HASHTHETEXT refeito no segundo endereço do prêmio (17ucy) | parcial | 2 | O `17ucy` só aparece como destino dos halvings a partir de 2020, depois de os blobs estarem publicados. A âncora é anacrônica. |
| `gramatica-cadeia-hex-fases` | Cadeia dos hex de senha das fases concatenados e re-hasheados | parcial | 2 | "Our first hint" está no singular, e nenhuma fase reutilizou senhas anteriores. |
| `gramatica-primeiro-igual-ultimo` | 'primeiro hint' (resposta da fase 2) emparelhado com 'último comando' (pass da 3.2) | parcial | 1 | A concatenação do par já tinha sido testada (`firstlast_grammar.py`, 48/48 candidatos). Resta o XOR, sem âncora no criador. |
| `roteiro-blocos-primos` | yellowblueprimes aplicado aos blocos CBC dos três blobs (blocos de índice primo são enchimento ou são o conteúdo), com oráculo que não depende do padding publicado | parcial | 2 | O núcleo já estava coberto em SMALL/TAIL32 por `ct_montage_attack.py` e pelo blockscan. |
| `roteiro-partes-fase3` | Gramática da fase 3 ('parts → sha-256 → password to enter') sobre as respostas dos passos 1–3 do roteiro: produto cartesiano nunca executado | parcial | 2 | Na fase 3, cada parte era a resposta única de um enigma. Aqui cada parte é um leque de interpretações que já deu negativo sozinho (3,3 M senhas). |
| `ferramentas-01` | VIC do dcode com alfabetos da gramática autenticada da 3.2.2 (letra repetida → '.') tirados dos cabeçalhos e rótulos da página, sobre o resíduo §6 | nenhuma | 2 | A frequência de dígitos de escape do resíduo (≤ 21 de 61) é incompatível com VIC de texto em inglês (média de 26,8 a 33,5). |
| `ferramentas-02` | VIC do dcode no modo 'With a numeric key' (soma mod 10) com as listas de somas da matriz como chave, seguida do checkerboard, sobre o resíduo §6 | nenhuma | 2 | Os componentes já tinham sido testados separadamente, e o conjunto custaria ~60 M decisões AES com prior baixo. |
| `dualidade-17ucy-primeira-peca` | Segunda porta = metade do prêmio: reverificar contra 17ucy os escalares diretos das famílias de cores, matriz e dualidade que só foram comparados com 1GSMG | parcial | 1 | "Half and better half" é de 2019, anterior ao `17ucy`. A fatia barata foi rodada como higiene de oráculo (frente `retro_17ucy`). |
| `dualidade-cosmic-83-sem-padding` | COSMIC (83 blocos = L83) com oráculo por bloco, sem exigir PKCS7, sobre as senhas já testadas | parcial | 1 | Exigiria `-nopad` com plaintext de exatamente 1.328 B. Foi rodada como lacuna declarada da §3.13 (frente `cbc_sem_padding`, parte B). |
| `auditoria-01` | Corpus órfão em %TEMP%: plaintexts de 17/09 nunca varridos contra 17ucy nem nas visões cp273/UTF-16 | parcial | 2 | A lacuna é real, mas menor do que a hipótese dizia. Foi rodada como lacuna reproduzida (frente `orfaos_temp`). |
| `auditoria-02` | G.semantic e G.nested_blob cegos a UTF-16 e a UTF-8 multibyte: corrigir o oráculo e fazer a triagem retroativa | parcial | 1 | Os três plaintexts autênticos usam 1 byte por caractere, com CRLF e sem BOM, o que contradiz UTF-16 e UTF-8 multibyte. |
| `falas-1` | Gramática de caixa/espaço '(aBa, connected enf / not enf)' aplicada à senha da SalPhaseIon | parcial | 1 | "(aBa, connected not enf)" preservou espaço dentro de uma resposta, nunca entre partes. A SalPhaseIon não tem anotação desse tipo. |
| `falas-2` | 'Close friends' como referência à LORE PÚBLICA do projeto revelada no farewell (regra 6) | parcial | 2 | Os handles e nomes principais já estavam no inventário da F6, e o resto não tem ponteiro na página. A lacuna F6 × `17ucy` foi rodada na frente `retro_17ucy`. |

O veredito completo de cada verificador (evidências com caminho:linha, parte não coberta e plano de teste) fica no resultado local do workflow, fora do git.

## Hipóteses do Codex Astra: testadas

| id | Hipótese | Prior do Codex | Frente | Resultado |
|---|---|---|---|---|
| I1 | Corrigir a direção EBCDIC antes da poda da busca decimal | 4 | `ebcdic_decimal_inverso` | lacuna reproduzida; negativo |
| I2 | Aplicar SHA256 como senha aos materiais que só chegaram ao oráculo de chave | 3 | `faed_selecao_sha256` | lacuna reproduzida; negativo |
| I3 | Lista numérica seguida das palavras reais anteriores a choice | 3 | `lista_mais_fala` | lacuna reproduzida; negativo |
| I4 | SMALL sem padding: chave binária invisível aos filtros anteriores | 3 | `cbc_sem_padding (parte A)` | lacuna reproduzida; negativo |

Sessão do Codex: thread `01a0b367-f3a1-7612-9d13-815490b22e53`, 1.292,7 s, HEAD `5f12b71`. Prompt e resposta em `_work/codex_pair/20260918T072528Z_9808a238/`, local.

## Apêndice: observações verificadas por lente

Fatos que cada lente conferiu ao ler o repositório. Os caminhos de rascunho apontam para o scratchpad local da sessão.

### gramatica

TABELA DA GRAMÁTICA DAS SENHAS (extraída verbatim do README.md, fase a fase). Em todas as fases o argumento de -pass é SHA256 HEX MINÚSCULO (64 chars); openssl enc -aes-256-cbc -d -a -pass pass:<hex>.

- Fase 0 (URL do endgame): fonte = banner "GSMG.IO 5 BTC PUZZLE CHALLENGE" + endereço 1GSMG...; regra "picky" do autor = manter só [A-Za-z0-9], CAIXA PRESERVADA -> GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe; op = SHA256 -> hex minúsculo = 89727c... (é o path, não abre AES). Isto é o "HASHTHETEXT".
- Fase 1: matriz 14x14 (preto/azul=1, amarelo/branco=0), espiral anti-horária de (0,0), grupos de 8 bits -> ASCII -> gsmg.io/theseedisplanted. Só decodificação.
- Fase 2: senha = UMA palavra identificada de citação do Merovíngio ("causality"), minúscula como está; SHA256("causality") hex -> -pass. Gramática mínima: 1 keyword -> sha256.
- Fase 3: 7 PARTES concatenadas SEM separador, cada uma na CAIXA NATIVA: causality+Safenet+Luna+HSM+11110+0x736B...(string hex LITERAL, com "0x")+B5KR/1r5B/2R5/...b - - 0 1 (FEN de xadrez, COM espaços e barras). Tokens de instrução: /(aBa, connected enf) = preserva caixa, junta; /(aBa, connected not enf) = preserva caixa, MANTÉM whitespace (por isso o FEN entra com espaços). SHA256(concat) hex -> -pass. Fato-chave: o input do sha256 CONTÉM espaços/barras/"0x".
- Fase 3.2: 3 respostas de enigma, MINÚSCULAS, sem espaços, com palavra de instrução embutida: jacquefresco + giveit + justonesecond + heisenbergsuncertaintyprinciple. Instrução /(aa, connected enf) = minúsculo, junta; o "giveit" é PREPENDIDO à resposta 2 por ordem explícita do plaintext ("just add giveit in front of the answer"). SHA256 hex -> -pass. Mantém o 's' possessivo (heisenberg+s).
- Fase 3.2.1: Beaufort (chave THEMATRIXHASYOU, hint "beautiful"->beaufort) sobre o bloco ╬╚; EBCDIC 1141/cp273 ("one for one, four for one"->1141). Decodificação.
- Fase 3.2.2: VIC/straddling checkerboard, alfabeto FUBCDORA.LETHINGKYMVPS.JQZXW (de "fubcd-king & oracle-queen, thingky mvps"), dígitos 1,4. Decodificação.

PÁGINA SalPhaseIon, tokens decodificados em ORDEM DE LEITURA: matrixsumlist (binário abba a=0/b=1, entre dbbi e faed) ; [SMALL: entre suas 2 metades base64 há o binário abba "enter"] ; lastwordsbeforearchichoice + thispassword (dois z-segmentos, método a=1..i=9,o=0 -> decimal -> hex -> ASCII) ; shabef = sha256 (a1z26 misto: "sha" + b=2,e=5,f=6) ; "our first hint is your last command" (inglês, letra a letra com espaços) ; [SMALL blob] ; "shabef ans too" = "sha256 answer too". COSMIC = textarea separada. TAIL32 = blob no fim do plaintext da 3.2. A página tem DUAS numerações ensinadas: a1z26 (shabef) e a1i9,o0 (z-segmentos).

DEFINIÇÃO DE "hint" e "command" nas fases anteriores: "hint" = pista que revela palavra(s)-chave (poema, imagem, citação); a operação HASHTHETEXT (fase 0) é literalmente "o primeiro hint" (hash the text). "command" = a linha openssl que o solver roda (o -pass é o argumento). Logo "our first hint is your last command" = "refaça a operação do primeiro hint (HASHTHETEXT/sha256 do texto) para obter o -pass do último comando".

LACUNAS VERIFICADAS POR MIM (grep em solver/, _work/**/RELATORIO.md, docs/historico/):
1) O SEGUNDO endereço do prêmio, 17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa (guarda ~3,75 BTC = 3/4 do prêmio; só entrou no projeto em 2026-09-17), NUNCA foi usado como STRING de senha/texto: aparece só como h160-alvo de privkey (grep "17ucy" em contexto de senha = vazio). hashthetext.py usa só ADDR=1GSMG (linha 61-63). ENDGAME §4-C "segunda porta = sha256(título+17ucy)" refere-se a 10 SONDAS DE URL (todas 404) + as 217 senhas do first_hint_literal, que usa H1 (o hash de 2019), NÃO 17ucy. Portanto sha256(banner-picky + 17ucy) como SENHA de SMALL/COSMIC/TAIL32 é lacuna real.
2) A concatenação dos PRÓPRIOS hex de senha das fases (PH2 eb3efb..., PH3 1a57c5..., PH32 250f37..., PH0 89727c...) seguida de sha256 NUNCA foi montada: f4_passwords.py testa cada hash INDIVIDUALMENTE; intertwine_attack.py só faz XOR dos sha256 e interleave de STRINGS.

O QUE JÁ ESTÁ COBERTO (não reabrir): concatenação em qualquer ordem/sep dos tokens da página incl. join com espaço (hashthetext.py SEPS=["","," ","\n"] sobre permutações e a full-concat de 7/8 tokens); a string de 103 chars em ordem-de-página com shabef (telegram_miner.py #65298); concat do roadmap completo (salphaseion_passphrase_sweep.py); ENTRELAÇAMENTO round-robin das 7 senhas-de-fase E das 7 partes da fase 3 (familia3_entrelacamento.py, conjunto S_p3_partes); "our first hint" literal como o hash de 2019 e como linha de comando (first_hint_literal.py); HASHTHETEXT do texto visível/blobs/formas de shell (hashthetext.py, ans_too_ct_text.py). Todos = 0.

CAVEAT ESTRUTURAL (rebaixa o prior de TODA hipótese de concatenação-senha): a página SalPhaseIon NÃO tem a notação /(aXa, connected [not] enf) que governa a gramática "compor texto + sha256" das fases 2/3/3.2; e o plaintext do Arquiteto (3.2) roteia o endgame por "return to source codes / reinserting the prime basics / select from over 23 ciphers, 16 encryptions, 7 intertwined passwords / brute forcing" (ENDGAME §6). Isso indica que o passo final NÃO é "concatenar respostas e sha256" — é o lead dos primos sobre dbbi. Por isso o espaço de senha já está quase esgotado. As hipóteses abaixo são as fatias FINITAS que sobraram; a mais forte usa dado genuinamente novo (o 2º endereço).

### roteiro

1) SATURAÇÃO DA LEITURA LITERAL. Conferi com Grep/Read que quase toda leitura literal da página já foi executada. Rótulos e textos da página, como senha ou como sha256, com sufixos de shell (\n, \r\n, \r, espaço, BOM, UTF-16): hashthetext.py, ans_too_ct_text.py, fresh_designer.py, first_hint_sweep/frontier.py e first_hint_literal.py. Permutações de 1 a 3 tokens com separadores "", " " e "\n": hashthetext.py. Segmentos z crus e as metades do SMALL: idem, mais a família 5. "our first hint" como hash da fase 0 ou como hash publicado em 2019: 7,34 M AES. Últimas palavras do Arquiteto: 70.340 senhas. RAB. Reinserção dos primos com duas cláusulas: 1.080 senhas. Rótulos binários 0/1/remoção: 3^9 mapas. Zeros no método z: certificados. Não achei leitura literal de rótulo → senha que continue aberta com prior razoável.

2) CHECAGENS RÁPIDAS NEGATIVAS (feitas por mim, sem campanha). Scripts em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\ideacao_roteiro\:
 (a) livro.py: somas de linha/coluna da matriz como índices de palavras, contados do fim e do início, antes das 6 ocorrências de "choice" na cena do filme (MISC.txt + TRANSCRIPT_ARQUITETO.txt). Saída ilegível em todas as combinações. Os valores 3–10 só alcançam as últimas 10 palavras e se repetem.
 (b) salto.py: resíduo L84/L83, direto e reverso, como saltos cumulativos em letras e palavras, nos dois sentidos, a partir de cada "choice". Melhor escore limpo −6,28; o nulo de 200 embaralhamentos dá p95 −5,90. Nenhum sinal.
 (c) vazia.py: senhas da tecla Enter ("", "\n", "\r\n", "\r", " " e o sha256hex de cada) nos 3 blobs × 2 KDF: 0 paddings.
 (d) intermed.py: formas intermediárias dos segmentos z (decimal, hex, HEX, 0x-hex, concatenações; crua, sha256hex e SHA256HEX): 34 senhas, 204 AES, 2 paddings (ruído, printable 0,38).
 (e) by84.py: dbbi lido na convenção "shabef" (a1z26 com dígitos em letras; b=2=B e be=25=Y nos primos, L83/L84, letras/dígitos/espaçado): 21 senhas, 126 AES, 0 paddings. A leitura be=25=Y, b=2=B explica "yellowblueprimes" pela própria convenção da página; a comunidade já registrou isso (#49745).
 (f) lagic.py: coincidência por lag em faed, lags 1–285, contra 400 embaralhamentos. Nos lags 7, 13, 14, 15, 23, 38, 60, 61, 83, 84, 91, 101, 104, 196 e 285, |z| ≤ 1,7. O maior z foi 3,8 no lag 253, dentro do look-elsewhere de 285 lags. Isso estende residue_autocorr_*.py, que só cobria lags 1–60 (range(1,61)). Não há chave periódica de período 61, 91 etc. sobre codificação enviesada.
 A fase 2 abre pelo kit (gsmg_common OK) e o controle plantado de blocos_primos.py passou.

3) PONTOS CEGOS DE ORÁCULO (base de H1).
 (a) G.aes_try exige PKCS7 válido no último bloco publicado. multicipher_attack.py usa o "oráculo do último bloco" para os modos CBC. Toda a história de decifração é cega a estruturas em que o último bloco publicado não é o último bloco real.
 (b) ct_blockscan_oracle.py cobre só SMALL/TAIL32 e só com o corpus. Seu "limpo" exige bytes imprimíveis, então é cego a plaintext binário (chave crua de 32 B) e ao bloco de padding cheio 0x10×16.
 (c) O COSMIC nunca passou por oráculo de bloco.

4) FATOS ESTRUTURAIS.
 - COSMIC tem 1328/16 = 83 blocos. Retirando os de índice primo 1-based (23 blocos) sobram 60 = |resíduo L83|; 0-based (22 blocos) sobram 61 = |resíduo L84|. Pode ser coincidência: look-elsewhere de uns 10 %.
 - SMALL e TAIL32 têm 5 blocos cada. 0-based, retirar os blocos {2,3} deixa 48 B = 32 B + bloco de padding cheio. 1-based, retirar {2,3,5} deixa 32 B exatos.
 - No SMALL, o "enter" fica exatamente antes do bloco 2 (0-based), porque a linha 1 = cabeçalho + blocos 0 e 1. Isso vale para qualquer blob de 80 B quebrado em 64 caracteres, então não é evidência sozinho.

5) PREMISSA SUSPEITA. solver/architect_sum_attack.py, paired_extractions(), usa as quebras de linha do README antes de SELECT, que a verificação de 2026-09-11 declarou editoriais (README, nota da fase 3.2.1). Os braços que usam as somas de linha/coluna da matriz rodaram sobre material não autêntico. extractions() usa só as somas de faed (140…188), não as da matriz. A checagem 2(a) cobre a lacuna por legibilidade.

6) LEITURA DO TAIL32. A saída VIC 3.2.2 ("IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE"), junto com "Raising the stakes without extra chances of winning" e o "No" do criador (2023-06-10), admite a leitura de que o TAIL32 guarda chaves pessoais e não é o caminho do prêmio. É interpretação, não fato.

7) PRIORIDADE HONESTA. Nenhuma das duas hipóteses chega a prior 3/5. H1 fecha um ponto cego real de toda a história AES a custo de minutos. H2 é extensão cartesiana de prior baixo e só vale se houver folga.

### ferramentas

Tudo abaixo foi conferido em 18/09/2026, somente para leitura do repositório. Os rascunhos estão em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\ideacao_ferramentas\ (morbit_count.py, morbit_ctl.py, quick_residuo.py, grammar_cb.py). Nenhuma campanha AES foi executada.

1) INVENTÁRIO DE FERRAMENTAS COM ALFABETO a–i OU 1–9 × COBERTURA.
- Multitap/T9: testado só em dbbi/faed/metades/pareado (solver/experiments/claude_endgame_2026_09_02/polybius_pairs.py). No resíduo §6 eu rodei multitap com e sem separador: saída sem sentido (GWMTEPWT.KWTQJPJ…). Com T9, a=1 como espaço daria palavras de 9, 18 e 30 letras, o que é inviável.
- Morbit (9!) e Pollux (3^9): testados só nos campos inteiros (solver/morse_endgame.cjs). Rodei os dois no resíduo, em R84, R83 e nas versões invertidas: 0 decodificações Morse válidas em todas as chaves. O controle ACA passou, "ONCE UPON A TIME" (morbit_ctl.py). No nulo aleatório deu 0/10.000, então o filtro é forte e a família fica excluída no resíduo.
- Polybius/Bifid 3×3 e Trifid: exaustivos em dbbi/faed; no resíduo, 216 e 2.904 configurações (resid_decoders.py).
- A1Z26: no resíduo só em grupos fixos k=2/3. A leitura de lista de comprimento variável (o "1812") fica excluída pela composição: o resíduo tem apenas três 1 e dois 2 em 61 dígitos, e inglês em A1Z26 concatenado exige cerca de 25–40 % de 1/2. O mesmo vale para faed.
- Numerologia pitagórica (letra mod 9, saída 1–9 sem zero): excluída pelo unigrama. No resíduo há a=3 e b=2, contra ~9 e ~7 esperados, e g=10 contra ~3,6. Em faed g é 18,8 % contra 5,9 % esperados.
- Coordenadas QWERTY (linha 1–3, coluna 1–9) e teclado de telefone (tecla, posição): violam a restrição posicional já nos primeiros pares de dbbi, faed e do resíduo.
- Tap code: exige 1–5, então não se aplica.
- Códigos de barras e checksums: EAN-13 nas 7 linhas 7×13 de dbbi deu 0/7 e 0/7; ISBN-10 deu 2/9; Luhn nas linhas de 15 de faed deu 5/38 e 2/38 (a=1 e a=0); em 38 deu 1/15. Tudo no nível do acaso.
- Rótulos binários 0/1/remover (3^9) no resíduo, em 7 e 8 bits: nenhum texto (antes só havia sido testado em dbbi/faed).
- Go 9×9 em SGF (coordenadas a–i): 30 pares de R83 não formam glifo e têm 4 pontos repetidos (cc, ff, gg, gi), o que é ilegal como partida sem captura. Shogi usa fileiras a–i com dígitos e xiangqi (ICCS) usa a–i mais 0–9: nenhum dos dois se aplica a dbbi/faed.
- Base 36 (To Base do CyberChef): a frase do roteiro "itsinfrontofyoureyesbutyourenotseeingit" (39 caracteres) em base 36 dá exatamente 61 dígitos decimais, o mesmo tamanho do resíduo. Mas os dígitos não casam sob nenhuma bijeção: há conflito no índice 3. É coincidência de tamanho.
- A leitura "radix nativa" (a=10..i=18 em base ≥19) tem prior nulo: o criador não consegue produzir 91 símbolos só a–i por conversão de base.
- Base64 e Base58 diretos: mesmo argumento. Uma saída restrita a a–i não sai de codificação de dados reais; por isso só sobram ferramentas com alfabeto de saída ≤ 9 ou substituição de dígitos.

2) FATOS SOBRE O dcode (WebFetch, 18/09).
- A página vic-cipher usa grade de 28 caracteres (26 letras + '.' + '/'), com parâmetros "Digit 1"/"Digit 2" e modos "Without key" ou "With a numeric key". A chave numérica é somada dígito a dígito mod 10. Exemplo verbatim do dcode: chave 0248, 86167202522 → 88547240546. A saída pode ser "Digits" ou "Letters".
- O deranged-alphabet-generator remove as letras repetidas e completa em ordem alfabética; tem botões "Reverse fill" e "Random fill".

3) ALFABETO DA 3.2.2.
- Decodificando a mensagem autêntica, são usadas as células 0–7 e 9–21. A célula 8 ('.') é um marcador autenticado pelo deslocamento: é o lugar do C repetido de ORACLE. As células 22–27 ('.', J, Q, Z, X, W) não são usadas e não estão autenticadas.
- A ordem "JQZXW" vem do README (comunidade). Não é o preenchimento alfabético do dcode.
- A gramática "letra repetida → '.'" nunca foi aplicada a outras frases: grep por SALPH.., COSMI.DUAL e THISPA.. deu vazio. Os alfabetos chaveados testados (ambiguous_checkerboard, resid_decoders) têm os pontos no fim ou nenhum ponto.
- Com essa gramática, o <title> "GSMG Puzzle", os dois <h1> "SalPhaseIon" e "Cosmic Duality", e ainda "thispassword" e "yinyang" dão exatamente 28 células, o tamanho do tabuleiro. "enter" e "ans too" dão 27, como a frase da 3.2.2, que precisou de um '.' extra.

4) PREMISSAS SUSPEITAS.
(a) "R=18 A=1 B=2 Could also be 21 or 1812 bit" (#6913) foi postada em 2021-04-01, dia da mentira. Ela responde à conta de cores de #6911 ("15+9+1=25 bit… 15*3+9*2+1=64 bit") e continua com "Sometimes I'm glad I don't have to solve this puzzle myself". A leitura mais simples é um trocadilho, RAB+bit = rabbit, zombando da numerologia. ENDGAME §2 e §4-C tratam a fala como "operador que o criador demonstrou": a premissa é mais fraca do que o documento declara.
(b) 1GSMG1… tem prefixo vanity: 6 caracteres, cerca de 58^5 tentativas, com pubkey não comprimida, típica do vanitygen. A chave do prêmio é aleatória. Famílias que derivam a chave aritmeticamente de dbbi/faed (escalar, janelas, seleção de bits) têm prior perto de zero, salvo se os dígitos da chave estiverem embutidos. A chave deve vir de uma abertura AES. A comunidade já notou isso (#70598, resumo tg_2026-07_09).
(c) O unigrama de faed bate com decimal uniforme em que g vale 0 ou 7 (χ² 11,5, já registrado no caderno histórico). O resíduo tem g=10/61, o que é compatível.

5) O controle de fase 2 e o do checkerboard 3.2.2 foram reproduzidos pelo kit: G.checkerboard_decode com o alfabeto autêntico e os prefixos (1,4) devolve "INCASEYOUMANAGETOCRACKTHIS…".

6) Conclusão da lente: as famílias "de ferramenta" com alfabeto de 9 símbolos estão praticamente esgotadas, pelos testes históricos e pelas minhas checagens. Sobram duas lacunas exatas ligadas à única ferramenta que o criador comprovadamente usou em dígitos → texto, a VIC do dcode. As duas estão abaixo.

### dualidade

Fatos que conferi (somente leitura; o único teste foi uma checagem de 12 brainwallets triviais nos dois alvos, com zero acertos):

1. O oráculo de padding tem uma lacuna no COSMIC. G.aes_try exige PKCS7 válido (gsmg_common.py, linhas 140–154): toda decifração com padding inválido é descartada sem registro. O único oráculo por bloco, que não depende de padding nem de IV, é solver/ct_blockscan_oracle.py. Ele só varre SMALL e TAIL32 (SALTS/CTS = {"S","T"}), e só sobre o corpus de 1.272.149 formas. O COSMIC nunca passou por oráculo por bloco. Na página ao vivo, o COSMIC tem 28 linhas de 64 caracteres (1.792 em base64), que dão 1.344 B = 16 + 1.328, ou seja, exatamente 83 blocos AES.

2. O braço de chave direta das famílias de cores, matriz e dualidade anteriores a 17/09 comparou só com 1GSMG:
   - select256.py (l. 49), ybp.py (l. 166), yinyang_sweep/roundB/roundC, cores163.py (l. 30) e infrared_spectrum.py (l. 33) usam TGT = TARGET_PUBKEY_HEX (pasta _work/frontier_2026-09-17/rodada*_scripts do checkout principal).
   - brainwallet.py usa TARGETS = h160 só de 1GSMG.
   - Os .cjs url_prime_reinsertion, zero_cells_prime_sums, color_factor_sum_passwords e prime_codepoint derivam target_h160 da pubkey de 1GSMG. Os relatórios de prime_host_delta e prime_host_l84 dizem "ponto público do prêmio e sua negação".
   - oracles.check_mnemonic só deriva m/44'/0'/{0,1}'/{0,1}/{0..4}.
   A re-varredura da §3.11 cobriu plaintexts com padding, não esses escalares diretos. Isso bate com a própria §3.11: "os demais negativos históricos de privkey valem só para 1GSMG".

3. 1GSMG1… tem prefixo de vanidade de 5 caracteres (chance ao acaso de 58⁻⁴). Então a chave dele é essencialmente aleatória, ou texto mais nonce, e precisa estar guardada literalmente num envelope. Escalares derivados de texto quase não tinham poder contra 1GSMG. 17ucy não é vanidade: é o único alvo em que brainwallet ou derivação é plausível. Essa consequência não está no ENDGAME.

4. Falas do criador que não estão no ENDGAME §2 (conferidas no result.json do checkout principal):
   - #3923, 2020-05-11: "who knows what you'll find after opening the 2nd door. The price is in half, but what does it mean".
   - #4589, 2020-08-02, respondendo à suspeita de que o endereço das metades já estava definido e ao link de 17ucy: "Or the same puzzle, or just not at all". Logo depois, #4590: "Really nobody managed to find the extra door…".
   - #5069 "We have our reasons halving the price money"; #5365 "It'll be split on the next halving".
   - #8364: não nega a pergunta "the solver could receive prizes from both addresses".
   - #60314: "If any of you reaches the next phase, the price is taken in no-time".
   - #4102/#4104/#4105: "answer is there", depois a pergunta sobre "another door from the 1st piece", respondida com "First or zero" (a resposta está na primeira peça).

5. Correção de contexto do RAB. A fala #6913 ("R=18/A=1/B=2 … 21 or 1812 bit") veio dois minutos depois de #6911 (Saber: "15+9+1= 25 bit... 15*3+9*2+1=64 bit", contagem das cores) e de #6904 ("there is 1 pixel here look"). Portanto não foi espontânea, ao contrário do que diz o relatório F1, e "RAB"+"bit" pode ser trocadilho com rabbit. Já "Infrared" (#6250) é seguido na hora por #6252 "No hints 🤡", em resposta a uma piada ("xor … or we need sum for red xD").

6. Inferências estruturais (não são prova):
   - b/be = a1z26 de B(2) e Y(25). "Yellow has a number and so does Blue" explica a grafia dos marcadores; a comunidade já notou (#49745–6). O #FEFEFE aparece como B.
   - L83 corresponde aos primeiros 23 eventos coloridos em ordem espiral (omite 24 e 25), sem nenhuma escolha livre, e termina num marcador no 23.º primo, 83. L84 exige pular o evento 22. O resíduo de L83 tem 60 símbolos e cabe em grade (6×10, 5×12); o de L84 tem 61, que é primo. O COSMIC também tem 83 blocos. Isso favorece L83 pela navalha de Occam, e só isso.
   - O byte 20 ('n') é o único da URL com duas marcas: W no bit 3 e Y no LSB. Seria a estrela branca mais a amarela da capa.
   - O #FEFEFE está na linha 7, bem à frente da cara do coelho (olho em (7,7), virado para a esquerda), o que casa com "in front of your eyes but you're not seeing it" / "Bingo".
   - {1},{4},{21} só foi testado de forma literal (telegram_miner.py). Nos eventos coloridos contados a partir de 1, o 21 é o W, e o 21.º primo (73) é a vaga do W em dbbi.

7. Não encontrei hipótese nova de prior alto nesta lente. A §4-C (F5, dualidade) e a §6 esgotaram as operações textuais e numéricas. As duas hipóteses abaixo fecham lacunas reproduzidas, ancoradas na lente e baratas; os priors estão declarados sem inflar.

### auditoria

Tudo o que está abaixo foi conferido em modo somente leitura. Os scripts de conferência ficaram em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\ideacao_auditoria\ (blobs_audit.py, openssl_audit.py, overlap.py, overlap_all.py, overlap_311.py).

(a) BLOBS: nenhum bug.
- SMALL e COSMIC foram reconstruídos a partir de 7 capturas HTML: 5 do Wayback em _work/archive/endgame/ (de 20230601 a 20260405), _work/archive/endgame_20230601.html e o body ao vivo _work/gsmg_live_2026-09/body_89727c…. Todos são idênticos byte a byte a G.BLOBS.
- O binário `enter` tem 40 símbolos a/b, contíguos entre 'z' e 'Q', no offset 64 do base64 compactado (64+64 caracteres). A divisão é única por aritmética. Se k símbolos a/b fossem do base64, com k ∈ {8,16,24,32,40}, o ciphertext teria 86, 92, 98, 104 ou 110 B, e nenhum desses tamanhos é múltiplo de 16. Só k=0 dá 80 B.
- COSMIC tem 28 linhas de 64 caracteres, com LF, o que dá 1344 B.
- TAIL32 foi extraído do plaintext autêntico da fase 3.2, aberto pelo kit com sha256hex(jacquefresco…principle) e EVP-SHA256. O plaintext tem 2422 B, usa CRLF e termina em 'NAv4', sem newline final. O TAIL32 extraído é idêntico a G.BLOBS.

(b) KIT contra o openssl CLI real (C:\Program Files\Git\mingw64\bin\openssl.exe, OpenSSL 3.5.7): nenhum bug.
- Comparei 720 decifrações (120 senhas × 3 blobs × {sha256, md5}) de G.evp + AES, com -nopad. Resultado: 0 divergências de bytes. As decisões de padding de G.unpad coincidem com o código de saída do openssl (4 válidas nos dois).
- A fase 2 abre pelo CLI com o md padrão.
- TARGET_H160S confere com o base58 dos dois endereços, e a pubkey de 1GSMG gera o h160 correto.

(c) FORMAS E FILTROS: sem bug novo nas campanhas de senha.
- As formas são {crua, sha256hex minúsculo sem newline, SHA256HEX}, o que cobre o que as fases 2, 3 e 3.2 usaram. first_hint_literal inclui ainda variantes com \n e espaço.
- Filtros antes do AES já tratados:
  - o top-N do bifid3x3 passe 1 foi corrigido pelo bifid3x3_pass2, que é exaustivo;
  - o top-20 do resid_decoders foi corrigido na §3.13;
  - O.aes_open(min_ascii=0.90) é legado, e o corpus de 1,27 M foi refeito pelo multicipher_attack, que guardou todo padding;
  - o filtro dos modos de fluxo já é conhecido (§3.13).

BUG 1: CORPUS ÓRFÃO EM %TEMP% (reproduzido).
- Onde está: …\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle\bd1a3ae7-baeb-4498-9cf8-1a8d8944473a\scratchpad\.
- O que contém:
  - premissa_cifra/survivors_*.jsonl: 360.074 registros, 424 MB;
  - montagem_ct/survivors_*.jsonl: 797.172 registros com D_hex+iv_hex, 516 MB, mais corpus.pkl;
  - rerun_ext, infrared, unicode_yinyang, kfile_first_line, marcadores, forense_bytes.
- Todas as execuções terminaram até 17/09 15:05. O commit 9062dc7 (14:57) mostra G.fast_priv_scan comparando só format(False) == pubkey de 1GSMG. A correção de dois alvos (0ce4185) é de 17/09 23:21. priv_at, o priv_scan do ct_montage e o priv_ok do tail32_history também comparavam só com 1GSMG.
- Nenhum inventário posterior leu o %TEMP%:
  - retro_dois_alvos e v4 (§3.11) leem só MAIN/_work e MAIN/solver;
  - collect.py (§3.12) lê só _work e solver;
  - recover_corpus.py (§3.13) lê 4 arquivos fixos;
  - a frente lacuna_cp273_utf16 lê só a recoleta da §3.11.
- Medi por SHA256: 1.140.554 conteúdos, com 248.194.162 janelas raw32, estão fora de v3 + supplement + partial + recovered (818.193 hashes).
- Dos 20.070 plaintexts aes-256-cbc de SMALL/COSMIC do corpus histórico, só 19 estão na recoleta da §3.11 (1.894.673 conteúdos).
- Controle de sobreposição: o TAIL32 aes-256-cbc do mesmo corpus aparece 100% nos corpora já varridos (9.786 na §3.11; o restante em v3). Isso mostra que o método de comparação funciona.
- Os arquivos de %TEMP% são voláteis e são a única cópia desses dados. É preciso congelar os hashes antes de qualquer limpeza.

BUG 2: G.semantic e G.nested_blob são cegos a UTF-16 e a UTF-8 multibyte.
- Texto UTF-16LE com BOM contendo um WIF: semantic False, printable 0,487, wif False.
- Base64 `U2FsdGVk…` em UTF-16: nested_blob False, semantic False.
- UTF-8 CJK (陰陽 ☯ 太極): semantic False, printable 0,167.
- Os detectores propostos deram 0 falsos positivos em 200.000 buffers aleatórios de 79 e 1.327 B.

MENORES (fora das hipóteses):
- _B64_RE de nested_blob rejeita armadura base64 em várias linhas. Em ASCII isso é inofensivo, porque printable ≥ 0,85 já pega o texto.
- O braço brainwallet contra 17ucy nunca rodou sobre as 1.272.149 formas do corpus histórico: tail32_history.priv_ok compara só 1GSMG. Custo ≈ 1 CPU-min, mas prior ≈ 1/5: 17ucy guarda os halvings do próprio criador (a "better half"), então é improvável que seja brainwallet de frase do puzzle. 1GSMG é vanity e não pode ser brainwallet.
- O corpus histórico não tem algumas grafias óbvias: 'SalPhaseIon', o roadmap com espaços, 'sha256', 'YinYang'. É trivial.

Custos medidos nesta máquina: ECC 23,3 µs por tentativa (coincurve, 2 formas de pubkey, 2 h160); decisão AES completa 6,6 µs.

### falas

Li ENDGAME.md inteiro (§2 falas, §4 famílias, §6 lead dos primos), README.md (fases 0–3.2), spec.json da campanha e os sumários de Telegram; extraí e li TODAS as 492 falas do criador (from_id user9815232) dos três exports (result.json até 08/07/2026; ChatExport 09-08 e 09-17), com contexto de reply e todos os forwards de falas antigas.

FATOS QUE CONFERI (controle positivo: fase 2 abre com sha256hex("causality") sob EVP-SHA256; rodei via kit G.try_password_all). Todas as leituras diretas abaixo deram 0 hard / padding no nível do acaso — já as registro para servir de "linha refutada próxima" e para não serem re-propostas:
- Faixa Slack "chaos pixel / spiraling down the rabbit hole" (a3SBaWpXe4k), citada pelo criador como "a tiny one in the music channel on slack for the rabbit phase" (#28293, fwd; original 2019): 96 senhas (raw/sha/dsha), 3 blobs, 2 KDF = 576 AES → 0. Também sondei gsmg.io/spiralingdowntherabbithole e o sha256 dele: 404. Esses termos NÃO constam de solver/ (grep 0), mas a leitura como senha está agora fechada por mim.
- "your last command" = pass do último openssl (fase 3.2 250f37…, fase 3 1a57c…) como senha de SMALL/COSMIC/TAIL32: 30 senhas → 0.
- Concatenação ordenada do roadmap (yellowblueprimes…verylaststep…) crua E como sha256hex: 0. Segmentos decodificados da SalPhaseIon em ordem de página (matrixsumlist,enter,lastwords,thispassword,…) crus e sha256hex: 0. Representações intermediárias (a–i, decimal, hex) de "thispassword"/"lastwords" como senha: 0.
- Todos os 64-hex publicados no puzzle (89727c…url, 5ac407…2019, eb3ef…, 1a57c…, 250f37…) como -pass e o cru como -K (IV=0): 0.
- sha256("primeiro hint") de cada candidato de primeiro hint (poema #1710, "follow the white rabbit", "hush hush", hashthetext, theflowerblossoms…) como -pass: 82 senhas → 0.

CONFIRMAÇÕES DE MAPA: (a) o coelho na PNG viva é pixel-art uniforme em minicélulas de 5px, 5 cores exatas, nada sub-pixel novo (bate com §5); (b) a mensagem binária de Ano-Novo 2026-01-01 #53342 decodifica "Happy new year! Make the best of everything. Oh, and here's a 'tiny hint' <3." — a "tiny hint" é a própria brincadeira (binário), sem operação nova (coerente com telegram_miner); (c) o farewell #61385 (13/04/2026, fwd) traz muita LORE PÚBLICA do projeto (MR ROIbot, d0d, Darky, Greengras, Bloctite, EPIPREMNUM AUREUM, Sydney 2017, Poloniex, "June 10 8:30") — insumo tardio possivelmente ausente do inventário de "referência pessoal" (17/09) da §4-C.

CONCLUSÃO ESTRUTURAL (não é hipótese gated, é reframe): "shabef ans too" = "sha256 answer too" (a página SalPhaseIon) e "our first hint is your last command" implicam ENCADEAMENTO: a chave do 2º blob = sha256 da resposta do 1º. Se isso vale, varrer COSMIC/TAIL32 de forma independente é estruturalmente estéril (consistente com todos os negativos), e o orçamento deve ir para SMALL (o blob inline de 80 B). Uma varredura-retro barata e AUSENTE dos relatórios (as retro-varreduras §3.11–3.13 só procuraram privkey embutida, nunca usaram sha256(plaintext) como CHAVE de outro blob): pegar os ~1,3 M plaintexts já logados com padding, sha256 de cada → testar como chave/senha de COSMIC/TAIL32. Custo ~8 M AES (~15 min em 20 núcleos). Prior de HIT baixo (exige que a plaintext verdadeira de SMALL já esteja no corpus, o que não ocorre), mas fecha a leitura de encadeamento no nível do corpus. Recomendo ao coordenador como scan de fechamento, não como frente gated.

AVISO DE HONESTIDADE: a lente "falas" está fortemente exaurida — o criador deu pouquíssima instrução operacional e quase tudo virou teste. Coerente com ENDGAME §6: só insumo novo do criador ou lacuna reproduzida move a fronteira. As duas hipóteses abaixo são as fatias defensáveis que sobraram; ambas têm risco de cobertura declarado. NÃO persegui identidade de ninguém (regra 6): as referências usadas são lore pública do projeto, o "tipo de resposta" que a fala "close friends" indica.

### codex

Proponho quatro hipóteses, com prioridade I1 → I3 → I2 → I4. Não alterei arquivos nem executei as quatro buscas propostas. Reproduzi a abertura da fase 2, os hashes exatos das fases 3/3.2 e os 1.539 bytes do segmento cp273 inverso. Enumerei os conjuntos de I2 e I3: não têm interseção entre si nem com um conjunto conservador de 376.213 valores reconstruído de 14 artefatos históricos, cujos hashes conferiram. Isso sustenta novidade nos corpora examinados, sem provar ausência em todo histórico não preservado. Os custos distinguem CPU acumulada de tempo de relógio: medi aproximadamente 7,8 µs por decisão AES com filtro do último bloco e 23,4 µs por escalar ECC, incluindo as duas serializações de pubkey. As estimativas com 20 processos incluem margem, mas a escalabilidade não foi medida. Em todas as propostas, parada = esgotar o conjunto; padding e texto plausível são somente candidatos. Nulo N/A para enumeração determinística sem alegação estatística; se forem comparados escores ou taxas, acrescentar 100 embaralhamentos casados. Toda possível solução exige proof-certificate.
