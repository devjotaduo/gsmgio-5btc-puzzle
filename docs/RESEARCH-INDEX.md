# Indice dos experimentos

Relatorios em `_work/<experimento>/RELATORIO.md`; atualizado em 18/09/2026.
**A senha final nao foi validada.** Cada relatorio define a cobertura exata do seu negativo;
constar aqui nao significa que a familia inteira esteja excluida. O consolidado do que cada
familia excluiu esta em [`ENDGAME.md`](../ENDGAME.md), secao 4; as regras de trabalho em
[`AGENTS.md`](../AGENTS.md); o historico cronologico em
[`docs/historico/`](historico/ENDGAME_cronologico_2026.md); a execucao dos scripts em
[`solver/README.md`](../solver/README.md). Dados brutos podem ser locais: o `.gitignore`
mantem no git so os relatorios e as execucoes finais.

## Lead aberto

- [Segmentacao de `dbbi` por marcadores `b`/`be` nos primos (`yellowblueprimes`): reproducao, residuo, campanha e limites](../_work/frontier_2026-09-17/RELATORIO.md) - scripts em [`solver/primos_2026_09_17/`](../solver/primos_2026_09_17/README.md).
- [Export de 17/09: marcadores primos, matriz anotada e diferencas do coelho](../_work/prime_host_delta_2026-09-17/RELATORIO.md).
- [L84/16+7 adotado como premissa: consequencias testadas](../_work/prime_host_l84_2026-09-17/RELATORIO.md).
- [Enxame de 19/09: 10 frentes sobre as lacunas declaradas — pontos cegos do oraculo medidos, cota exata do lead (P <= 1,86e-17), `faed` removido das evidencias, modos de fluxo cobertos mas nao fechados](../_work/enxame_2026-09-19/RELATORIO.md) - scripts em `solver/enxame_2026_09_19/`.

## Alegacoes publicas, auditorias e fontes

- [Hex ímpar: zero à esquerda × From Hex do CyberChef, e `faed` como 95 cores — 18/09/2026](../_work/hex_paridade_2026-09-18/RELATORIO.md). Bug real: o kit (`G.z_method`) e ~40 scripts completam hex ímpar com zero à esquerda; o CyberChef lê pares desde o início. Alcance estreito: texto printável sempre dá hex par, e aí as duas coincidem. Leitura CyberChef (3.296 senhas, 19.776 AES), `faed` em 95 cores RGB (109.440 senhas, 656.640 AES) e raw32 sem filtro de padding sobre as saídas (629 M janelas): 0. Script: `solver/lacunas_2026_09_18/hex_paridade.py`.
- [O resíduo como escalar direto em bases 2–19 — 18/09/2026](../_work/residuo_escalar_2026-09-18/RELATORIO.md). MITM por pesos posicionais (`k = Σ d[c]·W[c] mod n`, identidade conferida 5000/5000): 72 configurações, 3,15 bi pares configuração/atribuição, 0 correspondências. Só vale para `1GSMG` — `17ucy` nunca gastou, logo não tem pubkey conhecida.
- [O discriminante L83 × L84 estava na fala do Arquiteto — 18/09/2026](../_work/l83_cosmic_2026-09-18/DISCRIMINANTE.md). "Reinserting the prime basics… twenty-three ciphers, sixteen encryptions and or seven intertwined passwords": L84 dá 23 = 16 `b` + 7 `be`; L83 dá 15 + 8. Fornece a **justificativa** que `prime_host_l84` declarou ausente ao fixar L84 — mas a nota foi corrigida duas vezes: L84 já era a premissa em uso, e **os números 23/16/7 são do roteiro de *Matrix Reloaded*** ("23 individuals — 16 female, 7 male"), não escolha do criador. O argumento sobrevive como condicional e fraco; nenhum resultado muda.
- [O resíduo como seleção: saltos sobre `faed` — 18/09/2026](../_work/residuo_saltos_2026-09-18/RELATORIO.md). Primeira instância concreta da hipótese "o resíduo não é linguagem". Teto próprio: a soma dos saltos (341/336) cabe nos 570 de `faed`, limitando o offset a 230/235. 3.712 seleções exaustivas: melhor escore −6,516 (inglês −3,679), 0 chaves, 0 candidatos em 44.544 AES.
- [O resíduo *como* a lista das 28 somas, e os acertos isolados da PR #6 — 18/09/2026](../_work/residuo_como_somas_2026-09-18/RELATORIO.md). Inverte o papel do rótulo `matrixsumlist` e fecha a lacuna que `symbolic_color_sums_2026-09-16` deixou explícita; limites de peso derivados dos dados (azul em 22/28 somas, amarelo em 15/28): 0 em 524.288 + 1.564.864 combinações. Também: 144 caminhos da PR #6 = 136 escalares distintos, nenhum acerto isolado, e os intermediários testados como senha AES (8.976 decifrações) e como chave (8,3 M janelas).
- [A1 e A2 — 18/09/2026: raw32 sem unpad do corpus de 1,27 M em SMALL/TAIL32 (498,7 M janelas) e os codecs da família 4 sobre os conteúdos recuperados pelo `splitlines`](../_work/lacunas_2026-09-18/RELATORIO_A1_A2.md) - scripts em `solver/lacunas_2026_09_18/`. Ambos 0; z de padding −0,87. Fecham os dois últimos abertos baratos da §3.14; sobram só os modos de fluxo.
- [O registro pessoal-informal do criador como classe de senha — 18/09/2026: os 41 itens de 12/07 e 16/07 que a família 6 não inventariou](../_work/vocabulario_2026-07/RELATORIO.md) - script em `solver/lacunas_2026_09_18/vocabulario_2026_07.py`. 19.913 candidatos, 358 k AES, 19.913 brainwallets: 0, z +1,16; nulo casado z +0,57. Disjunção com a família 6 garantida por construção.
- [Releitura "half and better half" — 18/09/2026: a SalPhaseIon como par de chaves (1GSMG + 17ucy), não senha de blob; teste do par (560 operações estruturais) negativo](../_work/half_betterhalf_2026-09-18/RELATORIO.md) - script em `solver/lacunas_2026_09_18/par_half_betterhalf.py`. Reframe do alvo e do oráculo; discute a hipótese de o passo final ser não-computacional.
- [Lacunas de 18/09/2026: EBCDIC por códigos decimais na direção autêntica, recoleta da §3.11 sem `splitlines()`, negação N−k e camadas C/D do corpus órfão](../_work/lacunas_2026-09-18/RELATORIO.md) - scripts em `solver/lacunas_2026_09_18/`. Zero chaves em ~997 M multiplicações na curva contra os dois alvos; nenhum dos 58,2 M caminhos EBCDIC passa de 52 % de letras e espaço.
- [Enxame de 18/09/2026: lacuna cp273/UTF-16 da §3.11 fechada, EBCDIC decimal na direção autêntica, seleções de `faed` como senha, lista + fala, CBC sem padding, `17ucy` nos escalares históricos e plaintexts órfãos de `%TEMP%`](../_work/enxame_2026-09-18/RELATORIO.md) - scripts em `solver/enxame_2026_09_18/`. Resultados: 6,58 M decisões AES, ~168 M testes de privkey contra os dois alvos, zero candidatos. As 17 hipóteses e o gate estão em [`ideacao/FINDINGS.md`](../_work/enxame_2026-09-18/ideacao/FINDINGS.md).
- [Rodada multiagente — 18/09/2026: cp273 inverso, recuperação de caudas, varredura BE/LE concluída, decodificadores, primos reinseridos e geometria da capa](../_work/multiagente_2026-09-18/RELATORIO.md). 225.854 plaintexts recuperados; 506.358.474 janelas raw32 BE/LE contra dois alvos, zero hits; controles e auditoria final no relatório.
- [Rodada "operador ensinado": `matrixsumlist` como operador RAB, últimas palavras do Arquiteto, sete senhas entrelaçadas, codecs, dualidade e referência pessoal; oráculo de dois endereços (`1GSMG…` e `17ucy…`) e re-varredura retroativa — 17/09/2026](../_work/operador_ensinado_2026-09-17/RELATORIO.md) - scripts em `solver/operador_ensinado_2026_09_17/`.
- [Consulta dos 3.370 endereços de candidatos textuais: saldo zero; 12 com histórico — 17/09/2026](../_work/oraculo_duplo_2026-09-17/saldos_candidatos/RELATORIO.md). Conferência adicional de 18 endereços em segundo provedor.
- [Oráculo de dois endereços, revisão independente: 592.339 conteúdos únicos, 58.357.232 janelas raw32, zero hits — 17/09/2026](../_work/oraculo_duplo_2026-09-17/RELATORIO.md). Snapshot finito dos bytes salvos; condição de prêmio do segundo alvo não confirmada.
- [`lastwordsbeforearchichoice`: fronteiras verificadas](../_work/recipe_audit_2026-09-11/FRONTEIRA_TEXTUAL.md).
- [Conferência pública — 16/09/2026](../_work/public_recheck_2026-09-16/RELATORIO.md).
- [DBBI/FAED: mapa comum, bases primas e origem de ASCII 127](../_work/shared_numeric_2026-09-11/RELATORIO.md).
- [Execução do plano: dependências de X e três consequências](../_work/recipe_audit_2026-09-11/RELATORIO.md).
- [Fronteira comunitária refutada (#108/#111), montagem do CT × corpus e oráculo estendido — 17/09/2026](../_work/frontier_2026-09-17/RELATORIO.md).
- [Leitura integral e reconciliação do ENDGAME](../_work/endgame_review_2026-09-11/LEITURA_ENDGAME.md).
- [Operações da receita de X e suas fontes](../_work/recipe_audit_2026-09-11/OPERACOES_E_FONTES.md).

## Cifras classicas e linguagem

- [Checkerboard com zeros ambíguos e auditoria do modelo de inglês](../_work/ambiguous_checkerboard_2026-09-15/RELATORIO.md).
- [Checkerboard: máscaras exatas e palavras — rodada concluída](../_work/checkerboard_exact_mask_2026-09-16/RELATORIO.md).
- [FAED: alfabeto desconhecido e zeros no checkerboard](../_work/joint_checkerboard_2026-09-16/RELATORIO.md).
- [Morbit e Pollux diretos sobre a-i](../_work/morse_2026-09-15/RELATORIO.md).
- [Nihilist: somas de coordenadas e limite da chave repetida](../_work/nihilist_2026-09-16/RELATORIO.md).
- [Rotulos binarios 0/1/remocao e Bacon](../_work/binary_partition_2026-09-15/RELATORIO.md).
- [Tokens b/g de FAED em grades 11×41 e 41×11](../_work/checkerboard_token_routes_2026-09-16/RELATORIO.md).

## Digitos, zeros e codificacoes

- [Alfabeto desconhecido e códigos ASCII decimais — 16/09/2026](../_work/substituted_codepoints_2026-09-16/RELATORIO.md).
- [Assinaturas de compactação com dígitos desconhecidos](../_work/substituted_format_headers_2026-09-16/RELATORIO.md).
- [Bases primas com palavras concatenadas (busca parcial)](../_work/prime_joined_words_2026-09-16/RELATORIO.md).
- [Brotli e cabeçalhos Zstandard na conversão decimal](../_work/brotli_decimal_2026-09-16/RELATORIO.md).
- [Codificações sem zero, sem escolha de palavras da comunidade — 17/09/2026](../_work/zero_free_numerals_2026-09-17/RELATORIO.md).
- [Códigos decimais sem limite de letras zeráveis — 16/09/2026](../_work/unbounded_zero_codepoints_2026-09-16/RELATORIO.md).
- [DBBI como escalar secp256k1 com zeros ocultos](../_work/dbbi_curve_zero_2026-09-16/RELATORIO.md).
- [DBBI e FAED como um único número](../_work/joined_fields_2026-09-16/RELATORIO.md).
- [DBBI nas células zero, primos das cores e listas de somas](../_work/zero_cells_prime_sums_2026-09-16/RELATORIO.md).
- [DBBI/FAED como dados compactados — 11/09/2026](../_work/compressed_payload_2026-09-11/RELATORIO.md).
- [FAED/base 127: busca concluída](../_work/radix127_completion_2026-09-16/RELATORIO.md).
- [Fluxos zlib após substituição decimal](../_work/substituted_zlib_2026-09-16/RELATORIO.md).
- [Inteiro decimal com qualquer ocorrência zerável](../_work/unbounded_zero_integer_2026-09-16/RELATORIO.md).
- [Inteiro decimal zerável com restrições de palavras](../_work/unbounded_integer_words_2026-09-16/RELATORIO.md).
- [Leitura decimal com zeros e UTF‑8 — 16/09/2026](../_work/utf8_decimal_2026-09-16/RELATORIO.md).
- [Leitura decimal em EBCDIC 1141 — 16/09/2026](../_work/ebcdic_decimal_2026-09-16/RELATORIO.md).
- [Listas como sementes e como ordem de colunas](../_work/feedback_decimal_2026-09-15/RELATORIO.md).
- [Remoção opcional de símbolos e zeros na conversão decimal](../_work/optional_null_decimal_2026-09-16/RELATORIO.md).
- [RSA por caractere com os dígitos desconhecidos](../_work/rsa_substituted_digits_2026-09-16/RELATORIO.md).
- [SalPhaseIon: listas, chaves decimais e alfabetos de nove símbolos](../_work/decimal_keystream_2026-09-15/RELATORIO.md).
- [Somas dos sete anéis da matriz — 2026-09-16](../_work/ring_sum_decimal_2026-09-16/RELATORIO.md).
- [Substituição decimal desconhecida e segmentação](../_work/substituted_decimal_2026-09-15/RELATORIO.md).
- [Zeragem de qualquer símbolo — 15/09/2026](../_work/zero_symbol_2026-09-15/RELATORIO.md).

## Matriz, cores e geometria

- [Blocos modulares: formatos de chave e autenticação de amostras](../_work/rsa_color_candidates_2026-09-16/RELATORIO.md).
- [Capitalização dos títulos — 2026-09-16](../_work/title_position_masks_2026-09-16/RELATORIO.md).
- [Chaves das cores com transporte decimal](../_work/color_carry_2026-09-16/RELATORIO.md).
- [Contagens das cores como índices primos — 16/09/2026](../_work/count_prime_matrix_2026-09-16/RELATORIO.md).
- [Continuação da receita de X — 11/09/2026](../_work/blue_hex_2026-09-11/RELATORIO.md).
- [DBBI como produtos internos das linhas ou colunas](../_work/dbbi_gram_2026-09-16/RELATORIO.md).
- [DBBI como SHA256 das somas da matriz](../_work/dbbi_matrix_hash_2026-09-16/RELATORIO.md).
- [DBBI como tabela de distâncias: contradição de paridade](../_work/dbbi_distance_parity_2026-09-16/RELATORIO.md).
- [Exclusão das 14 somas decimais, sem escolher os primos ou a ordem](../_work/symbolic_color_sums_2026-09-16/RELATORIO.md).
- [Fatores primos das cores como pesos da matriz — 16/09/2026](../_work/color_factor_sums_2026-09-16/RELATORIO.md).
- [Frequências inteiras primas como pesos das cores](../_work/frequency_primes_2026-09-16/RELATORIO.md).
- [Listas de somas dos campos DBBI e FAED](../_work/matrix_sum_words_2026-09-16/RELATORIO.md).
- [Matriz como expoentes de um produto de primos](../_work/prime_product_matrix_2026-09-16/RELATORIO.md).
- [Pista imprevista, cores e primos — 11/09/2026](../_work/matrix_hint_2026-09-11/RELATORIO.md).
- [Primos das cores e RSA por caractere](../_work/rsa_color_blocks_2026-09-16/RELATORIO.md).
- [Primos das cores: blocos modulares com vários bytes](../_work/rsa_color_multibyte_2026-09-16/RELATORIO.md).
- [Primos em faixas convencionais de azul e amarelo](../_work/wavelength_primes_2026-09-16/RELATORIO.md).
- [SalPhaseIon: execução da investigação de cores, primos e somas](../_work/prime_geometry_2026-09-11/RELATORIO.md).
- [Somas das cores como chave decimal: todos os pesos inteiros](../_work/color_residue_2026-09-16/RELATORIO.md).
- [Somas diagonais: inversão aritmética com alfabeto desconhecido](../_work/diagonal_sum_inverse_2026-09-17/RELATORIO.md).

## Primos, bases e RSA

- [Bases primas como alfabetos — 2026-09-16](../_work/prime_alphabet_words_2026-09-16/RELATORIO.md).
- [Bases primas na entrada e limites da saída em base 127](../_work/source_prime_radix_2026-09-16/RELATORIO.md).
- [Conclusão dos sessenta casos RSA inconclusivos — 16/09/2026](../_work/rsa_pending_dfa_2026-09-16/RELATORIO.md).
- [FAED como lista de números em bases primas: prefixos](../_work/positional_prime_prefix_2026-09-16/RELATORIO.md).
- [Linhas da matriz interpretadas em bases primas](../_work/positional_prime_bases_2026-09-16/RELATORIO.md).
- [Lista posicional em bases primas: qualquer ordem das linhas](../_work/positional_prime_order_2026-09-16/RELATORIO.md).
- [Potências inteiras antes da conversão em bytes](../_work/integer_power_2026-09-15/RELATORIO.md).
- [Primos como códigos de caracteres — 16/09/2026](../_work/prime_codepoints_2026-09-16/RELATORIO.md).
- [Priorização por linguagem nos cinco modelos parciais — 2026-09-16](../_work/prime_radix_beam_2026-09-16/RELATORIO.md).
- [Valores ASCII primos da URL e reinserção na matriz](../_work/url_prime_reinsertion_2026-09-16/RELATORIO.md).

## Operacoes, fluxos e transposicoes

- [DBBI como chave de transposição de FAED](../_work/dbbi_columnar_2026-09-16/RELATORIO.md).
- [XOR repetido após a conversão decimal](../_work/xor_period_2026-09-15/RELATORIO.md).

## Midia e assinaturas

- [Assinaturas do prêmio: nonces pequenos, relacionados ou recorrentes — 17/09/2026](../_work/prize_nonce_2026-09-17/RELATORIO.md).
- [Contêiner do áudio Decentraland — 2026-09-16](../_work/mp3_container_2026-09-16/RELATORIO.md).
- [Correção do teste histórico de recuperação de assinaturas](../_work/signature_audit_2026-09-16/RELATORIO.md).
