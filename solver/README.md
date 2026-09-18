# solver/ — kit, oráculos e campanhas

A senha final e a chave do prêmio continuam sem validação (ver [`ENDGAME.md`](../ENDGAME.md)).
Esta pasta guarda o **kit** que qualquer teste novo deve usar, os **verificadores** que sustentam
as refutações, e as **campanhas fechadas**, mantidas como evidência reproduzível. Nada aqui é
uma solução. Leia o relatório da campanha (`_work/<nome>/RELATORIO.md`, índice em
[`docs/RESEARCH-INDEX.md`](../docs/RESEARCH-INDEX.md)) antes de executar um script.

## Regras de execução

- Python: `C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe` (único com as
  dependências). Node 24 para `.cjs`. Go 1.26 para os dois módulos Go.
- Raiz do repositório como diretório de trabalho, salvo indicação no docstring. Muitos scripts
  gravam em `_work/<campanha>/` por caminho fixo: **não mova campanhas nem renomeie pastas**.
- Nunca execute a pasta em lote: há buscas de horas e scripts que sobrescrevem evidências.
- Padding AES válido, checksum BIP39 e escore de inglês não são solução. Só conta o oráculo
  duro da regra 1 de `AGENTS.md`: privkey que gera `1GSMG…` ou `17ucy…`, ou abertura AES
  certificada. Plaintext semântico (o `hard` de `G.try_password_all`) é candidato.

## 1. Kit e oráculos (não mover: importados por caminho)

| Arquivo | Papel |
|---|---|
| `experiments/claude_endgame_2026_09_02/gsmg_common.py` | **kit ativo**: dados canônicos (`DBBI`, `FAED`, `BLOBS` SMALL/COSMIC/TAIL32, matriz, espiral, células coloridas), EVP_BytesToKey, `aes_try`/`try_password_all` (registra plaintext em hex, varre privkey, blob aninhado e assinatura EBCDIC), `semantic`, `nested_blob`, `ebcdic_sig`, `priv_hit`/`fast_priv_scan`, `checkerboard_decode/encode`, `bifid`, `z_method`. `python gsmg_common.py` = self-test (fase 2, 3.2.2, espiral, KDF). Importado por ~100 scripts por caminho absoluto. |
| `oracles.py` | oráculos duros históricos (`aes_open`, `check_privkey`, `check_mnemonic`); lê `README.md` pela raiz. Importado por 82 scripts. |
| [`oraculo_duplo_2026_09_17/`](oraculo_duplo_2026_09_17/README.md) | oráculo isolado para `1GSMG…` e `17ucy…`: raw32, hex64 e WIF; ambas as serializações P2PKH; ASCII, cp273 e UTF-16. Coletor com proveniência, scanner retomável e controles independentes. Não modifica o kit ativo; condição de prêmio do segundo endereço não confirmada. |
| `scorer.py` | quadgramas treinados no export do Telegram. **Contaminado**: aprendeu os quadgramas do próprio `dbbi`. Use `primos_2026_09_17/clean_scorer.py` para qualquer escore de texto. |
| `dsl.py`, `search.py` | DSL de operações e Bifid do harness antigo; importados por 14/7 scripts. |
| `experiments/claude_endgame_2026_09_02/BRIEFING.md` | dados, hints e famílias fechadas das rodadas de 02/09 (referência histórica; o estado atual é o `ENDGAME.md`). |

## 2. Verificadores das refutações (rodáveis)

| Script | Prova |
|---|---|
| `verify_community_claims_2026_09.py` | issues #108 (não há typo no SMALL), #111 (`gros` irreproduzível), #110/#99 |
| `final_chain.py`, `strong_oracle_35.py` | reprodução da cadeia comunitária (Chain1→4, 35 blocos) **para auditoria**; é a miragem refutada, não um caminho |
| `ct_montage_attack.py`, `ct_montage_corpus_collect.py`, `ct_blockscan_oracle.py` | montagem do ciphertext × corpus de 1,27 M senhas; oráculo por bloco agnóstico a IV/ordem/padding |
| `mitm16_dbbi_hex/` (Go) + `make_config.py` | as 16! bijeções de `dbbi` (tokens `b`/`g`) como privkey hex, MITM na curva; controle plantado |
| `gpu_aes16_dbbi_hex/` (OpenCL) | as 16! bijeções como senha sha256-hex do SMALL; validado (`validate_result.json`), **não executado** (132 h/variante); `launch.py` retoma por checkpoint |
| `premissas_2026_09_17/` | cifra/modo do openssl, `-kfile`/1.ª linha de arquivo, alfabeto de espectro, senhas Unicode, forense de bytes, varredura retroativa EBCDIC |
| [`multiagente_2026_09_18/`](multiagente_2026_09_18/README.md) | auditoria do cp273 inverso e do filtro de modos de fluxo; recuperação de caudas completas; scanner BE/LE com checkpoints; complemento dos decodificadores, reinserção de primos e geometria da capa. Cobertura e limites no relatório da rodada. |
| `primos_2026_09_17/`, `prime_host_*.cjs`, `rabbit_reference_delta.cjs` | segmentação de `dbbi` por primos (o lead aberto): decoders no resíduo, regra em `faed`, `matrixsumlist` estrutural, marcadores; `clean_scorer.py` |
| `prize_nonce_bsgs/` (Go), `prize_nonce_recurrence.cjs`, `prize_signature_inputs.cjs`, `gsmg_sig_recover.py` | superfície ECC do prêmio (nonces pequenos/relacionados/recorrentes; recuperação por OP_RETURN) |
| `verify_*.cjs` (57) | conferência independente das campanhas `.cjs` homônimas |

## 3. Campanhas fechadas (evidência; premissas ativas)

Famílias sobre `dbbi`/`faed`, a matriz e as cores, todas negativas, cada uma com relatório:

| Prefixo | Família |
|---|---|
| `checkerboard_*`, `joint_checkerboard_*`, `nihilist_*`, `ambiguous_*`, `vic_*`, `straddle_*` | straddling checkerboard / VIC / Nihilist |
| `decimal_*`, `zero_*`, `substituted_*`, `unbounded_*`, `utf8_*`, `joined_*`, `optional_*`, `ebcdic_*`, `brotli_*`, `compressed_*`, `radix127_*`, `source_prime_*`, `zero_free_*`, `ternary_*` | leituras decimais/base com zeros, códigos de caracteres, compressão |
| `color_*`, `matrix_*`, `ring_*`, `diagonal_*`, `positional_*`, `count_prime_*`, `frequency_*`, `wavelength_*`, `symbolic_*`, `dbbi_gram*`, `dbbi_distance_*`, `dbbi_matrix_hash*`, `dbbi_columnar*`, `title_position_*`, `url_prime_*`, `zero_cells_*`, `blue_hex_*`, `prime_geometry_*`, `prime_product_*`, `prime_radix_*`, `prime_alphabet_*`, `prime_codepoints*`, `prime_joined_*` | matriz, cores, somas, primos e bases |
| `rsa_*`, `integer_power_*`, `xor_period_*`, `feedback_*`, `morse_*`, `binary_partition_*` | RSA por caractere, potências, XOR, sementes, Morbit/Pollux, rótulos binários |
| `lf_*`, `cosmic_book_attack.py`, `miroir_*` | livros (*Looking Forward*, *Cosmic Duality*, poema da p.39) |
| `tg2026_*`, `live_site_2026_attack.py`, `first_hint_*`, `answer_phrase_sweep.py`, `roadmap_sweep.py`, `salphaseion_passphrase_sweep.py`, `new_hints_attack.py` | senhas de tokens, roadmap, site, Telegram |
| `dbbi_hash_*`, `dbbi_repeat_attack.py`, `xor_key_attack.py`, `bip39_passphrase_attack.py`, `exact_plaintext_tail32_attack.py`, `tail32_*` | dbbi como hash, chave XOR, BIP39, TAIL32 |
| `experiments/claude_endgame_2026_09_02/*.py` (exceto o kit) | rodadas 1–3 de 02/09: Bifid 3×3 exaustivo, keystreams, permutações, seleção de bits, running keys, KDFs, brainwallet, estego PNG, mineração do Telegram |

## 4. Ferramentas da cadeia refutada (premissa inválida; mantidas como evidência)

Scripts que importam `final_chain`/`strong_oracle_35` ou assumem `BTCSEED`/`BIF_REST`/`half`/
`better_half` como reais: `a1_integrity_checks.py`, `a3_rereads_attack.py`, `a4_controls.py`,
`anomaly_dbbi_attack.py`, `architect_*`, `blue_net_attack.py`, `btcseed_*`, `bifrest_*`,
`chain4pw_frontier.py`, `composition_attack.py`, `direct_combine.py`, `duality_attack.py`,
`eps35_attack.py`, `first_hint_frontier.py`, `intertwine_attack*.py`, `inv1_*`, `inv2_*`,
`inv3_*`, `mask_provenance.py`, `mirror_attack.py`, `neighbors_attack.py`, `new_hypotheses*.py`,
`pop_culture_attack.py`, `seed_*`, `send_blue_sethex_attack.py`, `skeptic_*`, `strong_recheck.py`,
`third_grammar_attack.py`, `matrixsum_attack.py`, `alphabet_group_attack.py`,
`faed_matrix_sum_attack.py`, `color_prime_faed_shift.py`, `colored_prime_dbbi_attack.py`,
`vic_anchor_scan.py`, `prime_attack.py`, `checkerboard.py`. Vários se importam por nome, por isso
ficam onde estão. **Não use como base para hipóteses novas**; os controles `skeptic_*` e `a4_controls`
são o que mostra que a cadeia não ancora.

O harness autônomo llama3/GPU (`launch.py`, `runner.py`, `gpu_search.py`, `gpu_checkerboard.py`,
`gpu_trifid.py`, `interpret.py`, `selftest.py`, `vector_graph.py`) foi removido em 17/09/2026:
assumia `BTCSEED` como âncora e dependia de torch/Ollama. Está no histórico do git (`d90f901`).

## 5. Como registrar uma campanha nova

1. Hipótese em prosa, finita e falsificável; conferir a tabela §4 do `ENDGAME.md`.
2. Script aqui (subpasta por campanha quando houver mais de um arquivo), usando o kit.
3. Controle positivo, nulo casado (≥ 100 embaralhamentos), plaintexts com padding em hex.
4. `_work/<nome>_<data>/RELATORIO.md` com cobertura exata e limites; linha em
   `docs/RESEARCH-INDEX.md`; entrada no `ENDGAME.md` só se mudar o mapa.
