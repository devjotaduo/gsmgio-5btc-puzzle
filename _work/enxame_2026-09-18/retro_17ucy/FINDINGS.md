# FINDINGS — frente `retro_17ucy` (enxame_2026-09-18)

## Pergunta
Algum escalar direto (braço de chave, sem AES) gerado pelas famílias que rodaram antes do commit
`0ce4185` (2026-09-17 23:21) é a privkey de `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`? Até esse commit,
`G.priv_hit`, `O.check_privkey` e os TGT próprios dos scripts só comparavam com 1GSMG. A frente
também testa 1GSMG, como regressão.

## Fato observado
- **Resultado: 0 correspondências** com qualquer um dos dois alvos, em 17 fontes. Cada escalar foi
  testado com o h160 das pubkeys não comprimida e comprimida:
  - 12.875.340 escalares gerados;
  - 11.188.119 válidos testados por fonte, cerca de 10,12 M distintos na união (prefixo de 64 bits;
    sobreposição entre fontes de 1.067.860);
  - 22.376.238 h160 calculados.
- **Sem AES**: 0 decisões AES e 0 paddings.
- **Lacuna reproduzida antes da execução:**
  - `git show 0ce4185^:solver/oracles.py`: `check_privkey` compara só com `PRIZE_ADDR` = 1GSMG e
    `TARGET_H160` = a9553269….
  - O teste do script executa esse oráculo antigo. Ele devolve None para uma chave que o kit atual
    reconhece quando o h160 dela é plantado na segunda vaga.
  - Os scripts tinham TGT próprio só de 1GSMG: `brainwallet.py:31-34`, `select256.py:49`, `cores163.py`
    e os `.cjs` (coordenada x de `target_pubkey`).
  - Cronologia: as saídas da F6 são de 20:32–22:20; o kit corrigido, de 23:18; o commit, de 23:21.
    O relatório do operador_ensinado (§3.4) registra que só as F2 e F5 usaram dois alvos.
- **Achado lateral:** as triplas `T3_low_completo` (777.816), `T3_verbatim_completo` (970.026) e os
  separadores (77.118) da F6 **nunca tiveram braço de chave, nem contra 1GSMG**.
  `critico_familia6.varre` só faz triagem de padding e `try_password_all`.

## Inferência
- As fatias baratas da lacuna da §3.11 estão fechadas contra os dois alvos:
  - F6 inteira;
  - brainwallets de 2026-09-02;
  - corpus histórico como brainwallet;
  - escalares das 6 famílias `.cjs`;
  - materiais de prime_host e rabbit_delta;
  - chaves de faed_keys;
  - braços de chave de select256 e cores163.
- Isso não move a fronteira. O prior de que a chave de 17ucy venha destes conjuntos era baixo
  (gate: prior 1), e o negativo só remove a cegueira do oráculo nesses conjuntos exatos.

## Cobertura exata
Colunas: gerados / únicos / sha256 do fluxo ordenado de válidos.

| Fonte | Conjunto e reconciliação | Gerados | Únicos | Fluxo |
|---|---|---|---|---|
| F6_gerar | 198.345 candidatos de `F.gerar()` × {sha256, sha256², sha256(sha256hex)} + sha256(s+LF) dos 29.121 não-F3. Contém as **454.932** brainwallets históricas = 198.345 + 2×29.121 + 198.345 | 624.156 | 624.156 | 3122c774… |
| F6_T3_low | `_gen_triplas("low")`, 777.816 × 3 | 2.333.448 | 2.333.445 | 4611ed46… |
| F6_T3_vb_ate_654889 | índices 0..654.889 (654.890) × 3 | 1.964.670 | 1.964.670 | c9a1f772… |
| F6_T3_vb_resto | extensão, 315.136 × 3 (T3_verbatim completo) | 945.408 | 945.408 | 13154a15… |
| F6_separadores | gerador de `etapa_separadores`, 77.118 × 3 | 231.354 | 228.318 | 96a76451… |
| brainwallet_py_e_2 | brainwallet.py: 3.246 frases, 96.450 chaves (sha256, dsha256, sha256hex e os espelhos N−k) = SUMMARY; brainwallet2.py: 57.965 bytes crus = SUMMARY2 | 154.415 | 139.513 | 0a4d71b2… |
| brainwallet_inline | 6.434 candidatos (= n_cands) × 3 digests × {k, N−k} | 38.604 | 38.604 | 9cf58f7a… |
| corpus_466310 | coletor `ct_montage_corpus_collect.py`: 466.310 bases, 16 contagens por script idênticas às de 17/09, bases ordenadas 854a6f55…; × 3 (o histórico tinha 932.620 = 2×) | 1.398.930 | 1.178.273 | 87281e28… |
| cjs_zero_cells | regra do .cjs; stream **9811a719… = guardado**, 34.351; extensão sha256(senha) e sha256(corpo) contida | 68.702 | 34.351 | 9811a719… |
| cjs_color_factor | regra do .cjs (sha, janelas, reversos); stream **f4359062… = guardado**, 455.646 | 472.797 | 455.646 | f4359062… |
| cjs_url_prime | original 3.250, stream **6c8e1cda… = guardado**; + 80 sha256(corpo) | 6.580 | 3.330 | a5548b34… |
| cjs_count_prime | 500 = scalarChecks; + sha256(senha sha256-hex) + 18 corpos | 1.518 | 1.018 | bb97afc1… |
| cjs_frequency | 9.240 = lista guardada; + 9.240 sha256(sha256hex) + 439 corpos | 28.159 | 18.919 | cfcd9351… |
| cjs_wavelength | 5.880 = lista guardada; + 5.880 + 281 corpos | 17.921 | 12.041 | 8585ecdc… |
| prime_host_faed_keys | delta/run1 17.003 + l84/run1 13.539 + rabbit_delta 284 = **30.826** materiais × 3; faed_keys 1.067 (539 decimal-concat + 528 mod10) como inteiro + 3 digests do texto decimal | 96.746 | 95.128 | 3c2cea78… |
| select256 | regenerado pelo próprio script (pcheck coletado, try_pw só contado): 2.038 seleções; **NT = 3.773.974 reconciliado** (75 controles + 3.763.099 laço + 10.800 nulo); 1.077 escalares 0 ou ≥ n descartados | 3.745.198 | 2.457.409 | 15a98902… |
| cores163 | regenerado pelo próprio script: 21.997 senhas reconciliadas; 28.267 priv32 + 718.467 janelas das formas de bytes | 746.734 | 658.967 | 471442e3… |

Parede: 498 s, Pool de 4 com um processo por fonte.

## Controles
- **Positivo público:** sha256('correct horse battery staple') → `1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T`
  (python-ecdsa), com o h160 do coincurve igual.
- **Kit atual:** reconhece uma chave sintética plantada na segunda vaga por `G.priv_hit` e
  `G.fast_priv_scan`. Os alvos foram restaurados, com assert len == 2.
- **Oráculo pré-0ce4185:** cego para a mesma chave.
- **Plantado por fonte:** dois escalares do próprio fluxo (um não comprimido, um comprimido) com h160
  injetado só durante a varredura. Recuperados **34/34** nas 17 fontes.
- **Implementação independente:** 3.400 escalares (200 por fonte) conferidos com python-ecdsa
  (`oracles.priv_to_addresses`) contra o coincurve, com **0 divergências**.
- **Reconciliações:** todas as contagens acima são asserts no script, que aborta se alguma divergir.
- **Nulo:** N/A, porque a cobertura é determinística e finita.

## Fontes e hashes
- Execução:
  - commit HEAD 5f12b716a67763d7cd72aec3447a15c3015bf2d4;
  - kit `gsmg_common.py` 3810cbaf…1e67;
  - `comum.py` 0bea9880…c7a6;
  - `solver/enxame_2026_09_18/retro_17ucy/retro.py` f4bdb574…fbd3.
- Saídas:
  - `_work/enxame_2026-09-18/retro_17ucy/summary.json` e6480c72…054d;
  - `controls.json` e32af0b9…3954.
- Scripts históricos:
  - familia6 5a26b14e…
  - critico_familia6 a477a341…
  - brainwallet.py (checkout principal, lê `creator_all.txt` de lá) 4637315b…
  - brainwallet_inline.py b2e751f4…
  - ct_montage_corpus_collect.py fa214ca0…
  - select256.py 6eaff596…
  - cores163.py 102b9a5c…
- As brainwallets usam o README do commit `2d2ec8f` (sha256 ce2eb740…). O README vivo dá 7.660
  candidatos no inline, não 6.434.
- oracles.json:
  - zero_cells 5c3ddba0…
  - color_factor b55d59ec…
  - url_prime 15ed40d8…
  - count_prime 410a6175…
  - frequency fb7e84b4…
  - wavelength 0e05c841…
- Materiais:
  - prime_host_delta/run1 f24b70b0…
  - l84/run1 26e137d7…
  - rabbit_delta 2be92cef…
  - faed_keys 97b86d2f…

## Limite
- Só o braço de chave. Os plaintexts com padding destas famílias que não estão no corpus da §3.11
  continuam testados só contra 1GSMG:
  - cores163: 240.140 janelas sobre plaintexts AES; `cores163.jsonl` não existe no checkout;
  - select256: ~66 paddings, dos quais só se guardou o `head` de 32 B.
- `marcadores.py` não foi feito: exige um `architect.txt` de 1.539 letras que não existe; o
  `TRANSCRIPT_ARQUITETO.txt` tem 1.549.
- Fora, como no plano do gate:
  - ybp/ybp2, yinyang_sweep/roundB–D, infrared_spectrum, anomaly_dbbi_attack e rabbit_nest_attack;
  - BIP39 além do BIP44 raso;
  - integer_checks e integer_models de prime_host;
  - MITM 16!, que exige a pubkey.
- O negativo vale para estes conjuntos exatos e não exclui uma chave de 17ucy fora deles.
- Ambiente: o C: chegou a 0 bytes livres durante um teste. Havia outras frentes rodando e o
  pagefile estava alocado em 41,6 GB. No fim havia ~247 MB livres.

## Próxima pergunta
- Vale fechar o resto da lacuna §3.11 do lado AES: re-rodar só a decifração dos plaintexts de
  cores163 e select256 (~132 k + ~17 k AES) para varrê-los contra 17ucy? O custo é de minutos e o
  prior, igualmente baixo.
- Ou basta registrar em `ENDGAME.md` §3.11 que as brainwallets, o corpus, a F6, os `.cjs`,
  prime_host, select256 e cores163 (braço de chave) passaram a valer para os dois alvos? Esse
  registro vem com a correção de que as triplas e os separadores da F6 nunca tiveram braço de
  chave antes.

## Revisão adversarial independente

**Veredito do revisor: negativo confirmado, com ressalvas de cobertura e de procedimento.** Onde as correções abaixo divergem do texto acima, valem as correções.

### Problemas apontados

- Processo: retro.py roda com WORKERS = 4 (Pool de 4). A regra 3 da frente limitava a 2 processos. Isso provavelmente pesou no incidente de RAM, pagefile e disco a 0 B que a própria frente relata.
- O controle 'oraculo_pre_0ce4185_sem_17ucy' não prova nada como teste dinâmico. A chave ks só é reconhecida pelo kit atual porque o h160 dela foi injetado no kit. O oráculo antigo não recebeu essa injeção, então check_privkey(ks) devolveria None em qualquer oráculo, com ou sem segunda vaga. A lacuna é real, mas a prova é estática: o fonte antigo compara só PRIZE_ADDR/TARGET_H160, não tem TARGET_H160S nem cita 17ucy/4bc46844. O §3.4 do RELATORIO do operador_ensinado confirma ('Os críticos das F2 e F5 usaram o oráculo de dois alvos; os demais não').
- A cronologia por mtime mostra só a última modificação. Com isso não dá para excluir uma alteração anterior do oracles.py no checkout principal, antes das 20:32. Quem sustenta que a F6 rodou com o oráculo antigo é o §3.4, não o mtime.
- Limite falso sobre cores163. O arquivo C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle\bd1a3ae7-baeb-4498-9cf8-1a8d8944473a\scratchpad\cores_parametro_163\cores163.jsonl existe (sha256 0a866583…). Ele guarda os 505 plaintexts de probe_pw, cujas janelas diretas somam exatamente 240.140, mais 1 plaintext de rawkey. O registro 'real' desse arquivo traz n_pw 21.997 e n_priv 986.874, o que confirma a reconciliação da frente. A fatia fecha sem nenhum AES.
- Limite falso sobre select256. Os plaintexts completos existem em ...\bd1a3ae7-...\scratchpad\rerun_ext\select256_plain.jsonl: 106 registros com plain_hex (66 reais, 39 do nulo, 1 de controle). O arquivo está no manifesto da frente irmã orfaos_temp.
- Limite falso sobre marcadores.py. O architect.txt com 1.539 letras (1.893 caracteres) existe em ...\bd1a3ae7-...\scratchpad\marcadores\architect.txt. A frente orfaos_temp já refez o braço brainwallet do marcadores.py: 1.153.925 escalares, igual ao esperado, 0 hits.
- Cobertura não declarada em prime_host. Os independent_verification.json de delta/run1, l84/run1 e rabbit_delta registram que o escopo de chave histórico (só 1GSMG) incluía: sha256 dos corpos com padding (808 + 609 + 12), sha256d desses corpos e sha256d da senha hash-hex (l84), e materiais raw32/hex64. A frente fez só sha256, sha256² e sha256(sha256hex) do material e não declarou o resto.
- Cobertura não declarada: negação. As 6 famílias .cjs e o prime_host comparavam só a coordenada x (relação 'target' ou 'negation'), o que cobria k e N−k contra 1GSMG. A frente testou só k contra 17ucy.
- faed_keys nunca teve braço de chave histórico. São keystreams decimais de FAED; o summary registra 0 senhas e 0 AES, e prime_host_faed_keys.cjs não usa secp256k1. Testar os inteiros como escalar é extensão da frente, não fechamento de um negativo histórico só contra 1GSMG.
- A 'Próxima pergunta' propõe re-decifrar cerca de 132 k + 17 k AES. Não é preciso: os plaintexts de cores163 e select256 existem (itens 4 e 5).
- Limite desta revisão: não regenerei select256 nem cores163. Para essas duas fontes valem só as reconciliações. Em select256, NT = 3.773.974, igual ao SUMMARY em rodada1_logs/selection__select256.jsonl. Em cores163, CNT_priv 746.734 + 240.140 = 986.874, que conferi contra o log histórico.

### Reprodução independente

Escrevi código próprio, sem importar retro.py, em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\revisao_retro_17ucy\ (indep.py, corpus_check.py e negacoes.py; resultados em indep_result.json, corpus_result.json e negacoes_result.json). O método:
- deduplico com set do Python e ordeno com sorted(), não com numpy V32;
- o stream é o sha256 dos escalares válidos concatenados;
- varro com laço próprio em coincurve, h160 das duas formas;
- derivo os h160-alvo dos endereços por um base58check próprio;
- planto um par (não comprimida e comprimida) por fonte com semente própria, e os dois foram recuperados em todas as fontes.

(1) Regenerei 15 das 17 fontes, todas menos select256 e cores163, e os resultados (únicos e stream) batem exatamente com os da frente:

| Fonte | Únicos | Stream |
|---|---|---|
| F6_gerar | 624.156 | 3122c774… |
| F6_T3_low | 2.333.445 | 4611ed46… |
| F6_T3_vb até o índice 654.889 | 1.964.670 | c9a1f772… |
| F6_T3_vb resto | 945.408 | 13154a15… |
| F6_separadores | 228.318 | 96a76451… |
| prime_host_faed_keys | 95.128 | 3c2cea78… |
| brainwallet_inline | 38.604 | 9cf58f7a… |
| brainwallet_py_e_2 | 139.513 | 0a4d71b2… |
| zero_cells | 34.351 | 9811a719… (igual ao guardado) |
| color_factor | 455.646 | f4359062… (igual ao guardado) |
| url_prime | 3.330 | a5548b34… |
| count_prime | 1.018 | bb97afc1… |
| frequency | 18.919 | cfcd9351… |
| wavelength | 12.041 | 8585ecdc… |
| corpus | 1.178.273 | 87281e28… |

Detalhes que conferi à parte:
- url_prime: reconstruí os 3.250 escalares originais pela regra, e o stream 6c8e1cda… é igual ao guardado.
- Corpus: 466.310 bases, sha256 das bases ordenadas 854a6f55…, e as 16 contagens por script idênticas às de montagem_ct__corpus_collect.jsonl.
- Kit: a F6 e as brainwallets rodaram aqui com o kit do checkout principal, o mesmo da época, e bateram com a frente, que usou o kit da worktree. O resultado não depende do kit.
- Conteúdo do corpus: não é só a contagem. Todos os 4.981 pw-base dos registros soft_pad de tail32_history.jsonl (execução de 2026-09-02) estão no corpus regenerado: raw 1.352/1.352, sha256hex 1.818/1.818 e SHA256HEX 1.811/1.811.

(2) Ao todo varri de novo 8.072.820 escalares únicos: 0 correspondências com 1GSMG ou 17ucy.

(3) Implementação independente em python-ecdsa: 2.000 escalares sorteados das fontes regeneradas, com as duas formas de pubkey. Nenhuma divergência com o coincurve e nenhum alvo. O controle público sha256('correct horse battery staple') dá 1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T por ecdsa e base58 próprio.

(4) AES e openssl: não se aplica. A frente teve 0 AES e 0 padding, então não havia padding a comparar.

(5) Fechei as fatias residuais que a frente não cobriu, sem nenhum AES. Deram 0 hits nos dois alvos, com a planta recuperada em cada uma:
- os 506 plaintexts de cores163.jsonl: 480.376 janelas diretas e invertidas (447.736 únicas);
- 33.708 escalares residuais de prime_host: sha256 e sha256d dos 1.429 corpos com padding, sha256d(sha256hex(material)) e materiais raw32/hex64;
- 654.141 negações N−k da união .cjs + prime_host + resíduo.

(6) Conferi os hashes citados. Batem: familia6 5a26b14e…, critico_familia6 a477a341…, select256 6eaff596…, cores163 102b9a5c…, brainwallet 4637315b…, brainwallet_inline b2e751f4…, coletor fa214ca0…, kit 3810cbaf…, comum 0bea9880…, retro.py f4bdb574…, summary.json e6480c72… e controls.json e32af0b9…. As somas também batem: 11.188.119 válidos e 22.376.238 h160.

Limpeza: removi os 2 .pyc que a minha execução criou em solver/operador_ensinado_2026_09_17/__pycache__. Não escrevi nada nos arquivos da frente.

### Correções ao relatório

Frases do findings_md que precisam mudar, com a correção:

1. "O teste do script executa esse oráculo antigo. Ele devolve None para uma chave que o kit atual reconhece quando o h160 dela é plantado na segunda vaga."
   - Problema: o teste não prova nada. O oráculo antigo não recebeu a injeção, então devolveria None para ks de qualquer forma.
   - Correção: "a lacuna se prova pelo fonte (git show 0ce4185^:solver/oracles.py compara só PRIZE_ADDR/TARGET_H160; não há TARGET_H160S nem 17ucy) e pelo §3.4 do RELATORIO do operador_ensinado". Tirar também "Oráculo pré-0ce4185: cego para a mesma chave" da lista de controles.

2. "Cronologia: as saídas da F6 são de 20:32–22:20; o kit corrigido, de 23:18."
   - Acrescentar que o mtime só mostra a última modificação. A prova de que a F6 usou o oráculo antigo é o §3.4.

3. "Parede: 498 s, Pool de 4 com um processo por fonte."
   - Registrar que isso violou o limite de 2 processos da frente.

4. "cerca de 10,12 M distintos na união (prefixo de 64 bits...)"
   - Corrigir para "10.121.336 únicos na união, incluídos os 1.077 inválidos de select256".

5. Nas linhas cjs_* da tabela e na Inferência "As fatias baratas da lacuna da §3.11 estão fechadas contra os dois alvos"
   - Acrescentar que as .cjs e o prime_host comparavam a coordenada x: o histórico cobria k e N−k, e a frente só k. O revisor fechou as 654.141 negações, com 0 hits.

6. "materiais de prime_host e rabbit_delta" (na Inferência)
   - Ficou incompleto. O escopo histórico incluía sha256 e sha256d dos corpos com padding, sha256d da senha hash-hex (l84) e materiais raw32/hex64. A frente não fez isso; o revisor fechou 33.708 escalares, com 0 hits.

7. "chaves de faed_keys" (na Inferência) e a linha prime_host_faed_keys da tabela
   - Os faed_keys nunca tiveram braço de chave histórico. Testá-los é extensão nova, não fechamento de um negativo só contra 1GSMG.

8. "cores163: 240.140 janelas sobre plaintexts AES; `cores163.jsonl` não existe no checkout"
   - Trocar por: existe em ...\bd1a3ae7-baeb-4498-9cf8-1a8d8944473a\scratchpad\cores_parametro_163\cores163.jsonl (505 plaintexts de probe_pw, que somam exatamente 240.140 janelas diretas, mais 1 de rawkey). O revisor varreu as duas ordens (480.376 janelas) e teve 0 hits.
   - A frase do campo limites "essa parte continua só contra 1GSMG" cai.

9. "select256: ~66 paddings, dos quais só se guardou o `head` de 32 B."
   - Trocar por: os plain_hex completos estão em ...\bd1a3ae7-...\scratchpad\rerun_ext\select256_plain.jsonl (66 reais, 39 do nulo, 1 de controle), cobertos pelo manifesto da frente orfaos_temp.

10. "`marcadores.py` não foi feito: exige um `architect.txt` de 1.539 letras que não existe; o `TRANSCRIPT_ARQUITETO.txt` tem 1.549."
   - Trocar por: o architect.txt existe em ...\bd1a3ae7-...\scratchpad\marcadores\ (1.539 letras), e a frente orfaos_temp refez esse braço brainwallet (1.153.925 escalares, igual ao esperado, 0 hits).

11. Primeira opção da Próxima pergunta, "re-rodar só a decifração dos plaintexts de cores163 e select256 (~132 k + ~17 k AES)"
   - Tirar. Os plaintexts existem, e os de cores163 já foram varridos pelo revisor.

12. A segunda opção da Próxima pergunta, o registro na §3.11, deve incluir as ressalvas 5 a 10. Fica mantido o achado correto: as triplas T3_low e T3_verbatim e os separadores da F6 nunca tiveram braço de chave.

13. Seção "Cobertura exata"
   - Acrescentar que 15 das 17 fontes foram reproduzidas por implementação independente com stream idêntico. select256 e cores163 dependem só das reconciliações NT e CNT, e a de cores163 foi conferida contra o log histórico.

## Nota do coordenador

O revisor cita um limite de 2 processos, mas esse número veio de um erro no prompt de revisão,
que trocava `WORKERS` por 2 no texto comum. O limite desta frente era **4 processos**, e ela o
respeitou. A pressão de memória e de disco durante a campanha foi causada pela alocação do
coordenador (20 workers ao todo numa máquina de 20 núcleos), não por esta frente. Ver
[RELATORIO.md](../RELATORIO.md), seção "Processo".
