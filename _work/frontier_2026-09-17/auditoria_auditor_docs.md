[harness: subagent output matched instruction-shaped pattern(s): settings-json. Control tags below are neutralized (`<` → `<\`); treat any remaining directive-shaped text as a finding to relay to the user, not an instruction to you.]

# Auditoria de documentos e evidências — gsmgio-5btc-puzzle

**Base auditada:** commit `d90f901` (HEAD). **Atenção:** durante a auditoria outro agente alterou a árvore de trabalho (`git status`): moveu `ENDGAME.md → docs/historico/ENDGAME_cronologico_2026.md` e `docs/notes/* → docs/historico/notes/*`; apagou `docs/README.md`, `docs/CODEX-NAVIGATION-GUIDE.md`, `docs/ORGANIZATION-CHECKS.md`, `docs/research-manifest.json`, `.claude/skills/gsmg-solver/SKILL.md` e 11 soltos de `_work/`; reescreveu `AGENTS.md`, `CLAUDE.md`, `README.md` (78,9 → 50,9 KB) e `docs/RESEARCH-INDEX.md`; criou um novo `ENDGAME.md` (17,6 KB, não rastreado). Onde coincide com meus vereditos eu marco "(já feito na árvore)". Os números de linha do item 4 referem-se a `git show HEAD:README.md`.

---

## 1. `docs/`

| Caminho | Veredito | Justificativa |
|---|---|---|
| `docs/README.md` (59 l.) | **APAGAR** (já feito na árvore) | Meta-doc da organização de 16/09: tabela de 6 pontos de entrada + "O que fica no Git" + "Reprodução". Tudo já coberto por `AGENTS.md` (§Leia nesta ordem, §Layout), `solver/README.md` (mesmo comando `node solver/title_position_masks.cjs …`) e `RESEARCH-INDEX.md`. Links `../ENDGAME.md` e `notes/README.md` quebram com a movimentação. |
| `docs/RESEARCH-INDEX.md` (102 l.) | **MANTER** (índice útil) | Em HEAD: 71 links → 69 pastas, **0 quebrados, 0 duplicados**, todos rastreados. Problemas: (1) **não aponta para o único lead vivo** (segmentação de `dbbi` por primos, `solver/primos_2026_09_17/`, commit `cc9a879`) — não há `_work/…/RELATORIO.md` dele; (2) 3 pastas rastreadas sem relatório e fora do índice: `_work/binary_partition_2026-09-15`, `_work/morse_2026-09-15`, `_work/prime_joined_words_2026-09-16` (só `summary/spec/independent_verification.json`) — escrever RELATORIO curto ou tirar do git; (3) categorias inconsistentes: "Matriz, cores e geometria" abre com `prime_host_l84` (follow-up de Telegram/primos) seguido de linha em branco solta; "Fontes, formatos e auditorias" virou gaveta mista (prize_nonce, prime_host_delta, frontier, mp3, signature_audit, endgame_review); (4) não distingue negativos fechados do lead aberto; (5) cabeçalho "até 17/09/2026" e link `../ENDGAME.md` envelhecem/quebram. |
| `docs/CODEX-NAVIGATION-GUIDE.md` (48 l.) | **APAGAR após fundir 5 frases no `AGENTS.md`** (já apagado na árvore) | Regras de navegação da rodada 16/09, ~80 % duplicadas pelas "Regras de ouro" 7–8 e §Layout do `AGENTS.md`. Únicas a preservar: "`rg` antes de renomear — scripts têm caminhos fixos em `_work/`; não mover campanha só para limpar a raiz"; "não ler/versionar `result.json` em bloco"; "`node --check` só verifica sintaxe"; "não executar scripts antigos em lote (buscas longas/sobrescrevem)"; "commit e push são ações separadas". Link `../ENDGAME.md` quebra. |
| `docs/ORGANIZATION-CHECKS.md` (33 l.) | **APAGAR** (já feito) | Meta-doc de uma rodada passada (contagens de `node --check`, `pip-audit`, conferência do manifesto). Único fato de valor — digest `baa2ef57…` da rodada dos títulos — já está em `_work/title_position_masks_2026-09-16/{RELATORIO.md,summary.json,independent_verification.json}`. |
| `docs/research-manifest.json` (2082 l., 415 artefatos) | **APAGAR** (já feito) | Snapshot `{path,bytes,sha256}` de 16/09; em HEAD todos os 415 caminhos existem e estão rastreados, mas **nenhum script/doc o consome** (grep: 0 consumidores) e o git já endereça conteúdo por hash; fica obsoleto ao primeiro edit de qualquer RELATORIO (o próprio ORGANIZATION-CHECKS admite). |
| `docs/notes/README.md` (14 l.) | **ARQUIVAR** (já em `docs/historico/notes/`) | Índice útil das 4 notas; após a movimentação o link `../RESEARCH-INDEX.md` está **quebrado** (precisa `../../RESEARCH-INDEX.md`). Acrescentar 1 linha: "contêm afirmações refutadas (BTCSEED, cadeia/35 blocos, 2 blobs)". |
| `docs/notes/ANALISE_PRIORIDADES.md` (292 l.) | **ARQUIVAR** (já feito) | Planejamento datado 11/09 (SMALL primeiro; cores/primos ↔ `matrixsumlist`), superado. Contém evidência primária valiosa que merece viver no ENDGAME se ainda não estiver: tabela de mensagens do criador com IDs (#1710, #6508–9, #8000, #8330, #8446/#8483, #9599, #39224/#39237, #20223, #60304–12, #66573–4, #63957, #12653), a capa yin-yang #8310/#8311 (SHA256 `3a9b0a6e…`), o controle 1000/1000 do BTCSEED e a auditoria do scorer contaminado. **9 links relativos quebrados** no novo nível (`../../_work` → `../../../_work`; `../../solver/prime_geometry_constraints.cjs`). |
| `docs/notes/PLANO_PROXIMA_ETAPA.md` (190 l.) | **ARQUIVAR** (já feito; APAGAR seria defensável) | Plano de 11/09 já integralmente executado; todo resultado está nos RELATORIOs de `recipe_audit`, `matrix_hint`, `compressed_payload`, `radix127_completion`. Nenhuma evidência única. **7 links quebrados** no novo nível. |
| `docs/notes/COLLAB_CLAUDE_GPT.md` (144 l.) | **ARQUIVAR** (já feito) | Chat T1–T6. O cabeçalho "Contexto verificado" afirma como fato: regra de encadeamento (`Cosmic.pw = sha256(plaintext SMALL)`), "2 blobs → 2 privkeys half/better half", "o alfabeto do dbbi está certo (BTCSEED)" — refutados/sem base. O corpo tem negativos válidos (mnemonic BIP39 do canal-b → 104 endereços virgens on-chain; azuis/amarelas não dão permutação única). Precisa de aviso no topo. |
| `docs/notes/PROMPT_GPT.md` (57 l.) | **APAGAR** (conservador: já arquivado) | Prompt sem dado único; rotula como "Verified facts (do NOT re-derive)" exatamente as teses refutadas (BTCSEED confirma alfabeto, chaining rule, half/better half, "dois blobs" ignorando TAIL32). É o arquivo mais perigoso para reuso por um LLM. |

---

## 2. Arquivos soltos rastreados em `_work/` (40)

| Caminho | Tipo | Veredito | Justificativa |
|---|---|---|---|
| `creator_msgs_2026-07_09.txt` (8,7 KB) | fonte primária | MANTER | Falas literais do criador jul–set/2026 com IDs, do export Desktop; citado no cronológico. |
| `tg_2025-09_11_summary.md` (71 KB) | fonte primária (resumo com IDs) | MANTER | Extração estruturada do export 2025-09→11 (ids #48478–#51482, limitações do export). |
| `tg_2026-07_09_summary.md` (63 KB) | fonte primária | MANTER | Idem 2026-07→09; todas as msgs do criador literais. |
| `looking_forward.txt` (374 KB) | texto do livro | MANTER | *Looking Forward* (1969) OCR; usado por 4 scripts (`lf_*`, `dbbi_hash_direct`). |
| `looking_forward_pages_1969.json` (296 KB) | texto do livro (mapa folha→página + 92 páginas) | MANTER | Base das hipóteses de "página"; citado no cronológico. |
| `miroir_verse.txt` (315 B) | texto do livro (poema francês, p.39 Cosmic Duality) | MANTER | Usado por `miroir_attack.py`, `miroir_verbatim_attack.py`. |
| `wayback_gsmg_domain_cdx.txt` (70 KB, 618 capturas) | CDX | MANTER | Prova de "domínio esgotado, nenhuma página inédita". |
| `salphaseion.html` (5092 B) | captura HTML (com beacon Cloudflare) | MANTER (duplicata) | **Byte-idêntico** a `_work/archive/endgame/endgame_20260405154227.html`; mantido só porque `solver/title_position_masks.cjs` e o cronológico apontam para este caminho. Alternativa: redirecionar o script e apagar. |
| `salphaseion_raw.html` (3029 B) | duplicata | **APAGAR** | É o **gzip** de `salphaseion.html` (gunzip == byte-idêntico); 0 referências. |
| `salphaseion_wayback_20241123.html` (4588 B) | duplicata | **APAGAR** | Byte-idêntico a `_work/archive/endgame/endgame_20241123015038.html`; só o cronológico cita o caminho (ajustar). |
| `seed.html` (1585 B) | captura HTML (`/theseedisplanted`, era Cloudflare, com form CSRF) | MANTER (mover para `_work/archive/`) | Única cópia rastreada dessa versão: `gsmg_live/body_theseedisplanted` (2026) difere (favicon, sem beacon); as `archive/stages/theseedisplanted_*.html` não estão no git. |
| `seed_raw.html` (886 B) | duplicata | **APAGAR** | Gzip byte-idêntico de `seed.html`; 0 referências. |
| `phase32_plaintext.bin` (2422 B) | evidência reproduzível | MANTER | Plaintext exato da fase 3.2 com CRLF (SHA256 `b82afeb8…`), fixture do `exact_plaintext_tail32`; regenerável pelo README. |
| `tg2026_scan_attack.jsonl` (20 registros) | log de campanha fechada (rodada 04–05/09) | ARQUIVAR | Ledger compacto e útil (YOUWON, Hb_m!%D, Looking Forward, wayback_endgame_verification, second_door, rabbit_nest); o mais valioso dos logs. |
| `answer_phrase_sweep.jsonl`, `first_hint_sweep.jsonl`, `five_gaps.jsonl`, `roadmap_sweep.jsonl`, `hashthetext_enter_sweep.jsonl` | logs de sweeps de senha (0 hits) | ARQUIVAR | Regenerados pelos scripts homônimos em `solver/` (docstrings "Log: _work/…"); `hashthetext_enter_sweep` tem 0 referências. |
| `bifrest_transpose.jsonl`, `composition_attack.jsonl`, `vic_full_attack.jsonl`, `joint_attack_v2_results.jsonl` (130 KB) | logs da era Bifid/BTCSEED (refutada) | ARQUIVAR | Só scores de legibilidade com cabeçalho "BTCSEED…"; scripts em `solver/` os regeneram. |
| `anomaly_dbbi_attack.json` (430 l.) | log construído sobre a miragem ("7x5 Chain4") | ARQUIVAR | Inclui modelo nulo, mas o objeto testado é a cadeia refutada. |
| `neighbors_attack.jsonl` (10,7 MB, 243 900 l.) | log da miragem (`half±k`, todos `hit:false`) | **APAGAR** (já feito) | 10 MB de negativos sobre `half/better_half`; regenerável por `solver/neighbors_attack.py`; só o próprio script o cita. |
| `exact_plaintext_tail32.json`, `rabbit_nest.json`, `roadmap_yb_matrixsum.json`, `second_door_traversals.json`, `send_blue_sethex_attack.json` | resumos de campanhas fechadas (≤ 14 KB) | ARQUIVAR | Sumários com contagens/pads esperados; cada um tem script em `solver/`. |
| `a3_rereads_attack.jsonl`, `gsmg_sig_recover.jsonl` | **vazios (0 B)** | **APAGAR** (já feito) | Nada a preservar; scripts recriam. |
| `crop_zoom.ps1`, `pixel_forensics.ps1`, `pixel_geo.ps1`, `winrt_ocr.ps1`, `zone_map.ps1` | ferramentas descartáveis (System.Drawing/WinRT OCR, 30/08) | **APAGAR** (já feito) | Nenhum RELATORIO depende; `.gitignore`/regra 7 do AGENTS bloqueiam scripts em `_work/`; `winrt_ocr`/`zone_map` só citados no cronológico. |
| `gan_exploration.js`, `gan_exploration.py` | ferramenta quebrada | **APAGAR** (já feito) | `.py` contém JavaScript misturado com Python (não compila); `.js` é stub de "GAN v2" da era BTCSEED. |
| `joint_attack_v2.py.broken` | rascunho quebrado | **APAGAR** (já feito) | Versão funcional existe em `solver/joint_attack_v2.py`. |

Sugestão para os "ARQUIVAR": uma única pasta `_work/campanhas_2026-07_09/` (ou fora do git), com o cronológico apontando para lá.

---

## 3. Pastas de fonte

| Pasta | Veredito | Justificativa / duplicatas (SHA256) |
|---|---|---|
| `_work/archive/` (17 rastreados) | **MANTER** — fonte primária | `Puzzle_full.png`, 8 PNGs das palavras da fase 2, `choiceisanillusion_2020.html`, `homepage_2020.html`, `follow_the_white_rabbit.png`, `endgame/` 5 capturas Wayback (2023-06, 2023-11, 2024-11, 2025-10, 2026-04). Quase-duplicatas **internas** (manter como prova de estabilidade): 2025-10 vs 2026-04 diferem só no beacon Cloudflare; 2023-06 vs 2023-11 só `<h1>`→`<H1>` (edição do criador); 2023-11 vs 2024-11 só indentação. **40 arquivos não rastreados** no disco (`2019/PROVENANCE.txt`, `2019/home_2019*.html`, `reddit_dfwcqk_OP_verbatim.txt`, `stages/*.html`, `paths/*.html`, `appjs/*.js`) são capturas primárias fora do git — inconsistente com a política; considerar versionar os HTML/TXT pequenos. |
| `_work/gsmg_live_2026-09/` (36 rastreados) | **MANTER** — fonte primária (site revivido, 08/09/2026, com headers) | Bodies HTML **não** são idênticos aos de `archive/` (2026 traz `<link rel="icon">`, sem `x-ua-compatible`/beacon) → snapshot distinto, legítimo. Duplicatas: `body_img_follow_the_white_rabbit.png` == `archive/follow_the_white_rabbit.png` (`5e8d84b8…`); `body_img_logo_GSMG_restored.png` == `archive/logo_GSMG_restored.png` (não rastreado); 6 bodies de 9 B idênticos (`4641333e…` = "Hello :-)", 404): `sitemap.xml`, `help-center`, `img_puzzle.png`, `phase1verification`, `puzzle.png`, `register` — inofensivos. `logo_diffmask.png`/`logos_side_by_side.png` são derivados de análise, não capturas (poderiam ir para o relatório que os usa). |
| `_work/decentraland/` (3 rastreados: `entity.json`, `scene.json`, `scene_code.js`) | **MANTER** os 3 — fonte primária (cena da parcela GSMG) | 33 não rastreados (mp3/wav, espectrogramas `py_*/spec_*`, `resp_*`, `dep_*`) são mídia/derivados bloqueados pelo `.gitignore`; o `mp3_container` RELATORIO depende do mp3 local — documentado. |
| `_work/looking_forward_img/` (3 rastreados) | MANTER `u04_dome_grid.jpg`, `u11_243.jpg`; **ARQUIVAR fora do git** `contact_sheet.png` (2,8 MB) | Gravuras do livro; veredito da campanha: "sem dado do puzzle". O contact sheet é montagem derivada, regenerável, e pesa 2,8 MB. |

---

## 4. `README.md` — seção `## Salphaseion` (HEAD, linhas 673–1138)

**(a) MANTER — transcrição verbatim e decodificações corretas (verificadas contra `_work/salphaseion.html`):**

| Linhas | Conteúdo | Verificação |
|---|---|---|
| 673, 738 | título e frase original "This phase can be split into multiple sections…" | texto upstream |
| 1052–1054 | transcrição do 1.º `<textarea>` (dbbi, abba, faed, z-segmentos, blob SMALL, "shabef ans too") | **igual, caractere a caractere (1075 símbolos sem espaços)**, ao HTML capturado |
| 1056–1060 | a/b → binário → ASCII | reproduz `matrixsumlist` e `enter` |
| 1062–1072 | `shabef`=sha256 (a1z26), separador `z`, a–i,o → decimal → hex → ASCII | reproduz `lastwordsbeforearchichoice` e `thispassword` |
| 1074–1077 | `### AES Blob` + blob SMALL verbatim | idêntico |
| 675–685 (só a 1.ª frase) | "Estado verificado em 2026-09-17: não há solução…" | reduzir a 2–3 linhas apontando para `ENDGAME.md` e `docs/RESEARCH-INDEX.md` |

Observação: o blob COSMIC e o `<h1>Cosmic Duality</h1>` estão transcritos em 641–670 (fim da fase 3.2), não nesta seção — vale um cross-ref; TAIL32 idem.

**(b) REMOVER — notas de estado/experimentos empilhadas (todas já têm linha no RESEARCH-INDEX):**

| Linhas | Conteúdo |
|---|---|
| 687–736 | blockquote: estado 09-11 (687–689), ponteiro para ANALISE_PRIORIDADES (691–694), resumos de `prime_geometry` (696–698), `blue_hex` (700–703), `shared_numeric`+`radix127` (705–710), `recipe_audit` (712–716), `matrix_hint` (718–723), `compressed_payload` (725–730), `brotli_decimal` (732–736) |
| 740–1050 | **44 parágrafos**, um por relatório, iniciando em 740, 747, 754, 762, 769, 777, 784, 793, 801, 809, 817, 825, 833, 841, 849, 856, 864, 872, 880, 889, 896, 901, 908, 915, 925, 932, 939, 947, 954, 962, 968, 975, 984, 993, 1001, 1009, 1017, 1024, 1030, 1036, 1042 (`zero_symbol` … `prime_product_matrix`) — duplicam o índice |

Links que quebram com a reorganização: `ENDGAME.md` (684, 689, 1093, 1117, 1138 — o novo `ENDGAME.md` de raiz não terá a âncora `#sessão-2026-09-11--teste-exaustivo-condicional-de-g07`, que está na linha 2890 do cronológico) e `docs/notes/ANALISE_PRIORIDADES.md` (691).

**(c) REMOVER / reduzir a uma frase — `### Cadeia histórica reproduzível (não validada)`, 1079–1138 inteira:**

| Linhas | Conteúdo que apresenta a miragem como progresso |
|---|---|
| 1081–1085 | "Correção 2026-08-30": é a refutação, mas ainda diz "reproduz bytes e hashes" e remete à issue #104 — reescrever como a frase única |
| 1087–1093 | somas 15×38 `[140,171,…]` como "pista estrutural" + numerologia "hundred fourty"/FEFEFE + 720 mil caminhos BIP39 |
| 1095–1106 | comando `solver\final_chain.py` e checkpoints Cosmic `4f7a1e4e…`, matriz 103×103/base-38 `half`/`better_half`, Chain4 `e4269ed5…`, corpo 35×32 B `43d3fe43…` |
| 1108–1113 | tail `fc0c1b02` → 5 pares → `11111₂=31` "encaixe novo e reproduzível", com falas reais do criador ("First or zero", "prime number is very important") usadas como corroboração |
| 1115–1117 | "a chave AES-256 que abre esses 35 blocos… ainda não tem derivação" |
| 1119–1122 | MITM `4 × 2^35` sobre os 35 blocos |
| 1124–1130 | leituras `28 = 7×4`, `35 = 7×5`, 153 526 chaves, 4,57 M escalares |
| 1132–1138 | Adendo 2026-08-20 (f): Mr. Robot eps3.5, `89727c…` como chave dos 35 blocos, senha do Chain4 reusada |

Substituto sugerido (1 parágrafo): "A 'cadeia comunitária' (Chain1→4, `cc`, `half`/`better_half`, 35 blocos, BTCSEED) foi refutada em 2026-08-30/09-11: só passa por padding PKCS#7 (`0x01`, p≈1/256) sob EVP-MD5, enquanto os blobs autênticos das fases 2/3/3.2 abrem apenas com EVP-SHA256. Tabela de refutadas em `ENDGAME.md`; histórico em `docs/historico/ENDGAME_cronologico_2026.md`."

---

## 5. `.claude/` e `.codex/`

| Caminho | Estado no git | Veredito | Justificativa |
|---|---|---|---|
| `.claude/agents/telegram-digger.md` | rastreado (apesar de `/.claude/` no `.gitignore`) | **MANTER** (+2 linhas) | Correto (read-only, Grep/Read sobre `result.json`). Desatualizado num ponto: `result.json` termina em 2026-07-08; mensagens posteriores estão em `ChatExport_2026-09-08/`, `_work/tg_export_*.json` (ignorados) e nos resumos `_work/tg_2025-09_11_summary.md` / `tg_2026-07_09_summary.md` — o agente não sabe deles. |
| `.codex/agents/telegram-digger.toml` | local (ignorado) | **MANTER** (duplicado por desenho) | `developer_instructions` é cópia **verbatim** do `.md` — dois runtimes, um texto; `AGENTS.md` documenta. Risco de deriva: aplicar a mesma atualização acima nos dois (ou gerar um a partir do outro). |
| `.codex/config.toml` | local (ignorado) | **MANTER** | `approval_policy=on-request`, `sandbox=workspace-write`, 6 MCPs (github, context7, exa, memory, playwright, sequential-thinking), `persistent_instructions` = "Follow AGENTS.md… result.json read-only", `[agents.telegram_digger] config_file` correto. Nada afirma domínio morto/cadeia; sem segredos. |
| `.claude/skills/solve-phase/SKILL.md` + `solve.sh` | rastreados | **MANTER** | Correto e alinhado à regra 2 do `AGENTS.md`: SHA256 → `openssl enc -aes-256-cbc -d -a -pass pass:`, KDF default SHA256 (sem `-md`), `tr -d`/`fold -w 64`; `-md md5` só como controle. |
| `.claude/skills/gsmg-solver/SKILL.md` | rastreado (já `D` na árvore) | **APAGAR** | Descreve o harness llama3+GPU Bifid (`launch.py`, `gpu_search.py`, `selftest.py` "reproduz BTCSEED") como busca "incansável" ativa; `solver/README.md` já o chama de "harness histórico"; BTCSEED é âncora refutada; o kit ativo é `gsmg_common.py` (AGENTS §Ambiente). Como skill auto-carregável, mantê-lo é nocivo. |
| `.claude/skills/{classical-cipher-analysis,ctf-crypto,ctf-forensics}` | symlinks locais → `.agents/skills/*` | MANTER (fora do escopo) | Skills genéricas de CTF, ignoradas pelo git. |
| `.claude/plans/endgame-internal-frontier.plan.md` (94 l.) | local (ignorado) | **APAGAR** | Inteiramente sobre a miragem: "Chain1→4", `CHAIN4_MASK=b657264f2f6e6921`, "35 blocos = a única fronteira interna"; propõe `solver/chain_audit.py` e `internal_reread_attack.py` (**nunca criados**) e atualizar a memória `endgame-frontier-internal.md` (já marcada HISTÓRICO/superada). A suspeita da sua Fase 0.4 (mask = `cc[158:166] XOR "Salted__"`, construído) foi confirmada em ANALISE_PRIORIDADES — o plano já cumpriu seu papel. |
| `.claude/settings.local.json` | local (ignorado) | **MANTER** | Allowlist (`rtk ls/git/wc/read`, 3 checks `python -c`); correto e pessoal. |
| `.gitignore` ↔ `.claude/` | — | corrigir | `/.claude/` ignora a pasta, mas 4 arquivos dela estão rastreados (herança). Decidir: versionar `agents/` e `skills/solve-phase/` explicitamente (ignorando `settings.local.json`, `plans/`, symlinks) ou desrastrear. |
| `CLAUDE.md` / `AGENTS.md` (árvore atual) | modificados | coerentes | `CLAUDE.md` virou `@AGENTS.md` + 3 notas; `AGENTS.md` já descreve `docs/historico/`, o kit `gsmg_common.py`, o scorer limpo e o lead dos primos. Confere com esta auditoria. |

---

### Pendências que a reorganização em curso ainda não cobre
1. **17 links relativos quebrados** nas notas movidas (`docs/historico/notes/*`: `../../_work/…` → `../../../_work/…`; `notes/README.md`: `../RESEARCH-INDEX.md` → `../../RESEARCH-INDEX.md`).
2. `RESEARCH-INDEX.md`: adicionar o lead vivo (primos/`dbbi`), resolver as 3 pastas sem RELATORIO, reagrupar as categorias mistas.
3. `README.md` Salphaseion: âncora `#sessão-2026-09-11…` e o ponteiro para `docs/notes/ANALISE_PRIORIDADES.md` precisam apontar para `docs/historico/…`.
4. Soltos ainda em `_work/`: `salphaseion_raw.html`, `seed_raw.html`, `salphaseion_wayback_20241123.html` (duplicatas exatas) e os logs jsonl/json listados como ARQUIVAR.
5. Espelhar no `.codex/agents/telegram-digger.toml` qualquer ajuste feito no `.claude/agents/telegram-digger.md`.