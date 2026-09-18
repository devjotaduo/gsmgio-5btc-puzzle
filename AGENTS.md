# AGENTS.md — guia único para quem trabalha neste repositório

Vale para Claude Code, Codex e humanos. `CLAUDE.md` importa este arquivo e acrescenta notas só do Claude.
Responda e documente em português do Brasil.

## O que é

Arquivo público de hints e pesquisa do **GSMG.IO 5 BTC puzzle** (https://gsmg.io/puzzle).
As fases 0 a 3.2 estão resolvidas e documentadas no `README.md`. A fase final
(**SalPhaseIon / Cosmic Duality**) **não está resolvida**: o prêmio segue intacto em
`1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` (~1,256 BTC; o criador reduz a cada halving).
Não é um projeto de software: não há build, lint nem testes. Há scripts de pesquisa
em `solver/`, cada um com seus próprios controles.

## Leia nesta ordem

1. **`ENDGAME.md`** — o relatório único do endgame: dados verbatim, hints do criador,
   fatos provados, **tabela do que já foi refutado**, o único lead estrutural aberto e as
   regras de trabalho. Nenhuma hipótese nova sem conferir a tabela.
2. **`README.md`** — solução das fases 0–3.2, transcrições verbatim das páginas.
3. **`docs/RESEARCH-INDEX.md`** — índice dos relatórios de experimento
   (`_work/<experimento>/RELATORIO.md`), cada um com a cobertura exata do seu negativo.
4. **`solver/README.md`** — o kit, os oráculos e a taxonomia dos scripts.
5. **`docs/historico/`** — caderno cronológico antigo e notas datadas. Contém afirmações
   já refutadas ("canônico", "validado", "35 blocos"); só para arqueologia.

## Layout

| Caminho | Conteúdo |
|---|---|
| `README.md` | fases 0–3.2, hint → raciocínio → senha/comando → resultado |
| `ENDGAME.md` | relatório único do endgame (fonte de verdade do estado) |
| `AGENTS.md`, `CLAUDE.md` | este guia; o segundo só importa o primeiro |
| `docs/RESEARCH-INDEX.md` | índice dos relatórios de `_work/` |
| `docs/historico/` | `ENDGAME_cronologico_2026.md`, notas e planos antigos |
| `solver/` | kit `experiments/claude_endgame_2026_09_02/gsmg_common.py`, `oracles.py`, verificadores, campanhas fechadas |
| `_work/<experimento>_<data>/` | relatório + execução final (o `.gitignore` deixa entrar `*.md` e alguns `summary/spec/controls/final_qa.json`) |
| `_work/archive/`, `_work/gsmg_live_2026-09/` | capturas do site (Wayback e site revivido), imagens originais |
| `result.json`, `ChatExport_*/` | exports do Telegram do grupo "GSMG Puzzle Solvers" — **locais, nunca commitar**; ver "Dados locais" |
| `tg_monitor.py` | monitor local do grupo (telethon; credenciais fora do repo) |
| `tools/codex_pair.py` | chamada do Codex CLI com limites fixos (ver "Trabalho em dupla") |

**Dados locais.** `result.json` (até 2026-07-08) e `.codex/` existem só no checkout principal
`C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle`; numa worktree, use esse caminho absoluto
(`solver/scorer.py` já faz isso, e os caches `.pkl` se recriam em qualquer cópia). Os exports íntegros posteriores estão em
`C:/Users/ruthe/Downloads/Telegram Desktop/ChatExport_2026-09-08/` (2025-09-01 → 2026-09-08) e
`ChatExport_2026-09-17/` (04/09 → 17/09); a cópia de 09-08 no checkout principal está truncada.

## Skills versionadas

A cópia canônica de cada skill é `.agents/skills/<nome>/SKILL.md` (o Codex lê daí);
`.claude/skills/<nome>/SKILL.md` é espelho **idêntico byte a byte** (o Claude Code lê daí; sem
symlink neste clone). Edite a canônica, copie para o espelho e confira com
`git diff --no-index .agents/skills/<nome>/SKILL.md .claude/skills/<nome>/SKILL.md` (saída vazia).
Skill nova só entra no git com a exceção correspondente no `.gitignore`, nos dois diretórios.
Use somente a que corresponde ao trabalho:

| Skill | Quando usar |
|---|---|
| `research-swarm` | uma questão aberta exige hipóteses concorrentes e síntese de evidências |
| `related-problem-ladder` | é preciso testar um mecanismo em uma instância menor antes de ampliar a campanha |
| `proof-certificate` | uma alegação precisa de verificação independente ou prova formal antes de ser tratada como fato |
| `solve-phase` (só Claude) | reproduzir o padrão sha256 → AES de uma fase; o Codex roda `.claude/skills/solve-phase/solve.sh` direto |

## Regras de ouro

1. **Só o oráculo duro declara solução:** uma privkey de 32 B cujo h160 (pubkey comprimida ou
   não) bate com `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` (pubkey `04f4d1bb…bf33559`) ou com
   `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` (destino dos halvings; condição de prêmio não
   confirmada, `ENDGAME.md` §3.11), ou um blob AES aberto cujo plaintext leva adiante como nas
   fases: um blob aninhado que por sua vez abre, uma chave que bate com um dos alvos, ou texto
   que descreve o próximo passo e é lido igual pelo `openssl` CLI e por uma segunda
   implementação. Os sinais semânticos (≥ 85 % ASCII, WIF/hex64 plausível, blob openssl aninhado
   `Salted__`, assinatura EBCDIC cp273 como o plaintext da fase 3.2) marcam **candidato**, e o
   `hard` de `G.try_password_all` significa candidato. Candidato só vira solução pelo certificado
   de `proof-certificate`. **Padding PKCS7 válido
   sozinho é ruído (1/255 em escala).** Checksum BIP39 válido não é solução. Escore de inglês é
   triagem, nunca prova.
2. **KDF:** `openssl enc -aes-256-cbc -pass pass:<senha>` com EVP_BytesToKey **SHA256**
   (openssl ≥ 1.1.0). Os blobs autenticados das fases 2, 3 e 3.2 abrem **só** assim; MD5 é
   controle secundário. `G.try_password_all` testa os dois por padrão (`kdf="both"`); o
   relatório declara quais foram cobertos. O cabeçalho `Salted__` prova `-pass`/`-k`, não a cifra.
3. **Antes de codar:** escreva a hipótese em prosa, finita e falsificável; confira a tabela
   de famílias refutadas em `ENDGAME.md`; rode um controle positivo (fase 2 abre com
   `sha256hex("causality")`; o checkerboard reproduz a 3.2.2); rode um nulo casado (≥ 100
   embaralhamentos preservando contagens; N/A justificado em prova determinística). Para
   escores de texto use `solver/primos_2026_09_17/clean_scorer.py`: o `solver/scorer.py`
   aprendeu os quadgramas do próprio `dbbi` e infla leituras ricas em a–i. **Campanha nova** só
   com insumo novo do criador, lacuna de cobertura reproduzida (como `ENDGAME.md` §3.13) ou
   família ausente da tabela com prior compatível com a regra 4; a condição de parada é a do
   `spec.json` da campanha.
4. **Teto de complexidade:** o criador montou o puzzle em "couple hours" com ferramentas
   online (sha256, openssl, CyberChef, dcode). Hipóteses que ele não montaria numa tarde
   têm prior baixo.
5. **Registre todo padding válido com o plaintext em hex** (`G.try_password_all` já faz)
   para varredura retroativa quando o oráculo melhorar.
6. **Nunca perseguir a identidade real de ninguém.** "Close friends have the best chance"
   é um hint sobre o tipo de resposta, não um convite.
7. **Ao encerrar uma campanha:** `_work/<nome>_<data>/RELATORIO.md` (hipótese, cobertura
   exata, controles, nulo, resultado, o que ficou de fora); scripts reproduzíveis em
   `solver/` (o `.gitignore` bloqueia scripts dentro de `_work/`); linha em
   `docs/RESEARCH-INDEX.md`; uma entrada em `ENDGAME.md` **só** se mudar o mapa (fato novo,
   família fechada, correção de oráculo). Negativos são resultado válido e devem ser escritos
   como tal.
8. **Git:** `origin` é o fork `devjotaduo/gsmgio-5btc-puzzle`; commits em pt-BR
   (conventional commits). Vários agentes trabalham em paralelo: confira `git status` e
   estagie só os próprios hunks; nunca reverta trabalho alheio não commitado. Nunca use
   `git stash` puro: a pilha é compartilhada entre worktrees; use commit WIP.

## Modo de investigação em enxame

Use este modo para uma pergunta aberta que tenha mais de uma hipótese razoável;
não o use para repetir campanhas fechadas ou inflar uma enumeração sem premissa.

1. **Contrato antes de paralelizar.** Registre em `_work/<campanha>_<data>/spec.json` a
   pergunta, oráculo de sucesso, hipótese, contra-hipótese, fontes, parâmetros, controle
   positivo, nulo, condição de parada e o dono de cada arquivo. Divida as frentes por
   mecanismos independentes, não por fatias arbitrárias da mesma busca.
2. **Tese contra construção.** Quando aplicável, uma frente procura uma regularidade ou
   invariante; outra busca uma construção que a viole. As duas precisam atacar a mesma
   alegação e declarar o que as refutaria. Não force esse par quando não houver uma
   antítese concreta.
3. **Problema-ponte antes da campanha cara.** Se a operação ainda for incerta, resolva
   primeiro uma instância menor que preserve o mecanismo. Um degrau só é útil quando
   diferencia hipóteses, calibra o oráculo ou elimina um parâmetro. Resultado no degrau
   não é solução do puzzle.
4. **Troca de achados em formato verificável.** Cada frente publica em
   `_work/<campanha>_<data>/<frente>/FINDINGS.md`: fato observado, inferência, fontes ou
   hashes, cobertura, controles, limite e próxima pergunta. Não repasse conclusão sem
   evidência reproduzível, nem material sensível/volumoso fora das regras de Git.
5. **Síntese com conjuntos exatos.** Antes de combinar resultados, compare bytes,
   senhas, parâmetros e alvos; declare sobreposição e não some tentativas duplicadas.
   O sintetizador separa o que foi provado do que só ganhou prioridade.
6. **Certificado antes de declarar vitória.** Uma suposta chave ou abertura passa por
   implementação independente. Uma cobertura finita precisa de hashes, checkpoints e
   reconciliação. Para uma afirmação matemática geral, formalize em Lean ou outro
   verificador quando o modelo estiver definido e a ferramenta disponível; a prova formal
   não substitui validar a modelagem do puzzle.
7. **Organização e propriedade.** Scripts reproduzíveis ficam em `solver/<campanha>/<frente>/`;
   relatório e execução final em `_work/<campanha>_<data>/`. Cada frente escreve só nos
   próprios diretórios. O coordenador é dono de `spec.json` e `RELATORIO.md` e propõe no
   relatório o delta para o índice e para `ENDGAME.md`. Quem integra o PR em `master` aplica e
   reconcilia esse delta, e só esse papel edita esses dois arquivos globais. Para alterações
   concorrentes do mesmo módulo, use worktrees separados ou serialize a edição. A campanha
   encerra com `RELATORIO.md`, linha no índice e delta de `ENDGAME.md` apenas se o mapa mudou.

Não há meta fixa de agentes, horas ou tentativas. Escale apenas até cobrir as hipóteses
independentes declaradas; o critério é qualidade de evidência, não volume de execução.

## Trabalho em dupla (Claude Code ↔ Codex CLI)

1. **Escrita paralela exige branch/worktree própria** (`claude/<campanha>`, `codex/<campanha>`).
   Chamadas só de leitura podem rodar na worktree do coordenador. `master` só recebe merge por
   PR; antes de mergear, traga o `master` para a branch.
2. **Um coordenador por campanha**: quem escreveu o `spec.json` é dono dele e do `RELATORIO.md`.
   O outro agente devolve achados e escreve só em `solver/<campanha>/<frente>/` e
   `_work/<campanha>_<data>/<frente>/`. Índice e `ENDGAME.md` ficam com quem integra o PR
   (enxame, item 7).
3. **Claude chama o Codex** por `python tools/codex_pair.py --prompt-file p.txt [--schema s.json]`.
   Por padrão o wrapper usa `gpt-6-astra` com effort max, `-s read-only` e `approval_policy=never`.
   Ele ignora a config global, para não carregar MCPs alheios, e mantém
   `windows.sandbox="elevated"`, sem o qual o Codex não consegue ler arquivos. No Windows ele
   chama `node codex.js` direto, sem passar pelo `cmd.exe`. O prompt vai pelo stdin. Cada
   execução tem pasta nova em `_work/codex_pair/<carimbo>_<uuid>/`, fora do git, com
   `response.json`, `events.jsonl`, `stderr.txt` e `meta.json`. O `response.json` é conferido
   contra o schema pelo `jsonschema`, e o `meta.json` guarda `thread_id`, exit code, duração, HEAD
   e erro. O timeout encerra a árvore de processos. `--write` exige `--cwd` com o diretório da
   frente (ou a worktree do Codex) e aceita `--add-dir` para os diretórios extras dela.
4. **Retomada** só com `--resume <thread_id>` em formato UUID. Nunca use `--last`, que pode pegar
   a sessão de outra frente. Uma trava por thread recusa duas chamadas simultâneas à mesma
   sessão. Revisão independente começa em thread nova.
5. **No prompt ao Codex, cite o caminho da skill**, por exemplo "siga
   `.agents/skills/proof-certificate/SKILL.md`". O catálogo global dele estoura o orçamento de
   contexto e descarta as descrições, então a escolha automática pela descrição não é confiável.
6. **Codex chama o Claude** só quando o Codex coordena e roda fora do `codex_pair`. O comando é
   `claude -p --permission-mode plan --allowedTools "Read,Grep,Glob" --output-format json
   "<prompt>" > _work/<campanha>_<data>/<frente>/claude_<carimbo>.json`. O modo plan impede
   edições e, com ele, a autorização global de commit, PR e merge do `~/.claude/CLAUDE.md`.
7. **O que se troca é evidência**: fatos, inferências, comandos, artefatos, cobertura e limites,
   no formato de `FINDINGS.md`. A resposta de um agente é insumo; o coordenador reproduz o que
   for decisivo antes de publicar. Transcrições ficam locais; o que se publica vai no relatório.

## Ambiente

- **Python:** `C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe`
  (pycryptodome, coincurve, ecdsa, base58, mnemonic, bip_utils, numpy, PIL, pyopencl,
  opencv-python-headless). Outros interpretadores não têm as dependências.
- **Processos e disco:** o C: vive quase cheio, e o pagefile cresce nele sob pressão de RAM. Em
  18/09, com 20 workers em seis frentes, chegou a 41,6 GB e zerou o disco. Some no máximo 12
  processos entre todas as frentes paralelas, contando os revisores.
- **Node 24** para os `.cjs`; **Go 1.26** para `solver/mitm16_dbbi_hex/` e
  `solver/prize_nonce_bsgs/`; **GPU** RTX 5060 Laptop (OpenCL via driver; sem nvcc/MSVC).
- **Kit:** `import sys; sys.path.insert(0, r"…\solver\experiments\claude_endgame_2026_09_02"); import gsmg_common as G`
  → `G.DBBI`, `G.FAED`, `G.BLOBS{SMALL,COSMIC,TAIL32}`, `G.MATRIX_README`, `G.SPIRAL`,
  `G.COLORED`, `G.aes_try`, `G.try_password_all`, `G.semantic`, `G.nested_blob`,
  `G.ebcdic_sig`, `G.priv_hit`, `G.fast_priv_scan`, `G.checkerboard_decode/encode`,
  `G.bifid`, `G.z_method`. `python gsmg_common.py` roda o self-test. O kit resolve `solver/`
  pela própria localização, então numa worktree usa os oráculos da worktree. Scripts
  históricos em `solver/` ainda importam o kit por caminho absoluto do checkout principal. Numa
  campanha nova, importe pelo caminho relativo ao script e registre commit e hash do kit no
  relatório.
- **Codex:** `.codex/config.toml` e `.codex/agents/telegram-digger.toml` são locais (ignorados)
  e só existem no checkout principal. Numa worktree, o subagente `telegram_digger` do Codex não
  está registrado. Para ele carregar, o Codex precisa rodar no checkout principal com a config
  global (`codex_pair.py --cwd <checkout principal> --user-config`), o que também traz os MCPs
  globais e `web_search`. Sem isso, use o `telegram-digger` do Claude. O agente pesquisa o
  export sem despejá-lo no contexto. O suplemento global `~/.codex/AGENTS.md` (ECC) descreve projetos de software:
  aqui não há `docs/CODEX-NAVIGATION-GUIDE.md`, pipeline, TDD nem indexação a rodar.

## Como o puzzle se resolve (padrão das fases 0–3.2)

1. Um hint (imagem, texto, referência a Matrix, Alice, genesis block, xadrez, HSM…) revela
   palavras-chave.
2. As palavras são concatenadas numa ordem específica, com caixa e espaços preservados
   (o README anota `/(aBa, connected enf)`), e passadas por **SHA256**; o hex é a senha.
3. O texto da etapa seguinte é **AES-256-CBC em base64** (`U2FsdGVk…`), aberto com
   `openssl enc -aes-256-cbc -d -a -pass pass:<sha256>`.

Fase 3.2 acrescentou Beaufort (chave `THEMATRIXHASYOU`), EBCDIC 1141 e um straddling
checkerboard (VIC). A página final ensina dois decodificadores (a/b → binário → ASCII;
a–i,o → decimal → hex → ASCII) e deixa `dbbi` e `faed` sem decodificação conhecida.

## Estado em uma frase

O único fato estrutural novo é o encaixe reproduzido de marcadores `b`/`be` nas posições
lógicas primas de `dbbi`. Que o autor o construiu assim (o passo `yellowblueprimes`) é
inferência com evidência estatística forte. O resíduo é compatível com i.i.d. e as
operações enumeradas sobre ele deram zero, o que não exclui informação codificada.
**Só insumo novo do criador ou lacuna de cobertura reproduzida move a fronteira**; ver
`ENDGAME.md` §6.
