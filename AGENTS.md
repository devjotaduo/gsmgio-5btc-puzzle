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
| `result.json`, `ChatExport_*/` | exports do Telegram do grupo "GSMG Puzzle Solvers" — **locais, nunca commitar** |
| `tg_monitor.py` | monitor local do grupo (telethon; credenciais fora do repo) |

## Skills versionadas

As skills de pesquisa ficam em `.agents/skills/` e podem ser invocadas pelo nome.
Use somente a que corresponde ao trabalho:

| Skill | Quando usar |
|---|---|
| `research-swarm` | uma questão aberta exige hipóteses concorrentes e síntese de evidências |
| `related-problem-ladder` | é preciso testar um mecanismo em uma instância menor antes de ampliar a campanha |
| `proof-certificate` | uma alegação precisa de verificação independente ou prova formal antes de ser tratada como fato |

## Regras de ouro

1. **Só o oráculo duro declara solução:** uma privkey de 32 B que gera a pubkey do prêmio
   (`04f4d1bb…bf33559`), ou um blob AES abrindo com plaintext semântico (≥ 85 % ASCII,
   WIF/hex64 plausível, blob openssl aninhado `Salted__`, ou assinatura EBCDIC cp273 como o
   plaintext da fase 3.2). **Padding PKCS7 válido sozinho é ruído (1/256).** Checksum BIP39
   válido não é solução. Escore de inglês é triagem, nunca prova.
2. **KDF:** `openssl enc -aes-256-cbc -pass pass:<senha>` com EVP_BytesToKey **SHA256**
   (openssl ≥ 1.1.0). Os blobs autenticados das fases 2, 3 e 3.2 abrem **só** assim; MD5 é
   controle secundário. O cabeçalho `Salted__` prova `-pass`/`-k`, não a cifra.
3. **Antes de codar:** escreva a hipótese em prosa, finita e falsificável; confira a tabela
   de famílias refutadas em `ENDGAME.md`; rode um controle positivo (fase 2 abre com
   `sha256hex("causality")`; o checkerboard reproduz a 3.2.2); rode um nulo casado (≥ 100
   embaralhamentos preservando contagens). Para escores de texto use
   `solver/primos_2026_09_17/clean_scorer.py`: o `solver/scorer.py` aprendeu os quadgramas
   do próprio `dbbi` e infla leituras ricas em a–i.
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
   (conventional commits). Vários agentes trabalham em paralelo neste diretório: confira
   `git status` e estagie só os próprios hunks; nunca reverta trabalho alheio não commitado.

## Modo de investigação em enxame

Use este modo para uma pergunta aberta que tenha mais de uma hipótese razoável;
não o use para repetir campanhas fechadas ou inflar uma enumeração sem premissa.

1. **Contrato antes de paralelizar.** Registre no `spec.json` a pergunta, oráculo de
   sucesso, hipótese, contra-hipótese, fontes, parâmetros, controle positivo, nulo e
   condição de parada. Divida as frentes por mecanismos independentes, não por fatias
   arbitrárias da mesma busca.
2. **Tese contra construção.** Quando aplicável, uma frente procura uma regularidade ou
   invariante; outra busca uma construção que a viole. As duas precisam atacar a mesma
   alegação e declarar o que as refutaria. Não force esse par quando não houver uma
   antítese concreta.
3. **Problema-ponte antes da campanha cara.** Se a operação ainda for incerta, resolva
   primeiro uma instância menor que preserve o mecanismo. Um degrau só é útil quando
   diferencia hipóteses, calibra o oráculo ou elimina um parâmetro. Resultado no degrau
   não é solução do puzzle.
4. **Troca de achados em formato verificável.** Cada frente publica em
   `_work/<campanha>/FINDINGS.md` ou no relatório: fato observado, inferência, fontes ou
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
7. **Organização e propriedade.** Scripts reproduzíveis ficam em `solver/<campanha>/`;
   relatório e execução final em `_work/<campanha>_<data>/`. Frentes que escrevem arquivos
   distintos declaram propriedade; para alterações concorrentes do mesmo módulo, use
   worktrees separados ou serialize a edição. A campanha encerra com `RELATORIO.md`, índice
   e atualização de `ENDGAME.md` apenas se o mapa realmente mudou.

Não há meta fixa de agentes, horas ou tentativas. Escale apenas até cobrir as hipóteses
independentes declaradas; o critério é qualidade de evidência, não volume de execução.

## Ambiente

- **Python:** `C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe`
  (pycryptodome, coincurve, ecdsa, base58, mnemonic, bip_utils, numpy, PIL, pyopencl,
  opencv-python-headless). Outros interpretadores não têm as dependências.
- **Node 24** para os `.cjs`; **Go 1.26** para `solver/mitm16_dbbi_hex/` e
  `solver/prize_nonce_bsgs/`; **GPU** RTX 5060 Laptop (OpenCL via driver; sem nvcc/MSVC).
- **Kit:** `import sys; sys.path.insert(0, r"…\solver\experiments\claude_endgame_2026_09_02"); import gsmg_common as G`
  → `G.DBBI`, `G.FAED`, `G.BLOBS{SMALL,COSMIC,TAIL32}`, `G.MATRIX_README`, `G.SPIRAL`,
  `G.COLORED`, `G.aes_try`, `G.try_password_all`, `G.semantic`, `G.nested_blob`,
  `G.ebcdic_sig`, `G.priv_hit`, `G.fast_priv_scan`, `G.checkerboard_decode/encode`,
  `G.bifid`, `G.z_method`. `python gsmg_common.py` roda o self-test.
- **Codex:** `.codex/config.toml` e `.codex/agents/telegram-digger.toml` são locais
  (ignorados); o agente `telegram-digger` (Claude e Codex) pesquisa `result.json` sem
  despejá-lo no contexto.

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

O único fato estrutural novo é que `dbbi` foi construído com marcadores `b`/`be` nas
posições lógicas primas (o passo `yellowblueprimes`); o resíduo é estatisticamente
aleatório e tudo o que é simples sobre ele já deu zero. **Só insumo novo do criador ou
lacuna de cobertura reproduzida move a fronteira**; ver `ENDGAME.md` §6.
