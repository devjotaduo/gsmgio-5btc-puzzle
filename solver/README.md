# Scripts de pesquisa GSMG

A senha final e a chave do prêmio continuam sem validação. Esta pasta reúne
experimentos independentes, verificadores e um harness histórico. O
[índice de relatórios](../docs/RESEARCH-INDEX.md) é o ponto de entrada para
escolher o que executar.

## Famílias de scripts

| Prefixo ou grupo | Finalidade |
| --- | --- |
| `color_`, `matrix_`, `ring_`, `positional_` | Cores, geometria e listas de somas |
| `decimal_`, `zero_`, `substituted_`, `unbounded_` | Dígitos, zeros e conversões de inteiros |
| `prime_`, `radix127_`, `rsa_` | Primos, bases e hipóteses RSA |
| `checkerboard_`, `joint_checkerboard_`, `nihilist_` | Cifras clássicas e análise de linguagem |
| `xor_`, `feedback_`, `columnar_` | Fluxos, operações e transposições |
| `compressed_`, `brotli_`, `mp3_`, `title_` | Formatos e pistas estruturais |
| `verify_*.cjs` | Conferência independente de experimentos específicos |
| `experiments/claude_endgame_2026_09_02/` | Snapshot histórico, com documentação própria |

Os nomes e caminhos foram mantidos: vários scripts importam outros módulos
desta pasta ou usam entradas em `_work/`. Nem todo script é um comando
isolado e nem todo resultado bruto faz parte do Git.

## Executar uma rodada

Leia o relatório correspondente antes de executar. Use a raiz do repositório
como diretório de trabalho, salvo indicação explícita. Alguns scripts
aceitam uma nova pasta de saída; outros têm destinos fixos e podem
sobrescrever evidências. Não execute a pasta inteira em lote.

Exemplo de rodada que usa apenas módulos nativos do Node.js, validada com
Node 24:

```powershell
node --check solver/title_position_masks.cjs
node solver/title_position_masks.cjs _work/title_mask_reproduction
```

O exemplo inclui um controle conhecido AES e salva parâmetros,
transformações, materiais e resultados. Não encontrou uma senha válida.
As fontes e entradas públicas necessárias estão no repositório; o arquivo
grande de materiais pode ser regenerado pelo comando.

## Como interpretar os resultados

- Um negativo exclui somente a hipótese e o espaço declarados no relatório.
- Uma busca parcial não exclui os ramos pendentes.
- Padding AES válido ocorre por acaso; não autentica uma senha.
- Checksum BIP39 confirma um formato, não a carteira do prêmio.
- Texto coerente precisa de derivação reproduzível; uma chave final deve
  corresponder ao endereço ou ponto público do prêmio.

O fragmento histórico `BTCSEED` e as cadeias binárias antigas não são
soluções autenticadas. O modelo de linguagem treinado com `result.json`
contém as próprias cifras; seus escores não são evidência independente.
Consulte a [auditoria](../_work/ambiguous_checkerboard_2026-09-15/RELATORIO.md).

## Harness histórico Python/GPU

`oracles.py`, `dsl.py`, `scorer.py`, `search.py`, `gpu_search.py`,
`runner.py` e `launch.py` pertencem ao harness anterior. Suas saídas,
inclusive um eventual `SOLVED.json`, exigem revisão dos critérios acima.
A organização do repositório não revalidou todas as campanhas históricas.

Esse grupo documentava Python 3.11+, PyCryptodome, ecdsa, base58, mnemonic,
bip-utils e numpy; o motor GPU também utiliza PyTorch/CUDA, e o loop de
propostas utiliza Ollama. Esses requisitos não se aplicam automaticamente
aos scripts Node. Consulte os imports e o relatório do experimento antes
de preparar um ambiente. `puzzle-env/` e `solver/out/` são locais.

O [snapshot recuperado](experiments/claude_endgame_2026_09_02/README.md)
preserva seu próprio briefing e código. Corpus e modelos grandes do
snapshot permanecem fora do Git.
