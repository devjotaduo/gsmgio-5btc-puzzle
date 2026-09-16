# Navegação e contribuição

Leia primeiro [AGENTS.md](../AGENTS.md), o [guia da pesquisa](README.md)
e o [índice de relatórios](RESEARCH-INDEX.md). Consulte o histórico
[ENDGAME.md](../ENDGAME.md) antes de repetir uma hipótese.

## Responsabilidade dos arquivos

- `README.md`: fontes, hints, decodificações e estado verificável por fase.
- `ENDGAME.md`: histórico de hipóteses, resultados e limites de cobertura.
- `solver/`: algoritmos e verificadores; `experiments/` guarda snapshots
  históricos que podem depender de corpus local.
- `_work/<experimento>/RELATORIO.md`: explicação da hipótese, comandos,
  controles, resultados e limites; os arquivos vizinhos preservam a evidência.
- `docs/notes/`: planejamento e discussão histórica, sujeitos às correções
  dos relatórios mais recentes.

## Antes de mudar

Procure referências com `rg` antes de renomear arquivos. Muitos scripts
possuem caminhos fixos para `_work/`; não mova uma campanha apenas para
limpar a raiz. Nunca altere blobs, alfabetos, hashes ou strings de entrada
para adequá-los a uma hipótese. A `.gitattributes` conserva os bytes dos
artefatos recentes usados em conferências SHA256.

Não leia nem versione `result.json` em bloco. Consulte apenas as mensagens
necessárias. Não inclua sessões, credenciais, preferências locais ou dumps
de conversas nos commits. Não remova saídas locais para reduzir o tamanho
do commit: use a seleção de arquivos e o `.gitignore`.

## Verificação e revisão

Execute controles pertinentes à mudança. Para JavaScript de pesquisa,
`node --check caminho.cjs` verifica apenas sintaxe; os controles e
verificadores do experimento verificam seu comportamento. Não execute
todos os scripts antigos indiscriminadamente: vários iniciam buscas
longas ou sobrescrevem resultados.

Um relatório de revisão deve indicar arquivos alterados, hipótese ou
comportamento, comandos executados e limites. Distinguir busca parcial,
exclusão dentro de um modelo e solução autenticada é obrigatório para
uma conclusão reproduzível. Padding ou legibilidade parcial não são
autenticação.

Antes do commit, confira o diff e os arquivos preparados no índice.
Faça auditoria de dependências quando houver dependências instaladas;
Node com apenas módulos nativos não possui pacote npm a auditar.
Commit local e publicação/push são ações separadas.
