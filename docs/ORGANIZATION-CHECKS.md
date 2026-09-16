# Conferência da organização — 16/09/2026

Foram agrupadas quatro notas em `docs/notes/`, atualizados seus links,
criados os guias de navegação e um índice de 65 relatórios. Os scripts
continuam em seus caminhos originais. O `.gitignore` separa evidências
compactas de saídas, corpus, downloads e estado local.

## Verificações

- 169 arquivos CJS novos passaram por `node --check`.
- 92 arquivos Python novos foram compilados em memória, sem executar
  seus experimentos e sem gerar cache.
- Os 415 artefatos do manifesto tiveram tamanho e SHA256 conferidos
  diretamente contra os bytes preparados no índice Git.
- A rodada dos títulos foi reproduzida em uma pasta isolada usando somente
  os scripts e insumos preparados para o commit. As 38.400 decisões AES
  reproduziram o digest
  `baa2ef57b6e06e37212be45421ad79f14e3cb44701c199423bdc76e1b320b095`.
- Os scripts Node desta organização usam módulos nativos; não há
  manifesto npm nem dependências npm a auditar.
- `pip-audit --path puzzle-env/Lib/site-packages` examinou 25 distribuições
  do ambiente Python local. A ferramenta retornou duas ocorrências do
  mesmo aviso `PYSEC-2026-1325` para `ecdsa 0.19.2`, sem versão de correção
  informada. Esse ambiente não é versionado e não foi alterado.

Sintaxe válida não substitui os controles específicos dos experimentos.
Esta organização não repetiu buscas históricas extensas e não validou a
senha final. Os relatórios preservam os testes já executados e suas limitações.

Os hashes em checkpoints históricos identificam os arquivos no momento
de cada campanha. A atualização de links de documentação nesta organização
pode mudar o hash de um relatório sem mudar o algoritmo ou seus dados;
o manifesto registra os bytes atualmente versionados dos artefatos selecionados.
