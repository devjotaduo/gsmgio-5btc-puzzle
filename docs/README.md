# Guia da pesquisa GSMG

**Estado:** as fases 1 a 3.2 estão documentadas; a senha final e a chave do
prêmio continuam sem validação. Padding AES, checksum BIP39 e palavras
isoladas não bastam para declarar uma solução.

| Quero consultar… | Onde começar |
| --- | --- |
| Hints e decodificações por fase | [README principal](../README.md) |
| Experimentos e seus limites | [Índice de relatórios](RESEARCH-INDEX.md) |
| Histórico cronológico detalhado | [ENDGAME](../ENDGAME.md) |
| Execução e dependências dos scripts | [Guia do solver](../solver/README.md) |
| Prioridades e discussão histórica | [Notas de pesquisa](notes/README.md) |
| Regras para navegar e contribuir | [Guia de navegação](CODEX-NAVIGATION-GUIDE.md) |

## Organização

```text
README.md                    pistas e resultados por fase
ENDGAME.md                   diário dos experimentos
docs/                        navegação, índice e notas
solver/                      scripts de pesquisa e verificadores
solver/experiments/          snapshots históricos de código
_work/<experimento>/         relatório, parâmetros e resultados locais
```

Os caminhos de `solver/` e `_work/` foram preservados porque scripts e
relatórios os utilizam diretamente. A organização separa o que entra no
Git sem apagar as saídas locais.

## O que fica no Git

Fontes de pesquisa, documentação, os relatórios próprios e checkpoints
compactos (`summary`, `spec`, `controls`, `final_qa` e
`independent_verification`) são versionados. Alguns checkpoints grandes
têm exceções explícitas no `.gitignore`. O índice registra os relatórios;
o [manifesto](research-manifest.json) registra os caminhos, tamanhos e
hashes dos artefatos de pesquisa incluídos nesta organização.

Listas grandes de candidatos, certificados, corpus, mídia baixada e
extratos do Telegram permanecem locais. `result.json`, sessões, credenciais,
ambientes Python e preferências locais de ferramentas também ficam fora.
Não houve exclusão dessas saídas do disco.

## Reprodução

Um clone contém os relatórios e os checkpoints selecionados, não todos os
resultados brutos citados por eles. Consulte os comandos e pré-requisitos
de cada relatório antes de executar. Arquivos citados apenas em código
inline podem depender da bancada local. Os hashes em `final_qa.json`
também podem identificar arquivos deliberadamente não versionados.

A rodada [capitalização dos títulos](../_work/title_position_masks_2026-09-16/RELATORIO.md)
inclui os scripts e insumos necessários à reprodução em Node.js. Escolha
uma pasta de saída nova para preservar os resultados anteriores:

```powershell
node solver/title_position_masks.cjs _work/title_mask_reproduction
```
