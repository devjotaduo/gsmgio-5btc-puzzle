# Conferência pública — 16/09/2026

**Nenhuma solução nova ou operação nova confirmada foi localizada nas fontes
consultadas.** Essa conclusão é restrita às consultas abaixo, não a toda a
internet ou a grupos privados.

## Repositório original

Foram recuperados via API os 15 issues/PRs mais recentemente atualizados,
abertos ou fechados, e os comentários atualizados desde 11/09/2026 00:00 UTC.
A consulta de comentários retornou um item e nenhum link de próxima página.
O item mais recente continua sendo de 11/09/2026 01:43:37 UTC, já registrado
na consulta anterior. A promessa de enviar uma assinatura não é uma prova de
posse da chave; a resposta recuperada não traz essa assinatura.
[Discussão #99](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/99#issuecomment-5628153255).

Arquivos locais: `issues.json`, `comments.json`. A enumeração de 15 issues
não constitui inventário completo do repositório; serviu para conferir os
itens mais recentemente atualizados.

A conferência encontrou uma divergência no hash anotado no resumo compacto
da consulta anterior. O corpo atual foi então comparado com o arquivo integral
`session_2026-09-11/github_99_comments.json`: os 2.362 caracteres são idênticos,
com SHA256 `0d8d8f3764ce7b67a8d26ac2f224c48071940d0d2b629899c905e7ff6f22b6a7`.
A conclusão de ausência de comentário novo usa esse arquivo integral e os
IDs/datas da API; não depende do hash divergente do resumo antigo.

## Fork de Naddiseo

O [fork indicado pelo contribuidor](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/105)
tem apenas a branch `master` na resposta da API. A antiga referência
`notebook-solutions` retorna 404. A árvore completa de `master`, sem truncamento,
foi fixada no commit `81f68e5073a7ad0a002acd2a2db0b6bcfa0570ac`.
O push mais recente informado é de 05/09/2026.

O [caderno de SalPhaseIon](https://github.com/Naddiseo/gsmgio-5btc-puzzle/blob/81f68e5073a7ad0a002acd2a2db0b6bcfa0570ac/salphaseion.ipynb)
documenta as conversões conhecidas, mas termina deixando DBBI e FAED sem
decodificação. As células foram lidas como dados; nenhum código obtido da
rede foi executado.

Três notas marcadas como não verificadas também foram examinadas:

- As contagens de 9 células amarelas e 15 azuis e sua relação com os bits
  finais da URL são as mesmas já conferidas localmente.
- A nota de FEFEFE distingue a interpretação de paridade da alegação
  incorreta de que a célula ocuparia o índice espiral 104.
- A nota 1141 apresenta uma extração da fala e relata resultado negativo.
  Não fornece senha ou derivação validada para a etapa final.

Uma limitação lógica merece registro: os bits coloridos serem determinados
pela URL **não impede** que suas contagens sejam reutilizadas como parâmetro
de outra etapa. A observação não fornece informação adicional à URL, mas
isso não basta para excluir uma regra que use 9 e 15.

Esse ponto motivou a hipótese delimitada **contagens → primos de índices
9/15 → pesos 23/47 → somas da matriz**, examinada no
[relatório de execução](../count_prime_matrix_2026-09-16/RELATORIO.md).
Não foi apresentada pelo fork como solução, e os testes locais foram negativos.

Fontes consultadas: [nota das contagens](https://github.com/Naddiseo/gsmgio-5btc-puzzle/blob/81f68e5073a7ad0a002acd2a2db0b6bcfa0570ac/unverified/phase0_yellow_blue_counts.md),
[nota FEFEFE](https://github.com/Naddiseo/gsmgio-5btc-puzzle/blob/81f68e5073a7ad0a002acd2a2db0b6bcfa0570ac/unverified/phase0_fefefe_parity.md) e
[nota 1141](https://github.com/Naddiseo/gsmgio-5btc-puzzle/blob/81f68e5073a7ad0a002acd2a2db0b6bcfa0570ac/unverified/phase3.2_1141.md).
