# Saldos dos endereços derivados dos candidatos preservados

**Consulta em 17/09/2026, 21:21–21:23, horário de Brasília: todos os
3.370 endereços consultados retornaram saldo zero.** Doze têm histórico
de transações. Os 18 endereços da conferência por segundo provedor também
retornaram zero confirmado e zero incluindo mempool.

## Escopo

A extração reutilizou as visões textuais do oráculo sobre os três corpora
congelados da campanha: 674 ocorrências hex64 e três WIFs válidos,
sem janelas raw32. Deduplicação por bytes produziu 674 candidatos distintos
e cinco endereços distintos para cada um: P2PKH comprimido/não comprimido,
P2SH-P2WPKH, P2WPKH e P2TR com chave interna BIP86 sem árvore de scripts.

Esses conteúdos são candidatos: incluem hashes, dados de fases públicas
e resultados de campanhas históricas. Sua validade como escalar ou WIF
não prova que sejam uma resposta do puzzle. Nenhum gerou os dois alvos
do prêmio/reduções dos halvings na campanha anterior.

## Execução e conferência

- API primária: endpoint de consulta em lotes
  [`balance` da Blockchain.com](https://www.blockchain.com/explorer/api/blockchain_api).
  Foram 68 lotes, com no máximo 50 endereços e conferência do conjunto
  exato de endereços de cada resposta. 3.370 sucessos, zero erros e zero
  saldos positivos; 3.358 endereços sem histórico e 12 com histórico.
- Essa API informa `final_balance`, sem separar confirmado/mempool.
  A saída preserva esse limite e chama o campo de `balance_reported_sat`.
- A API Esplora de mempool.space conferiu todos os 12 endereços com
  histórico, mais os demais formatos das três chaves WIF: união de
  **18 endereços**. Todos retornaram zero confirmado e zero com mempool;
  os mesmos 12 tinham histórico. Nenhuma dessas consultas falhou.
- Não foram enviadas chaves privadas às APIs. Os candidatos estão apenas
  no arquivo local ignorado `keys.jsonl`; os resultados contêm endereços
  públicos e referências de origem. Não foram criadas transações.

## Endereços com histórico

Datas e valores das últimas transações estão em
[`Movimentações recentes`](recent/MOVIMENTACOES.md).

Todos os endereços abaixo tinham saldo **0 BTC** em ambos os provedores
no instante das consultas. O número de transações vem da API primária.

| Endereço público | Transações |
|---|---:|
| [1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8](https://mempool.space/address/1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8) | 221 |
| [1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T](https://mempool.space/address/1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T) | 4.163 |
| [3KToBU4ykTWfjnu4kAUV1q8QosnxT61sbf](https://mempool.space/address/3KToBU4ykTWfjnu4kAUV1q8QosnxT61sbf) | 2 |
| [bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4](https://mempool.space/address/bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4) | 4 |
| [151XjjaceJMiB1gBH7jZiuqx2ZVj9Usa6R](https://mempool.space/address/151XjjaceJMiB1gBH7jZiuqx2ZVj9Usa6R) | 2 |
| [1F3iEJXDbQ1sZi6sx3LKNi1QNk6CYWf4ti](https://mempool.space/address/1F3iEJXDbQ1sZi6sx3LKNi1QNk6CYWf4ti) | 2 |
| [1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK](https://mempool.space/address/1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK) | 8 |
| [1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S](https://mempool.space/address/1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S) | 51 |
| [bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd](https://mempool.space/address/bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd) | 2 |
| [1JX13G3cfWJgqpEfiTaksnN9RRAQKbH6et](https://mempool.space/address/1JX13G3cfWJgqpEfiTaksnN9RRAQKbH6et) | 2 |
| [19GuvDvMMUZ8vq84wT79fvnvhMd5MnfTkR](https://mempool.space/address/19GuvDvMMUZ8vq84wT79fvnvhMd5MnfTkR) | 2 |
| [1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj](https://mempool.space/address/1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj) | 288 |

## Proveniência

Conferência independente das 677 ocorrências contra o SQLite: zero
payloads ausentes, zero divergências de SHA256, 965 registros de origem.
Todos os candidatos vieram do corpus principal; os suplementos não
acrescentaram candidato textual. Classificação por origem:

- 101 exclusivos dos arquivos de campanhas de `frontier_2026-09-17`;
- 86 exclusivos do plaintext público da fase 3.2;
- 484 exclusivos das campanhas históricas de 02/09;
- três presentes tanto em `frontier` como nas campanhas históricas.

Os três WIFs são `k00001` (logs `selection__select256`/`rerun_ext__select256`),
`k00191` (`ans_too_ct_text.jsonl`) e `k00674` (`tail32_history.jsonl`).
Sua proveniência aponta para materiais públicos/campanhas já documentadas;
saldo histórico não autentica uma solução do puzzle.

## Artefatos e limites

- [`spec.json`](spec.json): hashes dos corpora, contagens e versão executada da extração.
- [`live/summary.json`](live/summary.json): resultado primário e endereços com histórico.
- [`final_qa.json`](final_qa.json): união exata dos 3.370 endereços, seleção dos
  18 conferidos e hashes das saídas.
- `extraction.jsonl`, `live/balances.jsonl` e `verification.jsonl`: registros
  públicos completos, mantidos localmente.

Os saldos são os valores reportados pelos provedores nesses instantes,
sem snapshot atômico da rede. A consulta não abrange candidatos não
preservados, outros scripts/derivações HD ou janelas raw32 arbitrárias.
O negativo de saldo não demonstra como o autor codificou a solução.

Scripts e uso em
[`SALDOS.md`](../../../solver/oraculo_duplo_2026_09_17/SALDOS.md).
