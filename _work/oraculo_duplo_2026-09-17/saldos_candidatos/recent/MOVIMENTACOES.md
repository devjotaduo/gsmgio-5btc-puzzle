# Movimentações recentes dos 12 endereços com histórico

Consulta em 17/09/2026 via mempool.space. A mais recente entre esses
endereços foi confirmada em **09/07/2026**. Nenhuma transação pendente
apareceu nas páginas consultadas. O saldo havia sido conferido como zero
nas consultas de saldo imediatamente anteriores.

Foram lidas as primeiras páginas dos 12 endereços: **224 movimentos por
endereço, correspondentes a 223 transações distintas**. Uma transação
aparece em dois endereços. A API retornou 50 transações confirmadas nas
quatro páginas maiores; não foi coletado o histórico completo desses
endereços. Os JSONs brutos estão em `page_01.json` a `page_12.json`.

## Cinco pares mais recentes entre os últimos movimentos de cada endereço

Datas e horários são os timestamps dos blocos em **UTC**. O valor é a
entrada no endereço e o consumo desse saldo na transação de saída,
incluindo eventual participação em taxas; não é o total da transação
nem necessariamente o valor líquido recebido por um destinatário.

Nos cinco pares abaixo, a revisão dos outpoints confirmou que a saída
consome exatamente o output da entrada, com o mesmo hash e altura de
bloco. Isso prova recebimento e gasto no mesmo bloco, mas não permite
medir o intervalo em segundos nem identificar autoria ou automação.
Na saída de `1JwSSub…` há seis inputs; apenas 4.750 sat são deste endereço.

| Data UTC | Endereço | Valor recebido e depois consumido | Entrada | Saída |
|---|---|---:|---|---|
| 09/07/2026 16:29:44 | `1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S` | 15.934 sat = 0,00015934 BTC | [tx](https://mempool.space/tx/f0ddb222bd2e2010fff8b3375ea93274a271e85ab9c0485f61ed2eca0e07f4df) | [tx](https://mempool.space/tx/4c52e643cd5b961ecd6f3164b8d1e19d8af372f2b2d9d6adaff3af4aa94ab1e1) |
| 01/07/2026 18:03:39 | `1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T` | 4.750 sat = 0,00004750 BTC | [tx](https://mempool.space/tx/630bc4f1ae46315579996de11f2ff194039297f2b71d500bb7a2366da94b1da3) | [tx](https://mempool.space/tx/70ec4f69e3bcabdb832fcd4777ea4a7e6502757a3d522086606a3e81fbc7b1e4) |
| 09/05/2026 18:50:15 | `1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8` | 2.851 sat = 0,00002851 BTC | [tx](https://mempool.space/tx/982fc6dc3434b5dfb39b2a0e30ee6c399d6a4c0cb98ecae1ced6d00eb78e6a4e) | [tx](https://mempool.space/tx/fc97c58d9fbed05f09efce2e8cf4309363d38a12dee06fa0f9b53aa2dfb869f9) |
| 04/05/2026 13:14:44 | `bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd` | 1.000 sat = 0,00001000 BTC | [tx](https://mempool.space/tx/555b424791fe4fb7ba3fe5861992719b71f9a735bb57b6427d83ac1c99befe79) | [tx](https://mempool.space/tx/14214e84f00751c3d57ea4bf0683e0d3f577368ed2db4e17853618e8d490f03c) |
| 20/04/2026 23:57:03 | `1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj` | 3.568 sat = 0,00003568 BTC | [tx](https://mempool.space/tx/4ee94189c3cc468b5e14a42374df23f641a3d308a419fd9547455d1967e72ca2) | [tx](https://mempool.space/tx/854cc1e601f78dd5b29fabb67ac2db6c5402624bde7184bbd428740b897e2518) |

## Último movimento confirmado de cada endereço

| Data UTC | Endereço | Variação líquida |
|---|---|---:|
| 09/07/2026 | `1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S` | −0,00015934 BTC |
| 01/07/2026 | `1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T` | −0,00004750 BTC |
| 09/05/2026 | `1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8` | −0,00002851 BTC |
| 04/05/2026 | `bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd` | −0,00001000 BTC |
| 20/04/2026 | `1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj` | −0,00003568 BTC |
| 01/04/2026 | `1F3iEJXDbQ1sZi6sx3LKNi1QNk6CYWf4ti` | −0,00010500 BTC |
| 27/02/2026 | `151XjjaceJMiB1gBH7jZiuqx2ZVj9Usa6R` | −0,00010500 BTC |
| 09/09/2025 | `1JX13G3cfWJgqpEfiTaksnN9RRAQKbH6et` | −0,00000892 BTC |
| 02/05/2025 | `bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4` | −0,00001031 BTC |
| 24/02/2022 | `1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK` | −0,00005737 BTC |
| 31/12/2019 | `3KToBU4ykTWfjnu4kAUV1q8QosnxT61sbf` | −0,00000546 BTC |
| 21/11/2018 | `19GuvDvMMUZ8vq84wT79fvnvhMd5MnfTkR` | −0,00044349 BTC |

O cálculo por endereço soma os outputs para ele e subtrai os prevouts
dele consumidos nos inputs. Isso trata troco e transações com vários
inputs sem atribuir todo o valor global da transação a uma só chave.
Os valores, datas e hashes das páginas foram conferidos por revisão
independente; não há inferência sobre a identidade dos participantes.

Metadados, txids e os 20 movimentos confirmados mais recentes estão em
[`summary.json`](summary.json); os 224 movimentos estão no arquivo local
`movements.jsonl`. Script reproduzível:
[`recent_transactions.py`](../../../../solver/oraculo_duplo_2026_09_17/recent_transactions.py).
