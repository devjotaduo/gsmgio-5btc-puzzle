# Consulta de saldos de chaves encontradas

`balances.py` deriva endereços Bitcoin mainnet de qualquer chave hex64
ou WIF válida, sem exigir coincidência com os endereços do puzzle.
Consulta saldos atuais reportados pela API em BTC e satoshis; não converte
para reais (BRL). Somente os endereços públicos saem do computador.

## Entrada e execução

Use um arquivo UTF-8 local com uma chave por linha (hex64, opcionalmente
com `0x`, ou WIF mainnet). Também aceita JSONL com exatamente um dos
campos `private_key`, `privkey` ou `wif`; os outros campos são ignorados.
Linhas vazias e comentários iniciados por `#` são ignorados.
O JSONL do oráculo é compatível, mas seu arquivo de entrada pode conter
chaves de qualquer outro endereço. As chaves devem ficar em arquivo local
ignorado pelo Git, como `_work/chaves_descobertas/chaves.txt`.

Na raiz da worktree `gsmgio-5btc-puzzle-oraculo-duplo`:

```powershell
$python = 'C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe'
& $python solver/oraculo_duplo_2026_09_17/balances.py --keys-file _work/chaves_descobertas/chaves.txt --out _work/chaves_descobertas/saldos.jsonl
```

O arquivo de saída precisa ser **novo**. Para uma consulta posterior,
escolha outro nome: cada execução busca valores atuais, sem reutilizar
saldos em cache. Pode repetir `--keys-file` para juntar arquivos; os
endereços derivados são deduplicados antes dos pedidos.

Para derivar e inspecionar os endereços sem rede:

```powershell
& $python solver/oraculo_duplo_2026_09_17/balances.py --keys-file _work/chaves_descobertas/chaves.txt --dry-run --out _work/chaves_descobertas/enderecos.jsonl
```

Também aceita endereços públicos diretamente:

```powershell
& $python solver/oraculo_duplo_2026_09_17/balances.py --address 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe --provider blockstream --out _work/chaves_descobertas/controle_publico.jsonl
```

## Cobertura e opções

Por padrão deriva cinco endereços por escalar:

- P2PKH com pubkey comprimida e não comprimida;
- P2SH-P2WPKH (SegWit encapsulado);
- P2WPKH (SegWit nativo);
- P2TR usando a chave como chave interna BIP86, sem árvore de scripts.

WIF com ou sem marca de compressão é aceito. Os cinco tipos são testados
independentemente dessa marca. Restrinja, se necessário, com
`--types p2pkh-compressed p2pkh-uncompressed` ou outros tipos de `--help`.
Não enumera derivações HD, mnemonics, multisig, scripts arbitrários nem
árvores Taproot; não existe um saldo universal associado a um escalar.

O provedor padrão é `mempool`; `--provider blockstream` usa a outra API.
Os pedidos são GET para hosts HTTPS fixos, com intervalo padrão de um
segundo, timeout de 15 segundos e até duas novas tentativas para falhas
de rede, HTTP 429 e HTTP 5xx. Há limites padrão de 1.000 endereços únicos
e 10.000 registros de entrada. Ajuste explicitamente com `--max-addresses`,
`--max-records`, `--interval`, `--timeout` e `--retries`.

O script valida toda a entrada e os limites antes de consultar a rede.
Não varre janelas de plaintext nem gera candidatos: consulta somente
as chaves fornecidas e os endereços públicos explícitos.

## Como ler o resultado

Cada linha de saída corresponde a um endereço público, com suas origens
identificadas apenas pelo índice do arquivo, linha e tipo. Não inclui
chaves, WIFs, labels ou outros campos livres da entrada.

| Campo | Significado |
|---|---|
| `confirmed_sat` / `confirmed_btc` | Recebido confirmado menos gasto confirmado |
| `mempool_delta_sat` / `mempool_delta_btc` | Entradas pendentes menos saídas pendentes; pode ser negativo |
| `with_mempool_sat` / `with_mempool_btc` | Saldo confirmado mais variação pendente |
| `received_confirmed_sat` | Total recebido historicamente, não o saldo |
| `has_history` | Há transações confirmadas ou pendentes |
| `checked_at_utc`, `provider` | Momento e fonte da consulta |
| `status: error` | Consulta falhou; os campos de saldo ficam ausentes |

O código de saída é 0 quando todas as consultas terminaram, 2 quando
alguma falhou e 1 para erro de entrada/arquivo. Os resultados concluídos
são gravados imediatamente no JSONL. `--dry-run` usa `derived_only`,
sem campos de saldo. Pendências podem mudar e as consultas não formam
um snapshot atômico da rede; saldo reportado não garante disponibilidade
imediata para gasto.

O cálculo segue os campos `chain_stats` e `mempool_stats` da
[API Esplora](https://github.com/Blockstream/esplora/blob/master/API.md#addresses).
O tipo P2TR segue o [BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki).

## Controles

```powershell
& $python solver/oraculo_duplo_2026_09_17/balance_controls.py
```

Controles offline cobrem vetores públicos de endereços, BIP86 oficial,
conferência ECC independente, hex/WIF inválidos, valores pendentes
negativos, falhas HTTP/rede, limite de entrada, ausência de segredos
no GET/saída, deduplicação e derivação sem acesso à rede.

## Candidatos textuais do corpus e consulta em lotes

`extract_balance_candidates.py --corpus caminho/corpus.sqlite --out _work/nova_extração`
captura hex64/WIF nas mesmas visões textuais do oráculo, com proveniência,
sem exigir um dos endereços do puzzle. Pode repetir `--corpus`. A pasta
de saída deve ser nova e ficar sob `_work/` desta worktree.
`keys.jsonl` contém as chaves e fica ignorado pelo Git; `extraction.jsonl`
contém somente os endereços derivados e as referências às ocorrências.
Os candidatos incluem hashes, controles e exemplos; não são evidência
de resolução do puzzle. Janelas raw32 arbitrárias não são extraídas.

`balances_batch.py --extraction _work/nova_extração/extraction.jsonl --out _work/nova_consulta`
consulta os endereços públicos em lotes de até 50 pelo endpoint
[`balance` da Blockchain.com](https://www.blockchain.com/explorer/api/blockchain_api).
Exige uma resposta para cada endereço, sem transformar omissões em zeros.
Grava `balances.jsonl` e um resumo com endereços que têm saldo ou histórico.
Este endpoint informa `final_balance`; a saída usa `balance_reported_sat`
e não presume uma divisão entre confirmado e mempool. Use `balances.py`
para essa divisão ou para conferir o resultado em outro provedor.
