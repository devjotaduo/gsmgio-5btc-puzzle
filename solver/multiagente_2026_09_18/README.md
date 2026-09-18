# Complementos finitos do oráculo e da pesquisa — 18/09/2026

O [relatório da rodada](../../_work/multiagente_2026-09-18/RELATORIO.md) registra
escopo, hipóteses, resultados e limites. Não há solução autenticada.

| Arquivo | Responsabilidade |
|---|---|
| `audit_codecs.py` | Reproduz a codificação inversa cp273 da fase real e a correção do oráculo isolado. |
| `audit_stream.py` | Reproduz descarte de chave binária interior em modos de fluxo; não repete a campanha ampla. |
| `audit_recovered_semantic.py` | Examina texto, trechos ASCII e blobs aninhados nas três visões dos plaintexts recuperados. |
| `recover_corpus.py` | Recupera quatro fontes finitas, regenera AES com senha conhecida e deduplica contra três bancos anteriores. |
| `scan_delta.py` | Varre SQLite fechado, com modo textual ou raw32 BE/LE + codecs; registra checkpoints efetivamente concluídos. |
| `scan_delta_v2.py` | Mesma cobertura; corrige o tipo do argumento padrão para retomar sem declarar alvos explicitamente. Use para novas execuções. |
| `scan_controls.py` | Valida hits plantados, offsets, retomada e rejeição de fontes adulteradas. |
| `verify_scan.py` | Reconcilia corpus, lotes, hashes, resumo e hits depois da conclusão do scanner v1; não repete ECC. |
| `residue_complete.py` | Completa configurações dos decodificadores e corrige máscara de marcadores primos. |
| `reinsert_primes.py` | Testa reinserção do próprio primo na sequência lógica antes das somas. |
| `reinsert_architect.py` | Complemento restrito às bases numéricas seguidas de duas cláusulas candidatas do Arquiteto; `reinsert_architect_v1.py` preserva a versão anterior à ampliação de proveniência. |
| `cover_geometry.py` | Mede estrelas da capa e testa uma família pequena de coordenadas, com nulo geométrico. |

Todas as saídas ficam em `_work/multiagente_2026-09-18/`. Use o Python 3.12
definido no AGENTS.md. Não publique corpus, plaintexts, exports ou arquivos de hits.
Nenhum desses scripts envia transações.

O scanner em execução está congelado por hash. Para retomá-lo, declare os alvos
explicitamente: a primeira versão tem uma diferença de tipo tuple/list no
default do argumento que faz o contrato recusar uma retomada sem `--targets`.
Isso foi identificado em execução e não altera os candidatos examinados.
`scan_delta_v2.py` corrige somente esse default; foi validado com retomadas sem
`--targets`, além dos controles anteriores. Não substitui o arquivo congelado
nem permite retomar um contrato v1 como se fosse a mesma versão.

```powershell
& 'C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe' solver/multiagente_2026_09_18/scan_delta.py --corpus _work/multiagente_2026-09-18/recovered/corpus.sqlite --out _work/multiagente_2026-09-18/scan_recovered --mode both --workers 16 --batch-windows 100000 --targets 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe 17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa
```

`--workers` pode mudar em uma retomada; corpus, código, tamanho dos lotes, modo
e alvos devem permanecer idênticos. Contagens `expected_*` são estimativas do
espaço. Somente status `complete` e reconciliação dos checkpoints provam cobertura.
