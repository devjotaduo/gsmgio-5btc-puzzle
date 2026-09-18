# Oráculo isolado de dois endereços

Para consultar saldos de **qualquer chave encontrada**, inclusive fora dos
alvos do puzzle, veja [consulta de saldos](SALDOS.md) (`balances.py`).

Corrige a cobertura do endereço adicional associado aos halvings sem
modificar `gsmg_common.py` nem `solver/oracles.py`. Não contém uma solução
e não cria/transmite transações.

Campanha de 17/09/2026 concluída: **zero hits**, 592.339 conteúdos únicos,
58.357.232 tentativas raw32, 674 hex64 e 3 WIFs válidos. Cobertura e
limites no [relatório](../../_work/oraculo_duplo_2026-09-17/RELATORIO.md).

Alvos P2PKH mainnet:

- `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`: endereço publicado do puzzle.
- `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`: destino dos fundos retirados nos
  halvings; condição de prêmio adicional não confirmada pelo criador.

`oracle.py` compara o hash160 completo de chaves públicas comprimidas e
não comprimidas. Rejeita escalares fora de `1 <= k < n`, sem reduzi-los
módulo n. Percorre todas as janelas raw32 dos bytes originais, hex64
sobreposto inclusive por nibble e WIF com Base58Check, versão e sufixo
válidos. As representações textuais incluem ASCII, cp273 e UTF-16 LE/BE
nos dois alinhamentos. As transcodificações preservam os offsets nos
bytes de origem; não acrescentam janelas raw artificiais.

## Reprodução

Na raiz desta worktree, com o Python indicado pelo AGENTS.md:

```powershell
$python = 'C:/Users/ruthe/AppData/Local/Programs/Python/Python312/python.exe'
$sourceRoot = 'C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle'
& $python solver/oraculo_duplo_2026_09_17/controls.py --source-root $sourceRoot --out _work/oraculo_duplo_repro/controls.json
& $python solver/oraculo_duplo_2026_09_17/collect.py --self-test
& $python solver/oraculo_duplo_2026_09_17/collect.py --source-root $sourceRoot --out _work/oraculo_duplo_repro/corpus
& $python solver/oraculo_duplo_2026_09_17/scan.py --corpus _work/oraculo_duplo_repro/corpus/corpus.sqlite --out _work/oraculo_duplo_repro/scan --workers 4
```

A coleta exige pasta nova. Para retomar a varredura, repita exatamente o
comando `scan.py`: ele reaproveita só os lotes concluídos cujo contrato
de corpus/código/alvos coincide. SQLite com WAL/journal pendente é
recusado; o coletor deve terminar e fechar o banco antes da varredura.

## Evidência e limites

`corpus.sqlite` guarda os conteúdos únicos, suas origens e os hashes dos
snapshots de entrada. `manifest.json` registra seleção, campos, erros,
truncamentos e exclusões. Registros com apenas um prefixo são marcados;
a cauda não preservada não pode ser examinada. Logs ambíguos mantêm
representações alternativas explicitamente identificadas.

`scan/summary.json` só recebe `status: complete` depois de conferir o
total de conteúdos/bytes/janelas, a estabilidade do corpus e a estabilidade
do código. Toda coincidência é repetida com python-ecdsa. Eventuais chaves
ficam nos arquivos locais ignorados `checkpoint.sqlite` e `hits.jsonl`;
não aparecem no resumo ou no progresso.

`partition.py` permite varrer antecipadamente um snapshot estável e,
quando a coleta terminar, extrair só o complemento. Ele verifica os bytes
comuns, rejeita sobreposição entre partes anteriores e exige que todas
estejam contidas no corpus completo. O relatório final deve conferir
a união disjunta de todas as partes.

O número de tentativas não é o número de escalares distintos: diferentes
conteúdos e offsets podem repetir a mesma chave. A campanha não recupera
os milhões de candidatos históricos descartados sem persistência.

## Conferência da execução preservada

`snapshot.py` congela apenas os payloads já confirmados por transação
no banco do coletor ativo. `partition.py` extrai o complemento sem alterar
o corpus. `audit_explicit_hex.py` confere, por parser independente, campos
hex explicitamente rotulados e entre aspas contra o snapshot principal;
registra fontes que já não reproduzem os bytes originais.
`recover_partial.py` recupera somente o prefixo específico de 789 bytes
auditado nesta campanha, exigindo os hashes exatos da fonte e do prefixo.

Com os cinco lotes e corpus locais preservados:

```powershell
& $python solver/oraculo_duplo_2026_09_17/finalize.py --campaign _work/oraculo_duplo_2026-09-17 --source-root $sourceRoot
```

O finalizador exige hashes, contratos e totais coerentes, confirma a união
disjunta A+B+C, conta a sobreposição dos suplementos e grava `summary.json`
e `final_qa.json`. A origem ativa pode mudar; coletá-la novamente não
promete reproduzir o snapshot antigo. Os bancos e arquivos com possíveis
chaves ficam ignorados pelo Git; relatórios e resumos compactos podem ser
versionados.
