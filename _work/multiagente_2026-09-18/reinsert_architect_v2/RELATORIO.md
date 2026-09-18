# Listas com primos reinseridos seguidas de cláusulas

**Negativo no complemento finito; nenhuma abertura autenticada ou chave.**

## Hipótese e novidade

A ordem `matrixsumlist lastwordsbeforearchichoice` poderia pedir uma lista
numérica seguida de uma cláusula. As listas vêm exclusivamente das grades
lógicas L83/L84 com o primo p reinserido nos marcadores e a1z26 nas demais
posições: mesmos três modos, retângulos exatos, somas e serializações da
[reinserção v2](../reinsert_primes_v2/RELATORIO.md).

Os 336 registros de listas isoladas contêm **270 bases únicas**. O gerador
reproduziu esse conjunto byte a byte antes de compor as senhas. Foram usadas
somente as duas cláusulas previamente registradas:

- `reinsertingtheprimebasicsafterwhichyouwillberequiredto`: texto autenticado
  da fase 3.2; escolher o trecho de REINSERTING até antes de SELECT é interpretação.
- `sheisgoingtodieandthereisnothingyoucandotostopit`: oração no roteiro de
  27/10/2001, página 122A/PDF 130, antes do movimento de Neo à porta. O roteiro
  é anterior ao filme e não comprova a montagem final.

Não há separador entre a lista e a cláusula. Foram testadas as formas literal
e SHA256 hexadecimal minúsculo, sem acrescentar prefixos ou outros recortes.
A [auditoria de sobreposição](../reinsert_architect_evidence/RELATORIO.md)
encontrou zero coincidências nas 1.080 senhas contra 14 corpora de 13 campanhas;
isso não demonstra ausência em todo histórico não preservado.

## Controles e execução

Passaram fase 2/causality, checkerboard da fase 3.2.2, somas retangulares
plantadas, conservação dos nulos e senha composta sintética que abre AES nos
dois KDFs e revela uma chave plantada no offset 7. O oráculo isolado testa os
dois endereços, as duas serializações P2PKH e codecs textuais. Hits reais, se
houvesse, exigiriam confirmação por python-ecdsa antes do registro.

| Medida | Resultado |
|---|---:|
| Bases / materiais / senhas únicas | 270 / 540 / 1.080 |
| Decisões AES: três blobs × SHA256/MD5 | **6.480** |
| Plaintexts completos com padding válido | 31 |
| Janelas raw32 big-endian desses plaintexts | 16.464 |
| Candidatos semânticos / chaves dos alvos | **0 / 0** |
| Nulos casados | 100 |
| AES nos nulos | 647.808 |
| Paddings nos nulos / candidatos semânticos | 2.515 / 0 |

Os nulos embaralham os resíduos não primos de cada segmentação, preservando
contagens e posição/tipo dos marcadores. O número de senhas únicas varia de
1.064 a 1.080 por réplica; não há p-value global. Não se executou ECC nos nulos.
O embaralhamento é independente por segmentação e não preserva a relação
conjunta `resíduo84 = resíduo83 + e`.

Todos os paddings, inclusive os nulos, foram preservados em `paddings.jsonl`.
`passwords.jsonl` contém as senhas e proveniência. Esses arquivos ficam locais.
O resumo não divulga chaves. [Especificação](spec.json), [controles](controls.json)
e [resultado](summary.json) distinguem dados reais de nulos.

## Rastreabilidade e reprodução

Esta execução v2 é a referência. `reinsert_architect/` teve números idênticos,
mas v2 acrescenta hashes das dependências efetivamente importadas no checkout
original e snapshot dos DBBI/blobs usados. As duas execuções **não são somadas**.
A versão antiga está preservada como `reinsert_architect_v1.py`; a versão atual
é [reinsert_architect.py](../../../solver/multiagente_2026_09_18/reinsert_architect.py).
Os nove hashes de dependências conferiram antes/depois; o checkout original
foi apenas lido.
Um revisor reproduziu independentemente os 31 plaintexts a partir do snapshot
dos blobs, conferiu as 1.080 senhas e recontou as 16.464 janelas. Os 2.546
registros de padding real/nulo são idênticos nas duas execuções; a repetição
não acrescentou candidatos nem cobertura.

```powershell
python -B solver/multiagente_2026_09_18/reinsert_architect.py --out _work/repro_reinsert_architect
```

Use o Python 3.12 indicado em AGENTS.md e um diretório novo. O negativo cobre
exatamente as composições declaradas. Não cobre raw32 little-endian, outras
cláusulas, representações, KDFs ou ordens de concatenação.
