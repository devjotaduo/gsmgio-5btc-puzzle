# Complemento dos decodificadores do resíduo — 18/09/2026

**Nenhuma abertura autenticada ou chave dos dois alvos.** A execução completou
as configurações declaradas dos decodificadores, corrigindo a identificação dos
marcadores e removendo a seleção linguística antes dos testes criptográficos.
O checkout original não foi alterado.

## Hipótese e diferença de cobertura

A hipótese registrada em `run1/spec.json`, antes da geração, é que uma senha
válida poderia estar numa saída sem aparência de inglês, descartada pelo
ranking anterior, ou resultar da preservação dos `b` não primos.

O script histórico `solver/primos_2026_09_17/resid_decoders.py` declara **23.164
configurações**, das quais **23.114** receberam escore. Seu resumo registra
**680 senhas**, correspondentes a **4.080 decisões AES**, após escolher os
20 melhores resultados por família. O arquivo atual já injeta o scorer limpo;
esta campanha não atribui a ele o uso remanescente do scorer contaminado.

Outra diferença está em `seq_variants`: a versão histórica substitui um token
pelo seu conteúdo, incluindo os `b` legítimos nas posições lógicas **30 e 52**.
A versão corrigida substitui somente posições primas. Isso vale nas duas
segmentações, L83 e L84. As demais regras foram preservadas.

| Família | Configurações |
|---|---:|
| Checkerboard | 19.710 |
| Polybius 3×3 | 216 |
| Bifid 3×3 | 2.904 |
| Substituição por frequência | 4 |
| Grupos de dígitos | 150 |
| Grupos entre marcadores | 20 |
| A1Z26 direto | 4 |
| Conversão de bases | 48 |
| Índices em textos conhecidos | 108 |
| **Total** | **23.164** |

Há 27 saídas vazias. Todas as formas não vazias chegam ao oráculo, sem escore
de inglês: saída sem `?`, minúscula, maiúscula, somente letras em maiúsculas
ou minúsculas, e pontos substituídos por espaços com remoção de espaços nas
pontas. Cada material fornece senha direta e SHA256 hexadecimal minúsculo.

## Corpus e comparação exata

- **9.068 saídas** mudam com a correção da máscara.
- **71.599 materiais** e **143.198 senhas** distintas por bytes exatos.
- O gerador antigo, sem aplicar seu ranking, produziria **71.025 materiais**.
- Interseção dos dois geradores: **37.920 materiais**; **33.679** aparecem
  somente após a correção; **33.105** formas antigas deixam de ser geradas.

Essa comparação é entre os **geradores**, não entre as senhas efetivamente
testadas nas duas campanhas. O conjunto completo das 680 senhas históricas
não foi preservado. Portanto, não se afirma que as 143.198 senhas sejam todas
novas nem que o complemento corresponda à simples diferença entre esses números.

`run1/coverage.json` registra hashes de cada forma separadamente. Para os hashes
de conjuntos, os bytes são ordenados, cada item precedido pelo comprimento
uint64 big-endian, e o fluxo recebe SHA256:

| Conjunto | SHA256 |
|---|---|
| Materiais antigos gerados sem gate | `068eb91a254b3fabd9a5ace666083a9514a68e9b179c892fe30b92c59188a518` |
| Materiais corrigidos | `54577ee1dd0b950ca1068c814aef56df06e63325136ef5c827f010f3c4557f9c` |
| Senhas testadas | `c2ee7104c0f3a6e97da342def1c48478465a230b6709bda7297054339391b95f` |

Os arquivos locais `outputs.jsonl`, `materials.jsonl` e `passwords.jsonl`
preservam configurações, bytes e proveniência. São ignorados pelo Git.

## Controles e conferência independente

- A fase 2 abre com SHA256 hexadecimal de `causality` e EVP-SHA256; MD5 falha.
- O checkerboard reproduz a frase e os 149 dígitos exatos da fase 3.2.2.
- Os `b` das posições 30 e 52 permanecem na sequência corrigida.
- Cifrar/decifrar Bifid reconstrói os resíduos nos períodos examinados.
- Uma senha sintética sem aparência de inglês atravessa o checkerboard e o
  teste AES, com os dois KDFs; a chave inserida no plaintext é detectada em
  ambos os endereços sintéticos, com serializações comprimida/não comprimida.
- Uma conferência separada extraiu **somente funções puras** dos arquivos
  históricos pela AST, sem importar ou executar seus comandos de módulo.
  Foram conferidas **46.328 saídas** — 23.164 com cada máscara — e todas as
  seis normalizações. Não houve divergência. Registro em
  [independent_verification.json](independent_verification.json).
- Ruff passou no script novo. O oráculo usado inclui a correção cp273 inversa,
  SHA256 `1b927716a5339a5a8cabe8527f1d7197e9bf539fdb508f25562dabafd45eec8d`.

Foram executados **100 nulos casados**, embaralhando somente os símbolos não
primos e preservando contagens e marcadores. A amostra foi fixada por posição
na lista ordenada de configurações: até oito por família, **64 ao todo**.
Todas as formas dessa amostra foram testadas nos três blobs e dois KDFs:
**178.116 decisões AES**, **603 paddings**, nenhuma triagem semântica.
Os corpos completos estão em `run1/null_padding.jsonl`.

Esse nulo é uma amostra estratificada do mecanismo, não uma repetição integral
da busca. Não fornece p-value global; senhas podem reaparecer entre réplicas.
Não foi feita varredura ECC dos plaintexts do nulo.

## Resultado da execução real

| Medida | Resultado |
|---|---:|
| Senhas | 143.198 |
| Decisões AES: SMALL, TAIL32, COSMIC × SHA256/MD5 | **859.188** |
| Plaintexts completos com padding válido, todos distintos | **3.420** |
| Janelas raw32 verificadas, ambos os alvos e serializações | **1.635.534** |
| Escalares únicos: SHA256 das senhas + derivações numéricas históricas | **143.242** |
| Registros de derivações numéricas históricas | 60 |
| Candidatos hex64/WIF nos paddings | 0 |
| Triagens semânticas | **0** |
| Chaves correspondentes aos alvos | **0** |

O teste criptográfico real levou 75,5 segundos; geração, 3,95 segundos;
nulos, 5,91 segundos, nesta máquina e carga. Todos os paddings estão em
`run1/padding.jsonl`; `run1/hits.jsonl` está vazio. A execução confere a
estabilidade dos hashes de fontes antes de declarar `complete`.

O segundo alvo é `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`, destino dos halvings;
sua condição de prêmio permanece não confirmada. A varredura é local.

## Limites e reprodução

O negativo cobre exatamente as configurações e formas acima. Mantém regras
históricas que perdem informação: escape final isolado descartado, códigos
inválidos como `?`, remoção desse `?` nas formas, módulos e apenas os dois
alfabetos de saída Polybius originalmente selecionados. Não acrescenta
famílias, parâmetros, alfabetos ou hipóteses sobre a segmentação.

O script é [residue_complete.py](../../../solver/multiagente_2026_09_18/residue_complete.py).
Use um diretório novo, dentro da worktree:

```powershell
python -B solver/multiagente_2026_09_18/residue_complete.py --run --out _work/multiagente_2026-09-18/residue/repro
```

Sem `--run`, prepara o corpus e imprime a contagem sem executar a campanha
AES. A execução `prepare/` é apenas a prévia; **`run1/summary.json`** é o
resultado final. Não há processo desta campanha em execução.
