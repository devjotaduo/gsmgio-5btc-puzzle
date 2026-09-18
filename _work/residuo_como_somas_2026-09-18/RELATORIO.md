# O resíduo *como* a lista das 28 somas, e os intermediários da PR #6

**Estado: ambos negativos.** Nenhuma senha final, abertura reconhecida ou chave de um dos dois alvos.

O pacote completo da continuação (código, dados brutos, manifesto e controles) foi entregue e
**verificado pelo coordenador com código próprio**. Quase tudo que antes era "aceito do relato" está
agora reproduzido; o que não está vai listado no fim. Números em
[`verificacao_coordenador.json`](verificacao_coordenador.json).

| Verificação do coordenador | Relato | Reproduzido |
|---|---|---|
| `MANIFEST.sha256` | — | **91/91**, 0 divergem |
| `dbbi`, `faed`, os 3 blobs, a grade de cores | — | **idênticos ao kit**, 0 divergências |
| Decifrações AES (amostra de 500, com o kit do repo) | — | **0 divergências** no raw e no despadded |
| Alvos numéricos distintos do `sum28` | 2.046 | **2.046** |
| Combinações peso/perfil | 1.564.864 | **1.564.864** |
| Construções com comprimento compatível | 240.928 | **240.928** |
| Reconstruções exatas do resíduo | 0 | **0** |
| Janelas raw32 válidas BE/LE | 8.347.680 | **8.347.680** |
| Acertos na varredura raw32 | 0 | **0** |

Não houve escrita remota, consulta de saldo, assinatura nem transmissão de transação.

## Procedência (commit conferido aqui)

O código da PR #6 foi lido pelo conector GitHub no commit `1dba50a1` — conferi que é exatamente o
commit do `pipeline_roadmap.py`, **anterior** à correção `ef55ccf`. Ou seja, a reimplementação partiu da
versão **com** o defeito do critério do par e chegou à mesma conclusão por caminho independente.

Duas ressalvas de método, declaradas pela própria continuação:

- **o arquivo original não foi executado**: as operações foram reimplementadas a partir da leitura. Uma
  segunda formulação, sem chamar as funções da primeira, deu os mesmos 144 pares caminho/valor. Isso
  confere as duas reimplementações entre si — **não** é reexecução do histórico do repositório;
- **não é pré-registro**: a especificação principal foi consolidada depois da primeira execução AES e
  antes da varredura binária integral.

## 1. Inverter o papel do rótulo `matrixsumlist`

A hipótese muda a *função* do rótulo em vez de variar a operação:

> em vez de `matrixsumlist` ser a operação que decifra o resíduo, **o resíduo seria o objeto que o
> rótulo nomeia** — a lista das 14 somas de linha e 14 de coluna, concatenadas em decimal mínimo.

Não se presume que as somas sejam fluxo de deslocamento. Isso a separa de `color_residue_2026-09-16`,
que tratou as somas como chave aditiva módulo 10.

**A abertura estava declarada.** `symbolic_color_sums_2026-09-16` fechou o modelo de 14 valores e
registrou nos limites, textualmente: *"Continuam fora do modelo: … combinar linhas e colunas em uma
lista de 28 valores, outras bases…"*.

### O modelo

Para cada linha ou coluna, `S_i = B_i·p + Y_i·q + K_i·k + W_i·w + F_i·f`, com `p` (azul) e `q` (amarelo)
inteiros uniformes `≥ 2` — o que inclui todos os pares de primos **e também os compostos**; preto e
branco recebendo 0 ou 1 independentemente; e a célula `#FEFEFE` separada de branco, com quatro
interpretações declaradas: 0, 1, `p` ou `q`.

Cobertura: L83 e L84, sentido publicado e invertido, os 512 subconjuntos globais de letras que poderiam
significar zero (o modelo de 16/09 cobria até duas), e 16 ordens naturais das 28 somas — linhas/colunas
antes ou depois, cada eixo nos dois sentidos, concatenação ou intercalação. Fora do subconjunto zerado,
vale `a=1…i=9`.

### Por que não há teto arbitrário de peso (reproduzido pelo coordenador)

Cada uma das 28 somas contém ao menos uma célula colorida, logo ocupa ao menos um dígito. Se um peso tem
`d` dígitos e sua cor aparece em `k` somas, então `L ≥ k·d + (28−k)`. Conferi a contagem em `G.COLORED`
(15 azuis, 9 amarelas, 1 `#FEFEFE`):

| | somas de 28 que contêm a cor | linhas | colunas |
|---|---|---|---|
| azul | **22** | 12 | 10 |
| amarelo | **15** | 8 | 7 |

Daí: azul com 3 dígitos exigiria `22×3 + 6 = 72`; amarelo com 4 exigiria `15×4 + 13 = 73`. O resíduo tem
60 (L83) ou 61 (L84). Logo azul tem no máximo 2 dígitos e amarelo no máximo 3 — **`p ≤ 99` e `q ≤ 999`
são limites derivados da hipótese e dos dados**, não escolhas de orçamento. A célula especial, nas quatro
interpretações, não reduz esses mínimos.

### Resultado (reproduzido pelo coordenador)

| Medida | Valor |
|---|---|
| Combinações de interpretação (método inverso, por sistemas lineares) | 524.288 |
| Strings numéricas distintas que essas interpretações fornecem | 2.046 |
| Combinações peso/perfil (verificador direto, soma as células) | 1.564.864 |
| Construções ordenadas com comprimento compatível | 240.928 |
| **Reconstruções exatas do resíduo** | **0** |
| Controles positivos | 64 (inverso) + 32 (direto) |

Reimplementei o **método direto** do zero — varrendo `p ∈ [2,99]`, `q ∈ [2,999]`, `k,w ∈ {0,1}` e as
quatro escolhas da célula especial, montando as 28 somas a partir da grade validada contra o kit e
filtrando por comprimento antes de gerar as 16 ordens. Os quatro números saíram idênticos em 8,6 s.
Isso cobre o mesmo espaço do método inverso por outro caminho. O segundo método da entrega também não
usa o solucionador de prefixos do primeiro. **As contagens medem conjuntos
diferentes e não devem ser somadas como se fossem tentativas AES**; as 240.928 construções ordenadas não
foram declaradas distintas.

**Alcance:** o resíduo não é a concatenação decimal direta das 28 somas neste modelo, nem escolhendo
outros primos para azul/amarelo. Não elimina listas em outras bases, bijeção arbitrária dos dígitos,
alias de zero variável por ocorrência, ordem arbitrária entre as 28 somas, uma quinta cor com peso
independente, nem as somas como operandos de outra transformação.

## 2. Acertos isolados e intermediários da PR #6

### O núcleo, reproduzido pelo coordenador

```
caminhos = 144   escalares distintos = 136
escalares que batem isoladamente com algum alvo: []
```

Confere com o relato e confirma, por caminho independente, a reexecução de `ef55ccf`.

### O que a continuação acrescenta (verificado pelo coordenador)

Fecha o limite que eu havia **declarado e não coberto** — "não testa abertura AES das saídas". Antes da
redução, cada lista virou dígitos ASCII, bytes dos dígitos, inteiro decimal em bytes e símbolos `a..i`
com `o=0`; mais as duas reduções de 32 B e suas formas hexadecimais. Cada material entrou como senha
literal, SHA256 hex e SHA256 em bytes, com deduplicação por bytes.

| Medida | Valor |
|---|---|
| Materiais intermediários distintos | 544 |
| Senhas distintas | 1.496 |
| Decifrações AES reais (SMALL, TAIL32, COSMIC) | 8.976 |
| Padding PKCS7 válido | 35 (esperado 35,2) |
| **Sinalizados pela triagem** | **0** |

| Varredura binária, sem filtro de padding ou de texto | Verificações BE/LE | Acertos |
|---|---|---|
| Todas as saídas AES, inclusive com padding inválido (4.452.096 B preservados) | 8.347.680 | **0** |
| Intermediários e senhas em representações diretas | 61.086 | **0** |

Refiz **a varredura inteira** com parser e scanner próprios (formato `[uint32 length][bytes]`, 8.976
registros, 4.452.096 B, comprimentos conferidos contra o índice): **8.347.680 janelas válidas BE/LE, 0
acertos**, em 32 s. Meu controle plantou duas chaves reais em offsets não nulos e recuperou ambas — BE
no offset 17 e LE no offset 9, os mesmos do controle da entrega — sem hit antes do plantio.

São contagens de **verificações**, não de chaves únicas; os dois endereços e as duas serializações
públicas não foram usados para inflar os totais. Execução em 18 lotes síncronos, todos concluídos e
reconciliados (hashes, nº de registros, nº de janelas e concatenação conferem com o bruto). Uma tentativa
agrupada atingiu o limite de execução: o lote incompleto foi refeito integralmente e a tentativa
interrompida não foi somada.

**Ressalva importante sobre senhas binárias:** foram passadas com comprimento explícito e **não**
truncadas no primeiro NUL. Esses casos representam a **API de derivação de chave**, não necessariamente
uma senha escrevível como argumento literal de shell.

O modelo criptográfico foi AES-256-CBC com EVP_BytesToKey, uma iteração, digest SHA256 ou MD5 — isso
especifica os testes, **não** demonstra qual é o modo ou KDF dos envelopes ainda fechados. A triagem
textual (bytes diretos, cp273 nos dois sentidos, UTF-16 em duas ordens e alinhamentos, marca de blob
aninhado, formatos textuais de chave) serve só para identificar candidatos; a ausência de marca não prova
ausência de outra codificação — por isso a varredura raw32 não dependeu dela.

## 3. Controles da entrega (não reproduzidos aqui)

- Fase 2 abre com `sha256hex("causality")`: 648 bytes iguais aos do OpenSSL.
- **Todas** as 8.976 decifrações reconferidas pelo `EVP_BytesToKey` e pelo decifrador EVP nativos de
  libcrypto — chaves, IVs e todos os bytes coincidentes, inclusive com senha binária contendo NUL ou
  bytes acima de 127.
- Scanner com tabela de multiplicação de base fixa: 128 escalares de controle por execução comparados
  com `EC_POINT_mul`, 5 pontos contra implementação Python independente, e duas chaves plantadas em
  offsets não nulos (uma BE, outra LE; comprimida e não comprimida) localizadas corretamente.
- **Bug corrigido no próprio controle, declarado:** a primeira expectativa de offset usava um número
  fixo incorreto, substituído pelo comprimento real do prefixo (17 bytes) antes de aceitar o controle.
- Calibração de padding: 100 réplicas de permutações que preservam frequência de bytes, 32 materiais por
  réplica, 57.600 decifrações de controle → 227 paddings contra 225,88 esperados. Não é teste de solução
  nem prova de aleatoriedade dos dados.

## 4. O que fica e o que não fica

**Fica:** a leitura literal das 28 somas está fechada no modelo detalhado, com limites algébricos vindos
dos dados. E a suspeita de acerto isolado não registrado na PR #6 foi testada para os valores
reproduzidos — não havia acerto; os intermediários também foram examinados como senha e como material
binário.

**Não fica:** nada decide entre L83 e L84; não prova que `matrixsumlist` seja irrelevante, que não exista
mensagem nos campos, nem que seja necessária informação pessoal externa.

**Limitação de escopo declarada:** a sobreposição com todas as campanhas históricas **não foi medida** —
os corpora completos não estavam disponíveis nessa entrega. Não se reivindica que cada senha testada
seja inédita no histórico.

**O que o coordenador não reproduziu:** a reconferência por EVP nativo de libcrypto (usei pycryptodome,
que também é implementação distinta da deles); a calibração de 100 réplicas (227 paddings contra 225,88);
os controles internos do scanner da entrega (128 escalares contra `EC_POINT_mul`, 5 pontos contra Python);
e o método inverso do `sum28` por sistemas lineares — cobri o mesmo espaço pelo método direto.

O pacote (9,9 MB, 92 arquivos) fica local, fora do git; aqui ficam o relatório, a especificação, os
sumários e a verificação.

## 3. O princípio aplicado aos demais rótulos (negativo, com teto algébrico mais forte)

A hipótese das 28 somas vale como *método*, não só como teste: inverter a função do rótulo. Aplicado
aos outros rótulos da página, o teto algébrico fica ainda mais afiado — e vem de uma propriedade do
próprio resíduo, não de uma escolha de orçamento:

> O resíduo usa só `a..i` e **nunca `o`**. Na convenção da página (`a=1…i=9`, `o=0`), a string de
> dígitos do resíduo **não contém nenhum zero**.

Em a1z26 concatenado, as únicas letras que produzem dígito 0 são **`j` (10)** e **`t` (20)**. Logo, se o
resíduo é a codificação a1z26 de um texto, esse texto **não pode conter `j` nem `t`** — e `t` é a
segunda letra mais frequente do inglês. O filtro decide antes de rodar qualquer coisa.

**Os rótulos literais morrem de imediato** ([`rotulo_nomeia_objeto.json`](rotulo_nomeia_objeto.json)):

| rótulo | dígitos a1z26 | gera zero? | proibidas |
|---|---|---|---|
| `lastwordsbeforearchichoice` | 37 | **sim** | `t` |
| `thispassword` | 20 | **sim** | `t` |
| `matrixsumlist` | 23 | **sim** | `t` |
| `causality` | 14 | **sim** | `t` |
| `thematrixhasyou` | 24 | **sim** | `t` |
| `enter` | 8 | **sim** | `t` |
| `yellowblueprimes` | 27 | não | — |
| `yinyang` | 11 | não | — |

Os dois que sobrevivem ao filtro morrem pelo comprimento (27 e 11 dígitos, contra 60/61).

**E o objeto que o rótulo nomeia?** `lastwordsbeforearchichoice` aponta para as últimas palavras antes
de "choice". Tomei todas as janelas de 1 a 40 palavras terminando imediatamente antes de cada uma das 5
ocorrências de "choice" no `MISC.txt` (sha256 `223d7f76…`, a mesma fonte da frente `lista_mais_fala`):

| | |
|---|---|
| Janelas | 200 |
| Sobrevivem ao filtro `j`/`t` | **13** (6,5 %) |
| Dessas, com comprimento 60 ou 61 | **0** |
| Reconstruções do resíduo | **0** |

As 13 sobreviventes são fragmentos curtos e sem `t` como `neo`, `youneo`, `killyouneo` — nenhuma chega
perto do comprimento necessário. **93,5 % do espaço morre por uma propriedade estrutural do resíduo**,
e o restante morre por contagem de dígitos.

**Controle:** um texto sem `j`/`t` codifica sem zero (`acegik` → `1357911`); um com `t` gera zero
(`cat`); e o resíduo de fato não tem `o` nem zero em nenhum dos quatro alvos.

**Alcance:** fecha "o resíduo é a codificação **a1z26** de um texto em inglês" — praticamente toda a
família, porque quase todo texto em inglês contém `t`. Não fecha outras codificações (ASCII decimal,
o método `To_Base(16)` da página, bases não decimais), nem textos em outras línguas, nem objetos que
não sejam texto.

## 4. ASCII decimal: fechada por impossibilidade estrutural

Na seção 3 declarei a codificação **ASCII decimal** (cada caractere vira seu código de 2 ou 3 dígitos)
como não fechada. Fechei ([`residuo_ascii_decimal.json`](residuo_ascii_decimal.json)), e o resultado é
mais forte que o esperado: **não existe nenhuma segmentação válida**.

**Primeiro, o argumento do zero refeito para esta codificação.** O resíduo não tem `o`, logo nenhum
código pode conter o dígito 0. Nas minúsculas isso proíbe `defghijklmnx` — 12 letras, entre elas **`e`**,
a mais frequente do inglês. Restam 77 dos 95 códigos imprimíveis.

**Depois, a impossibilidade estrutural**, que dispensa qualquer varredura:

| dígito inicial | códigos de 2 dígitos | de 3 dígitos | pode iniciar? |
|---|---|---|---|
| `1` | 0 | 15 (111–119, 121–126) | sim |
| **`2`** | **0** (21–29 < 32; 20 tem zero) | **0** (2xx > 126) | **nunca** |
| `3`–`9` | 8 ou 9 | 0 | sim |

O dígito **`2`** não pode iniciar código algum. E o resíduo **contém `2`** — a letra `b` — nas posições
19 e 36. Todo `2` teria de ser consumido como dígito não-inicial, e a aritmética dos comprimentos (só
blocos de 2 ou 3) não permite acomodá-los.

Enumeração exaustiva do DAG de segmentação nos quatro alvos:

| alvo | dígitos | caminhos |
|---|---|---|
| L84 | 61 | **0** |
| L84 invertido | 61 | **0** |
| L83 | 60 | **0** |
| L83 invertido | 60 | **0** |

Não é "nenhum caminho é legível" — é **não existe caminho**. **Controle:** um texto cujos códigos não
contêm zero (`rasp copa`) é recuperado pelo mesmo grafo, com fração 1.

**Alcance.** Fecha por completo a leitura ASCII-decimal do resíduo, nos dois campos e nos dois sentidos.
Junto com a seção 3 (a1z26) e com o método `To_Base(16)` da página — já fechado no PR #7, e exaustivo
porque é bijetivo e há só quatro alvos —, as três codificações decimais naturais do resíduo estão
encerradas. Continuam fora: bases não decimais, bijeção arbitrária dígito↔símbolo e objetos que não
sejam texto.
