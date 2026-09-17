# Telegram de 17/09: marcadores primos, matriz anotada e diferenças do coelho

**Nenhuma senha final ou chave do prêmio foi encontrada.** Esta rodada usou
o export novo fornecido pelo usuário e examinou objetos que não estavam
implementados nas campanhas locais consultadas. Não retomou a permutação
das 16! chaves, a montagem de blocos AES ou os dicionários históricos.

Foram feitas **207.444 decisões AES**, todas reproduzidas em PyCryptodome.
As 820 saídas com padding foram preservadas e não forneceram texto coerente,
contêiner OpenSSL reconhecido ou chave do prêmio nas verificações declaradas.
Separadamente, 6.402 modelos de chave decimal sobre FAED foram excluídos
integralmente no repertório de sete bits. Nenhum processo ficou em execução.

## Fontes novas e atribuição

O diretório fornecido resolve para
`C:\Users\ruthe\Downloads\Telegram Desktop\ChatExport_2026-09-17`.
Seu `result.json` contém **1.209 mensagens**, de 04/09/2026 00:07:20 a
17/09/2026 13:40:30, nos horários do export. Não há mensagem do identificador
do criador `user9815232` nesse intervalo. São discussões da comunidade,
não novas instruções confirmadas pelo criador.

| Fonte | Uso nesta rodada |
| --- | --- |
| #71971, Doober, 15/09/2026 06:55:34, `GSMG IO ATLAS.pdf` | Segmentações de DBBI e seleções dos eventos coloridos, especialmente páginas 13 e 36–39. |
| #71413, 10/09/2026 11:02:31 | Observação `91 + 104 = 195`, um a menos que 14². |
| #72118, Boulayo, 17/09/2026 05:16:19 | Foto da referência do coelho, com identificação do catálogo. |
| #71525, Varholy Viktor, 11/09/2026 14:53:58 | Alegação “wife up”: recorte por somas mostrado em fotografia, sem abertura AES; não adotada como texto autenticado. |

Hashes SHA256 dos insumos locais:

```text
export: 5196406dafe46a6c37804bd40b894e040ede8f257e07d12497d183c864d40030
atlas:  b21dffa6be14661c0060e9a3d36fe6befd6e1ed9e48e1e971a5342dc9a8c9c14
foto:   5483649c1a9fd5a67f85d6ff963c38077aa7e2225c56f3dd16f6dd8ba0228b87
```

O PDF foi extraído por página e as páginas 37–38 foram renderizadas e
inspecionadas. Conversas, PDF, fotos e extração integral permanecem locais;
não foram copiados para arquivos destinados ao Git. O anexo `PROGRESS.md`
de X repete o modelo de 64 tokens/16 tipos já examinado em 08/09.

## 1. Segmentação por marcadores nas posições primas

Regra do atlas, reproduzida sem usar seus scripts privados:

1. Numerar as posições **lógicas** a partir de 1.
2. Em posição prima, consumir `b` ou `be` do texto físico.
3. Nas demais posições, consumir um único símbolo.
4. Exigir que os 91 símbolos de DBBI sejam consumidos integralmente.

Há exatamente duas segmentações. Uma busca recursiva e uma contagem por
programação dinâmica concordam; ambas recuperam nove controles sintéticos.

| Posições lógicas | `b` nos primos | `be` nos primos | Símbolos fora dos primos |
| --- | --- | --- | --- |
| 83 | 15 | 8 | 60 |
| 84 | 16 | 7 | 61 |

As segmentações diferem somente na interpretação do último `e`: sufixo do
marcador da posição 83 ou símbolo independente na posição 84. Os resíduos são:

```text
83: difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeea
84: difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae
```

Em 20.000 embaralhamentos com as mesmas contagens de letras, nenhum admitiu
uma segmentação completa nessa **regra fixa**. Isso merece investigação,
mas não corrige a seleção histórica de hipóteses nem autentica uma senha.
A regra e o encaixe 16/7 foram trazidos pelo atlas; não são descobertas
originais desta rodada.

### Ressalva sobre a suposta seleção única da figura

Incluindo FEFEFE como um evento azul, há cinco correspondências entre
os 23 marcadores e seleções ordenadas de 23 dos 25 eventos da figura.
Sem FEFEFE, nenhuma seleção de 23 dos 24 marcadores corresponde.
Os números omitidos abaixo são os ordinais **1-based** dos 25 eventos.

| Segmentação | Eventos omitidos | Bytes distintos representados |
| --- | --- | --- |
| 83 | 22, 24 | **23: bytes 1–22 e 24** |
| 83 | 23, 24 | 22 |
| 83 | 24, 25 | 22 |
| 84 | 22, 25 | **23: bytes 1–23** |
| 84 | 23, 25 | 22 |

Portanto, **“um representante por byte” não escolhe sozinho a segmentação
84**. É necessário exigir adicionalmente os primeiros 23 bytes, descartando
o 24º. O atlas registra o primeiro conjunto de omissões na tabela, mas não
lhe atribui os 23 bytes distintos ao argumentar pela unicidade. A exigência
extra continua hipotética. Ambas as alternativas entraram nos testes.

### Consequências testadas

As seis vistas declaradas foram o resíduo, os símbolos lógicos, zeragem dos
primos lógicos, zeragem dos não primos lógicos, zeragem dos marcadores
físicos e zeragem dos sufixos `e`. Em ambas as direções, a conversão decimal
integral com todas as escolhas `g→0/7` deu **24 modelos completos sem saída
de sete bits**. Uma enumeração independente conferiu 20.484 atribuições.

Também foram geradas somas dos retângulos fatoráveis das novas sequências,
listas das posições dos marcadores, coordenadas das cinco seleções e somas
da reinserção dos primos na figura. As formas exatas estão em
[spec.json](run1/spec.json) e no código.

## 2. Manter o rótulo binário dentro da matriz

Em vez de remover os 104 símbolos que dizem `matrixsumlist`, esta hipótese
usa os **195 símbolos completos**: DBBI seguido do rótulo binário.
Acrescenta um zero no início ou no final e preenche a matriz 14×14 por
linhas, colunas ou pela espiral conhecida. São seis preenchimentos.

Foram examinadas seleções pelas células 0/1/azuis/amarelas/coloridas da
figura original e listas de somas. Essa inclusão do rótulo como dado é uma
hipótese exploratória motivada pela #71413, não uma instrução comprovada.
Não houve troca ou reordenação dos blocos do ciphertext AES.

As famílias 1–2 produziram 17.003 materiais, 34.006 casos de senha e
204.036 decisões AES: três blobs originais, EVP-SHA256 e EVP-MD5, senha
direta ou SHA256 hexadecimal. Os 808 paddings têm no máximo 56,96% de
bytes imprimíveis; nenhum recebeu interpretação de solução.

PyCryptodome reproduziu **todas** as decisões e os corpos completos.
Com coincurve, 786.312 escalares distintos foram comparados com o ponto
público do prêmio e sua negação, sem correspondência. O escopo inclui
hashes das senhas e saídas, materiais de 32 bytes/hex64 e todas as janelas
de 32 bytes das saídas com padding, nas duas ordens.
[Resumo](run1/summary.json) · [Conferência](run1/independent_verification.json).

### As novas listas como chaves para FAED

539 listas deram 1.067 chaves distintas: concatenação decimal ou restos
módulo 10. Nenhuma coincidiu com as chaves do gerador histórico
`baseLists()/keysFromLists()`; isso não é uma auditoria de todos os corpus.

As duas ordens de FAED e as três operações `C−K`, `C+K`, `K−C` módulo 10
deram **6.402 modelos completos**, com todas as escolhas `g→0/7`.
Nenhum permite bytes exclusivamente de sete bits após conversão do
inteiro decimal. Uma implementação aritmética independente conferiu os
10.088 certificados e a cobertura integral de cada espaço de máscaras.
Não surgiram candidatos para AES.
[Resumo](faed_keys/summary.json) · [Conferência](faed_keys/independent_verification.json).

## 3. Diferenças entre o coelho e a referência

O catálogo identifica a imagem 541878964 como obra de **paramouse**,
publicada em 23/12/2016. Isso confirma a identificação do anexo, mas não
prova que esse arquivo exato tenha sido usado pelo autor do puzzle.
[Página do catálogo](https://www.shutterstock.com/image-vector/pixelated-bunny-8-bit-pixel-art-541878964).

Foi alinhada uma grade de 13×14 subcélulas, com origem `(30,32)` e passo
15 pixels na cópia arquivada do puzzle. Na foto, a caixa medida é
`x=64, y=69, largura=132, altura=122`. A leitura preta/branca da referência
permaneceu igual em 27 combinações de limiar e deslocamento de amostragem.

Das 182 subcélulas, **144 têm fundo branco conhecido** na matriz original;
38 ficam encobertas por células pretas e foram consideradas desconhecidas.
Há **sete diferenças visíveis**, com coordenadas locais zero-based:

```text
linha,coluna: referência → puzzle
6,12: 0 → 1    6,13: 0 → 1    7,12: 1 → 0
8,12: 0 → 1    9, 8: 0 → 1    9, 9: 0 → 1    9,12: 1 → 0
```

Logo, a diferença mencionada na cauda existe na comparação declarada,
e há diferenças na parte inferior visível. Isso não demonstra uma
codificação intencional. O JPEG não permite verificar se os valores RGB
exatos de FEFEFE vieram da fonte; essa questão continua aberta.

O XOR e a diferença com sinal, suas somas, coordenadas e leituras binárias
produziram 284 materiais, 568 casos de senha e **3.408 decisões AES**,
com 12 paddings e nenhum texto/contêiner identificado. PyCryptodome
reproduziu todas as decisões; 9.226 escalares distintos também não
corresponderam ao ponto público ou à sua negação.
[Resumo](rabbit_delta/summary.json) · [Conferência](rabbit_delta/independent_verification.json).

## Reprodução e limite da conclusão

Os três scripts usam apenas módulos nativos de Node e as entradas públicas
já versionadas. As coordenadas medidas do coelho estão explícitas no
terceiro script; repetir a **medição visual** exige os arquivos locais
identificados pelos hashes. Escolha destinos novos:

```powershell
node solver/prime_host_delta.cjs _work/prime_host_repro/run1
node solver/prime_host_faed_keys.cjs _work/prime_host_repro/run1 _work/prime_host_repro/faed_keys
node solver/rabbit_reference_delta.cjs _work/prime_host_repro/rabbit_delta
```

Controles recuperaram a fase 3.2 conhecida, nove segmentações sintéticas e
seis textos plantados nos modelos de chave decimal. As conferências
independentes desta sessão usaram Python/PyCryptodome/coincurve por comandos
inline; seus resultados e hashes estão preservados, mas não há novo
programa Python de verificação versionado nesta rodada.

**A operação que transforma os marcadores primos em uma senha permanece
desconhecida.** Os negativos cobrem as representações e transformações
explicitadas, não todas as funções dos resíduos, do coelho ou de
`matrixsumlist`. Não demonstram impossibilidade, falta de informação
externa ou resolução de SMALL, TAIL32 ou COSMIC.
