# XOR repetido após a conversão decimal

15/09/2026, America/Sao_Paulo. **Não foi recuperada a senha final.**
A rodada excluiu uma camada XOR de período curto sobre FAED no modelo
declarado abaixo. DBBI exigiu uma verificação adicional; seus dois candidatos
de sete bits com as chaves fixadas não são texto imprimível e não abrem AES.

## Hipótese e condição exata

Hipótese: transformar DBBI/FAED em um inteiro decimal com `a=1..i=9`, permitindo
que um símbolo também signifique zero em cada ocorrência; converter o inteiro
para bytes mínimos big-endian; aplicar XOR com uma chave repetida para obter
texto. O uso de XOR é uma hipótese de cifra clássica, não uma instrução
confirmada pelo criador. O [desafio Cryptopals 6](https://cryptopals.com/sets/1/challenges/6)
documenta o mecanismo de XOR com chave repetida.

Se `P[i] = C[i] XOR K[i mod p]` e todos os bytes de `P` são menores que 128,
então o bit mais alto de `C[i]` é igual ao de `K[i mod p]`. Portanto:

```text
MSB(C[i]) = MSB(C[i+p])
```

A condição abrange **qualquer conteúdo da chave**, incluindo bytes não ASCII.
Não é necessário adivinhar palavras nem enumerar todas as chaves. Passar na
condição permite construir alguma saída de sete bits, mas não identifica
texto, chave ou intenção do autor.

O buscador escolhe os zeros por prefixos. Cada prefixo define um intervalo
decimal contendo todas as continuações. Calcula-se o menor inteiro a partir
do limite inferior que tem o padrão periódico de bits altos. Se ele ultrapassa
o limite superior, o ramo inteiro é impossível. O comprimento em bytes é o
mínimo de cada inteiro, sem remover bytes nem inventar preenchimento.

## 1. Todas as chaves com períodos de 1 a 32 bytes

O limite de 32 bytes foi declarado para cobrir, entre outros tamanhos, uma
lista de 14 bytes e um digest SHA256 cru. Não é um limite fornecido pelo puzzle.
Foram examinados os campos completos, na ordem original e com todos os seus
símbolos invertidos.

| Campo | Símbolo que pode ser zero | Casos | Resultado |
|---|---|---:|---|
| FAED | Qualquer um de `a..i`, isoladamente | 576 | Todos excluídos |
| DBBI | `g` | 62 para períodos 1–31 | Todos excluídos |
| DBBI | `g` | 2 para período 32 | 32 máscaras diretas e 16 invertidas compatíveis |

**Os 640 casos terminaram.** Foram 2.361.112 nós e 1.180.828 certificados.
Não se afirma que tenham sido executadas fisicamente todas as chaves XOR
possíveis: a exclusão decorre da condição necessária sobre os bits altos.

Consequência restrita: **FAED, nessa representação, não produz ASCII por XOR
com nenhuma chave repetida de até 32 bytes**, qualquer que seja o símbolo
único zerável. Em particular, não serve um digest SHA256 cru repetido.
Como o caso de período 1 também é impossível, uma sequência XOR inteiramente
ASCII, mesmo com bytes diferentes e sem repetição, não resolve FAED: seus
bits altos seriam todos zero e não alterariam os bits altos do ciphertext.

O verificador não importa o algoritmo de busca. Ele conta diretamente quantos
inteiros até `N` têm bits altos periódicos, tratando separadamente cada
comprimento mínimo em bytes. Confirmou todos os intervalos, a cobertura sem
sobreposição e todos os candidatos. Para DBBI, também enumerou diretamente
as 1.024 máscaras nos 64 casos: 65.536 verificações concordantes.

Controles: o buscador conferiu 262.144 sucessores por enumeração simples,
32 conjuntos pequenos por força bruta e recuperou três ciphertexts plantados.
O verificador passou 262.144 contagens pequenas, 400 intervalos enumerados
e 1.500 verificações de comprimentos maiores.

Arquivos: [especificação](spec.json), [resumo](summary.json),
[verificação](verification.json), [48 máscaras compatíveis](witnesses.json).
Os certificados estão nos 20 arquivos `dbbi-*.json` e `faed-*.json` desta pasta.

## 2. O que sobrevive em DBBI não é uma mensagem

Para cada um dos 48 ciphertexts compatíveis, foram calculados os conjuntos
de bytes de chave que poderiam produzir alfabetos específicos, coluna por
coluna do período 32.

| Alfabeto permitido no plaintext | Ciphertexts compatíveis |
|---|---:|
| Somente `a..z` | 0 |
| `a..z`, dígitos, espaço, TAB/LF/CR | 0 |
| Letras maiúsculas/minúsculas, dígitos e esses espaços | 48 |
| ASCII imprimível e TAB/LF/CR | 48 |

Logo, uma saída com somente minúsculas e dígitos, como os rótulos vizinhos
da página, também é impossível nesse modelo. A compatibilidade com um
alfabeto mais amplo continua sem fornecer a chave ou uma frase.

Foram reutilizadas **14.042 pré-imagens distintas derivadas das matrizes e
suas concatenações já registradas**, aplicando SHA256 e usando seus 32 bytes
crus como chave XOR. Fontes: os candidatos da rodada `prime_geometry`, as
senhas de `carry_color` e serializações das 43 listas preservadas. Não se
criou um vocabulário novo de senhas. **674.016 pares chave/ciphertext** não
produziram saída completa de sete bits.

Uma conferência independente reconstruiu todas as chaves a partir das fontes,
calculou cada corpo XOR diretamente, sem o filtro de bits altos, e refez os
192 testes de alfabeto por interseção de conjuntos.
Ver [resultados](dbbi_followup.json) e [conferência](dbbi_followup_verification.json).

## 3. DBBI com qualquer símbolo zerável e as mesmas chaves

O teste anterior restringia DBBI a `g=0/7`. Foi então ampliado para **qualquer
um dos nove símbolos**, isoladamente, com as mesmas 14.042 chaves SHA256, em
ambas as direções. O programa usa os bits altos agora fixados pela chave para
cobrir todas as escolhas de zero.

**252.756 casos completos, 588.584 nós, 420.668 certificados, nenhum caso
parcial.** Surgiram somente dois plaintexts de sete bits, ambos com `b=0/2`,
na ordem original e com a mesma chave. Nenhum é totalmente imprimível.
Os resultados diferem apenas no final e contêm vários controles ASCII.

A pré-imagem da chave é `OCSILOTAKOUTEZ`, proveniente de uma extração antiga
pelas últimas palavras de linhas editoriais do README. A fragilidade dessa
formatação já foi documentada anteriormente; reutilizar a entrada para este
teste não autentica sua origem como instrução do puzzle. Os dois corpos XOR
não são evidência de uma mensagem intencional.

Os corpos foram testados diretamente e como SHA256 hexadecimal: **quatro
senhas, 24 tentativas AES nos três blobs e nos dois KDFs, zero padding válido**.
Um verificador separado reconstruiu todos os intervalos, os dois candidatos
e as decisões AES, desativando o padding automático e verificando PKCS#7
manualmente. Hashes e janelas de 32 bytes dos plaintexts forneceram dez
escalares distintos válidos; nenhum corresponde à coordenada x da chave
pública do prêmio, incluindo sua negação.

Controles: 327.680 sucessores, nove ciphertexts plantados, 327.680 contagens
independentes, 1.500 comprimentos maiores e a fase 3.2 conhecida como controle
positivo de AES. O caso `g` desta ampliação se sobrepõe à conferência anterior;
suas contagens não devem ser somadas como buscas disjuntas.

Arquivos: [especificação](known_keys/spec.json),
[resumo](known_keys/summary.json), [certificados](known_keys/cases.jsonl),
[candidatos completos](known_keys/candidates.json),
[AES](known_keys/aes.json), [verificação independente](known_keys/verification.json).

## Reprodução e limites

```powershell
node solver/xor_period_constraints.cjs run
node solver/verify_xor_period.cjs
node solver/xor_dbbi_followup.cjs
node solver/verify_xor_dbbi_followup.cjs
node solver/xor_knownkey_constraints.cjs
node solver/verify_xor_knownkeys.cjs
```

Não houve abertura de SMALL, TAIL32 ou COSMIC nem recuperação de chave privada.
A conclusão não cobre múltiplos símbolos simultaneamente zeráveis, outros
alfabetos numéricos, outras bases, transposição adicional, dados binários ou
chaves XOR gerais com período maior que 32. Para DBBI com símbolo diferente
de `g`, foram testadas as 14.042 chaves declaradas; não todas as chaves possíveis.
As chaves fixas começam no primeiro byte; não se alegam todos os deslocamentos
ou a leitura dos bytes em ordem inversa.

Essa rodada fecha o uso das listas e dos seus hashes como as chaves XOR
descritas. Não justifica ampliar o dicionário de palavras nem tratar uma
saída de sete bits ou um alfabeto compatível como solução.
