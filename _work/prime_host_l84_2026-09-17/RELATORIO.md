# L84 escolhido: teste das consequências de 16/7

17/09/2026. A pedido do usuário, a leitura de **84 posições lógicas** foi
adotada como premissa para executar os próximos passos. **Os testes não
produziram senha validada nem chave do prêmio.**

## Escolha fixada

DBBI é segmentado em 84 tokens, com `b` ou `be` nas 23 posições primas.
Há 16 `b`, sete `be` e 61 símbolos fora dessas posições. Na figura,
FEFEFE conta como azul; omitem-se os eventos 22 e 25, conservando um
representante de cada byte 1–23. É a seleção A do atlas da comunidade.

Não foi necessário resolver a ambiguidade com L83 para executar esta
rodada: L84/A foi fixado explicitamente. A justificativa dessa escolha
continua sendo uma hipótese. A análise anterior está no
[relatório do export novo](../prime_host_delta_2026-09-17/RELATORIO.md).

As sete posições amarelas são:

| Unidade contada, origem 1 | Posições |
| --- | --- |
| Entre os 23 marcadores | 5, 9, 10, 15, 18, 19, 22 |
| Entre os 84 tokens lógicos | 11, 23, 29, 47, 61, 67, 79 |

Essas duas listas têm funções distintas nos testes abaixo.

## Testes executados

**1. Entrelaçamento da frase conhecida.** Os ordinais entre os 23
marcadores selecionam estas palavras da mensagem já decifrada da fase 3.2:

```text
TO PRIVATE KEYS BETTER THEY ALSO TO
```

O atlas informa que concatenações permutadas já foram tentadas. Aqui a
operação foi outra: emitir uma letra de cada palavra, sucessivamente,
saltando palavras esgotadas. Foram cobertas todas as 5.040 ordens dos
sete lugares, com todas as palavras normais ou todas invertidas, em
minúsculas e maiúsculas. As duas ocorrências de `TO` e outras coincidências
reduzem isso a **10.080 materiais distintos**.

**2. Os sete D e os trechos vizinhos em FAED.** A construção comunitária
usa o quadrado `dbifhcegaklmnopqrstuvwxyz` e Bifid com período completo.
Nos 285 pares da saída, 83 segundas letras pertencem a `a–g`.
As posições lógicas amarelas selecionam sete dessas âncoras, todas `d`,
nos pares **39, 91, 113, 164, 207, 224 e 269**.

A seleção foi reproduzida e a transformação inteira foi recodificada
para os 570 símbolos originais. Isso confere a implementação; não prova
que o autor tenha usado esse quadrado ou Bifid.

As 83 âncoras delimitam 84 intervalos. Testaram-se os intervalos antes e
depois dos sete D, nas representações de pares de entrada, pares de saída
e segundas letras de saída. Concatenar ou entrelaçar os sete intervalos,
nas 5.040 ordens e duas orientações globais, em duas caixas, produziu
**3.360 materiais novos distintos**. Intervalos vazios foram preservados.
Serializações dos pares selecionados, posições e valores das letras
acrescentaram **99 materiais**.

**3. A grade 7×12 de L84.** Duas vistas foram usadas: primeiro caractere
de cada token; ou zero nos 23 lugares primos e o símbolo original nos
demais lugares. Em cada vista, testaram-se sete linhas contíguas
entrelaçadas e sete colunas intercaladas concatenadas, com todas as
permutações e duas orientações globais.

Cada resultado foi interpretado com `a=1 … i=9`, permitindo cada `g`
independentemente como 0 ou 7, seguido da conversão do inteiro decimal
para bytes big-endian mínimos. **Todos os 40.320 modelos foram concluídos;
nenhum admite uma saída inteiramente de sete bits.** A conferência
independente reconstruiu cada modelo e verificou a exclusão de todas as
máscaras por intervalos aritméticos, em 123.556 nós.

## Verificação dos resultados

Os **13.539 materiais** não coincidem com os materiais da rodada
imediatamente anterior. Esse controle de duplicação não representa uma
auditoria de todos os testes históricos da comunidade.

Cada material foi testado diretamente e como SHA256 hexadecimal
minúsculo: **27.078 casos de senha, 162.468 decisões AES**, nos três
blocos originais e com EVP-SHA256/EVP-MD5. Houve 609 saídas com padding,
nenhuma com texto reconhecível ou cabeçalho de contêiner aninhado. A maior
fração de caracteres imprimíveis foi 0,519; padding não foi considerado
uma solução.

PyCryptodome reproduziu todas as decisões e os corpos completos. Com
coincurve, **640.486 escalares distintos** foram comparados ao ponto
público do prêmio e à sua negação, sem correspondência. O escopo inclui
SHA256 e SHA256 duplo dos materiais, senhas e saídas com padding;
materiais de 32 bytes/hex64; e todas as janelas de 32 bytes das saídas
com padding, nas duas ordens dos bytes.

Controles: recuperação da fase 3.2 conhecida; 5.040 permutações únicas;
inversão do entrelaçamento de comprimentos diferentes; recuperação de
um texto plantado na conversão decimal de 84 dígitos; e recodificação
integral do Bifid condicional.

[Especificação](run1/spec.json) · [Resumo](run1/summary.json) ·
[Controles](run1/controls.json) · [Conferência independente](run1/independent_verification.json).

## Reprodução e limite

O script usa Node e as entradas públicas do repositório. A comparação
de duplicação também requer `materials.json` da rodada anterior, gerado
por `solver/prime_host_delta.cjs`. Use um destino novo:

```powershell
node solver/prime_host_l84_followthrough.cjs _work/prime_host_l84_repro/run1
```

As verificações independentes desta rodada foram executadas por Python
inline; o relatório e os hashes ficaram preservados, mas não foi criado
um programa Python versionado. Os arquivos volumosos de materiais,
modelos e saídas permanecem locais.

**Adotar L84/A permitiu testar o ramo, mas não o tornou uma solução.**
Os negativos cobrem apenas as seleções, entrelaçamentos, conversões e
derivações de senha descritos aqui. Não descartam outras operações sobre
os 84 tokens nem demonstram que o puzzle seja insolúvel.
