# Listas como sementes e como ordem de colunas

15/09/2026, America/Sao_Paulo. **A senha final continua desconhecida.**
Nenhum dos três blobs originais foi aberto nesta rodada. Foram concluídos
168.456 modelos condicionais de transformação de DBBI/FAED, sem candidatos
que tenham todos os bytes abaixo de 128. Não houve novas tentativas AES,
porque os modelos não produziram materiais candidatos.

## Hipótese e diferença em relação ao histórico

`matrixsumlist` está decodificado, mas seu papel operacional não está.
As listas poderiam ser sementes de uma chave que cresce ou ordenar colunas.
Essas são hipóteses de investigação, não instruções confirmadas pelo criador.

O histórico inclui adição em cadeia com poucas sementes e testes estatísticos
de transposição/checkerboard. Esta rodada combina as transformações declaradas
com **todas as escolhas independentes de zero**, exigindo a leitura do resultado
decimal inteiro como bytes. Não reapresenta testes antigos como inéditos.

As entradas são as de `../prime_geometry_2026-09-11/inputs.json`. Os hashes
do arquivo de entrada e dos programas estão nas especificações. A matriz usada
tem 101 uns. Mantêm-se `a=1..i=9` para os valores não zerados; não há troca
de alfabeto, remoção de cabeçalho, descarte de bytes ou dados compactados.

## 1. Adição em cadeia e realimentação

Foram reutilizadas 43 listas explícitas da rodada anterior: somas, posições,
valores binários e hipóteses de pesos de cores/primos. Cada lista fornece
duas representações, resíduos módulo 10 ou concatenação dos dígitos decimais,
em ambas as direções. Depois de deduplicar, são **156 sementes**.

Acrescentaram-se **2.048 sementes** de DBBI: todas as 1.024 máscaras `g=0/7`,
cada uma direta e invertida. Essas sementes aplicam-se somente a FAED, evitando
tratar DBBI simultaneamente como texto e chave com máscaras inconsistentes.
Não há rotações arbitrárias das sementes.

Para semente de comprimento `L`, foram declarados quatro mecanismos:

1. Adição em cadeia, `K[i]=(K[i-L]+K[i-L+1]) mod 10`, incluindo a semente no início.
2. A mesma sequência, iniciando depois dos `L` dígitos da semente.
3. Realimentação pelo plaintext: após a semente, `K[i]=P[i-L]`.
4. Realimentação pelo ciphertext: após a semente, `K[i]=C[i-L]`.

Cada mecanismo usa as três operações `P=C-K`, `P=C+K` ou `P=K-C`, dígito a
dígito módulo 10. DBBI e FAED são examinados completos, diretos e invertidos.
Cada `g` do campo cifrado pode, independentemente, valer 0 ou 7.
O resultado é interpretado como um único inteiro decimal, incluindo zeros
iniciais, e convertido para bytes mínimos big-endian, todos menores que 128.

| Mecanismo | Casos completos | Nós | Candidatos |
|---|---:|---:|---:|
| Cadeia com semente | 14.160 | 23.806 | 0 |
| Cadeia após semente | 14.160 | 29.260 | 0 |
| Realimentação pelo plaintext | 14.160 | 26.104 | 0 |
| Realimentação pelo ciphertext | 14.160 | 26.008 | 0 |
| Total | **56.640** | **105.178** | **0** |

O exemplo numérico da [ACA para Gromark](https://www.cryptogram.org/downloads/aca.info/ciphers/Gromark.pdf)
é reproduzido como controle da adição. **Não se afirma que esta experiência
implemente Gromark completo ou VIC completo**: a aplicação a sementes de outros
comprimentos e ao inteiro decimal é a hipótese desta rodada.

Passaram 108 recuperações de mensagens plantadas, 144 comparações com enumeração
integral de pequenos exemplos e a decifração conhecida da fase 3.2. O plaintext
deste último controle conserva SHA256
`b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34`.

Na realimentação, as decisões anteriores alteram a chave futura. O buscador
preserva essa dependência; não trata os dígitos de saída como escolhas
independentes. Ele calcula intervalos conservadores a partir dos prefixos
decimais possíveis. Os **80.909 certificados** cobrem todas as máscaras
dos casos declarados, sem casos interrompidos.

O [verificador separado](../../solver/verify_feedback_decimal.cjs) recalculou
as sequências com uma fila, reconstruiu cada prefixo e contou aritmeticamente
os inteiros admissíveis nos intervalos. Conferiu também a completude das
sementes e dos casos. Não importa o buscador nem sua função de sucessor.

Arquivos: [especificação](spec.json), [resumo](summary.json),
[certificados](cases.jsonl), [conferência independente](verification.json).

## 2. Listas como ordem de colunas

Esta família reutiliza as 43 listas e acrescenta os três rótulos decodificados
da própria página: `matrixsumlist`, `lastwordsbeforearchichoice` e
`thispassword`. São **46 listas e 168 chaves distintas**, usando os inteiros
originais ou seus dígitos concatenados, em ambas as direções.

Modelos:

- Transposição colunar incompleta, com desempate da esquerda para a direita.
- A mesma, com desempate da direita para a esquerda.
- Myszkowski: colunas de mesmo valor são lidas em conjunto, linha a linha.
- Valores ascendentes/descendentes; permutação e inversa; reversão da entrada
  e da saída independentemente. Não se insere preenchimento na última linha.

Os algoritmos reproduzem os exemplos da ACA para
[transposição colunar incompleta](https://www.cryptogram.org/downloads/aca.info/ciphers/IncompleteColTransposition.pdf)
e [Myszkowski](https://www.cryptogram.org/downloads/aca.info/ciphers/Myszkowski.pdf).
Também passaram 72 verificações de inversão e 54 recuperações de mensagens
plantadas.

Para cada permutação, **qualquer um dos nove símbolos**, isoladamente, pode
representar zero ou seu dígito original em cada ocorrência. A conversão final
é a mesma: inteiro decimal completo para bytes mínimos menores que 128.

| Campo | Permutações propostas | Permutações distintas | Casos com os nove símbolos | Candidatos |
|---|---:|---:|---:|---:|
| DBBI | 8.064 | 6.240 | 56.160 | 0 |
| FAED | 8.064 | 6.184 | 55.656 | 0 |
| Total | 16.128 | 12.424 | **111.816** | **0** |

Todos os casos terminaram: **357.956 nós e 234.886 certificados**.
O [verificador independente](../../solver/verify_columnar_decimal.cjs) constrói
as permutações ordenando todas as posições da grade por tuplas, em vez de ler
colunas como o buscador. Regerou a coleção inteira de permutações, conferiu
cada mapeamento e confirmou todos os intervalos por contagem aritmética.

Arquivos: [especificação](columnar/spec.json), [modelos](columnar/models.jsonl),
[resumo](columnar/summary.json), [certificados](columnar/cases.jsonl),
[conferência independente](columnar/verification.json).

## Reprodução e limites

```powershell
node solver/feedback_decimal_constraints.cjs run
node solver/verify_feedback_decimal.cjs
node solver/columnar_decimal_constraints.cjs
node solver/verify_columnar_decimal.cjs
```

São **168.456 casos completos, 463.134 nós e 315.795 certificados conferidos**.
Cada verificador também passou 65.536 controles de contagem de pequenos
inteiros e 300 controles de comprimentos maiores. Os valores das 43 listas
foram comparados com a especificação preservada da rodada anterior; essa
comparação não prova que alguma lista seja a chave pretendida pelo autor.

A conclusão exclui somente os modelos declarados. Não cobre todas as
permutações de colunas, transposição dupla, substituição arbitrária combinada
com transposição, vários símbolos simultaneamente zeráveis, outras bases ou
dados binários. Não é evidência de que o puzzle seja impossível ou de que
falte informação privada. **Nenhuma senha ou chave privada foi recuperada.**

Não retomar essas mesmas sementes, chaves e regras apenas trocando seletores
de zero: todas as escolhas dentro do modelo já foram abrangidas. A fronteira
continua sendo uma transformação derivada das pistas que produza uma abertura
autêntica de SMALL, TAIL32 ou COSMIC.
