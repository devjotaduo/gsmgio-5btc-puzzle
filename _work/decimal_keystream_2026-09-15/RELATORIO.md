# SalPhaseIon: listas, chaves decimais e alfabetos de nove símbolos

Data: 15/09/2026, America/Sao_Paulo.

**Nenhuma senha final ou decifração final foi validada nesta rodada.** Os
resultados abaixo eliminam modelos explicitamente delimitados. Não provam
que o puzzle seja impossível nem que as pistas estejam erradas.

## Material e critério de confirmação

Foram usados os campos completos DBBI (91 símbolos) e FAED (570 símbolos), a
matriz binária 14×14, as posições coloridas originais e os três blobs da
fronteira: SMALL, TAIL32 e COSMIC. A entrada preservada está em
[`inputs.json`](../prime_geometry_2026-09-11/inputs.json).

SHA256 dos campos, sem espaços:

- DBBI: `71fe46259e270c113529dfaded4b59c59a9dffd826a7202ab07fc498b6a2c5ca`.
- FAED: `066191b4aafc114fbca7f0d168382f40129c4ff18490375b689741081d5ef3c2`.

Uma abertura AES precisa fornecer conteúdo coerente com consequência
verificável, ou uma chave que corresponda à chave pública do prêmio.
Padding PKCS#7, isoladamente, não confirma senha. Como controle positivo,
os programas reabrem a fase 3.2 conhecida com EVP_BytesToKey/SHA256.
O plaintext desse controle tem SHA256
`b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34`.

## 1. Listas da matriz como chaves decimais periódicas

Hipótese: `a=1..i=9`, com cada ocorrência de `g` podendo valer 0 ou 7;
aplicar uma chave decimal periódica; interpretar o resultado como um único
inteiro decimal; convertê-lo em bytes mínimos big-endian, todos menores que
128. Os campos foram usados na ordem original e inteiramente invertidos.
O teste permite controles ASCII, sendo mais amplo que texto imprimível.

As 27 listas iniciais incluem somas de linhas/colunas, contagens de cores,
atribuições dos primos 2/3 às cores em ambas as ordens, valores binários das
linhas/colunas, pesos primos e posições coloridas. Cada lista recebe duas
serializações (resíduos módulo 10 ou concatenação decimal), ambas as
direções e todas as rotações cíclicas. Isso gera 2.012 chaves distintas.

As três operações dígito a dígito, módulo 10, são `C-K`, `C+K` e `K-C`.
**24.144 casos completos; nenhum texto de sete bits possível.** Foram
visitados 43.538 nós e emitidos 33.841 certificados de exclusão por intervalos.

Uma segunda família permite os transportes da aritmética inteira: as três
operações são feitas módulo `10^L`, com `L` igual ao comprimento do campo.
Ela usa 43 listas e 3.326 chaves, incluindo 16 listas adicionais de cores.
**39.912 casos completos; nenhum candidato.** Foram visitados 75.444 nós
e emitidos 57.678 certificados.

Os valores adicionais vêm de duas convenções externas: posição no espectro
visível (amarelo 3, azul 5) e código de resistores (amarelo 4, azul 6), com
variantes que substituem os valores pelos primos correspondentes. Fontes:
[NASA](https://cosmicopia.gsfc.nasa.gov/qa_gp_b.html) e
[Vishay](https://www.vishay.com/docs/49411/resistor_color_code_calculator.pdf).
**O uso dessas convenções no puzzle é uma hipótese nossa, não uma instrução
confirmada do criador.**

Também foram testadas 1.600 senhas SHA256-hex derivadas das listas coloridas:
listas isoladas e concatenações explícitas com os campos e duas leituras de
`lastwordsbeforearchichoice`. As frases são
`reinsertingtheprimebasicsafterwhichyouwillberequiredto` e
`sheisgoingtodieandthereisnothingyoucandotostopit`. As pré-imagens e separadores
exatos estão em [`carry_color/passwords.json`](carry_color/passwords.json).
Nos três blobs, com KDF SHA256 e MD5: **9.600 tentativas, 31 paddings,
nenhuma decifração validada**. Nenhuma das 16.816 verificações de escalares
contra a chave pública encontrou o prêmio.

O verificador independente conta os inteiros admissíveis em cada intervalo,
sem importar o buscador. Confirma os **64.056 casos e 91.519 certificados**,
a cobertura integral das escolhas de `g`, e as 9.600 tentativas AES com
remoção manual de PKCS#7. Controles: 65.536 inteiros pequenos e 300 intervalos
grandes, além dos controles plantados dos buscadores.
Resultados: [`summary.json`](summary.json),
[`carry_color/summary.json`](carry_color/summary.json) e
[`independent_verification.json`](independent_verification.json).

## 2. Todas as chaves decimais de um a seis dígitos

Para FAED, foram esgotadas **todas** as chaves decimais de comprimentos 1 a 6,
inclusive zeros iniciais, nas duas direções do campo e nas operações
dígito a dígito `C-K` e `K-C`. A adição é redundante neste espaço completo de
chaves. Todas as escolhas de `g=0/7` estão cobertas por intervalos.

São **4.444.440 combinações de chave/direção/operação**, não 4.444.440
senhas AES distintas. Resultado: 9.621.640 nós, **zero candidatos e zero
casos interrompidos**. Os 24 arquivos `.nodes` guardam a contagem por chave;
seus hashes estão no [resumo](short_keys/summary.json).
Uma [conferência contábil](short_keys/accounting_check.json) confirmou os
tamanhos, hashes e somas das contagens de todos os 24 arquivos.

Controles: 240 comparações com o buscador genérico e 12 recuperações de
mensagens plantadas de 237 bytes. Esta busca não recebeu uma segunda
enumeração integral independente. Não cobre períodos maiores, outras bases,
transposições ou codificações que exijam bytes acima de 127.

## 3. Morbit e Pollux

O alfabeto `a..i` tem exatamente nove símbolos, como as nove combinações de
pares usadas por Morbit. Pollux permite que vários símbolos representem
ponto, traço ou separador. Foram implementadas as regras descritas pela
American Cryptogram Association:
[Morbit](https://www.cryptogram.org/downloads/aca.info/ciphers/Morbit.pdf) e
[Pollux](https://www.cryptogram.org/downloads/aca.info/ciphers/Pollux.pdf).
Os exemplos publicados foram reproduzidos como controles positivos.

Foram esgotados os `9! = 362.880` mapas Morbit e os `3^9 = 19.683` mapas
Pollux para ambos os campos, originais e invertidos: **1.530.252 decodificações
testadas, sem mapas pendentes**. A gramática aceita A–Z, 0–9 e a tabela explícita de pontuação
preservada no resumo, com separadores entre letras/palavras.

Morbit não produz saída válida em nenhum dos quatro campos/direções.
Pollux produz 12 saídas sintaticamente válidas, todas em DBBI original;
nenhuma abre os blobs. Suas variantes diretas e SHA256-hex, com ajustes
explícitos de caixa/espaços, dão 96 senhas: **576 tentativas AES, cinco
paddings, nenhuma decifração validada**.

Isso exclui as leituras diretas declaradas. Não exclui Morse com uma camada
adicional de transposição, substituição variável ou outra gramática.
Resultados: [`morse/summary.json`](../morse_2026-09-15/summary.json) e
[`morse/candidates.json`](../morse_2026-09-15/candidates.json).

## 4. Cada símbolo como 0, 1 ou remoção

Foram esgotados os `3^9` mapas fixos de `a..i` para `0`, `1` ou remoção,
ambos os campos e suas inversões, ambas as ordens dos bits por unidade,
ASCII imprimível de 7/8 bits (mais TAB/LF/CR) e Bacon de 5 bits com
alfabetos de 26 e 24 letras. A única sobra permitida é um sufixo de zeros
menor que uma unidade. Saídas vazias ou degeneradas também foram retidas.

Das **629.856 decodificações**, 32.474 passam a gramática, gerando 23.350
saídas distintas. Suas formas diretas, SHA256-hex e minúsculas produzem
92.818 senhas: **556.908 tentativas AES, 2.193 paddings, nenhuma abertura
coerente identificada**. A maior proporção de bytes imprimíveis nas saídas
aceitas por padding é 58,23%; esse escore não é usado como prova de solução.
Resultados: [`binary/summary.json`](../binary_partition_2026-09-15/summary.json).

## Verificação independente de Morse, binário e chaves do prêmio

Um segundo programa reenumerou todos os mapas. Para Morse, usa outro
gerador de permutações e separa cadeias de pontos/traços, em vez do estado
incremental do buscador. Para as leituras binárias, usa cadeias de bits e
conversão textual, em vez de acumular valores numericamente.

Ele confirmou as 1.530.252 tentativas Morse e suas 12 saídas, as 629.856
tentativas binárias e suas 23.350 saídas distintas. Reexecutou as **557.484
tentativas AES** dessas duas famílias com remoção manual de PKCS#7,
confirmando todos os sucessos e fracassos e os bytes das 2.198 saídas com
padding válido. A conferência decimal separada cobre as outras 9.600
tentativas e 31 saídas.

Também foram verificadas as pré-imagens de exatamente 32 bytes, os hashes
SHA256 candidatos e todas as janelas consecutivas de 32 bytes big-endian
das 2.198 saídas, além de sequências hexadecimais de 64 caracteres. São
**1.074.236 verificações de escalares; zero correspondências**. A comparação
usa a coordenada x da chave pública do prêmio, incluindo a possibilidade de
escalar negado. O total de verificações não afirma unicidade dos escalares.
Não foram testadas todas as derivações possíveis de chaves.

Resultado integral:
[`independent_verification.json`](../binary_partition_2026-09-15/independent_verification.json).
Uma inspeção adicional das 2.229 saídas das três famílias encontrou no
máximo 14 bytes ASCII imprimíveis consecutivos e nenhum dos cabeçalhos
iniciais testados: OpenSSL `Salted__`, gzip, ZIP, bzip2, XZ, Zstandard, PNG
ou PDF. Esses testes não excluem todo formato binário possível.

## Reprodução

Na raiz do repositório, com Node.js:

```powershell
node solver/decimal_keystream_constraints.cjs
node solver/decimal_carry_color.cjs
node solver/verify_decimal_keystream.cjs
node solver/decimal_short_key.cjs 6
node solver/morse_endgame.cjs
node solver/binary_partition_endgame.cjs
node solver/verify_morse_binary.cjs
```

Os scripts gravam os resultados apenas nos diretórios locais desta rodada.
Não enviam candidatos a serviços externos nem movimentam fundos.

## Consequência para a investigação

Foram executadas **567.084 tentativas AES** nas três famílias que produziram
senhas. Os totais de senhas são distintos dentro de cada família, sem
afirmação de deduplicação entre famílias. As 2.229 aceitações de padding
não forneceram uma decifração validada.

A ligação operacional entre `yellowblueprimes`, `matrixsumlist`, DBBI e FAED
permanece desconhecida. Os resultados não justificam retomar a antiga cadeia
binária comunitária como se estivesse autenticada. Ainda falta uma regra
derivada das pistas que gere uma abertura verificável de SMALL, TAIL32 ou
COSMIC; esta rodada não fornece a senha nem o resultado final solicitado.
