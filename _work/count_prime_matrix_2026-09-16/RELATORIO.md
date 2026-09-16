# Contagens das cores como índices primos — 16/09/2026

**Nenhuma senha ou chave do prêmio encontrada.** A regra de pesos testada
não abriu os blobs pelos modelos declarados abaixo. Isso não elimina a
pista `yellowblueprimesmatrixsumlist` em geral.

## Pista → hipótese

A mensagem #1710 do criador associa números a amarelo e azul e remete à
primeira peça. As mensagens #8000, #8330 e o binário #8446/#8483 confirmam
o papel de primos, sem determinar a operação. A matriz original contém
**9 células amarelas e 15 azuis**.

Hipótese desta rodada: usar as contagens como índices na lista dos primos:
amarelo recebe o 9º primo, **23**, e azul recebe o 15º, **47**. Mantêm-se os
bits originais nas outras células ou substituem-se essas células por zero.
As somas das 14 linhas e das 14 colunas formam as listas.

O vínculo entre contagem e índice primo é uma inferência testável, não uma
instrução explícita do autor. As contagens serem determinadas pelos bits
da URL não impede seu reaproveitamento; também não comprova a regra.
Ver a [conferência das fontes públicas](../public_recheck_2026-09-16/RELATORIO.md).

## Listas calculadas

```text
Demais células conservam seus bits:
linhas  [75,102,54,53,75,52,74,73,101,78,30,54,76,101]
colunas [54,102,146,56,54,99,49,75,53,51,124,29,29,77]

Demais células zeradas:
linhas  [70,94,47,47,70,46,70,70,94,70,23,47,70,94]
colunas [47,94,141,47,47,94,46,70,47,46,117,23,23,70]
```

As quatro listas geram **352 chaves decimais distintas**: resíduos módulo
10 ou concatenação de dígitos, duas direções e todas as rotações cíclicas.
Nenhuma coincide com as 3.326 chaves geradas pelas 43 listas da campanha
anterior. Essa comparação não afirma que nenhuma senha semelhante tenha
sido testada em qualquer investigação histórica.

## Lista como chave antes da conversão decimal

Dois modelos fixos foram executados:

1. Adição, subtração ou Beaufort dígito a dígito, módulo 10, com a chave repetida.
2. As mesmas três operações sobre o inteiro completo, com transporte decimal,
   usando a chave repetida e redução módulo `10^L`, onde `L` é o tamanho do campo.

Cada ocorrência de `g` pode ser 0 ou 7, independentemente; as outras letras
mantêm `a=1..i=9`. São examinados DBBI e FAED completos, nas ordens direta e
inversa, e os bytes mínimos do inteiro em big-endian ou little-endian.
A saída precisa ser UTF‑8 estrito; controles são permitidos. Não se usa um
classificador de inglês nem se substituem bytes inválidos.

**Resultado: 16.896 casos completos, 48.584 nós, 32.740 intervalos excluídos,
zero candidatos e nenhuma busca pendente.** Todas as máscaras de zero dos
modelos declarados foram cobertas. O resultado exclui esses usos das listas
como chaves; não exclui outros algoritmos ou outras regras de zeragem.

O buscador passou 96 comparações com enumeração de máscaras e recuperou 24
textos conhecidos contendo caracteres não ASCII. Um verificador separado
recalculou as contagens, os primos, a geometria, as listas, cada chave e os
limites de todas as máscaras. Conferiu as exclusões por contagem de sequências
Unicode, reutilizando o contador independente da rodada UTF‑8, sem importar
o buscador nem seu autômato.

[Especificação](spec.json), [resultados](summary.json),
[verificação independente](verification.json).

## Lista como ingrediente direto da senha

Também foram fixadas representações diretas das listas: linhas, colunas,
concatenação nas duas ordens e intercalação; cada sequência direta/inversa;
dígitos concatenados, vírgulas, espaços, quebras de linha ou bytes crus.

Para cada uma, testaram-se a lista isolada e duas composições explícitas:
`lista + últimas palavras` e `DBBI + lista + FAED + últimas palavras`.
As palavras são as duas fronteiras já documentadas, sem varrer sufixos:

```text
reinsertingtheprimebasicsafterwhichyouwillberequiredto
sheisgoingtodieandthereisnothingyoucandotostopit
```

As composições com DBBI/FAED usam os campos ainda cifrados literalmente;
são sondagens condicionais, não a afirmação de que esses campos estejam
resolvidos. Obtiveram-se **500 pré-imagens**. Cada uma foi usada diretamente
ou como SHA256 hexadecimal, totalizando **1.000 senhas e 6.000 testes AES**
nos blobs SMALL, TAIL32 e COSMIC, sob EVP-SHA256 e EVP-MD5.

- 18 paddings aceitos, sem decifração validada; maior fração ASCII/whitespace
  de 49,37%.
- 500 hashes comparados como escalares secp256k1, sem correspondência com a
  chave pública do prêmio ou sua negação.
- PyCryptodome e coincurve confirmaram todas as decisões AES, inclusive
  rejeições, os corpos completos e as comparações de chave.
- A fase 3.2 conhecida e o gerador secp256k1 passaram como controles positivos.

[Pré-imagens](preimages.json), [oráculos](oracles.json),
[conferência independente](oracle_verification.json).

## Consequência

A campanha fecha esses dois usos concretos dos pesos 23/47 sem fornecer uma
nova direção de decifração. Não ampliar automaticamente permutações de palavras
ou valores das cores. A operação pretendida de `matrixsumlist` continua
desconhecida; a senha final permanece sem recuperação validada.

```powershell
node solver/count_prime_matrix.cjs
node solver/verify_count_prime_matrix.cjs
```

[Buscador e oráculos](../../solver/count_prime_matrix.cjs),
[verificador](../../solver/verify_count_prime_matrix.cjs).
