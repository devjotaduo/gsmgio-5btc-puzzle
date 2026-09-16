# Leitura decimal com zeros e UTF‑8 — 16/09/2026

**Nenhuma senha final encontrada.** A leitura direta de FAED como UTF‑8 é
incompatível com todos os modelos desta rodada. DBBI admite sequências UTF‑8
quando duas letras podem virar zero, mas todas contêm controles e nenhuma
produziu uma decifração validada ou a chave do prêmio.

## Pista, hipótese e diferença em relação aos testes anteriores

A própria página ensina a conversão de um inteiro decimal em bytes nos trechos
`lastwordsbeforearchichoice` e `thispassword`. A mensagem #8000 do criador,
de 26/12/2021, diz que alguns caracteres precisam ser zerados. Ela não escolhe
`g`, não limita a operação a uma letra nem determina a codificação do resultado.

As exclusões recentes desse caminho exigiam bytes de sete bits. Essa restrição
não admite texto com acentos ou aspas tipográficas. Aqui foi usada a gramática
completa de UTF‑8, com sequências de um a quatro bytes, sem codificações
excessivamente longas, surrogates ou valores acima de U+10FFFF, conforme
[RFC 3629, seção 4](https://www.rfc-editor.org/rfc/rfc3629.html#section-4).
Controles e caracteres não atribuídos também são aceitos pelo filtro estrutural.

Modelo fixado:

1. `a..i` mantém os valores decimais `1..9`.
2. Escolhe-se uma letra ou um par de letras diferentes. **Cada ocorrência**
   dessas letras pode manter seu valor ou virar zero, independentemente.
3. O campo inteiro é lido como número decimal, na ordem original ou com todos
   os símbolos invertidos. Não são removidos prefixos, símbolos ou controles.
4. O número vira sua representação mínima em bytes, big-endian ou little-endian.
   A ordem little-endian refere-se ao inteiro; UTF‑8 não tem variante de
   endianness de unidades de código.
5. Todos os bytes precisam formar uma sequência UTF‑8 válida, sem substituição
   de erros por U+FFFD e sem descartar BOM.

O uso de duas letras amplia o modelo de zeragem. É uma hipótese, não uma
instrução do autor para zerar exatamente duas letras. Uma transformação
criptográfica ou de transposição adicional permanece fora do teste.

## Resultados completos

| Letras zeráveis | Casos | Nós | Intervalos excluídos | Sequências UTF‑8 |
|---|---:|---:|---:|---:|
| Uma, todas as 9 escolhas | 72 | 482 | 277 | 0 |
| Duas, todos os 36 pares | 288 | 318.460 | 125.966 | 33.408, todas em DBBI |
| Total | **360** | **318.942** | **126.243** | **33.408** |

Os casos incluem dois campos, duas ordens de símbolos e duas ordens de bytes.
Todas as buscas terminaram com cobertura integral das máscaras, sem nós
pendentes. As famílias se sobrepõem; as quantidades de máscaras não devem
ser somadas como tentativas distintas de senha.

Para FAED, **nenhuma sequência é UTF‑8**, mesmo permitindo controles ou
qualquer escrita Unicode. Para DBBI, **todas as 33.408 sequências contêm
algum controle C0/C1 diferente de TAB, LF ou CR**. Nenhuma constitui texto
comum sem esses controles. Não removemos esses bytes para fabricar uma frase.

## Como a cobertura foi conferida

O buscador constrói autômatos para UTF‑8 normal e para a sequência inteira de
bytes invertida. A partir de cada limite decimal mínimo, encontra o menor
inteiro que respeita a gramática. Se esse valor ultrapassa o máximo possível
do ramo, todas as máscaras daquele ramo são excluídas.

O verificador não importa esses autômatos nem a função sucessora. Ele conta
sequências formadas pelos nove modelos de bytes que codificam valores
Unicode, calculando quantas cabem em cada intervalo. Conferiu os **126.243
certificados**, seus limites derivados dos campos originais, a ausência de
sobreposição das máscaras e a cobertura integral. Também reconstruiu todos
os candidatos e verificou os resumos que alimentam os testes AES.

Controles do buscador: 131.072 inteiros curtos comparados com `TextDecoder`
estrito, 270 recuperações de textos conhecidos — inclusive acentos, aspas,
caracteres chineses e emoji —, 270 comparações com enumeração de máscaras,
18 fronteiras inválidas e contabilização de busca interrompida.

Controles do verificador: 131.072 contagens exatas acumuladas, 6.006 testes
de pertinência com decoder estrito e 474 contagens de larguras completas.
Esses controles são repetidos pelas duas execuções; não são conjuntos
independentes adicionais nem testes de senha.

[Resultados de uma letra](summary.json),
[resultados de duas letras](two_symbols/summary.json),
[verificação de uma letra](verification.json) e
[verificação de duas letras](two_symbols/verification.json).

## Senhas e alvo criptográfico

Cada uma das 33.408 sequências de bytes foi testada integralmente como senha
direta e como pré-imagem de SHA256, cujo hexadecimal é a senha. Não foi
alterada a caixa, removida pontuação ou aplicada normalização Unicode.

- **66.816 senhas distintas; 400.896 testes AES-256-CBC**, nos três blobs
  originais, com EVP-SHA256 e EVP-MD5.
- **1.487 paddings aceitos**, sem decifração validada. A maior fração de bytes
  ASCII imprimíveis ou whitespace foi 56,97%.
- **33.408 hashes tratados como escalares secp256k1**: nenhuma correspondência
  com a chave pública do prêmio nem sua negação.

Uma implementação independente inline em Python, com PyCryptodome 3.23.0 e
coincurve 21.0.0, conferiu **todas as decisões AES, inclusive rejeições**, os
1.487 corpos integrais e todas as comparações de pontos. Também decodificou
todos os candidatos com UTF‑8 estrito e confirmou seus controles. A fase 3.2
conhecida e o gerador secp256k1 foram os controles positivos.

[Oráculos](oracles.json), [conferência independente](oracle_verification.json).

## Consequência e reprodução

Essa rodada elimina a hipótese de que a leitura direta de FAED tenha falhado
apenas por uma restrição indevida a ASCII, **sob o mapeamento e a zeragem
de uma ou duas letras definidos acima**. Ela não exclui UTF‑8 após outra
transformação, outro alfabeto, três ou mais letras zeráveis, UTF‑16 ou dados
binários. Não justifica ampliar automaticamente o número de letras zeráveis:
a multiplicação de sequências válidas de DBBI não trouxe evidência de mensagem.

A próxima investigação deve fixar uma operação anterior a partir de
`yellowblueprimes / matrixsumlist` ou de outra pista primária. O significado
operacional continua desconhecido; SMALL, TAIL32 e COSMIC continuam sem
abertura validada.

```powershell
node solver/utf8_decimal_constraints.cjs
node solver/utf8_decimal_constraints.cjs pairs
node solver/verify_utf8_decimal.cjs
node solver/verify_utf8_decimal.cjs pairs
node solver/utf8_decimal_oracles.cjs
```

Código: [buscador](../../solver/utf8_decimal_constraints.cjs),
[verificador independente](../../solver/verify_utf8_decimal.cjs) e
[testes AES e secp256k1](../../solver/utf8_decimal_oracles.cjs).
