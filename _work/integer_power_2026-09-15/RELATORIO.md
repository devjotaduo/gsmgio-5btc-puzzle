# Potências inteiras antes da conversão em bytes

**Nenhuma senha nem chave final recuperada.** A referência a primos motivou
a hipótese `N = P^e`. Não existe uma instrução primária que confirme esse
uso. Para não escolher apenas alguns primos, foram cobertos todos os
expoentes inteiros possíveis no modelo.

## Modelo e resultado

DBBI ou FAED inteiro, em ordem original ou com todos os símbolos invertidos,
é um decimal com `a=1..i=9`. Qualquer um dos nove símbolos, isoladamente,
pode representar zero ou seu dígito em cada ocorrência. Procuramos uma
potência exata `N=P^e`, com `e>=2` e todos os bytes mínimos big-endian de
`P` menores que 128. Isso inclui controles ASCII e é mais permissivo que
exigir uma frase imprimível.

Como todos os números possíveis são maiores que 1, `P>=2`. Logo basta
examinar `e<=floor(log2(max N))`: 301 em DBBI e 1.892 em FAED. Foram
**39.438 casos completos, 42.960 nós e 41.199 certificados de exclusão**,
sem candidatos, casos parciais ou tentativas AES.

O buscador calcula raízes inteiras por Newton e descarta intervalos que
não contêm uma potência com raiz em sete bits. Um verificador separado,
que não importa essas funções, usa busca binária para as raízes e contagem
dos inteiros admissíveis. Ele confirmou cada certificado, a cobertura
integral das máscaras e o conjunto completo de expoentes.

O buscador passou 22.450 controles de raiz, 12 mensagens plantadas e 36
comparações com enumeração direta. O verificador passou outros 22.240
controles de raiz, 65.536 contagens pequenas e 300 verificações de largura.

## Limites e reprodução

Não foram excluídas exponenciação modular/RSA, separação em blocos,
transposição, outras bases, outros alfabetos ou plaintext binário. O
resultado não autoriza concluir que os números primos sejam irrelevantes.

```powershell
node solver/integer_power_constraints.cjs run
node solver/verify_integer_power.cjs
```

Entradas e hashes: [spec.json](spec.json). Contagens: [summary.json](summary.json).
Conferência independente: [verification.json](verification.json).
Programas: [buscador](../../solver/integer_power_constraints.cjs) e
[verificador](../../solver/verify_integer_power.cjs).
