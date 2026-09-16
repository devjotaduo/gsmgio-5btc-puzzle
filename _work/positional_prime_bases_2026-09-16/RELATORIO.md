# Linhas da matriz interpretadas em bases primas

16/09/2026. **Nenhuma senha final validada.** A concatenação decimal das
14 linhas ou colunas, lidas como números numa base prima, foi excluída
para DBBI no modelo abaixo. Para FAED obtivemos apenas limites necessários;
não foi feita uma busca completa dos pares de dígitos.

**Atualização de 16/09/2026:** esses limites de FAED foram posteriormente
completados por uma [prova de prefixos](../positional_prime_prefix_2026-09-16/RELATORIO.md)
e uma [extensão para qualquer ordem dos 14 números](../positional_prime_order_2026-09-16/RELATORIO.md).
As duas receberam conferência independente. O modelo declarado também foi
excluído para FAED; a seção abaixo preserva o resultado da etapa inicial.

## Modelo e limites

A base `r` é prima. Todas as células azuis recebem um dígito primo `p` e
todas as amarelas um dígito primo `q`, com `2≤p,q<r`. A desigualdade estrita
é parte desta hipótese de representação posicional, e não uma instrução
confirmada do puzzle. Células sem cor usam pesos independentes 0 ou 1
para os bits preto/branco originais. A célula quase branca segue seu bit.

Cada linha ou coluna é avaliada com os pesos posicionais `r^13,…,r^0`,
também invertidos. Seus 14 valores são escritos em decimal mínimo e
concatenados. São 16 perfis da matriz, para cada um dos dois campos.

Para qualquer base, o comprimento mínimo ocorre relaxando ambos os
dígitos das cores para 2. Um limite superior ocorre relaxando ambos
para `r−1`, mesmo quando esse número não é primo. Esses comprimentos
são monótonos na base. Busca binária encontra o intervalo necessário
de bases, e divisão inteira identifica todos os primos dentro dele.
Os limites cobrem bases arbitrariamente grandes; não há teto arbitrário
de primos escolhido para o teste.

## DBBI: exclusão completa neste modelo

Em 14 dos 16 perfis, nenhum primo está no intervalo compatível com os
91 caracteres de DBBI. Nos dois perfis restantes, a base é necessariamente
3 e os dois dígitos primos são necessariamente 2.

| Perfil restante | Zeros decimais | Maior contagem de um dígito positivo | Soma máxima |
|---|---:|---:|---:|
| Linhas, posições invertidas, preto 1/branco 0 | 10 | 14 | 24 |
| Colunas, posições diretas, preto 0/branco 1 | 7 | 13 | 20 |

DBBI tem **25 ocorrências de `b`**. Sob qualquer bijeção fixa dos dígitos
positivos com `a..i`, uma letra pode representar seu dígito e receber
todos os zeros; mesmo essa concessão dá no máximo 24 ou 20 ocorrências.
Logo, ambos os perfis são impossíveis.

Essa contradição de frequências independe da ordem das 14 linhas/colunas,
do sentido do campo e de quantas letras podem também representar zero.
Ela não cobre pesos das cores maiores ou iguais à base, fusão de dois
dígitos positivos numa letra, separadores ou transformações adicionais.

## FAED: limite, sem exclusão geral

Dois perfis não admitem base prima pelo comprimento. Nos demais, os
intervalos necessários incluem primos entre 1.181 e 29.501, variando com
o perfil. As listas completas estão nos dados; o intervalo global não
significa que todos os primos nele sejam possíveis em todos os perfis.

Os pares `p,q` desses casos **não foram esgotados**. Comprimento compatível
não implica correspondência com os 570 símbolos de FAED. Esta etapa não
produziu plaintext, candidato de senha, teste AES ou chave privada.

## Verificação e reprodução

Os 32 conjuntos de limites foram conferidos por outra implementação em
Python, usando avaliação de Horner com inteiros arbitrários, desigualdades
nos dois extremos e primalidade por divisão. As duas listas de valores
de DBBI e seus histogramas também foram reconstruídos independentemente.
O gerador conferiu 64 controles de base prima conhecida.

```powershell
node solver/positional_prime_bounds.cjs
```

[Todos os intervalos](cases.json), [dois casos de DBBI](residual_dbbi.json),
[resumo](summary.json), [verificação independente](verification.json),
[programa](../../solver/positional_prime_bounds.cjs).

SHA256 do programa:
`51ce1ea2ee5e37c49d05fcca397ef0ebf93def4270c5900c514466e4126afbb6`.
SHA256 dos intervalos:
`a8536dc55a67dbde4666a4f6364e2d0be433284daab58ecd9f7ddcb47b3c89fc`.
