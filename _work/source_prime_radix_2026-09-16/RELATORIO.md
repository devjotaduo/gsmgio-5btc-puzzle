# Bases primas na entrada e limites da saída em base 127

16/09/2026. **A senha final continua desconhecida.** Esta rodada distingue
duas operações que não são equivalentes: ler a entrada numa base prima e
converter um inteiro decimal para uma base prima. Nenhuma delas foi indicada
explicitamente pelo criador; são hipóteses para combinar a conversão numérica
da página com a referência a primos.

## 1. Base prima de origem: família inteiramente excluída

Modelo examinado:

1. Preservar cada campo completo, DBBI ou FAED, na ordem original ou inversa.
2. Usar `a..i = 1..9` e escolher uma letra que, por ocorrência, possa também
   significar zero. Todas as nove escolhas de letra foram consideradas.
3. Ler esses dígitos numa base prima entre 11 e 257, inclusive: 51 bases.
4. Converter o inteiro para seus bytes mínimos e exigir que **todos estejam
   em 0..127**, incluindo qualquer controle ASCII.

O intervalo de bases é o escopo escolhido para esta experiência, não uma
faixa confirmada pelo autor. Bases menores que 11 não comportam os nove
dígitos positivos desse mapa. Inverter a ordem dos bytes preserva a condição
de todos terem sete bits e está, portanto, coberto pela mesma exclusão.

**Resultado: 1.836 casos completos, 3.200 nós, 2.518 intervalos rejeitados,
zero candidatos.** DBBI e FAED têm 918 casos cada. A base 127, isoladamente,
tem 36 casos, todos incompatíveis. Nenhuma tentativa AES ou comparação de
chave privada foi acionada, pois esta hipótese não produziu candidatos.

Cada prefixo de escolhas de zero determina um intervalo inteiro que contém
todas as suas continuações. O buscador rejeita o intervalo quando o próximo
inteiro com bytes de sete bits excede seu máximo. As folhas rejeitadas
particionam integralmente as máscaras possíveis, sem limite de tempo ou
corte de busca atingido nesta execução.

O verificador não importa o buscador: reconstrói os intervalos por Horner,
conta os inteiros de sete bits em cada intervalo e confere ausência de
sobreposição e cobertura integral das máscaras. Reconstrói também a lista
de primos por uma peneira, com outro algoritmo. Passaram 150 controles
pequenos contra enumeração, três recuperações de mensagens plantadas usando
a base decimal de controle e 65.536 comparações do contador independente.

Isso exclui somente o modelo descrito. Não abrange permutações de dígitos,
mais de uma letra zerável, bases maiores, deslocamentos de códigos, recorte
de bytes ou saída binária que dependa de outra transformação.

## 2. Base 127 de destino: limites independentes das máscaras

Aqui a operação é a da pesquisa anterior: ler o campo como decimal com
`a..i = 1..9`, permitir cada `g` como 0 ou 7 e escrever o inteiro na base
127. O conjunto textual aceito anteriormente era 32..126 mais TAB/LF/CR.

Os extremos inteiro mínimo/máximo dão prefixos comuns a **todas** as máscaras:

| Campo e ordem dos símbolos | Dígitos de saída | Restrição fixa |
|---|---:|---|
| DBBI original | 44 | Começa com código 1; também tem 17 na posição 4 |
| DBBI inverso | 44 | Começa com código 1 |
| FAED original | 271 | Começa com `9i` ou `9j` |
| FAED inverso | 271 | Tem códigos 23 e 27 nas posições 9 e 11 |

As posições da tabela são contadas de 1. Os controles 1, 17, 23 e 27 ficam
fora daquele conjunto textual. Assim, os dois sentidos de DBBI e FAED
inverso estão excluídos nessa leitura direta. FAED original não pode começar
com uma palavra formada apenas por letras; **isso não exclui senhas com
números nem textos com cabeçalho numérico**.

A pesquisa anterior de FAED original/base127 ainda estava parcial nesta
rodada, com 177 candidatos. Posteriormente foi [concluída e conferida](../radix127_completion_2026-09-16/RELATORIO.md),
com exatamente 188 saídas e nenhum caso pendente; os registros antigos foram preservados.
O novo limite de prefixo não seleciona nenhuma das máscaras restantes e
não justifica afirmar que toda a base 127 foi eliminada.

## Reprodução e arquivos

Na raiz do repositório:

```powershell
node solver/source_prime_radix.cjs
node solver/verify_source_prime_radix.cjs
```

- [Especificação e hashes de origem](spec.json).
- [Todos os casos e certificados](cases.json).
- [Resumo da busca](summary.json).
- [Limites decimais e prefixos de destino](destination127_prefixes.json).
- [Conferência independente](verification.json).
- [Buscador](../../solver/source_prime_radix.cjs) e
  [verificador](../../solver/verify_source_prime_radix.cjs).

O SHA256 dos casos é
`b2e1291b4c1d0ddb8cf0be2f4eb92d8294cf9132db12ce6193d1cd909059ca9f`.
O resultado favorece procurar a operação que falta antes da conversão;
não sustenta ampliar automaticamente a faixa de primos ou enumerar mais
saídas ASCII construídas. SMALL, TAIL32 e COSMIC continuam sem abertura
autenticada nesta investigação.
