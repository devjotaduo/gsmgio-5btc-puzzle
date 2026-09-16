# FAED como lista de números em bases primas: prefixos

**Nenhuma senha final.** Foi concluída e conferida uma hipótese que antes
tinha apenas limites necessários: FAED como concatenação decimal dos 14
números obtidos ao ler linhas ou colunas da matriz numa base prima.

Este relatório cobre a ordem original ou inversa das linhas/colunas. A
[ampliação para qualquer permutação](../positional_prime_order_2026-09-16/RELATORIO.md)
está documentada separadamente.

## Modelo

- Uma única base prima `r` para toda a matriz.
- Dígitos primos uniformes `B` e `Y` para azul e amarelo, `2 ≤ B,Y < r`.
  Os dois podem ser iguais.
- Valores fixos 0 ou 1 para preto e branco, escolhidos independentemente.
- Leitura por linhas ou colunas, com a mesma orientação interna direta ou
  inversa em todas elas; concatenação das 14 representações decimais mínimas.
- FAED no sentido original ou inverso; qualquer bijeção `a..i → 1..9`.
  Ocorrências de até duas letras selecionadas podem representar zero em vez
  de seu dígito positivo. Não há separadores nem dígitos removidos.

A pista de primos e o nome `matrixsumlist` motivam a investigação. A leitura
posicional e a condição de cores menores que a base continuam sendo hipóteses,
não instruções atribuídas ao criador.

O [estudo dos comprimentos](../positional_prime_bases_2026-09-16/RELATORIO.md)
delimitou todos os primos possíveis, sem escolher um teto arbitrário. Dois
dos 16 perfis não admitem base. Nos demais, há 6.975 pares perfil/base, com
bases entre 1.181 e 29.501. Esses intervalos também foram reconferidos aqui.

## Restrição que evita enumerar todos os pares

Para uma linha fixa, o valor é `A(r)·B + C(r)·Y + D(r)`, com coeficientes
inteiros não negativos. Fixar o primo da cor com coeficiente maior e deixar
a outra cor variar por todos os seus primos produz um intervalo numérico.
Se os extremos têm o mesmo comprimento, seus dígitos decimais iniciais
comuns aparecem em **todos** os valores dentro do intervalo.

Esse começo precisa ser compatível com o começo de FAED. Uma letra não pode
receber dois dígitos positivos diferentes, dois símbolos não podem receber
o mesmo dígito positivo, e zeros não podem exigir mais de duas letras zeráveis.
Qualquer contradição rejeita simultaneamente todos os primos da outra cor.

Exemplo reproduzível: primeira linha, base 8.377, azul 2 e preto/branco 0.
Para todo primo amarelo de 2 a 8.369, o número começa por `484`. FAED começa
por `fae`. Isso exigiria `f=4` e `e=4`, contrariando a bijeção. A possibilidade
de zeros não altera esses três dígitos positivos. [Valores exatos](example.json).

## Resultado concluído

Os primeiros números das listas na ordem original e inversa correspondem
às linhas/colunas 0 e 13. Foram examinados todos os 13.950 casos de
perfil/base/primeira linha, com 27.310.080 valores de primo dominante.
Os dois sentidos do campo geraram **54.620.160 certificados de intervalo**.
Nenhum intervalo permaneceu compatível.

Eles abrangem 118.276.063.712 cenários de parâmetros de base, cores, perfil,
ordem original/inversa e sentido do campo. **Esse número conta a cobertura
dos intervalos, não tentativas individuais executadas**, nem textos distintos.
Todos os mapas de dígitos e escolhas de até duas letras zeráveis estão
implicitamente cobertos pelas contradições, sem enumeração de alfabetos.

O verificador independente não importa o buscador. Recalcula os coeficientes
com potências explícitas, os primos por divisão, os extremos necessários da
base e cada prefixo numérico por divisão inteira. Confere a contradição como
uma relação entre posições do texto, em vez de repetir o atribuidor de mapas
do buscador. Todos os certificados e a cobertura passaram.

A implementação também passou por 3.072 modelos pequenos de substituição
enumerados diretamente e 96 controles com números plantados da matriz.

## Reprodução e limites

```powershell
node solver/positional_prime_prefix.cjs
node solver/verify_positional_prime_prefix.cjs
```

O produtor recusa sobrescrever resultados existentes. O verificador pode
ser repetido sobre os arquivos preservados.

- [Especificação e controles](spec.json).
- [Resumo](summary.json).
- [Verificação independente](verification.json).
- [Buscador](../../solver/positional_prime_prefix.cjs).
- [Verificador](../../solver/verify_positional_prime_prefix.cjs).

O resultado não cobre cores maiores ou iguais à base, bases não primas,
pesos variados por célula, orientações diferentes por linha, separadores,
transformações anteriores ou outro uso da lista. Não houve material para
testar como senha AES. O método pretendido para `matrixsumlist` permanece
desconhecido.
