# O discriminante L83 × L84 estava na fala do Arquiteto

**Achado: o argumento que justifica L84.** L84 já vinha sendo **adotado** como premissa; o que faltava
era a razão. O argumento abaixo é documental e direto, não estatístico, e resolve **metade** da
"ligação ainda desconhecida" da §6.

> **O que já estava no repositório, para não inflar o achado.** Em 17/09,
> [`prime_host_l84`](../prime_host_l84_2026-09-17/RELATORIO.md) fixou L84 **a pedido do usuário** e
> registrou honestamente o buraco: *"Não foi necessário resolver a ambiguidade com L83 para executar
> esta rodada: L84/A foi fixado explicitamente. **A justificativa dessa escolha continua sendo uma
> hipótese.**"* O `ENDGAME.md` também já anotava que L84 tem "os números do Arquiteto".
> A contribuição desta rodada não é a escolha — é a **justificativa** que aquele relatório declarou
> ausente, mais a reconstrução independente que confere a segmentação byte a byte.

## A frase

Na fase 3.2 (`README.md`, linhas 554–555), a fala do Arquiteto — o mesmo texto que o rótulo
`lastwordsbeforearchichoice` nomeia — diz:

> **REINSERTING THE PRIME BASICS** AFTER WHICH YOU WILL BE REQUIRED TO SELECT FROM OVER
> **TWENTY-THREE** CIPHERS **SIXTEEN** ENCRYPTIONS AND OR **SEVEN** INTERTWINED PASSWORDS TO FIND THE
> ACTUAL PRIVATE KEY

Repare que a frase **começa nomeando o próprio passo**: "reinserting the prime basics" é
`yellowblueprimes`, a segmentação por posições primas. Ela então dá três números: **23, 16 e 7**.

## O que a segmentação produz

Reconstruída do zero e validada contra o resíduo publicado
([RELATORIO.md](RELATORIO.md)):

| | marcadores | `b` | `be` | bate a fala? |
|---|---|---|---|---|
| **L84** | 23 | **16** | **7** | **os três números** |
| L83 | 23 | 15 | 8 | só o 23 |

L84 reproduz **23 = 16 + 7** exatamente como a fala enumera. L83 acerta o total e erra a repartição.

## Por que o argumento não tinha sido formulado

O `ENDGAME.md` **menciona** que L84 tem "os números do Arquiteto", mas o teste de desambiguação que ele
narra logo em seguida é o das **cores da matriz** — e conclui, corretamente, que as cores casam com as
duas segmentações e portanto "não desambiguam". A conclusão sobre as cores acabou lida como se nada
desambiguasse, e a menção aos números ficou como observação solta, nunca como discriminante.

São dois argumentos independentes:

- **cores** → confirmam a segmentação, não escolhem entre as duas (5 casamentos, não 4);
- **números 16/7** → escolhem, e escolhem L84.

O que esta rodada acrescenta ao segundo é a **frase inteira**: ela não só contém 23/16/7, ela **começa
nomeando o passo** — "reinserting the prime basics" é `yellowblueprimes`. Um número solto é
coincidência; um número enunciado imediatamente depois do nome da operação é especificação.

## A ressalva que derruba metade da força — os números são do filme

**Descoberta depois de escrever o acima, conferindo o caderno histórico.** A fala não é do criador: é o
Arquiteto de *Matrix Reloaded*, copiada e editada. O original
([registro de 01/09](../../docs/historico/ENDGAME_cronologico_2026.md), diff palavra a palavra contra
duas transcrições concordantes) diz:

> reinserting the **prime program**. After which you will be required to select from the matrix
> **23 individuals — 16 female, 7 male** — to rebuild Zion.

O criador trocou **só os substantivos**: `prime program → prime basics`, `individuals → ciphers`,
`female → encryptions`, `male → intertwined passwords`, `the matrix → over`. Os números **23, 16 e 7
são herdados do roteiro**, não escolhidos por ele.

Isso desmonta a parte do meu argumento que dizia "a mesma frase nomeia o passo **e** enumera a
repartição, logo é especificação": **essa adjacência é do filme**. No roteiro, "reinserting the prime
program" já vem seguido de "16 female, 7 male". Eu li como desenho do autor o que é estrutura do texto
que ele copiou.

Some-se que **23 não discrimina nada**: π(83) = π(84) = 23, então o total de marcadores é consequência
aritmética do comprimento, idêntico nas duas segmentações. Resta só a repartição.

## Força e limite, reavaliados

**O que sobra de força.** Das duas segmentações que a regra admite, só L84 reproduz a repartição
16/7 — L83 dá 15/8. O autor demonstrou estar trabalhando com essa fala (usou-a inteira, como plaintext
da 3.2), então mirar a repartição ao desenhar `dbbi` é plausível e barato dentro da regra 4. O argumento
passa a ser **condicional**: *se* ele desenhou para bater os números do roteiro, então L84.

**O que caiu.** A premissa desse "se" não tem evidência independente. E o prior não é desprezível: as
duas segmentações diferem por um único token, logo suas repartições são sempre adjacentes — dado que
uma delas ia cair perto de 16/7, que a vizinha exata batesse é menos surpreendente do que parecia.

**Limite que já estava.** É argumento **semântico**, não prova. "Over twenty-three ciphers" pode ser
narrativa e não especificação, e nada garante que 16/7 se refira aos tipos de marcador.

## Consequência prática — pequena, e é preciso dizer isso

**Nenhum resultado muda.** A maioria das campanhas já varria L83 **e** L84 em paralelo, e as que não
varriam já haviam escolhido L84: `prime_host_l84_2026-09-17` (fixou L84 por decisão declarada) e
`zero_free_numerals_2026-09-17` (só L84). Ou seja, o argumento **não abre trabalho novo nem invalida
trabalho velho** — ele converte uma premissa adotada por conveniência em premissa fundamentada, e
com isso justifica retroativamente essas duas campanhas, que até aqui carregavam uma escolha sem razão.

O ganho real é de **prioridade**: onde uma varredura custa o dobro por rodar as duas segmentações, há
motivo para gastar em L84 primeiro. Com a ressalva da proveniência, esse motivo é mais fraco do que a
primeira versão desta nota dizia, mas não some — nada mudou a favor de L83.

A §6 **não** passa de duas incógnitas para uma. A segmentação continua sem prova; o que ela ganhou foi
uma razão condicional para a escolha já em uso. A incógnita cara — **como `matrixsumlist` consome o
resíduo** — segue inteira.

## O que isto custou e o que ensina

Este documento foi corrigido **duas vezes** depois de publicado: primeiro por inflar a novidade (L84 já
era premissa adotada), depois por inflar a força (os números são do roteiro). As duas correções vieram
de ler o próprio repositório — o relatório de 17/09 e o caderno histórico —, não de dado novo.

A lição operacional é a regra 3 do `AGENTS.md` levada a sério: **conferir o que já está registrado antes
de afirmar, não só antes de codar.** O caderno histórico é declarado "só para arqueologia", mas continha
os dois fatos que decidiam o peso deste achado.
