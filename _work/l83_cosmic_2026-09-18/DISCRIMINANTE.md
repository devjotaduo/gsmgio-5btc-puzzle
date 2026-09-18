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

## Força e limite do argumento

**Força.** Não é coincidência numérica solta: a mesma frase nomeia o passo (`prime basics`) e enumera a
repartição (16 e 7). Das duas segmentações que a regra admite, só uma a satisfaz.

**Limite.** É argumento **semântico**, não prova. "Over twenty-three ciphers" pode ser lido como
narrativa do Arquiteto e não como especificação; e nada garante que 16/7 se refira aos tipos de
marcador, embora a proximidade com "reinserting the prime basics" seja forte.

## Consequência prática — pequena, e é preciso dizer isso

**Nenhum resultado muda.** A maioria das campanhas já varria L83 **e** L84 em paralelo, e as que não
varriam já haviam escolhido L84: `prime_host_l84_2026-09-17` (fixou L84 por decisão declarada) e
`zero_free_numerals_2026-09-17` (só L84). Ou seja, o argumento **não abre trabalho novo nem invalida
trabalho velho** — ele converte uma premissa adotada por conveniência em premissa fundamentada, e
com isso justifica retroativamente essas duas campanhas, que até aqui carregavam uma escolha sem razão.

O ganho real é de **prioridade**: onde uma varredura custa o dobro por rodar as duas segmentações, agora
há motivo para gastar em L84 primeiro. A §6 passa de duas incógnitas para uma — resta **como
`matrixsumlist` consome o resíduo** —, mas a incógnita que resta é a cara.
