# O discriminante L83 × L84 estava na fala do Arquiteto

**Achado: L84 é a segmentação pretendida.** O argumento é documental e direto, não estatístico, e
resolve **metade** da "ligação ainda desconhecida" da §6.

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

## Por que isto não tinha sido usado

O `ENDGAME.md` **menciona** que L84 tem "os números do Arquiteto", mas o teste de desambiguação que ele
narra logo em seguida é o das **cores da matriz** — e conclui, corretamente, que as cores casam com as
duas segmentações e portanto "não desambiguam". A conclusão sobre as cores acabou lida como se nada
desambiguasse.

São dois argumentos independentes:

- **cores** → confirmam a segmentação, não escolhem entre as duas (5 casamentos, não 4);
- **números 16/7** → escolhem, e escolhem L84.

## Força e limite do argumento

**Força.** Não é coincidência numérica solta: a mesma frase nomeia o passo (`prime basics`) e enumera a
repartição (16 e 7). Das duas segmentações que a regra admite, só uma a satisfaz. E o autor usou esses
números de propósito — o ENDGAME já os registra como "os números do Arquiteto".

**Limite.** É argumento **semântico**, não prova. "Over twenty-three ciphers" pode ser lido como
narrativa do Arquiteto e não como especificação; e nada garante que 16/7 se refira aos tipos de
marcador, embora a proximidade com "reinserting the prime basics" seja forte. Não muda nenhum resultado
já obtido: todas as campanhas testaram L83 **e** L84 em paralelo.

## Consequência prática

A §6 listava duas incógnitas. Com isto, resta **uma**: como `matrixsumlist` consome o resíduo. E o
resíduo relevante passa a ser o de **61 símbolos** (L84) — que é o que as varreduras vinham usando como
principal, de modo que nada precisa ser refeito.
