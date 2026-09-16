# `lastwordsbeforearchichoice`: fronteiras verificadas

Foram confrontados o texto original da fase 3.2, já conferido nas sessões anteriores, e uma cópia digitalizada do roteiro de *The Matrix Reloaded*, datada de 27/10/2001 na capa. Trata-se de um **roteiro anterior ao filme**, não de uma transcrição autenticada da montagem final. [Fonte do roteiro](https://www.horrorlair.com/movies/scripts/matrixreloaded.pdf).

Arquivo recuperado: 4.402.074 bytes, SHA256 `713d1a593b8025b8a746059b8effe24e5b05f2ea785424b71c328e0468238d07`. A leitura foi visual, nas páginas renderizadas; a extração com `pdftotext` não forneceu texto útil. [Proveniência](draft_provenance.json).

## Leitura local preferida, ainda hipotética

Na fase 3.2, `SELECT` introduz a seleção de cifras, criptografias e senhas. A última oração iniciada por `REINSERTING` imediatamente antes dessa fronteira fornece:

```text
reinsertingtheprimebasicsafterwhichyouwillberequiredto
```

Essa sequência existe no texto do puzzle. A extração usada nesta rodada remove tudo que não for letra e converte para minúsculas. O início da oração é uma escolha semântica documentada, não um comprimento encontrado por busca. Essa variante já havia sido testada em outras composições; nesta rodada entrou somente com os materiais novos.

As quebras de linha do README não pertencem ao texto original recuperado. Por isso não foram usadas como fronteiras ou índices. A seleção do Arquiteto no roteiro aparece na página impressa 121, folha 128 do PDF; a oração do puzzle altera o conteúdo, mas preserva a estrutura da passagem.

## Leitura alternativa: decisão entre as portas

O roteiro distingue três momentos:

1. O Arquiteto apresenta as duas portas na página impressa 122, folha 129 do PDF.
2. Ao fim da fala seguinte, na página 122A, folha 130, a última oração é: “she is going to die and there is nothing you can do to stop it.”
3. A folha 131, página impressa 123, descreve Neo indo à porta esquerda; **a fala sobre Hope vem depois desse movimento**.

A segunda leitura testada foi a oração do item 2, compactada em minúsculas. Ela é uma alternativa delimitada para as últimas palavras antes do movimento de escolha. A fala inteira do Arquiteto é maior e atravessa páginas; usar somente essa oração continua sendo uma interpretação, não uma senha confirmada.

Isso enfraquece a classificação de Hope como fala **anterior** à decisão nessa versão do roteiro. Não exclui seu uso em uma resposta posterior, em `ans too`, ou sob outra interpretação da fronteira. As tentativas anteriores com Hope também não demonstram que a referência correta já tenha sido identificada.

Foram testadas apenas essas duas extrações, com as normalizações declaradas em [consequence_spec.json](consequence_spec.json). Nenhuma abriu SMALL, TAIL32 ou COSMIC nas composições desta rodada. Não foi necessário escolher palavras do poema de Cosmic Duality nem realizar uma nova varredura de sufixos.
