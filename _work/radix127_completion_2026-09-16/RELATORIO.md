# FAED/base 127: busca concluída

**Nenhuma senha final encontrada.** A busca que estava parcial foi
concluída: há **exatamente 188 saídas** no repertório declarado, incluindo
os 177 candidatos anteriores. Os onze candidatos novos também foram
testados, sem resultado autenticado. Todos os processos terminaram com
saída 0; não há máscaras pendentes nesta hipótese.

## Escopo preservado

O campo FAED original completo é convertido com `a=1,…,i=9`, mas cada
um de seus 107 `g` pode valer 0 ou 7 independentemente. O número decimal
resultante é escrito em base 127, sem zeros iniciais; cada dígito dessa
base deve ser TAB, LF, CR ou ASCII 32–126. Isso é uma hipótese de conversão,
não uma interpretação comprovada da fala do criador sobre ASCII 127.

Não há cortes de cabeçalho, troca de alfabeto, seleção de palavras ou
deslocamentos de códigos. As 188 saídas têm 271 caracteres e começam por
`9i` ou `9j`, como previsto pela análise anterior de prefixos. Ser ASCII
é a condição imposta pela busca e não demonstra uma mensagem intencional.

## Como a lacuna foi fechada

O ponto de retomada antigo correspondia a aproximadamente 92,2853% da
ordem binária das máscaras. A implementação anterior recalculava os
caracteres iniciais já fixados a cada nó.

A nova implementação conserva o prefixo base 127 que já foi verificado
e o remove dos intervalos descendentes. No primeiro dígito que varia,
decide se existe uma cadeia permitida no intervalo usando os menores e
maiores sufixos legais. Isso preserva a exatidão e reduz o trabalho por nó.

Foi gerada uma prova de **todo o domínio**, em arquivo separado, sem
sobrescrever o registro parcial antigo. A prova tem 4.176.355 nós e
2.087.990 intervalos rejeitados. Ela cobre as `2^107` máscaras:

```text
Total:     162259276829213363391578010288128
Rejeitadas:162259276829213363391578010287940
Candidatas:188
Pendentes: 0
```

Esses totais representam a cobertura por intervalos, não a enumeração
individual de todas as máscaras. O produtor levou cerca de 8,7 segundos.

## Conferência independente

Outro programa conta exatamente quantas cadeias legais de base 127
existem em cada intervalo, pela diferença de duas funções de contagem
por dígitos. Ele não importa o produtor. Conferiu todos os nós da árvore,
todos os intervalos rejeitados, a cobertura integral e cada candidato.

Cada candidato foi reconstruído de ASCII para inteiro e comparado ao
padrão decimal de FAED. Os 177 candidatos antigos reaparecem com os mesmos
bytes. Os onze novos ficam depois do checkpoint antigo. Os hashes
confirmam que o diário anterior não foi alterado.

O produtor passou por 1.600 intervalos pequenos enumerados, dezoito
comparações de todas as máscaras e três textos plantados. O verificador
tem mil intervalos de controle adicionais. Sua conferência integral levou
cerca de treze segundos.

- [Especificação e controles](spec.json), [resumo](summary.json).
- [Árvore de certificados](tree.bin), [todas as 188 saídas](hits.json).
- [Verificação integral](verification.json).
- [Buscador](../../solver/radix127_completion.cjs),
  [verificador](../../solver/verify_radix127_completion.cjs).

Hash da árvore:
`a9945db649ba377d822eace4466f041907915475728f19d7dd479ece810a0db5`.

## Testes dos onze textos novos

Mantiveram-se as quatro formas declaradas na rodada anterior: texto
original, sem whitespace, minúsculo e maiúsculo. Cada uma foi testada
diretamente e como SHA256 hexadecimal minúsculo.

- 44 materiais e 88 senhas novas, sem duplicação com as senhas antigas;
- **528 decisões AES**, três blobs e EVP_BytesToKey SHA256/MD5;
- cinco paddings aceitos, nenhum resultado validado; o maior percentual
  no repertório imprimível ampliado foi 40,51%;
- **16.276 escalares distintos nesta rodada**, incluindo hashes das
  senhas e janelas dos materiais/corpos, nas duas ordens de bytes;
  nenhum corresponde à chave pública do prêmio ou ao seu negativo.

Python/PyCryptodome refez todas as transformações, senhas, decisões AES e
corpos; coincurve/libsecp256k1 refez o conjunto de escalares e comparações.
A fase 3.2 conhecida e o HASH160 da chave pública foram os controles.
[Resultados](new_candidate_auth.json),
[conferência independente](new_candidate_auth_verification.json).

Somadas à rodada anterior, as 188 saídas forneceram **1.504 senhas
distintas e 9.024 decisões AES**, sem abertura autenticada. As contagens
de escalares das duas rodadas não são somadas como se fossem globalmente
distintas. Padding isolado continua sem provar uma senha.

## Leitura em sete bits / base 128

Para a conversão decimal direta em base 128, os intervalos completos
fixam o primeiro código em 1 para DBBI nos dois sentidos, 6 para FAED
original e 4 para FAED inverso. Esses controles não pertencem ao
repertório textual declarado. A exclusão vale para todas as máscaras
`g=0/7` desses quatro casos, sem cortar bits ou caracteres iniciais.
[Limites exatos e prefixos](base128_prefixes.json).

Esta rodada fecha a única busca antes pendente entre os dois campos
originais e as 55 bases primas até 257. As outras 109 exclusões permanecem
documentadas na [análise anterior](../shared_numeric_2026-09-11/RELATORIO.md).
Não exclui outras codificações, usos de primos, mapas de símbolos ou
operações que combinem campos antes da conversão.

Para conferir a árvore já salva:
`node solver/verify_radix127_completion.cjs`.
Os produtores recusam sobrescrever suas saídas. Não é necessário retomar
o antigo processo parcial para esta mesma hipótese.
