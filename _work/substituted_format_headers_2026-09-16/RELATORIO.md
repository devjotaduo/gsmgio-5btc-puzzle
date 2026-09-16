# Assinaturas de compactação com dígitos desconhecidos

**Nenhuma senha final foi encontrada.** Este teste exclui cinco famílias de
cabeçalhos na leitura decimal descrita abaixo. Zlib ainda passa por essa
restrição; seus exemplos compatíveis não constituem descompactações.

## Hipótese e cobertura

Cada campo completo, DBBI ou FAED, é lido na ordem original ou inversa como
um inteiro decimal. As letras `a..i` podem representar qualquer bijeção dos
dígitos `1..9`. São escolhidas zero, uma ou duas letras cujas ocorrências
podem, independentemente, valer zero ou o dígito atribuído à letra.

O inteiro é convertido em bytes mínimos, do mais significativo para o menos
significativo. Exige-se que esses bytes comecem por uma assinatura de arquivo.
Os 46 conjuntos possíveis de letras zeráveis, quatro campos/sentidos e seis
formatos produzem **1.104 casos**. Todos foram concluídos e conferidos.

| Formato | Restrição inicial | Casos compatíveis / 184 |
|---|---|---:|
| GZIP com DEFLATE | `1f8b08` | 0 |
| Zlib com DEFLATE | CMF/FLG válidos, janela até 32 KiB | 110 |
| ZIP | qualquer prefixo `504b` | 0 |
| bzip2 | `BZh1` a `BZh9` | 0 |
| XZ | `fd377a585a00` | 0 |
| 7z | `377abcaf271c` | 0 |

GZIP e zlib seguem respectivamente os cabeçalhos dos
[RFC 1952](https://www.rfc-editor.org/rfc/rfc1952.html) e
[RFC 1950](https://www.rfc-editor.org/rfc/rfc1950.html). Para ZIP, a restrição
foi deliberadamente mais permissiva que um registro completo: apenas `PK`,
conforme as assinaturas na
[especificação PKWARE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).
As demais referências estão no
[manual bzip2](https://sourceware.org/bzip2/manual/manual.html), na
[especificação XZ](https://tukaani.org/xz/xz-file-format.txt) e na
[descrição de recuperação 7z](https://www.7-zip.org/recover.html).

## Como foi provado

Uma assinatura e um comprimento de bytes delimitam um intervalo de inteiros.
O limite decimal inferior permite zerar todo o trecho inicial composto das
letras selecionadas; a primeira letra fora desse conjunto precisa ser
positiva. O limite superior usa apenas o comprimento completo do campo.
Os limites são conservadores, e todos os comprimentos possíveis são cobertos.

Dentro de cada intervalo, a busca acompanha posição decimal, igualdade com
os extremos e atribuições parciais dos dígitos. Um zero é permitido somente
nas letras selecionadas. Um dígito positivo deve respeitar a bijeção. Quando
o prefixo já fica estritamente entre os extremos, qualquer preenchimento
legal do sufixo fornece uma testemunha. As rejeições preservam todas as
ramificações legais num certificado, compartilhando estados já rejeitados.

Houve **7.460 intervalos e 28.281 nós**: 6.642 intervalos rejeitados e 818
com testemunhas completas. Esses 818 intervalos pertencem aos 110 casos
zlib compatíveis. Os demais cinco formatos foram excluídos em todos os casos.

O verificador não importa a implementação da busca. Reconstitui os formatos,
intervalos e cobertura; confere cada ramificação das rejeições e valida todas
as testemunhas por inteiro, inclusive a bijeção, os zeros, os bytes e o
cabeçalho. A busca também passou por 96 casos pequenos enumerados diretamente
e 36 inteiros plantados. Os controles internos não substituem a conferência
independente dos certificados da campanha.

## O que continua aberto

Nos casos zlib há 546 intervalos compatíveis sem dicionário indicado e 272
com o bit FDICT ativo. Esses números contam intervalos, não mensagens nem
chaves distintas. O cabeçalho não valida o fluxo DEFLATE nem o checksum.
Nenhuma descompactação foi produzida ou enviada aos oráculos AES nesta etapa.

Uma [etapa posterior sobre o fluxo zlib](../substituted_zlib_2026-09-16/RELATORIO.md)
excluiu a leitura sem zeros e sem dicionário por enumeração independente de
1.451.520 configurações. A ampliação com zeros continua inconclusiva.

O resultado não cobre ordem inversa dos bytes, símbolos removidos, cabeçalhos
omitidos, prefixos adicionais, outras bases, três ou mais letras zeráveis ou
outros formatos. Em particular, não exclui DEFLATE bruto. Também não demonstra
que compactação seja a operação pretendida pelo criador.

## Reprodução e artefatos

```powershell
node solver/substituted_format_headers.cjs
node solver/verify_substituted_format_headers.cjs
```

- [Especificação e controles internos](spec.json).
- [Casos, testemunhas e certificados](cases.json).
- [Resumo](summary.json).
- [Verificação independente](verification.json).
- [Implementação da busca](../../solver/substituted_format_headers.cjs).
- [Verificador](../../solver/verify_substituted_format_headers.cjs).

SHA256 dos casos:
`06e030ae52019395159f4bd7b2604b425528fc59c5ee984fdfbd44b06c6f884a`.
