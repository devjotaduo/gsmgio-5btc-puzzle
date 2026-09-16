# Correção do teste histórico de recuperação de assinaturas

16/09/2026. **Nenhuma senha ou chave final validada.** O resultado negativo
antigo de `solver/gsmg_sig_recover.py` era inválido. Uma repetição corrigida
das mesmas 43 mensagens também não encontrou os endereços procurados.

## Defeitos do teste antigo

O programa passava `recid=` para `PublicKey.from_signature_and_message`.
Na API instalada, esse argumento não existe: o identificador de recuperação
deve ser o último byte da assinatura de 65 bytes `r || s || recid`.
O erro era capturado e ignorado, impedindo a recuperação de qualquer chave.

Além disso, a literal `GSMGJH` tinha somente 64 bytes: faltava o cabeçalho
`0x20`, que coincide com o código ASCII de espaço. Os bytes brutos da
transação preservam esse byte. Não se pode concluir que houve uma operação
de trim no histórico; a causa da omissão não foi identificada.

O arquivo antigo foi preservado, SHA256
`fe3e9b3c2c5b467d66b78ca6ac03f1104d7ae69b0fe8340bdb3212ded20753dd`.

## Fontes e repetição corrigida

Foram arquivadas as transações brutas e os metadados do Blockstream:

- [GSMGJH, transação 808f812f…](https://blockstream.info/tx/808f812f13a3137e48a0c95a818ae661a80fafaf409237efbb4b62b8198a4c13).
- [GSMGBH, transação 22381b60…](https://blockstream.info/tx/22381b6013973fedbe7821eb82e60d50ef61ee6e430896bd47f209b12157614b).

Em ambos os casos, o OP_RETURN contém seis bytes de identificação e 65
bytes de assinatura. Os cabeçalhos reais são `0x20` e `0x1f`. Os txids
foram recalculados por SHA256 duplo dos bytes serializados; os scripts
foram comparados com os metadados, por dois parsers independentes.

As **43 mensagens** foram extraídas da AST do programa antigo, sem
executá-lo. Para cada uma das duas assinaturas, testamos os oito cabeçalhos
27..34: **688 configurações**. Houve 344 recuperações de chaves públicas e
344 ramos impossíveis porque a coordenada candidata `r+n` excede o primo
do campo. Dos resultados recuperados, 86 usam os cabeçalhos originais.
A substituição dos cabeçalhos é apenas um teste diagnóstico adicional.

Todas as 344 assinaturas recuperadas foram verificadas com a biblioteca
Python `ecdsa`, além da recuperação via coincurve. Um controle com chave
conhecida validou a chamada corrigida. Um segundo verificador, Node/OpenSSL,
reconstruiu o hash Bitcoin Signed Message, validou cada assinatura e
recalculou todos os endereços P2PKH. Também verificou a cobertura das
configurações e a impossibilidade dos ramos `recid=2,3`.

**Zero correspondências** com os quatro endereços declarados no experimento:

```text
1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
1GSMG9VDLTU6jyuG7bkNMdmnHBLtbbM51M
1GSMG1ABC95GES4k9UZCLtz6CYCUL8LUV2
3GSMG24TujqfMJG1kQoBX18DzJHQLeJYMK
```

Recuperar uma chave que verifica uma mensagem escolhida não autentica
o remetente: a recuperação pode produzir uma chave para outra mensagem.
Este negativo cobre somente a lista de 43 mensagens. A verificação
Node/OpenSSL valida assinaturas e endereços, sem implementar uma segunda
recuperação independente da paridade de R.

## Autoria das mensagens na blockchain

O histórico atribuiu o endereço `3GSMG24…` ao criador pela aparência dos
OP_RETURNs. Essa autoria não foi autenticada e a associação foi corrigida.
Em 28/08/2023, ArchOptic escreveu que Jrk havia declarado que as mensagens
na blockchain não eram dele nem parte do puzzle (#12580); Jrk respondeu
“Correct” em 29/08/2023 (#12653). Essa confirmação refere-se à conversa
de 2023 e não autentica nem exclui automaticamente posts posteriores.
As duas mensagens estão preservadas em [creator_context.json](creator_context.json).

## Artefatos e conferência

```powershell
node solver/verify_signature_recovery.cjs
```

[Mensagens candidatas](messages.json), [todos os casos](recovery_cases.json),
[manifesto da repetição](verification.json),
[verificação Node/OpenSSL](openssl_verification.json),
[programa verificador](../../solver/verify_signature_recovery.cjs).

Os arquivos `.hex` e `.json` nomeados pelos txids estão nesta pasta.
SHA256 do verificador: `e50f9d52f746e3b54ce45dd3c692b2e0f26c35039dbf84318ec645b4ab79bea5`.
SHA256 dos casos: `45810ce6fe3ca00bb9b7705fad53192b547a1d72e398ed4206471e1c5bd45709`.
