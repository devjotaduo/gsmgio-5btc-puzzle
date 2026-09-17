# Assinaturas do prêmio: nonces pequenos, relacionados ou recorrentes

**17/09/2026 — nenhuma chave recuperada.** Esta abordagem usa as assinaturas
públicas do próprio endereço do prêmio. Não depende de interpretações da
comunidade sobre DBBI, FAED, Bifid ou marcadores primos.

## Fonte e validação

As transações
[88cdb3…9df3](https://mempool.space/tx/88cdb3cdca12b471551b1b26188508a14ca5fd8a415223ffb7c190381c9b9df3)
e [2aa9a4…1b13](https://mempool.space/tx/2aa9a4a90be819d5122d70c993280785a0508f163521e7b38cebb4db0b071b13)
possuem três entradas cada assinadas pela chave pública do prêmio. Os dados
foram obtidos pela API pública do mempool.space; o contrato dos endpoints
é documentado na [API Esplora](https://github.com/Blockstream/esplora/blob/master/API.md).

O extrator conferiu os TXIDs a partir dos bytes brutos, versão, entradas,
saídas, sequências, locktime, DER, tipo SIGHASH_ALL, chave pública e hash160.
Reconstruiu a preimagem legacy de cada assinatura e validou todas as seis
com Node/OpenSSL. coincurve/libsecp256k1 repetiu a validação. Não houve
criação ou transmissão de transação.

Os dados públicos necessários estão no [fixture compacto](inputs/spec.json).
O conjunto validado de paginação local contém 126 transações distintas; a
pesquisa criptográfica usa apenas os dois gastos acima. Os rascunhos locais
`transactions_all.json` e `spending_transactions.json` não são fontes
validadas e não foram usados no extrator.

## Valores pequenos e diferenças/somas pequenas

Para uma assinatura ECDSA `(r,s)` da mensagem `z`, com chave pública `Q`, o
ponto do nonce é calculável sem conhecer a chave privada:

```text
R = s⁻¹ (zG + rQ) = kG
```

Foram construídos seis `R` e as 30 somas/diferenças entre pares. Isso inclui
as possibilidades de sinal introduzidas pela normalização de `s`. Todos
os 36 pontos foram reconstruídos independentemente por libsecp256k1 e
coincidiram com a implementação Go.

Baby-step/giant-step examinou o intervalo assinado
`−2^40 < k < 2^40` para cada ponto: seis nonces pequenos, 15 diferenças e
15 somas pequenas. **Nenhuma correspondência.** O teste preliminar com
limite 2^32 também foi negativo. O limite maior usa 1.048.576 baby steps e
2.097.151 giant steps por alvo; não significa gerar individualmente cada
escalar desse intervalo.

Na busca, toda coordenada X é preservada. Uma coincidência de X é apenas
um filtro: ambos os sinais são conferidos como pontos completos antes de
aceitar o logaritmo. Controles recuperaram uma chave com nonce pequeno e
quatro casos de sinais de nonces grandes cuja diferença era conhecida.
Onze controles cobrem zero, sinais e bordas; quatro valores fora do limite
foram rejeitados.

**Limite da conferência:** o percurso completo de BSGS a 40 bits não foi
repetido em outra biblioteca. Foram conferidos independentemente seus 36
alvos e usados os controles de cobertura/reconstrução acima.

## Recorrência afim de nonces grandes

Foi testada também a hipótese `k_next = A*k + B mod n`, onde `n` é a ordem
secp256k1, com o multiplicador desconhecido `A` compartilhado pelas duas
transações. Cada transação pode começar com semente e incremento `B`
diferentes. Cada lote precisa conter três saídas consecutivas do gerador.

Como cada nonce é uma função linear da chave privada `d`,
`k(d) = z/s + (r/s)*d`, igualar as razões entre diferenças consecutivas
dos dois lotes produz um polinômio de grau no máximo dois em `d`. É
possível resolver todas as raízes no corpo finito, sem adivinhar `A`.

Todas as ordens dos três elementos em cada lote e todas as normalizações
de sinal foram incluídas: `3! × 3! × 2^6 = 2.304` casos. Houve 1.200 casos
com raízes, totalizando **100 candidatos distintos de chave**. Nenhum
gerou a chave pública do prêmio. Não houve polinômio identicamente nulo
que deixasse um conjunto indeterminado de chaves.

Um controle com multiplicador grande desconhecido e incrementos distintos
recuperou a chave escolhida. A conferência Python independente verificou
a cobertura dos 2.304 casos, os coeficientes por avaliação, o número exato
de raízes usando o discriminante e todos os pontos públicos candidatos.

Isso não exclui geradores não lineares, saltos entre saídas, multiplicadores
diferentes entre lotes ou recorrências módulo outro inteiro.

## Reprodução e checkpoints

Na raiz do repositório, extraia o fixture para uma pasta nova:

```powershell
@'
const fs = require('fs');
const data = JSON.parse(fs.readFileSync('_work/prize_nonce_2026-09-17/inputs/spec.json'));
const out = '_work/prize_nonce_repro';
fs.mkdirSync(out);
fs.writeFileSync(out + '/spending_verified.json', JSON.stringify(data.transactions.map(t => t.api)));
for (const t of data.transactions) fs.writeFileSync(out + '/' + t.txid + '.hex', t.rawHex);
'@ | node
node solver/prize_signature_inputs.cjs _work/prize_nonce_repro _work/prize_nonce_repro/inputs
node solver/prize_nonce_recurrence.cjs _work/prize_nonce_repro/inputs/signatures.json _work/prize_nonce_repro/recurrence
```

Para BSGS, Go 1.26.3 e secp256k1/v4 4.4.1, já disponíveis no ambiente:

```powershell
Set-Location solver/prize_nonce_bsgs
go run . -in ../../_work/prize_nonce_repro/inputs/signatures.json -out ../../_work/prize_nonce_repro/bsgs40.json -bits 40
go vet ./...
```

O [resumo](summary.json) reúne os resultados e hashes do código. A
[verificação independente](independent_verification.json) delimita
precisamente o que foi repetido por outra implementação. `go vet` e a
compilação passaram; os controles relevantes executam dentro da busca.
Não há processo desta campanha ainda em execução.

Os testes eliminam três falhas específicas de geração de nonce dentro
dos limites acima. Não demonstram que a chave é irrecuperável e não
resolvem a senha AES final do puzzle.
