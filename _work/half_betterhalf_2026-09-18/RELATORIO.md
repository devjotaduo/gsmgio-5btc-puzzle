# Releitura "half and better half": o par de chaves, não a senha de um blob

**Estado: hipótese estrutural, não resolvida.** Não é uma campanha de força bruta — é uma releitura do
alvo, com um teste barato e conceitualmente novo (o par), que deu negativo. Registro aqui porque muda
o critério de sucesso e a direção de qualquer tentativa futura, e porque parte do valor é reconhecer o
que a evidência do próprio criador sugere.

## O reframe

A última linha que a comunidade decodificou da fase 3.2.2 (VIC, `README.md`) é literal:

> IN CASE YOU MANAGE TO CRACK THIS **THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF** AND THEY ALSO
> NEED FUNDS TO LIVE

Chaves no plural. E o prêmio tem **dois** endereços:

- `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` — 1,25 BTC, 126 transações → a *half*;
- `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` — 3,75 BTC, nunca gastou, 3× maior → a *better half*.

Consequência que nunca foi o centro de uma frente: **a SalPhaseIon não produz uma senha para abrir um
blob AES — produz duas chaves privadas de uma vez.** Toda campanha até 18/09 tratou os dois endereços
como filtro de saída de escalares soltos (a §3.11 e a frente `retro_17ucy` inclusive). Ninguém montou
uma operação que emita o **par** `(chave de 1GSMG, chave de 17ucy)` e o valide junto.

Dois indícios reforçam que `dbbi` e `faed` são as duas fontes:

1. `dbbi` (91 símbolos) tem **estrutura provada** — os marcadores `b`/`be` nas posições lógicas primas
   (ENDGAME §6, 0/20.000 no nulo). Tem cara de dado com informação.
2. `faed` (570 símbolos) é **indistinguível de i.i.d.** (ENDGAME §3.3). Um bloco verdadeiramente
   aleatório na página só faz sentido se *for* material de chave (entropia direta) — que é exatamente
   a aparência que uma chave privada tem.

Leitura natural: `dbbi` → uma metade, `faed` → a outra.

## Por que o par é um oráculo melhor

Exigir que **a mesma operação O** dê `O(dbbi) → um alvo` e `O(faed) → o outro` tem probabilidade de
coincidência dupla de ordem 2⁻³²⁰. Isso permite varrer operações paramétricas ou ambíguas que, contra
um alvo só, produziriam candidatos de ruído — sob o critério do par, um acerto espúrio é impossível na
prática. Não é abrir um espaço de busca novo e caro; é um **critério de sucesso mais forte** sobre as
leituras estruturais baratas que o roadmap do criador nomeia (`yellowblueprimes`, `matrixsumlist`,
`yinyang`).

## O teste (negativo)

[`solver/lacunas_2026_09_18/par_half_betterhalf.py`](../../solver/lacunas_2026_09_18/par_half_betterhalf.py):
fontes de `dbbi` (original, invertido, resíduo L84/L83) × fontes de `faed` (original, invertido, as
duas metades yin/yang) — 16 pares de fontes, 560 operações comuns. Cada operação é uma redução
(base 9, base 10 com `o`=0, sha256 dos dígitos, sha256 do cru, sha256²) composta com um passo do
roadmap (identidade, negação N−k, offset e XOR por `matrixsumlist`), testada também cruzada
(`dbbi`→17ucy, `faed`→1GSMG). Critério: `{addr(O(dbbi)), addr(O(faed))} ⊇ {1GSMG, 17ucy}`.

**Resultado: 0.** O controle planta os h160 de dois secrets sintéticos e confirma que o detector do
par dispara. As leituras diretas isoladas (101 variações de `dbbi`/`faed`/resíduo/salts como chave dos
dois alvos) também deram 0.

Isso **não** refuta o reframe — refuta apenas o conjunto pequeno de operações "primeira ordem" testado
aqui. O muro continua sendo o de sempre (ENDGAME §6): qual segmentação de `dbbi` é a pretendida (L83 ou
L84), o que `zeroed out` zera, e como `matrixsumlist` consome o resíduo. É um nó de **interpretação**, e
compatibilidade com i.i.d. em 61 símbolos não prova ausência de informação — só que nenhuma operação
enumerada a extraiu.

## A parte que a evidência do criador sugere e vale encarar

Em 12/07/2026 (ENDGAME §2), três falas juntas:

- *"The 5 btc was never the actual prize"*;
- *"hidden laptop … on that thing is the actual answer"*;
- *"My close friends have the best chance of solving it … NOTE: that is a hint"*.

E o próprio roadmap dele (binário invertido, 2023-02-23) **termina** com
`itsinfrontofyoureyesbutyourenotseeingit` e `verylaststepisatruegiveaway`.

Leitura conjunta, honesta: a cadeia criptográfica é *"salphaseion 100% solvable"* (ele confirmou), mas
o **passo final pode ser não-computacional** — uma referência ao mundo pessoal do criador que "amigos
próximos" reconhecem e que nenhuma varredura força. `itsinfrontofyoureyes…` é auto-referente: o material
visível na página basta; falta a leitura certa, não um dado externo. Se for esse o caso, mais busca não
fecha o último passo, por melhor que seja o oráculo.

## O pipeline ordenado do roadmap (negativo)

Segundo passo da mesma ideia: em vez de testar os tokens do roadmap isolados (como fez todo o
histórico), **encadeá-los**, a saída de um virando a entrada do próximo, terminando na fusão com
`faed` que emite o par.
[`solver/lacunas_2026_09_18/pipeline_roadmap.py`](../../solver/lacunas_2026_09_18/pipeline_roadmap.py):

1. `yellowblueprimes` → dado inicial: resíduo de `dbbi` (L84/L83, comprovado) ou `dbbi` inteiro;
2. `matrixsumlist` → operador: as 28 somas da matriz sobre a lista (soma/subtração mod 10, concatenar,
   selecionar);
3. `lastwordsbeforearchichoice` → keystream: essa string (e `thispassword`, `matrixsumlist`) em a1z26,
   somada à lista;
4. `yinyang` → funde o lado `dbbi` com `faed` (metades, XOR das metades, cru/sha) e reduz a 32 B cada.

144 cascatas sob o critério do par: **0**. Os três últimos tokens do roadmap
(`wewontgiveawaythepassword`, `itsinfrontofyoureyesbutyourenotseeingit`, `verylaststep…`) são
meta-comentário, não operações. Isso fecha a composição de **primeira ordem**; ampliar para milhares
de variantes por passo seria voltar à força bruta, não compor com intenção — e o muro não é de volume.

## O que isto muda para quem continuar

- **Reorientar o oráculo para o par**, não para escalar-contra-alvo. `par_half_betterhalf.py` é o
  arcabouço: basta ampliar `reducoes()`/`modificadores()` com leituras estruturais, e o critério do par
  segura o ruído.
- **Compor o roadmap como pipeline ordenado** (`yellowblueprimes → matrixsumlist → lastwords → yinyang →
  …`), não token a token — que é como tudo foi testado até aqui.
- **Aceitar que o último passo pode ser pessoal.** Nesse caso o trabalho produtivo é decodificar a
  cadeia até a mensagem que ela revela, não recuperar a chave por busca.

Nada aqui pede campanha cara. O gargalo é conceitual: a "ligação desconhecida" da §6.
