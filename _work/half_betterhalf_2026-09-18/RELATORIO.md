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

## A evidência do criador: o que ela realmente diz (revisado com o export verbatim)

**Correção.** Uma versão anterior deste relatório leu as falas de 12/07/2026 como indício de que o passo
final seria *não-computacional*, e citou `itsinfrontofyoureyesbutyourenotseeingit` como fala dele. As
duas coisas estão erradas, e a conferência verbatim no export desfaz ambas.

`itsinfrontofyoureyes…` é token do **roadmap de 2023-02-23**, não fala de 2026; não há nenhuma
ocorrência do criador com essa frase nos exports (os ~30 hits são solvers citando o roadmap).

Quanto às três falas: são de **uma única noite de bar** (21:17–22:30, ele declaradamente bêbado às
21:26), e o contexto desarma a leitura fácil — o detalhamento está na nota de contexto da §2 do
`ENDGAME.md`. Em resumo:

1. **O laptop é sobre a memória dele.** Responde a "você só aparece quando há hint", logo depois de *"A
   day later I can hardly understand what I have done. And that is not a joke"*. Significa *o gabarito
   que perdi está lá*, não *a peça que falta está lá*.
2. **No mesmo fio ele afirma solubilidade**: "Yes" a *salphaseion is 100% solveable?* e *"I've verified
   many times back then … it's all still solvable with a few stable qubits"*. Se dependesse do objeto
   físico, seria afirmação vazia.
3. **Os halvings de 2024** implicam que ele opera as chaves por outro meio — contradição levantada no
   grupo e nunca respondida.

O hint marcado (`NOTE: that is a hint`) está sobre **close friends**, e é paradoxal de propósito: eles
têm mais chance **apesar de não terem a habilidade técnica** do grupo. O que têm é o **vocabulário**
dele. Ou seja, o hint anuncia uma **classe de senha** — palavra ou expressão de registro
pessoal-informal, do mesmo universo de `causality` e `thematrixhasyou` — e **não** impossibilidade.

**Consequência para a estratégia:** isto é evidência *a favor* de continuar a criptoanálise, com o
orçamento dividido entre mecanismo e **listas de candidatos semânticos** dentro do teto da regra 4
(ferramentas online, poucas camadas). A família "referência pessoal" já foi atacada com 104 itens
públicos (§4-C, 1,7 M candidatos, 0), o que reduz mas não esgota essa classe. Perseguir identidade,
locais ou o objeto é interdito pela regra 6 e sem valor operacional.

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

## A "transformação não identificada" do resíduo, atacada de frente (negativo)

O fluxo comprovado é `dbbi → segmentação pelas posições primas → L83/L84 → resíduo de 60/61 símbolos
→ ???`. [`solver/lacunas_2026_09_18/residuo_leituras.py`](../../solver/lacunas_2026_09_18/residuo_leituras.py)
ataca o `???` com as duas leituras que o **próprio criador ensinou ou apontou**, com controle validado
e escore pelo `clean_scorer` (o scorer original inflaria a leitura identidade, rica em a–i):

**(1) a1z26 com segmentação ambígua.** O criador escreveu *"R=18 / A=1 / B=2. Could also be 21 or
1812"* — ou seja, `1,8,1,2` ou `18,12`: a ambiguidade de fronteira. Aplicada ao resíduo (dígitos 1–9
lidos como números 1–26, enumerando todas as fronteiras), o espaço é **minúsculo**: 16 segmentações em
L84, 8 em L83. Só os poucos `1` e `2` geram bifurcação; o resto dos dígitos (3–9) é forçado. Melhor
escore: **−6,904** (L84) e **−6,925** (L83) — e o "melhor" é a própria leitura identidade. Inglês real
no mesmo scorer: **−3,748**. Não há texto, e a dica "1812" não abre o resíduo.

**(2) Método literal da página.** `Substitute(a–i,o → 1–9,0)` → `To_Base(16)` → `From_Hex`, que é
exatamente o que decodificou `lastwordsbeforearchichoice` e `thispassword` (o controle reproduz os dois
verbatim a partir dos números documentados no README). Sobre o resíduo: 26 bytes com **31 %**
imprimíveis em L84, 25 bytes com **44 %** em L83 — lixo binário. O resíduo não tem `o`, então não há
zeros naturais; é aí que entraria o *"some characters need to be zeroed out"*, e essa varredura
(escolher quais símbolos viram 0) já está no histórico como negativo.

Composição do resíduo, para registro: `e` 11, `f` 10, `g` 10, `c` 8, `h` 8, `i` 5, `d` 4, `a` 3, `b` 2
(L84); soma a1i9 = 341 (L84) e 336 (L83). Desvio da uniformidade não é significativo (χ² p 0,11, §6).

**O que isso diz.** Não é "falta rodar a operação certa": as duas leituras que o criador *ensinou* para
esse tipo de segmento produzem lixo, e o espaço da dica "1812" tem 24 leituras no total. O `???` não é
um buraco de enumeração — é um nó de **interpretação**.

## "Zeroed out": o último buraco enumerável, fechado

O criador disse (2021-12-26) que *"prime numbers … definitely required to proceed"* e que *"some
characters need to be 'zeroed out'"*. Os primos já são o `yellowblueprimes`, provado. Faltava a
zeragem: o histórico varreu zerar **um** e **dois** tipos de símbolo; três ou mais nunca tinha sido
coberto no alfabeto literal.

O espaço inteiro é pequeno — 2⁹ = 512 subconjuntos de `{a..i}` — e
[`residuo_zerados.py`](../../solver/lacunas_2026_09_18/residuo_zerados.py) roda **todos**, inclusive os
de tamanho 0, 1 e 2 para reconciliar com o histórico, em L84 e L83, na ordem publicada e invertida.
São 2.044 leituras de zeragem e 6.132 escalares, com três leituras por caso: o método literal da
página, a chave privada (decimal mod n, sha256 dos dígitos, sha256 dos bytes) contra os dois alvos nas
duas formas de pubkey, e o critério do par com as leituras de `faed`.

**Resultado: 0 chaves, 0 pares e 0 textos.** Nenhuma das 2.044 leituras produz um único plaintext com
≥ 85 % de imprimíveis; o melhor de todo o espaço é **0,72**, zerando `a` e `g` em L83 — e não é texto.
Controles: o leitor da página recupera um ASCII plantado e o oráculo de chave acha um h160 plantado.
Tempo: 2,6 s.

Isto encerra o item "o que `zeroed out` zera" da *ligação desconhecida* de §6, não por amostragem, mas
por exaustão do espaço.

## O que isto muda para quem continuar

- **Reorientar o oráculo para o par**, não para escalar-contra-alvo. `par_half_betterhalf.py` é o
  arcabouço: basta ampliar `reducoes()`/`modificadores()` com leituras estruturais, e o critério do par
  segura o ruído.
- **Compor o roadmap como pipeline ordenado** (`yellowblueprimes → matrixsumlist → lastwords → yinyang →
  …`), não token a token — que é como tudo foi testado até aqui.
- **Aceitar que o último passo pode ser pessoal.** Nesse caso o trabalho produtivo é decodificar a
  cadeia até a mensagem que ela revela, não recuperar a chave por busca.

Nada aqui pede campanha cara. O gargalo é conceitual: a "ligação desconhecida" da §6.
