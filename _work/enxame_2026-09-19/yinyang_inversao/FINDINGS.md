# F6 — `yinyang_inversao`: fechar o eixo da involução, declarar o eixo do par

Campanha `enxame_2026-09-19` (contrato em `../spec.json`). Frente de recuperação de cobertura sobre
a linha `inversão yin-yang (parcial)` da tabela §4-E do `ENDGAME.md`.

**Kit:** `solver/experiments/claude_endgame_2026_09_02/gsmg_common.py` sha256
`f109cd8a41441d7439b18cf60ec72d465a3a446ae03260036672457136932c3a`.

**Procedência e verificação.** Frente executada por subagente, impedida pelo harness de escrever
arquivos de relatório; este `FINDINGS.md` foi materializado pelo coordenador a partir do texto
devolvido. **O coordenador reproduziu de forma independente, com DFS própria, o controle estrutural
da §3:** saem exatamente **2** segmentações, com L84 = 61 símbolos /
`difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae` / tipos `00001000110000100110010`
= **16 `b` + 7 `be`**, e L83 = 60 símbolos / 15 `b` + 8 `be`. Bate byte a byte com §6.
Dados de execução em `summary.json`, `paddings.json` e `segmentacao_invertida.json`.

## 1. O domínio, em prosa (produto principal da frente)

"Inversão" só é operação definida sobre um objeto com **involução canônica**. No material do criador
há quatro, e só quatro, com lastro:

- **C** — complemento do alfabeto a–i: `x → 10−x` (a↔i, b↔h, c↔g, d↔f, `e` fixo). É a **única**
  involução que inverte a ordem de {1..9}; em base 9 (a=0…i=8) vira `x → 8−x`, **a mesma permutação
  de letras**.
- **R** — inversão da ordem de leitura.
- **B** — complemento de bits, com lastro **demonstrado**: o criador publicou o roadmap de
  2023-02-23 em binário invertido. Sobre a matriz, "azul↔amarelo" **é** B (azul=1, amarelo=0,
  provado em §1) — logo troca de cores **não é eixo independente**.
- **M** — espelho da curva `k → N−k`.

C e R comutam e são involuções ⇒ o grupo gerado sobre strings a–i é **{id, C, R, CR}: 4 elementos**;
sobre binários, {id, B, R, BR}. M vive no escalar e entra como os 2 sinais de todo teste de chave.
Com objetos publicados finitos e materializações da gramática das fases, **o domínio é finito e
pequeno**.

O que faz a família *parecer* infinita é o **eixo do par** — quaisquer duas coisas podem ser
chamadas yin e yang (os dois blobs, os dois endereços, os dois `<h1>`, as duas segmentações, as duas
estrelas, as metades de qualquer corte). Esse eixo **não é finito sem arbitrar**, e foi ele que
inflou a família a 265 k senhas. **Não foi reaberto** — enumerá-lo seria campanha sem premissa, o que
a regra 3 proíbe.

## 2. O que já estava coberto — e por que a linha ficou parcial

| Leitura de `yinyang` | Cobertura anterior | Estado |
|---|---|---|
| **Par** (half/better half, blob como senha do outro, cortes, XOR) | 265.362 senhas, 1,60 M AES, 268.511 privkeys | negativo confirmado |
| **Cor** (complemento da matriz, azul↔amarelo) | 945 k AES | **"negativo parcial"** ← é esta a linha `(parcial)` |
| **Fusão** (`dbbi` com `faed`) | 144 cascatas, 16 pares × 560 operações | negativo com limite declarado |
| **Objeto literal** (☯, 陰陽, taijitu) | 754 k senhas; 99.008 testes | fechado |

**Nenhuma dessas ataca a palavra *inversão* como operação — todas atacam a palavra *par*.** É
exatamente aí que a família ficou parcial: "inversão" nunca teve o domínio escrito.

## 3. Ganho estrutural: o eixo de composição some por teorema

Onde a inversão age em relação ao único passo provado (`yellowblueprimes`)? Resolvido
deterministicamente:

- **Controle positivo estrutural:** segmentação reimplementada por DFS devolve exatamente 2
  soluções, idênticas a §4d/§6 (**reconferido pelo coordenador**, acima).
- **Regra literal** (marcador segue `b`/`be`) sobre o objeto já invertido: `C(dbbi)`, `R(dbbi)`,
  `CR(dbbi)`, `C(faed)`, `R(faed)` → **0 segmentações**. "Inverter e depois segmentar" fechado **por
  impossibilidade**.
- **Regra relabelada** (marcador = imagem de `b`): C é bijeção pontual, logo **comuta** com a
  segmentação — os resíduos de `C(dbbi)` são exatamente `C` dos resíduos originais. Nenhum objeto
  novo.

Para C e R, o eixo de composição **não multiplica nada**.

## 4. O conjunto fechado — números exatos

- **16 objetos**: 10 em a–i (`dbbi` 91, `faed` 570, L84 61, L83 60, `dbbi‖faed` 661, `faed‖dbbi`
  661, metades de `faed` 285+285, trocas de metades) + 6 binários (matriz row-major/column-major/
  espiral 196 cada, `cores24`, `cores25` com `#FEFEFE` como azul, `marcadores23`).
- **Grupo de 4** por objeto → **64 pares (objeto, transformação)**.
- **844 senhas distintas**, **5.064 AES** (3 blobs × 2 KDF).
- **336 escalares distintos de 32 B**, cada um já com o espelho **M** (`k` e `N−k`), contra os
  **dois** alvos, pubkey comprimida e não.
- **99.510 janelas raw32** sobre os buffers derivados, **sem filtro de padding**, contra os dois alvos.
- **Padding:** 21 válidos contra 19,86 esperados (5.064/255). **0 candidatos semânticos. 0 no
  oráculo duro.**

```
cd solver/enxame_2026_09_19/yinyang_inversao
python3 fecha_inversao.py --null 100
python3 segmentacao_invertida.py
```

## 5. Controles e nulo

- **Positivo:** fase 2 abre com `sha256hex("causality")` sob EVP-SHA256 (`printable` 0,981); o
  script **aborta** se falhar.
- **Plantado:** h160 de chave conhecida injetado nos alvos; `priv_hit` **e** `fast_priv_scan` a
  recuperaram no interior de um buffer; restaurados os alvos reais, nenhum dispara.
- **Nulo casado:** 100 embaralhamentos dos 16 objetos preservando contagens, pipeline inteiro
  reexecutado (**506.400 AES de nulo**): média 19,88, dp 4,17, observado 21 → **z = +0,27**. Ruído.

## 6. Sobreposição declarada (protocolo, item 5 — não somar duplicatas)

- A linha `id` do grupo é material já varrido por dezenas de campanhas; entra só como âncora.
- `B` sobre a matriz e azul↔amarelo **sobrepõem** os 945 k AES de `frontier_2026-09-17`. **Novo**
  ali: `B` sobre `cores25` e sobre `marcadores23` (palavra que só existe desde 17/09).
- Troca `dbbi`↔`faed` e metades do SMALL **sobrepõem** a família 5 — esses números **não** foram
  somados aos desta frente.
- **C sobre o resíduo como leitura de texto já estava fechado** pelas 3.628.800 bijeções de §6. O
  que esta frente fecha é C como **material de senha** e como **escalar**.

## 7. Limitações do ambiente

Sem scorer de quadgramas (`result.json` ausente): nenhuma triagem por escore foi usada — o que não
altera o veredito, já que escore nunca é prova (regra 1) e o oráculo aplicado foi o duro +
`G.semantic`. Sem GPU, 1 processo. Corpora históricos ausentes, por isso as sobreposições da §6 são
declaradas por leitura dos relatórios, não por reexecução.

## 8. A fronteira que permanece

1. **O eixo do par não é finito sem arbitrar, e não foi fechado.** "Escolha duas coisas e cruze-as"
   tem domínio gerado por escolha livre do solver, não pelo material. **A linha §4-E não deve ser
   declarada "fechada" por enumeração desse eixo.**
2. **As duas estrelas da capa de *Cosmic Duality*** seguem **insumo ausente**, não negativo (a
   família 5 usou `#FEFEFE` como *proxy*; não há imagem no repositório).
3. **Involuções sem lastro:** existem 2.620 involuções sobre 9 símbolos; só `x → 10−x` tem
   justificativa no material. As outras 2.619 são enumeração sem premissa — e, para leituras
   textuais do resíduo, já cobertas pelas 9! bijeções de §6. Fora, deliberadamente.
4. **Composição com passos de operação desconhecida:** o teorema da §3 vale só para o passo
   **provado**. Compor uma involução com `matrixsumlist` ou com o "zeroed out" não é domínio finito.
   Essa é a fronteira real — e ela não é da inversão, é da **indeterminação daqueles passos**.
5. **A ordem do roadmap.** O export de 28/04/2025 (#39237) situa yin-yang **na fase seguinte à
   abertura de AES**. Se estiver certo, a inversão opera sobre um plaintext que ainda não temos, e
   **nenhuma varredura sobre `dbbi`/`faed`/matriz/resíduo pode testá-la** — o negativo desta frente
   seria *vacuamente verdadeiro* para a leitura pretendida. Limite epistêmico que nenhuma cobertura
   fecha.

## 9. Delta proposto para o §4-E (o `ENDGAME.md` **não** foi editado)

Substituir "inversão yin-yang (**parcial**)" por: *eixo da involução fechado — 16 objetos ×
{id, C, R, CR/BR} × gramática das fases: 844 senhas, 5.064 AES, 336 escalares nos dois sinais,
99.510 janelas raw32, 0; composição com `yellowblueprimes` fechada por impossibilidade (0
segmentações sob a regra literal) e por comutação. **Continua parcial só o eixo do par**, que não é
finito sem arbitrar, e as estrelas da capa, que são insumo ausente.*
