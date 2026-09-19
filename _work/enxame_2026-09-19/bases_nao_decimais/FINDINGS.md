# F11 — bases_nao_decimais

Campanha `enxame_2026-09-19`. Frente F11 (`spec.json`). Lacuna: `ENDGAME.md` §6, em texto —
"Com isso as leituras textuais do resíduo estão esgotadas; continuam fora apenas bases não
decimais e objetos que não sejam texto". Esta frente cobre a primeira metade.

## Hipótese

O resíduo `dbbi` fora das posições primas (L84, 61 símbolos; L83, sem o `e` final, 60 símbolos)
codifica um número, senha ou chave quando seus símbolos a–i são lidos como dígitos de uma base
diferente de 10, em vez de decimal (já fechado em §6 pelas três leituras naturais: a1z26 com
pares, ASCII decimal, `To_Base(16)` da própria página).

## Derivação algébrica das bases admissíveis (produto principal desta frente)

Repertório real do resíduo (conferido por contagem, não assumido):

```
L84: a×3 b×2 c×8 d×4 e×11 f×10 g×10 h×8 i×5   (todas as 9 letras a–i ocorrem, inclusive 'a' e 'i')
L83: idêntico, e×10 em vez de e×11
```

Duas convenções de dígito são possíveis para o alfabeto a–i (9 letras):

- **conv1** — `a=1 … i=9` (a mesma do método `z_method` da página, "a=1..i=9"). Nunca tem
  dígito 0 **por construção do alfabeto**: não há letra que valha 0 nesta convenção — é
  exatamente a numeração **bijetiva** de base 9 (dígitos 1..k, sem zero).
- **conv2** — `a=0 … i=8` (mapeamento padrão, posicional, para uma base cujo alfabeto de
  dígitos tem 9 símbolos). Aqui 'a' vale 0, e 'a' **ocorre** no resíduo (3× em L84/L83) — logo
  esta convenção *tem* zero; o argumento "sem 'o' → sem zero" de §6 não se aplica a ela, é só
  o mapeamento natural alternativo para base 9.

**Prova de impossibilidade por repertório (determinística, sem busca):** o resíduo contém a
letra `i`. Em conv1, `i=9`; em conv2, `i=8`. Para uma base posicional `b`, todo dígito precisa
ser `< b`. Logo:

- conv1 exige `b ≥ 10` (dígito 9 presente);
- conv2 exige `b ≥ 9` (dígito 8 presente).

**Conclusão: as bases 2..8 são impossíveis nas duas convenções, sem exceção** — eliminadas só
pela contagem de símbolos, custo zero. Verificado no script (`bases_nao_decimais.py`, seção
"prova de impossibilidade").

Isso deixa:

- **base 9**: é a única base **forçada pela álgebra**, e de duas formas independentes — conv1
  dá a numeração **bijetiva** de base 9 (sem zero por definição, o encaixe exato do argumento
  "sem `o`" quando generalizado do alfabeto a-i-o de 10 símbolos para o alfabeto a-i de 9); conv2
  dá a base 9 **padrão** (0..8), motivada por ser exatamente o tamanho do alfabeto disponível.
  Note-se que a **cobertura anterior de base 9** em §4-B ("Codificações sem zero (base 9
  bijetiva…)", 11,6 M modelos, cobertura parcial) é sobre o **DBBI inteiro** (91 símbolos, como
  senha) e testa só o melhor caminho por modelo — **não** é o mesmo objeto nem o mesmo teste
  desta frente (o resíduo de 60/61 símbolos, convertido para inteiro/bytes e testado como senha
  literal e como escalar). Não há sobreposição de contagem a descontar.
- **base 10**: decimal, fora de escopo — já fechada em §6 pelas três leituras naturais.
- **bases ≥ 11**: tecnicamente não excluídas pelo repertório (nenhum dígito do resíduo excede
  `b-1`), mas a ausência de zero **não é mais um argumento forçado** para elas — qualquer base
  ≥ 10 "por acaso" não teria dígito 0 numa amostra de 60/61 símbolos sem que isso signifique
  nada. É uma família infinita e não motivada pela álgebra. Pela regra 4 (teto de complexidade:
  o criador usou ferramentas online numa tarde), cobri um subconjunto de bases "redondas" que
  CyberChef `From Base`/dcode oferecem diretamente: **11, 12, 13, 14, 15, 16 (hex), 20, 24, 32,
  36, 60** — 11 bases, só na convenção conv1 (a leitura literal a=1..i=9; a conv2 não tem
  motivação própria acima de 9, seria um deslocamento arbitrário). Declaro explicitamente que
  isto **não é exaustivo**: prior baixo, cobertura de amostra por regra 4, não fechamento.

Nota sobre `hex`/`To_Base(16)`: o item já fechado em §6 é decimal→hex (dígitos lidos em base
10, resultado formatado em hex — o `z_method` da página). O que testo aqui em base 16 é
diferente: os símbolos a–i lidos **diretamente como dígitos de base 16** (valores 1–9, nunca
usando a-f hexadecimal como dígito >9) — não é o mesmo cálculo, por isso não está coberto.

## Cobertura exata

- Bases cobertas: **9** (2 convenções) + **11 bases redondas** (1 convenção) = **13
  combinações base×convenção**.
- Resíduos: L84 e L83 (2).
- Direções de leitura: direta e invertida (2).
- **52 leituras** (13 × 2 × 2), cada uma um inteiro grande via avaliação posicional (Horner).
- Por leitura, 4 formas de material de senha: string decimal do inteiro, string hex do
  inteiro, sha256hex de cada uma das duas → **208 chamadas a `G.try_password_all`**, cada uma
  cobrindo 3 blobs (SMALL/COSMIC/TAIL32) × 2 KDF (SHA256/MD5) = **1.248 tentativas de AES**.
- Por leitura, bytes do inteiro como escalar de 32 B (pad à esquerda quando ≤32 B; janelas
  baixa/alta de 32 B quando maior) → **71 chamadas a `G.priv_hit`**, cada uma cobrindo os dois
  alvos (comprimido/não comprimido, `1GSMG…` e `17ucy…`).
- Bases 2..8 (7 bases): **fechadas por prova determinística** (repertório), sem busca.
- Base 10: fora de escopo (já coberta em §6).

## Comando reproduzível

```
cd /home/user/gsmgio-5btc-puzzle/solver/enxame_2026_09_19/bases_nao_decimais
python3 bases_nao_decimais.py
```
Kit: `solver/experiments/claude_endgame_2026_09_02/gsmg_common.py`, commit base `e481e626`
(HEAD do clone no momento da execução: `f0358341`).
Saída bruta: `_work/enxame_2026-09-19/bases_nao_decimais/resultado.json`.

## Controle positivo

- **KDF**: blob da fase 2 decifra com `sha256hex("causality")` via EVP-SHA256 e **não** via
  EVP-MD5 (`ok_sha=True`, `ok_md5=False`) — confirma que o pipeline `evp`/`unpad` do kit está
  correto antes de testar os 208 candidatos.
- **Privkey**: chave plantada `sha256("controle-f11-bases")`; `fast_priv_scan` não a encontra
  antes de injetar seu h160 em `TARGET_H160S`, e a encontra (`priv@5`) depois — confirma que o
  oráculo de escalar está funcional.
- O self-test completo do kit (`python3 gsmg_common.py`) passa em todas as asserções até a
  penúltima; a última depende do `scorer.py` de quadgramas, que quebra neste clone por falta de
  `result.json` (limitação de ambiente documentada no prompt da campanha, não desta frente) —
  não uso escore de quadgramas em nenhum ponto desta frente, então essa limitação não afeta o
  resultado.

## Nulo

N/A justificado: a prova de impossibilidade das bases 2–8 é determinística (contagem de
símbolos vs. teto de dígito da base), não estatística. A varredura das 52 leituras é exaustiva
sobre o conjunto de bases/convenções declarado, também sem componente aleatória a comparar
contra embaralhamentos — o objeto testado (oráculo duro de AES/privkey) não usa escore de texto
que precise de nulo casado.

## Resultado no oráculo duro

**0 hits.** Nenhuma das 208 tentativas de senha produziu candidato semântico
(`G.semantic`) nem chave embutida (`fast_priv_scan` dentro do plaintext); nenhuma das 71
tentativas de escalar de 32 B bateu com `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` nem com
`17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`. Houve **6 paddings PKCS7 válidos sem sinal semântico**
(de 1.248 tentativas; esperado ≈1.248/255 ≈ 4,9 por acaso) — ruído puro por AGENTS.md regra 1,
registrado no `resultado.json` (campo `hits_pw`/`n_soft_padding_only`) para varredura
retroativa caso o oráculo melhore.

## O que ficou de fora (limitação declarada)

- **Objetos que não sejam texto** — a outra metade da lacuna do §6 — permanece **totalmente
  aberta**; não é desta frente.
- **Bases ≥ 11 além das 11 "redondas" testadas**: família infinita, não fechada, prior baixo
  por regra 4. Uma base "estranha" específica (ex.: base 13, 23, ou qualquer valor não redondo)
  não está descartada por este trabalho.
- **conv2 (zero-based) para bases ≥ 11**: não testada — motivação nula (deslocamento arbitrário
  sem ancoragem no alfabeto), mas não é impossível por repertório.
- **Formas de senha não testadas**: só literal decimal, literal hex e sha256 de cada uma. Não
  testei, por exemplo, o inteiro serializado em outras bases como texto (ex.: base64 do
  próprio número), nem concatenações com outros tokens do puzzle.
- **Padding-only não é solução** (AGENTS.md regra 1) — os 6 hits soft não avançam a fronteira.

## Conclusão

Bases 2–8 estão **provadas impossíveis** por repertório (letra `i`, valor 9/8, excede o maior
dígito legal). Base 9 (as duas convenções motivadas: bijetiva e padrão) e um conjunto de 11
bases "redondas" ≥ 11 foram varridas contra os dois oráculos duros (senha × 3 blobs × 2 KDF;
escalar × 2 alvos) com **0 hits**. Resultado negativo com cobertura exata, como esperado pela
campanha — não fabrica positivo.
