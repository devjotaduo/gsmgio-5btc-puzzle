# O registro pessoal-informal do criador como classe de senha

**Estado: negativo.** 19.913 candidatos inéditos, 358.434 decifrações AES, 19.913 brainwallets:
nenhum candidato, nenhuma chave. Extensão da família 6 (`ENDGAME.md` §4-C), não repetição dela.

## Por que esta campanha

O criador marcou **uma única fala** como hint (2026-07-12, ids 66573/66574):

> "My close friends have the best chance of solving it (a few tried). But they don't have the skills
> some of you do."
> "NOTE: that is a hint."

A estrutura é paradoxal de propósito: os amigos ganham **apesar de terem menos habilidade técnica** que
o grupo. Logo, o que eles têm não é acesso privilegiado nem capacidade de cálculo — é o **vocabulário**
dele. Isso não anuncia mecanismo novo; anuncia **classe de senha**: uma palavra ou expressão do
registro pessoal-informal, do mesmo tipo de `causality` e `thematrixhasyou`.

A família 6 de 17/09 já atacou essa classe com 104 itens e ≈1,7 M candidatos (0). Mas o inventário dela
capturou só parte do registro das noites de 12/07 e 16/07 — pegou `Iykyk`, `geestveruimend`, `Ibiza`,
`close friends`, `hidden laptop`, o koan *"Give yourself yourself…"*, e deixou de fora o resto.

## Fonte e limite ético

Somente falas públicas dele no grupo, curadas verbatim em `_work/creator_msgs_2026-07_09.txt` (checkout
principal, 84 linhas, conferidas contra o export). Nenhum dado de identidade, endereço, família ou
terceiros — `AGENTS.md`, regra 6. O hint é sobre o **tipo** de resposta; perseguir pessoas ou objetos
não é permitido nem teria valor operacional.

## Os 41 itens inéditos

Agrupados como ele os usou, com os **typos dele preservados** — um typo é assinatura de registro, e o
puzzle já usou grafia própria antes (`geestveruimend`):

| Grupo | Itens |
|---|---|
| o puzzle contado por ele | `the rickroll effect`, `matrix cypher`, `life enjoying project`, `monstrosity`, `spur of the moment`, `frenzy`, `ego-centric`, `I rushed (t)it` |
| meta e AI | `meta`, `Meta hunting`, `ELI5`, `ELI4.5`, `many NOTES`, `NOTES`, `Latetly` (typo, #66962) |
| quantum e bitcoin | `bip360`, `BIP 360`, `stable qubits`, `piggy bank`, `nation state` |
| o trocadilho com primos | `in your prime`, `You have to be in your prime for that` |
| koans e despedida | `Going dark again`, `Some already found it`, `quite a secret in my head`, `share with the planet`, `a tiny fraction`, `still saw double`, `I might me drunk` (typo, #66549) |
| o registro de bar | `It kills braincells`, `braincells`, `Beer, red wine and champagne`, `ketamine`, `ayahuasca`, `mao-inhibitors` |

`in your prime` entrou porque o lead aberto de §6 é de primos e ele fez o trocadilho em 16/07 — é
coincidência temática, não evidência.

## Disjunção com a família 6, por construção

Duas garantias, não uma:

1. **0 colisões de item** — o script lê o `INV` da família 6 e falha se algum item inédito já estiver
   lá (comparação normalizada, sem espaço e em minúscula);
2. **todo candidato contém ao menos um item inédito** — a família 6 só combinava itens do inventário
   dela, logo nenhum candidato daqui foi testado antes.

## Gramática e cobertura

A mesma das fases resolvidas e da família 6: concatenação verbatim sem separador, nas formas de caixa
que o puzzle usa (verbatim, minúsculo sem espaço, minúsculo com espaço, sem espaço, MAIÚSCULO).

| Sub-família | Candidatos |
|---|---|
| `F3_tripla_prio` (triplas entre os prioritários inéditos) | 12.144 |
| `F2x_novo_antigo` + `F2x_antigo_novo` (inédito × prioritário da família 6) | 3.520 |
| `F2_par_low` + `F2_par_verbatim` (inédito × inédito) | 3.110 |
| `F4_roadmap` (item colado a token do roadmap) | 1.008 |
| `F1_single` (item sozinho, todas as formas) | 131 |
| **Total** | **19.913** |

Cada candidato vira senha `raw`, `sha256hex` e `SHA256HEX` → 59.739 senhas únicas → **358.434
decifrações** (3 blobs × 2 KDF), mais **19.913 brainwallets** (sha256 do candidato como privkey,
pubkey comprimida e não, contra os dois alvos).

## Resultado

| | |
|---|---|
| Candidatos `hard` (abertura semântica) | **0** |
| Hits de privkey | **0** |
| Paddings observados | 1.449 |
| Paddings esperados (1/255) | 1.405,62 |
| **z** | **+1,16** |

O z de +1,16 é ruído puro — dentro da faixa de ±2 que o §3.9 calibra como comportamento do acaso.

**Controles.** O controle positivo abre a fase 2 com `sha256hex("causality")` sob EVP-SHA256 pelo mesmo
caminho de código. **Nulo casado:** 3.000 candidatos com os caracteres embaralhados (preserva
comprimento e multiconjunto) pelo mesmo pipeline — 9.000 senhas, 54.000 AES, z +0,57, 0 candidatos.

## O que isto fecha e o que não fecha

Fecha: este inventário, nestas aridades (1–3), sob esta gramática. Não fecha a classe — o registro de
uma pessoa não é enumerável, e qualquer lista é um recorte. O hint continua sendo a melhor indicação
disponível sobre o **tipo** de resposta, e continua sem indicar mecanismo.

Vale registrar o que o negativo custa: 358 k AES em poucos minutos. Ampliar a aridade para 4+ nesta
lista explodiria sem ganho de prior — a fase 3 concatenou 7 partes, mas cada uma era a resposta única
de um enigma, não um item de leque.
