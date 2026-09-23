# F8 — `antitese_primos`: a construção contrária ao lead `yellowblueprimes`

Campanha `enxame_2026-09-19`, frente F8 (papel: **adversário** do único lead estrutural aberto,
`ENDGAME.md` §6). Container Linux, 4 cores, sem GPU, Python 3.11 + numpy.
**Semente mestra declarada: `20260919`** (A → `20260919`, B → `+1`, C → `+2`, C-20k → `+3`).

Scripts: `solver/enxame_2026_09_19/antitese_primos/{seg_core,fast_seg,exp_a_geradores,exp_b_sensibilidade,exp_c_lookelsewhere,exp_d_exato,exp_e_texto_real}.py`.
Dados: `exp_a.json`, `exp_b.json`, `exp_c.json`, `exp_c_full20k.json`, `exp_e.json`, `resumo_F8.json`.

**Procedência e verificação independente.** Frente executada por subagente, impedida pelo harness de
escrever relatórios; este `FINDINGS.md` foi materializado pelo coordenador. **Os dois resultados
decisivos foram reproduzidos pelo coordenador com implementação própria, separada da da frente:**

1. **A cota exata bate em três algarismos.** Implementação independente da esperança em forma
   fechada dá **E[#seg] = 1,859 × 10⁻¹⁷** (frente: 1,86 × 10⁻¹⁷), com os maiores termos em
   **L = 87 e L = 88**, e L84 = 1,14 × 10⁻¹⁸ contra L83 = 4,13 × 10⁻¹⁹ — todos idênticos aos da
   frente.
2. **A impossibilidade de `faed` confirma-se.** Com n = 570, 49 `b` e 69 `e`: exigir π(L) ≤ 49 força
   **L ≤ 228**; exigir n − L ≤ π(L) força **L ≥ 479**. Janela vazia, verificado por varredura de
   todos os L.

## 0. Contrato

**Alegação atacada:** o encaixe `b`/`be` em posições lógicas primas de `dbbi` é desenho do autor.
**Mecanismo desta frente** (diferente do embaralhamento já feito em §6): o encaixe é *construtível
sem intenção autoral*?

**Controle positivo:** `count_segmentations(G.DBBI)` → 2 segmentações, L83 (15 `b` + 8 `be`) e L84
(16 `b` + 7 `be`); `G.FAED` → 0. Reproduz §6 byte a byte. O DP vetorizado foi conferido contra o DP
escalar em 301 strings (301/301).
**Nulo:** A/B/C/E amostrais com semente declarada; **D é determinístico** → nulo casado N/A,
justificado por ser prova de cota.
**Oráculo duro:** frente estatística; nenhum candidato produzido, nenhuma chave nem blob testado.

## 1. Experimento A — processos geradores alternativos: 0 acertos em 180.000 amostras

Nove geradores (20.000 amostras cada, n = 91): embaralhamento preservando contagens (o nulo
existente, recalibrado); i.i.d. com frequências de `dbbi`; i.i.d. com as de `faed`; Markov de ordem 1
treinada em `dbbi` (com e sem Laplace 0,25); Markov de ordem 1 em `faed`; Markov de ordem 2 em
`dbbi`; renovação com lacunas entre `b` amostradas do próprio `dbbi`; embaralhamento por blocos de 2
(preserva metade dos bigramas `be`). **Acertos: 0 em todos.**

Três desses herdam a estrutura local do próprio `dbbi`. **Trocar o nulo não move o resultado:** a
objeção "o nulo existente é o nulo errado" não se sustenta.

## 2. Experimento B — sensibilidade

- n = 91, varrendo o número de `b` (`dbbi` tem 25; mínimo aritmético = 23): **0/20.000 para todo
  m de 23 a 55**; 2/20.000 em m = 60; 16/20.000 em m = 65. Um texto precisaria ser ~⅔ composto por
  `b` para o encaixe virar plausível por acaso.
- Fração de `b` fixa, varrendo n de 60 a 140: **0/20.000 nos 17 pontos.** A propriedade não é
  artefato de n = 91.

## 3. Experimento C — look-elsewhere medido, não estimado

Família a priori montada **sem olhar para `dbbi`**: letra X ∈ a–i (9) × sufixo Y ∈ {nenhum} ∪ a–i
(10) × 13 famílias de posições = **1.170 regras**.

- `dbbi` sob as 1.170: **exatamente uma funciona**, `primos_1based | b | e`.
- 20.000 embaralhamentos × 1.170 regras = **23,4 M testes**: **1** string admite alguma regra
  (`triangulares|b|f`), taxa 5 × 10⁻⁵; **0** admitem qualquer regra com posições **primas**.

O look-elsewhere é real, minúsculo, e se concentra nas regras com poucos marcadores. A regra
canônica é das mais **difíceis** da família (23 marcas contra 9–13).

## 4. Experimento D — a cota EXATA (o resultado que sustenta o veredito)

Uma segmentação é determinada por L e por quais dos m = π(L) primos usam o token de 2 chars
(k = n − L deles). Por desigualdade de Markov, P(≥ 1 segmentação) ≤ E[#seg], com

```
E[#seg] = Σ_L  C(π(L), n−L) · P(m posições dadas = 'b'  e  k posições dadas = 'e')
```

e P exata no modelo de multiconjunto fixo (fatoriais decrescentes em `Fraction`).

| | valor |
|---|---|
| E[#seg], i.i.d. com frequências de `dbbi` | 6,62 × 10⁻¹² |
| **E[#seg], multiconjunto fixo (= o nulo do embaralhamento, exato)** | **1,86 × 10⁻¹⁷** ✔ reproduzido |
| Bonferroni exato sobre as 1.170 regras a priori | 8,92 × 10⁻⁵ |
| **Bonferroni exato sobre as 180 regras de posições PRIMAS** | **5,37 × 10⁻¹⁷** |

Validação cruzada da própria frente: a cota de 8,92 × 10⁻⁵ prevê ~1,8 acertos em 20.000 —
observou-se **1**. Analítica e amostra concordam.

- `dbbi` realiza **2** segmentações contra esperança 1,86 × 10⁻¹⁷ (fator ~10¹⁷).
- Os L realizados **não** são os favorecidos a priori (os de maior peso são L = 87 e 88) —
  confirmado independentemente.
- Para levar o p efetivo a 0,05 seria preciso uma família a priori de **≈ 2,7 × 10¹⁵ regras**.

## 5. Experimento E — geradores "do mundo real"

**535.310 janelas** de 91 símbolos, de codificações naturais texto → a–i (a1z26 dos dígitos,
ord mod 9, base 9 dos bytes) sobre `README.md`, `ENDGAME.md`, `AGENTS.md`, o índice,
`G.MATRIX_README` e `faed` literal. 7 acertos brutos, **todos contaminação identificada** — são a
própria `dbbi` citada nesses documentos e recuperada intacta pelas codificações, inspecionados um a
um. **0 acertos genuínos.**

## 6. Um sub-argumento do §6 que esta frente derruba

**`faed` não é evidência.** O §6 lista "`faed` não admite segmentação" entre as evidências de
desenho. Para a regra canônica isso é **impossibilidade de contagem**, não resultado empírico:
nenhum conteúdo de `faed`, em nenhuma ordem, poderia admitir a regra (L ≥ 479 e L ≤ 228
simultaneamente). **Verificado pelo coordenador.** A afirmação vale para a regra canônica; as 4.248
variantes não foram reconferidas uma a uma.

## 7. Veredito: **LEAD REFORÇADO**

A construção contrária **falhou, com margem enorme**.

1. Nove geradores (180.000 amostras), 41 pontos de sensibilidade, 23,4 M testes de look-elsewhere e
   535 mil janelas de texto real: **zero em tudo**.
2. O número que sustenta o veredito é **determinístico**: P(encaixe) ≤ 1,86 × 10⁻¹⁷, e
   ≤ 5,37 × 10⁻¹⁷ já com Bonferroni exato sobre as 180 regras de posições primas. Substitui o
   "0 em 20.000" (p < 1,5 × 10⁻⁴) por algo ~8 × 10¹² vezes mais forte, **independente de semente, de
   amostragem e da escolha do nulo**.
3. Continua sendo **inferência sobre intenção, não medida dela**: a §3.4 permanece válida.
4. **O que não foi atacado:** todos os nulos aqui são "texto sorteado". Não cobre a hipótese de que
   `dbbi` seja saída de **outra construção determinística** que force `b` às primas como efeito
   colateral. Essa classe não é enumerável. Tal construção precisaria conter, ela mesma, a estrutura
   prima — o que **empurra a intenção um passo atrás, não a elimina**.
5. **Nada disto desambigua L83 de L84.** E[#seg] de L84 = 1,15 × 10⁻¹⁸ contra 4,13 × 10⁻¹⁹ de L83:
   fator 2,8, fraco demais. O argumento 16/7 segue o único discriminante, e segue condicional.

## 8. Limites declarados

- **Sem scorer de quadgramas** (`result.json` ausente): esta frente não usa escore de texto em ponto
  algum, então a limitação não afeta nenhum número acima.
- A/B/C/E são amostrais (cotas de 95 %: ~1,5 × 10⁻⁴ em A/B/C, ~5,6 × 10⁻⁶ em E). **O veredito
  repousa em D, determinístico.**
- A família de 1.170 regras é escolha da frente, feita sem olhar para `dbbi`, e não é a família de
  todas as descrições possíveis (infinita). O contra-argumento honesto está na §4: seriam precisas
  ~2,7 × 10¹⁵ regras para anular a cota.
- Markov de ordem 2 treinada em 91 símbolos é fortemente superajustada; é o gerador menos
  informativo da tabela A.
- Nenhum teste de oráculo duro executado; nenhum candidato produzido.

## 9. Próxima pergunta

**Existe uma construção determinística simples — na altura do "couple hours com CyberChef" (regra 4)
— cuja saída sobre a–i ponha `b` em posições primas sem que o autor tenha mirado nisso?** O teste
natural é um **nulo de pipeline** (não de urna): varrer as operações que o puzzle já usa
(checkerboard VIC, Beaufort com `THEMATRIXHASYOU`, EBCDIC 1141, base 9) sobre textos-fonte
plausíveis e medir a frequência do encaixe nas saídas. Se der 0, a discussão sobre intenção fecha do
lado estatístico e a prioridade passa inteira para a segunda ligação desconhecida de §6 — **como
`matrixsumlist` consome o resíduo**.

## 10. Delta proposto para o `ENDGAME.md` §6

*(proposta; aplicada por quem integra o PR, não por esta frente nem pelo coordenador)*

- substituir "0 em 20.000 embaralhamentos" por **P(encaixe) ≤ 1,86 × 10⁻¹⁷** (cota exata,
  multiconjunto fixo; 6,6 × 10⁻¹² no modelo i.i.d.) — **reproduzido por implementação independente**;
- acrescentar **"≤ 5,37 × 10⁻¹⁷ com Bonferroni exato sobre 180 regras de posições primas; 1 falso
  positivo em 23,4 M testes de 1.170 regras a priori"** (look-elsewhere medido, não estimado);
- **remover `faed` da lista de evidências**, anotando que para a regra canônica `faed` é impossível
  por contagem — **verificado**.
