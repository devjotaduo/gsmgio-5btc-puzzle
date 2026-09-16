# Tokens b/g de FAED em grades 11×41 e 41×11

16/09/2026. **Nenhuma senha final ou chave do prêmio validada.** A leitura
com prefixos `b,g`, seguida das rotas geométricas declaradas e substituição
desconhecida, não produziu texto coerente nem candidato autenticado. A
busca de alfabetos é heurística; não é uma exclusão de toda a família.

## Hipótese e calibração

Nas duas direções de FAED, `b` e `g` consomem o símbolo seguinte, enquanto
as demais letras são tokens individuais. Cada leitura completa produz
**451 tokens de 25 tipos**. O comprimento `451=11×41` permite experimentar
essas duas grades sem preenchimento ou descarte de símbolos.

As rotas incluem linhas, colunas, linhas/colunas alternadas e espiral,
com reflexões, inversão da sequência e permutações inversas, usando
preenchimento em ordem de linhas. São 160 descrições geométricas que
se reduzem a **70 permutações distintas**. Não são todas as possíveis
permutações dos tokens, nem todos os pares de rotas de entrada e saída.

Para cada sequência, foram buscadas substituições injetivas dos 25
símbolos por 25 das 26 letras A–Z. O modelo de quadgramas é o
[modelo geral previamente conferido](../ambiguous_checkerboard_2026-09-15/general_english/scorer.json),
independente do export do Telegram. Cada busca usou oito reinícios e
30.000 propostas por reinício, com recusas de trocas de um índice consigo
mesmo. O programa usa avaliações incrementais e as compara periodicamente
com o cálculo completo da nota.

Antes de usar FAED, o mesmo buscador recuperou integralmente **três
controles com exatamente 451 letras**, alfabetos embaralhados e `J→I`:
um trecho da Declaração de Independência, um da fase 3.2 e um de Alice.
As notas verdadeiras foram −3,985142, −4,219672 e −4,183140.
Os textos, alfabetos, parâmetros e resultados estão preservados.

## Comparação com embaralhamentos

Além das duas leituras reais, foram criados dois embaralhamentos de tokens
para cada direção. Eles preservam todas as frequências dos 25 símbolos.
Receberam exatamente as mesmas 70 rotas, sementes e parâmetros da busca.

| Dados | Melhor nota, direção original | Melhor nota, direção invertida |
|---|---:|---:|
| FAED real | −5,444949 | −5,411045 |
| Embaralhamento 1 | −5,435783 | −5,409615 |
| Embaralhamento 2 | −5,461160 | −5,439686 |

Uma nota menos negativa é melhor. Em ambas as direções, o resultado real
ficou entre os dois controles. Os fragmentos favorecidos pelo modelo não
formam mensagens coerentes. Dois controles não permitem uma estimativa
precisa de significância; a comparação impede tratar esses fragmentos
como evidência suficiente de decifração.

Foram **420 configurações**, 140 reais e 280 controles, com **96.921.451
avaliações de propostas**. Uma implementação independente reconstruiu
todos os tokens, os 160 rótulos geométricos, as 70 permutações e os
embaralhamentos. Conferiu **25.502 caminhos guardados**, suas notas,
alfabetos e posições na sequência, além dos três controles exatos.

## Testes criptográficos

Todas as melhorias globais e os melhores resultados de cada reinício
das configurações reais produziram **8.120 textos distintos**. As versões
maiúscula/minúscula, diretamente e como SHA256 hexadecimal, geraram
32.480 senhas. Foram testadas em SMALL, TAIL32 e COSMIC com EVP-SHA256 e
EVP-MD5:

- **194.880 decisões AES**, 816 paddings, nenhum plaintext autenticado.
  A maior proporção imprimível, incluindo TAB/LF/CR, foi 59,49%.
- **16.240 hashes como escalares**, sem correspondência com a pubkey
  do prêmio ou sua negação.
- Nos corpos com padding, SHA256 e todas as janelas de 32 bytes, em ambas
  as ordens, produziram **723.118 escalares distintos**, também sem acerto.

PyCryptodome 3.23.0 reproduziu todas as decisões AES, inclusive rejeições
e corpos completos. Coincurve 21.0.0 conferiu os pontos. A fase 3.2
conhecida e a conversão da pubkey no endereço-prêmio foram controles.
Os textos dos embaralhamentos não foram usados como candidatos de senha.

## Correção histórica e limites

A descrição antiga de `straddle_bg_attack.py` dizia que o controle tinha
o mesmo comprimento de FAED. O literal contém **387 letras**; `[:451]`
não o aumenta. Esse número foi conferido pela AST sem executar o programa.
Os três controles desta rodada têm 451 letras, verificadas por asserção.
O programa antigo foi preservado e a afirmação no ENDGAME foi corrigida.

Este experimento não cobre outros prefixos, escolhas independentes de
zero, chaves numéricas anteriores ao checkerboard, transposições gerais,
outros alfabetos ou todo o espaço de substituições. Nenhum resultado
justifica declarar VIC ou checkerboards impossíveis.

```powershell
node solver/checkerboard_token_routes.cjs controls
node solver/checkerboard_token_routes.cjs run
node solver/verify_checkerboard_token_routes.cjs
node solver/checkerboard_token_route_oracles.cjs
```

[Controles](controls.json), [especificação e rotas](spec.json),
[todos os casos](cases.jsonl), [resumo](summary.json),
[verificação dos caminhos](verification.json),
[candidatos com proveniência](oracle_candidates.json),
[oráculos](oracles.json), [corpos com padding](padding.json),
[conferência criptográfica](oracle_verification.json),
[escalares dos corpos](padding_scalar_verification.json).

Programas: [buscador](../../solver/checkerboard_token_routes.cjs),
[verificador](../../solver/verify_checkerboard_token_routes.cjs),
[oráculos](../../solver/checkerboard_token_route_oracles.cjs).

SHA256 do buscador:
`17c7330747f228426be8d89e15804b47aa4ff64a5af27d3c0d681309de61a444`.
SHA256 dos casos:
`fe9fd3d91357d3549c9209e04ff9af2c06a0955bce3c5c7d7e71cefb84a0d21f`.
SHA256 dos candidatos criptográficos:
`cbaad6a19bd4d5b895a786983c705c267c7a960566ef3c58f5384e66c4308d92`.
