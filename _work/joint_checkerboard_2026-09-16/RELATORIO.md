# FAED: alfabeto desconhecido e zeros no checkerboard

16/09/2026, America/Sao_Paulo. **Nenhuma senha final ou chave do prêmio
recuperada.** A busca conjunta não separou FAED de embaralhamentos com as
mesmas frequências. O alfabeto não foi esgotado, e controles difíceis
mostram limitações do método; não é uma exclusão da cifra VIC.

## Diferença em relação aos testes anteriores

`checkerboard.py`, `gpu_checkerboard.py`, `straddle_bg_attack.py` e
`straddle_sweep.py` já procuravam alfabetos desconhecidos. Contudo, fixavam
os dígitos/tokenização e usavam o modelo do Telegram, cuja contaminação foi
confirmada na rodada anterior. Não havia uma busca conjunta desses
alfabetos com a escolha independente de `g=0/7` usando o novo modelo geral.

O modelo desta rodada considera:

- FAED inteiro, original e com todos os símbolos invertidos;
- `a=1..i=9`, com cada `g` representando independentemente 0 ou 7;
- dois prefixos de checkerboard entre 0 e 9;
- alfabeto desconhecido com A–Z e duas posições reservadas, que não podem
  aparecer no plaintext contínuo;
- nenhum deslocamento, transposição ou chave decimal anterior ao checkerboard.

São 45 pares de prefixos, não ordenados: trocar a ordem dos prefixos pode
ser absorvido pela permutação das duas linhas do alfabeto desconhecido.
O alto número de `g` em FAED motiva sua investigação como zero/7, mas isso
não é uma confirmação do mapeamento pelo criador. Outros aliases não
foram examinados nesta rodada.

## Calibração antes dos dados reais

O primeiro protótipo permitia pontos ignorados pela nota linguística. Nos
controles, ele favorecia apagar letras raras, como partes de `MATRIX`.
Esse protótipo e suas saídas foram preservados para auditoria, mas não
serviram de base para afirmar uma solução. A busca principal usa texto
contínuo A–Z e rejeita as posições reservadas.

A busca alterna trocas de letras/colunas do alfabeto com mudanças nas
escolhas de zero. A cada 500 iterações, programação dinâmica encontra a
melhor atribuição de zeros para aquele alfabeto. O algoritmo de máscaras
foi confrontado com enumeração direta: **288 modelos pequenos, 816 máscaras,
todos os ótimos coincidentes**.

Três controles usam o mesmo texto de 417 letras, alfabetos aleatórios
desconhecidos pela busca e diferentes prefixos. O esforço final é igual ao
dos dados reais: oito reinícios, 20.000 iterações por reinício.

| Prefixos | Dígitos do controle | Distância de edição para o texto verdadeiro | Resultado |
|---|---:|---:|---|
| 1,4 | 714 | 3/417 = 0,72% | Mensagem reconhecível, três letras incorretas |
| 0,7 | 757 | 123/417 = 29,50% | Recuperação insuficiente |
| 1,7 | 684 | 390/528 = 73,86% | Recuperação insuficiente, comprimento errado |

**Esses controles impedem interpretar a ausência de uma solução como prova
de impossibilidade.** Mesmo o primeiro não recupera uma senha exata: termos
raros podem receber uma nota menor que uma substituição errada. Os controles
também são mais longos que FAED; não medem uma taxa universal de sucesso.

[Controles completos](controls.json), [enumeração de máscaras](mask_controls.json),
[protótipo com pontos ignorados](controls_with_dots.json).

## Busca e comparação com embaralhamentos

Foram criados três embaralhamentos determinísticos que preservam todas as
frequências de FAED. Cada um recebeu os mesmos pares de prefixos, ambas as
direções, os mesmos parâmetros e sementes da busca real. Eles são controles
negativos; seus textos não foram tratados como candidatos a senha.

| Entrada | Maior nota encontrada, considerando ambas as direções |
|---|---:|
| FAED real | -5,082816 |
| Embaralhamento 1 | -5,061486 |
| Embaralhamento 2 | -5,051942 |
| Embaralhamento 3 | -5,114248 |

Quanto menos negativa, maior a nota. FAED ficou entre os controles: dois
embaralhamentos receberam nota maior. Nenhum dos melhores textos constitui
uma mensagem coerente. Três controles não sustentam uma estimativa precisa
de significância estatística, mas mostram que esses fragmentos podem surgir
sem preservar a ordem do puzzle.

Foram **360 configurações**: 90 reais e 270 embaralhadas. Houve
47.831.645 avaliações de propostas e 1.312.343 chamadas ao otimizador de
máscaras. Cinquenta configurações não admitem uma leitura completa com
duas posições reservadas, incluindo 16 das reais. Nas demais, a busca de
alfabetos foi heurística, com orçamento finito. Não confundir o término
dessas execuções com enumeração de todas as permutações do alfabeto.

O verificador independente reconstruiu as tabelas e as escolhas de dígitos,
conferiu **18.449 caminhos guardados** e suas notas, enumerou novamente os
pares possíveis de posições reservadas por programação dinâmica reversa e
conferiu os conjuntos de parâmetros e esforço. Ele não importa o buscador.

[Especificação](spec.json), [resumo](summary.json),
[verificação independente](verification.json).

## Validação dos candidatos reais

Foram preservadas todas as melhorias globais e a melhor saída de cada
reinício, não apenas a melhor nota final. Os **4.269 textos distintos** da
busca real foram usados em maiúsculas/minúsculas, diretamente e como SHA256
hexadecimal, contra SMALL, TAIL32 e COSMIC com EVP-SHA256 e EVP-MD5.

- 17.076 senhas distintas e **102.456 decisões AES**;
- 412 paddings aceitos, nenhum corpo com mais de 56,97% de bytes imprimíveis
  ou whitespace e nenhuma decifração final autenticada;
- **8.538 hashes como escalares secp256k1**, zero correspondências com a
  chave pública do prêmio ou sua negação.

Uma segunda implementação, com **PyCryptodome 3.23.0 e coincurve 21.0.0**,
reproduziu todas as decisões AES, inclusive rejeições, os 412 corpos completos
e todas as comparações de pontos da curva. A pubkey-alvo foi também convertida
localmente para `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`. A fase 3.2 conhecida e o
gerador secp256k1 serviram como controles positivos.

[Candidatos e oráculos](oracles.json),
[conferência com bibliotecas independentes](oracle_verification.json).

## Consequência e reprodução

Esta rodada não revela uma senha nem uma direção promissora dentro deste
modelo. Não ampliar o tempo de annealing apenas porque ainda existem
permutações não testadas. Os pontos continuam abertos: a operação exigida
por `matrixsumlist`, o papel dos primos, outro mapeamento de zero, uma
transformação anterior ao checkerboard ou outra representação dos campos.

```powershell
node solver/run_joint_checkerboard.cjs controls
node solver/run_joint_checkerboard.cjs run
node solver/joint_checkerboard_oracles.cjs
node solver/verify_joint_checkerboard.cjs
```

Programas: [buscador](../../solver/joint_checkerboard_search.cjs),
[campanha e controles](../../solver/run_joint_checkerboard.cjs),
[oráculos](../../solver/joint_checkerboard_oracles.cjs),
[verificador](../../solver/verify_joint_checkerboard.cjs).
