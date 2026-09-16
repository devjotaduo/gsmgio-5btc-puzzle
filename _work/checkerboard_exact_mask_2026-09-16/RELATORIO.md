# Checkerboard: máscaras exatas e palavras — rodada concluída

**Ainda não há senha final.** A calibração, os 180 casos e os testes
criptográficos foram concluídos e conferidos. A campanha começou em
16/09/2026, por volta de 06:57 UTC, e terminou com saída 0 perto de 07:30 UTC.
Os candidatos reais foram verificados também por uma implementação separada.
Nenhum processo desta rodada continua ativo.

## Por que retomar essa família

O teste anterior de alfabeto desconhecido e `g=0/7` não recuperava bem os
controles com prefixos `0,7` e `1,7`. Além disso, mesmo fornecendo o alfabeto
verdadeiro ao otimizador de quatro letras, a saída de maior nota podia conter
palavras erradas. A falha era parcialmente do critério de seleção, não apenas
da quantidade de tentativas.

Esta rodada mantém a família explicitamente delimitada: tabela com 28 posições,
A–Z e duas posições reservadas; dois prefixos decimais; `a=1,…,i=9`, com cada
`g` independentemente 0 ou 7; nenhum deslocamento ou transposição anterior.
O parentesco com a cifra conhecida da fase 3.2 motiva o teste, mas não comprova
que seja a operação correta para FAED.

## Mudança de método

1. A escolha de zeros é otimizada exatamente a cada proposta de alfabeto,
   usando o algoritmo de máscaras já conferido. São quatro reinícios e
   4.000 propostas por reinício, temperatura de 0,04 a 0,0001.
2. Um decodificador de palavras procura simultaneamente as escolhas de zero
   e as fronteiras das palavras. Para um alfabeto fixo, maximiza a soma dos
   logaritmos das frequências por programação dinâmica, sem selecionar
   previamente uma máscara ou uma separação de palavras.
3. O alfabeto é refinado por até vinte rodadas, cada uma examinando todas as
   377 trocas distintas entre suas posições. O melhor vizinho estritamente
   superior é aceito. Uma rodada sem melhora encerra esse refinamento.
4. São usados dois pontos de partida quando seus códigos diferem: o novo
   melhor alfabeto de quadgramas e o melhor da campanha anterior.

A otimização das palavras para um alfabeto fixo é exata no vocabulário
declarado. **A busca do alfabeto continua heurística.** Uma rodada sem melhora
não prova que o alfabeto seja o correto ou o melhor global.

Cada refinamento maximiza a soma das notas das palavras. A comparação entre
configurações usa a média por letra dos melhores resultados assim obtidos;
ela não equivale a maximizar globalmente essa média.

O vocabulário vem de [Peter Norvig, Natural Language Corpus Data](https://norvig.com/ngrams/),
independentemente do Telegram e das cifras. O arquivo `count_1w.txt` fornece
palavras e contagens. Após o filtro de letras, tamanho máximo de 32 e palavras
de uma letra limitadas a A/I, há 333.296 entradas. A normalização usa a soma
original de 588.124.220.187 ocorrências, anterior ao filtro.

O vocabulário também contém siglas, nomes e termos raros. Separar uma saída
em entradas desse arquivo **não** demonstra que ela seja inglês coerente.
A nota linguística também não autentica uma senha.

[Modelo e hash dos dados](word_model.json).

## Calibração concluída

Os três controles anteriores usam a mesma fala de 417 letras, mas alfabetos
aleatórios e prefixos diferentes. Mais três controles usam recortes escolhidos
por uma regra determinística para produzir exatamente 570 símbolos, o tamanho
de FAED. O alfabeto verdadeiro não é fornecido à busca.

| Controle | Prefixos | Símbolos cifrados | Letras esperadas/obtidas | Distância de edição |
|---|---|---:|---:|---:|
| Antigo 0 | 1,4 | 714 | 417/417 | 0 |
| Recorte 0 | 1,4 | 570 | 330/330 | 0 |
| Antigo 1 | 0,7 | 757 | 417/417 | 9 |
| Recorte 1 | 0,7 | 570 | 316/316 | 7 |
| Antigo 2 | 1,7 | 684 | 417/417 | 0 |
| Recorte 2 | 1,7 | 570 | 343/369 | 274 |

São três recuperações exatas em seis casos. Houve uma melhora grande nos
controles antigos, mas o recorte 2 ainda falhou. Portanto, o método não permite
excluir a cifra a partir de uma busca sem solução.

O verificador independente não importa os buscadores. Ele usa um grafo de
palavras completas e programação dinâmica reversa, em vez de acompanhar
prefixos de palavras no sentido direto. Conferiu 12 modelos pequenos por
enumeração de 303 máscaras, 184 saídas com palavras, 376 caminhos de quadgramas
e 18 ótimos para alfabetos fixos. Reconstruiu as mensagens, notas e distâncias.

- [Plano dos controles](controls_spec.json).
- [Controles completos](controls.json).
- [Verificação dos controles](control_verification.json).

Um controle adicional com a tabela conhecida da fase 3.2, após ocultar zeros
como `g`, recuperou exatamente suas 91 letras:
`INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE`.
Esse controle fornece o alfabeto conhecido e não mede a busca de alfabetos.
[Resultado](phase32_word_control.json).

## Sondagens auxiliares

- A otimização apenas por quadgramas foi repetida com a melhor máscara a cada
  proposta. Seus resultados ficaram preservados em [probe_controls.json](probe_controls.json).
- A comparação de critérios de palavras, com alfabeto verdadeiro, antigo e
  novo, está em [word_controls.json](word_controls.json).
- Foram enumeradas as 200 melhores sequências distintas de letras sob o
  modelo de palavras, fornecendo o alfabeto verdadeiro. O texto dos controles
  0 e 2 aparece em primeiro lugar; o controle 1 não aparece entre os duzentos.
  [Enumeração](word_path_controls.json). Isso evidencia ambiguidade residual.
- Um modelo de pares de palavras foi testado apenas nos controles e não
  melhorou de forma consistente a recuperação exata. Não foi usado na campanha
  real. [Modelo](bigram_model.json), [resultados](bigram_controls.json).

Essas sondagens não são decifrações do puzzle e não entram como candidatos AES.

## Campanha concluída

A [especificação](spec.json) foi gravada antes da campanha. Inclui hashes
das fontes, dados, controles e casos da campanha anterior.

São examinados todos os 45 pares de prefixos, as duas direções de FAED e
duas entradas: o campo real e o primeiro embaralhamento determinístico da
campanha anterior. São **180 configurações declaradas**, com os mesmos
parâmetros nos dois conjuntos. Um único embaralhamento não fornece uma
estimativa precisa de significância estatística.

O diário `cases.jsonl` contém os 180 casos terminados. `progress.json` é
somente um registro histórico de acompanhamento. A conclusão foi observada
no processo e conferida em `summary.json`; nenhum processo continua ativo.
A execução foi feita pelo comando abaixo. Ele recusa sobrescrever o diário
existente; não é necessário reiniciar a campanha:

```powershell
node solver/checkerboard_word_search.cjs run
```

Os 90 casos reais já foram conferidos pelo comando `real` do verificador.
Foram reconstruídas 4.745 saídas com palavras, 4.986 caminhos de quadgramas
e 314 ótimos para alfabetos fixos, incluindo os controles de calibração.
A parte real fez 1.130.875 avaliações de quadgramas e 518.523 de palavras.
[Verificação dos casos reais](real_verification.json).

A conferência completa dos 180 casos também terminou com saída 0:

```powershell
node solver/verify_checkerboard_words.cjs
```

Foram **2.261.344 avaliações de quadgramas e 1.041.193 de palavras**.
O verificador independente conferiu 9.468 saídas com palavras, 9.459 caminhos
de quadgramas e 610 ótimos para alfabetos fixos, incluindo a calibração.
[Resumo completo](summary.json), [verificação completa](verification.json).

| Entrada | Sentido | Prefixos do melhor resultado | Letras | Nota média por letra |
|---|---|---|---:|---:|
| FAED real | Original | 1,4 | 482 | −1,427639374 |
| FAED real | Inverso | 8,9 | 469 | −1,422007866 |
| Embaralhamento | Original | 1,3 | 482 | −1,416343622 |
| Embaralhamento | Inverso | 2,3 | 485 | −1,415975384 |

Uma nota menos negativa é maior. O embaralhamento superou o campo real nos
dois sentidos. Nenhuma dessas saídas forma uma mensagem coerente; palavras
soltas e separações plausíveis também aparecem com dados aleatórios.
O controle é uma comparação limitada a um embaralhamento, não uma prova
estatística de que a cifra escolhida seja impossível.

## Validação criptográfica concluída

O programa de oráculos preservou os 90 casos reais completos em
`real_cases.jsonl`. Seu SHA256 coincide com o verificador. A conclusão dos
embaralhamentos não altera esse conjunto. Foram incluídas todas as melhorias
guardadas de quadgramas, os melhores de cada reinício e todas as melhorias
dos refinamentos por palavras. Entradas repetidas foram eliminadas.

Os **10.330 textos distintos**, juntos ou com espaços inferidos, geraram
**41.320 senhas**, considerando maiúsculas/minúsculas e uso direto ou SHA256
hexadecimal. Nos três blobs, com EVP-SHA256 e EVP-MD5, houve **247.920 decisões
AES**. Os 954 corpos aceitos pelo padding não formaram uma mensagem
autenticada; nenhum superou 54,44% de bytes ASCII imprimíveis e TAB/LF/CR.
Padding isolado não prova a senha.

Os hashes SHA256 dos candidatos, os hashes dos corpos aceitos e todas as
janelas de 32 bytes desses corpos, nas duas ordens, produziram **919.404
escalares distintos válidos**. Nenhum correspondeu à chave pública do
endereço do puzzle ou à sua negação.

Uma implementação separada em Python, com PyCryptodome e coincurve, reconstruiu
todos os candidatos, senhas, decisões AES — incluindo as rejeições —,
plaintexts aceitos, escalares e pontos públicos. Também conferiu o controle
AES conhecido da fase 3.2, o gerador da curva e a derivação do endereço-alvo.

- [Resultados criptográficos](oracles.json).
- [Conferência independente](independent_oracles.json).
- [Textos considerados](candidates.json).
- [Senhas derivadas](passwords.json).
- [Corpos com padding válido](padding.json).

Esses resultados excluem as variantes de senha efetivamente testadas. A busca
heurística de alfabetos e as falhas de recuperação dos controles impedem
excluir toda a família de cifras.

## Fontes locais

- [Busca e refinamento](../../solver/checkerboard_word_search.cjs).
- [Decodificador de palavras](../../solver/checkerboard_word_decoder.cjs).
- [Enumeração de caminhos](../../solver/checkerboard_word_paths.cjs).
- [Sondagem de pares de palavras](../../solver/checkerboard_word_bigrams.cjs).
- [Verificador independente](../../solver/verify_checkerboard_words.cjs).
- [Oráculos criptográficos](../../solver/checkerboard_word_oracles.cjs).

O limite permanece o objetivo original: obter a senha correta e um resultado
final verificável. Mensagens plantadas, notas, palavras soltas e padding não
atendem a esse objetivo.
