# Checkerboard com zeros ambíguos e auditoria do modelo de inglês

Rodada iniciada em 15/09 e concluída em 16/09/2026, America/Sao_Paulo.

**A senha final continua desconhecida.** A investigação usa o mecanismo
straddling checkerboard já autenticado na fase 3.2, sem assumir que ele
também seja a cifra dos campos finais.

## 1. Viés encontrado no classificador antigo

`solver/scorer.py` treina quadgramas sobre mensagens do Telegram selecionadas
por comprimento e proporção de vogais. Esse filtro admite 65 mensagens que
contêm um fragmento longo de DBBI e 25 que contêm o início de FAED. Essas
contagens podem se sobrepor. Reconstituir o modelo atual produziu exatamente
os mesmos **456.976 valores** e o mesmo piso de `solver/quadgram.pkl`, com
2.970.853 ocorrências de quadgramas no corpus. Portanto, não se trata apenas
de um risco hipotético: as próprias cifras integram o modelo de pontuação.

Isso permite favorecer cópias da cifra e fragmentos de tentativas antigas.
As pontuações anteriores não são prova de linguagem natural. O cache e os
scripts históricos foram preservados; nenhum resultado AES foi convertido
em solução por causa da nota do classificador.

A busca inteira foi repetida com as contagens gerais de inglês publicadas
por [Practical Cryptography](https://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/),
obtidas da [cópia mantida na Florida State University](https://people.sc.fsu.edu/~jburkardt/datasets/ngrams/english_quadgrams.txt).
O arquivo tem 389.373 quadgramas presentes e 4.224.127.912 ocorrências.
Hash SHA256: `b461953d6ad3b5e1f0f07c133102b7656a205529cb8697a8ecda8d45311f7a55`.
Foi gerada uma tabela float32 de `log10(contagem/total)`, com piso
`log10(0,01/total)` para quadgramas ausentes. Não há material do puzzle
adicionado a esse segundo modelo.

Fontes e auditoria: [contamination_audit.json](contamination_audit.json),
[modelo geral](general_english/scorer.json), [modelo antigo](scorer.json).

## 2. Modelos examinados

Em todos os modelos, `a=1..i=9`, qualquer um dos nove símbolos pode também
ser zero, e cada ocorrência decide independentemente. São incluídos os
campos DBBI/FAED em ordem original e com todos os símbolos invertidos.
O parser exige consumir todos os dígitos, sem descartar um prefixo final.

| Família | Parâmetros | Casos por modelo de inglês |
|---|---|---:|
| Checkerboard direto | 12 alfabetos explícitos, 90 pares ordenados de prefixos, nove aliases, dois campos e duas direções | 38.880 |
| Chave decimal da matriz, depois checkerboard | 43 listas geram 156 chaves distintas; alinhamento inicial fixo; soma, subtração e Beaufort módulo 10; alfabeto e prefixos `1,4` da fase 3.2 | 16.848 |

Os alfabetos incluem o da fase 3.2, ordem alfabética, oito letras frequentes
no topo e nove alfabetos chaveados por expressões literais das pistas. As
43 listas incluem somas da matriz correta de 101 bits ativos, variantes
com primos e hipóteses de valores das cores. Seus significados operacionais
continuam sendo hipóteses, não regras confirmadas pelo criador. Os arquivos
`spec.json` preservam todos os alfabetos, valores e rótulos.

Por perfil, são **55.728 casos**, dos quais 47.080 têm uma leitura completa
e 8.648 não admitem terminar a leitura. Repetir com dois modelos de inglês
não cria duas famílias criptográficas distintas.

Para cada caso, programação dinâmica mantém o contexto das três últimas
letras. Otimização fracionária encontra a maior média de quadgramas,
permitindo todas as escolhas de zero sem enumerar `2^107` máscaras. Pontos
do alfabeto permanecem no texto, mas são ignorados pela função linguística.
É guardado apenas um caminho de nota máxima por caso.

## 3. Verificação e limites

Uma implementação separada construiu novamente as tabelas, reverteu cada
caminho, conferiu a nota e calculou um limite para a melhor nota possível.
Ela não importa o buscador e usa contextos textuais em vez de estados
numéricos. Conferiu também todos os casos sem leitura completa. Os resíduos
numéricos ficaram abaixo de `1,8e-12`, com tolerância declarada de `1e-7`.

O controle original da fase 3.2 foi reproduzido exatamente, de 149 dígitos
para a mensagem iniciada por `INCASEYOUMANAGETOCRACKTHIS`. Passaram 36
comparações pequenas com enumeração integral e 72 mensagens plantadas por
perfil, verificando que a mensagem verdadeira estava incluída nos caminhos.

**Um caminho de nota máxima não recupera necessariamente a mensagem exata.**
No modelo geral, apenas 25 das 72 mensagens plantadas foram recuperadas
sem diferenças. Nos outros casos, substituições locais recebem nota maior.
Por exemplo, o modelo pode preferir uma letra errada em uma frase ainda
reconhecível. Logo, testar somente o máximo linguístico não esgota as
possíveis senhas dessa cifra. [Controles completos](general_english/controls_detailed.json).

Nos campos reais, nenhum máximo forma uma mensagem coerente. No perfil
geral, o melhor DBBI tem nota `-4,92775` e o melhor FAED `-5,31184`; o controle
conhecido da fase 3.2 tem `-4,18034`. Essas comparações são diagnósticas,
sem transformar uma nota de linguagem em autenticação criptográfica.

Não foram examinados todos os alfabetos possíveis, VIC completo com suas
transposições, todos os deslocamentos das chaves decimais, truncamento de
padding do checkerboard, mapas de dígitos desconhecidos ou toda saída de
nota inferior. Esta rodada não exclui a família VIC inteira.

## 4. AES e chave pública

Cada caminho guardado foi usado em maiúsculas/minúsculas, mantendo pontos,
retirando-os ou trocando-os por espaços. As formas distintas foram testadas
diretamente como senha e como SHA256 hexadecimal, nos três blobs originais,
com EVP-SHA256 e EVP-MD5. Os hashes binários dos textos foram comparados como
escalares secp256k1 com a chave pública do prêmio, incluindo sua negação.

| Classificação que gerou os candidatos | Senhas novas distintas | Tentativas AES | Padding aceito | Escalares novos |
|---|---:|---:|---:|---:|
| Modelo histórico do Telegram | 493.744 | 2.962.464 | 11.443 | 246.872 |
| Modelo geral independente, descontando os anteriores | 452.656 | 2.715.936 | 10.710 | 226.328 |
| União | **946.400** | **5.678.400** | **22.153** | **473.200** |

**Zero correspondências com a chave pública e nenhuma decifração final
validada.** Nenhum corpo AES ultrapassou 59,50% de bytes ASCII imprimíveis
ou whitespace. Isso não prova que todo corpo binário seja inválido, mas os
paddings isolados não autenticam nenhum deles. A fase 3.2 conhecida serviu
de controle positivo do KDF/AES; o gerador secp256k1 foi também conferido.

PyCryptodome, em uma segunda implementação do KDF e da decifração, reproduziu
os **22.153 corpos completos com padding aceito**. Essa conferência não
reexecutou as senhas rejeitadas nem as comparações de pontos da curva.

Resultados: [primeira rodada](oracles.json),
[candidatos adicionais do modelo geral](general_english/oracles.json),
[conferência dos paddings originais](padding_verification.json) e
[conferência dos paddings adicionais](general_english/padding_verification.json).
A versão original do validador, antes de acrescentar seleção de perfil e
reutilização de candidatos, está preservada em
[oracle-original-source.txt](oracle-original-source.txt).

## Reprodução

O perfil independente é selecionado explicitamente:

```powershell
$env:GSMG_CHECKERBOARD_PROFILE = 'general'
node solver/ambiguous_checkerboard.cjs run
node solver/checkerboard_matrix_keys.cjs
node solver/verify_ambiguous_checkerboard.cjs
node solver/checkerboard_oracles.cjs
```

Para reproduzir a rodada histórica com o modelo Telegram, usar
`$env:GSMG_CHECKERBOARD_PROFILE = 'telegram'` e os mesmos comandos. A validação
geral reutiliza a lista de candidatos já examinados na rodada histórica e
verifica os hashes desses arquivos antes de evitar testes duplicados.

Programas: [buscador](../../solver/ambiguous_checkerboard.cjs),
[chaves da matriz](../../solver/checkerboard_matrix_keys.cjs),
[verificador independente](../../solver/verify_ambiguous_checkerboard.cjs),
[oráculos](../../solver/checkerboard_oracles.cjs).
