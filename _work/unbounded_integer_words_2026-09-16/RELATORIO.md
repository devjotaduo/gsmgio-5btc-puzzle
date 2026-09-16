# Inteiro decimal zerável com restrições de palavras

**Resultado: a senha final continua desconhecida.** Dez dos dezesseis modelos
terminaram; seis continuam parciais. A união de todas as saídas encontradas tem
100.404 candidatos. Nenhum abriu um bloco de forma validada ou produziu a chave
pública do prêmio nas formas de senha e escalar declaradas abaixo.

## Hipótese e limites

O ponto de partida é o mesmo da investigação anterior: cada ocorrência de
`a..i` pode representar seu valor `1..9` ou zero, independentemente das outras.
Todo o campo decimal é convertido em um inteiro e depois em bytes big-endian
sem zeros à esquerda. Isso permite longos prefixos decimais zerados. DBBI e
FAED são examinados em seus sentidos original e invertido.

Esta rodada acrescenta um filtro: cada sequência máxima de letras ASCII deve
constar no corpus de palavras, com no máximo 32 letras e apenas `a` ou `i`
como palavras de uma letra. Há dois vocabulários, ambos derivados do arquivo
Norvig já preservado no repositório:

- Completo: 333.296 entradas.
- Contagem de pelo menos um milhão no corpus: 26.264 entradas.

O corpus inclui abreviações, siglas e ruído de páginas web. Portanto,
compatibilidade com ele não demonstra inglês coerente.

Também há dois modelos de caixa: mistura livre dentro de cada palavra ou
somente minúsculas, inicial maiúscula ou maiúsculas em cada palavra. Dígitos
`0..9`, TAB/LF/CR e os caracteres ` !"'(),-./:;?` separam palavras. Sequências
compostas apenas desses separadores e dígitos também são admitidas. Não foram
incluídos nomes ausentes do corpus, palavras concatenadas que não constem
nele, Unicode, outra substituição de dígitos ou uma cifra adicional.

A pista do criador sobre caracteres zerados motiva examinar zeros. A escolha
deste modelo numérico e do filtro lexical é do solver; não é uma instrução
confirmada do criador.

## Resultados exatos e parciais

Os números da tabela são candidatos por modelo, com sobreposição entre
colunas. O asterisco indica uma busca **parcial**, limitada por nós/tempo.

| Campo/sentido | Frequentes, caixa livre | Completo, caixa livre | Frequentes, caixa por palavra | Completo, caixa por palavra |
|---|---:|---:|---:|---:|
| DBBI original | 547 | 25.962 | 41 | 243 |
| DBBI invertido | 147 | 3.208 | 30 | 106 |
| FAED original | 3.944* | 9.020* | 2.222 | 19.916* |
| FAED invertido | 3.579* | 8.430* | 5.766 | 18.901* |

Os oito modelos DBBI terminaram. Os dois modelos FAED com vocabulário de
maior contagem e caixa por palavra também terminaram. Cada modelo completo
cobre `2^91` ou `2^570` atribuições, por intervalos e não por enumeração de
cada atribuição. Os outros seis modelos FAED não estão esgotados.

Dois casos inicialmente limitados foram continuados apenas nas máscaras
pendentes: DBBI original/completo/caixa livre e FAED invertido/frequentes/caixa
por palavra. Ambos terminaram. Seus arquivos antigos permanecem como
histórico; os arquivos `_resumed.json.gz` substituem seu estado atual.

Os dezesseis estados atuais contêm 2.754.072 certificados terminais, incluindo
exclusões, candidatos e máscaras pendentes. A maior saída encontrada tem
192 bytes, mas contém sequências curtas de siglas e pontuação. A maior
sequência contínua de letras entre os 100.404 candidatos tem apenas seis
letras. Não surgiu uma instrução reconhecível nos candidatos inspecionados;
essa avaliação visual não substitui a autenticação.

## Método e conferência

O produtor calcula o menor inteiro maior ou igual a um limite cujo texto
seja aceito por um autômato de palavras. Se esse inteiro ultrapassa o limite
superior de uma máscara decimal, a máscara inteira é excluída. Distâncias
até palavras terminais permitem decidir se um prefixo pode ser completado
com o número de bytes restante.

Uma implementação Python separada reconstrói os vocabulários e usa um teste
de existência com limites inferior e superior em bytes, sem chamar o
algoritmo de sucessor. Ela verifica cada exclusão, cada candidato, cobertura
disjunta das máscaras e contagens, inclusive nos arquivos parciais. Também
reconstrói as três listas de candidatos preservadas. Os 18 registros incluem
os dois estados antigos continuados; correspondem a 16 modelos distintos.

Os controles do produtor incluem comparação com enumeração integral em
campos curtos e vinte recuperações plantadas, como `The 42`, `THE` e `Hi!`.
A conferência independente compara seu teste de intervalos com enumeração
literal em 479 intervalos por combinação de vocabulário e caixa.

## Autenticação dos candidatos encontrados

As três listas de candidatos foram unidas sem duplicatas. Cada uma das
100.404 saídas foi testada diretamente como senha e como SHA256 hexadecimal:
200.808 senhas distintas.

- SMALL, TAIL32 e COSMIC, com EVP-SHA256 e EVP-MD5: **1.204.848 decisões AES**.
- 4.778 paddings válidos, sem conteúdo autenticado. A maior proporção de
  ASCII imprimível/TAB/LF/CR foi 59,49%.
- **200.808 escalares** sem correspondência com a chave pública do prêmio
  ou sua negação. O conjunto inclui SHA256 das senhas; corpos inteiros de
  32 bytes ou 64 dígitos hexadecimais seriam incluídos se encontrados.

PyCryptodome reproduziu todas as decisões AES e corpos com padding; coincurve
reproduziu as comparações de pontos. A fase 3.2, o gerador da curva e o HASH160
do alvo foram controles positivos. Não houve movimentação de fundos.

Isso autentica negativamente somente os candidatos **encontrados**, nas
formas declaradas. Não testa todas as composições possíveis com últimas
palavras, inversão dos bytes decodificados ou resultados dos ramos pendentes.

## Artefatos

- [Especificação de caixa livre](spec.json) e [resultados iniciais](summary.json).
- [Especificação de caixa por palavra](wordcase_spec.json) e [resultados](wordcase_summary.json).
- [Continuações concluídas](resume_summary.json) e [estado atual consolidado](latest_summary.json).
- [Conferência dos intervalos e candidatos](verification.json).
- [Autenticação](oracles.json) e [conferência independente](oracle_verification.json).
- [Candidatos de caixa livre](candidates.json), [caixa por palavra](wordcase_candidates.json)
  e [continuações](resume_candidates.json).

Programas: [busca lexical](../../solver/unbounded_integer_words.cjs),
[caixa por palavra](../../solver/unbounded_integer_wordcase.cjs),
[continuação](../../solver/unbounded_integer_words_resume.cjs) e
[autenticação](../../solver/unbounded_integer_words_oracles.cjs).
As conferências Python foram executadas inline; árvores e parâmetros de
entrada estão preservados para reprodução. Os programas recusam sobrescrever
os resultados existentes.

SHA256 de `oracles.json`:
`163333a4ab2e8d9bd9dddd885d297a6dba6dec404e2918f86ab520d28f24dd5d`.

A transformação pretendida para `matrixsumlist`, a senha dos blocos ainda
fechados e a chave final continuam sem identificação. Não há processo desta
rodada em execução; os seis modelos parciais têm suas máscaras preservadas.
