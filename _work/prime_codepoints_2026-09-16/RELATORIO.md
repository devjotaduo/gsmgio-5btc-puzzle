# Primos como códigos de caracteres — 16/09/2026

**Nenhuma senha ou chave final encontrada.** Esta é uma hipótese explícita
para a pista dos primos, sem confirmação de que seja a cifra do puzzle.

## Modelo e resultados

Cada caractere seria substituído por um primo e os códigos decimais seriam
concatenados. Foram testadas dez tabelas: `A=p1,...,Z=p26`, com espaço
ausente/0/1/p27, e primos indexados por ASCII, ASCII+1 ou ASCII−31, com
repertórios de letras/espaço e ASCII. Para cada tabela: DBBI/FAED completos,
nos dois sentidos, códigos mínimos ou preenchidos com zeros até três
dígitos, e três mapas: a=1,...,i=9 com g zerável, o mesmo mapa com até duas
letras zeráveis, ou qualquer bijeção 1,...,9 com até duas letras zeráveis.
Cada ocorrência pode usar o dígito positivo ou zero; não há remoções.

Os **240 modelos** terminaram em **238 exclusões e duas compatibilidades**.
Os dois limites iniciais foram resolvidos no follow-up; nenhum caso segue
inconclusivo. Um segundo programa regenerou as tabelas com crivo,
verificou 80 casos por DP de sufixos, 36 por outro parser com mapa
desconhecido, 60 por comprimento, 60 pela capacidade da última coluna
decimal e quatro pela enumeração exata abaixo.

Para códigos de três dígitos, DBBI tem comprimento incompatível. FAED usa
nove símbolos na última coluna; nenhuma tabela admite nove dígitos finais
distintos, mesmo concedendo até duas letras zeráveis. Essa contradição
dispensa uma busca de senhas.

## Exceção A=2, B=3, ... e espaço=0

Só DBBI com mapa desconhecido admite essa leitura, nos dois sentidos.
Foram enumeradas **9! bijeções × 36 pares de letras zeráveis × quatro
campos/sentidos = 52.254.720 configurações**. Pares de capacidades cobrem
também casos que efetivamente usam zero em nenhuma ou apenas uma letra.

| Campo | Sentido | Configurações compatíveis | Soma das contagens de caminhos |
|---|---|---:|---:|
| DBBI | original | 498 | 289.471.080 |
| DBBI | inverso | 42 | 189.780.804 |
| FAED | original | 0 | 0 |
| FAED | inverso | 0 | 0 |

A soma de 479.251.884 caminhos **não é uma contagem de textos distintos**:
configurações podem compartilhar saídas. O autômato de prefixos representa
simultaneamente todas as fronteiras de caracteres e escolhas de zero.
Outro programa reverteu códigos e fontes, usou outro autômato e outra
ordem de permutações e reproduziu todas as 52.254.720 decisões. Também
recontou os caminhos e recodificou as 540 testemunhas.

Um filtro exato de palavras do corpus Norvig foi aplicado a todos os
caminhos dessas configurações. Cada trecho entre espaços realmente
decodificados precisava ser uma palavra do vocabulário de 333.296 entradas;
palavras de uma letra só A/I, tamanho máximo 32, espaços repetidos e nas
extremidades permitidos. **Nenhuma configuração contém uma frase sob
esse filtro.** Dois algoritmos distintos de DP concordaram. Isso não
exclui nomes desconhecidos, outras línguas, texto sem espaços ou outra
camada cifrada. O filtro tem três frases plantadas de controle.

## Teste criptográfico da amostra

Uma testemunha por configuração, mais as duas do parser inicial, deu
**530 textos distintos**. Maiúsculas/minúsculas e formas com/sem espaços
geraram 2.120 materiais e 4.240 senhas diretas/SHA256-hex. Nos três blobs,
com EVP-SHA256 e EVP-MD5: **25.440 decisões AES**, 106 aceitações de padding
e nenhum resultado autenticado. A maior fração textual foi 50,63%.

Foram comparados **234.488 escalares distintos** com a chave pública do
prêmio e seu negativo: nenhum acerto. Incluem SHA256 de cada senha,
janelas de 32 bytes dos materiais e SHA256/janelas dos corpos com padding,
nos dois sentidos de bytes. PyCryptodome e coincurve reproduziram todas
as decisões, corpos e comparações, com controles da fase 3.2 e secp256k1.
**Os demais caminhos não foram testados como senhas.**

## Reprodução e evidências

Os produtores recusam sobrescrever resultados existentes. A ordem usada:

```powershell
node solver/prime_codepoints.cjs
# followup.jsonl registra a conclusão dos dois casos inicialmente limitados.
node solver/prime_space_dfa.cjs
node solver/verify_prime_space_dfa.cjs
node solver/prime_space_words.cjs
node solver/verify_prime_codepoints.cjs
node solver/prime_codepoint_oracles.cjs
```

- [Especificação](spec.json), [240 decisões](cases.jsonl), [follow-up](followup.jsonl),
  [verificação independente](verification.json).
- [Especificação do autômato](space_dfa_spec.json), [enumeração](space_dfa_summary.json),
  [conferência](space_dfa_verification.json), [testemunhas](space_dfa_results.jsonl).
- [Filtro de palavras](word_filter_summary.json), [testes criptográficos](candidate_auth.json),
  [conferência PyCryptodome/coincurve](candidate_auth_verification.json).

SHA256 dos resultados: `cases.jsonl`
`c49b85b13654c63a23845a37659507e71fd715188f8e301f37d385f4048e19c2`;
flags do autômato
`fde4d638fd6f29c66b5c0514e6cc0830d633a0009258a69d0f15ae3e8b23cc84`;
autenticação da amostra
`fdb8e4f0170d17bdb294683e1cf27a471f17157872438b8b65f8cdf708075750`.
