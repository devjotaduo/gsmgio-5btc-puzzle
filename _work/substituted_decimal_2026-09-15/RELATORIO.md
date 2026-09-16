# Substituição decimal desconhecida e segmentação

15/09/2026, America/Sao_Paulo. **Objetivo final ainda não alcançado: não
há senha nem chave do prêmio recuperada.** Esta rodada testa premissas de
representação dos campos, não apenas novas palavras como senhas.

## Uso da skill solicitada

Foi lida `C:/Users/ruthe/.agents/skills/find-skills/SKILL.md`, consultado o
[catálogo](https://skills.sh/) e executado `npx --yes skills find cryptanalysis`.
A busca retornou `yaklang/hack-skills@classical-cipher-analysis` com cerca de
3 mil instalações. O [repositório de origem](https://github.com/yaklang/hack-skills)
tinha 2.215 estrelas na consulta à API do GitHub desta rodada. A skill já
estava instalada em `.agents/skills/classical-cipher-analysis/SKILL.md`; não
foi necessária nova instalação. Foi aplicado seu passo de identificar a
representação antes de escolher a cifra.

## 1. A leitura decimal falha mesmo com o alfabeto desconhecido?

Modelo:

1. Escolher qualquer bijeção entre `a..i` e os dígitos `1..9`.
2. Escolher qualquer um dos nove símbolos para também representar zero.
   Cada ocorrência desse símbolo decide independentemente entre zero e o
   dígito atribuído. Os outros oito símbolos conservam seus dígitos.
3. Interpretar todo DBBI ou FAED como um inteiro decimal e convertê-lo em
   bytes mínimos big-endian. Exigir todos os bytes abaixo de 128,
   inclusive controles ASCII.
4. Testar o campo completo original e inteiramente invertido.

São `9! × 9 × 2 × 2 = 13.063.680` configurações de mapa/símbolo/campo/direção.
Todas terminaram, cobrindo todas as escolhas de zero dentro de cada uma.
A busca usa limites de intervalos, sem enumerar fisicamente cada máscara.
Zeros iniciais estão incluídos.

| Símbolo que também pode ser zero | Configurações completas | Candidatos de sete bits |
|---|---:|---:|
| a | 1.451.520 | 0 |
| b | 1.451.520 | 183 |
| c | 1.451.520 | 0 |
| d | 1.451.520 | 0 |
| e | 1.451.520 | 0 |
| f | 1.451.520 | 0 |
| g | 1.451.520 | 0 |
| h | 1.451.520 | 0 |
| i | 1.451.520 | 0 |

Os 183 candidatos são de DBBI: 113 na ordem original e 70 na inversa.
**Nenhum é inteiramente imprimível**, mesmo permitindo TAB/LF/CR.
FAED não tem nenhuma saída de sete bits em todo o espaço declarado.

As saídas de DBBI foram testadas como senha crua e SHA256-hex: 366 senhas,
2.196 tentativas AES nos três blobs e dois digests EVP, seis paddings,
nenhuma decifração validada. Houve 7.509 comparações de chaves candidatas
com a coordenada x da chave pública do prêmio, incluindo a possibilidade
de chave negada: zero correspondências.

O teste de chaves cobre SHA256 das saídas e janelas big-endian de 32 bytes
das saídas e dos plaintexts com padding aceito, além de trechos hexadecimais
de 64 caracteres. Não cobre todas as derivações possíveis.

### Conferência independente

O buscador usa o sucessor numérico formado por bytes admissíveis e
permutações pelo algoritmo de Heap. Outro programa usa contagem de inteiros
admissíveis em intervalos, permutações por recursão lexicográfica e visita
primeiro o ramo oposto da árvore.

Essa segunda enumeração confirmou **13.063.680 configurações, 42.443.886 nós
e os 183 candidatos exatos**. Também foram conferidos os hashes, tamanhos
e totais dos 36 arquivos de contagem. Controles do buscador: 81 casos
comparados com força bruta, 27 recuperações plantadas e verificação das
362.880 permutações distintas. Controles aritméticos do verificador:
65.536 inteiros pequenos e 300 mudanças de comprimento.

A conferência AES usa remoção manual de PKCS#7 e reproduz todos os
sucessos, fracassos e plaintexts. A fase 3.2 conhecida e a chave privada
escalar 1 são controles positivos.

Arquivos: [`spec.json`](spec.json), resultados `alias-a.json` até
`alias-i.json`, [`verification-all.json`](verification-all.json) e
[`aes_verification.json`](aes_verification.json).

## 2. E se o campo contiver vários números menores?

Aqui se conserva o mapa conhecido `a=1..i=9`, permitindo qualquer um dos
nove símbolos como zero ou seu dígito original em cada ocorrência.

Foram testadas **todas as larguras de bloco de 1 até o comprimento do campo**,
ambos os campos e suas inversões. Cada bloco é convertido separadamente
de inteiro decimal para bytes mínimos big-endian; o último bloco curto é
preservado. A saída precisa ser ASCII imprimível ou TAB/LF/CR.

Resultado: **11.898 modelos completos, todos excluídos**. Cada exclusão
registra um bloco impossível, sem descartar letras do campo. Um contador
aritmético distinto verificou os 15.464 certificados de intervalos e a
cobertura de todas as máscaras do bloco testemunha.

Também foi testada a concatenação de códigos ASCII decimais de tamanhos
variáveis: por exemplo, `65 32 66` sem separadores representa `A B`.
Programação dinâmica a partir do início e recursão a partir do fim
confirmaram **zero segmentações nos 36 casos**. Essa gramática não permite
zeros extras à esquerda de cada código.

Controles: 65.536 contagens de inteiros, 36 modelos plantados recuperados
e 18 casos comparados com enumeração bruta.
Resultados: [`chunk_summary.json`](chunk_summary.json),
[`chunk_cases.json`](chunk_cases.json) e
[`codepoint_cases.json`](codepoint_cases.json).

**Limite essencial:** o teste por blocos usa o mapa conhecido. Ele não
combina todas as substituições desconhecidas da seção 1 com todas as
segmentações da seção 2. Não há alegação de excluir essa combinação.

## 3. Primos como expoentes: uma restrição imediata

A codificação usual de Gödel de uma lista positiva contém o fator
`2^n`, com `n > 0`, e portanto é par. A definição por produto de potências
de primos está descrita na
[exposição de Gödel numbering](https://plato.stanford.edu/archives/spr2024/entries/goedel-incompleteness/sup1.html).

Com o mapa `a=1..i=9` e somente `g` ambíguo, DBBI original termina em `e=5`
e FAED original em `c=3`: ambos são ímpares, independentemente das escolhas
de `g`. Isso exclui a leitura direta como a codificação usual de uma lista
estritamente positiva. Não exclui listas começando por zero, primos
iniciados em 3, números acrescidos/decrementados ou a ordem invertida.
Nenhuma relação do criador com essa técnica foi encontrada; era uma
hipótese estrutural, não uma dica confirmada.

## Reprodução

```powershell
node solver/substituted_decimal_constraints.cjs all
node solver/verify_substituted_decimal.cjs all
node solver/verify_substituted_aes.cjs
node solver/decimal_chunk_constraints.cjs
```

A busca principal reutiliza resultados terminados somente quando os hashes
do código e da entrada coincidem. Nenhum programa envia candidatos à rede
nem movimenta fundos.

## Consequência para o objetivo

A substituição desconhecida não corrige a conversão do campo inteiro para
texto nestes modelos. A segmentação uniforme também não corrige a leitura
com o mapa conhecido. Repetir apenas novas permutações ou escolher outro
símbolo isolado para zero nessa mesma representação não abre uma nova frente.

O objetivo permanece recuperar a senha e o resultado final, validando os
blobs originais e, quando pertinente, a chave pública do prêmio. Ele não
foi redefinido como completar essas buscas. As próximas hipóteses precisam
explicar uma operação adicional ou uma representação diferente a partir
das pistas; os resultados desta rodada não escolhem qual delas é a correta.
