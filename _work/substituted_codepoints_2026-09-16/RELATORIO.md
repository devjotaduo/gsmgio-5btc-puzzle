# Alfabeto desconhecido e códigos ASCII decimais — 16/09/2026

**Nenhuma senha final encontrada. FAED é incompatível com a família definida
abaixo.** DBBI admite leituras, mas nenhuma das 3.600 sequências inteiramente
imprimíveis produziu uma abertura validada ou a chave do prêmio.

## Hipótese e lacuna anterior

O teste anterior de códigos ASCII decimais usava apenas `a=1..i=9`. A busca
anterior por alfabetos desconhecidos tratava o campo como **um inteiro
decimal completo**. As duas investigações não cobriam a combinação de um
alfabeto desconhecido com a segmentação em códigos de caracteres.

O modelo desta rodada combina exatamente essas duas escolhas:

1. Qualquer bijeção de `a..i` para os dígitos `1..9`: todas as **9!** permutações.
2. Uma letra escolhida entre as nove pode representar seu dígito ou zero,
   independentemente em cada ocorrência.
3. O campo completo, direto ou invertido, é uma concatenação das representações
   decimais mínimas de TAB, LF, CR ou ASCII 32 a 126. Por exemplo, `A0` seria
   `6548`; `a` seria `97`; `d` seria `100`.
4. Não há separadores nem zeros extras à esquerda de cada código, símbolos
   removidos, transposição adicional ou outra cifra nesse modelo.

A distinção entre códigos de caracteres e conversão do inteiro é importante:
`6548` como dois códigos significa `A0`; como inteiro e depois bytes tem
outro resultado. O uso de códigos concatenados é uma hipótese analítica,
não uma instrução confirmada pelo criador.

Antes de escolher essa frente, foi relida a exclusão já existente da forma
usual de Gödel para listas positivas. A paridade contradiz aquela leitura
direta com o mapa conhecido e `g=0/7`. Não foi repetida uma campanha de
fatoração nem alegada exclusão geral de codificações por primos.

## Cobertura e resultado

Foram decididos **13.063.680 modelos**:
`2 campos × 2 direções × 9 letras zeráveis × 362.880 alfabetos`.
Cada decisão cobre todas as escolhas de zero e todas as segmentações do
modelo, por reconhecimento exato de uma gramática finita.

| Campo | Modelos examinados | Modelos que admitem alguma leitura |
|---|---:|---:|
| DBBI | 6.531.840 | 50.808 |
| FAED | 6.531.840 | **0** |

Para DBBI, a contagem exata dos pares **modelo/caminho de leitura** é
1.208.192.544. Isso não significa esse número de mensagens distintas nem
de tentativas AES. A maior parte dessas leituras inclui TAB, LF ou CR.

- **3.600 leituras** usam somente ASCII 32 a 126; todas foram enumeradas e
  são distintas entre si.
- **Zero leituras**, mesmo permitindo todos os modelos e caminhos, contêm
  apenas letras ASCII e espaços.
- Toda leitura de DBBI exige pelo menos **sete caracteres fora de letras
  ASCII e espaço**. Pontuação, números e controles contam nessa categoria;
  isso não é uma prova de que qualquer mensagem pontuada seria impossível.
- Os caminhos com TAB/LF/CR foram contados, mas **não foram integralmente
  materializados nem testados como senhas**. A família inteira de DBBI não
  foi eliminada pelos testes AES.

Um protótipo guardava até 39 leituras arbitrárias por modelo. Essa amostragem
não indicava quais textos testar. O artefato final foi substituído pela
enumeração completa do subconjunto imprimível; as amostras iniciais não
foram usadas como evidência de senha ou de linguagem.

## Verificação independente

O buscador reconhece a linguagem por um autômato de prefixos dos códigos
decimais, acumulando as duas opções da letra zerável. Percorre os alfabetos
na ordem de Heap. Passou 81 recuperações de mensagens curtas conhecidas,
81 comparações com um decoder explícito de códigos e uma conferência das
362.880 permutações distintas.

O segundo programa **não importa o buscador nem seu autômato**. Gera os
alfabetos em ordem lexicográfica e calcula as fronteiras dos códigos por
aritmética decimal. Comparou cada uma das **13.063.680 decisões**, refez
as contagens de caminhos de todos os 50.808 modelos aceitos e recodificou
integralmente as 3.600 leituras salvas. Também calculou a restrição de
letras/espaços e o mínimo de outros caracteres. Seus 81 controles de
mensagens conhecidas passaram.

[Especificação](spec.json), [resumo](summary.json),
[modelos aceitos e leituras imprimíveis](accepted.json),
[verificação](verification.json).

## Testes das 3.600 leituras imprimíveis

Cada sequência completa foi testada diretamente como senha e como SHA256
hexadecimal. Nenhuma alteração de caixa, remoção de pontuação ou normalização
foi aplicada.

- **7.200 senhas; 43.200 decisões AES-256-CBC**, nos três blobs originais,
  com EVP-SHA256 e EVP-MD5.
- **165 paddings aceitos**, sem decifração validada. A maior fração de bytes
  ASCII imprimíveis/whitespace foi 53,16%.
- **3.600 hashes comparados como escalares secp256k1**: nenhuma correspondência
  com a chave pública do prêmio ou sua negação.
- Nenhuma leitura tem 32 bytes crus ou constitui texto Base64 canônico ou
  Base58 no reconhecimento declarado. Não foi encontrada uma chave por
  esses formatos diretos.

PyCryptodome e coincurve, em uma conferência inline separada, reproduziram
**todas as decisões AES, incluindo rejeições**, os 165 corpos completos e
todas as comparações de pontos. As entradas foram regeneradas dos candidatos.
A fase 3.2 conhecida e o gerador secp256k1 serviram como controles positivos.

[Candidatos](candidates.json), [oráculos](oracles.json),
[conferência independente](oracle_verification.json).

## Consequência e limites

Uma codificação comum de DBBI e FAED por esse mecanismo é impossível, pois
FAED não admite qualquer leitura nos alfabetos examinados. Essa conclusão
não depende de escolher um texto mais parecido com inglês. Um uso isolado
do mecanismo em DBBI permanece possível, especialmente se o resultado
contiver controles; os testes não estabelecem esse uso nem uma senha.

Não ampliar automaticamente as máscaras, a pontuação ou a gramática apenas
para admitir FAED. As lacunas que permanecem são outras transformações,
outros alfabetos, mais de uma letra zerável ou outra representação. Esta
rodada não identifica a operação pretendida de `matrixsumlist`.

```powershell
node solver/substituted_codepoints.cjs
node solver/verify_substituted_codepoints.cjs
node solver/substituted_codepoint_oracles.cjs
```

[Buscador](../../solver/substituted_codepoints.cjs),
[verificador](../../solver/verify_substituted_codepoints.cjs),
[oráculos](../../solver/substituted_codepoint_oracles.cjs).
