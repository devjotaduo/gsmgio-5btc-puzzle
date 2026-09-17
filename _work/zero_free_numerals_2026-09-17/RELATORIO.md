# Codificações sem zero, sem escolha de palavras da comunidade

**17/09/2026 — não houve abertura autenticada nem chave do prêmio.** A rodada
partiu do alfabeto a–i e dos comprimentos integrais de DBBI/FAED, sem fixar
L84, Bifid, marcadores primos ou uma frase extraída do Telegram.

## Hipóteses e cobertura

| Modelo | Cobertura completa dentro do modelo | Resultado |
| --- | ---: | --- |
| Base 9 bijetiva: dígitos 1–9, inteiro integral, bytes mínimos | 9! mapas × dois campos × duas direções = 1.451.520 | Nenhuma saída inteira de sete bits; nenhum quadro de 32 bytes + checksum de quatro bytes em DBBI, nas duas ordens de bytes |
| Códigos ASCII/CP1141 decimais com **todos os zeros apagados** | 9! mapas × quatro campos/direções × seis repertórios = 8.709.120 | FAED incompatível em todos; DBBI admite 192.969 modelos do repertório amplo |
| Dois trits por símbolo, cinco trits por byte | 9! mapas × duas direções de FAED × pares adjacentes/coordenadas separadas = 1.451.520 | Nenhuma saída inteira de sete bits |

Base bijetiva não é a conversão usual de base 9 com dígitos 0–8 já testada no
histórico. A segunda hipótese elimina o dígito zero de cada código decimal;
não o substitui por uma letra nem escolhe posições para inseri-lo. A terceira
usa 1.140 trits de FAED para formar exatamente 228 bytes. Os 182 trits de DBBI
não cabem integralmente nesse agrupamento e ficaram fora desse modelo.

Os seis repertórios são ASCII e CP1141, cada um com minúsculas/espaço,
maiúsculas/espaço ou ASCII visível mais TAB/LF/CR. Todas as segmentações de
códigos são consideradas na decisão de compatibilidade.

DBBI teve 78.480 modelos ASCII no sentido original, 114.480 no inverso e nove
CP1141 no inverso. Nenhum repertório de uma só caixa mais espaço funcionou.
Esses números representam gramáticas compatíveis; não representam mensagens
legíveis ou senhas corretas.

## Continuação dos modelos positivos

Foram enumerados todos os **10.356 textos** dos nove modelos CP1141. Nos
modelos ASCII, o dicionário Norvig preexistente admitiu 113.108 modelos e
309.717.866.762.148.758.807 caminhos. O filtro é permissivo: siglas, nomes e
pontuação podem produzir sequências sem sentido. Testou-se apenas o melhor
caminho de cada modelo, priorizando letras, menos separadores e frequência
das palavras. **Não foram esgotados esses caminhos ambíguos.**

Foram também verificadas as gramáticas exatas de chave hexadecimal de 64
caracteres e WIF de 51/52 caracteres. Nenhum modelo passou. A conferência
adicional de hexadecimal com caixa arbitrariamente misturada também deu
zero, antes mesmo da restrição de comprimento.

Os 123.464 materiais distintos foram usados diretamente e como SHA256
hexadecimal nos três blobs AES **originais**, com EVP_BytesToKey SHA256 e
MD5: **1.481.568 decisões AES**. Os 5.772 paddings válidos por acaso tiveram
no máximo 58,23% de bytes ASCII visíveis/controles. Nenhum atingiu o filtro
de 85% ou continha os marcadores `Salted__`/`U2FsdGVk`.

A comparação na curva testou 5.485.056 escalares distintos: hashes dos
materiais, material integral quando tinha 32 bytes, todas as janelas de 32
bytes dos resultados com padding em ambas as ordens e hashes desses
resultados. **Nenhum gerou a chave pública original do prêmio.** Não se
afirma que todo possível conteúdo binário ou toda segmentação ASCII foi
testada.

Um teste estrutural adicional tratou os nove símbolos como oito comandos
Brainfuck mais um símbolo ignorado. Nenhum par possível de colchetes tem
contagens iguais e todos os prefixos balanceados, nos campos integrais e
nas duas direções. Isso exclui apenas essa leitura literal como programa
completo, sem rotações, cortes ou outras transformações.

## Conferência e reprodução

Os [checkpoints independentes](independent_verification.json) registram:

- DP de fronteiras, diferente da máquina de prefixos do produtor, reproduz
  as 8.709.120 decisões de códigos sem zero;
- aritmética em blocos de 16 dígitos reproduz as 1.451.520 decisões de base 9;
- agrupamento de cinco símbolos reproduz as 1.451.520 decisões ternárias;
- PyCryptodome reproduz todas as decisões AES, inclusive os bytes dos paddings;
- coincurve/libsecp256k1 compara os candidatos com o ponto público do prêmio;
- o controle AES conhecido da fase 3.2 abre 2.422 bytes, SHA256
  `b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34`.

Os produtores passaram nove controles de base bijetiva, 18 de remoção de
zeros, quatro de trits e controles de texto/dígitos hex conhecidos. A
enumeração de permutações foi conferida por cobertura lexicográfica
independente e unicidade dos 362.880 mapas.

Na raiz do repositório, com Node 24, use **pastas novas**:

```powershell
node solver/zero_free_numerals.cjs _work/zero_free_repro/run1
node solver/zero_free_plaintexts.cjs _work/zero_free_repro/run1 _work/zero_free_repro/plaintexts
node solver/ternary_byte_packing.cjs _work/zero_free_repro/ternary
node solver/verify_zero_free_numerals.cjs _work/zero_free_repro
```

Entradas: `_work/prime_geometry_2026-09-11/inputs.json`; tabela local
`_work/ebcdic_decimal_2026-09-16/encoding.json`; corpus local
`_work/checkerboard_exact_mask_2026-09-16/count_1w.txt`. Os códigos usados
estão integralmente no [spec](run1/spec.json), com hashes das dependências.
O corpus não vem do Telegram. O campo histórico
`dictionaryBestPathsAuthenticated` no JSON conta caminhos **testados**, não
autenticados: `authenticatedSolution` permanece falso.

Decisões AES SHA256:
`250ce858019d381edd0e9b76ac4f4b33163d2aafa0cb171be953943a048faab2`.
Saídas grandes permanecem locais; resumos, especificações e controles são
compactos. Não há processo desta campanha ainda em execução.

O resultado restringe estas representações diretas. Não exclui uma cifra
adicional, outra codificação, dados binários ou os caminhos ASCII não
selecionados pelo filtro de linguagem.
