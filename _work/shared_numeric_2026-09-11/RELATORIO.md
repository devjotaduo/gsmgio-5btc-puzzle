# DBBI/FAED: mapa comum, bases primas e origem de ASCII 127

Data: 11/09/2026. Continuação da [receita original de X](../blue_hex_2026-09-11/RELATORIO.md), depois da [leitura integral do ENDGAME](../endgame_review_2026-09-11/LEITURA_ENDGAME.md).

**Atualização de 16/09/2026:** a busca FAED/base127 foi
[concluída e conferida integralmente](../radix127_completion_2026-09-16/RELATORIO.md),
com exatamente 188 saídas e nenhum caso pendente. Os onze textos adicionais
também foram testados, sem senha autenticada. Os registros abaixo preservam
o estado histórico de 177 candidatos; não é necessário retomar aquela busca.

**Nenhuma abertura validada de SMALL, TAIL32 ou COSMIC.** A pesquisa recuperou a fala original sobre ASCII 127 e delimitou modelos numéricos específicos. A busca de FAED na base 127 permanece parcial; os 177 candidatos encontrados foram conferidos e testados como senhas, sem resultado validado. SalPhaseIon → SMALL permanece a prioridade de pesquisa, sem atribuir uma probabilidade numérica não sustentada.

## 1. Fonte primária de “ASCII 127”

No `result.json`, a mensagem **#32613**, de **Jrk Bgrt**, datada de **2024-11-29T07:47:19** no export, diz:

> I think I'll be going for ASCII 127 myself. But not overly dramatic.

Ela responde diretamente à **#32600**, de ArchOptic: “What character do I have to imagine myself as?”. A conversa próxima menciona temas e personagens do puzzle. A atribuição da frase ao criador está documentada; sua aplicação criptográfica não é explicitada nessa resposta.

X respondeu na **#32615**, em 29/11/2024, associando `ourfirsthintisyourlastcommand` ao último código ASCII, DEL, e ao primo 127. **A mesma interpretação já aparece na #25419, de X, em 06/05/2024**, antes da fala de Jrk. Não foi encontrada uma resposta posterior do criador endossando diretamente #32615 no trecho #32620–#32700 examinado.

A tabela técnica confirma **127 = DEL**, mas não transforma essa fala numa instrução de apagar posições específicas, substituir `g` por zero ou usar uma base numérica. [RFC 20](https://www.rfc-editor.org/rfc/rfc20.html).

Fontes locais: [ocorrências e autoria](ascii127_provenance.json), [contexto e respostas diretas](ascii127_context.json), [seguimento examinado](ascii127_followups.json). Os horários acima são os do export, sem inferir fuso. A dúvida pública sobre a origem da frase também aparece na [issue #104](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/104); a recuperação local não foi publicada externamente.

## 2. Um único alfabeto hexadecimal bijetivo não serve aos dois campos

Foram examinados os 36 pares de símbolos de `a..i` como prefixos de tokens de dois caracteres. A leitura é gulosa, da esquerda para a direita, na ordem original: um símbolo prefixo consome também o seguinte; os demais formam tokens simples.

Só o par **`b/g`** produz **64 tokens de 16 tipos** para DBBI. O par `b/c` também produz 64 tokens, mas de 18 tipos; FAED termina com um prefixo incompleto nessa leitura.

Com os mesmos prefixos `b/g`, FAED produz **451 tokens de 25 tipos**. Os nove tipos adicionais são:

```text
bc bd bg bi ga gc gd gf gh
```

Portanto, os dois campos não podem ser simultaneamente texto hexadecimal sob **a mesma substituição bijetiva token → dígito hexadecimal**. Isso não exclui mapas diferentes, substituição homofônica, um alfabeto de 25 letras, funções distintas para os campos ou outras tokenizações. Também não autentica DBBI como hash apenas por ter 64 tokens/16 tipos. [Resultados dos 36 pares](shared_prefix_constraints.json).

## 3. Triagem aritmética limitada

Interpretando cada campo inteiro como decimal com `a=1..i=9`, foram avaliados dois mapas globais: todos os `g` como 7 ou todos como 0. DBBI tem 302 bits e FAED, 1.893 bits nos dois mapas.

| Campo / mapa | Fatores primos encontrados até 100.000 | Cofator restante |
|---|---|---|
| DBBI, `g=7` | `5^3 × 109` | Composto, 288 bits |
| DBBI, `g=0` | `5^3 × 17 × 18043 × 75797` | Composto, 260 bits |
| FAED, `g=7` | Nenhum | Composto, 1.893 bits |
| FAED, `g=0` | Nenhum | Composto, 1.893 bits |

Nenhum dos quatro inteiros é uma potência perfeita. Isso é somente divisão experimental por primos até o limite indicado e teste de potência; **não houve fatoração completa**, nem exclusão de modelos gerais de fatoração/RSA. [Valores e cofatores](trial_division.json).

## 4. Bases primas: hipótese e cobertura exatas

Hipótese testada:

1. Manter a ordem original e converter `a..i` em dígitos `1..9`.
2. Permitir que **cada ocorrência de `g` seja independentemente 0 ou 7**.
3. Interpretar o campo inteiro como um único número decimal.
4. Representá-lo numa base prima, com o dígito mais significativo primeiro e sem zeros iniciais.
5. Interpretar cada dígito dessa representação diretamente como código ASCII; aceitar somente **32–126, TAB 9, LF 10 e CR 13**.

Foram testados **todos os 55 primos até 257**. A motivação é combinar a conversão numérica já presente na página com a referência a primos. A escolha desse mecanismo é uma hipótese nossa, não uma instrução comprovada do criador.

| Campo | Espaço de máscaras | Cobertura | Resultado |
|---|---:|---|---|
| DBBI | `2^10 = 1.024` | Todas as 55 bases, completa | Nenhuma saída inteiramente no conjunto ASCII aceito |
| FAED | `2^107` | 54 das 55 bases, completa por restrições | Nenhuma saída inteiramente no conjunto ASCII aceito |
| FAED / base 127 | `2^107` | **Parcial, limite de tempo** | 177 saídas de 271 caracteres; nenhuma abertura validada |

As exclusões não exigem enumerar `2^107` máscaras. Cada prefixo de escolhas define um intervalo inteiro contendo todas as continuações possíveis. O algoritmo calcula o menor inteiro nesse intervalo que poderia ter apenas dígitos permitidos na base testada. Se ele excede o máximo do intervalo, elimina o ramo inteiro. A poda é exata; o limite de tempo é declarado separadamente.

Por exemplo, em FAED o primeiro dígito é obrigatoriamente 3 na base 101, 18 na base 163, 4 na base 193 e 11 na base 257. Esses códigos já violam o conjunto aceito. Isso **não exclui dados binários**, outros controles ASCII, cabeçalhos descartáveis, outras ordens, agrupamentos ou deslocamentos de códigos.

Foram concluídas **109 de 110 buscas campo/base**. Uma implementação independente em Python reproduziu todas as 109 exclusões, usando 189 nós de restrição no total. Para DBBI, uma enumeração independente das 56.320 combinações máscara/base também concordou.

A busca parcial FAED/127 acumulou **3.932.596 nós e 360.002 ms** em duas execuções limitadas. O ponto de retomada está salvo em `resumeMinDecimal`. Os 177 resultados são ASCII **por construção** e não constituem, por isso, evidência de texto intencional. Não se assume que sejam todos os resultados possíveis. Nenhuma execução ficou em segundo plano.

Artefatos: [especificação](prime_radix_spec.json), [resultados por campo/base e ponto de retomada](prime_radix_results.json), [resumo e candidatos](prime_radix_summary.json), [enumeração independente de DBBI](dbbi_prime_radices.json), [conferência independente das exclusões](independent_constraints.json).

## 5. DEL como remoção e máscaras derivadas das pistas

Também foi examinada a remoção literal de cada `g` de DBBI, independentemente, ou sua manutenção como 7. As 1.024 máscaras geram **576 inteiros distintos**, pois apagar símbolos adjacentes iguais pode dar o mesmo número. Nas 55 bases primas e na base 256, foram 57.344 tentativas máscara/base, correspondentes a 32.256 casos inteiro/base distintos: **nenhuma saída inteiramente no conjunto ASCII aceito**. A remoção arbitrária em FAED não foi enumerada. [Resultado](dbbi_g_deletion.json).

Para FAED/base127, foram verificadas 12 regras determinísticas de escolha dos `g` zerados: posições primas ou não primas, contadas de 0 ou de 1; ordinais primos ou não primos entre os próprios `g`, também de 0 ou de 1; e bits da matriz original por linhas ou na espiral da URL, repetidos a cada 196 posições, com cada polaridade. Todas falharam em produzir ASCII completo; a melhor ainda tem 45 dígitos fora do conjunto permitido. [Doze regras e contagens](canonical_mask_checks.json).

## 6. Validação dos 177 candidatos disponíveis

Para cada candidato foram usados o ASCII original, a remoção de todo whitespace, o original em minúsculas e o original em maiúsculas. Cada material foi testado diretamente como senha e como SHA256 em hexadecimal minúsculo.

- **708 materiais e 1.416 senhas distintos** dentro desta família.
- **8.496 tentativas AES**: os três blobs originais × EVP-SHA256 e EVP-MD5.
- **28 paddings PKCS#7 válidos**, com plaintext completo preservado; nenhum texto validado. A maior proporção de ASCII foi 48,10%.
- **206.556 escalares distintos** conferidos contra a chave pública alvo ou sua negação, sem correspondência. Incluem SHA256 das senhas, janelas contíguas de 32 bytes em ambas as ordens, e candidatos hex/WIF.
- Nenhum formato comum examinado validou os 28 plaintexts: marcadores `Salted__`, ZIP, PNG, PDF, gzip e streams completos zlib/gzip no início. Isso não cobre todos os formatos binários possíveis.

Um verificador Node independente reconstruiu os 177 inteiros, regenerou as 1.416 senhas e reproduziu **todas as 8.496 decisões AES, inclusive as falhas**, comparando os 28 plaintexts completos com a execução PyCryptodome. A fase 3.2 conhecida foi o controle positivo. Padding sozinho não autentica uma solução.

Artefatos: [especificação de candidatos](candidate_checks/spec.json), [senhas em hex](candidate_checks/passwords.jsonl), [plaintexts completos com padding](candidate_checks/padding_results.jsonl), [contagens](candidate_checks/summary.json), [conferência cruzada](candidate_checks/verification.json), [formatos examinados](candidate_checks/format_checks.json).

## 7. Reprodução e ponto em aberto

Código: [busca por restrições](../../solver/prime_radix_constraints.cjs), [verificador AES e reconstrução](../../solver/verify_prime_radix.cjs). O primeiro inclui 53 controles de sucessor, 25 comparações de máscaras com força bruta, recuperação de texto plantado nas bases 101/163/257 e comparação entre execução contínua e interrompida/retomada.

Para conferir os candidatos já salvos, na raiz do repositório:

```powershell
node solver/verify_prime_radix.cjs
```

Para continuar a única busca incompleta, usando o ponto salvo:

```powershell
node solver/prime_radix_constraints.cjs --resume
```

Cada retomada limita FAED/127 a 180 segundos ou 20 milhões de nós. Executar **sem `--resume` reinicia os resultados**. Se surgirem candidatos novos, é necessário regenerar os materiais/senhas e seus testes AES conforme a seção 6; o verificador rejeita cobertura salva que não corresponda à lista atual. As contagens deste relatório descrevem o estado de 177 candidatos, antes de qualquer retomada futura.

O avanço mais sólido foi recuperar a fonte de ASCII 127 e excluir interpretações explicitamente delimitadas. A base 127 continua aberta neste modelo, mas seus candidatos atuais não fornecem uma regra de seleção derivada das pistas. O elo prioritário continua sendo **deduzir uma transformação comum ou funções distintas para DBBI/FAED que usem integralmente as entradas e produzam uma senha verificável de SMALL**. Não há fundamento para declarar o puzzle resolvido, impossível ou dependente de informação privada.
