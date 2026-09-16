# Leitura integral e reconciliação do ENDGAME

Em 11/09/2026 foram lidas as **2.923 linhas e 131 títulos** do ENDGAME
existente antes destas anotações. O manifesto registra o hash dessa versão e
os intervalos lidos. Não foram reexecutadas todas as campanhas históricas:
os números delas continuam sendo resultados reportados pelos respectivos autores.
Foram conferidos diretamente o script original recuperado e contextos específicos
das mensagens primárias.

## Resultado que muda uma pendência documental

O arquivo **`dbbi_sum_faed.py` existe no export de Downloads**. Foi publicado
por **X, mensagem #63518, 22/05/2026 às 06:59:21**, imediatamente antes da
explicação do método em #63520. Tem **1.899 bytes**, como os metadados do export,
e SHA256:

`e4496050bb1424b87964949b160a1ac3ddc826958e0a86c89373b3d6a8ea9642`

Depois da inspeção integral do código, sua execução foi comparada com
`solver/blue_net_attack.py`: a matriz e as três saídas coincidem exatamente.

```text
JLIQFOPGVBLSENDTHECZAGJJYDSWCGUDJNFTWB
JLUPFLPGLBLUENETDICZAGAJQDSWCGUDONFHWB
OLIQUBROVQLTOSETHEXQYOJSSICJFGUDCCVBWQ
```

Isso encerra a pendência do **código ausente**, mas não autentica os fragmentos
como instruções do criador e não revela senha nova. A imagem #63517 ainda está
marcada como não incluída no export consultado. A cópia integral do script foi
preservada em `original_dbbi_sum_faed.py`, sem alterações.

**Limite do nosso teste anterior:** a hipótese excluída era
`14 valores → somas/distâncias de pares → dbbi`.
A receita de X faz `dbbi → pesos de 91 arestas → 14 somas → XOR com somas de faed`.
São sentidos e modelos diferentes. A contradição matemática do primeiro não
refuta o segundo. Este último tem resultados reproduzíveis, mas continua sem
consequência criptográfica validada; suas máscaras e palavras escolhidas exigem
cuidado com seleção posterior ao resultado.

## Como ler as conclusões conflitantes

| Afirmação encontrada no histórico | Leitura sustentada pelas verificações |
|---|---|
| Chain1–4, `cc` e os 35 blocos são o caminho validado | Os bytes são reproduzíveis; isso não autentica a senha nem o caminho. As auditorias posteriores retiram essa validação. SMALL, TAIL32 e COSMIC originais continuam sem abertura demonstrada. |
| XOR dos SHA256 reproduz `a795…`, logo a gramática é provada | A igualdade identifica a construção comunitária dessa senha. Não demonstra que o criador usou essa construção. |
| Quatro paddings `01` demonstram falsidade com probabilidade 1/65.536 | Esse cálculo presume uma distribuição de comprimentos e independência que não foram estabelecidas. Entre resultados aleatórios selecionados por padding válido, aproximadamente 255/256 terminam com pad de um byte. A crítica forte à cadeia é a falta de estrutura independente e a máscara que impõe `Salted__`, não esse produto de probabilidades. |
| `Salted__` prova EVP-SHA256 | O cabeçalho não identifica o digest. SHA256 é confirmado nos controles das fases conhecidas e deve ser priorizado; o KDF dos três blobs desconhecidos continua sem demonstração direta. |
| `BTCSEED` confirma a segunda camada e o ramo do prêmio | O prefixo é reproduzível, mas depende de somente oito posições de `faed`. Não valida os outros 562 símbolos. A raridade sob determinado modelo nulo não prova intenção nem identifica uma segunda cifra. |
| `matrixsumlist=101` está resolvido | A matriz tem 101 uns. A função desse número e das listas de linhas/colunas na senha permanece hipótese. |
| Toda cifra clássica, livro ou segunda porta foi descartada | Foram examinadas famílias delimitadas, por vezes com bons controles. Negativos não cobrem todos os alfabetos, rotas, chaves, formatos e mecanismos possíveis. |
| “Regular Bitcoin Private key” exclui BIP39 | Identifica o objetivo; não exclui uma representação ou derivação intermediária. |
| “Close friends” e laptop escondido provam que falta informação privada | São falas do criador; não demonstram que a solução pública dependa de informação privada. |
| A p.39 de Cosmic Duality foi indicada explicitamente | A correção de proveniência já registrada identifica o anexo elogiado como a capa com yin-yang. A escolha da p.39 é interpretação comunitária. |
| “Bingo” identifica inequivocamente Looking Forward | Há associação contextual plausível; não há resposta direta que nomeie livro, página ou algoritmo. |

Não é necessário aceitar todas as conclusões de uma seção para aproveitar os
testes que ela documenta. Tampouco uma seção mais recente é automaticamente
correta: fonte, método e alcance precisam concordar.

## Duas falas primárias reconferidas

**TAIL32 — 10/06/2023, #8569.** O criador escreveu três respostas sequenciais:
“Correct. / No. / Can't say anything about this.” As três mensagens anteriores
de PoW tratavam, respectivamente, do blob ainda não aberto (#8566), da hipótese
de conter a dica procurada para SalPhaseIon (#8567) e da tabela da fase 2 (#8568).
A leitura contextual favorece que o TAIL32 continuava aberto e não era aquela
dica de SalPhaseIon. Não há `reply_to_message_id`; o alinhamento é contextual.
Isso favorece manter TAIL32 como alvo paralelo, sem pressupor que abri-lo seja
pré-requisito obrigatório para SMALL.

**“Pfff. Coincidence.” — 01/09/2026, #70307.** Não tem resposta encadeada a uma
mensagem específica. Imediatamente antes, #70306 responde à numerologia de
Diego Schmidt (#70303), que relacionava um derivado de YOUWON ao número 13224
e ao passaporte de Neo. Portanto, é excessivo apresentá-la como uma refutação
formal e isolada do fragmento YOUWON original. Os testes negativos e as
ressalvas estatísticas desse fragmento permanecem; a atribuição da refutação
ao criador deve conservar esse contexto.

## Consequência para a investigação

**A SalPhaseIon continua sendo a prioridade escolhida, com SMALL como primeiro
alvo de validação e TAIL32/COSMIC como alvos paralelos.** A leitura integral
não trouxe uma senha nem uma nova instrução operacional confirmada.

Não há motivo para voltar à cadeia dos 35 blocos, repetir as campanhas
registradas ou procurar o código de X novamente. O código recuperado fecha
uma lacuna de fonte e permite revisar a receita exata; não justifica outra
varredura das mesmas senhas. Uma nova tentativa deve explicar uma ligação
ainda não demonstrada entre os dados e as pistas, com consequência testável
no texto completo ou nos blobs originais.

Artefatos desta leitura: `reading_manifest.json`, `primary_context.json`,
`original_script_check.json` e `original_dbbi_sum_faed.py`.
