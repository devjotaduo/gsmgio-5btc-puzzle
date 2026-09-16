# RSA por caractere com os dígitos desconhecidos

**Atualização posterior em 16/09/2026:** os sessenta casos limitados abaixo
foram concluídos por enumeração exata e conferência independente: 58
incompatíveis e dois compatíveis. O estado atual está no
[relatório de conclusão](../rsa_pending_dfa_2026-09-16/RELATORIO.md).
Este documento e `final_status.json` preservam os números da rodada anterior.

**Nenhuma senha final encontrada.** O teste de textos só com letras e
espaços foi concluído e conferido. Para o repertório ASCII mais amplo,
sessenta modelos continuam inconclusivos. Todos os processos desta rodada
terminaram; não há busca em execução.

## Premissa removida

A [rodada anterior](../rsa_color_blocks_2026-09-16/RELATORIO.md) mantinha
`a=1,…,i=9`. Esta permite **qualquer bijeção** desses nove símbolos para
os dígitos positivos e, adicionalmente, até duas letras podendo valer zero
independentemente em cada ocorrência. A busca constrói o mapa ao percorrer
os números; não presume os valores b=2/e=5/f=6 nesta ampliação.

São os mesmos módulos de fatores primos RGB, acrescidos de `47·23`, e
todas as classes invertíveis de expoentes: 26.473 pares módulo/expoente.
DBBI/FAED, dois sentidos e decimal mínimo/preenchido dão oito configurações
por par. Cada uma foi examinada em dois repertórios:

- letras A–Z/a–z e espaço;
- ASCII 32–126, TAB, LF e CR.

Isso dá **423.568 decisões de existência**, cada uma abrangendo o espaço
de bijeções e escolhas de zero. Não são 423.568 tentativas de senha.
Mantém-se um caractere por bloco modular; blocos maiores e outros módulos
ficam fora deste teste.

## Busca e verificações

O primeiro programa unifica relações símbolo/dígito por palavras decimais,
memoriza estados impossíveis e usa um limite de 50.000 estados por busca.
Estados que atingem esse limite são registrados como **inconclusivos**.
Houve doze controles com mensagens plantadas e dezesseis casos pequenos
conferidos por enumeração de bijeções, máscaras e separações.

O verificador independente calcula os códigos com BigInt e procura
palavras pelo fim do campo, usando atribuições em strings em vez do mapa
numérico do produtor. Recifrou as testemunhas e confirmou todas as
423.120 negativas iniciais. Também resolveu parte dos casos antes
inconclusivos; seu limite de 500.000 estados continua explícito.

As doze pendências de letras/espaços foram concluídas por uma ampliação
do primeiro método e confirmadas pelo segundo. Os maiores casos dessa
ampliação usaram 125.815 estados; nenhuma testemunha alfabética apareceu.
Uma rodada adicional examinou 271 pendências ASCII. Onze negativas que
ainda faltava conferir foram reproduzidas pelo verificador independente
com a direção de palavras invertida.

## Contradição dos blocos de dois dígitos

Para `n=74`, todos os números cifrados estão abaixo de 74. Se eles são
preenchidos com zero até dois dígitos, cada par consecutivo de FAED é
um bloco. Em ambos os sentidos, todas as nove letras aparecem na primeira
posição e cada uma possui pelo menos sete letras diferentes depois dela.

As letras atribuídas a 8 e 9 precisam ser zeráveis quando aparecem na
primeira posição: um número `8x` ou `9x` não cabe. Isso consome as duas
letras zeráveis. A letra atribuída a 7 permanece 7 e só permite os números
70–73; suas vizinhas podem ser as letras de 1, 2, 3 e as duas zeráveis.
São no máximo cinco vizinhas, contradizendo o mínimo sete observado.

Essa prova independe do expoente, do repertório de plaintext e da busca.
Abrange 48 decisões, incluindo 24 antes inconclusivas. Outra implementação
recalculou os pares e o limite de cinco.
[Certificado](pair_capacity_certificate.json),
[conferência independente](pair_capacity_verification.json).

## Estado consolidado

| Repertório | Excluídos e conferidos | Compatíveis | Inconclusivos |
|---|---:|---:|---:|
| Letras e espaços | 211784 | 0 | 0 |
| ASCII/TAB/LF/CR | 211666 | 58 | 60 |

Não há negativas aguardando conferência independente. Os sessenta casos
abertos e seus parâmetros estão em [final_status.json](final_status.json).
As saídas compatíveis não são texto reconhecível e não excluem outras
possibilidades de separação dentro do mesmo modelo.

## Autenticação das testemunhas

Foram recifradas 71 testemunhas guardadas, produzindo 57 textos distintos.
Só essas testemunhas foram usadas como candidatas; não se enumeraram todos
os textos dos modelos compatíveis.

- 114 senhas diretas/SHA256 hexadecimal, testadas nos três blobs com
  EVP_BytesToKey SHA256 e MD5: **684 decisões AES**.
- Um padding aceito, com 36,71% dos bytes no repertório imprimível ampliado;
  não é uma senha autenticada.
- **212 escalares distintos**, derivados por SHA256 e por janelas de
  32 bytes do corpo com padding aceito, nas duas ordens de bytes:
  nenhum corresponde à chave pública do prêmio ou ao seu negativo.

Python/PyCryptodome reproduziu todas as decisões AES e o conjunto de
escalares; coincurve/libsecp256k1 repetiu as comparações. A senha conhecida
da fase 3.2 recuperou o plaintext de controle, e o HASH160 da chave pública
de referência foi recalculado.
[Testes](candidate_auth.json), [conferência](candidate_auth_verification.json).

## Artefatos

- [Especificação](spec.json), [primeira busca](summary.json),
  [verificação principal](verification.json).
- [Pendências de letras concluídas](letters_followup.jsonl),
  [rodada ASCII adicional](ascii_followup.jsonl),
  [onze negativas adicionais conferidas](negative_followup_verification.jsonl).
- [Estado antes da última conferência](consolidation.json) e
  [estado final desta rodada](final_status.json).
- [Buscador](../../solver/rsa_substituted_digits.cjs),
  [verificador independente](../../solver/verify_rsa_substituted_digits.cjs),
  [consolidação e autenticação](../../solver/rsa_substituted_oracles.cjs).

Os produtores recusam sobrescrever registros. Os sessenta casos inconclusivos
não devem ser descritos como rejeitados. Mesmo o fechamento de um modelo
não excluiria outras codificações ou forneceria a senha final por si só.
