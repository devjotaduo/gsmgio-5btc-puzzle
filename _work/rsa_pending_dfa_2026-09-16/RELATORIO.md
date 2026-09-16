# Conclusão dos sessenta casos RSA inconclusivos — 16/09/2026

**A hipótese foi delimitada; a senha final continua desconhecida.** Esta
rodada conclui os sessenta casos que atingiram limites de busca na
[investigação anterior](../rsa_substituted_digits_2026-09-16/RELATORIO.md).
Os arquivos de resultados anteriores foram preservados.

## Domínio exato

Mantém-se um caractere ASCII/TAB/LF/CR por bloco `c=m^e mod n`, com `m<n`,
códigos decimais mínimos ou preenchidos conforme cada caso, DBBI/FAED
completos nos sentidos declarados, qualquer bijeção dos símbolos a,...,i
em 1,...,9 e até duas letras podendo valer zero por ocorrência. Os módulos
e expoentes continuam aqueles da investigação das cores. Isso não é uma
exclusão de RSA em geral, outros módulos, outros encodings ou blocos maiores.

Os sessenta modelos têm 26 conjuntos distintos de palavras decimais e
cinquenta combinações distintas de conjunto/campo/sentido. Para cada uma,
foram enumeradas **9! × 36 = 13.063.680 configurações**. Um par de letras
com capacidade de zero cobre também casos que usam nenhuma ou só uma
delas. Não se exige usar a capacidade.

O total executado foi **653.184.000 decisões de configurações**, com
fronteiras de caracteres e escolhas de zeros tratadas simultaneamente
pelo autômato. O programa constrói somente os subconjuntos alcançáveis
dos estados de prefixo: entre 8 e 134 estados nos 26 autômatos. Houve
181 controles por conjunto, incluindo um texto que usa todos os códigos.

Um programa independente refez os códigos com BigInt, reverteu códigos
e fontes, representou estados como conjuntos, usou permutações de Heap
e comparou o hash de **todas** as decisões na ordem original. Recodificou
as testemunhas e calculou por DP de sufixos todos os caminhos das 27
configurações compatíveis. As 653.184.000 decisões concordaram.

## Resultado e consequência

**58 dos sessenta modelos são incompatíveis; dois são compatíveis:**

| Modelo | Campo/sentido | Configurações compatíveis | Caminhos |
|---|---|---:|---|
| n=362, e=133, decimal mínimo | DBBI original | 3 | 144 + 24 + 192 = 360 |
| n=74, e=7, decimal mínimo | FAED inverso | 24 | Muito numerosos; contagem exata por configuração nos artefatos |

Com a rodada anterior, a classificação completa dos **423.568 modelos** é:

| Repertório | Excluídos e conferidos | Compatíveis | Inconclusivos |
|---|---:|---:|---:|
| Letras e espaços | 211.784 | 0 | 0 |
| ASCII/TAB/LF/CR | 211.724 | 60 | 0 |

Os 58 modelos compatíveis anteriores eram todos de DBBI. Assim, a única
compatibilidade FAED de toda essa família é a linha da tabela acima.
Uma DP exata mostra que cada caminho desse caso tem **ao menos nove
TAB/LF/CR** e ao menos **363 caracteres**. Portanto, nenhum modelo FAED
dessa família produz apenas ASCII 32–126. Os controles permitidos são
espaços em branco; essa constatação não prova que a saída não possa ser
um intermediário. O módulo 74 contém o fator 2, incluído como relaxação
da hipótese de RSA convencional com primos ímpares.

## Seleção reproduzível de candidatos

Os três mapas DBBI foram enumerados por completo: **360 caminhos e
360 textos distintos**. Para as 24 configurações FAED, foram salvas as
testemunhas e saídas que minimizam lexicograficamente controles,
não-letras/espaços e comprimento, além de comprimentos mínimo e máximo.
Os objetivos e seus desempates estão em `rsa_pending_candidates.cjs`.

Com as duas testemunhas do produtor, a seleção contém **465 textos
distintos**. Outra implementação, em Python, refez as potências,
contagens, 108 ótimos e toda a enumeração DBBI, e recodificou os candidatos.
Os caminhos restantes de FAED não foram enumerados como senhas.

## Testes criptográficos

As formas original, minúscula, maiúscula, sem espaços em branco e
minúscula sem espaços deram 2.220 materiais e 4.440 senhas diretas ou
SHA256 hexadecimal. Foram testadas nos três blobs com EVP-SHA256 e
EVP-MD5: **26.640 decisões AES**, 126 aceitações de padding, nenhum
resultado autenticado. A maior fração de bytes textuais foi 50,63%.

**391.340 escalares distintos** foram comparados com a chave pública do
prêmio e seu negativo, sem acerto. Incluem SHA256 das senhas, janelas
de 32 bytes dos materiais e SHA256/janelas dos corpos com padding, nos
dois sentidos de bytes. PyCryptodome e coincurve reproduziram todas as
decisões, corpos, conjuntos de escalares e multiplicações, com controles
da fase 3.2 e da curva. Esses números são desta rodada; não afirmam
unicidade global em relação às rodadas anteriores.

O [estado consolidado atual](final_status.json) substitui as sessenta
pendências do arquivo histórico. O espaço de modelos de gramática está
classificado; os caminhos compatíveis de FAED continuam apenas amostrados
na autenticação.

## Evidências e reprodução

- [Especificação e parâmetros](spec.json), [resumo](summary.json),
  [classificação por modelo](results.jsonl).
- [Conferência independente](verification.json),
  [conferência por conjunto](verification_groups.jsonl),
  [27 configurações compatíveis e contagens](positive_configurations.jsonl).
- [Candidatos e ótimos](candidates.json), [conferência Python](candidate_verification.json).
- [Testes criptográficos](candidate_auth.json),
  [conferência PyCryptodome/coincurve](candidate_auth_verification.json).

```powershell
node solver/rsa_pending_dfa.cjs
node solver/verify_rsa_pending_dfa.cjs
node solver/rsa_pending_candidates.cjs
# candidate_verification.json registra a implementação Python independente.
node solver/rsa_pending_oracles.cjs
```

Os produtores de enumeração recusam sobrescrever arquivos existentes.
SHA256 dos resultados:
`adbd8f09c35b3d2811a1c6ae09fbee7a02335a3afdfba7f40a3cb88361cab687`.
SHA256 das 27 configurações positivas:
`5d57a2087ad78b3f5a994d7bd9d9a586a701a5303e364fdb40d79d53692e5405`.
SHA256 da autenticação:
`dc1fe37601fa9989c19e82dcb83e0d19bb51caa8819894c85d6245ed8b98a749`.
