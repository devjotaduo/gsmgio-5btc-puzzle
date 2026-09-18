# FINDINGS — frente `lista_mais_fala` (hipótese I3 do Codex Astra)

Campanha `enxame_2026-09-18`. Script: `solver/enxame_2026_09_18/lista_mais_fala/lista_mais_fala.py`.
Saídas: `_work/enxame_2026-09-18/lista_mais_fala/{summary.json, controls.json, paddings.jsonl}`.

## Hipótese

`matrixsumlist → lastwordsbeforearchichoice` pede dois operandos concatenados na ordem da página:

- `b`: uma das 270 listas numéricas isoladas de `reinsert_primes.generate_materials`, com o primo p reinserido nos marcadores de DBBI (L83/L84);
- `f`: as 1–30 palavras imediatamente antes de uma das 5 ocorrências de "choice" na cena do Arquiteto, coladas sem espaço, com caixa e apóstrofo preservados, mais a forma minúscula.

A senha é `sha256hex(UTF8(b+f))`. A hipótese é refutada se nenhuma senha abrir SMALL, COSMIC ou TAIL32 (EVP SHA256 ou MD5) com candidato e se `sha256(b+f)` não for a privkey de um dos dois alvos.

## Fato observado

**Negativo.** Foram 474.120 senhas distintas e 2.844.720 decisões AES, com resultado zero:

- 0 candidatos: nenhum plaintext semântico, nenhum blob aninhado, nenhum hex64, WIF ou EBCDIC;
- 0 privkeys embutidas;
- 0 de 474.120 digests sha256 bateram com `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` ou `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`.

Houve 11.196 paddings PKCS7 válidos contra 11.155,77 esperados (z = +0,38). O printable máximo foi 0,582.

| Grupo | Senhas | AES | Paddings (esp.) | z | Cand. |
|---|---:|---:|---:|---:|---:|
| núcleo I3: sha256hex(b+f), F com U+2019 | 62.910 | 377.460 | 1.460 (1.480,24) | −0,53 | 0 |
| ext.: raw(b+f) | 62.910 | 377.460 | 1.468 (1.480,24) | −0,32 | 0 |
| ext.: f+b, sha256hex e raw | 125.820 | 754.920 | 2.986 (2.960,47) | +0,47 | 0 |
| ext.: F com apóstrofo ASCII ou sem apóstrofo (206 strings novas) × {b+f, f+b} × {sha256hex, raw} | 222.480 | 1.334.880 | 5.282 (5.234,82) | +0,65 | 0 |
| **total** | **474.120** | **2.844.720** | **11.196 (11.155,77)** | **+0,38** | **0** |

Os grupos são disjuntos: cada grupo só recebeu senhas inéditas em relação aos anteriores.

A privkey foi testada em 474.120 digests distintos:

- 237.060 `sha256(material)`, iguais a sha256 das senhas raw;
- 237.060 `sha256(senha sha256hex)`.

Os dois alvos foram testados com pubkey comprimida e não comprimida.

## Lacuna, reproduzida antes da execução

**Pelo código.** Nenhum gerador anterior compõe lista numérica com fala real:

- `reinsert_primes.py:179` (`compose_materials`) cola a lista só aos rótulos literais `lastwordsbeforearchichoice` e `thispassword`;
- `reinsert_architect.py:24` usa 2 cláusulas fixas;
- `critico_familia2.py:206` e `familia2_lastwords.py:209` (`COMPOS`) compõem as falas só com rótulos fixos.

**Pelos conjuntos.** A interseção com as senhas e os materiais desta frente deu 0 em todas as fontes:

- critico_familia2, regerado das próprias definições via `ast`, sem os efeitos de módulo: 55.576 senhas, contagem igual à do resumo em `run.jsonl`;
- reinsert_primes, todas as composições: 3.240 valores;
- reinsert_architect: 1.080 senhas;
- os 14 corpora da auditoria `reinsert_architect_evidence`: 188.142 valores, com sha256 de cada arquivo conferido;
- 1.610 campos `pw` dos logs de padding de familia2.

## Cobertura exata

**B.** São 270 bases:

- L83 e L84;
- modos ambos, só b, só be;
- todos os retângulos exatos;
- somas de linhas e colunas, diretas e reversas;
- serialização concatenada e CSV.

As bases batem byte a byte com `reinsert_primes_v2/materials.jsonl`.

**F_núcleo.** São 233 strings distintas, vindas de 300 ocorrências textuais (5 ocorrências de "choice" × 30 janelas × 2 caixas). As ocorrências estão nos índices 180, 184, 347, 356 e 733 de 830 palavras. A cena vem de `cena_completa` sobre MISC.txt, e as palavras seguem o regex do crítico, `[A-Za-z][A-Za-z'’]*`.

O sha256 da concatenação ordenada das 62.910 senhas do núcleo é `ba03b9f52e8466c009a758fe19a953cd60ac662cc39bd0f7f5fd7ffe8af88b3d`, conferido.

**Blobs e KDF.** SMALL, COSMIC e TAIL32 × EVP-SHA256 (primário) e EVP-MD5 (controle).

**Plaintexts com padding.** Passaram por `fast_priv_scan` (raw32 direto), `nested_blob` e `semantic`. Todos estão em hex no `paddings.jsonl`, com proveniência: grupo, material, forma, ordem e variante.

## Controles

Todos passaram:

- **Fase 2:** abre com `sha256hex("causality")` pelo `comum`.
- **Ponte da fase 3:** o mesmo concatenador aplicado às 7 partes dá `1a57c572…30d5`, que abre PHASE3 só com EVP-SHA256.
- **openssl CLI 3.5.7:** abre as fases 2 e 3 com `-md sha256`.
- **Bases:** as 270 são idênticas às salvas na reinserção v2.
- **Chave sintética plantada:** plantei uma chave num blob cifrado com uma senha do núcleo. `C._um` (o mesmo `try_password_all`) a recuperou em SHA256 e em MD5.
- **Varredura de privkey:** com o h160 de `sha256(material)` plantado como alvo, a varredura dispara; com outro material, não dispara.
- **Restauração:** os alvos sintéticos foram removidos no fim; `TARGET_H160S` voltou aos 2 alvos reais.

## Nulo

A taxa de padding foi comparada com a referência analítica ≈ 1/255: z total = +0,38 e |z| < 0,7 em todos os grupos. A distribuição por blob e KDF é homogênea. Não rodei nulo por embaralhamento: é uma varredura determinística finita, sem escore a comparar.

## Inferência

A leitura I3 — lista reinserida seguida de fala real antes de "choice", concatenada e passada por SHA256 — está refutada no recorte declarado. O mesmo vale para as extensões: forma raw, ordem inversa e as duas normalizações de apóstrofo. Os paddings são ruído compatível com 1/255.

## Fontes e hashes

- Commit (HEAD e kit): `5f12b716a67763d7cd72aec3447a15c3015bf2d4`
- `gsmg_common.py`: `3810cbaf…1e67`
- `lista_mais_fala.py`: `44188452…ad59`
- `comum.py`: `0bea9880…c7a6`
- `reinsert_primes.py`: `c335e1ae…aa9b`
- `critico_familia2.py`: `69162e22…2f74`
- MISC.txt: `223d7f76…5ac7`
- `paddings.jsonl`: `bf8f1d14…d571` (11.196 linhas, 15,2 MB)
- `summary.json`: `de859611…6e6e`
- `controls.json`: `83085f84…1b2b`

Tempo de execução: 138 s com 2 processos.

## Limite

- **Fora do recorte:**
  - separadores e rótulos intermediários (`thispassword`, `yinyang`);
  - sha256HEX maiúsculo e sha256 duplo como senha;
  - PBKDF2 e iterações;
  - janelas com mais de 30 palavras ou depois de "choice";
  - outras transcrições da cena.
- **Premissa das bases:** as 270 bases dependem da reinserção do primo p nos marcadores, que é inferência.
- **Fonte da cena:** MISC.txt não é fonte autenticada do criador. A primeira ocorrência de "choice" no parser cai depois de "I’ll fuckin’ kill you", um artefato da ordem de reconstrução.
- **Varredura dos plaintexts:** não varri raw32 little-endian nem as visões cp273/UTF-16. Os plaintexts ficaram em hex para varredura retroativa.
- **Auditoria de lacuna:** compara com geradores regerados e corpora preservados, o que não prova ausência em toda a busca histórica.

## Próxima pergunta

Algum dos 11.196 plaintexts de `paddings.jsonl` mostra estrutura nas visões cp273 inversa, cp273 direta ou UTF-16, ou em raw32 little-endian? A frente `lacuna_cp273_utf16` pode rodar sobre esse arquivo com `processar()`.

Fora isso, a única variação da I3 com prior compatível com a regra 4 seria um separador explícito entre os operandos (espaço ou vírgula, como no CSV da lista). Ela só deve ser testada se houver insumo que a justifique.

## Revisão adversarial independente

**Veredito do revisor: negativo confirmado.** Onde as correções abaixo divergem do texto acima, valem as correções.

### Problemas apontados

- AMBIENTE (urgente para o coordenador): durante a revisão o disco C: chegou a 0 byte livre (Get-PSDrive C: Free = 0; o rtk falhou com 'Espaço insuficiente no disco'). Os arquivos da frente já estavam gravados e os hashes deles conferem, mas qualquer gravação nova (FINDINGS.md, outras frentes) pode falhar ou sair truncada. Não apaguei nada.
- Controles descritos como 'pelo mesmo caminho de código da campanha', mas nem todos passam por ele. Só o (a), a fase 2, passa por C.testar → Pool → _um → try_password_all. O plantado (e) chama C._um no processo principal, sem testar, sem Pool e sem o laço de grupos e candidatos do main(). A ponte da fase 3 (b) usa G.aes_try direto e a função concatenar(), que montar() não chama (a enumeração usa b + f direto). A equivalência é semântica, não o mesmo código.
- Nenhum controle exercita o caminho de registro de candidato do main() (g[c['senha'].encode('latin-1')], a reprodução pelo openssl e candidatos.jsonl). Pela leitura do código o risco é baixo, mas um bug ali passaria despercebido.
- A homogeneidade por blob e KDF foi afirmada citando só o núcleo. No grupo ext_apostrofo, a célula COSMIC/EVP-SHA256 tem 968 paddings contra 872,47 esperados (z = +3,24), o maior |z| das 24 células. Tudo aponta para ruído: o qui-quadrado global dá 24,93 com 24 células (p ≈ 0,41), e o valor de Bonferroni sobre as 24 células fica em ≈ 0,03. A célula tem 968 senhas distintas, sem duplicatas, espalhadas pelas quatro combinações de forma e ordem (265/253/238/212). Os bytes de padding são compatíveis (964 com pad 1, 4 com pad 2), e minha implementação independente reproduz os mesmos 968. O relatório deveria declarar isso em vez de omitir.
- A frase sobre 'I’ll fuckin’ kill you' atribui a posição da 1ª ocorrência de 'choice' a um artefato da reconstrução. Não é: no MISC.txt (bloco 1 '*skipped in puzzle*'), a linha 'TV Neos: … I’ll fuckin’ kill you!' vem imediatamente antes de 'Neo: Choice. The problem is choice.', e o parser só preserva essa ordem do arquivo.
- A lacuna foi reproduzida só contra os geradores adjacentes auditados (4 scripts, os 14 corpora e 2 logs), mas o texto diz 'nenhum gerador anterior'. Na prática a lacuna é trivialmente verdadeira porque as 270 bases B só existem desde 2026-09-18 (reinsert_primes). O architect_sum_attack.py já cruzava listas de somas com a transcrição do Arquiteto, mas como índices, não como concatenação. Também faltou um controle de sensibilidade da interseção, ou seja, mostrar que o procedimento acusa uma sobreposição conhecida. Para as senhas sha256hex, que são ASCII, o risco de zero espúrio por codificação é nulo; para as formas raw com U+2019, ele não foi testado.

### Reprodução independente

Script próprio em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\revisao_lista_mais_fala\indep.py, com resultado em indep_resultado.json e openssl_amostra.py na mesma pasta. O script não importa o kit, o comum.py, o reinsert_primes nem o critico_familia2 para decidir nada; o kit só entra para comparar bytes de blobs e alvos.

(1) Enumeração recodificada. Li o DBBI do README e recodifiquei a segmentação por primos b/be como busca em largura, os modos ambos/b/be, todos os retângulos, as somas diretas e reversas e as serializações concat e csv. Deu 270 bases, idênticas às isoladas de reinsert_primes_v2/materials.jsonl. Recodifiquei o parser da cena sobre MISC.txt (sha256 223d7f76…5ac7 conferido): são 830 palavras, com 'choice' nos índices 180, 184, 347, 356 e 733. Saem 300 janelas e 233 strings F; o sha256 do núcleo ordenado dá ba03b9f5…8b3d, igual ao da especificação. Os grupos disjuntos batem com a frente (62.910 / 62.910 / 125.820 / 222.480, total 474.120). As 206 F novas se dividem em 103 com apóstrofo ASCII e 103 sem apóstrofo.

(2) AES independente, no conjunto INTEIRO e não em amostra. Usei a biblioteca cryptography (não pycryptodome) e EVP_BytesToKey via hashlib. O padding foi checado pelo último bloco, D(C_n) xor C_{n-1}, com decifração CBC completa só nos paddings. Os blobs vieram das fontes: SMALL das linhas salph 6 e 8 do MISC.txt, COSMIC e TAIL32 do README. Foram 2.844.720 decisões em 36 s. Resultado: 11.196 paddings, com o mesmo conjunto (senha, blob, KDF) do paddings.jsonl da frente. Nenhum aparece só de um lado, nenhum hex de plaintext diverge, nenhuma senha está fora do conjunto e nenhum grupo diverge. O jsonl tem 11.196 linhas, chaves únicas e plaintexts únicos. Por grupo: 1.460 / 1.468 / 2.986 / 5.282. Controle positivo pelo mesmo varre_aes: a fase 2 abre com sha256hex('causality') e a fase 3 com 1a57c572…30d5, as duas só em SHA256.

(3) openssl CLI 3.5.7 (Git for Windows), com senha por arquivo. 40 paddings sorteados reproduzem o plaintext byte a byte (40/40), e 40 decisões sem padding falham (40/40).

(4) Triagem semântica própria dos 11.196 plaintexts. Printable máximo 0,582, igual ao relatado. Salted__, U2FsdGVk, hex64 e WIF: zero. ebcdic_sig máximo 0,351. A fração de letras sob cp273 tem máximo 0,747, igual ao máximo de um nulo de bytes aleatórios com os mesmos comprimentos (0,747). Printable em UTF-16 LE/BE: máximo 0,051.

(5) Privkey. Os endereços foram decodificados por base58check próprio e batem com O.TARGET_H160S; o h160 da pubkey de 1GSMG também confere. Passei os 474.120 digests pelo coincurve, com código meu: 0 hits. Numa amostra de 2.000 digests pelo python-ecdsa, os h160 comprimido e não comprimido coincidem com os do coincurve em 2.000 de 2.000, com 0 hits. O controle plantado do meu scanner detecta o alvo sintético.

(6) Raw32 nos plaintexts com padding, nas DUAS ordens de byte. Varri todos os 7.404 de SMALL e TAIL32 e mais 150 de COSMIC sorteados: 1.099.514 janelas, 0 hits. Isso vai além da ordem direta que a frente varreu.

(7) Hashes conferidos: lista_mais_fala.py, comum.py, gsmg_common.py (sem diff contra o HEAD 5f12b716), reinsert_primes.py, critico_familia2.py, MISC.txt, paddings.jsonl, summary.json e controls.json batem com os declarados. Os números de linha citados na evidência da lacuna (reinsert_primes.py:179, reinsert_architect.py:24, critico_familia2.py:206, familia2_lastwords.py:209) conferem.

Pela leitura do código, não há top-N, filtro nem limite silencioso. O único except engolido é o de segredo inválido no fast_priv_scan, com probabilidade de ~2^-128. As contagens por grupo batem com os itens gerados.

### Correções ao relatório

1. Em Limite/'Fonte da cena' (e no item 3 de 'limites'): 'A primeira ocorrência de "choice" no parser cai depois de "I’ll fuckin’ kill you", um artefato da ordem de reconstrução.' → Trocar por: 'As ocorrências 1 e 2 (índices 180 e 184) são falas de Neo ("Choice. The problem is choice."), que no MISC.txt vêm logo após a fala dos TV Neos "…I’ll fuckin’ kill you!" (ordem do próprio arquivo, bloco 1). As ocorrências 3 e 4 (347 e 356) estão no fragmento canônico do Arquiteto "Please As I was saying…", e só a 5 (733) é o "the problem is choice" do Arquiteto. As janelas atravessam fronteiras de fala.'

2. Em 'controles': 'Todos passaram, pelo mesmo caminho de código da campanha.' → Trocar por: 'Todos passaram. A fase 2 passa pelo mesmo caminho (C.testar → Pool → try_password_all). O plantado usa C._um, o mesmo try_password_all, fora do Pool e do laço de grupos. A ponte da fase 3 usa G.aes_try e concatenar(), que a enumeração não chama (ela usa b + f direto). O openssl CLI é independente por construção. Nenhum controle exercita o registro de candidatos do main().'

3. Em Controles/'Ponte da fase 3': 'o mesmo concatenador aplicado às 7 partes dá 1a57c572…30d5' → Trocar por: 'a concatenação sem separador (a mesma operação de b + f, feita por concatenar()) aplicada às 7 partes dá 1a57c572…30d5'.

4. Em Nulo: 'A distribuição por blob e KDF é homogênea.' (citando só o núcleo) → Acrescentar: 'Das 24 células grupo×blob×KDF, a maior é ext_apostrofo COSMIC/SHA256, com 968 contra 872,47 (z = +3,24). O qui-quadrado global é 24,93 com 24 células (p ≈ 0,41) e o Bonferroni da célula máxima ≈ 0,03. A célula tem 968 senhas distintas, espalhadas por forma e ordem (265/253/238/212), e é reproduzida por implementação independente. É compatível com ruído.'

5. Em 'Lacuna, reproduzida antes da execução': 'Nenhum gerador anterior compõe lista numérica com fala real' → Trocar por: 'Nenhum dos geradores adjacentes auditados (reinsert_primes, reinsert_architect v1/v2, critico_familia2, familia2_lastwords) compõe lista numérica com fala real. As 270 bases só existem desde 2026-09-18. O architect_sum_attack.py cruzou somas com a transcrição, mas como índices, não por concatenação.'

6. Em Limite/'Varredura dos plaintexts' e no item 4 de 'limites': acrescentar que a revisão varreu raw32 nas duas ordens em todos os 7.404 plaintexts de SMALL/TAIL32 e em 150 de COSMIC (1.099.514 janelas, 0 hits). A cp273 inversa (máximo igual ao nulo, 0,747) e UTF-16 LE/BE (máximo 0,051) não mostram estrutura. Ficam de fora só o raw32 reverso nos outros 3.642 plaintexts de COSMIC e as visões completas da frente lacuna_cp273_utf16.

7. Em 'Próxima pergunta': retirar ou rebaixar a sugestão de rodar processar() sobre este paddings.jsonl, já que a revisão respondeu parcialmente (item 6).

8. (Opcional) Em Fato observado: acrescentar que a reprodução independente, com cryptography e base58 próprio, deu o mesmo conjunto de 11.196 paddings byte a byte e 0 hits nos 474.120 digests.
