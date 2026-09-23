# F1 — `modos_fluxo` — enxame 2026-09-19

Frente tese/experimental. Base `66fecdc`. Kit
`solver/experiments/claude_endgame_2026_09_02/gsmg_common.py`,
sha256 `f109cd8a41441d7439b18cf60ec72d465a3a446ae03260036672457136932c3a`.
Resultado: **negativo, 0 no oráculo duro, com cobertura exata declarada abaixo.**

## 1. Lacuna e hipótese

`ENDGAME.md` tabela D e §3.13/§3.14 declaram a única lacuna de cobertura ainda aberta:
*"Continua aberto: só os modos de fluxo"* e *"filtro de modos de fluxo não cobre raw32
binário interior"*. O mecanismo da lacuna é de execução, não de ideia: CFB, CFB1, CFB8,
OFB e CTR **não produzem padding PKCS7**, e as campanhas de 2026 filtravam por padding
válido antes de persistir o plaintext — logo todo o material de modo de fluxo era
descartado antes de qualquer varredura, e seu interior binário (janelas de 32 B que
poderiam ser a chave privada) nunca foi comparado com os dois alvos.

**Hipótese (prosa, finita, falsificável):** um dos três blobs não é `aes-256-cbc`, mas um
modo de fluxo do mesmo `openssl enc`, e o plaintext correspondente contém, em algum
offset, a chave privada de 32 B de `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` ou de
`17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`.
**O que a refutaria no domínio coberto:** varrer toda janela raw32, nas duas orientações,
de todo plaintext produzido pelo domínio, e obter 0 — com o scanner demonstrando, por
chave plantada, que recuperaria o acerto se ele existisse.

## 2. Conjunto coberto (números exatos)

| Eixo | Cobertura |
|---|---|
| Blobs | 3 — SMALL (80 B), COSMIC (1328 B), TAIL32 (80 B) |
| Modos | 5 — `aes-256-cfb` (CFB128), `aes-256-cfb1`, `aes-256-cfb8`, `aes-256-ofb`, `aes-256-ctr` |
| KDF | 2 — EVP_BytesToKey **SHA256** (o provado das fases) e MD5 (controle secundário) |
| Senhas | **1.750 únicas**, de **570 bases** em 8 camadas (tabela abaixo) |
| Decifrações | **52.500** (= 1.750 × 3 × 5 × 2); **10.500 por modo**, 26.250 por KDF |
| Janelas raw32 | **48.825.000** (BE + LE), = 52.500 × 2.790 janelas por decifração |
| Alvos | **os dois**, h160 da pubkey **comprimida e não comprimida** em cada janela |
| Filtro de padding | **nenhum** — todo plaintext foi varrido por inteiro |
| Execução | 1 processo, 1.413,7 s de varredura + 90,6 s de nulo; domínio 100 % concluído (`interrompido_por_tempo: null`) |

Janelas por decifração: SMALL 49 BE + 49 LE = 98; TAIL32 98; COSMIC 1.297 + 1.297 = 2.594.
"LE" é o conjunto exato das janelas lidas em ordem inversa (o buffer é revertido e varrido).

Camadas de senha (`solver/enxame_2026_09_19/modos_fluxo/passwords.py`, determinístico):

| Camada | Bases | Formas | Senhas novas |
|---|---|---|---|
| A — operandos de nível-senha das fases 0–3.2 (pré-imagens verbatim do README, os 3 sha256, os 2 endereços, a URL do endgame) | 13 | 6 | 54 |
| B — os 7 tokens do roadmap de 2023-02-23 + as duas concatenações | 9 | 6 | 36 |
| C — campos da página SalPhaseIon (`dbbi`, `faed`, `faed` sem prefixo, rótulos, frases) | 18 | 6 | 77 |
| D — objetos de §6 (resíduos L84/L83, bits dos marcadores, somas de linha/coluna da matriz) | 13 | 6 | 43 |
| E — tokens do monólogo do Arquiteto (plaintext autêntico da fase 3.2) | 37 | 6 | 148 |
| F — tokens das transcrições verbatim do README (linhas em blockquote) | 228 | 6 | 888 |
| G — pares ordenados distintos do roadmap | 42 | 2 | 84 |
| H — trios ordenados distintos do roadmap | 210 | 2 | 420 |
| **Total** | **570** | | **1.750** |

Formas por base: literal; `sha256hex(literal)`; `sha256hex(normalizada)`; normalizada
(minúscula, só `[a-z0-9]`); `sha256hex(MAIÚSCULA)`; `sha256hex(sha256hex(literal))`.

## 3. Comando reproduzível

```
cd solver/enxame_2026_09_19/modos_fluxo
python3 stream_scan.py  --out ../../../_work/enxame_2026-09-19/modos_fluxo --nulo 200
python3 nulo_casado.py  --n 1750 --out ../../../_work/enxame_2026-09-19/modos_fluxo
```

Saídas: `summary.json` (cobertura, controles, top-20), `controls.json`, `final_qa.json`
(nulo casado), `hits.jsonl` e `candidatos.jsonl` (ambos **vazios**, 0 linhas),
`execucao.log`.

## 4. Controles

1. **Controle positivo de KDF (obrigatório).** O blob da fase 2 abre com
   `sha256hex("causality")` em `aes-256-cbc` via EVP-**SHA256** (`True`) e **não** via MD5
   (`False`) — o plaintext começa em `The ironic`.
2. **Corretude da cifra, contra o `openssl enc` real (OpenSSL 3.0.13).** Para cada um dos
   **10** pares modo × KDF, um plaintext conhecido de 542 B foi cifrado pelo CLI
   (`openssl enc -aes-256-<modo> -e -md <kdf> -pass pass:…`) e esta implementação o
   reproduziu **byte a byte**: 10/10. Cobre inclusive o CFB de 1 bit, implementado à mão
   (NIST SP 800-38A) porque o pycryptodome não aceita `segment_size=1`.
3. **Chave plantada, ponta a ponta.** Duas chaves conhecidas foram escondidas dentro de um
   plaintext — uma em ordem direta, outra invertida —, o plaintext foi cifrado pelo CLI em
   `ofb` e em `cfb1`, e o pipeline (decifra + varredura) teve de recuperá-las: **2 hits em
   cada modo, um em BE e um em LE**. No mesmo material, contra os dois alvos **reais**:
   **0 falsos positivos** em 124 janelas. Sem este controle, "0 hits" não valeria nada.

## 5. Nulo casado

Não há scorer de quadgramas neste clone (`result.json` ausente ⇒ `solver/scorer.py` e
`solver/primos_2026_09_17/clean_scorer.py` quebram), então **nenhum escore de inglês foi
calculado** e nenhum é reportado. O critério estrutural usado foi `G.semantic`
(printable ≥ 0,85, blob openssl aninhado, assinatura EBCDIC cp273, WIF/hex64 plausível).

Nulo **do mesmo tamanho** (1.750 senhas aleatórias, 52.500 decifrações, mesmos 3 blobs ×
5 modos × 2 KDF, seed 20260919):

| Medida | Nulo | Varredura real |
|---|---|---|
| `printable` médio | 0,3712 (= 95/256, ruído uniforme) | — |
| `printable` p99 / p99,9 | 0,4875 / 0,5250 | — |
| `printable` máximo | **0,5875** (SMALL e TAIL32) | **0,6000** (TAIL32, `ctr`/sha256) |
| plaintexts semânticos (thr 0,85) | 0 | **0** |
| blob aninhado / assinatura EBCDIC | 0 / 0 | 0 / 0 |

O máximo real excede o do nulo em **exatamente um byte imprimível em 80** (48/80 contra
47/80), num blob de 80 B — dentro do comportamento normal do acaso já calibrado em
`ENDGAME.md` §3.9 (printable até ~0,60–0,65 em 80 B). O top-20 real é 15× TAIL32 e 5×
SMALL, espalhado pelos cinco modos: nenhuma concentração em modo, KDF ou família de senha.

## 6. Resultado no oráculo duro

- **Chaves dos dois alvos: 0** em 48.825.000 janelas raw32 (BE e LE), com h160 comprimido
  e não comprimido. `hits.jsonl` vazio.
- **Candidatos (`G.semantic` ou `nested_blob`): 0** em 52.500 plaintextos.
  `candidatos.jsonl` vazio. Como `G.semantic` também dispara em WIF/hex64 plausível, o
  zero implica que **nenhum plaintext deste domínio continha chave em forma textual** —
  a via hex64/WIF está vazia aqui por construção, não por omissão.
- Nada a submeter a `proof-certificate`.

## 7. Um argumento estrutural que o mapa não registrava (prior da família)

Modo de fluxo não faz padding: `|plaintext| = |ciphertext|`. Os três ciphertexts têm
**80, 1328 e 80 bytes — os três ≡ 0 (mod 16)**. Sob CBC com PKCS7 isso é obrigatório; sob
modo de fluxo exigiria que os três plaintexts tivessem, por acaso, comprimento múltiplo de
16, o que vale ≈ (1/16)³ ≈ 2,4 × 10⁻⁴ para comprimentos arbitrários. É um fator de Bayes
da ordem de **4·10³ a favor de um modo em bloco com padding** — não exclui a família (o
autor pode ter escrito textos de comprimento redondo, e o `enter` inline do SMALL mostra
que ele formatava o material), mas explica por que a lacuna tem prior baixo e por que
fechá-la vale como cobertura, não como aposta. Este argumento é independente da varredura.

## 8. Limitação declarada (o que ficou de fora)

1. **O corpus histórico não existe neste clone.** Não estão aqui as 466.310 senhas-base /
   1,27 M formas, os 694.386 + 1.331.155 plaintexts da §3.11, os 592.339 conteúdos da
   §3.12, o `result.json` nem os `ChatExport_*`. As 1.750 senhas foram **reconstruídas do
   repositório** e **nenhuma contagem histórica é herdada**. Em ordem de grandeza, 1.750
   está para 1,27 M como ~0,14 %; a sobreposição real entre os dois conjuntos **não foi
   medida** (isso é da F10). Portanto: **o mecanismo dos modos de fluxo está coberto e
   certificado; o espaço de senhas sob modos de fluxo continua quase todo aberto.**
2. **Sem escore de texto.** Nenhum quadgrama, nenhum escore de inglês, nenhum nulo por
   embaralhamento de texto — só o oráculo duro e critérios estruturais determinísticos.
3. **Só `-pass`.** O IV é sempre o do EVP_BytesToKey. Chave/IV crus (`-K`/`-iv`), PBKDF2
   (`-pbkdf2`), outros digests e `-nosalt` ficam fora (já refutados em CBC na tabela D,
   §4-D, mas **não** re-testados aqui em modo de fluxo).
4. **Só AES-256.** Chaves de 128/192 bits, `xts` e os modos AEAD (`gcm`/`ccm`, que o
   `openssl enc` recusa) não foram tocados.
5. **Só raw32 BE/LE** como forma de chave. Nada de N−k, chave derivada do plaintext por
   sha256, nem seleção de 32 B não contíguos.
6. **Ambiente:** 4 núcleos, sem GPU, 1 processo, ~25 min. O domínio foi dimensionado para
   caber inteiro — não houve amostragem: as 1.750 senhas declaradas foram **todas**
   processadas.

## 9. Próxima pergunta

Reexecutar exatamente este pipeline sobre o corpus histórico de 1,27 M formas (no checkout
principal, onde ele existe) custa ≈ 1,27 M × 27.900 janelas ≈ 3,5 × 10¹⁰ testes de chave —
inviável em CPU, viável em GPU/Go com o kernel de `solver/gpu_aes16_dbbi_hex/` adaptado.
Dado o fator de prior da §7, a decisão razoável é **não** disparar essa campanha sem
insumo novo, e registrar a família como "mecanismo fechado, espaço de senhas em aberto".
