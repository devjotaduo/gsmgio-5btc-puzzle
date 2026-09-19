# F2 — `auditoria_fluxo`: antítese e verificação independente da F1

Campanha `enxame_2026-09-19` (contrato em `../spec.json`). Papel declarado: reimplementar o pipeline
**sem reusar o código da F1**, plantar uma chave no interior binário e exigir que o scanner a
recupere, e auditar se o "0 hits" da F1 é **execução** ou **aritmética**.

Motivo da frente, verbatim de `ENDGAME.md` §3.13: *"O scanner Go antigo terminou por falta de
memória, apesar de um relatório citar a contagem calculada como execução."*

**Procedência.** Frente executada por subagente, impedida pelo harness de escrever relatórios; este
`FINDINGS.md` foi materializado pelo coordenador a partir do texto devolvido. **Todas as contagens
abaixo foram reconferidas pelo coordenador com aritmética própria** (ver §6), inclusive as quatro
checagens históricas do `ENDGAME.md`, que saem exatas.

## 1. Hipóteses

**H1 (conteúdo, idêntica à da F1, de propósito).** O blob não é `aes-256-cbc` mas um **modo de
fluxo** do mesmo `openssl enc`, e o plaintext contém em algum offset a chave privada de 32 B de um
dos alvos. Modos de fluxo não produzem padding PKCS7, então o filtro histórico descartava esse
material antes de qualquer varredura do interior binário.

**H2 (método, específica desta frente).** Um "0 hits" só é informação se o pipeline que o produziu
for capaz de **achar uma chave que esteja lá**. **O que refutaria H2:** um controle plantado no
interior binário que o scanner não recupere.

## 2. Implementação independente

`indep_fluxo.py` **não importa** `gsmg_common` nem `oracles`. Escritos do zero: `EVP_BytesToKey` sem
iteração; CBC sem unpad; CFB128; CFB8; CFB1 (bit a bit, registrador de 128 bits); OFB; CTR (IV como
contador de 128 bits); **secp256k1 em Python puro** (double-and-add); `hash160` nas duas formas de
pubkey. A única primitiva de terceiros no caminho de cifra é o AES-ECB de **um bloco**; todos os
**modos** são próprios. Na varredura em escala a EC usa `coincurve`, mas só depois do controle C1
provar igualdade com a implementação em Python puro.

Blobs amarrados por hash: SMALL `772a6377…` (80 B), COSMIC `43cb531c…` (1328 B), TAIL32 `cbbf9452…`
(80 B).

## 3. Controles

- **C1 — a EC está certa:** 40 escalares pseudoaleatórios (seed 20260919), pubkey comprimida e não
  comprimida **idênticas** entre Python puro e `coincurve`; vetor `d = 1 → G` confere.
- **C2 — `openssl enc` CLI como segunda implementação:** nos **10** pares modo × KDF, o CLI cifra e a
  decifra própria reproduz **byte a byte**: 10/10.
- **C3 — controle canônico do projeto:** a fase 2 abre com `sha256hex("causality")` sob EVP-SHA256 e
  **não** sob EVP-MD5.
- **C4 — CONTROLE PLANTADO (o que dá sentido ao negativo):** plaintext de 200 B com duas chaves
  enterradas em offsets **não alinhados a 16** — `15ad5561…d36d` no **offset 37** (BE) e
  `650d9bdf…cd5e` no **offset 113**, gravada invertida (só recuperável em LE). Cifrado pelo CLI nos
  5 modos e devolvido ao pipeline completo: o scanner devolve `be@37` **e** `le@113` **nos 5 modos**.
  **Negativo casado:** com os dois h160 **reais**, o mesmo scanner devolve 0. O detector dispara
  quando a chave está lá e fica calado quando não está.
- **C5 — os blobs reais contra o CLI:** os 3 blobs verdadeiros decifrados em cada modo × KDF pelo
  `openssl enc -d` e comparados: **30/30 iguais**. O material varrido é, byte a byte, o que o
  `openssl` produziria.

**Nulo casado: N/A justificado.** O oráculo é determinístico e sem escore (igualdade de h160); o
papel do nulo é cumprido pelo negativo casado do C4. Sem scorer de quadgramas neste clone, e esta
frente **não** inventou substituto.

## 4. Cobertura independente

| Grandeza | Valor | Conferência |
|---|---|---|
| senhas únicas | **586** | — |
| decifrações | **17.580** | 586 × 5 × 2 × 3 ✔ (assert no script; reconferido) |
| janelas raw32 | **8.174.700** | 586 × 10 × (49 + 1297 + 49) ✔ |
| escalares BE+LE | **16.349.400** | 2 × janelas ✔ |
| **hits no oráculo duro** | **0** | `hits.jsonl` = 0 bytes, criado antes do laço |
| tempo | 534,0 s, 1 processo | **30.617 escalares/s** medidos |

Fidelidade das pré-imagens conferida: o `sha256` das strings das fases 2, 3 e 3.2 reproduz
`eb3efb51…`, `1a57c572…` e `250f3772…` do README.

## 5. Veredito da auditoria sobre a F1

**O "0 hits" da F1 é confiável. Não é artefato de implementação nem aritmética disfarçada de
execução.**

Confirmado:

1. **Equivalência de mecanismo** — as duas frentes decifram o mesmo material (C5, 30/30 contra o CLI).
2. **A varredura LE da F1 está correta** — ela inverte o buffer inteiro (`buf[::-1]`); o conjunto de
   janelas resultante é idêntico a `{buf[j:j+32][::-1]}`, verificado para L ∈ {32, 33, 40, 80, 100,
   1328}. *(Ressalva de relatório, não de cobertura: os offsets LE saem na coordenada invertida.)*
3. **Oráculo duro correto** — h160 das pubkeys comprimida e não comprimida contra os **dois** alvos,
   sem filtro de padding nem semântico na frente da varredura.
4. **Controle plantado real** — duas chaves em offsets desalinhados (7 e 52), cifradas pelo CLI, com
   hits exigidos nas duas orientações.
5. **Arquivo de hits vazio por execução, não por omissão** — `hits.jsonl` e `candidatos.jsonl` são
   criados **antes** do laço e recebem `append`; ambos tinham 0 bytes com a varredura em curso e
   40 M janelas contadas. É o oposto do modo de falha da §3.13.
6. **As contagens batem com a fórmula fechada** `dec = n × 30` e `jan = n × 10 × 1395 × 2`, nas 32
   linhas de progresso **e** no total: 1.750 → 52.500 ✔ e 48.825.000 ✔. `interrompido_por_tempo:
   None`.
7. **O throughput prova trabalho real** — 24.473 a 36.710 janelas/s (mediana 34.720) contra os
   30.617/s medidos na mesma máquina. *(O coordenador confirma: 48.825.000 / 1.413,7 s = 34.538/s.)*
   Uma contagem só calculada não produziria essa curva.
8. **Nulo e triagem coerentes** — nulo de 200 senhas aleatórias: `printable` média 0,371, p99 0,4875;
   máximo real 0,5875 em 52.500 decifrações, muito abaixo do limiar 0,85. Nenhum outlier.
9. **Kit conferido** — `kit_sha256 = f109cd8a…` bate com este clone; os 10 controles `openssl_cli`
   são `True`; o controle de KDF dá `sha256: True, md5: False`.

### 5.1 Sobreposição medida (protocolo, item 5)

| conjunto | senhas |
|---|---|
| F1 | 1.750 |
| F2 | 586 |
| **F1 ∩ F2** | **69** |
| **união** | **2.267** |

Das 586 senhas desta frente, **517 são material que a F1 não cobre**. **As decifrações não podem ser
somadas inteiras:** 52.500 + 17.580 = 70.080 brutas, das quais **2.070 (69 × 30) são duplicadas de
propósito** — é nelas que a verificação independente tem valor.
**Cobertura única da campanha nesta família: 2.267 senhas → 68.010 decifrações e 63.249.300 janelas
raw32 BE+LE. Zero hits.** *(Reconferido pelo coordenador.)*

### 5.2 Ressalvas

1. **O controle plantado da F1 cobre 2 dos 5 modos** (`ofb` e `cfb1`) — confirmado pelo coordenador
   em `controls.json`. Os outros três ficam cobertos só pelo controle de igualdade com o CLI, que é
   forte mas **não exercita o scanner**. Esta frente fecha a lacuna: o C4 planta e recupera nos
   **5** modos. Não é erro da F1; é cobertura que só a antítese produziu.
2. **`passwords.py` mudou durante a auditoria** (1.330 → 1.750, ao entrar a camada H). O
   `resumo.json` final é da versão de 1.750; quem integrar deve conferir que o relatório da F1
   descreve essa versão (`sha256 fd6cc66b…`).
3. **Ordem dos modos difere** entre as frentes (mesmo conjunto) — registrado para a reconciliação
   não tratar como divergência.

### 5.3 O que NÃO pôde ser auditado

- **O `FINDINGS.md` da F1 não existia** ao fim do orçamento desta frente. Código, execução e
  `resumo.json` foram auditados; **o texto do relatório da F1 não**.
- **Qualquer alegação sobre o corpus histórico.** Confirmado que este clone não o tem. A F1 **não**
  fez tal alegação. Se o relatório final herdar contagens históricas, isso é achado de auditoria.

## 6. Aritmética das contagens históricas do `ENDGAME.md`

Consistência, não execução — **todas reconferidas pelo coordenador e exatas**:

| Alegação | Checagem | Veredito |
|---|---|---|
| §3.13: 253.179.237 janelas em cada orientação | × 2 = 506.358.474 | **exato** |
| §3.14: corpus de 1,27 M sem unpad = 498.682.408 | 1.272.149 × 2 × 2 × 49 × 2 | **exato** — devolve o tamanho do corpus sem que ele estivesse escrito ali |
| `raw32_corpus_nopad/summary.json`: `aes = 5.088.596` | 1.272.149 × 2 × 2 | **exato** |
| tabela D: "16 cifras × 1,27 M × 3 blobs × 2 KDF = 122 M" | = 122.126.304 | **exato** |
| §3.15: 12.754.752 montagens sobre 797.172 | razão = 16,0 | **consistente** |

**Uma ressalva de plausibilidade, não de aritmética.** O mesmo `summary.json` declara 498.682.408
janelas em **1.577,2 s** = **316.182 verificações/s**. Medidos aqui: **30.617/s** com `coincurve` em
1 processo — a contagem histórica exige **~10,3×** esse ritmo. É compatível com 8 a 12 workers
paralelos na máquina original (o `AGENTS.md` declara teto de 12 processos), mas **não é verificável
deste clone**, porque o corpus e o `.pkl` não estão aqui. **Item aberto de auditoria, não
divergência.**

## 7. Limitações declaradas

1. **Isto NÃO fecha a família "modos de fluxo".** Fecha 68.010 decifrações exatas sobre um conjunto
   nomeado de 2.267 senhas. A família só estaria fechada sobre o corpus histórico de 1,27 M formas,
   ausente deste clone. **Nada aqui autoriza escrever "modos de fluxo fechados" no `ENDGAME.md`** —
   a §3.14 continua valendo: *"continua aberto: só os modos de fluxo"*.
2. Só os 5 modos de fluxo do `openssl enc`, só `aes-256`.
3. Só `-pass` (EVP_BytesToKey); `-K/-iv` com chave crua não foi varrido.
4. Só raw32 BE/LE + hex64/WIF ASCII — chaves codificadas de outra forma não seriam vistas.
5. Sem scorer de quadgramas; nenhum substituto construído.
6. 1 processo, 4 cores compartilhados com as outras frentes.

## 8. Próxima pergunta

Se a família tiver de ser mesmo fechada, o passo decisivo não é mais senha nem mais modo: é rodar o
pipeline já certificado (C1–C5) sobre o **corpus de 1,27 M formas**, na máquina que o tem. A
aritmética cabe declarar de saída: 1.272.149 × 5 × 2 × 3 = **38.164.470 decifrações** e
1.272.149 × 10 × 1.395 × 2 = **35.493.457.500 escalares** — ~13 dias-CPU ao ritmo medido aqui, ~1,2
dia com 12 workers. Essa é a conta que precisa ser **executada**, e não citada, para que a §3.14
possa deixar de dizer "continua aberto: só os modos de fluxo".
