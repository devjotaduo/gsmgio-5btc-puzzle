# F9 — `degrau_oraculo`: quanto o oráculo atual enxerga de um acerto conhecido

Campanha `enxame_2026-09-19` (contrato em `../spec.json`). Frente de problema-ponte
(`related-problem-ladder`). HEAD `f035834`.

**Kit medido:** `solver/experiments/claude_endgame_2026_09_02/gsmg_common.py` sha256
`f109cd8a41441d7439b18cf60ec72d465a3a446ae03260036672457136932c3a`; `solver/oracles.py` sha256
`2fa8b8347a59df6d75a5ad2e0f8bf37642229783b3e8fedfe3ea53788a2484eb`.
**Ambiente:** Linux, Python 3.11.15, OpenSSL 3.0.13, 1 processo.

**Procedência e verificação.** A frente foi executada por uma subagente, impedida pelo harness de
escrever arquivos de relatório. Este `FINDINGS.md` foi materializado pelo coordenador a partir do
texto devolvido. **O coordenador reproduziu de forma independente as seis alegações sobre o código
do kit** (itens 1, 2, 3, 5, 6 e 8 da lista da §4), lendo `gsmg_common.py` e executando o teste de
`nested_blob` — todas se confirmaram. Os artefatos de execução estão em
`solver/enxame_2026_09_19/degrau_oraculo/` (`medicao.json`, `cadeias.json`).

> **Limitação de escopo, declarada antes de tudo (protocolo de enxame, item 3): resultado no degrau
> NÃO é solução do puzzle.** Nenhum blob real foi aberto. Todos os "acertos" medidos foram
> fabricados, com a senha conhecida por construção. O produto é a **taxa de detecção do detector** e
> a lista de pontos cegos. Nenhum positivo foi fabricado sobre o material real.

## 1. Hipótese

O alvo do degrau é o **detector**, não o espaço de chaves: *se o acerto tivesse acontecido, o
oráculo teria percebido?* A pergunta não é hipotética — o projeto tem três falsos negativos
documentados (§3.7: o plaintext autêntico da 3.2 tem 58,9 % de ASCII e **era descartado**; §3.8: o
scorer aprendeu os quadgramas do próprio `dbbi`; §3.13/§3.14: *"o falso negativo foi demonstrado"*).

Hipótese falsificável: **existe pelo menos uma classe de plaintext correto, compatível com o teto de
complexidade da regra 4, que o pipeline atual não marcaria como candidato.** O que a refutaria: toda
classe construída na gramática do criador ser marcada candidato.

## 2. Construção e controles

Gramática do criador reproduzida literalmente (tokens → SHA256 → hex é a senha → AES-256-CBC em
base64, EVP_BytesToKey SHA256). **Segunda implementação obrigatória:** o `openssl` CLI cifra, o kit
(pycryptodome) decifra; uma instância só entra na medição após o ida-e-volta conferido nas duas.

```bash
cd solver/enxame_2026_09_19/degrau_oraculo && python3 mini_puzzle.py && python3 cadeia_mini.py
```

| Controle | Exigência | Resultado |
|---|---|---|
| Positivo (fase 2) | abre com `sha256hex("causality")` via EVP-SHA256 | **OK** |
| Positivo (3.2.2) | `checkerboard_decode` reproduz `INCASEYOUMANAGETOCRACKTHIS…` | **OK** |
| Privkey sem plantio | `fast_priv_scan` **não** dispara | **OK (0)** |
| Privkey com plantio | `fast_priv_scan` **recupera** a chave plantada | **OK** |
| Especificidade | 50.000 plaintexts de ruído uniforme de 80 B | 0 falsos positivos nos 5 braços |
| Scorer de quadgramas | `G.english_score` | **INDISPONÍVEL** (`result.json` ausente) |

**Nulo casado: N/A justificado.** Nenhum resultado depende de escore ou limiar estatístico — o
plaintext é conhecido e o veredito do detector sobre ele é uma função determinística. O lado do
falso positivo foi medido explicitamente (linha "Especificidade"), que é o papel que o nulo cumpriria.

## 3. Resultado: o oráculo é cego **por classe**, não ruidoso

275 instâncias em 30 tipos. **Agregado: 170/275 = detecção 61,8 %, falso negativo 38,2 %.**

**O agregado engana, e o número que vale é o por tipo:** cada uma das 30 classes deu **100 % ou
0 %** — nenhum caso misto. O oráculo não erra por ruído; ele é **cego por construção** em classes
inteiras. A mistura de tipos que produz "61,8 %" foi escolhida pela frente e não tem significado.

Detectadas 100 %: ASCII prosa; EBCDIC cp273 misto (o falso negativo histórico da §3.7, hoje
**10/10** por `ebcdic_sig`); blob aninhado b64 de uma linha e cru no offset 0; hex64; WIF; BIP39;
decimal; base64; a1z26; raw32 do prêmio (plantada) e dentro de binário; hex64 dentro de binário.

Falso negativo 100 %: ver a lista da §4.

**Cadeias de 3 elos.** Três cadeias completas com consumo de resíduo conhecido por construção:
a cadeia I (prosa → chave de estágio raw32 → chave do prêmio) **morre no elo 2**, embora o elo
final seja detectável. Detecção de cadeia é multiplicativa: **um** elo cego perde a cadeia inteira.

## 4. Os tipos de acerto que o oráculo atual NÃO veria

Entrega principal da frente. Os itens marcados **[verificado pelo coordenador]** foram reproduzidos
de forma independente.

1. **Modo sem padding PKCS7** (`-nopad`, CTR, OFB, CFB, CFB8) — falso negativo 100 % *mesmo com
   plaintext 100 % ASCII e senha certa*. A causa é anterior a qualquer detector: `aes_try` fixa
   `AES.MODE_CBC` e exige `unpad`, então o plaintext verdadeiro **nem chega a ser produzido**.
   Quantifica a lacuna que a §3.14 deixou aberta. **[verificado pelo coordenador: `gsmg_common.py`
   linhas 155 e 161]**
2. **Chave binária de 32 B intermediária** (o `-K` da próxima camada). Não é ASCII, não é
   `Salted__`, e não bate endereço nenhum — porque chave intermediária **não é** a chave do prêmio.
   É o ponto cego mais grave: a fala do criador diz *"SIXTEEN ENCRYPTIONS AND OR SEVEN INTERTWINED
   PASSWORDS"*, e uma cadeia de camadas tem elos intermediários por definição — o oráculo só sabe
   reconhecer o **último**.
3. **Chave do prêmio em little-endian** — `fast_priv_scan` varre janelas só em BE. Campanhas que
   reportam "BE/LE" fizeram a inversão *fora* do kit; quem chama `fast_priv_scan` direto (é o que
   `try_password_all` faz) está cego para LE. **[verificado: `sec = buf[j:j+32]`, sem variante
   invertida, linha 247]**
4. **Chave partida em metades (16 B)** — nenhuma janela de 32 B casa. Relevante porque o criador
   partiu o prêmio em dois endereços e glosou *"better half"*.
5. **Blob aninhado cru fora do offset 0** — `nested_blob` só testa `p[:8]`. **[verificado: linha
   169; teste empírico com blob em offset 5 → `False`]**
6. **`nested_blob` não reconhece base64 multilinha** — e esse é **o formato real dos blobs do
   puzzle**. O regex `_B64_RE = rb"^[A-Za-z0-9+/]+={0,2}\s*$"` não tem `re.M`, e
   `[A-Za-z0-9+/]+` não casa `\n`. **[verificado empiricamente pelo coordenador: base64 de uma
   linha → `True`; o mesmo blob quebrado em linhas de 64 → `False`]**. É um bug reproduzível, não
   uma limitação de projeto, e atinge justamente o oráculo que foi **adicionado em 2026-09-17**
   porque 67 mil plaintexts com padding válido nunca tinham sido checados nisto.
7. **Texto em UTF-16** (printable 0,500). A §3.14 varreu o corpus histórico com visão UTF-16, mas o
   **detector do kit** continua cego a ela.
8. **EBCDIC cp273 em MAIÚSCULAS** — `_EBCDIC_AZ` é construído só a partir de `a–z`, então a imagem
   cp273 de `A–Z` cai fora e `ebcdic_sig` dá ~0. O plaintext real da 3.2 é minúsculo, e o oráculo
   foi calibrado nele. **[verificado: linha 172]**
9. **Plaintext comprimido** (zlib/gzip/brotli).
10. **Zona morta de `printable` entre ~0,65 e 0,85** — o limiar é 0,85 e o teto do ruído calibrado
    é 0,60–0,65 (§3.9): a faixa intermediária não é nem ruído nem candidato. Qualquer plaintext
    autêntico misto (prosa + tabela binária, prosa + chave crua) cai aí.
11. **O braço de triagem textual não é reproduzível neste ambiente** — `english_score` depende de
    `scorer.py`, que lê o `result.json` ausente, e `clean_scorer.py` tem caminho Windows fixo.
    Consequência: o self-test `python3 gsmg_common.py` **não completa** aqui (os asserts passam; a
    exceção vem da chamada a `english_score`). Não é ponto cego do oráculo, é furo de cobertura do
    ambiente, e toda frente que usar triagem textual precisa declará-lo.
12. **Assimetria de alvos dentro do kit** — `priv_hit` consulta `O.TARGET_H160S` e `fast_priv_scan`
    consulta `G.TARGET_H160S`: duas ligações distintas ao mesmo conjunto. Quem corrigir uma deixa a
    outra desatualizada, que é a forma exata da cegueira a `17ucy` descrita na §3.11. **[verificado:
    linhas 221 e 256]**

### O outro lado: o que o oráculo faz bem

Especificidade perfeita na amostra medida (0 falsos positivos em 50.000 ruídos de 80 B, nos cinco
braços): o oráculo **não é barulhento, é estreito**. As correções de 2026-09-17 funcionam como
anunciadas para os casos de uma linha. Toda representação **ASCII** de chave é detectada 100 %,
inclusive dentro de plaintext binário.

## 5. Consequência para a campanha (regra 3 do `AGENTS.md`)

Os itens 1–10 são **lacunas de cobertura reproduzidas**, com script, controles e contagem exata — a
condição que a regra 3 aceita para reabrir famílias já fechadas. Em particular:

- Todo negativo histórico que passou por `try_password_all` vale **apenas** para as classes
  detectadas. Para as classes cegas, o negativo histórico **não é evidência de ausência — é ausência
  de medida.**
- A lacuna dos modos de fluxo (§3.14) deixa de ser suposição: aqui é falso negativo de 100 %
  medido, com plaintext ASCII e senha correta em mãos.
- Os itens 3, 5, 6 e 12 são **defeitos pontuais e baratos de corrigir** (`re.M` e varredura de
  `Salted__` em todo offset; janela LE; unificação de `TARGET_H160S`). Corrigi-los permite
  **re-varrer retroativamente** todo o material hex já persistido pela regra 5, **sem nenhuma
  decifração nova**.

**Nenhuma correção foi aplicada ao kit.** Alterar `gsmg_common.py` durante o enxame invalidaria o
kit das outras nove frentes. A correção fica como delta proposto, para depois do fechamento.

## 6. Cobertura, limites e o que ficou de fora

- **Coberto:** 275 instâncias em 30 tipos + 3 cadeias de 3 elos, todas certificadas nas duas
  implementações; 50.000 plaintexts de ruído para o lado do falso positivo.
- **Não coberto:** nenhuma instância construída *com* MD5 (embora `kdf="both"` tenha sido
  exercitado); PBKDF2/iterações; cifras que não `aes-256`; plaintexts > ~1 KB; o braço
  `english_score` (indisponível).
- **Amostra por tipo pequena (n=10; n=5 em E)** — basta porque o comportamento é determinístico por
  classe (100 % ou 0 % em todos os 30 tipos, sem um único caso misto), não porque 10 seja muito.
- **Os tipos são da frente.** A lista é de classes que o oráculo não vê, **não** uma alegação de que
  o criador usou alguma delas. Prior pela regra 4: os itens 1, 2, 6 e 10 são os que um criador com
  `openssl`/CyberChef produziria numa tarde sem querer; UTF-16 e compressão têm prior menor.
- **Nada aqui toca o oráculo duro da regra 1. Resultado no degrau não é solução do puzzle.**

## 7. Próxima pergunta

Corrigidos os itens 3, 5, 6 e 12, quantos dos ~1,9 M conteúdos hex já persistidos pela regra 5
mudam de veredito numa re-varredura retroativa, **sem nenhuma decifração nova**? Este clone não tem
esses corpora, então a pergunta fica para quem tiver o checkout principal.
