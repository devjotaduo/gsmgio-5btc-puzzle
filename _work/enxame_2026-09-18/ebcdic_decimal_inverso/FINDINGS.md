# FINDINGS: frente ebcdic_decimal_inverso (enxame_2026-09-18, hipótese I1 do Codex Astra)

**Resultado: negativo completo, com a lacuna reproduzida.** Nenhum inteiro da I1 nem das extensões passou pelo repertório da direção autêntica da fase 3.2. Por isso não houve texto, senha, decisão AES, padding, privkey ou candidato.

## Fato observado

### A lacuna existe e foi reproduzida

- `solver/ebcdic_decimal.cjs:11` (checkout principal, sha256 `b1a14c3c…0f0d`, o hash do RELATORIO de 16/09) monta `allowed` pela leitura EBCDIC 1141 convencional. Esse conjunto é, byte a byte, a imagem cp273 **direta** do ASCII imprimível.
- A fase 3.2 real usa a direção inversa: bytes = `ASCII.decode('cp273').encode('latin-1')`. Conferido no `_work/phase32_plaintext.bin`: o segmento de 1.539 B no offset 447, passado por `b.decode('latin-1').encode('cp273')`, reproduz exatamente a linha Beaufort do README.
  - Os 1.539 bytes estão no repertório inverso.
  - Só 864 estão no repertório antigo.
- Os dois repertórios têm 98 bytes, mas só 43 são comuns; cada lado tem 55 exclusivos. O alfabeto a–z na direção autêntica perde 12 de 26 bytes no repertório antigo.
- Falso negativo concreto no código antigo, rodado sem modificação por `node` + `require`:
  - O texto "I've been waiting for you.\nThe matrix has you!" na direção autêntica dá 46 B, 26 deles fora do repertório antigo, e vira 111 dígitos com os zeros trocados pela letra ℓ.
  - Para as 9 letras, a `search()` antiga termina completa com 0 hits. O mesmo arnês acha o mesmo texto codificado na direção antiga.
  - O código novo recupera o texto nas 9 letras.
- **Lacuna irmã, não coberta aqui:** `solver/ebcdic_codepoints.cjs:7` usa o mesmo repertório direto na leitura por concatenação de códigos decimais (26.127.728 casos em 16/09).

### Busca

| Conjunto | Tamanho | Método | Aceitos |
|---|---:|---|---:|
| I1: dbbi na ordem publicada, a=1..i=9, 1 letra zerável | 33.819.184 inteiros distintos | enumeração direta (Gray, sem poda) + DFS (17 nós) | 0 |
| Literal: dbbi/faed × orig/rev × {∅, 9 letras, 36 pares} | 184 configurações | DFS completo, 764 nós | 0 |
| Bijeções: 9! × 9 letras zeráveis × dbbi/faed × orig/rev | 13.063.680 casos | DFS completo, 29.225.802 nós | 0 |

- A I1 soma 1 + Σ(2^c − 1). As máscaras não vazias por letra são: a 7, b 33.554.431, c 255, d 15, e 262.143, f 1.023, g 1.023, h 255, i 31.
- Literal + bijeções = 13.063.864 configurações, exatamente a cobertura de inteiros de 16/09, agora no repertório correto.
- A execução levou ~134 s de relógio (3 processos só na fase das bijeções).

## Inferência

A leitura "inteiro decimal com zeros substituídos → bytes → texto EBCDIC" fica excluída também na direção autêntica da fase 3.2, com a mesma cobertura do negativo de 16/09. Isso vale para texto ASCII e para os modelos de alfabeto e zeros declarados.

O negativo quase não carrega informação estatística. Com bytes uniformes, um inteiro de 38 B passa com p = (98/256)^38 ≈ 1,4e-16, e o esperado na I1 é 4,8e-9. O teste só teria sucesso se o autor tivesse de fato construído o dbbi assim; o resultado diz que não construiu, dentro desta cobertura.

A I1 fica refutada no seu domínio: nenhuma decodificação admissível existe, logo nenhuma senha abre SMALL.

## Fontes e hashes

- Script: `solver/enxame_2026_09_18/ebcdic_decimal_inverso/busca.py`, sha256 `9606291b814bd0959056b66548dc2f40fa83e6c1f885e8d7a8b5f431583e50f2`.
  - Reprodução: `python solver/enxame_2026_09_18/ebcdic_decimal_inverso/busca.py --workers 3`
- `comum.py`: `0bea9880…c7a6`.
- Kit `gsmg_common.py`: `3810cbaf…1e67`, no commit `5f12b716a67763d7cd72aec3447a15c3015bf2d4`. O `busca.py` e o `comum.py` ainda não estão commitados.
- Entradas:
  - `inputs.json` `2e58c16a…edc6` (`G.DBBI` e `G.FAED` idênticos a ele).
  - sha256(dbbi) `71fe4625…c5ca`; sha256(faed) `066191b4…f3c2`.
  - `encoding.json` 1141 `91dbd5a1…2179`.
  - `phase32_plaintext.bin` `b82afeb8…8a34`.
- Saídas em `_work/enxame_2026-09-18/ebcdic_decimal_inverso/`:
  - `controls.json` `5436bc0c…aa00`, idêntico em duas execuções.
  - `summary.json` `2ce64320…00b1`.
  - `aceitos.jsonl`, vazio.

## Cobertura

- **Reconciliação da I1:**
  - 1 inteiro sem zeros + Σ das máscaras não vazias = 33.819.184 (conferido por assert).
  - Cada letra passa por dois checkpoints do código de Gray: a posição final e a soma Σn em forma fechada, 2^c·n0 − 2^(c−1)·Σw.
  - A enumeração direta e o DFS dão o mesmo conjunto de aceitos (vazio).
  - Os hits da família literal para dbbi/orig com 0 ou 1 letra foram conferidos iguais aos da I1.
- **Sobreposições:** I1 ⊂ literal; as letras isoladas da literal ⊂ bijeções (pela bijeção identidade). As contagens de casos acima não somam inteiros únicos.
- **Ordem dos bytes:** a pertença ao repertório é invariante à reversão, então a leitura little-endian está coberta.
- **Oráculos:** 0 textos aceitos, portanto 0 senhas (raw e sha256hex), 0 decisões AES (SMALL/COSMIC/TAIL32 × SHA256/MD5) e 0 privkeys sha256(t) testadas contra os dois alvos. A regra 5 não tem padding a registrar.

## Controles (todos passaram)

1. A fase 2 abre com sha256hex('causality') pelo `C.testar`.
2. O repertório antigo é igual à tabela 1141 da cjs e à cp273 direta (98/98 bytes, 43 comuns).
3. A direção da 3.2 reproduz o Beaufort (1.539 B, offset 447).
4. `sucessor()` e `aceito()`:
   - `sucessor()` contra força bruta em todo n < 2^16, nos dois repertórios.
   - `aceito()` contra a definição literal (decode latin-1 → encode cp273) em 85.536 inteiros.
   - Em 6.000 inteiros de 1–240 B, `sucessor(n)` conferido por uma contagem posicional independente: [n, s) não tem aceitos e s é aceito.
5. DFS contra enumeração de máscaras: 2.000 casos (1.000 plantados), 1.090 com aceitos, 1.791 inteiros conferidos.
6. Ponte: recuperação pelo DFS (9/9 letras) e pela enumeração direta (7/7 com ≤ 22 ocorrências). O repertório antigo rejeita a ponte; a cjs original não a acha, mas acha a direção antiga.
7. 400 textos aleatórios de 8–60 B, com bijeção e letra aleatórias, recuperados pelo mesmo `modelo_bijecao()` + `dfs()` da campanha.
8. Privkey plantada, sha256 do texto da ponte:
   - com o alvo plantado, `G.fast_priv_scan` dispara;
   - desplantada, não dispara;
   - `TARGET_H160S` volta aos 2 alvos.
9. Blob sintético do openssl CLI 3.5.7 (`-md sha256`), cifrado com sha256hex da ponte, abre por `G.try_password_all` com KDF SHA256.

**Nulo:** N/A. A enumeração é determinística e deu 0 aceitos, então a condição (aceitos > 0) para os 100 embaralhamentos não se cumpriu. A calibração analítica está na seção "Inferência".

## Limites

- Só cobre texto inteiramente ASCII 32–126/TAB/LF/CR. Fica fora texto com caracteres não ASCII do cp273 (ä, ö, ü, ß, ç…).
- Não refaz a leitura por códigos decimais concatenados (`ebcdic_codepoints.cjs:7`, lacuna irmã com o mesmo repertório errado).
- Não cobre três ou mais letras zeráveis no alfabeto literal, nem duas letras zeráveis com bijeção.
- Não cobre remoção de símbolos, outras transposições, compressão nem cifra adicional.
- O caminho AES/privkey só rodou nos controles, porque não houve texto aceito.

## Próxima pergunta

A lacuna irmã: a leitura por concatenação de códigos decimais de byte, mínimos ou com 3 dígitos, refeita no repertório inverso, com a mesma cobertura de 16/09 (26.127.728 casos). Ela usa o mesmo repertório errado e ainda não foi refeita. É preciso um autômato de viabilidade em Python ou portar a `ebcdic_codepoints.cjs` trocando só o repertório.

**Delta proposto** (para quem integra): na §4-B do ENDGAME, linha "Decimal → hex → ASCII/EBCDIC 1141", acrescentar: "repertório corrigido para a direção autêntica (cp273 inversa) em 2026-09-18: mesmas 13.063.864 configurações de inteiros, 0 aceitos; a leitura por códigos concatenados segue coberta só no repertório direto".

## Revisão adversarial independente

**Veredito do revisor: negativo confirmado.** Onde as correções abaixo divergem do texto acima, valem as correções.

### Problemas apontados

- Violação de procedimento: a frente rodou com --workers 3 (3 processos de trabalho mais o principal), acima do limite de 2 processos da regra 3. O argparse de busca.py tem default=3, e o comando de reprodução do findings_md usa --workers 3. O resultado não muda: com 2 processos a reprodução independente deu os mesmos números.
- O controle positivo da enumeração direta (código de Gray) só foi exercido em até 22 ocorrências. A letra b do dbbi tem 25, então esse tamanho nunca rodou com alvo plantado. O código é o mesmo para qualquer c, e minha enumeração independente cobre a lacuna, mas o controle da frente não cobre.
- O repertório inverso foi derivado só do cp273 do Python e não foi conferido contra a tabela 1141 de 16/09. Conferi: os dois dão os mesmos 98 bytes. Outra observação: a visão cp273_inverse_view do oráculo duplo (solver/oraculo_duplo_2026_09_17/oracle.py:36) troca o 0xAF não codificável por '?' e aceita 99 bytes. A I1 pede codificação estrita, e no 1141 real o 0xAF vira 0xBC, que não é imprimível, então a frente está certa. Testei a I1 e a família literal com o repertório de 99 bytes: 0 aceitos. As bijeções não foram refeitas com ele.
- A especificação pedia conferir a direção contra solver/multiagente_2026_09_18/audit_codecs.py. O findings não cita esse arquivo; a frente conferiu só contra o plaintext autêntico, que é a prova mais forte. Conferi: a visão do audit/oráculo duplo transforma o segmento em 447 no Beaufort, na mesma direção.
- O caminho de ponta a ponta nunca rodou com um inteiro aceito plantado, só componente a componente: main → registros → texto(n) → testar_textos (C.testar mais privkey) → summary. Com 0 aceitos, esse trecho de main não foi executado sobre dado nenhum. Pela leitura, as chaves do summary existem no retorno de C.testar.
- Afirmação vazia: 'os hits da família literal para dbbi/orig com 0 ou 1 letra foram conferidos iguais aos da I1'. Os dois conjuntos são vazios, então a conferência é trivial.
- Contexto da execução: durante esta revisão o disco C: chegou a 0 bytes livres por alguns instantes, e até o stdout falhou. Não foi esta frente, cujas saídas somam 44 KB. O coordenador deve conferir se outras frentes perderam gravações nesse intervalo.

### Reprodução independente

Scripts em C:\Users\ruthe\AppData\Local\Temp\claude\C--Users-ruthe-Desktop-puzzle-gsmgio-5btc-puzzle-oraculo-duplo\8577a684-4fe9-4572-b8ca-d4298a0fcc6f\scratchpad\revisao_ebcdic_decimal_inverso\: base.py, enum_i1.py, bij.py, old.cjs, casos.json, ctl_hash.py, ctl_diff.py. Nenhum importa busca.py, exceto os dois de hash dos controles. Rodei tudo em primeiro plano com Pool(2).

(1) Manifesto. Recalculei os sha256 e todos batem com o relato: busca.py 9606291b…; comum.py 0bea9880…; kit 3810cbaf… com HEAD 5f12b716…; ebcdic_decimal.cjs b1a14c3c…; encoding.json 91dbd5a1…; inputs.json 2e58c16a…; phase32_plaintext.bin b82afeb8…; sha256(dbbi) 71fe4625… e sha256(faed) 066191b4…; controls.json 5436bc0c…; summary.json 2ce64320…; aceitos.jsonl vazio (e3b0c442…). G.DBBI e G.FAED são iguais ao inputs.json. O dbbi tem 91 letras (a3 b25 c8 d4 e18 f10 g10 h8 i5), o que dá 33.819.184 inteiros, e n0 tem 38 B.

(2) Direção e lacuna.
- Aplicada ao plaintext real da 3.2, a transformação b.decode('latin-1').encode('cp273') põe o Beaufort do README (1.539 B) exatamente no offset 447. A direção contrária não o encontra (find = -1).
- Os bytes 0–446 e o trecho depois do segmento são ASCII puro: só o segmento foi transformado.
- Repertórios: o antigo, pela tabela 1141, tem 98 bytes. O inverso tem 98 tanto pela tabela 1141 quanto pelo cp273 do Python, com conjuntos iguais. Há 43 bytes comuns e 55 exclusivos de cada lado.
- Do segmento, 1.539 de 1.539 bytes estão no inverso e 864 no antigo. O alfabeto a–z perde 12 bytes no antigo. A ponte tem 46 B, 26 deles fora do antigo, e vira 111 dígitos.
- Falso negativo refeito com arnês meu (old.cjs): chamei a search() original por require, sem modificação e com maxNodes de 10 milhões. Usei dois textos (a ponte e 'Close friends have the best chance') com as letras a, e, i. Na direção autêntica a busca termina completa com 0 hits (1 a 7 nós); na direção antiga acha o texto nos 6 casos. A lacuna é a própria I1, não uma variante mais fácil.

(3) I1 por enumeração completa independente (enum_i1.py, 191 s).
- Método: máscaras em ordem binária, com divisão das subsomas em parte alta e baixa, sem código de Gray. O teste é a definição literal: decode latin-1, encode cp273 (caractere não codificável conta como byte ruim) e verificação contra ASCII 32–126/TAB/LF/CR, sem usar a tabela da frente. A mesma passada testa a direção antiga.
- Contagem: 33.819.184 inteiros, com contagem por letra e soma em forma fechada conferidas por assert.
- Resultado: 0 aceitos no inverso e 0 no direto, o que também reconfirma 16/09 neste subconjunto.
- Nenhum inteiro chega perto de passar: o mínimo é 9 de 38 bytes não imprimíveis no inverso e 8 no direto; n0 tem 23 ruins.
- Controle plantado pelo mesmo código: 'Close friends!' com zeros trocados por g é achado no ramo inverso e não no direto; o mesmo texto na direção antiga é achado no ramo direto.

(4) Família literal e bijeções com outra poda (bij.py, 468 s).
- Método: poda por PREDECESSOR (o maior aceito ≤ n+cauda, comparado com n), em vez de sucessor, com coeficientes recalculados. O controle confere pred() contra força bruta em todo n < 2^17 e recupera 200 textos plantados com bijeção e letra aleatórias.
- Literal: 184 configurações, 764 nós, 0 aceitos, iguais à frente grupo a grupo em nós e aceitos.
- Bijeções: 36 grupos × 362.880 = 13.063.680 casos, 29.225.802 nós, 0 aceitos, iguais à frente nos 36 grupos (casos, nós e aceitos).
- Como a poda por predecessor é equivalente à por sucessor, a igualdade exata de nós confirma que a árvore percorrida é a mesma.
- Não há limite de nós, top-N nem exceção engolida em busca.py. O único try/except (aceito_por_definicao) rejeita o 0xAF não codificável, o que está correto.

(5) Controles: rodei as funções de controle da frente em memória, sem gravar no diretório dela. O JSON é idêntico ao controls.json gravado; o sha256 fica 5436bc0c… com CRLF, porque o write_text do Windows grava CRLF. Depois dos controles, TARGET_H160S volta aos 2 alvos e o blob PONTE sai de G.BLOBS.

(6) Oráculos: o conjunto de textos aceitos é vazio, e confirmei isso de forma independente. Não há senhas, paddings nem h160 registrados para comparar, então a amostra de 2.000 senhas pela cryptography/openssl é N/A. Em vez dela, conferi o oráculo de privkey com outra biblioteca: 200 escalares (sha256 da ponte mais 199 aleatórios), com h160 comprimido e não comprimido calculados pelo python-ecdsa e plantados um a um. O kit detectou 400 de 400 e não disparou nenhum depois de desplantado. A abertura AES só foi conferida pelo controle da própria frente (openssl CLI 3.5.7 contra o kit).

Candidatos ou hits: nenhum.

### Correções ao relatório

1. "A execução levou ~134 s de relógio (3 processos só na fase das bijeções)." → "~134 s de relógio, com 3 processos de trabalho na fase das bijeções, acima do limite de 2 da frente. A reprodução independente com 2 processos confirmou os números."

2. "Reprodução: `python solver/enxame_2026_09_18/ebcdic_decimal_inverso/busca.py --workers 3`" → usar `--workers 2`. Trocar também o default do argparse, se o script for reutilizado.

3. Controle 4: "Em 6.000 inteiros de 1–240 B, `sucessor(n)` conferido por uma contagem posicional independente" → "Em 3.000 inteiros de 1–240 B, cada um nos dois repertórios (6.000 conferências), ...". O mesmo vale para a frase equivalente no campo controles.

4. "Os hits da família literal para dbbi/orig com 0 ou 1 letra foram conferidos iguais aos da I1." → acrescentar "(os dois são vazios, então a conferência é trivial)".

5. Inferência: "A leitura 'inteiro decimal com zeros substituídos → bytes → texto EBCDIC' fica excluída também na direção autêntica da fase 3.2, com a mesma cobertura do negativo de 16/09." → "... com a mesma cobertura da leitura por inteiro completo do negativo de 16/09 (13.063.864 configurações). As duas leituras por códigos concatenados de 16/09 (mínimos e 3 dígitos, 26.127.728 casos) seguem cobertas só no repertório direto."

6. "Controle 2: O repertório antigo é igual à tabela 1141 da cjs e à cp273 direta (98/98 bytes, 43 comuns)." → acrescentar: "O repertório inverso derivado da tabela 1141 é idêntico ao derivado do cp273 do Python (conferido na revisão). A visão cp273_inverse_view do oráculo duplo aceita também o 0xAF, porque troca o não codificável por '?'. Com esses 99 bytes, a I1 e a família literal também dão 0 aceitos (conferido na revisão; bijeções não refeitas)."

7. Controle 3: "A direção da 3.2 reproduz o Beaufort (1.539 B, offset 447)." → acrescentar: "Só esse segmento foi transformado; os bytes 0–446 e o trecho depois do segmento do plaintext de 2.422 B são ASCII puro."

8. Controle 6 (ponte), sobre "recuperação ... pela enumeração direta (7/7 com ≤ 22 ocorrências)": acrescentar que a letra b do dbbi tem 25 ocorrências, fora do alcance desse controle. A cobertura dela vem da soma de controle e da reprodução independente, não do plantado.

9. Nulo/Inferência: pode entrar o dado empírico da revisão: "nos 33.819.184 inteiros, o mínimo é de 9 bytes não imprimíveis em 38 no repertório inverso (8 no direto). Nenhum inteiro chega perto de passar."

10. Seção Cobertura, 'Oráculos': acrescentar "o trecho de main que leva um aceito ao C.testar e à privkey nunca rodou com dado; os controles só exercitaram os componentes (C.testar pela fase 2, fast_priv_scan plantado, try_password_all com blob do openssl)".

Os demais números do findings_md foram reproduzidos exatamente e não precisam mudar: 33.819.184; as máscaras por letra; 17 nós; 184/764; 13.063.680/29.225.802; 98/43/55; 1.539/864; 12/26; 46 B, 26 fora, 111 dígitos; hashes.

## Nota do coordenador

O revisor cita um limite de 2 processos, mas esse número veio de um erro no prompt de revisão,
que trocava `WORKERS` por 2 no texto comum. O limite desta frente era **3 processos**, e ela o
respeitou. A pressão de memória e de disco durante a campanha foi causada pela alocação do
coordenador (20 workers ao todo numa máquina de 20 núcleos), não por esta frente. Ver
[RELATORIO.md](../RELATORIO.md), seção "Processo".
