# Crítico final — família `codecs_23` ("over twenty-three ciphers" = codecs de byte único)

Data: 2026-09-17/18. Auditado: `solver/operador_ensinado_2026_09_17/familia4_codecs.py` e o JSON de ataque.
Script: `solver/operador_ensinado_2026_09_17/critico_codecs_final.py`. Log: `critico_codecs_final.jsonl`,
`resumo.json`, `stdout.txt` (esta pasta). Reaproveitado do crítico anterior: C1–C4 de
`critico_familia4_codecs.jsonl` e o braço multi-byte de `critico_codecs23.jsonl`.

## Veredito: CONFIRMADO_NEGATIVO (com dois erros de reporte e um furo de oráculo corrigidos aqui)

## 1. Controle positivo cp273 — passou (reimplementado char a char, sem as tabelas do agente)
- Segmento alto do plaintext real da 3.2 (1.539 B, 974 bytes altos): a–z = **1,000 sob cp273**, 0,000 sob os
  57 codecs não-EBCDIC, argmax único; re-encode reproduz `vtkvplmepphl…`.
- Nuance: com o limiar 0,75 do detector, cp037/cp500/cp1140/ebcdic_cp_us (0,951) e cp1026 (0,879) também
  "disparam"; o `scan_bytes` dele guarda só o argmax, logo o codec reportado seria cp273. Aceitável.
- **Furo:** o oráculo duro dele sobre a saída traduzida (`duro_traduzido`, copiado literalmente) devolve
  **None** para o positivo real — o campo 3 em cp273 é Beaufort (inglês −6,24; limpo −7,80; 0 palavras BIP39).
  Consequência: "699 hits de detector, 0 duros" na partição MATERIAL não excluía um segmento estilo 3.2.
  O kit (`G.semantic` via `ebcdic_sig` = 1,0) reconhece; ele evitou `ebcdic_sig` em ambas as direções.

## 2. Cobertura reproduzida
| Braço | JSON de ataque | Log final dele | Recontagem |
|---|---|---|---|
| A1 plaintexts AES / arquivos / material | 53.573 / 95 / 684.413 | **112.242 / 98 / 684.791** | coletor amplo do crítico anterior: 106.235 / 101 / 684.455 |
| A2 transformadas distintas | 114 | 114 | **114** (19 campos × 65 × 2) |
| A3 senhas / paddings | 105.519 / 2.540 | 105.519 / 2.540 | **bate** (z global +1,35) |
| A1 nulo, z do máximo | **+3,14** | **−0,88** (obs 0,387 vs 0,409 ± 0,024) | look-elsewhere: 6,8 ocorrências de `lower ≥ 0,533` esperadas por acaso |

Erros de reporte: (a) os números de A1 e o z = +3,14 do JSON são de uma execução anterior, não da final;
(b) 323.591 registros do corpus final dele vêm de logs de **críticos** (`critico_familia4_codecs.jsonl`
247.579, `critico_familia6/*` 69.771, `critico_familia5` 6.241) — realimentação, não material novo.
Lista de codecs: 65 nomes = 64 canônicos (`ebcdic_cp_us` = cp037); faltam 5 da stdlib, todos não-EBCDIC
(identidade sobre ASCII). Colapso "65 → 2 imagens" vale só na direção encode; nas 2 direções são 3–7 por
campo (C2), e fatias são vácuas (imagem(fatia) = fatia(imagem)). Nada disso muda o negativo.

## 3. Oráculo
- `fast_priv_scan` do kit: só `1GSMG…`, só ordem direta. A re-varredura (§6) usa os dois endereços
  (`h160` de pubkey comprimida e não comprimida), duas ordens, hex64/WIF embutidos; controle plantado OK
  em fwd@7 / rev, comp / unc, e não dispara em chave alheia.

## 4. Nulo casado
O A3 dele (100 lotes × 3.000, μ 70,98 vs 70,31) e o A1 final (z −0,27 / −0,88) são adequados. Acrescentado
o look-elsewhere analítico do máximo (p(a–z | byte alto) ≤ 0,203 por tabela EBCDIC → P(≥16/30) = 6,4e−5 ×
~107 k tentativas = 6,8 esperados).

## 5. Completado: auditoria individual dos 699 + censo multi-byte
- 699 hits MATERIAL (hex completo, ≤ 82 B): 300+4 `frequency_primes`, 144+1 `wavelength_primes`,
  109+67 `utf8_decimal`, 74 `f5_retro_ebcdic`; dispararam por `print ≥ 0,95` (não a–z), sob cp1026/cp037 dec.
  Traduzidos têm **2–14 letras** (433 com < 8; 290 com IoC degenerado). Oráculo da auditoria com controle
  positivo: campo 3 real → cp273 → Beaufort/`THEMATRIXHASYOU` = "YOURLIFEISTHESUMOFAREMAINDER…" (−3,985 vs
  nulo −7,96, máx −7,87). Nos 699: inglês limpo máx −5,74; Beaufort máx −4,265 = "PSLIJADQ→EPTERTOS"
  (8 letras), p = 0,013 no nulo de máximo (1.000 réplicas casadas por comprimento; o nulo produz 1 item
  > −4,5 tão frequentemente quanto o observado); BIP39 0; oráculo duro (2 endereços) cru e traduzido: **0**.
- Multi-byte: 22 codecs (CJK, ISO-2022, HZ, UTF-7, UTF-8) × 31 bases → **0 imagens inéditas** além das 7 UTF
  já varridas por `critico_codecs23` (21.427 senhas × 6 = 128.562 decifrações, controle plantado UTF-16LE
  recuperado, 0 duros, padding 0,00403). Ressalva: aquele braço rodou em `--rapido` (sem as 5.040
  permutações de 7 tokens; nulo de 20 lotes) e com oráculo só do endereço A — os 518 paddings dele foram
  re-varridos aqui com os dois endereços.

## 6. Re-varredura com oráculo completo e os DOIS endereços
3.761 plaintexts distintos (2.540 A3_pad + 4 A2_pad + 699 A1_material + 518 MB_pad): 2.903.074 janelas de
32 B × 2 formas × 2 endereços; hex64/WIF/blob aninhado/ebcdic_sig/printable. **0 hits**; máx printable 0,713,
máx ebcdic_sig 0,444 (positivo conhecido = 1,0; ruído calibrado ≤ 0,46).

## Fica de fora
Permutações de 7 tokens do roadmap em UTF-16/32 (prior ínfimo); os 106 k plaintexts AES do corpus amplo com
os dois endereços (coberto pelo retro-scan de 81,9 M de 2026-09-17 para o que já existia então).
Nota: `solver/primos_2026_09_17/quadgram_clean.pkl` é cache gerado pelo `clean_scorer` (não é artefato).
