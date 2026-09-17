# Rótulos binários 0/1/remoção e alfabeto Bacon — 15/09/2026

**Nenhuma senha final.** Hipótese: cada um dos nove símbolos de DBBI/FAED recebe um rótulo fixo
(0, 1 ou remoção); a sequência retida, nas duas direções e nas duas ordens de bit, é lida como
ASCII imprimível de 7/8 bits (mais TAB/LF/CR) ou como alfabeto Bacon de 24/26 letras, com cauda
zero opcional menor que uma unidade.

| Item | Valor |
|---|---|
| Mapas de rótulos | 19.683 (3⁹) |
| Decodificações | 629.856 |
| Aceitas pela gramática | 32.474 → 23.350 candidatos distintos |
| Senhas testadas | 92.818 → 556.908 decisões AES (3 blobs × 2 KDF) |
| Paddings válidos | 2.193 (esperado ≈ 2.176) |
| Maior fração imprimível | 0,58 (ruído) |
| Controles | 8 (formatos e homófonos) |

Resultado: nenhuma abertura autenticada e nenhuma chave do prêmio. Artefatos: `summary.json`,
`independent_verification.json`. Este relatório foi escrito em 17/09/2026 a partir do resumo,
porque a rodada original não deixou relatório.
