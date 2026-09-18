# Hex ímpar: zero à esquerda × From Hex do CyberChef — e duas frentes negativas

**Estado: bug real, alcance estreito; negativos.** Resultado de uma continuação independente. O que o
coordenador verificou está marcado como tal; o resto é aceito do relato (os ZIPs dessas três entregas
não estão no checkout).

## 1. O defeito — verificado

`solver/lacunas_2026_09_18/residuo_leituras.py` afirmava implementar o método da página como
`Substitute → To_Base(16) → From_Hex` do CyberChef. Com hex de comprimento ímpar, o código acrescenta um
**zero à esquerda**; o CyberChef lê **pares desde o início** e interpreta o último dígito sozinho.

| hex | zero à esquerda | CyberChef |
|---|---|---|
| `123` | `01 23` | `12 03` |

**Conferido pelo coordenador:**

- no código-fonte atual do CyberChef (`src/core/lib/Hex.mjs`, `fromHex`: `substr(j, byteLen)` com
  `j += 2` desde 0). A entrega diz ter conferido também a versão de 09/07/2019; não refiz essa parte;
- o **kit tem o mesmo padrão**: `G.z_method` (`gsmg_common.py`), e cerca de 40 scripts históricos (`.py`
  e `.cjs`) repetem `if len(h) % 2: h = "0" + h`. A entrega disse não ter verificado se o problema ia
  além de um script; vai;
- os números da entrega, reproduzidos por `solver/lacunas_2026_09_18/hex_paridade.py`: resíduo L84 sem
  zerar → hex de **51** dígitos, `03 17 80…` contra `31 78 07…`; nas 4.096 configurações (L83, L84,
  `dbbi`, `faed` × 2 sentidos × 512 subconjuntos zerados), **1.767** divergem.

Os dois controles do script (`lastwordsbeforearchichoice`, `thispassword`) não viam a diferença porque
têm hex par. As docstrings foram corrigidas (script, irmão `residuo_zerados.py` e kit) **sem mudar o
comportamento**, para que as campanhas históricas continuem reproduzíveis.

## 2. Por que o alcance é estreito — a paridade

O script de verificação demonstra (com asserts) um fato que limita o defeito:

1. **Texto printável sempre gera hex par.** Todo byte printável está em `0x20–0x7E`, então o primeiro
   nibble é ≥ 2 e o inteiro não perde dígito. Nesse caso as duas convenções devolvem **o mesmo** texto.
2. **As 1.767 divergências são exatamente as configurações com hex ímpar** (as 8 restantes de hex ímpar
   são `n = 0`, hex `"0"`, iguais nas duas).
3. **Se o criador codificou bytes crus** que começam com `0x0N`, o hex sai ímpar e **só o zero à
   esquerda** devolve os bytes originais; o CyberChef os embaralha.

Consequência: nas hipóteses em que o criador **codificou** algo (texto ou bytes) pelo método da página,
o zero à esquerda é o inverso correto e **nenhum teste histórico perdeu cobertura**. A leitura CyberChef
só importa se a senha for **definida** como a saída do CyberChef para um decimal que o criador não
obteve de bytes. É uma hipótese legítima dentro da regra 4, mas com prior baixo.

**Corolário útil:** numa hipótese "isto é texto codificado pelo método da página", hex ímpar já
**exclui** a configuração, sob qualquer convenção. Serve de filtro antes de gastar AES.

## 3. A leitura CyberChef testada (aceito do relato)

Nas 1.767 configurações divergentes, as mesmas letras mantidas em a=1…i=9: **3.296** senhas ausentes do
conjunto anterior e da outra frente da mesma rodada, × 3 blobs × 2 KDF = **19.776** AES, **0**
aberturas. Todas as decifrações conferidas byte a byte com o EVP nativo do OpenSSL; as 4.096 conversões
reproduzidas em JavaScript, com 4.368 controles hexadecimais curtos.

## 4. `faed` como 95 cores na matriz (aceito do relato)

`570 = 95 × 6`, e a matriz tem **95** células zero (conferido: 196 − 101). Seis dígitos por célula
formam uma cor RGB; as somas de linhas ou colunas viram material de senha. Diferente da construção
anterior (os 91 símbolos de `dbbi` nos 91 zeros do trecho da URL): aqui entra `faed` e os quatro zeros
centrais. A igualdade de tamanho permite a montagem, não prova intenção, e `a–i` cobre só 9 dos 16
dígitos hex, o que pesa contra "cor" como leitura natural.

720 configurações (agrupamento consecutivo ou por canal, 8 ordens de preenchimento, 3 tratamentos das
células restantes, 10 mapas de letras sem zeragem ou com uma letra zerada) → **109.440** senhas →
**656.640** AES, **0**. Conferência: reconstrução independente das 720 matrizes e 57.600 serializações;
segunda via do EVP numa amostra de 330.

## 5. As saídas dessas duas frentes sem filtro de padding (aceito do relato)

As 676.416 saídas AES (SMALL, TAIL32, COSMIC; SHA256 e MD5) foram regeneradas **sem descartar nada** e
varridas em toda janela de 32 bytes, BE e LE, pubkey comprimida e não comprimida, cada alvo à parte:
**629.066.880** verificações, **0**. O acréscimo real sobre a varredura de plaintexts é de 626.718.736
(626.713.532 nas 673.822 saídas com padding inválido + 5.204 janelas que atravessam o padding removido).
Hashes do corpus regenerado idênticos aos da rodada anterior; 16 chaves plantadas recuperadas; 84 lotes
reconciliados. **Limite declarado:** a auditoria conferiu a cobertura inteira, mas não refez as 629 M
operações de curva numa segunda implementação.

## Totais

| Frente | Senhas | AES | raw32 sem filtro | Resultado |
|---|---|---|---|---|
| Leitura CyberChef (hex ímpar) | 3.296 | 19.776 | 18.391.680 | 0 |
| `faed` como 95 cores | 109.440 | 656.640 | 610.675.200 | 0 |

## O que fica de fora

Outros mapas letra→dígito, zeragem por ocorrência, composições diferentes; o raw32 foi só sobre este
corpus. Nada aqui escolhe entre L83 e L84 nem define `matrixsumlist`.
