# Frequências inteiras primas como pesos das cores

16/09/2026. **Nenhuma senha ou chave final validada.** Esta rodada testa
frequências em THz, complementando o teste de comprimentos de onda em nm.

Usamos as mesmas faixas convencionais, azul 450–495 nm e amarelo 570–590 nm,
da página 2 do [Project SPECTRA!, LASP](https://lasp.colorado.edu/wp-content/uploads/2011/06/Wood_monday_SPECTRA.pdf).
A relação no vácuo é `f[THz] = 299792458 / (1000 × λ[nm])`, usando a
[velocidade da luz exata definida no SI](https://www.bipm.org/en/si-base-units/metre).
Limites inteiros foram calculados com aritmética exata, incluindo a inversão
dos extremos do intervalo. Não se trata de uma conversão dos pixels RGB
para frequências físicas únicas. O comentário “Infrared” do criador
também não confirma esta operação; ver o
[contexto preservado](../matrix_hint_2026-09-11/hint_context.json).

```text
Azul, inteiros 606..666 THz:    607 613 617 619 631 641 643 647 653 659 661
Amarelo, inteiros 509..525 THz: 509 521 523
```

Os 33 pares de primos geraram 66 matrizes, mantendo os bits originais nas
células sem cor ou zerando essas células. Somas de linhas e colunas, nas
duas direções, produziram **264 listas**. Cada lista teve sete formatos:
dígitos concatenados, separação por vírgula, espaço ou LF, vetor JSON e
inteiros de 16 bits big-endian/little-endian. Foram usados isoladamente e
antes/depois de cada uma destas duas leituras da fala do Arquiteto:

```text
reinsertingtheprimebasicsafterwhichyouwillberequiredto
sheisgoingtodieandthereisnothingyoucandotostopit
```

Os **9.240 materiais distintos** geraram 18.480 senhas, diretamente e como
SHA256 hexadecimal. SMALL, TAIL32 e COSMIC foram testados com EVP-SHA256
e EVP-MD5: **110.880 decisões AES**, 439 paddings aceitos, nenhum plaintext
autenticado. A maior proporção imprimível, incluindo TAB/LF/CR, foi 54,43%.

Os 9.240 hashes como escalares não atingiram a pubkey do prêmio nem sua
negação. Nos 439 corpos com padding aceito, SHA256 e todas as janelas de
32 bytes em ambas as ordens produziram mais **399.509 escalares distintos**,
também sem correspondência.

Uma implementação independente em Python regenerou os limites usando
frações exatas, todas as listas, materiais e senhas. PyCryptodome 3.23.0
reproduziu todas as decisões AES, inclusive rejeições e corpos completos;
coincurve 21.0.0 reproduziu os pontos. A fase 3.2 conhecida e a derivação
do endereço-prêmio a partir da pubkey serviram de controles.

Foi ainda verificada a hipótese condicional de DBBI representar um hash
hexadecimal por substituição: entre as 72 leituras com dois prefixos e
dois sentidos, somente a leitura original com prefixos `b,g` gera 64
tokens de 16 tipos. Seus padrões direto e invertido foram comparados
aos SHA256 dos **15.120 materiais** desta rodada e da rodada de comprimentos
de onda, sem sobreposição entre conjuntos. Foram **30.240 comparações e
zero correspondências**. Isso não prova que DBBI seja um hash.

O negativo limita essas faixas, unidades, serializações e combinações;
outras operações sobre a matriz e os campos continuam abertas.

```powershell
node solver/frequency_prime_passwords.cjs
```

[Especificação e listas](spec.json), [materiais](materials.json),
[oráculos](oracles.json), [resumo](summary.json),
[verificação independente](verification.json),
[escalares dos corpos](padding_scalar_verification.json),
[comparação dos padrões](digest_pattern_verification.json),
[programa](../../solver/frequency_prime_passwords.cjs).

SHA256 do programa: `2c20682e2767cc06ab0583a8b1cf941f1b880eedc9f941acfcb5c194500003a1`.
SHA256 dos materiais: `0b3f02eff87c45d2fb6c9d93952d6bca56e3ff6303c7adc5dfa29fdffd9eea5d`.
SHA256 dos oráculos: `fb7e84b4c78cc6b6b3d4775885ecd95729e4702883cdebc5a0b1d64a144c705f`.
