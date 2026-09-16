# Primos em faixas convencionais de azul e amarelo

16/09/2026. **Nenhuma senha ou chave final validada.** Testamos uma leitura
física, ainda não confirmada, dos números das cores: comprimentos de onda
inteiros primos, usados como pesos nas somas da matriz inicial.

## Origem e limite da hipótese

Na conversa de 05/03/2021, o criador escreveu “Infrared” (#6250) após
perguntas sobre somar ou fazer XOR das cores. Logo depois escreveu
“No hints” (#6252). Isso não determina uma operação nem confirma que
devamos usar comprimentos de onda. O contexto está preservado em
[hint_context.json](../matrix_hint_2026-09-11/hint_context.json).

Para tornar o teste finito e reproduzível, usamos a convenção de azul
entre 450–495 nm e amarelo entre 570–590 nm, presente na página 2 do
[material Project SPECTRA!, LASP/Universidade do Colorado](https://lasp.colorado.edu/wp-content/uploads/2011/06/Wood_monday_SPECTRA.pdf).
Isso é uma escolha de intervalos para a hipótese, **não uma conversão
dos valores RGB da imagem para comprimentos de onda únicos**.

Os primos nesses intervalos são:

```text
Azul:    457, 461, 463, 467, 479, 487, 491
Amarelo: 571, 577, 587
```

## Construção e resultado

Os 21 pares foram aplicados às células coloridas da matriz original.
As outras células conservaram os bits originais ou receberam zero.
Para cada uma das 42 matrizes, usamos as somas das linhas e das colunas,
nas duas direções: **168 listas**.

Cada lista foi serializada como dígitos concatenados, valores separados
por vírgula, espaço ou quebra de linha, vetor JSON e inteiros de 16 bits
nas duas ordens de bytes. Também foi concatenada, antes ou depois, com
cada uma das duas leituras explícitas de `lastwordsbeforearchichoice`:

```text
reinsertingtheprimebasicsafterwhichyouwillberequiredto
sheisgoingtodieandthereisnothingyoucandotostopit
```

Isso produziu **5.880 materiais distintos** e 11.760 senhas, usando cada
material diretamente ou como SHA256 hexadecimal. As senhas foram testadas
em SMALL, TAIL32 e COSMIC com EVP-SHA256 e EVP-MD5:

- **70.560 decisões AES**, 281 paddings aceitos, sem plaintext autenticado.
  A maior fração imprimível, incluindo TAB/LF/CR, foi 55,70%.
- **5.880 hashes como escalares**, sem correspondência com a pubkey do
  prêmio ou sua negação.
- Nos 281 corpos com padding aceito, mais **264.375 escalares distintos**:
  SHA256 do corpo e todas as janelas de 32 bytes, em ambas as ordens.
  Nenhum corresponde à pubkey-alvo ou à sua negação.

Uma implementação independente com PyCryptodome 3.23.0 e coincurve
21.0.0 reconstruiu todas as matrizes, listas, materiais e senhas. Reproduziu
todas as decisões AES, inclusive rejeições, todos os corpos de plaintext
e os 5.880 pontos derivados das preimagens. A fase 3.2 conhecida e a
conversão da pubkey para o endereço-prêmio serviram como controles.

O resultado limita apenas essas faixas, pesos e construções de senha.
Não exclui frequências, outras unidades, outras operações sobre as listas
ou outra interpretação do comentário do criador.

```powershell
node solver/wavelength_prime_passwords.cjs
```

[Especificação e listas](spec.json), [materiais](materials.json),
[oráculos completos](oracles.json), [resumo](summary.json),
[verificação independente](verification.json),
[verificação das janelas dos plaintexts](padding_scalar_verification.json),
[programa](../../solver/wavelength_prime_passwords.cjs).
