# Capitalização dos títulos — 2026-09-16

**Nenhuma senha ou chave final foi encontrada.** Esta rodada testa uma
observação tipográfica limitada; ela não estabelece uma nova instrução do
criador.

As seis cópias HTML examinadas conservam `SalPhaseIon` e `Cosmic Duality`.
No primeiro, as maiúsculas ficam nas posições 1, 4 e 9, contando a partir
de 1: quadrados perfeitos. No segundo, ficam em 1 e 8, contando o espaço:
cubos perfeitos. Os comprimentos exatos são 11 e 14; sem o espaço,
`CosmicDuality` tem 13 caracteres, com maiúsculas em 1 e 7.

A separação natural `Sal / Phase / Ion` e a capitalização das duas palavras
do outro título também explicam esses padrões. Não foi encontrada nas
fontes consultadas uma confirmação de que representem quadrados ou cubos.
Os caminhos e hashes dos seis HTML estão em `spec.json`.

## Teste definido

Foram aplicadas sete máscaras: posições quadradas ou cúbicas, com origem
0 ou 1, e a repetição da capitalização dos três textos acima. Cada máscara
e seu complemento foram usados nas duas direções de DBBI e FAED. As
operações foram zerar, manter ou retirar as posições selecionadas no campo
inteiro, ou zerar somente os `g` selecionados por sua ordem de ocorrência.

Cada resultado foi representado como dígitos decimais, letras `a=1,…,i=9`
com `o=0`, essas letras em maiúsculas e bytes do inteiro decimal completo.
Foram testados os materiais isolados e com cada uma das duas cláusulas
fixas das últimas palavras do Arquiteto, antes ou depois. O teste usa a
senha direta ou seu SHA256 hexadecimal, os três blocos AES e EVP com
SHA256 ou MD5. `spec.json` preserva as cláusulas e todas as escolhas.

- 224 transformações, 3.200 materiais distintos e 6.400 casos de senha.
- 38.400 tentativas AES; 152 paddings, sem texto coerente.
- Maior fração de bytes ASCII imprimíveis: 54,43%.
- Sete controles comparam cada máscara com uma construção explícita.
- O controle conhecido da fase 3.2 é decifrado e seu SHA256 é conferido.

Uma implementação separada em Python reconstruiu todas as transformações
e todos os materiais. Hashlib/PyCryptodome reproduziram integralmente as
decisões AES e os corpos: digest da sequência
`baa2ef57b6e06e37212be45421ad79f14e3cb44701c199423bdc76e1b320b095`.
Também comparou 6.554 escalares derivados de hashes ou materiais de
32 bytes ao ponto público do prêmio e à sua negação, sem correspondência.

## Reprodução e limite

Na raiz do repositório, com uma pasta de saída nova:

```powershell
node solver/title_position_masks.cjs _work/title_mask_reproduction
```

`transforms.json`, `materials.json`, `padding.json`, `summary.json` e
`independent_verification.json` registram os resultados. A verificação
independente foi executada por script inline, sem adicionar arquivo Python.

O negativo cobre somente essa família finita. Não exclui outros usos dos
títulos, outras transformações ou offsets arbitrários. Padding isolado não
autentica senha. SMALL, COSMIC e TAIL32 permanecem sem abertura validada.
