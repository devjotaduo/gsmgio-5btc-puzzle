# Contêiner do áudio Decentraland — 2026-09-16

**Nenhuma senha final encontrada.** A mensagem conhecida do espectrograma é
`HASHTHETEXT`. Esta rodada examinou metadados, limites de frames e regiões
não alocadas ao áudio comprimido; não refez a análise visual do sinal.

## Fonte e reprodução

Arquivo preservado: `../decentraland/puzzlepiece.mp3`, 212.031 bytes,
SHA256 `ef17a96dce37b4dd7cbf79f210c5cbaf37fcae60e5faf8004de4e0832bd0dfee`.
É idêntico a `sounds__puzzlepiece.mp3`. O manifesto `entity.json` associa
`sounds/puzzlepiece.mp3` ao CID `QmeRy5MjmEZ2W6J3DwhQfht5HKBKXBFpoGzSkzmjeGKiDK`.
Não houve nova aquisição da rede nesta rodada.

Na raiz do repositório, com Node e FFmpeg disponíveis no caminho WinGet:

```powershell
node solver/mp3_container_audit.cjs _work/mp3_container_reproduction
```

O destino precisa ser novo. O script preserva o original e produz os
registros completos em `audit.json`, `frames.json`, `unused_main_data.json`
e `ffprobe.json`.

## Resultados

- ID3v2.2.0 ocupa os primeiros 4.096 bytes. Contém somente `TSS` e dois
  `COM`: versão do Logic Pro X, `iTunNORM` e `iTunSMPB`. Seus bytes exatos,
  incluindo NULs e espaços, estão em `audit.json`. Os 3.815 bytes restantes
  do bloco ID3 são zero.
- 199 frames MPEG-1 Layer III seguem sem lacunas até o byte 212.031.
  Não há bytes anexados após o último frame. Todos usam 320 kbps, 44,1 kHz
  e joint stereo. FFprobe confirmou cada posição, tamanho e duração.
- Os bits privados do cabeçalho e de side info são zero em todos os frames,
  assim como copyright, original e emphasis. Mode extension varia entre
  0 e 2; os registros preservam essa variação, sem interpretá-la como texto.
- 179 frames têm um byte de padding e 20 não têm. A sequência inteira
  corresponde à compensação da fração `44/49` do tamanho de frame, com
  fase 43. Esta observação não prova qual algoritmo o codificador utilizou.
- Cada `main_data_begin` é zero. Os quatro comprimentos `part2_3_length`
  de cada frame delimitam suas regiões de áudio. Nos 200.771 bytes de
  payload agregado, os **121.875 bits fora dessas alocações são todos zero**,
  distribuídos em 199 regiões. Isso também explica os zeros no final do MP3:
  eles estão dentro do último frame, não em um arquivo anexado.
- FFmpeg decodificou todos os frames sem erro: 229.248 amostras por canal.
  Os valores de `iTunSMPB` são aritmeticamente consistentes:
  `528 + 2708 + 226012 = 229248`.
- Não aparecem as assinaturas literais `Salted__`, `U2FsdGVk`, ZIP, PNG
  ou PDF no arquivo. Essa busca de assinaturas, isoladamente, não exclui
  conteúdo cifrado ou outra codificação.

Seis controles detectaram trailer acrescentado, frame truncado, padding
ID3 alterado, bits privados alterados nos dois lugares e um bit alterado
em área não alocada. Uma implementação independente em Python, sem
importar o parser JavaScript, conferiu todos os offsets, tamanhos,
comprimentos e backpointers. Uma máscara de alocação por bit confirmou
os 121.875 zeros. Resultado em `independent_verification.json`.

## Limites e referências

O resultado não exclui esteganografia nos coeficientes, paridades ou
transformações do sinal. Tampouco autentica como senha os valores numéricos
dos metadados. Nenhum novo candidato fundamentado para AES foi obtido.
A descrição histórica de Decentraland como completamente “fechada” foi
qualificada: o que se conhece é a mensagem recuperada e os testes realizados.

O formato ID3 foi conferido na implementação primária de
[Mutagen](https://raw.githubusercontent.com/quodlibet/mutagen/main/mutagen/id3/_tags.py).
O layout MPEG e a fórmula de tamanho constam do
[parser MP3 do Mutagen](https://raw.githubusercontent.com/quodlibet/mutagen/main/mutagen/mp3/__init__.py).
A leitura de side info e do reservatório foi conferida no
[minimp3](https://raw.githubusercontent.com/lieff/minimp3/master/minimp3.h),
funções `L3_read_side_info` e `L3_restore_reservoir`. Nenhum código baixado
foi executado.
