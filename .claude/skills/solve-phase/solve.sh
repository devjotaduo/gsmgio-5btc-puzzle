#!/usr/bin/env bash
# solve.sh — padrão recorrente do puzzle GSMG:
#   SHA256(partes concatenadas) vira a senha de um blob AES-256-CBC base64.
# Uso: bash solve.sh "<partes concatenadas>" <arquivo-do-blob>
set -euo pipefail

parts="${1:?informe as partes concatenadas da senha (entre aspas)}"
blob="${2:?informe o arquivo com o blob base64}"

hash=$(printf '%s' "$parts" | sha256sum | cut -d' ' -f1)
echo "SHA256 = $hash" >&2

# tr -d: remove espaços/quebras que o README insere entre os caracteres do blob.
# fold -w 64: re-quebra em linhas de 64 — o base64 numa linha só estoura o buffer
#   de linha do OpenSSL ("error reading input file"). Verificado na fase 3.2.
# KDF: os blobs (2019) usam o default do OpenSSL 1.1.x = sha256, então NÃO force
#   -md. Se um blob não abrir (saída binária), tente acrescentar -md md5.
tr -d '[:space:]' < "$blob" | fold -w 64 \
  | openssl enc -aes-256-cbc -d -a -pass "pass:$hash"
