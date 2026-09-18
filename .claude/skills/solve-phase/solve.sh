#!/usr/bin/env bash
# solve.sh — padrão recorrente do puzzle GSMG:
#   SHA256(partes concatenadas) vira a senha de um blob AES-256-CBC base64.
# Uso: bash solve.sh "<partes concatenadas>" <arquivo-do-blob>
# Variáveis: KDF=sha256 (padrão; AGENTS.md regra 2) ou KDF=md5 só como controle declarado;
#            RAW=1 usa as partes como senha direta, sem SHA256.
set -euo pipefail

parts="${1:?informe as partes concatenadas da senha (entre aspas)}"
blob="${2:?informe o arquivo com o blob base64}"
kdf="${KDF:-sha256}"

if [ "${RAW:-0}" = 1 ]; then
  pass="$parts"
else
  pass=$(printf '%s' "$parts" | sha256sum | cut -d' ' -f1)
  echo "SHA256 = $pass" >&2
fi
echo "KDF = $kdf" >&2

# tr -d: remove espaços/quebras que o README insere entre os caracteres do blob.
# fold -w 64: re-quebra em linhas de 64 — o base64 numa linha só estoura o buffer
#   de linha do OpenSSL ("error reading input file"). Verificado na fase 3.2.
# -md explícito: os blobs autenticados (fases 2, 3, 3.2) só abrem com EVP-SHA256.
#   Saída pouco legível NÃO indica KDF errado: o plaintext autêntico da 3.2 tem só
#   58,9 % de ASCII (segmento EBCDIC cp273). Julgue com o oráculo do kit, não a olho.
tr -d '[:space:]' < "$blob" | fold -w 64 \
  | openssl enc -aes-256-cbc -d -a -md "$kdf" -pass "pass:$pass"
