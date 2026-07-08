---
name: solve-phase
description: Padrão recorrente do puzzle GSMG — concatena as palavras-chave de uma fase, aplica SHA256 e usa o hash como senha para decifrar um blob AES-256-CBC base64 (os que começam com U2FsdGVk...). Use ao resolver/reproduzir qualquer fase que termine num blob openssl.
disable-model-invocation: true
---

# solve-phase

Automatiza o fio condutor de quase toda fase do puzzle (ver [CLAUDE.md](../../../CLAUDE.md)):

1. Palavras-chave dos hints → concatenadas **na ordem certa**, respeitando
   caixa e espaços (o README anota isso como `/(aBa, connected enf)`).
2. `SHA256(concatenação)` → é a **senha**.
3. O blob da próxima etapa é **AES-256-CBC base64** → decifra com essa senha.

## Uso

Salve o blob num arquivo (pode copiar direto do README, mesmo com espaços entre
os caracteres — o script os remove) e rode:

```bash
bash .claude/skills/solve-phase/solve.sh "<partes concatenadas>" blob.txt
```

Exemplo (fase 3):

```bash
bash .claude/skills/solve-phase/solve.sh \
  "causalitySafenetLunaHSM111100x736B...B5KR/1r5B/2R5/... b - - 0 1" phase3.txt
```

O script imprime o SHA256 usado (em stderr) e o texto decifrado (em stdout).

## Calibragem

- **KDF**: os blobs (2019) usam o default do OpenSSL 1.1.x = **sha256**, então o
  script **não** passa `-md`. Verificado end-to-end na fase 3.2. Se um blob sair
  binário, o botão a girar é acrescentar `-md md5` no `solve.sh`.
- Se a senha da fase **não** for `SHA256(...)` e sim um valor direto, passe o
  valor e troque o `sha256sum` do script por um `echo` — casos raros.
