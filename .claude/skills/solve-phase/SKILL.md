---
name: solve-phase
description: Padrão recorrente do puzzle GSMG — concatena as palavras-chave de uma fase, aplica SHA256 e usa o hash como senha para decifrar um blob AES-256-CBC base64 (os que começam com U2FsdGVk...). Use ao resolver/reproduzir qualquer fase que termine num blob openssl.
disable-model-invocation: true
---

# solve-phase

Automatiza o fio condutor de quase toda fase do puzzle (ver [AGENTS.md](../../../AGENTS.md),
"Como o puzzle se resolve"):

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

- **KDF**: os blobs autenticados abrem só com EVP-**SHA256** (o default do OpenSSL ≥ 1.1),
  e o script passa `-md sha256` explícito. Verificado end-to-end na fase 3.2.
  `KDF=md5` existe só como controle declarado (AGENTS.md, regra 2).
- **Saída pouco legível não é KDF errado**: o plaintext autêntico da 3.2 tem só 58,9 % de
  ASCII (segmento EBCDIC cp273). Julgue com `G.semantic`/`G.try_password_all` do kit.
- Senha direta, sem SHA256: `RAW=1 bash .claude/skills/solve-phase/solve.sh "<senha>" blob.txt`.
- O Codex não carrega esta skill (fica só em `.claude/skills/`), mas pode rodar o `solve.sh`
  diretamente com os mesmos argumentos.
