# FINDINGS — fluxo_piloto

## Hipótese
Remover o filtro textual dos modos de fluxo altera a triagem e pode expor sinal em janelas interiores de 32 bytes.

## Cobertura executada
- Modos: `aes-256-cfb`, `aes-256-ofb`, `aes-256-ctr`, `chacha20`.
- KDFs: `sha256` e `md5` (EVP_BytesToKey).
- Blobs: `SMALL` e `COSMIC` extraídos do `README.md`.
- Corpus do degrau: 16 tokens base → 48 formas (raw + sha256hex + SHA256HEX).
- Total: 768 decriptações e 1.033.728 checagens raw32 (BE/LE).

## Controles
- Positivo: marcador de 32 bytes plantado em offset interno (17) foi recuperado em 8/8 combinações modo×KDF.
- Nulo casado: 100 embaralhamentos preservando bytes; 9.800 checagens raw32; 0 hits.

## Resultado
- `hex64_candidates`: 0
- `wif_candidates`: 0
- `sample_candidates`: 0
- Nenhum candidato duro neste degrau.

## Limite
Este degrau valida o pipeline técnico e a contabilidade de custo, mas **não** fecha a lacuna grande de cobertura da §4.D.

## Artefatos
- `controls.json`
- `summary.json`
