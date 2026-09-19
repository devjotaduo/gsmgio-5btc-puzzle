# FINDINGS — fluxo_piloto

## Hipótese
Remover o filtro textual dos modos de fluxo permite recuperar chave/candidato em janelas interiores raw32.

## Controles exigidos
- Positivo: chave sintética plantada em plaintext de modo de fluxo deve ser detectada pelo oráculo.
- Nulo: 100 embaralhamentos preservando bytes devem produzir zero hits.

## Estado
A implementar neste checkout com script reproduzível e artefatos `controls.json`/`summary.json`.

## Próxima pergunta
Qual implementação mínima reaproveita a tabela de cifras/KDF e elimina dependências locais ausentes?
