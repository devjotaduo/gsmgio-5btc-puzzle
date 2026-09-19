# Campanha `fluxo_raw32_2026-09-19` — relatório parcial

## Objetivo
Atacar a lacuna aberta em `ENDGAME.md` §4.D (modos de fluxo e raw32 interior), iniciando por um degrau reproduzível com controles completos.

## Execução desta rodada
- Contrato da campanha em `spec.json`.
- Frentes iniciais em `ideacao/`, `cobertura/` e `fluxo_piloto/`.
- Script reproduzível: `solver/fluxo_raw32_2026_09_19/fluxo_piloto.py`.

## Resultado do degrau (`fluxo_piloto`)
- 48 formas testadas (16 tokens × 3 formas).
- 768 decriptações de fluxo (4 modos × 2 KDF × 2 blobs).
- 1.033.728 janelas raw32 (BE/LE).
- 0 candidatos hex64/WIF.
- Controle positivo passou (8/8); nulo casado (100) com 0 hits.

## Limites
- Cobertura parcial por desenho: degrau técnico, não campanha exaustiva.
- Oráculo duro de privkey não foi exercido neste degrau; saída é validação de pipeline/custo.

## Decisão
Negativo parcial válido. A campanha permanece aberta para ampliar cobertura com partição explícita e checkpoint reproduzível.
