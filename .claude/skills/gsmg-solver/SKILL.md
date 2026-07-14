---
name: gsmg-solver
description: Controla o solver autônomo do endgame GSMG (solver/) — o modelo local llama3 propõe métodos e a GPU roda criptanálise Bifid batelada, tudo julgado por oráculos duros (endereço BTC / BIP39 / padding AES). Use para iniciar, monitorar ou parar a busca "incansável", ou revisar candidatos.
disable-model-invocation: true
---

# gsmg-solver

Harness que trabalha continuamente no endgame (ver [solver/README.md](../../../solver/README.md)).
Divisão de trabalho à prova de alucinação: **llama3 (na GPU) propõe** hipóteses e
alfabetos; o **gerador enumerativo + GA na GPU** varrem o espaço; **só um oráculo
duro declara solve** (`solver/oracles.py`).

## Antes de tudo — validar o núcleo
```bash
cd solver
python selftest.py              # reproduz BTCSEED, rejeita lixo, becos falham
python gpu_search.py --selftest # decode Bifid GPU == CPU
```

## Rodar incansável
```bash
cd solver
python launch.py                # sobe GPU (gpu_search) + CPU (runner+llama3)
python launch.py --only gpu     # só a criptanálise Bifid na GPU
python launch.py --only cpu     # só o runner com llama3 + oráculos AES/priv/bip39
```
Para: `Ctrl-C`. O modelo é configurável por `GSMG_MODEL` (default `llama3:latest`).

## Monitorar
```bash
cd solver && python launch.py --status
```
Mostra os heartbeats (`out/status.json`, `out/gpu_status.json`) e conta os
candidatos de legibilidade. Se um oráculo fechar, existe **`out/SOLVED.json`**
com a evidência (senha/chave + endereço batido) — esse é o único sinal de vitória.

## Revisar candidatos (trabalho humano)
`out/gpu_candidates.jsonl` e `out/candidates.jsonl` guardam plaintexts com
legibilidade acima do limiar — leia-os para faro humano; NÃO são solves.

## Estender
- Novos oráculos: adicione em `oracles.py` (devem retornar evidência verificável).
- Novas operações de cifra: adicione em `dsl.py` (`apply_op`) — o runner passa a
  usá-las automaticamente; o gerador enumerativo e o llama3 as combinam.
- Requisitos: `torch` cu128 (RTX 50xx) + `pip install pycryptodome ecdsa base58 mnemonic bip-utils numpy`.
