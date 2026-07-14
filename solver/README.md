# Solver autônomo GSMG (Llama local + GPU)

Harness que trabalha **incansavelmente** no endgame (SalPhaseIon / Cosmic Duality):
o modelo local **propõe** métodos, a máquina **executa** e **julga** contra
**oráculos duros**. Nada que o modelo "diga" conta como solução — só um oráculo
(endereço BTC batido, checksum BIP39, padding AES válido) pode declarar solve.
Isso torna impossível um falso-solve por alucinação.

## Arquitetura (divisão de trabalho)

```
                    ┌─────────── oráculos DUROS (oracles.py) ───────────┐
                    │  aes_open · check_privkey(addr) · check_mnemonic  │  ← única
                    └────────────────────────────────────────────────────┘     verdade
  llama3 (GPU)  ─┐        ▲                         ▲
  propõe JSON    ├─► runner.py (CPU) ──► DSL ───────┘                 hard-oracle a cada
  + alfabetos    │   enumerativo + feedback de becos                  novo melhor plaintext
                 │                                                     ▲
  GPU genética  ─┘        gpu_search.py (CUDA) ──► criptanálise Bifid ─┘
                          milhares de quadrados/geração
```

- **`oracles.py`** — fontes (dbbi/faed, blobs SMALL/COSMIC) + oráculos duros. Núcleo confiável.
- **`dsl.py`** — interpreta cada hipótese JSON como pipeline executável e determinístico.
- **`scorer.py`** — modelo de quadgramas EN (corpus = `result.json`) p/ sinal de legibilidade.
- **`search.py`** — hill-climb Bifid em CPU (referência).
- **`gpu_search.py`** — **algoritmo genético batelado na GPU** sobre quadrados Bifid.
  O único motor com *gradiente*. Requer `torch`+CUDA.
- **`runner.py`** — loop autônomo: llama3 propõe hipóteses/alfabetos + gerador
  enumerativo temático; oráculos AES/priv/bip39; dedup; `journal.jsonl`; feedback de becos.
- **`launch.py`** — sobe os dois motores juntos e para quando um oráculo fecha.

## Como rodar (incansável)

```bash
cd solver
python selftest.py            # valida o núcleo (reproduz BTCSEED, rejeita lixo)
python gpu_search.py --selftest   # valida o decode Bifid na GPU (GPU==CPU)
python launch.py             # sobe GPU + CPU; roda até SOLVED ou Ctrl-C
python launch.py --status    # heartbeats + candidatos
```

Saídas em `solver/out/` (ignoradas pelo git):
`SOLVED.json` (escrito 1× se um oráculo fechar), `journal.jsonl`, `gpu_candidates.jsonl`
(plaintexts com legibilidade alta p/ revisão humana), `status.json`/`gpu_status.json`.

## O que já se aprendeu com o harness (verificado)

- **Decode Bifid na GPU == CPU** e reproduz `BTCSEED` (marco verificado).
- **Controle**: o GA recupera 100% de um inglês conhecido cifrado em Bifid de
  **período curto** (ex.: 15). Logo o motor é capaz *quando existe solução*.
- **Bifid de período completo (570) é indecifrável por busca de quadrado** — o
  controle só recupera "THE…" e diverge. Portanto o quadrado (CANON) é *derivado
  do dbbi*, não buscável; e o corpo pós-BTCSEED, se for inglês, usaria outro passo.
- A busca sobre **todos os períodos curtos** do faed é o teste rigoroso pendente
  (roda em `gpu_search.py`): se nenhum (quadrado,período) atingir nível de inglês,
  é um negativo forte e *validado pelo controle*.

## Requisitos

Python 3.11+, `pip install pycryptodome ecdsa base58 mnemonic bip-utils numpy`,
`torch` cu128 (RTX 50xx). Ollama com `llama3:latest` (roda 100% na GPU).
Env: `GSMG_MODEL` p/ trocar o modelo (default `llama3:latest`).
