# FINDINGS — cobertura

## Fato observado
A tabela de premissas em `ENDGAME.md` marca a lacuna de modos de fluxo no ramo de `raw32` interior.

## Inferência
Antes de nova varredura ampla, é obrigatório fixar domínio, partição e custo com checkpoint e hashes para evitar recontagem e sobreposição.

## Limite
Sem corpus histórico completo presente nesta cópia, cobertura total não pode ser declarada neste momento.

## Próximo teste
Executar um degrau com corpus mínimo reproduzível e controle de plantio para validar pipeline técnico.
