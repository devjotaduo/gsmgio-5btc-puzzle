# -*- coding: utf-8 -*-
"""Auto-verificacao do harness. Falha ruidosamente se algo quebrar."""
import json, urllib.request
import dsl, oracles as O

def ok(cond, msg):
    print(("[ok] " if cond else "[FALHA] ") + msg)
    assert cond, msg

# 1. DSL reproduz o marco verificado: Bifid CANON periodo-570 -> BTCSEED
r = dsl.execute({"source": "faed",
                 "ops": [{"op": "bifid", "alphabet": dsl.CANON, "period": 570}],
                 "check": {"oracle": "readable"}})
ok(r.get("final_preview", "").startswith("BTCSEED"), f"Bifid->BTCSEED (got {r.get('final_preview','')[:12]!r})")

# 2. source bif_rest existe e tem 563
r2 = dsl.execute({"source": "bif_rest", "ops": [], "check": {"oracle": "readable"}})
ok(len(dsl.bif_full()) == 570 and len(dsl.bif_full()[7:]) == 563, "bif_rest = 563 chars")

# 3. oraculo AES rejeita lixo
ok(O.aes_open("xxx_wrong_xxx") == [], "aes_open rejeita senha errada")

# 4. beco conhecido: senha-direta 'lastwordsbeforearchichoice thispassword' NAO abre
r3 = dsl.execute({"source": "faed", "ops": [],
                  "check": {"oracle": "aes_open"}})  # faed cru como senha
ok(not r3.get("solve"), "faed cru como senha NAO abre (esperado)")

# 5. op invalida vira 'invalid', nao crash nem solve
r4 = dsl.execute({"source": "faed", "ops": [{"op": "inexistente"}], "check": {}})
ok("invalid" in r4 and not r4.get("solve"), "op desconhecida -> invalid")

# 6. as_privkey com sha256 de string aleatoria -> nao solve, nao crash
r5 = dsl.execute({"source": "faed", "ops": [], "check": {"oracle": "as_privkey"}})
ok(not r5.get("solve"), "as_privkey(faed) nao solve")

# 7. as_bip39 nao aceita degenerado como match
r6 = dsl.execute({"source": "bif", "ops": [{"op": "letters_to_nums", "base": 0}],
                  "check": {"oracle": "as_bip39"}})
ok(not r6.get("solve"), "as_bip39 nao da falso solve degenerado")

# 8. Ollama vivo e responde JSON
try:
    req = urllib.request.Request("http://localhost:11434/api/generate",
        data=json.dumps({"model": "llama3:latest", "prompt": "reply with json {\"ok\":true}",
                         "format": "json", "stream": False,
                         "options": {"num_predict": 20}}).encode(),
        headers={"Content-Type": "application/json"})
    resp = json.loads(urllib.request.urlopen(req, timeout=60).read())
    j = json.loads(resp["response"])
    ok(isinstance(j, dict), "Ollama responde JSON valido")
except Exception as e:
    print(f"[aviso] Ollama indisponivel: {e} (o loop enumerativo ainda funciona)")

print("\n=== SELFTEST OK ===")
