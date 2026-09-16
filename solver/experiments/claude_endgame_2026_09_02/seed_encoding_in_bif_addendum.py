# -*- coding: utf-8 -*-
"""Adendo: (1) variante I->J em base-26 (AZ26); (2) maior run de prefixos-4 BIP39 válidos
consecutivos por texto/offset (se fosse mnemonic abreviada, TODOS seriam válidos)."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seed_encoding_in_bif as S, gsmg_common as G
S.STATS.clear()
hard = []
for name, text in S.TEXTS.items():
    tj = text.replace("I", "J")
    S.ORDERS = {"AZ26": S.AZ26}
    hard += S.base_windows(tj, name + "/I->J")
    S.ORDERS = {"CANON": G.CANON, "AZ25": S.AZ25, "AZ26": S.AZ26}
runs = {}
for name, text in S.TEXTS.items():
    best = 0
    for o in range(4):
        cur = 0
        for j in range(o, len(text) - 3, 4):
            cur = cur + 1 if text[j:j+4] in S.PREF4 else 0
            best = max(best, cur)
    frac = sum(text[j:j+4] in S.PREF4 for j in range(0, len(text)-3)) / (len(text)-3)
    runs[name] = {"max_run_valid_pref4": best, "frac_valid_pref4_any_offset": round(frac, 4)}
out = {"event": "addendum", "IJ_base26_tests": dict(S.STATS), "hard": hard, "pref4_runs": runs}
G.jsonl(S.LOG, out); print(json.dumps(out, indent=1))
