# -*- coding: utf-8 -*-
"""
Interpretador de HIPOTESES. Uma hipotese e um JSON:
  {
    "id": "...",
    "source": "faed" | "dbbi" | "faed_no_prefix" | "bif" | "bif_rest",
    "ops": [ {op-name + params}, ... ],   # pipeline de transformacoes
    "check": {"oracle": "aes_open|as_privkey|as_bip39|readable", ...}
  }
O executor e DEFENSIVO: op desconhecida ou tipo errado -> DSLError (o runner
registra como 'invalid', nunca como solve). So os oraculos de oracles.py julgam.

Valor interno = ("text", str)  OU  ("nums", list[int]).
"""
import hashlib
import oracles as O

class DSLError(Exception):
    pass

A2I = {c: i + 1 for i, c in enumerate("abcdefghi")}          # a=1..i=9
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CANON = "DBIFHCEGAKLMNOPQRSTUVWXYZ"   # quadrado que produz BTCSEED (verificado)

# ---------- Bifid ----------
def _bifid(text, alphabet, period, mode="decrypt"):
    if len(alphabet) != 25 or len(set(alphabet)) != 25:
        raise DSLError("alfabeto Bifid precisa de 25 letras unicas")
    pos = {c: (i // 5, i % 5) for i, c in enumerate(alphabet)}
    up = text.upper().replace("J", "I")
    for c in up:
        if c not in pos:
            raise DSLError(f"letra {c!r} fora do alfabeto Bifid")
    period = period or len(up)
    if period < 1:
        raise DSLError("period<1")
    out = []
    for off in range(0, len(up), period):
        blk = up[off:off + period]
        if mode == "decrypt":
            seq = []
            for c in blk:
                r, co = pos[c]; seq += [r, co]
            n = len(blk); rows, cols = seq[:n], seq[n:]
            out.append("".join(alphabet[rows[i] * 5 + cols[i]] for i in range(n)))
        else:  # encrypt
            rows = []; cols = []
            for c in blk:
                r, co = pos[c]; rows.append(r); cols.append(co)
            seq = rows + cols
            out.append("".join(alphabet[seq[2 * i] * 5 + seq[2 * i + 1]] for i in range(len(blk))))
    return "".join(out)

@O.functools.lru_cache(maxsize=8)
def bif_full():
    return _bifid(O.sources()["faed"], CANON, len(O.sources()["faed"]), "decrypt")

# ---------- fontes ----------
def get_source(name):
    if name in ("faed", "dbbi", "faed_no_prefix"):
        return ("text", O.sources()[name].upper())
    if name == "bif":
        return ("text", bif_full())
    if name == "bif_rest":
        return ("text", bif_full()[7:])
    raise DSLError(f"source desconhecida: {name}")

# ---------- ops ----------
def _need(kind, val, op):
    if val[0] != kind:
        raise DSLError(f"op {op!r} exige {kind}, recebeu {val[0]}")
    return val[1]

def _key_to_nums(key, mod):
    """Aceita lista de ints, ou string a-i (1-9) ou A-Z (1-26)."""
    if isinstance(key, list):
        return [int(k) % mod for k in key]
    if isinstance(key, str):
        s = key.lower()
        if set(s) <= set("abcdefghi"):
            return [A2I[c] % mod for c in s]
        return [(ord(c) - 96) % mod for c in s if c.isalpha()]
    raise DSLError("key invalida")

def apply_op(val, op):
    name = op.get("op")
    if name == "to_digits":
        t = _need("text", val, name).lower()
        mp = dict(A2I);
        if op.get("o_is_zero"): mp["o"] = 0
        return ("nums", [mp.get(c, 0) for c in t])
    if name == "letters_to_nums":
        t = _need("text", val, name).upper()
        base = op.get("base", 0)
        return ("nums", [(AZ.index(c) + base) for c in t if c in AZ])
    if name == "nums_to_letters":
        ns = _need("nums", val, name)
        alpha = op.get("alphabet", AZ)
        return ("text", "".join(alpha[n % len(alpha)] for n in ns))
    if name == "digits_to_faed":  # 1..9 -> a..i
        ns = _need("nums", val, name)
        return ("text", "".join("abcdefghi"[((n - 1) % 9)] for n in ns))
    if name in ("keystream", "vigenere", "beaufort"):
        ns = _need("nums", val, name)
        mod = op.get("mod", 9)
        key = _key_to_nums(op["key"], mod)
        offset = op.get("offset", 0)
        oper = op.get("dir", "sub")
        out = []
        for i, x in enumerate(ns):
            k = key[(i + offset) % len(key)]
            if name == "beaufort":
                v = (k - x) % mod
            elif oper == "add":
                v = (x + k) % mod
            else:
                v = (x - k) % mod
            out.append(v if v != 0 else mod)
        return ("nums", out)
    if name == "bifid":
        t = _need("text", val, name)
        return ("text", _bifid(t, op.get("alphabet", CANON), op.get("period"),
                               op.get("mode", "decrypt")))
    if name == "columnar":
        t = _need("text", val, name)
        key = op["key"] if isinstance(op["key"], list) else _key_to_nums(op["key"], 999)
        order = sorted(range(len(key)), key=lambda i: (key[i], i))
        ncol = len(key)
        rows = [t[i:i + ncol] for i in range(0, len(t), ncol)]
        if op.get("mode", "dec") == "enc":
            out = "".join(r[c] for c in order for r in rows if c < len(r))
        else:
            out = "".join(r[c] for c in order for r in rows if c < len(r))
        return ("text", out)
    if name == "substitute":
        t = _need("text", val, name)
        frm, to = op["from"], op["to"]
        if len(frm) != len(to):
            raise DSLError("substitute: from/to tamanhos diferentes")
        table = str.maketrans(frm, to)
        return ("text", t.translate(table))
    if name == "reverse":
        k, d = val
        return (k, d[::-1])
    if name == "slice":
        k, d = val
        return (k, d[op.get("start", 0):op.get("end")])
    if name == "base_convert":
        ns = _need("nums", val, name)
        fb, tb = op.get("from_base", 10), op.get("to_base", 16)
        digs = "".join(str(n) for n in ns)
        num = int(digs, fb) if fb != 10 else int(digs)
        h = format(num, "x") if tb == 16 else format(num, "o")
        if len(h) % 2: h = "0" + h
        try:
            return ("text", bytes.fromhex(h).decode("latin-1"))
        except Exception as e:
            raise DSLError(f"base_convert: {e}")
    raise DSLError(f"op desconhecida: {name!r}")

# ---------- checagem (oraculos) ----------
def _as_text(val):
    if val[0] == "text":
        return val[1]
    return "".join(str(n) for n in val[1])

def run_check(val, check, scorer=None):
    oracle = check.get("oracle", "readable")
    if oracle == "aes_open":
        s = _as_text(val)
        forms = {s, s.lower(), s.upper(),
                 hashlib.sha256(s.encode()).hexdigest(),
                 hashlib.sha256(s.lower().encode()).hexdigest()}
        hits = []
        for f in forms:
            hits += O.aes_open(f)
        return {"solve": bool(hits), "oracle": oracle, "hits": hits}
    if oracle == "as_privkey":
        s = _as_text(val)
        cands = [hashlib.sha256(s.encode()).digest(),
                 hashlib.sha256(s.lower().encode()).digest()]
        # base26 do texto (se A-Z)
        up = "".join(c for c in s.upper() if c in AZ)
        if up:
            num = 0
            for c in up: num = num * 26 + AZ.index(c)
            bs = num.to_bytes((num.bit_length() + 7) // 8 or 1, "big")
            cands += [bs[:32].rjust(32, b"\x00"), bs[-32:].rjust(32, b"\x00")]
        # hex direto se aplicavel
        hx = "".join(c for c in s.lower() if c in "0123456789abcdef")
        if len(hx) >= 64:
            cands.append(bytes.fromhex(hx[:64]))
        for c in cands:
            r = O.check_privkey(c)
            if r:
                return {"solve": True, "oracle": oracle, "hit": r}
        return {"solve": False, "oracle": oracle}
    if oracle == "as_bip39":
        # nums -> palavras (mod 2048); ou texto A1Z26
        if val[0] == "nums":
            nums = val[1]
        else:
            nums = [AZ.index(c) for c in val[1].upper() if c in AZ]
        best = None
        for n in (24, 21, 18, 15, 12):
            if len(nums) >= n:
                words = [O.WORDLIST[i % 2048] for i in nums[:n]]
                r = O.check_mnemonic(words)
                if r and r.get("match"):
                    return {"solve": True, "oracle": oracle, "hit": r}
                if r and r.get("valid") and not r.get("degenerate"):
                    best = r
        return {"solve": False, "oracle": oracle, "candidate": best}
    if oracle == "readable":
        if scorer is None:
            return {"solve": False, "oracle": oracle, "score": None}
        t = "".join(c for c in _as_text(val).upper() if c in AZ)
        sc = scorer(t)
        return {"solve": False, "oracle": oracle, "score": round(sc, 3),
                "text": _as_text(val)[:120]}
    raise DSLError(f"oraculo desconhecido: {oracle!r}")

def execute(hyp, scorer=None):
    """Executa uma hipotese. Retorna dict resultado. Nunca levanta p/ o runner:
    erros viram {'invalid': msg}."""
    try:
        val = get_source(hyp["source"])
        for op in hyp.get("ops", []):
            val = apply_op(val, op)
        res = run_check(val, hyp.get("check", {"oracle": "readable"}), scorer)
        res["final_preview"] = _as_text(val)[:80]
        return res
    except DSLError as e:
        return {"invalid": str(e)}
    except (KeyError, TypeError, ValueError, IndexError) as e:
        return {"invalid": f"{type(e).__name__}: {e}"}
