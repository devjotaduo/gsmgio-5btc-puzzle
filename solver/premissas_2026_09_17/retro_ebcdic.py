# Critico: aplica a assinatura EBCDIC (agente 5) + nested_blob + printable>=0.85 a TODO plain_hex
# gravado pelos agentes 1, 2, 3 e 4. Zero e resultado valido.
import sys, json, glob, os, collections
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G
HIGH_AZ = {bytes([ord(c)]).decode("cp273").encode("latin-1")[0] for c in "abcdefghijklmnopqrstuvwxyz"}
HIGH_AZ = {v for v in HIGH_AZ if v >= 0x80}; assert len(HIGH_AZ) == 17
def sig(p):
    h = [x for x in p if x >= 0x80]
    return 0.0 if len(h) < 6 else sum(x in HIGH_AZ for x in h) / len(h)
# controle: plaintext real da 3.2 -> 1.0
import base64
from Crypto.Cipher import AES; from Crypto.Hash import SHA256
raw = base64.b64decode(G.PHASE32_B64); k, iv = G.evp(b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c", raw[8:16], SHA256)
assert sig(G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(raw[16:]))) == 1.0
groups = {
 "A1_premissa_cifra": glob.glob("premissa_cifra/survivors_*.jsonl"),
 "A2_kfile": ["kfile_first_line/soft_hits.jsonl", "kfile_first_line/soft_hits_lines.jsonl"],
 "A3_infrared": glob.glob("infrared/paddings*.jsonl"),
 "A4_unicode": ["unicode_yinyang/unicode_yinyang.jsonl"],
 "A5_f4": ["forense_bytes/f4_passwords.jsonl"],
}
for g, files in groups.items():
    n = 0; best = (0.0, None); nsem = 0; nnest = 0; nhigh = 0; hist = collections.Counter(); bad = 0
    for f in files:
        for line in open(f, encoding="utf-8"):
            try: d = json.loads(line)
            except Exception: bad += 1; continue
            hx = d.get("plain_hex") or d.get("hex") or (d.get("soft") or {}).get("hex")
            if not hx: continue
            p = bytes.fromhex(hx); n += 1
            s = sig(p); hist[round(s, 1)] += 1
            if s > best[0]: best = (s, {k: (v if not isinstance(v, str) or len(v) < 80 else v[:80]) for k, v in d.items() if k not in ("plain_hex", "hex", "head", "soft")}, hx[:64])
            if s >= 0.75: nhigh += 1
            if G.nested_blob(p): nnest += 1
            if G.printable(p) >= 0.85: nsem += 1
    print(f"{g}: plaintexts={n} json_ruim={bad} sig>=0.75={nhigh} nested={nnest} printable>=0.85={nsem} sig_max={best[0]:.3f}")
    print("   hist", sorted(hist.items()))
    print("   best", best[1], best[2] if len(best) > 2 else "")
