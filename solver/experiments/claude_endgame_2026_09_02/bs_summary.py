import json, collections
r = json.load(open("blob_structure_result.json"))
print(r["summary"]); print("hard:", len(r["hard"]))
soft = r["soft"]
c = collections.Counter((s["kind"], s["blob"], s["mode"]) for s in soft)
for k, v in sorted(c.items(), key=lambda kv: -kv[1])[:15]: print(v, k)
top = sorted(soft, key=lambda s: -s["printable"])[:8]
for s in top: print(s["printable"], s["kind"], s["blob"], s["mode"], s["kdf"][-6:], s["extra"], repr(s["pw"][:40]), repr(s["head"][:40]))
