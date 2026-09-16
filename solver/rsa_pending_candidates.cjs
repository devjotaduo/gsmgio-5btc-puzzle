'use strict';
// Exhaust DBBI's360 paths; select declared extrema from enormous FAED path sets.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { book } = require('./rsa_pending_dfa.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_pending_dfa_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
const read = f => JSON.parse(fs.readFileSync(path.join(out, f))), lines = f => fs.readFileSync(path.join(out, f), 'utf8').trim().split('\n').map(JSON.parse);
const alpha = c => c === 32 || c >= 65 && c <= 90 || c >= 97 && c <= 122;
function paths(r, words, source) {
  const edges = Array.from({ length: source.length }, (_, at) => words.filter(w => at + w.word.length <= source.length && [...w.word].every((d, i) => d === '0' ? r.zeroPair.includes(source[at + i]) : +d === r.mapping[source[at + i]])).map(w => ({ ...w, end: at + w.word.length })));
  const dp = Array(source.length + 1).fill(0n); dp[source.length] = 1n;
  for (let at = source.length - 1; at >= 0; at--) for (const edge of edges[at]) dp[at] += dp[edge.end];
  assert.equal(String(dp[0]), r.paths);
  return { edges, dp };
}
function compare(a, b) { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; }
function optimal(edges, dp, objective) {
  const best = Array(dp.length).fill(null), parent = Array(dp.length).fill(null); best[dp.length - 1] = [0, 0, 0];
  for (let at = edges.length - 1; at >= 0; at--) for (const e of edges[at]) if (best[e.end]) {
    const cost = objective === 'controls' ? [+(e.m < 32), +!alpha(e.m), 1] : objective === 'nonletters' ? [+!alpha(e.m), +(e.m < 32), 1] : objective === 'shortest' ? [1, +(e.m < 32), +!alpha(e.m)] : [-1, +(e.m < 32), +!alpha(e.m)];
    const candidate = cost.map((v, i) => v + best[e.end][i]); if (!best[at] || compare(candidate, best[at]) < 0) { best[at] = candidate; parent[at] = e; }
  }
  let at = 0; const bytes = []; while (at < edges.length) { const e = parent[at]; assert(e); bytes.push(e.m); at = e.end; }
  return { hex: Buffer.from(bytes).toString('hex'), cost: best[0], objective };
}
function main() {
  assert(read('verification.json').complete); const spec = read('spec.json'), positive = lines('positive_configurations.jsonl'), input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), candidates = new Map(), records = []; let enumeratedDBBIPaths = 0;
  function add(hex, provenance) { if (!candidates.has(hex)) candidates.set(hex, { id: candidates.size, hex, provenance }); }
  for (const [configuration, r] of positive.entries()) {
    const source = [...(r.reverse ? [...input[r.field]].reverse().join('') : input[r.field])].map(c => c.charCodeAt(0) - 97), words = book(spec.groups[r.group].representative), { edges, dp } = paths(r, words, source);
    add(r.witnessHex, { configuration, method: 'verifierWitness' }); const optima = ['controls', 'nonletters', 'shortest', 'longest'].map(k => optimal(edges, dp, k));
    for (const o of optima) add(o.hex, { configuration, method: o.objective });
    if (r.field === 'dbbi') {
      assert(dp[0] <= 10000n); let count = 0; const bytes = [];
      function visit(at) { if (at === source.length) { add(Buffer.from(bytes).toString('hex'), { configuration, method: 'allDBBIPaths' }); count++; return; } for (const e of edges[at]) if (dp[e.end]) { bytes.push(e.m); visit(e.end); bytes.pop(); } }
      visit(0); assert.equal(BigInt(count), dp[0]); enumeratedDBBIPaths += count;
    }
    records.push({ configuration, field: r.field, reverse: r.reverse, group: r.group, paths: r.paths, optima });
  }
  assert.equal(enumeratedDBBIPaths, 360);
  for (const group of lines('results.jsonl')) for (const row of group.rows) if (row.witness) add(row.witness.witnessHex, { index: row.index, method: 'producerWitness' });
  const result = { complete: true, sourceSHA256: sha(fs.readFileSync(__filename)), positiveConfigurationsSHA256: sha(fs.readFileSync(path.join(out, 'positive_configurations.jsonl'))), scope: 'All360 DBBI paths from three positive configurations. FAED has24 configurations with enormous path counts; save witnesses and lexicographic extrema minimizing controls/nonletters/length or maximizing length. Does not enumerate all FAED passwords.', enumeratedDBBIPaths, configurations: positive.length, candidates: [...candidates.values()], records };
  fs.writeFileSync(path.join(out, 'candidates.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({ candidates: candidates.size, enumeratedDBBIPaths, faedControlMinima: records.filter(r => r.field === 'faed').map(r => r.optima[0].cost[0]), faedLengthMinima: records.filter(r => r.field === 'faed').map(r => r.optima[2].cost[0]) }));
}
if (require.main === module) main();
module.exports = { paths, optimal };
