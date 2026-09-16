'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), zlib = require('node:zlib'), assert = require('node:assert/strict');
const { vocabulary, successor } = require('./unbounded_integer_words.cjs');
const { wordcase } = require('./unbounded_integer_wordcase.cjs');
const { bytes } = require('./unbounded_zero_integer.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/unbounded_integer_words_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function main() {
  assert(!fs.existsSync(path.join(folder, 'resume_summary.json')), 'Inspect previous resumed search');
  const input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), records = [], allHits = new Map(), limits = { maxNodes: 3000000, maxMs: 30000 };
  for (const name of ['dbbi_forward_full.json.gz', 'faed_reverse_common_wordcase.json.gz']) {
    const original = fs.readFileSync(path.join(folder, name)), old = JSON.parse(zlib.gunzipSync(original)); assert(!old.complete);
    const source = old.reverse ? [...input[old.field]].reverse().join('') : input[old.field], digits = [...source].map(c => c.charCodeAt(0) - 96), weights = digits.map((d, i) => BigInt(d) * 10n ** BigInt(digits.length - i - 1)), tails = Array(digits.length + 1).fill(0n);
    for (let i = digits.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
    let v = vocabulary(old.threshold); if (old.casing === 'wordcase') v = wordcase(v);
    const terminal = [], hits = [...old.hits]; let nodes = 0, excluded = BigInt(old.excluded), pending = 0n; const start = Date.now();
    function visit(low, mask) {
      const count = 1n << BigInt(digits.length - mask.length);
      if (nodes >= limits.maxNodes || Date.now() - start >= limits.maxMs) { terminal.push({ mask, status: 'pending' }); pending += count; return; }
      nodes++;
      if (successor(low, v) > low + tails[mask.length]) { terminal.push({ mask, status: 'excluded' }); excluded += count; return; }
      if (mask.length === digits.length) {
        const value = bytes(low); assert(v.accept(value)); terminal.push({ mask, status: 'hit' }); hits.push({ mask, hex: value.toString('hex'), leadingZeroDigits: mask.indexOf('1') }); return;
      }
      visit(low, mask + '0'); visit(low + weights[mask.length], mask + '1');
    }
    for (const row of old.terminal) {
      if (row.status !== 'pending') { terminal.push(row); continue; }
      let low = 0n; for (let i = 0; i < row.mask.length; i++) if (row.mask[i] === '1') low += weights[i];
      visit(low, row.mask);
    }
    assert.equal(excluded + pending + BigInt(hits.length), 1n << BigInt(source.length));
    const file = name.replace('.json.gz', '_resumed.json.gz'), result = { ...old, complete: pending === 0n, nodes: old.nodes + nodes, excluded: String(excluded), pending: String(pending), terminal, hits, elapsedMs: old.elapsedMs + Date.now() - start, resumedNodes: nodes, parentFile: name, parentSHA256: sha(original), limits, resumeSourceSHA256: sha(fs.readFileSync(__filename)) };
    fs.writeFileSync(path.join(folder, file), zlib.gzipSync(JSON.stringify(result)));
    for (const hit of hits) if (!allHits.has(hit.hex)) allHits.set(hit.hex, { id: allHits.size, ...hit, provenance: file });
    const row = { ...result, file, terminal: terminal.length, hits: hits.length, maxBytes: Math.max(0, ...hits.map(h => h.hex.length / 2)), artifactSHA256: sha(fs.readFileSync(path.join(folder, file))) }; records.push(row); console.log(JSON.stringify(row));
  }
  fs.writeFileSync(path.join(folder, 'resume_candidates.json'), JSON.stringify([...allHits.values()], null, 2) + '\n');
  fs.writeFileSync(path.join(folder, 'resume_summary.json'), JSON.stringify({ cases: records, complete: records.every(r => r.complete) }, null, 2) + '\n');
}
if (require.main === module) main();
