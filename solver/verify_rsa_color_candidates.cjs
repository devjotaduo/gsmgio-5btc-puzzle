'use strict';
// Independent suffix DP, BigInt arithmetic, and re-encryption of selected paths.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_color_candidates_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const lines = name => fs.readFileSync(path.join(out, name), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
const permitted = new Set([9, 10, 13, ...Array.from({ length: 95 }, (_, i) => i + 32)]);
function power(a, e, n) {
  let b = BigInt(a), k = BigInt(e), m = BigInt(n), r = 1n;
  while (k) { if (k & 1n) r = r * b % m; b = b * b % m; k >>= 1n; }
  return Number(r);
}
function bytes(n) { let h = n.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex'); }
function inverse(a, n) {
  let [r, s, x, y] = [n, a, 0, 1];
  while (s) { const q = Math.floor(r / s); [r, s] = [s, r - q * s]; [x, y] = [y, x - q * y]; }
  assert.equal(r, 1); return (x % n + n) % n;
}
function graph(source, aliases, n, d, format) {
  const width = String(n - 1).length, edges = Array.from({ length: source.length + 1 }, () => []), cache = new Map();
  for (let end = source.length; end > 0; end--) {
    let tails = [0], factor = 1;
    for (let size = 1; size <= width && end >= size; size++, factor *= 10) {
      const at = end - size, letter = source[at], digits = [letter.charCodeAt(0) - 96], next = [];
      if (aliases.includes(letter)) digits.push(0);
      for (const tail of tails) for (const digit of digits) {
        const c = digit * factor + tail; if (c >= n) continue; next.push(c);
        if (!c || format === 'minimal' && size > 1 && !digit || format === 'padded' && size !== width) continue;
        if (!cache.has(c)) { const m = power(c, d, n), b = bytes(m); cache.set(c, [...b].every(v => permitted.has(v)) ? { m, b } : null); }
        const v = cache.get(c); if (v) edges[at].push({ end, c, ...v });
      }
      tails = next;
    }
  }
  return edges;
}
function formatExists(edges, format, order) {
  const length = edges.length - 1, good = Array.from({ length: length + 1 }, () => new Uint8Array(format.length + 1));
  good[length][format.length] = 1;
  for (let at = length - 1; at >= 0; at--) for (const edge of edges[at]) {
    const b = order === 'BE' ? edge.b : Buffer.from(edge.b).reverse();
    for (let p = format.length - b.length; p >= 0; p--) if (good[edge.end][p + b.length]) {
      let valid = true;
      for (let k = 0; k < b.length; k++) {
        const alphabet = p + k < format.prefix.length ? format.prefix[p + k] : format.alphabet;
        if (!alphabet.includes(String.fromCharCode(b[k]))) { valid = false; break; }
      }
      if (valid) good[at][p] = 1;
    }
  }
  return Boolean(good[0][0]);
}
function fixedCount(edges, size) {
  const length = edges.length - 1, count = Array(length + 1).fill(0n); count[length] = 1n;
  for (let at = length - 1; at >= 0; at--) for (const edge of edges[at]) if (edge.b.length === size || edge.end === length && edge.b.length < size) count[at] += count[edge.end];
  return String(count[0]);
}
function edgeCost(b, strategy) {
  let control = 0, other = 0;
  for (const v of b) { if (v < 32) control++; if (!(v === 32 || v >= 65 && v <= 90 || v >= 97 && v <= 122)) other++; }
  return strategy === 'fewestControls' ? [control, other, b.length] : [other, b.length, control];
}
function less(a, b) { for (let k = 0; k < 3; k++) if (a[k] !== b[k]) return a[k] < b[k]; return false; }
function optimum(edges, strategy, fixed) {
  const length = edges.length - 1, dp = Array(length + 1).fill(null); dp[length] = [0, 0, 0];
  for (let at = length - 1; at >= 0; at--) for (const edge of edges[at]) if (dp[edge.end]) {
    if (fixed && edge.b.length !== fixed && !(edge.end === length && edge.b.length < fixed)) continue;
    const cost = edgeCost(edge.b, strategy).map((v, k) => v + dp[edge.end][k]);
    if (!dp[at] || less(cost, dp[at])) dp[at] = cost;
  }
  return dp[0];
}
function main() {
  const spec = JSON.parse(fs.readFileSync(path.join(out, 'spec.json'))), summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json')));
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw);
  const rowsRaw = fs.readFileSync(path.join(root, '_work/rsa_color_multibyte_2026-09-16/valid.jsonl'));
  const rows = rowsRaw.toString().trim().split(/\r?\n/).map(JSON.parse), models = lines('models.jsonl'), selected = lines('selected.jsonl'), candidates = lines('candidates.jsonl');
  assert.equal(sha(inputRaw), spec.inputSHA256); assert.equal(sha(rowsRaw), spec.validSHA256);
  for (const [f, h] of Object.entries(summary.files)) assert.equal(sha(fs.readFileSync(path.join(out, f))), h);
  for (const [f, h] of Object.entries(spec.sources)) assert.equal(sha(fs.readFileSync(path.join(__dirname, f))), h);
  assert.equal(rows.length, models.length); assert.equal(candidates.length, summary.candidates);
  const seen = new Set(), chosen = new Map();
  for (const row of selected) { if (!chosen.has(row.index)) chosen.set(row.index, []); chosen.get(row.index).push(row); }
  for (const [i, c] of candidates.entries()) { assert.equal(c.id, i); assert(!seen.has(c.hex)); seen.add(c.hex); }
  let decisions = 0, witnesses = 0, reencrypted = 0; const start = Date.now(), fixedTotals = [0, 0, 0];
  for (const [index, r] of rows.entries()) {
    const model = models[index], source = r.reverse ? input[r.field].split('').reverse().join('') : input[r.field];
    assert.equal(model.index, index); assert.equal(model.keyIndex, r.keyIndex); assert.equal(model.modelIndex, r.modelIndex);
    const edges = graph(source, r.aliases, r.n, r.d, r.format), results = [];
    for (const order of ['BE', 'LE']) for (const f of spec.formats) results.push(formatExists(edges, f, order));
    assert.deepEqual(results, model.keyFormats); decisions += results.length;
    assert.deepEqual([1, 2, 3].map(size => fixedCount(edges, size)), model.fixedPaths);
    model.fixedPaths.forEach((v, i) => { if (BigInt(v)) fixedTotals[i]++; });
    assert.equal(candidates[model.witnessId].hex, r.witnessHex);
    const e = inverse(r.d, r.lambda), records = chosen.get(index); assert(records);
    for (const s of records) {
      assert.deepEqual(optimum(edges, s.strategy, s.fixedSize), s.cost);
      let at = 0, actualCost = [0, 0, 0]; const blocks = [];
      for (const block of s.blocks) {
        assert.equal(block.start, at); assert(block.end > at); assert.equal(power(block.m, e, r.n), block.c);
        const b = bytes(block.m); assert([...b].every(v => permitted.has(v)));
        assert(!s.fixedSize || b.length === s.fixedSize || block.end === source.length && b.length < s.fixedSize);
        const word = r.format === 'padded' ? String(block.c).padStart(String(r.n - 1).length, '0') : String(block.c);
        assert.equal(word.length, block.end - at);
        for (let k = 0; k < word.length; k++) assert(word[k] === '0' ? r.aliases.includes(source[at + k]) : +word[k] === source.charCodeAt(at + k) - 96);
        actualCost = actualCost.map((v, i) => v + edgeCost(b, s.strategy)[i]); blocks.push(b); at = block.end; reencrypted++;
      }
      assert.equal(at, source.length); assert.deepEqual(actualCost, s.cost);
      for (const [i, order] of ['BE', 'LE'].entries()) assert.equal(candidates[s.candidates[i]].hex, Buffer.concat(blocks.map(b => order === 'BE' ? b : Buffer.from(b).reverse())).toString('hex'));
      witnesses++;
    }
  }
  assert.deepEqual(fixedTotals, summary.fixedSizeModels); assert.equal(decisions, summary.keyFormatDecisions); assert.equal(witnesses, summary.selectedPaths);
  const result = { complete: true, models: rows.length, keyFormatDecisions: decisions, keyFormatHits: models.reduce((s, r) => s + r.keyFormats.filter(Boolean).length, 0), fixedSizeModels: fixedTotals, selectedWitnesses: witnesses, reencryptedBlocks: reencrypted, candidates: candidates.length, files: summary.files, elapsedMs: Date.now() - start, verifierSHA256: sha(fs.readFileSync(__filename)), method: 'Independent backwards construction of numeric edges, BigInt decryption, suffix key-format DP without bitsets, fixed-size counts and lexicographic minima, then re-encryption of each saved selected block. Parent ASCII campaign separately verifies prior witnesses.' };
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
main();
