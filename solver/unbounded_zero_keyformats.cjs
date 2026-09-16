'use strict';
// Exact complete-path filters for a32-byte key representation, no guessed substring.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/unbounded_zero_codepoints_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
const standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', url = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const formats = [{ name: 'raw32', length: 32 }, { name: 'base64', length: 44, alphabet: standard, padded: true }, { name: 'base64-unpadded', length: 43, alphabet: standard, padded: false }, { name: 'base64url', length: 44, alphabet: url, padded: true }, { name: 'base64url-unpadded', length: 43, alphabet: url, padded: false }];
function chars(format, position) {
  if (!format.alphabet) return Array.from({ length: 95 }, (_, i) => i + 32);
  if (position === 43) return [61];
  return [...format.alphabet].flatMap((c, i) => position === 42 && i % 4 ? [] : [c.charCodeAt(0)]);
}
function graph(source, mapping) {
  const words = Array.from({ length: 95 }, (_, i) => ({ m: i + 32, digits: [...String(i + 32)].map(Number) }));
  return Array.from({ length: source.length }, (_, at) => words.filter(w => at + w.digits.length <= source.length && w.digits.every((d, i) => !d || d === mapping[source[at + i]])).map(w => ({ m: w.m, end: at + w.digits.length })));
}
function solve(source, mapping, format, enumerate = false, edges = graph(source, mapping)) {
  const dp = Array.from({ length: format.length + 1 }, () => Array(source.length + 1).fill(0n)); dp[format.length][source.length] = 1n;
  const options = Array.from({ length: format.length }, (_, position) => new Set(chars(format, position)));
  for (let position = format.length - 1; position >= 0; position--) for (let at = source.length - 1; at >= 0; at--) for (const w of edges[at]) if (options[position].has(w.m)) dp[position][at] += dp[position + 1][w.end];
  const texts = [];
  if (enumerate && dp[0][0]) {
    assert(dp[0][0] <= 1000000n, 'Candidate enumeration bound reached, not an exclusion'); const bytes = [];
    function visit(at, position) { if (position === format.length) { assert.equal(at, source.length); texts.push(Buffer.from(bytes).toString('hex')); return; } for (const w of edges[at] || []) if (options[position].has(w.m) && dp[position + 1][w.end]) { bytes.push(w.m); visit(w.end, position + 1); bytes.pop(); } }
    visit(0, 0); assert.equal(BigInt(texts.length), dp[0][0]);
  }
  return { count: String(dp[0][0]), texts };
}
function main() {
  const read = f => JSON.parse(fs.readFileSync(path.join(out, f))); assert(read('verification.json').complete);
  const input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), records = read('printable_candidates.json'), source = [...input.dbbi].map(c => c.charCodeAt(0) - 97); let controls = 0;
  for (const format of formats) {
    const scalar = Buffer.alloc(32); scalar[31] = 1;
    let text = format.name === 'raw32' ? '0123456789'.repeat(4).slice(0, 32) : scalar.toString('base64');
    if (format.alphabet === url) text = text.replace(/\+/g, '-').replace(/\//g, '_'); if (format.alphabet && !format.padded) text = text.replace(/=+$/, '');
    const mapping = [4, 6, 1, 7, 9, 3, 2, 5, 8], inverse = new Map(mapping.map((d, i) => [String(d), i])); let zero = 0;
    const encoded = [...Buffer.from(text)].flatMap(m => [...String(m)].map(d => d === '0' ? zero++ % 9 : inverse.get(d)));
    assert(BigInt(solve(encoded, mapping, format).count) > 0n); controls++;
  }
  const result = formats.map(f => ({ format: f.name, decisions: 0, paths: 0n, compatible: 0, examples: [] })), start = Date.now();
  for (const [record, r] of records.entries()) {
    const edges = graph(source, r.mapping);
    for (const [i, format] of formats.entries()) { const q = solve(source, r.mapping, format, false, edges); result[i].decisions++; result[i].paths += BigInt(q.count); if (q.count !== '0') { result[i].compatible++; result[i].examples.push({ record, rank: r.rank, mapping: r.mapping, count: q.count }); } }
    if ((record + 1) % 720 === 0) console.log(JSON.stringify({ records: record + 1, compatible: result.map(r => r.compatible), elapsedMs: Date.now() - start }));
  }
  for (const r of result) r.paths = String(r.paths);
  const report = { complete: true, scope: 'Every printable DBBI mapping under all-nine optional-zero relaxation; entire decoded text as exactly32 printable bytes or canonical standard/URL base64 of32 bytes, padded/unpadded. Includes final unused-bit constraints. ASCII decimal codes for a64-character hex key or51/52-character WIF require at least128/102/104 input digits, exceeding DBBI91; FAED printable grammar already excluded. No hash derivation or binary intermediates covered.', controls, formats, results: result, sourceSHA256: sha(fs.readFileSync(__filename)), printableSHA256: sha(fs.readFileSync(path.join(out, 'printable_candidates.json'))), elapsedMs: Date.now() - start };
  fs.writeFileSync(path.join(out, 'keyformats.json'), JSON.stringify(report, null, 2) + '\n');
}
if (require.main === module) main();
module.exports = { formats, chars, solve, graph };
