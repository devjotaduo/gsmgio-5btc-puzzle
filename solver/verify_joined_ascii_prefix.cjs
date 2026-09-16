'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/joined_fields_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex'), read = name => JSON.parse(fs.readFileSync(path.join(out, name), 'utf8'));
function count(n) {
  if (n < 0n) return 0n;
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const bytes = Buffer.from(hex, 'hex'); let total = 0n;
  for (let i = 0; i < bytes.length; i++) {
    total += BigInt(Math.min(bytes[i], 128)) * 128n ** BigInt(bytes.length - 1 - i);
    if (bytes[i] >= 128) return total;
  }
  return total + 1n;
}
function main() {
  const spec = read('ascii_prefix_spec.json'), summary = read('ascii_prefix_summary.json'), cases = read('ascii_prefix_cases.json');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), data = JSON.parse(raw);
  assert.equal(sha(raw), spec.inputSHA256); assert.equal(sha(fs.readFileSync(path.join(root, 'solver/joined_ascii_prefix.cjs'))), spec.sourceSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver/zero_decimal_constraints.cjs'))), spec.helperSHA256);
  assert.equal(sha(fs.readFileSync(path.join(out, 'ascii_prefix_cases.json'))), summary.casesSHA256);
  let expected = 0n;
  for (let n = 0; n < 65536; n++) {if ((n & 0x8080) === 0) expected++; assert.equal(count(BigInt(n)), expected);}
  for (let width = 1; width <= 300; width++) assert.equal(count(256n ** BigInt(width) - 1n), 128n ** BigInt(width));
  const options = [];
  for (let mask = 1; mask < 512; mask++) {const s = [...'abcdefghi'].filter((_, i) => mask & (1 << i)).join(''); if (s.length <= 2) options.push(s);}
  assert.deepEqual(options.sort(), [...spec.aliases].sort());
  const seen = new Set(); let certificates = 0, nodes = 0;
  for (const r of cases) {
    assert(['dbbi', 'faed'].includes(r.first)); assert(typeof r.reverse === 'boolean'); assert(options.includes(r.alias));
    const id = [r.first, r.reverse, r.alias].join('/'); assert(!seen.has(id)); seen.add(id);
    const symbols = r.reverse ? [...data[r.first]].reverse() : [...data[r.first]];
    const second = r.first === 'dbbi' ? 'faed' : 'dbbi'; assert.equal(r.tailLength, data[second].length);
    const ambiguous = symbols.filter(c => r.alias.includes(c)).length; assert.equal(ambiguous, r.ambiguous);
    function endpoint(mask, high) {
      let position = 0;
      const digits = symbols.map(c => {
        if (!r.alias.includes(c)) return c.charCodeAt(0) - 96;
        const full = position < mask.length ? mask[position] === '1' : high; position++;
        return full ? c.charCodeAt(0) - 96 : 0;
      }).join('');
      return BigInt(digits + (high ? '9' : '0').repeat(r.tailLength));
    }
    let coverage = 0n;
    for (const mask of r.certificates) {
      assert.match(mask, /^[01]*$/); assert(mask.length <= ambiguous);
      const lo = endpoint(mask, false), hi = endpoint(mask, true); assert.equal(count(hi) - count(lo - 1n), 0n);
      coverage += 1n << BigInt(ambiguous - mask.length); certificates++;
    }
    const sorted = [...r.certificates].sort(); for (let i = 1; i < sorted.length; i++) assert(!sorted[i].startsWith(sorted[i - 1]));
    assert.deepEqual(r.frontiers, []); assert.equal(coverage, 1n << BigInt(ambiguous)); assert.equal(r.nodes, 2 * r.certificates.length - 1); nodes += r.nodes;
  }
  assert.equal(seen.size, 180); assert.equal(certificates, summary.certificates); assert.equal(nodes, summary.nodes);
  assert.equal(summary.frontiers, 0); assert.equal(summary.coveredOriginalJoinedModels, 32400);
  const result = {verifiedAt: new Date().toISOString(), verifierSHA256: sha(fs.readFileSync(__filename)),
    casesSHA256: summary.casesSHA256, prefixTrees: cases.length, nodes, certificates, controls: {smallIntegers: 65536, fullWidths: 300},
    allIntervalsCountedIndependently: true, allFirstFieldMasksCovered: true, anyNumericSecondFieldCovered: true,
    coveredOriginalJoinedModels: 32400, finalPasswordFound: false};
  fs.writeFileSync(path.join(out, 'ascii_prefix_verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
