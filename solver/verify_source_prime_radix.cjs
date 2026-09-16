/* Independent verifier: Horner interval reconstruction + rank/count,
 * rather than weighted powers and an ASCII successor. No searcher imports.
 */
'use strict';
const fs = require('node:fs'), path = require('node:path');
const assert = require('node:assert/strict'), crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'source_prime_radix_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function countSevenBit(n) {
  if (n < 0n) return 0n;
  const digits = [];
  do { digits.unshift(Number(n & 255n)); n >>= 8n; } while (n);
  let count = 0n;
  for (let i = 0; i < digits.length; i++) {
    count += BigInt(Math.min(digits[i], 128)) * 128n ** BigInt(digits.length - i - 1);
    if (digits[i] >= 128) return count;
  }
  return count + 1n;
}
function bounds(source, base, alias, prefix) {
  let lo = 0n, hi = 0n, index = 0;
  for (const c of source) {
    const value = BigInt(' abcdefghi'.indexOf(c));
    lo *= BigInt(base); hi *= BigInt(base);
    if (c !== alias) { lo += value; hi += value; continue; }
    if (index < prefix.length) {
      if (prefix[index] === '1') { lo += value; hi += value; }
    } else hi += value;
    index++;
  }
  assert(prefix.length <= index);
  return {lo, hi, ambiguous: index};
}
function main() {
  const read = name => JSON.parse(fs.readFileSync(path.join(out, name)));
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const data = JSON.parse(inputRaw), spec = read('spec.json'), cases = read('cases.json'), summary = read('summary.json');
  assert.equal(sha(inputRaw), spec.inputSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver/source_prime_radix.cjs'))), spec.sourceSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver/zero_decimal_constraints.cjs'))), spec.successorSHA256);
  assert.equal(sha(fs.readFileSync(path.join(out, 'cases.json'))), summary.casesSHA256);
  const sieve = Array(258).fill(true); sieve[0] = sieve[1] = false;
  for (let n = 2; n < sieve.length; n++) if (sieve[n]) for (let j = 2 * n; j < sieve.length; j += n) sieve[j] = false;
  const primes = sieve.flatMap((yes, n) => yes && n >= 11 ? [n] : []);
  assert.deepEqual(spec.bases, primes);
  let brute = 0n;
  for (let n = 0; n < 65536; n++) {
    if ((n & 128) === 0 && (n & 32768) === 0) brute++;
    assert.equal(countSevenBit(BigInt(n)), brute);
  }
  let certificates = 0, nodes = 0;
  const ids = new Set();
  for (const item of cases) {
    assert(item.complete && item.hits.length === 0);
    assert(primes.includes(item.base) && ['dbbi', 'faed'].includes(item.field));
    assert(typeof item.reversed === 'boolean' && /^[a-i]$/.test(item.alias));
    const id = `${item.base}/${item.field}/${item.reversed}/${item.alias}`;
    assert(!ids.has(id)); ids.add(id);
    const source = item.reversed ? [...data[item.field]].reverse().join('') : data[item.field];
    const trie = {}, leafCount = item.rejected.length;
    let covered = 0n;
    for (const cert of item.rejected) {
      assert(/^[01]*$/.test(cert.prefix));
      const {lo, hi, ambiguous} = bounds(source, item.base, item.alias, cert.prefix);
      assert.equal(ambiguous, item.ambiguous);
      assert.equal(lo.toString(16), cert.loHex); assert.equal(hi.toString(16), cert.hiHex);
      assert.equal(countSevenBit(hi) - countSevenBit(lo - 1n), 0n);
      let node = trie;
      for (const bit of cert.prefix) {
        assert(!node.leaf); node = node[bit] ||= {};
      }
      assert.equal(Object.keys(node).length, 0); node.leaf = true;
      covered += 1n << BigInt(ambiguous - cert.prefix.length);
      certificates++;
    }
    assert.equal(covered, 1n << BigInt(item.ambiguous));
    assert.equal(item.nodes, 2 * leafCount - 1);
    nodes += item.nodes;
  }
  assert.equal(ids.size, primes.length * 2 * 2 * 9);
  assert.equal(summary.cases, ids.size); assert.equal(summary.completed, ids.size);
  assert.equal(summary.nodes, nodes); assert.equal(summary.certificates, certificates);
  assert.equal(summary.hits, 0); assert.equal(summary.aesTrials, 0);
  const prefixResults = read('destination127_prefixes.json');
  assert.equal(prefixResults.length, 4);
  const prefixIds = new Set();
  for (const item of prefixResults) {
    assert(['dbbi', 'faed'].includes(item.field) && typeof item.reversed === 'boolean');
    const id = `${item.field}/${item.reversed}`; assert(!prefixIds.has(id)); prefixIds.add(id);
    const source = item.reversed ? [...data[item.field]].reverse().join('') : data[item.field];
    const {lo, hi} = bounds(source, 10, 'g', '');
    assert.equal(lo.toString(), item.decimalMin); assert.equal(hi.toString(), item.decimalMax);
    let width = 1; while (127n ** BigInt(width) <= hi) width++;
    assert(lo >= 127n ** BigInt(width - 1)); assert.equal(item.digitCount, width);
    let used = 0n;
    for (let i = 0; i < item.fixedPrefix.length; i++) {
      const power = 127n ** BigInt(width - i - 1);
      assert.equal(lo / power, hi / power);
      assert.equal(Number(lo / power - used * 127n), item.fixedPrefix[i]);
      used = lo / power;
    }
    const power = 127n ** BigInt(width - item.fixedPrefix.length - 1);
    assert.deepEqual([Number(lo / power - used * 127n), Number(hi / power - used * 127n)], item.firstVariableDigitRange);
    assert.notEqual(item.firstVariableDigitRange[0], item.firstVariableDigitRange[1]);
    assert.deepEqual(item.fixedForbiddenPositions, item.fixedPrefix.flatMap((value, index) =>
      (value >= 32 && value <= 126) || [9, 10, 13].includes(value) ? [] : [{index, value}]));
  }
  const result = {verifiedAt: new Date().toISOString(), cases: ids.size, certificates, nodes,
    countControls: 65536, destinationPrefixProofs: prefixResults.length,
    inputSHA256: sha(inputRaw), verifierSHA256: sha(fs.readFileSync(__filename)),
    casesSHA256: summary.casesSHA256, allMasksCovered: true, independentIntervalCounts: true,
    aesTrials: 0, finalPasswordFound: false};
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
module.exports = {countSevenBit};
