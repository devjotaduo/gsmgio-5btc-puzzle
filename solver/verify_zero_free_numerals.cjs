'use strict';
// Independent boundary DP, chunked arithmetic, and five-symbol ternary packing.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
const digest = b => crypto.createHash('sha256').update(b).digest();

function canSegment(source, mapping, allowed) {
  let boundaries = 1, digits = 0;
  for (let i = 0; i < source.length; i++) {
    digits = (digits * 10 + mapping[source[i]]) % 1000;
    const okay = (boundaries & 1) && allowed[digits % 10] || (boundaries & 2) && i >= 1 && allowed[digits % 100] || (boundaries & 4) && i >= 2 && allowed[digits];
    boundaries = ((boundaries << 1) & 7) | Number(Boolean(okay));
    if (!boundaries) return false;
  }
  return Boolean(boundaries & 1);
}
function radixBytes(source, mapping) {
  let n = 0n;
  for (let i = 0; i < source.length; i += 16) {
    const length = Math.min(16, source.length - i); let chunk = 0;
    for (let j = 0; j < length; j++) chunk = chunk * 9 + mapping[source[i + j]];
    assert(Number.isSafeInteger(chunk)); n = n * (9n ** BigInt(length)) + BigInt(chunk);
  }
  let h = n.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex');
}
function adjacent(source, mapping) {
  assert.equal(source.length % 5, 0);
  for (let i = 0; i < source.length; i += 5) {
    let n = 0; for (let j = 0; j < 5; j++) n = n * 9 + mapping[source[i + j]] - 1;
    if (Math.floor(n / 243) >= 128 || n % 243 >= 128) return false;
  }
  return true;
}
function halves(source, mapping) {
  assert.equal(source.length % 5, 0);
  for (let i = 0; i < source.length; i += 5) {
    let high = 0, low = 0;
    for (let j = 0; j < 5; j++) { const v = mapping[source[i + j]] - 1; high = 3 * high + Math.floor(v / 3); low = 3 * low + v % 3; }
    if (high >= 128 || low >= 128) return false;
  }
  return true;
}
function nextPermutation(a) {
  let i = a.length - 2; while (i >= 0 && a[i] >= a[i + 1]) i--; if (i < 0) return false;
  let j = a.length - 1; while (a[j] <= a[i]) j--; [a[i], a[j]] = [a[j], a[i]];
  for (let l = i + 1, r = a.length - 1; l < r; l++, r--) [a[l], a[r]] = [a[r], a[l]]; return true;
}
function main() {
  const dir = path.resolve(process.argv[2] || path.join(root, '_work/zero_free_numerals_2026-09-17'));
  const read = name => JSON.parse(fs.readFileSync(path.join(dir, name))), spec = read('run1/spec.json'), result = read('run1/summary.json');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')); assert.equal(sha(inputRaw), spec.inputSHA256); const data = JSON.parse(inputRaw);
  const fields = spec.fields.map(f => [...(f.reverse ? [...data[f.field]].reverse().join('') : data[f.field])].map(c => c.charCodeAt(0) - 97));
  const lookup = spec.models.map(m => { const a = new Uint8Array(1000); for (const c of m.codes) { assert.equal(c.word, String(c.value).replaceAll('0', '')); assert(c.word.length > 0 && c.word.length <= 3); a[Number(c.word)] = 1; } return a; });
  const flags = fs.readFileSync(path.join(dir, 'run1/flags.bin')), radix = fs.readFileSync(path.join(dir, 'run1/radix_flags.bin')), ternary = fs.readFileSync(path.join(dir, 'ternary/flags.bin'));
  assert.equal(sha(flags), result.flagsSHA256); assert.equal(sha(radix), result.radixFlagsSHA256); assert.equal(sha(ternary), read('ternary/summary.json').flagsSHA256);
  // Cross-check the original permutation enumeration by membership, uniqueness and full lexicographic coverage.
  const ranks = new Map(); require('./zero_free_numerals.cjs').eachPermutation((m, rank) => { assert.equal(new Set(m).size, 9); assert(m.every(d => d >= 1 && d <= 9)); const key = m.join(''); assert(!ranks.has(key)); ranks.set(key, rank); });
  assert.equal(ranks.size, 362880);
  const mapping = [1,2,3,4,5,6,7,8,9], counts = Array(24).fill(0); let n = 0, radixChecks = 0, ternaryChecks = 0;
  const started = Date.now();
  do {
    const rank = ranks.get(mapping.join('')); assert.notEqual(rank, undefined);
    for (let m = 0; m < lookup.length; m++) for (let f = 0; f < fields.length; f++) {
      const okay = Number(canSegment(fields[f], mapping, lookup[m])); assert.equal(okay, flags[rank * 24 + m * 4 + f]); counts[m * 4 + f] += okay;
    }
    for (let f = 0; f < fields.length; f++) {
      const b = radixBytes(fields[f], mapping); let checksum = false;
      if (b.length === 36) for (const c of [b, Buffer.from(b).reverse()]) if (digest(digest(c.subarray(0,32))).subarray(0,4).equals(c.subarray(32))) checksum = true;
      assert.equal(Number(b.every(v => v < 128)) | 2 * Number(checksum), radix[rank * 4 + f]); radixChecks++;
    }
    const cases = [adjacent(fields[2], mapping), halves(fields[2], mapping), adjacent(fields[3], mapping), halves(fields[3], mapping)];
    cases.forEach((v, i) => { assert.equal(Number(v), ternary[rank * 4 + i]); ternaryChecks++; });
    n++; if (n % 100000 === 0) console.log(JSON.stringify({permutations: n, elapsedMs: Date.now() - started}));
  } while (nextPermutation(mapping));
  assert.equal(n, 362880); assert.deepEqual(counts, result.omittedZero.map(r => r.compatible));
  const report = {createdAt: new Date().toISOString(), sourceSHA256: sha(fs.readFileSync(__filename)), permutations: n,
    independentBoundaryDPDecisions: n * 24, independentChunkedRadixDecisions: radixChecks, independentFiveSymbolTernaryDecisions: ternaryChecks,
    everyDecisionMatched: true, counts, elapsedMs: Date.now() - started,
    limit: 'Verifies feasibility and arithmetic, not an exhaustive search of ambiguous plaintext paths or arbitrary binary payloads.'};
  fs.writeFileSync(path.join(dir, 'independent_numerals.json'), JSON.stringify(report, null, 2) + '\n', {flag: 'wx'}); console.log(JSON.stringify(report, null, 2));
}
if (require.main === module) main();
module.exports = {canSegment, radixBytes, adjacent, halves, nextPermutation};
