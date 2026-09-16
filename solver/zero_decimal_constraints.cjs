/* Exhaustive g -> {0,7} search under an explicit ASCII constraint.
 * Run: node solver/zero_decimal_constraints.cjs
 * Only Node built-ins; no network, wallet access, or external writes.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const ROOT = path.resolve(__dirname, '..');
const ALLOWED = [9, 10, 13, ...Array.from({length: 95}, (_, i) => i + 32)];
const ALLOWED_SET = new Set(ALLOWED);

function toBytes(n) {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  return Buffer.from(h, 'hex');
}

// Smallest integer >= n whose minimal big-endian bytes are ASCII or TAB/LF/CR.
function nextAscii(n, sevenBit = false) {
  const bytes = Array.from(toBytes(n));
  for (let i = 0; i < bytes.length; i++) {
    if (sevenBit ? bytes[i] < 128 : ALLOWED_SET.has(bytes[i])) continue;
    let j = i;
    while (j >= 0) {
      const next = sevenBit ? (bytes[j] < 127 ? bytes[j] + 1 : undefined)
        : ALLOWED.find(x => x > bytes[j]);
      if (next !== undefined) {
        bytes[j] = next;
        bytes.fill(sevenBit ? 0 : ALLOWED[0], j + 1);
        return BigInt('0x' + Buffer.from(bytes).toString('hex'));
      }
      j--;
    }
    const larger = Buffer.alloc(bytes.length + 1, sevenBit ? 0 : ALLOWED[0]);
    if (sevenBit) larger[0] = 1;
    return BigInt('0x' + larger.toString('hex'));
  }
  return n;
}

function solve(pattern, maxNodes = 2000000, sevenBit = false) {
  assert.match(pattern, /^[0-9?]+$/);
  const base = BigInt(pattern.replaceAll('?', '0'));
  const weights = [];
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === '?') weights.push(7n * 10n ** BigInt(pattern.length - i - 1));
  }
  const remaining = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) remaining[i] = remaining[i + 1] + weights[i];
  let nodes = 0, pruned = 0, complete = true;
  const hits = [];
  function visit(i, lo) {
    if (nodes >= maxNodes) { complete = false; return; }
    nodes++;
    if (nextAscii(lo, sevenBit) > lo + remaining[i]) { pruned++; return; }
    if (i === weights.length) { hits.push(toBytes(lo).toString('ascii')); return; }
    visit(i + 1, lo);
    if (complete) visit(i + 1, lo + weights[i]);
  }
  visit(0, base);
  return {ambiguous: weights.length, assignments: (1n << BigInt(weights.length)).toString(),
    minHexPrefix: toBytes(base).subarray(0, 8).toString('hex'),
    maxHexPrefix: toBytes(base + remaining[0]).subarray(0, 8).toString('hex'),
    nodes, pruned, complete, hits};
}

function selftest() {
  // Check the lexicographic successor independently against brute force.
  for (let n = 0n; n < 32000n; n += 997n) {
    let expected = n;
    while (!Array.from(toBytes(expected)).every(b => ALLOWED_SET.has(b))) expected++;
    assert.equal(nextAscii(n), expected);
  }
  assert.equal(nextAscii(0x7f7fn), 0x090909n);
  assert.equal(nextAscii(0xffffn), 0x090909n);
  for (const sevenBit of [false, true]) {
    for (const pattern of ['?2?', '1???', '?7?3?', '??????', '00?99?']) {
      const expected = [], count = (pattern.match(/\?/g) || []).length;
      for (let mask = 0; mask < 2 ** count; mask++) {
        let i = 0;
        const value = BigInt(pattern.replaceAll('?', () => ((mask >> i++) & 1) ? '7' : '0'));
        const bytes = toBytes(value);
        if (Array.from(bytes).every(b => sevenBit ? b < 128 : ALLOWED_SET.has(b))) expected.push(bytes.toString('ascii'));
      }
      const actual = solve(pattern, 2000000, sevenBit);
      assert(actual.complete);
      assert.deepEqual(actual.hits.sort(), expected.sort());
    }
  }
  assert.equal(nextAscii(0x7f80n, true), 0x010000n);
  assert.equal(nextAscii(0x110080n, true), 0x110100n);
  const planted = 'lastwordsbeforearchichoicethispassword'.repeat(3);
  const decimal = BigInt('0x' + Buffer.from(planted).toString('hex')).toString();
  const result = solve(decimal.replace(/[07]/g, '?'));
  assert(result.complete);
  assert(result.hits.includes(planted));
  return {successor: true, bruteForceAgreement: true, planted: result};
}

function main() {
  const controls = selftest();
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const line = readme.split(/\r?\n/).find(l => l.startsWith('> d b b i'));
  assert(line, 'Missing source line');
  const source = line.slice(2).replace(/[ *]/g, '');
  const dbbi = source.slice(0, 91), faed = source.slice(195, 765);
  assert.equal(dbbi.length, 91); assert.equal(faed.length, 570);
  assert.match(dbbi, /^[a-i]+$/); assert.match(faed, /^faed[a-i]+$/);
  const variants = {dbbi, dbbi_without_prefix: dbbi.slice(4), faed,
    faed_without_prefix: faed.slice(4), faed_half1: faed.slice(0, 285),
    faed_half2: faed.slice(285), faed_even: [...faed].filter((_, i) => i % 2 === 0).join(''),
    faed_odd: [...faed].filter((_, i) => i % 2 === 1).join('')};
  const results = {};
  for (const [name, value] of Object.entries(variants)) {
    for (const reverse of [false, true]) {
      const symbols = reverse ? [...value].reverse().join('') : value;
      const pattern = [...symbols].map(c => c === 'g' ? '?' : String(c.charCodeAt(0) - 96)).join('');
      results[name + (reverse ? '_reversed' : '')] = {
        printable: solve(pattern), sevenBit: solve(pattern, 2000000, true)};
    }
  }
  const report = {hypothesis: 'g independently means decimal 0 or 7; all other symbols use a1z26; whole integer to minimal big-endian bytes',
    acceptedBytes: 'printable: 32..126 plus TAB, LF, CR; sevenBit: every byte 0..127; minimal big-endian, no stripping',
    sourcesSha256: {dbbi: crypto.createHash('sha256').update(dbbi).digest('hex'),
      faed: crypto.createHash('sha256').update(faed).digest('hex')}, controls, results};
  const dir = path.join(ROOT, '_work', 'session_2026-09-11');
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'zero_decimal_constraints.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
}

if (require.main === module) main();
module.exports = {nextAscii, solve};
