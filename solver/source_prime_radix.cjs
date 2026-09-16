/* Prime source radix, as distinct from decimal -> prime output radix.
 * Only local, deterministic integer constraints. No language scoring.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {nextAscii} = require('./zero_decimal_constraints.cjs');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'source_prime_radix_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
const inputPath = path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json');
const prime = n => {
  for (let d = 2; d * d <= n; d++) if (n % d === 0) return false;
  return n >= 2;
};
const bases = Array.from({length: 247}, (_, i) => i + 11).filter(prime);
function bytes(n) {
  const h = n.toString(16);
  return Buffer.from(h.length % 2 ? '0' + h : h, 'hex');
}
function solve(source, base, alias, maxNodes = 200000) {
  assert(/^[a-i]+$/.test(source) && 'abcdefghi'.includes(alias));
  assert(Number.isInteger(base) && base > 9);
  let minimum = 0n, power = 1n;
  const weights = [];
  for (let i = source.length - 1; i >= 0; i--) {
    const v = BigInt(source.charCodeAt(i) - 96);
    if (source[i] === alias) weights.push(v * power);
    else minimum += v * power;
    power *= BigInt(base);
  }
  weights.reverse();
  const tail = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) tail[i] = weights[i] + tail[i + 1];
  const rejected = [], hits = [];
  let nodes = 0, complete = true;
  function visit(i, lo, prefix) {
    if (nodes >= maxNodes) { complete = false; return; }
    nodes++;
    const hi = lo + tail[i];
    if (nextAscii(lo, true) > hi) {
      rejected.push({prefix, loHex: lo.toString(16), hiHex: hi.toString(16)});
      return;
    }
    if (i === weights.length) {
      hits.push({prefix, valueHex: lo.toString(16), bytesHex: bytes(lo).toString('hex')});
      return;
    }
    visit(i + 1, lo, prefix + '0');
    if (complete) visit(i + 1, lo + weights[i], prefix + '1');
  }
  visit(0, minimum, '');
  return {ambiguous: weights.length, nodes, complete, rejected, hits};
}
function digits(n, base) {
  const result = [];
  do { result.push(Number(n % BigInt(base))); n /= BigInt(base); } while (n);
  return result.reverse();
}
function destination127(data) {
  const results = [];
  for (const field of ['dbbi', 'faed']) for (const reversed of [false, true]) {
    const source = reversed ? [...data[field]].reverse().join('') : data[field];
    const decimal = [...source].map(c => c.charCodeAt(0) - 96).join('');
    const lo = BigInt(decimal.replaceAll('7', '0')), hi = BigInt(decimal);
    const a = digits(lo, 127), b = digits(hi, 127);
    assert.equal(a.length, b.length);
    let common = 0;
    while (common < a.length && a[common] === b[common]) common++;
    const fixed = a.slice(0, common);
    results.push({field, reversed, decimalMin: lo.toString(), decimalMax: hi.toString(),
      digitCount: a.length, fixedPrefix: fixed,
      firstVariableDigitRange: common < a.length ? [a[common], b[common]] : null,
      fixedForbiddenPositions: fixed.flatMap((value, index) =>
        (value >= 32 && value <= 126) || [9, 10, 13].includes(value) ? [] : [{index, value}])});
  }
  return results;
}
function controls() {
  let bruteCases = 0, plantedCases = 0;
  for (const base of [10, 11, 17, 127, 257]) {
    for (const source of ['a', 'aaa', 'ababab', 'cggcgc', 'dbbibfbh', 'iiiiii']) {
      for (const alias of 'abcgi') {
        const count = [...source].filter(c => c === alias).length, wanted = [];
        for (let mask = 0; mask < 2 ** count; mask++) {
          let n = 0n, index = 0;
          for (const c of source) n = n * BigInt(base) + BigInt(
            c === alias && !(mask & (1 << index++)) ? 0 : c.charCodeAt(0) - 96);
          if ([...bytes(n)].every(b => b < 128)) wanted.push(n.toString(16));
        }
        const got = solve(source, base, alias);
        assert(got.complete);
        assert.deepEqual(got.hits.map(h => h.valueHex).sort(), wanted.sort());
        bruteCases++;
      }
    }
  }
  // Canonical ASCII packed as a decimal integer; replace both 0 and 7 by g.
  // Base ten is a control supported by solve(), not a prime in the real search.
  for (const text of ['matrixsumlist', 'ENTER', 'lastwordsbeforearchichoice']) {
    const n = BigInt('0x' + Buffer.from(text).toString('hex'));
    const source = [...n.toString()].map(c => c === '0' ? 'g' : String.fromCharCode(96 + Number(c))).join('');
    const got = solve(source, 10, 'g');
    assert(got.complete && got.hits.some(h => h.bytesHex === Buffer.from(text).toString('hex')));
    plantedCases++;
  }
  return {bruteCases, plantedCases};
}
function main() {
  fs.mkdirSync(out, {recursive: true});
  const raw = fs.readFileSync(inputPath), data = JSON.parse(raw);
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');
  save('spec.json', {createdAt: new Date().toISOString(), inputSHA256: hash(raw),
    sourceSHA256: hash(fs.readFileSync(__filename)),
    successorSHA256: hash(fs.readFileSync(path.join(__dirname, 'zero_decimal_constraints.cjs'))), bases,
    mapping: 'a..i = 1..9; one alias independently 0 or original digit at each occurrence.',
    hypothesis: 'Read each complete field as an integer in a prime source radix, then convert to minimal base-256 bytes; accept every byte 0..127, including controls.',
    scope: 'Both symbol orders; reversing byte order cannot change 7-bit validity. No digit permutations, multiple zero aliases, offsets, byte stripping or binary payload claims.',
    motivation: 'The page uses a whole-integer base conversion, while a later creator hint mentions primes. The source radix is a distinct hypothesis from a prime destination radix. The bound 257 is our finite search scope, not an instruction by the creator.'});
  const checked = controls(), cases = [];
  for (const base of bases) for (const field of ['dbbi', 'faed']) {
    for (const reversed of [false, true]) for (const alias of 'abcdefghi') {
      const source = reversed ? [...data[field]].reverse().join('') : data[field];
      cases.push({base, field, reversed, alias, ...solve(source, base, alias)});
    }
  }
  save('cases.json', cases);
  save('destination127_prefixes.json', destination127(data));
  const summary = {controls: checked, cases: cases.length, completed: cases.filter(c => c.complete).length,
    nodes: cases.reduce((n, c) => n + c.nodes, 0), certificates: cases.reduce((n, c) => n + c.rejected.length, 0),
    hits: cases.reduce((n, c) => n + c.hits.length, 0), aesTrials: 0,
    casesSHA256: hash(fs.readFileSync(path.join(out, 'cases.json')))};
  save('summary.json', summary);
  console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
module.exports = {solve};
