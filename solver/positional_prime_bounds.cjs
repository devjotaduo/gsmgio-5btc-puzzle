'use strict';
// Necessary length intervals for positional matrix lines in a prime radix.
// Blue/yellow are prime DIGITS, 2 <= p,q < radix; backgrounds each 0 or 1.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/positional_prime_bases_2026-09-16');
const bytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(bytes);
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
const colors = new Map(input.colored.map(([, color, r, c]) => [r + ',' + c, color]));
function lengthAt(base, profile, high) {
  const radix = BigInt(base), digit = high ? radix - 1n : 2n;
  let length = 0;
  for (let line = 0; line < 14; line++) {
    let value = 0n;
    for (let j = 0; j < 14; j++) {
      const index = profile.reversePositions ? 13 - j : j;
      const [r, c] = profile.axis === 'row' ? [line, index] : [index, line];
      const d = colors.has(r + ',' + c) ? digit : BigInt(input.matrix[r][c] ? profile.white : profile.black);
      value += d * radix ** BigInt(13 - j);
    }
    length += value.toString().length;
  }
  return length;
}
function firstTrue(predicate) {
  if (predicate(3)) return 3;
  let low = 3, high = 6;
  while (!predicate(high)) {low = high; high *= 2; assert(Number.isSafeInteger(high));}
  while (high - low > 1) {const mid = Math.floor((low + high) / 2); if (predicate(mid)) high = mid; else low = mid;}
  return high;
}
function prime(n) {if (n < 2) return false; for (let d = 2; d * d <= n; d++) if (n % d === 0) return false; return true;}
function interval(length, profile) {
  const lower = firstTrue(b => lengthAt(b, profile, true) >= length), upper = firstTrue(b => lengthAt(b, profile, false) > length) - 1;
  const primeBases = []; for (let b = lower; b <= upper; b++) if (prime(b)) primeBases.push(b);
  return {lower, upper, primeBases, boundaryLengths: {maxAtLower: lengthAt(lower, profile, true), maxBelowLower: lower > 3 ? lengthAt(lower - 1, profile, true) : null,
    minAtUpper: upper >= 3 ? lengthAt(upper, profile, false) : null, minAboveUpper: lengthAt(upper + 1, profile, false)}};
}
function main() {
  const profiles = [];
  for (const axis of ['row', 'column']) for (const reversePositions of [false, true]) for (const black of [0, 1]) for (const white of [0, 1]) profiles.push({axis, reversePositions, black, white});
  const cases = [];
  for (const field of ['dbbi', 'faed']) for (const profile of profiles) cases.push({field, length: input[field].length, ...profile, ...interval(input[field].length, profile)});
  const residual = [];
  for (const record of cases.filter(c => c.field === 'dbbi' && c.primeBases.length)) {
    // The only surviving radix is 3, so both prime colour digits must be 2.
    assert.deepEqual(record.primeBases, [3]);
    const values = [];
    for (let line = 0; line < 14; line++) {
      let value = 0n;
      for (let j = 0; j < 14; j++) {
        const index = record.reversePositions ? 13 - j : j, [r, c] = record.axis === 'row' ? [line, index] : [index, line];
        value = value * 3n + BigInt(colors.has(r + ',' + c) ? 2 : input.matrix[r][c] ? record.white : record.black);
      }
      values.push(value.toString());
    }
    const digits = new Array(10).fill(0); for (const d of values.join('')) digits[Number(d)]++;
    const maximumLetterCount = digits[0] + Math.max(...digits.slice(1)), observed = [...input.dbbi].filter(c => c === 'b').length;
    assert(maximumLetterCount < observed);
    residual.push({axis: record.axis, reversePositions: record.reversePositions, black: record.black, white: record.white,
      radix: 3, blue: 2, yellow: 2, values, digitHistogram: digits, maximumLetterCountEvenAssigningEveryZero: maximumLetterCount,
      witnessLetter: 'b', observedCount: observed, excluded: true});
  }
  let controls = 0;
  for (const profile of profiles) for (const radix of [3, 5, 11, 101]) {
    const length = lengthAt(radix, profile, false), found = interval(length, profile); assert(found.primeBases.includes(radix)); controls++;
  }
  fs.mkdirSync(out, {recursive: true}); const save = (f, x) => fs.writeFileSync(path.join(out, f), JSON.stringify(x, null, 2) + '\n');
  save('cases.json', cases);
  save('residual_dbbi.json', residual);
  const summary = {sourceSHA256: hash(fs.readFileSync(__filename)), inputSHA256: hash(bytes), casesSHA256: hash(fs.readFileSync(path.join(out, 'cases.json'))), cases: cases.length, controls,
    dbbiExcludedProfiles: cases.filter(c => c.field === 'dbbi' && c.primeBases.length === 0).length,
    dbbiResidualProfilesExcluded: residual.length, dbbiAllProfilesExcluded: cases.filter(c => c.field === 'dbbi').length === 16 && residual.length === 2,
    faedBounds: cases.filter(c => c.field === 'faed').map(({primeBases, ...c}) => ({...c, primeBaseCount: primeBases.length, firstPrime: primeBases[0], lastPrime: primeBases.at(-1)})),
    scope: 'Prime radix and prime digits p,q below radix, fixed binary background weights; minimal decimal concatenation of 14 lines. Length bounds do not solve or exclude FAED, test its prime pairs, or cover unrestricted colour weights.', finalPasswordFound: false};
  save('summary.json', summary); const faedNonempty = summary.faedBounds.filter(c => c.primeBaseCount);
  console.log(JSON.stringify({cases: cases.length, controls, dbbiExcludedByLength: summary.dbbiExcludedProfiles, dbbiExcludedByHistogram: residual.length,
    faedPrimeRange: [Math.min(...faedNonempty.map(c => c.firstPrime)), Math.max(...faedNonempty.map(c => c.lastPrime))]}));
}
if (require.main === module) main();
