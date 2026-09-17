'use strict';
// Independent verification: rebuild geometry, solve a length-class CSP, then
// reject decimal suffixes by direct modular arithmetic (no carry search).
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const reverse = text => [...text].reverse().join('');

function rebuild(input) {
  const colors = new Map(input.colored.map(([, color, row, col]) => [`${row},${col}`, color]));
  assert.equal(colors.size, 24);
  const profiles = [];
  for (const axis of ['difference', 'sum', 'wrapped-difference', 'wrapped-sum']) {
    for (const zeroWeight of [0, 1]) for (const oneWeight of [0, 1]) {
      const sums = Array.from({length: axis.startsWith('wrapped') ? 14 : 27}, () => [0, 0, 0]);
      for (let row = 0; row < 14; row++) for (let col = 0; col < 14; col++) {
        const index = axis === 'difference' ? row - col + 13 : axis === 'sum' ? row + col :
          axis === 'wrapped-difference' ? (row - col + 14) % 14 : (row + col) % 14;
        const color = colors.get(`${row},${col}`);
        if (color) sums[index][color === 'B' ? 0 : 1]++;
        else sums[index][2] += input.matrix[row][col] ? oneWeight : zeroWeight;
      }
      profiles.push({id: profiles.length, axis, zeroWeight, oneWeight, sums});
    }
  }
  return profiles;
}

function blank() { return {byLetter: Array(9).fill(-1), byDigit: Array(10).fill(-1), zero: new Set()}; }
function copy(state) { return {byLetter: [...state.byLetter], byDigit: [...state.byDigit], zero: new Set(state.zero)}; }
function accept(state, letter, digit) {
  const c = letter.charCodeAt(0) - 97;
  if (digit === 0) {state.zero.add(c); return state.zero.size <= 2;}
  if (state.byLetter[c] !== -1 && state.byLetter[c] !== digit) return false;
  if (state.byDigit[digit] !== -1 && state.byDigit[digit] !== c) return false;
  state.byLetter[c] = digit; state.byDigit[digit] = c;
  return true;
}
function constantBindings(sums, parts) {
  const state = blank();
  for (let i = 0; i < sums.length; i++) {
    if (sums[i][0] || sums[i][1]) continue;
    const decimal = String(sums[i][2]);
    if (decimal.length !== parts[i].length) return null;
    for (let k = 0; k < decimal.length; k++) if (!accept(state, parts[i][k], +decimal[k])) return null;
  }
  return state;
}

// Nonnegative x=p-2,y=q-2 imply Fi<=10^d Fj if every coefficient
// satisfies that bound. Compute d from ratios, not a fixed digit loop.
function lengthBound(left, right) {
  const a = [left[0], left[1], 2 * left[0] + 2 * left[1] + left[2]];
  const b = [right[0], right[1], 2 * right[0] + 2 * right[1] + right[2]];
  if (a.some((value, i) => value > 0 && b[i] === 0)) return Infinity;
  let d = 0;
  const ratio = Math.max(1, ...a.map((value, i) => b[i] ? value / b[i] : 0));
  while (10 ** d < ratio) d++;
  return d;
}

function enumerateLengths(sums, size, callback, cap = 3000000, partial = null) {
  const groups = [], lookup = new Map(), order = [];
  for (const sum of sums) {
    const key = sum.join(',');
    if (!lookup.has(key)) {lookup.set(key, groups.length); groups.push({sum, count: 0});}
    const id = lookup.get(key); groups[id].count++; order.push(id);
  }
  const bounds = groups.map(a => groups.map(b => lengthBound(a.sum, b.sum)));
  const first = groups.map(({sum: [a, b, c]}) => [String(2 * a + 2 * b + c).length, a || b ? size : String(c).length]);
  let nodes = 0, vectors = 0, stopped = false;
  function propagate(domains) {
    let changed = true;
    while (changed) {
      changed = false;
      for (let i = 0; i < groups.length; i++) for (let j = 0; j < groups.length; j++) {
        const upper = Math.min(domains[i][1], domains[j][1] + bounds[i][j]);
        const lower = Math.max(domains[i][0], domains[j][0] - bounds[j][i]);
        if (lower > upper) return false;
        if (lower !== domains[i][0] || upper !== domains[i][1]) {domains[i] = [lower, upper]; changed = true;}
      }
      const min = domains.reduce((n, d, i) => n + d[0] * groups[i].count, 0);
      const max = domains.reduce((n, d, i) => n + d[1] * groups[i].count, 0);
      if (min > size || max < size) return false;
      for (let i = 0; i < groups.length; i++) {
        const count = groups[i].count, [oldLo, oldHi] = domains[i];
        const lower = Math.max(oldLo, Math.ceil((size - (max - oldHi * count)) / count));
        const upper = Math.min(oldHi, Math.floor((size - (min - oldLo * count)) / count));
        if (lower > upper) return false;
        if (lower !== oldLo || upper !== oldHi) {domains[i] = [lower, upper]; changed = true;}
      }
    }
    return true;
  }
  function visit(domains) {
    assert(++nodes <= cap, 'Independent CSP node cap reached; no proof may be claimed');
    if (!propagate(domains)) return;
    if (partial && !partial(order.map(i => domains[i]))) return;
    let selected = -1;
    for (let i = 0; i < groups.length; i++) {
      const w = domains[i][1] - domains[i][0];
      if (w) {selected = i; break;}
    }
    if (selected === -1) {
      vectors++;
      if (callback(order.map(i => domains[i][0])) === false) stopped = true;
      return;
    }
    for (let length = domains[selected][0]; length <= domains[selected][1]; length++) {
      const next = domains.map(d => [...d]); next[selected] = [length, length];
      visit(next); if (stopped) return;
    }
  }
  visit(first);
  return {nodes, vectors, complete: !stopped, classes: groups.length};
}

function partition(text, lengths) {
  let pos = 0;
  const parts = lengths.map(length => {const value = text.slice(pos, pos + length); pos += length; return value;});
  assert.equal(pos, text.length);
  return parts;
}
function suffixAccepts(sums, parts, initial, p, q, width) {
  const state = copy(initial);
  for (let i = 0; i < sums.length; i++) {
    const amount = sums[i][0] * p + sums[i][1] * q + sums[i][2];
    const suffix = String(amount % 10 ** width).padStart(width, '0');
    const length = parts[i].length;
    for (let k = 0; k < width; k++) {
      const digit = +suffix[width - 1 - k];
      if (k >= length) {if (digit !== 0) return false; continue;}
      if (digit === 0 && k === length - 1 && length > 1) return false;
      if (!accept(state, parts[i][length - 1 - k], digit)) return false;
    }
  }
  return true;
}

function fixedConstantsPruner(text, sums) {
  return domains => {
    const state = blank();
    let prefixLo = 0, prefixHi = 0;
    const suffixLo = domains.reduce((n, d) => n + d[0], 0);
    const suffixHi = domains.reduce((n, d) => n + d[1], 0);
    for (let i = 0; i < sums.length; i++) {
      const [a, b, c] = sums[i], [lo, hi] = domains[i];
      if (!a && !b) {
        let offset = null;
        if (prefixLo === prefixHi) offset = prefixLo;
        // A fixed suffix determines the offset even when its prefix is free.
        else if (suffixLo - prefixLo - lo === suffixHi - prefixHi - hi) offset = text.length - (suffixLo - prefixLo);
        if (offset !== null) {
          const decimal = String(c);
          for (let k = 0; k < decimal.length; k++) if (!accept(state, text[offset + k], +decimal[k])) return false;
        }
      }
      prefixLo += lo; prefixHi += hi;
    }
    return true;
  };
}

function verifyCase(text, sums) {
  let partitions = 0, mod10Survivors = 0, mod100Survivors = 0;
  const lengthDigest = crypto.createHash('sha256');
  const csp = enumerateLengths(sums, text.length, lengths => {
    const parts = partition(text, lengths), initial = constantBindings(sums, parts);
    if (!initial) return;
    partitions++;
    lengthDigest.update(JSON.stringify(lengths) + '\n');
    for (let p = 0; p < 10; p++) for (let q = 0; q < 10; q++) {
      if (!suffixAccepts(sums, parts, initial, p, q, 1)) continue;
      mod10Survivors++;
      for (let pu = 0; pu < 10; pu++) for (let qu = 0; qu < 10; qu++) {
        if (suffixAccepts(sums, parts, initial, p + 10 * pu, q + 10 * qu, 2)) mod100Survivors++;
      }
    }
  }, 3000000, fixedConstantsPruner(text, sums));
  return {...csp, partitions, mod10Survivors, mod100Survivors, lengthOrderSHA256: lengthDigest.digest('hex')};
}

function controls(profiles) {
  let planted = 0;
  for (const profile of profiles) for (const [p, q] of [[2n, 3n], [47n, 113n], [1000003n, 1000033n]]) {
    const decimals = profile.sums.map(([a, b, c]) => String(BigInt(a) * p + BigInt(b) * q + BigInt(c)));
    let zero = 0;
    const text = decimals.join('').replace(/\d/g, digit => digit === '0' ? 'be'[zero++ % 2] : 'ihgfedcba'[+digit - 1]);
    const target = decimals.map(d => d.length).join(',');
    let recovered = false;
    enumerateLengths(profile.sums, text.length, lengths => {
      if (lengths.join(',') !== target) return;
      const parts = partition(text, lengths), bindings = constantBindings(profile.sums, parts);
      assert(bindings);
      assert(suffixAccepts(profile.sums, parts, bindings, Number(p % 100n), Number(q % 100n), 2));
      const exact = blank();
      for (let i = 0; i < decimals.length; i++) for (let k = 0; k < decimals[i].length; k++) assert(accept(exact, parts[i][k], +decimals[i][k]));
      recovered = true;
      return false;
    }, 3000000, fixedConstantsPruner(text, profile.sums));
    assert(recovered); planted++;
  }
  assert.throws(() => enumerateLengths([[1, 0, 0], [0, 1, 0]], 9, () => {}, 1), /node cap/);
  const s = blank();
  assert(accept(s, 'a', 1)); assert(!accept(s, 'b', 1)); assert(!accept(s, 'a', 2));
  assert(accept(s, 'a', 0)); assert(accept(s, 'b', 0)); assert(!accept(s, 'c', 0));
  return {planted, exactDigitBindings: true, nodeCapThrows: true, aliasAndBijectionChecks: true};
}

function main() {
  const dir = path.resolve(process.argv[2] || path.join(root, '_work/diagonal_sum_inverse_2026-09-17'));
  const bytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const input = JSON.parse(bytes), profiles = rebuild(input);
  const spec = JSON.parse(fs.readFileSync(path.join(dir, 'spec.json')));
  const expected = fs.readFileSync(path.join(dir, 'cases.jsonl'));
  const cases = expected.toString().trim().split('\n').map(JSON.parse);
  assert.equal(hash(bytes), spec.inputSHA256); assert.deepEqual(profiles, spec.profiles);
  const control = controls(profiles), results = [];
  for (const test of cases) {
    const text = test.sourceReverse ? reverse(input[test.field]) : input[test.field];
    const base = profiles[test.profile].sums, sums = test.sumsReverse ? [...base].reverse() : base;
    const result = verifyCase(text, sums);
    assert.equal(result.partitions, test.partitions, `Partition count mismatch model ${test.id}`);
    assert.equal(result.mod10Survivors, test.digitTransitions, `Residue-10 count mismatch model ${test.id}`);
    assert.equal(result.mod100Survivors, 0, `Cannot exclude model ${test.id} at modulus 100`);
    results.push({id: test.id, ...result});
    if (test.id % 16 === 15) console.log(JSON.stringify({verified: results.length, models: cases.length}));
  }
  const result = {
    complete: true, independentSourceSHA256: hash(fs.readFileSync(__filename)), inputSHA256: hash(bytes),
    specSHA256: hash(fs.readFileSync(path.join(dir, 'spec.json'))), casesSHA256: hash(expected),
    method: 'Cell-by-cell profile reconstruction; equal-expression length classes; global interval CSP and weighted length total; constant substitution constraints; direct residues modulo 10 and 100. No production imports or digit-carry search.',
    scope: 'Necessary decimal length bounds cover all p,q>=2. Every constant-compatible partition agrees with production; every such partition has no residue pair modulo 100 compatible with one nonzero digit bijection and at most two zero-alias letters. Therefore no full integer solution exists within these 128 models.',
    models: results.length, partitions: results.reduce((s, x) => s + x.partitions, 0),
    mod10Survivors: results.reduce((s, x) => s + x.mod10Survivors, 0),
    mod100Survivors: results.reduce((s, x) => s + x.mod100Survivors, 0),
    geometryMatches: true, controls: control, cases: results, finalPasswordFound: false
  };
  fs.writeFileSync(path.join(dir, 'independent_verification.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({...result, cases: undefined}, null, 2));
}
if (require.main === module) main();
module.exports = {rebuild, enumerateLengths, suffixAccepts, verifyCase};
