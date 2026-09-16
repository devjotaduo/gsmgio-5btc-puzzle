'use strict';
// Independent substring-dictionary and breadth-first checks. No solver imports.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), dir = path.join(root, '_work/symbolic_color_sums_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
const read = file => JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));

function longestDisjointRepeat(text) {
  function exists(length) {
    if (length === 0) return true;
    const first = new Map();
    for (let at = 0; at + length <= text.length; at++) {
      const piece = text.substring(at, at + length);
      if (first.has(piece)) {if (at - first.get(piece) >= length) return true;}
      else first.set(piece, at);
    }
    return false;
  }
  let low = 0, high = Math.floor(text.length / 2) + 1;
  while (high - low > 1) {const mid = (low + high) >> 1; if (exists(mid)) low = mid; else high = mid;}
  return low;
}

function buildProfiles(input) {
  const blue = input.matrix.map(row => row.map(() => 0)), yellow = input.matrix.map(row => row.map(() => 0));
  for (const [, color, row, col] of input.colored) (color === 'B' ? blue : yellow)[row][col] = 1;
  const transpose = grid => grid[0].map((_, col) => grid.map(row => row[col]));
  const sum = row => row.reduce((a, b) => a + b, 0), profiles = new Map();
  for (const black of [0, 1]) for (const white of [0, 1]) {
    const back = input.matrix.map((row, r) => row.map((bit, c) => blue[r][c] || yellow[r][c] ? 0 : bit === 1 ? white : black));
    for (const axis of ['row', 'column']) {
      const grids = [blue, yellow, back].map(grid => axis === 'row' ? grid : transpose(grid));
      const coefficients = grids[0].map((_, i) => grids.map(grid => sum(grid[i])));
      profiles.set([axis, black, white].join('/'), coefficients);
    }
  }
  return profiles;
}

function bounds(length, coefficients, repeat) {
  const limits = [], counts = new Map();
  coefficients.forEach(c => counts.set(JSON.stringify(c), (counts.get(JSON.stringify(c)) || 0) + 1));
  for (let variable = 0; variable < 2; variable++) {
    const active = coefficients.reduce((n, c) => n + (c[variable] > 0), 0);
    const digits = Math.floor((length - (coefficients.length - active)) / active);
    const candidates = [10n ** BigInt(digits) - 1n];
    for (const c of coefficients) if (c[variable] > 0 && counts.get(JSON.stringify(c)) >= 2) {
      const room = 10n ** BigInt(repeat) - 1n - BigInt(c[2] + 2 * c[1 - variable]);
      candidates.push(room < 0 ? -1n : room / BigInt(c[variable]));
    }
    limits.push(candidates.reduce((a, b) => a < b ? a : b));
  }
  const lengths = limits.some(n => n < 2n) ? [] : coefficients.map(c => String(BigInt(c[0]) * limits[0] + BigInt(c[1]) * limits[1] + BigInt(c[2])).length);
  return {limits, lengths};
}

function countSegmentations(text, coefficients, lengths) {
  let states = [{at: 0, assignments: new Map()}], visits = 1;
  for (let index = 0; index < coefficients.length; index++) {
    const key = JSON.stringify(coefficients[index]), next = [];
    const remainingMax = lengths.slice(index + 1).reduce((a, b) => a + b, 0), remainingMin = coefficients.length - index - 1;
    for (const state of states) {
      const first = Math.max(1, text.length - state.at - remainingMax), last = Math.min(lengths[index], text.length - state.at - remainingMin);
      for (let n = first; n <= last; n++) {
        const piece = text.substring(state.at, state.at + n);
        if (state.assignments.has(key) && state.assignments.get(key) !== piece) continue;
        const assignments = new Map(state.assignments); assignments.set(key, piece);
        next.push({at: state.at + n, assignments});
      }
    }
    visits += next.length; states = next;
  }
  return {count: states.filter(s => s.at === text.length).length, visits};
}

function main() {
  const spec = read('spec.json'), cases = read('cases.json'), summary = read('summary.json'), controls = read('controls.json');
  const inputBytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  assert.equal(hash(inputBytes), '2e58c16a953bc22c2361adb5124f43d8fe624d15e3c90858349dcb25ecefedc6');
  assert.equal(hash(inputBytes), spec.inputSHA256);
  assert.equal(hash(fs.readFileSync(path.join(root, 'solver/color_sum_symbolic.cjs'))), spec.sourceSHA256);
  assert.equal(hash(fs.readFileSync(path.join(dir, 'cases.json'))), summary.casesSHA256);
  const input = JSON.parse(inputBytes), profiles = buildProfiles(input), seen = new Set(), cache = new Map();
  const normalize = (text, aliases) => [...text].map(c => aliases.indexOf(c) >= 0 ? '0' : c).join('');
  const wantedAliases = [];
  for (let mask = 0; mask < 512; mask++) {
    const s = [...'abcdefghi'].filter((_, i) => mask & 1 << i).join(''); if (s.length <= 2) wantedAliases.push(s);
  }
  assert.deepEqual(spec.aliasSets.slice().sort(), wantedAliases.slice().sort());
  for (const p of spec.profiles) assert.deepEqual(p.sums, profiles.get([p.axis, p.black, p.white].join('/')));
  let lengthRejected = 0, segmentationRejected = 0, bfsVisits = 0;
  for (const record of cases) {
    const {field, aliases, axis, black, white, textReversed, sumsReversed} = record;
    assert(['dbbi', 'faed'].includes(field) && wantedAliases.includes(aliases));
    assert(typeof textReversed === 'boolean' && typeof sumsReversed === 'boolean');
    const profile = profiles.get([axis, black, white].join('/')); assert(profile);
    const id = [field, aliases, axis, black, white, textReversed, sumsReversed].join('/'); assert(!seen.has(id)); seen.add(id);
    const cacheKey = field + '/' + aliases;
    if (!cache.has(cacheKey)) {const text = normalize(input[field], aliases); cache.set(cacheKey, {text, repeat: longestDisjointRepeat(text)});}
    const {text, repeat} = cache.get(cacheKey); assert.equal(record.repeat.length, repeat);
    if (repeat) {
      const [a, b] = record.repeat.witness;
      assert(Number.isInteger(a) && Number.isInteger(b) && a >= 0 && b - a >= repeat && b + repeat <= text.length);
      assert.equal(text.slice(a, a + repeat), text.slice(b, b + repeat));
    }
    const result = bounds(text.length, profile, repeat);
    assert.deepEqual(result.limits.map(String), record.limits); assert.deepEqual(result.lengths, record.maxLengths);
    const maximum = result.lengths.reduce((a, b) => a + b, 0); assert.equal(maximum, record.maxLength);
    if (maximum < text.length) {assert.equal(record.reason, 'length'); assert.equal(record.nodes, 0); lengthRejected++;}
    else {
      assert.equal(record.reason, 'segmentation');
      const check = countSegmentations(textReversed ? [...text].reverse().join('') : text, sumsReversed ? profile.slice().reverse() : profile,
        sumsReversed ? result.lengths.slice().reverse() : result.lengths);
      assert.equal(check.count, 0); assert.equal(check.visits, record.nodes); bfsVisits += check.visits; segmentationRejected++;
    }
    assert.equal(record.matches, 0);
  }
  assert.equal(seen.size, 2 * 46 * 8 * 4);
  assert.equal(summary.cases, seen.size); assert.equal(summary.lengthRejected, lengthRejected);
  assert.equal(summary.segmentationRejected, segmentationRejected); assert.equal(summary.segmentationNodes, bfsVisits);
  assert.deepEqual(summary.survivors, []);
  // Check both repeat and segmentation algorithms against exhaustive small strings.
  let repeatControls = 0, segmentControls = 0;
  for (let length = 1; length <= 10; length++) for (let bits = 0; bits < 1 << length; bits++) {
    const text = bits.toString(2).padStart(length, '0'); let wanted = 0;
    for (let a = 0; a < length; a++) for (let b = a + 1; b < length; b++) {
      let n = 0; while (n < b - a && b + n < length && text[a + n] === text[b + n]) n++;
      wanted = Math.max(wanted, n);
    }
    assert.equal(longestDisjointRepeat(text), wanted); repeatControls++;
    const coefficients = [[1, 0, 0], [0, 1, 0], [1, 0, 0]]; let expected = 0;
    for (let a = 1; a <= 4; a++) for (let b = 1; b <= 4; b++) if (2 * a + b === length && text.slice(0, a) === text.slice(a + b)) expected++;
    assert.equal(countSegmentations(text, coefficients, [4, 4, 4]).count, expected); segmentControls++;
  }
  for (const control of controls.planted) {
    const coefficients = profiles.get([control.axis, control.black, control.white].join('/'));
    let zeros = 0;
    const values = coefficients.map(c => String(BigInt(c[0]) * BigInt(control.p) + BigInt(c[1]) * BigInt(control.q) + BigInt(c[2])));
    const text = [...values.join('')].map(d => d === '0' ? control.aliases[zeros++ % control.aliases.length] : control.alphabet[Number(d) - 1]).join('');
    const normalized = normalize(text, control.aliases), bound = bounds(text.length, coefficients, longestDisjointRepeat(normalized));
    assert(BigInt(control.p) <= bound.limits[0] && BigInt(control.q) <= bound.limits[1]);
    let at = 0; const equal = new Map();
    values.forEach((v, i) => {
      assert(v.length <= bound.lengths[i]);
      const key = JSON.stringify(coefficients[i]), piece = normalized.slice(at, at + v.length); at += v.length;
      if (equal.has(key)) assert.equal(equal.get(key), piece); else equal.set(key, piece);
    });
    assert.equal(at, text.length);
  }
  const result = {verifiedAt: new Date().toISOString(), sourceSHA256: hash(fs.readFileSync(__filename)), solverSHA256: spec.sourceSHA256,
    casesSHA256: summary.casesSHA256, completeCases: seen.size, lengthRejected, segmentationRejected, bfsVisits,
    repeatControls, segmentControls, plantedControls: controls.planted.length, allPassed: true, finalPasswordFound: false};
  fs.writeFileSync(path.join(dir, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
