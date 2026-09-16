'use strict';
// Exact finite reduction for nonnegative-integer colour weights in a Gram matrix.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const output = path.join(root, '_work/dbbi_gram_2026-09-16');
const inputPath = path.join(root, '_work/prime_geometry_2026-09-11/inputs.json');
const sha = data => crypto.createHash('sha256').update(data).digest('hex');
const names = ['blue', 'yellow', 'black', 'white', 'nearWhite'];

function categories(data) {
  const grid = data.matrix.map(row => row.map(x => x ? 2 : 3));
  for (const [, colour, row, column] of data.colored) grid[row][column] = colour === 'B' ? 0 : 1;
  assert.deepEqual(data.spiral[163], [7, 4]);
  assert.equal(grid[7][4], 3);
  grid[7][4] = 4;
  return grid;
}

function gram(grid, weights, axis) {
  const at = (vertex, coordinate) => weights[axis === 'rows' ? grid[vertex][coordinate] : grid[coordinate][vertex]];
  const values = [];
  for (let a = 0; a < 14; a++) for (let b = a + 1; b < 14; b++) {
    let value = 0;
    for (let coordinate = 0; coordinate < 14; coordinate++) value += at(a, coordinate) * at(b, coordinate);
    values.push(value);
  }
  return values;
}

function compatible(histogram, counts) {
  const sorted = [...counts].sort((a, b) => a - b).join(',');
  const matches = [];
  for (let aliasDigit = 1; aliasDigit <= counts.length; aliasDigit++) {
    const positive = Array.from({length: counts.length}, (_, i) => histogram[i + 1] || 0);
    positive[aliasDigit - 1] += histogram[0] || 0;
    if (positive.sort((a, b) => a - b).join(',') === sorted) matches.push(aliasDigit);
  }
  return matches;
}

function witnesses(grid) {
  const result = {};
  for (const axis of ['rows', 'columns']) {
    const at = (v, k) => axis === 'rows' ? grid[v][k] : grid[k][v];
    result[axis] = names.slice(0, 4).map((colour, category) => {
      for (let a = 0; a < 14; a++) for (let b = a + 1; b < 14; b++) {
        for (let coordinate = 0; coordinate < 14; coordinate++) {
          if (at(a, coordinate) === category && at(b, coordinate) === category) return {colour, vertices: [a, b], coordinate};
        }
      }
      throw new Error('Missing square lower-bound witness for ' + axis + '/' + colour);
    });
  }
  return result;
}

function controls() {
  // Plant every zero-count choice for a known three-symbol histogram, then
  // compare all possible histograms with an explicit permutation construction.
  const counts = [2, 3, 4], reachable = new Set();
  for (const p of [[1, 2, 3], [1, 3, 2], [2, 1, 3], [2, 3, 1], [3, 1, 2], [3, 2, 1]]) {
    for (let alias = 0; alias < 3; alias++) for (let zeroes = 0; zeroes <= counts[alias]; zeroes++) {
      const h = [zeroes, 0, 0, 0];
      for (let c = 0; c < 3; c++) h[p[c]] = counts[c] - (c === alias ? zeroes : 0);
      reachable.add(h.join(','));
    }
  }
  let checked = 0;
  for (let a = 0; a <= 9; a++) for (let b = 0; b <= 9 - a; b++) for (let c = 0; c <= 9 - a - b; c++) {
    const h = [a, b, c, 9 - a - b - c];
    assert.equal(compatible(h, counts).length > 0, reachable.has(h.join(',')));
    checked++;
  }
  const grid = Array.from({length: 14}, (_, r) => Array.from({length: 14}, (_, c) => r === c ? 0 : 1));
  assert(gram(grid, [7, 0], 'rows').every(v => v === 0));
  assert(gram(grid, [1, 1], 'rows').every(v => v === 14));
  assert(gram(grid, [1, 1], 'columns').every(v => v === 14));
  return {histogramsComparedWithExplicitPermutations: checked, plantedGramMatrices: 3};
}

function main() {
  fs.mkdirSync(output, {recursive: true});
  const raw = fs.readFileSync(inputPath), data = JSON.parse(raw), grid = categories(data);
  const counts = [...'abcdefghi'].map(c => [...data.dbbi].filter(x => x === c).length);
  assert.equal(data.dbbi.length, 91);
  assert(counts.every(c => c > 0));
  const spec = {
    createdAt: new Date().toISOString(), inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)),
    dbbiSHA256: sha(data.dbbi), colours: names, dbbiCounts: counts,
    hypothesis: 'DBBI encodes the 91 off-diagonal row or column inner products of the original 14x14 matrix. Each colour has one nonnegative integer weight. The near-white cell at [7,4] may have its own weight. Any permutation of all 91 entries is allowed.',
    encoding: 'Any bijection a..i -> 1..9; any ONE letter can independently denote zero or its assigned digit at each occurrence.',
    finiteReduction: {
      ordinaryColours: 'For each axis and ordinary colour, two distinct vectors share that colour at a coordinate. That dot product is at least weight^2; all products are nonnegative. Thus every ordinary weight is at most 3.',
      squareWitnesses: witnesses(grid),
      nearWhite: 'The fifth colour occurs once. If another entry in its coordinate across vectors has positive weight, a dot product is at least its weight, so the weight is at most 9. Otherwise every off-diagonal product involving it is zero, and any larger weight is equivalent to zero.',
      nearWhiteCell: [7, 4], weightDomains: [[0, 3], [0, 3], [0, 3], [0, 3], [0, 9]],
      cases: 2 * 4 ** 4 * 10
    },
    necessaryAndSufficientHistogramCondition: 'All values in 0..9. For some d in 1..9, merging the zero count into the count of d makes the nine positive-digit counts a permutation of the nine DBBI letter counts. This is sufficient only because arbitrary pair reordering is allowed.',
    limits: 'No negative weights/cancellation, modular dot products, arbitrary nondecimal labels, multiple independently zeroable letters, vector families other than original rows or columns, or general 196-entry row-column cross products.'
  };
  const records = [], totals = {range: 0, distinct: 0, histogram: 0, survivors: 0};
  const byAxis = {};
  for (const axis of ['rows', 'columns']) {
    byAxis[axis] = {range: 0, distinct: 0, histogram: 0, survivors: 0};
    for (let b = 0; b <= 3; b++) for (let y = 0; y <= 3; y++) for (let k = 0; k <= 3; k++) for (let w = 0; w <= 3; w++) for (let n = 0; n <= 9; n++) {
      const weights = [b, y, k, w, n], values = gram(grid, weights, axis);
      const max = Math.max(...values), histogram = {};
      for (const value of values) histogram[value] = (histogram[value] || 0) + 1;
      const positiveDistinct = Object.keys(histogram).filter(v => Number(v) > 0).length;
      const matches = max <= 9 ? compatible(histogram, counts) : [];
      const reason = max > 9 ? 'range' : positiveDistinct < 8 ? 'distinct' : matches.length ? 'survivors' : 'histogram';
      records.push({axis, weights, max, positiveDistinct, histogram, matches, reason});
      totals[reason]++; byAxis[axis][reason]++;
    }
  }
  const save = (file, value) => fs.writeFileSync(path.join(output, file), JSON.stringify(value, null, 2) + '\n');
  const cases = Buffer.from(records.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(path.join(output, 'cases.jsonl.gz'), zlib.gzipSync(cases));
  const summary = {cases: records.length, totals, byAxis, controls: controls(), casesSHA256: sha(cases),
    aesTrials: 0, finalPasswordFound: false};
  save('spec.json', spec); save('summary.json', summary);
  console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
module.exports = {gram, compatible};
