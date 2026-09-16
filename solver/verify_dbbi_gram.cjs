'use strict';
// Independent reconstruction by coordinate outer products, without importing the searcher.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const output = path.join(root, '_work/dbbi_gram_2026-09-16');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const read = f => JSON.parse(fs.readFileSync(path.join(output, f), 'utf8'));

function outerProducts(vectors) {
  const size = vectors.length, result = Array.from({length: size}, () => Array(size).fill(0));
  for (let k = 0; k < vectors[0].length; k++) {
    for (let a = 0; a < size; a++) for (let b = 0; b < size; b++) result[a][b] += vectors[a][k] * vectors[b][k];
  }
  return result;
}

function compatible(histogram, counts) {
  const positive = Array.from({length: counts.length}, (_, i) => histogram[i + 1] || 0).sort((a, b) => a - b);
  return counts.some((count, alias) => {
    if (count < (histogram[0] || 0)) return false;
    const remaining = counts.map((c, i) => c - (i === alias ? histogram[0] || 0 : 0)).sort((a, b) => a - b);
    return remaining.every((v, i) => v === positive[i]);
  });
}

function main() {
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const data = JSON.parse(raw), spec = read('spec.json'), summary = read('summary.json');
  assert.equal(sha(raw), spec.inputSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver/dbbi_gram.cjs'))), spec.sourceSHA256);
  assert.equal(sha(data.dbbi), spec.dbbiSHA256);
  const counts = Array(9).fill(0);
  for (const letter of data.dbbi) counts[letter.charCodeAt(0) - 97]++;
  assert.deepEqual(counts, spec.dbbiCounts);
  const grid = Array.from({length: 14}, (_, r) => Array.from({length: 14}, (_, c) => {
    if (r === 7 && c === 4) return 4;
    const coloured = data.colored.find(x => x[2] === r && x[3] === c);
    return coloured ? ({B: 0, Y: 1})[coloured[1]] : data.matrix[r][c] === 0 ? 3 : 2;
  }));
  assert.equal(grid.flat().filter(c => c === 4).length, 1);
  assert.deepEqual(data.spiral[163], [7, 4]);
  let boundsChecked = 0, inertCasesChecked = 0;
  for (const axis of ['rows', 'columns']) {
    const indexed = axis === 'rows' ? grid : grid[0].map((_, c) => grid.map(row => row[c]));
    const witnesses = spec.finiteReduction.squareWitnesses[axis];
    assert.equal(witnesses.length, 4);
    witnesses.forEach((w, category) => {
      assert.equal(w.colour, spec.colours[category]);
      const [a, b] = w.vertices;
      assert(a !== b && a >= 0 && a < 14 && b >= 0 && b < 14 && w.coordinate >= 0 && w.coordinate < 14);
      assert.equal(indexed[a][w.coordinate], category);
      assert.equal(indexed[b][w.coordinate], category);
      boundsChecked++;
    });
    const starVector = axis === 'rows' ? 7 : 4, starCoordinate = axis === 'rows' ? 4 : 7;
    assert.equal(indexed[starVector][starCoordinate], 4);
    for (let code = 0; code < 256; code++) {
      const weights = Array.from({length: 4}, (_, c) => Math.floor(code / 4 ** (3 - c)) % 4);
      const interacts = indexed.some((v, i) => i !== starVector && weights[v[starCoordinate]] > 0);
      const large = outerProducts(indexed.map(row => row.map(c => c === 4 ? 10 : weights[c])));
      if (interacts) {
        assert(large[starVector].some((x, i) => i !== starVector && x >= 10));
      } else {
        const zero = outerProducts(indexed.map(row => row.map(c => c === 4 ? 0 : weights[c])));
        for (let a = 0; a < 14; a++) for (let b = 0; b < 14; b++) if (a !== b) assert.equal(large[a][b], zero[a][b]);
        inertCasesChecked++;
      }
      boundsChecked++;
    }
  }
  assert.deepEqual(outerProducts([[1, 2], [3, 4]]), [[5, 11], [11, 25]]);
  assert.deepEqual(outerProducts([[1, 0, 0], [0, 1, 0], [0, 0, 1]]), [[1, 0, 0], [0, 1, 0], [0, 0, 1]]);
  let positiveControls = 0;
  for (let alias = 0; alias < 9; alias++) for (let zeroes = 0; zeroes <= counts[alias]; zeroes++) {
    const h = [zeroes, ...counts]; h[alias + 1] -= zeroes;
    assert(compatible(h, counts)); positiveControls++;
  }
  assert(!compatible([91, 0, 0, 0, 0, 0, 0, 0, 0, 0], counts));
  const bytes = zlib.gunzipSync(fs.readFileSync(path.join(output, 'cases.jsonl.gz')));
  assert.equal(sha(bytes), summary.casesSHA256);
  const records = bytes.toString('utf8').trim().split('\n').map(JSON.parse);
  const totals = {range: 0, distinct: 0, histogram: 0, survivors: 0}, byAxis = {}, seen = new Set();
  for (const record of records) {
    assert(['rows', 'columns'].includes(record.axis));
    assert.equal(record.weights.length, 5);
    record.weights.forEach((v, i) => assert(Number.isInteger(v) && v >= 0 && v <= (i === 4 ? 9 : 3)));
    const id = record.axis + '/' + record.weights.join(','); assert(!seen.has(id)); seen.add(id);
    const filled = grid.map(row => row.map(c => record.weights[c]));
    const vectors = record.axis === 'rows' ? filled : filled[0].map((_, c) => filled.map(row => row[c]));
    const products = outerProducts(vectors), histogram = {};
    let max = 0, entries = 0;
    for (let a = 0; a < 14; a++) for (let b = 0; b < a; b++) {
      const value = products[a][b]; histogram[value] = (histogram[value] || 0) + 1; max = Math.max(max, value); entries++;
    }
    assert.equal(entries, 91);
    assert.deepEqual(histogram, record.histogram); assert.equal(max, record.max);
    const distinct = Object.keys(histogram).filter(k => k !== '0').length;
    assert.equal(distinct, record.positiveDistinct);
    const possible = max <= 9 && compatible(histogram, counts);
    assert.equal(record.matches.length > 0, possible);
    const reason = max > 9 ? 'range' : distinct < 8 ? 'distinct' : possible ? 'survivors' : 'histogram';
    assert.equal(reason, record.reason); totals[reason]++;
    byAxis[record.axis] ||= {range: 0, distinct: 0, histogram: 0, survivors: 0}; byAxis[record.axis][reason]++;
  }
  assert.equal(records.length, 5120); assert.equal(seen.size, 5120);
  assert.equal(records.length, spec.finiteReduction.cases); assert.equal(records.length, summary.cases);
  assert.deepEqual(totals, summary.totals); assert.deepEqual(byAxis, summary.byAxis);
  assert.equal(totals.survivors, 0);
  const result = {verifiedAt: new Date().toISOString(), verifierSHA256: sha(fs.readFileSync(__filename)),
    inputSHA256: sha(raw), casesSHA256: sha(bytes), cases: records.length, totals, byAxis,
    controls: {boundsChecked, inertCasesChecked, knownOuterProductMatrices: 2, positiveHistogramControls: positiveControls, negativeHistogramControls: 1},
    allCasesRegenerated: true, allBoundsConfirmed: true, differentHistogramCriterion: true, allResultsMatch: true, finalPasswordFound: false};
  fs.writeFileSync(path.join(output, 'verification.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
