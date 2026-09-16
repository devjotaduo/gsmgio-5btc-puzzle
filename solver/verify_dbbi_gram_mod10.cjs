'use strict';
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib');
const crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/dbbi_gram_2026-09-16');
const read = file => JSON.parse(fs.readFileSync(path.join(out, file), 'utf8'));
const sha = x => crypto.createHash('sha256').update(x).digest('hex');

function products(grid, weights) {
  const n = grid.length, result = Array.from({length: n}, () => Array(n).fill(0));
  for (let coordinate = 0; coordinate < grid[0].length; coordinate++) {
    const column = grid.map(v => weights[v[coordinate]]);
    for (let a = 0; a < n; a++) for (let b = a + 1; b < n; b++) result[a][b] += column[a] * column[b];
  }
  const values = [];
  for (let a = 0; a < n; a++) for (let b = a + 1; b < n; b++) values.push((result[a][b] % 10 + 10) % 10);
  return values;
}

function inventory(pairs, labels) {
  const result = {};
  for (let vertex = 0; vertex < 14; vertex++) {
    const histogram = Array(9).fill(0);
    for (let e = 0; e < pairs.length; e++) if (pairs[e].includes(vertex)) histogram[labels[e]]++;
    assert.equal(histogram.reduce((a, b) => a + b, 0), 13);
    const key = histogram.join(','); result[key] = (result[key] || 0) + 1;
  }
  return result;
}

function main() {
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), data = JSON.parse(raw);
  const spec = read('modular_spec.json'), summary = read('modular_summary.json');
  assert.equal(sha(raw), spec.inputSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver/dbbi_gram_mod10.cjs'))), spec.sourceSHA256);
  const grid = Array.from({length: 14}, (_, r) => Array.from({length: 14}, (_, c) => {
    if (r === 7 && c === 4) return 4;
    const match = data.colored.find(x => x[2] === r && x[3] === c);
    return match ? ({B: 0, Y: 1})[match[1]] : data.matrix[r][c] ? 2 : 3;
  }));
  assert.deepEqual(data.spiral[163], [7, 4]);
  const counts = Array(9).fill(0); for (const c of data.dbbi) counts[c.charCodeAt(0) - 97]++;
  assert.deepEqual(counts, spec.counts);
  const orders = {row: [], column: [], diagonal: [], diagonalDescending: []};
  for (let a = 0; a < 14; a++) for (let b = a + 1; b < 14; b++) orders.row.push([a, b]);
  for (let b = 1; b < 14; b++) for (let a = 0; a < b; a++) orders.column.push([a, b]);
  for (let gap = 1; gap < 14; gap++) for (let a = 0; a + gap < 14; a++) orders.diagonal.push([a, a + gap]);
  for (let gap = 13; gap > 0; gap--) for (let a = 0; a + gap < 14; a++) orders.diagonalDescending.push([a, a + gap]);
  for (const [name, pairs] of Object.entries(orders)) orders[name + '/reversed'] = Array.from({length: pairs.length}, (_, i) => pairs[pairs.length - 1 - i]);
  assert.deepEqual(orders, spec.orders);
  const bytes = zlib.gunzipSync(fs.readFileSync(path.join(out, 'modular_cases.jsonl.gz')));
  assert.equal(sha(bytes), summary.casesSHA256);
  const lines = bytes.toString('utf8').trim().split('\n');
  const totals = {distinct: 0, histogram: 0, histogramSurvivor: 0}, byAxis = {}, seen = new Set(), survivors = [];
  const columns = grid[0].map((_, c) => grid.map(row => row[c]));
  for (const line of lines) {
    const record = JSON.parse(line), {code, axis} = record;
    assert(Number.isInteger(code) && code >= 0 && code < 100000 && ['rows', 'columns'].includes(axis));
    const id = axis + '/' + code; assert(!seen.has(id)); seen.add(id);
    const weights = [...String(code).padStart(5, '0')].map(Number);
    const values = products(axis === 'rows' ? grid : columns, weights), histogram = Array(10).fill(0);
    for (const v of values) histogram[v]++;
    assert.deepEqual(histogram, record.histogram);
    const sorted = histogram.slice(1).sort((a, b) => a - b), possibleAliases = [];
    for (let alias = 0; alias < 9; alias++) {
      if (counts[alias] < histogram[0]) continue;
      const remaining = counts.map((c, i) => c - (i === alias ? histogram[0] : 0)).sort((a, b) => a - b);
      if (remaining.every((c, i) => c === sorted[i])) possibleAliases.push(alias);
    }
    const reason = histogram.slice(1).filter(Boolean).length < 8 ? 'distinct' : possibleAliases.length ? 'histogramSurvivor' : 'histogram';
    assert.equal(reason, record.reason); totals[reason]++;
    byAxis[axis] ||= {distinct: 0, histogram: 0, histogramSurvivor: 0}; byAxis[axis][reason]++;
    if (reason === 'histogramSurvivor') survivors.push({axis, code, weights, histogram, values, possibleAliases});
  }
  assert.equal(lines.length, 200000); assert.equal(seen.size, 200000);
  assert.deepEqual(totals, summary.totals); assert.deepEqual(byAxis, summary.byAxis);
  const savedSurvivors = read('modular_survivors.json'), savedGraphs = read('modular_graph_cases.json');
  assert.equal(sha(fs.readFileSync(path.join(out, 'modular_survivors.json'))), summary.survivorsSHA256);
  assert.equal(sha(fs.readFileSync(path.join(out, 'modular_graph_cases.json'))), summary.graphCasesSHA256);
  assert.equal(savedSurvivors.length, survivors.length);
  let independentMappingCount = 0, graphCount = 0, signatureControls = 0, liftedIntegerControls = 0;
  const uniqueLabelledGraphs = new Set();
  survivors.forEach((s, survivorId) => {
    const saved = savedSurvivors[survivorId];
    for (const key of ['axis', 'code', 'weights', 'histogram', 'values']) assert.deepEqual(saved[key], s[key]);
    const mapSet = new Set();
    // Assign each positive digit to an unused letter. The alias count is
    // adjusted at the letter level, independently of the generator's merge.
    for (const alias of s.possibleAliases) {
      const required = counts.map((c, i) => c - (i === alias ? s.histogram[0] : 0));
      function enumerate(digit, labels, used) {
        if (digit === 10) {
          const digits = Array(9); labels.forEach((letter, i) => { digits[letter] = i + 1; });
          const mapping = {aliasDigit: digits[alias], digits};
          mapSet.add(JSON.stringify(mapping)); return;
        }
        for (let letter = 0; letter < 9; letter++) if (!(used & (1 << letter)) && required[letter] === s.histogram[digit]) enumerate(digit + 1, [...labels, letter], used | (1 << letter));
      }
      enumerate(1, [], 0);
    }
    assert.deepEqual(new Set(saved.mappings.map(JSON.stringify)), mapSet);
    independentMappingCount += mapSet.size;
    const vectors = s.axis === 'rows' ? grid : columns;
    for (const multiplier of [-17, -1, 1, 19]) {
      const lifted = s.weights.map((w, i) => w + 10 * multiplier * (i + 1));
      assert.deepEqual(products(vectors, lifted), s.values); liftedIntegerControls++;
    }
    for (const encoded of mapSet) {
      const mapping = JSON.parse(encoded), alias = mapping.digits.indexOf(mapping.aliasDigit);
      const labels = s.values.map(v => v === 0 ? alias : mapping.digits.indexOf(v));
      assert(labels.every(v => v >= 0));
      const own = inventory(orders.row, labels);
      for (const [order, pairs] of Object.entries(orders)) {
        const wanted = inventory(pairs, [...data.dbbi].map(c => c.charCodeAt(0) - 97));
        const matching = savedGraphs.filter(c => c.survivorId === survivorId && c.order === order && JSON.stringify(c.mapping) === encoded);
        assert.equal(matching.length, 1); const record = matching[0];
        assert.deepEqual(record.signaturesHere, own); assert(record.mismatch);
        const key = record.mismatch.signature;
        assert.equal(record.mismatch.matrixMultiplicity, own[key] || 0);
        assert.equal(record.mismatch.dbbiMultiplicity, wanted[key] || 0);
        assert.notEqual(own[key] || 0, wanted[key] || 0);
        graphCount++; uniqueLabelledGraphs.add(order + '/' + labels.join(','));
      }
      const renamed = orders.row.map(([a, b]) => [(a * 5 + 3) % 14, (b * 5 + 3) % 14]);
      assert.deepEqual(inventory(renamed, labels), own); signatureControls++;
    }
  });
  assert.equal(graphCount, savedGraphs.length); assert.equal(graphCount, summary.graphCases);
  assert.equal(graphCount, summary.graphSignatureRejections); assert.equal(summary.graphSurvivors, 0);
  const result = {verifiedAt: new Date().toISOString(), verifierSHA256: sha(fs.readFileSync(__filename)),
    casesSHA256: sha(bytes), cases: lines.length, totals, byAxis, histogramSurvivors: survivors.length,
    independentMappingCount, graphSignatureCertificates: graphCount, uniqueLabelledGraphsWithOrder: uniqueLabelledGraphs.size,
    controls: {signatureControls, liftedIntegerControls}, allCasesRegeneratedByOuterProducts: true,
    allDigitMapsRegenerated: true, allSignatureCertificatesValid: true, allResultsMatch: true, finalPasswordFound: false};
  fs.writeFileSync(path.join(out, 'modular_verification.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
