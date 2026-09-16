'use strict';
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib');
const crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/dbbi_gram_2026-09-16');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');

function pairOrders() {
  const row = [];
  for (let i = 0; i < 14; i++) for (let j = i + 1; j < 14; j++) row.push([i, j]);
  const orders = {row, column: [...row].sort((a, b) => a[1] - b[1] || a[0] - b[0]),
    diagonal: [...row].sort((a, b) => (a[1] - a[0]) - (b[1] - b[0]) || a[0] - b[0]),
    diagonalDescending: [...row].sort((a, b) => (b[1] - b[0]) - (a[1] - a[0]) || a[0] - b[0])};
  for (const [name, pairs] of Object.entries(orders)) orders[name + '/reversed'] = [...pairs].reverse();
  return orders;
}

function signatures(pairs, labels) {
  const degrees = Array.from({length: 14}, () => Array(9).fill(0));
  pairs.forEach(([a, b], i) => { degrees[a][labels[i]]++; degrees[b][labels[i]]++; });
  const inventory = {};
  for (const d of degrees) { const key = d.join(','); inventory[key] = (inventory[key] || 0) + 1; }
  return inventory;
}

function mappings(histogram, counts) {
  const result = [];
  for (let aliasDigit = 1; aliasDigit <= 9; aliasDigit++) {
    const merged = histogram.slice(1); merged[aliasDigit - 1] += histogram[0];
    if ([...merged].sort((a, b) => a - b).join(',') !== [...counts].sort((a, b) => a - b).join(',')) continue;
    function visit(assigned, used) {
      if (assigned.length === 9) { result.push({aliasDigit, digits: assigned}); return; }
      for (let d = 1; d <= 9; d++) if (!(used & (1 << d)) && merged[d - 1] === counts[assigned.length]) visit([...assigned, d], used | (1 << d));
    }
    visit([], 0);
  }
  return result;
}

function coefficients(grid, pairs) {
  return pairs.map(([a, b]) => {
    const bins = Array(25).fill(0);
    for (let k = 0; k < 14; k++) bins[Math.min(grid[a][k], grid[b][k]) * 5 + Math.max(grid[a][k], grid[b][k])]++;
    return bins.flatMap((n, i) => n ? [[i, n]] : []);
  });
}

function evaluate(terms, weights) {
  const products = Array.from({length: 25}, (_, i) => weights[Math.floor(i / 5)] * weights[i % 5] % 10);
  return terms.map(t => t.reduce((sum, [i, n]) => sum + n * products[i], 0) % 10);
}

function main() {
  fs.mkdirSync(out, {recursive: true});
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), data = JSON.parse(raw);
  const grid = data.matrix.map(row => row.map(v => v ? 2 : 3));
  for (const [, c, r, k] of data.colored) grid[r][k] = c === 'B' ? 0 : 1;
  assert.deepEqual(data.spiral[163], [7, 4]); assert.equal(grid[7][4], 3); grid[7][4] = 4;
  const counts = [...'abcdefghi'].map(c => [...data.dbbi].filter(v => v === c).length);
  const sortedCounts = [...counts].sort((a, b) => a - b).join(',');
  const orders = pairOrders(), targetSignatures = {};
  for (const [name, pairs] of Object.entries(orders)) targetSignatures[name] = signatures(pairs, [...data.dbbi].map(c => c.charCodeAt(0) - 97));
  const totals = {distinct: 0, histogram: 0, histogramSurvivor: 0}, byAxis = {}, records = [], survivors = [], graphCases = [];
  let coefficientControls = 0;
  for (const axis of ['rows', 'columns']) {
    const vectors = axis === 'rows' ? grid : grid[0].map((_, c) => grid.map(row => row[c]));
    const terms = coefficients(vectors, orders.row);
    byAxis[axis] = {distinct: 0, histogram: 0, histogramSurvivor: 0};
    for (let code = 0; code < 100000; code++) {
      const weights = Array.from({length: 5}, (_, i) => Math.floor(code / 10 ** (4 - i)) % 10);
      const values = evaluate(terms, weights), histogram = Array(10).fill(0);
      for (const value of values) histogram[value]++;
      if (code % 997 === 0) {
        const direct = orders.row.map(([a, b]) => vectors[a].reduce((s, c, k) => s + weights[c] * weights[vectors[b][k]], 0) % 10);
        assert.deepEqual(values, direct); coefficientControls++;
      }
      const positiveDistinct = histogram.slice(1).filter(Boolean).length;
      let possible = false;
      if (positiveDistinct >= 8) for (let d = 1; d <= 9; d++) {
        const merged = histogram.slice(1); merged[d - 1] += histogram[0];
        if (merged.sort((a, b) => a - b).join(',') === sortedCounts) possible = true;
      }
      const reason = positiveDistinct < 8 ? 'distinct' : possible ? 'histogramSurvivor' : 'histogram';
      records.push(JSON.stringify({axis, code, histogram, reason})); totals[reason]++; byAxis[axis][reason]++;
      if (!possible) continue;
      const allowed = mappings(histogram, counts), survivorId = survivors.length;
      survivors.push({axis, code, weights, histogram, values, mappings: allowed});
      for (const mapping of allowed) {
        const aliasLetter = mapping.digits.indexOf(mapping.aliasDigit);
        const labels = values.map(v => v === 0 ? aliasLetter : mapping.digits.indexOf(v));
        const signaturesHere = signatures(orders.row, labels);
        for (const [name, wanted] of Object.entries(targetSignatures)) {
          const witness = [...new Set([...Object.keys(signaturesHere), ...Object.keys(wanted)])]
            .find(key => (signaturesHere[key] || 0) !== (wanted[key] || 0));
          graphCases.push({survivorId, mapping, order: name, signaturesHere,
            mismatch: witness === undefined ? null : {signature: witness, matrixMultiplicity: signaturesHere[witness] || 0, dbbiMultiplicity: wanted[witness] || 0}});
        }
      }
    }
  }
  // Vertex relabeling preserves per-colour degree signatures.
  let signatureControls = 0;
  const controlLabels = orders.row.map(([a, b]) => (a * 7 + b * 3) % 9);
  const before = signatures(orders.row, controlLabels);
  for (let shift = 0; shift < 14; shift++) {
    const permuted = orders.row.map(([a, b]) => [(a + shift) % 14, (b + shift) % 14]);
    assert.deepEqual(signatures(permuted, controlLabels), before); signatureControls++;
  }
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');
  const bytes = Buffer.from(records.join('\n') + '\n');
  fs.writeFileSync(path.join(out, 'modular_cases.jsonl.gz'), zlib.gzipSync(bytes));
  save('modular_survivors.json', survivors); save('modular_graph_cases.json', graphCases);
  save('modular_spec.json', {createdAt: new Date().toISOString(), sourceSHA256: sha(fs.readFileSync(__filename)), inputSHA256: sha(raw),
    hypothesis: 'Row or column Gram entries reduced modulo 10, on the original five-colour matrix. All integer weights, including primes and negatives, reduce to five residues 0..9. Any digit bijection and one independently zeroable letter are allowed.',
    firstFilter: 'Arbitrary permutation of all 91 pairs: merge the zero count into one positive digit count and compare the nine multiplicities with DBBI.',
    secondFilter: 'Only for surviving histograms: all eight explicit triangular traversals and arbitrary relabeling of the 14 vertices. A colour-degree signature multiset mismatch rules out every such vertex permutation.',
    colours: ['blue', 'yellow', 'black', 'white', 'nearWhite'], nearWhiteCell: [7, 4], counts, orders,
    limits: 'A successful histogram is not ruled out for arbitrary unrelated permutations of all 91 edges. The second filter covers only these eight edge layouts up to any vertex permutation. No other modulus, multiple zeroable letters, or different source vectors.'});
  const summary = {cases: records.length, totals, byAxis, histogramSurvivors: survivors.length,
    graphCases: graphCases.length, graphSignatureRejections: graphCases.filter(c => c.mismatch !== null).length,
    graphSurvivors: graphCases.filter(c => c.mismatch === null).length,
    controls: {coefficientControls, signatureControls}, casesSHA256: sha(bytes),
    graphCasesSHA256: sha(fs.readFileSync(path.join(out, 'modular_graph_cases.json'))),
    survivorsSHA256: sha(fs.readFileSync(path.join(out, 'modular_survivors.json'))), aesTrials: 0, finalPasswordFound: false};
  save('modular_summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
