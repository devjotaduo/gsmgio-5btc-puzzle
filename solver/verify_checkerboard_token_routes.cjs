'use strict';
// Independently reconstruct the routes, token streams, saved substitutions and scores.
// This validates witnesses and coverage, not a global optimum of the heuristic.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), dir = path.join(root, '_work/checkerboard_token_routes_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest('hex'), read = name => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
const spec = read('spec.json'), summary = read('summary.json'), controls = read('controls.json');
const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw);
const q = fs.readFileSync(path.join(root, '_work/ambiguous_checkerboard_2026-09-15/general_english/quadgram.f32'));
assert.equal(hash(raw), spec.inputSHA256); assert.equal(hash(q), spec.scorerSHA256);
assert.equal(hash(fs.readFileSync(path.join(root, 'solver/checkerboard_token_routes.cjs'))), spec.sourceSHA256);
assert.equal(hash(fs.readFileSync(path.join(dir, 'controls.json'))), spec.controlsSHA256);
function quadScore(text) {
  let total = 0;
  for (let i = 0; i + 4 <= text.length; i++) {let index = 0; for (let j = 0; j < 4; j++) index = 26 * index + text.charCodeAt(i + j) - 65; total += q.readFloatLE(4 * index);}
  return total;
}
function route(label) {
  const {rows, cols, name, flipRows, flipCols, reverse, inverse} = label; assert.equal(rows * cols, 451);
  let cells = [];
  if (name === 'spiral') {
    const directions = [[0, 1], [1, 0], [0, -1], [-1, 0]], visited = new Set(); let r = 0, c = 0, d = 0;
    for (let i = 0; i < rows * cols; i++) {
      cells.push([r, c]); visited.add(r * cols + c);
      let nr = r + directions[d][0], nc = c + directions[d][1];
      if (nr < 0 || nc < 0 || nr >= rows || nc >= cols || visited.has(nr * cols + nc)) {d = (d + 1) % 4; nr = r + directions[d][0]; nc = c + directions[d][1];}
      r = nr; c = nc;
    }
  } else {
    for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) cells.push([r, c]);
    const position = ([r, c]) => name === 'rows' ? r * cols + c : name === 'rowSnake' ? r * cols + (r % 2 ? cols - c - 1 : c) :
      name === 'columns' ? c * rows + r : name === 'columnSnake' ? c * rows + (c % 2 ? rows - r - 1 : r) : NaN;
    assert(['rows', 'rowSnake', 'columns', 'columnSnake'].includes(name)); cells.sort((a, b) => position(a) - position(b));
  }
  let perm = cells.map(([r, c]) => (flipRows ? rows - 1 - r : r) * cols + (flipCols ? cols - 1 - c : c));
  if (reverse) perm = perm.slice().reverse(); if (inverse) perm = Array.from({length: 451}, (_, value) => perm.indexOf(value));
  return perm;
}
const labelIDs = new Set(), permutationIDs = new Set();
for (const r of spec.routes) {
  const id = r.permutation.join(','); assert(!permutationIDs.has(id)); permutationIDs.add(id);
  assert.deepEqual(r.permutation.slice().sort((a, b) => a - b), [...Array(451).keys()]);
  for (const label of r.labels) {const k = JSON.stringify(label); assert(!labelIDs.has(k)); labelIDs.add(k); assert.deepEqual(route(label), r.permutation);}
}
assert.equal(labelIDs.size, 160); assert.equal(permutationIDs.size, 70);
const datasets = new Map();
for (const data of spec.datasets) {
  const original = data.sourceReversed ? [...input.faed].reverse().join('') : input.faed;
  const tokens = original.match(/[bg][a-i]|[acdefhi]/g); assert.equal(tokens.join(''), original);
  const symbols = [...new Set(tokens)].sort(), ids = tokens.map(t => symbols.indexOf(t));
  assert.equal(tokens.length, 451); assert.equal(symbols.length, 25); assert.deepEqual(data.symbols, symbols);
  if (data.name === 'real') {assert.deepEqual(data.tokens, tokens); assert.deepEqual(data.ids, ids);}
  else {
    const number = Number(data.name.replace('shuffle', '')); assert(number === 1 || number === 2);
    let state = 701 + number + Number(data.sourceReversed) * 1009; const shuffled = ids.slice();
    for (let i = shuffled.length - 1; i > 0; i--) {state ^= state << 13; state ^= state >>> 17; state ^= state << 5; const j = Math.floor((state >>> 0) * (i + 1) / 4294967296); [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];}
    assert.deepEqual(data.ids, shuffled);
  }
  assert.deepEqual(data.ids.slice().sort((a, b) => a - b), ids.slice().sort((a, b) => a - b));
  const id = data.name + '/' + data.sourceReversed; assert(!datasets.has(id)); datasets.set(id, data);
}
assert.equal(datasets.size, 6);
function checkWitness(w, ids) {
  assert.deepEqual(w.key.slice().sort((a, b) => a - b), [...Array(26).keys()]);
  const text = ids.map(i => String.fromCharCode(65 + w.key[i])).join(''); assert.equal(text, w.text);
  assert.match(text, /^[A-Z]{451}$/); assert.equal(quadScore(text), w.total); assert.equal(w.total / 448, w.score);
  assert(Number.isInteger(w.restart) && w.restart >= 0 && w.restart < spec.options.restarts);
}
assert.deepEqual(controls.options, spec.options);
for (const c of controls.records) {
  assert.equal(c.text.length, 451); assert.equal(c.accuracy, 1); assert.equal(c.best.text, c.text);
  assert.equal(c.ids.map(i => c.alphabet[i]).join(''), c.text);
  checkWitness(c.best, c.ids);
}
const casesBytes = fs.readFileSync(path.join(dir, 'cases.jsonl')), records = casesBytes.toString().trim().split('\n').map(JSON.parse);
const seen = new Set(), tops = new Map(), candidates = new Map(); let witnesses = 0, evaluations = 0, deltaChecks = 0;
for (const c of records) {
  const dataKey = c.dataset + '/' + c.sourceReversed, data = datasets.get(dataKey); assert(data);
  assert(Number.isInteger(c.route) && c.route >= 0 && c.route < spec.routes.length);
  const caseKey = dataKey + '/' + c.route; assert(!seen.has(caseKey)); seen.add(caseKey);
  const ids = spec.routes[c.route].permutation.map(i => data.ids[i]);
  assert.equal(c.restartBests.length, spec.options.restarts);
  assert(c.evaluations > 0 && c.evaluations <= spec.options.restarts * spec.options.iterations); evaluations += c.evaluations; deltaChecks += c.deltaChecks;
  let last = -Infinity;
  for (const b of c.improvements) {checkWitness(b, ids); witnesses++; assert(b.total > last); last = b.total;}
  assert.deepEqual(c.best, c.improvements.at(-1));
  for (const [i, b] of c.restartBests.entries()) {checkWitness(b, ids); witnesses++; assert.equal(b.restart, i); assert(b.total <= c.best.total);}
  if (!tops.has(dataKey) || c.best.score > tops.get(dataKey).score) tops.set(dataKey, {route: c.route, ...c.best});
  if (c.dataset === 'real') for (const b of [...c.improvements, ...c.restartBests]) if (!candidates.has(b.text)) candidates.set(b.text, {text: b.text, score: b.score, sourceReversed: c.sourceReversed, route: c.route});
}
assert.equal(seen.size, 6 * 70); assert.equal(summary.cases, seen.size); assert.equal(summary.routes, 70);
for (const t of summary.tops) assert.deepEqual(t.best, tops.get(t.dataset + '/' + t.sourceReversed));
assert.equal(summary.candidates, candidates.size); assert.deepEqual(read('candidates.json'), [...candidates.values()]);
const result = {verifiedAt: new Date().toISOString(), verifierSHA256: hash(fs.readFileSync(__filename)), casesSHA256: hash(casesBytes), sourceSHA256: spec.sourceSHA256,
  routesVerified: 70, geometricLabelsVerified: 160, casesVerified: records.length, savedWitnessesVerified: witnesses,
  evaluations, deltaChecks, realCandidateTexts: candidates.size, exactControlRecoveries: controls.records.length,
  bestScores: summary.tops.map(t => ({dataset: t.dataset, sourceReversed: t.sourceReversed, score: t.best.score})),
  limitation: 'Finite heuristic substitution search. Exact saved paths and route coverage are verified, not every substitution key.', finalPasswordFound: false};
fs.writeFileSync(path.join(dir, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
