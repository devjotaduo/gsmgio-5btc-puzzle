'use strict';
// Fixed b/g checkerboard tokens, then rectangular routes and unknown substitution.
// Heuristic language search, calibrated before use. No claim of exhaustive keys.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/checkerboard_token_routes_2026-09-16');
const inputBytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputBytes);
const qb = fs.readFileSync(path.join(root, '_work/ambiguous_checkerboard_2026-09-15/general_english/quadgram.f32'));
const q = new Float32Array(qb.buffer, qb.byteOffset, qb.byteLength / 4), hash = b => crypto.createHash('sha256').update(b).digest('hex');
assert.equal(hash(qb), 'd2a64e70154725a0c0d1901690df47c73086e0bfc112ad419aad2eb069f89a43');
function rng(seed) {let s = seed >>> 0 || 1; return () => {s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return (s >>> 0) / 4294967296;};}
function shuffle(a, random) {a = [...a]; for (let i = a.length - 1; i > 0; i--) {const j = Math.floor(random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]];} return a;}
function parse(text) {
  const tokens = [];
  for (let i = 0; i < text.length;) {const length = 'bg'.includes(text[i]) ? 2 : 1; assert(i + length <= text.length); tokens.push(text.slice(i, i + length)); i += length;}
  return tokens;
}
function score(ids, key) {
  let total = 0;
  for (let i = 0; i + 3 < ids.length; i++) total += q[((key[ids[i]] * 26 + key[ids[i + 1]]) * 26 + key[ids[i + 2]]) * 26 + key[ids[i + 3]]];
  return total;
}
function routes() {
  const maps = new Map();
  const add = (permutation, label) => {
    assert.equal(new Set(permutation).size, 451); assert(permutation.every(i => i >= 0 && i < 451));
    const id = permutation.join(','); if (!maps.has(id)) maps.set(id, {permutation, labels: []}); maps.get(id).labels.push(label);
  };
  for (const rows of [11, 41]) {
    const cols = 451 / rows, named = {};
    named.rows = Array.from({length: 451}, (_, i) => [Math.floor(i / cols), i % cols]);
    named.rowSnake = named.rows.map(([r, c]) => [r, r % 2 ? cols - 1 - c : c]);
    named.columns = Array.from({length: 451}, (_, i) => [i % rows, Math.floor(i / rows)]);
    named.columnSnake = named.columns.map(([r, c]) => [c % 2 ? rows - 1 - r : r, c]);
    const spiral = []; let top = 0, left = 0, bottom = rows - 1, right = cols - 1;
    while (top <= bottom && left <= right) {
      for (let c = left; c <= right; c++) spiral.push([top, c]); top++;
      for (let r = top; r <= bottom; r++) spiral.push([r, right]); right--;
      if (top <= bottom) {for (let c = right; c >= left; c--) spiral.push([bottom, c]); bottom--;}
      if (left <= right) {for (let r = bottom; r >= top; r--) spiral.push([r, left]); left++;}
    }
    named.spiral = spiral;
    for (const [name, cells] of Object.entries(named)) for (const flipRows of [false, true]) for (const flipCols of [false, true]) for (const reverse of [false, true]) {
      let permutation = cells.map(([r, c]) => (flipRows ? rows - 1 - r : r) * cols + (flipCols ? cols - 1 - c : c));
      if (reverse) permutation.reverse();
      const label = {rows, cols, name, flipRows, flipCols, reverse}; add(permutation, {...label, inverse: false});
      const inverse = new Array(451); permutation.forEach((v, i) => {inverse[v] = i;}); add(inverse, {...label, inverse: true});
    }
  }
  return [...maps.values()];
}
function search(ids, {seed = 1, restarts = 8, iterations = 30000} = {}) {
  const random = rng(seed), symbols = Math.max(...ids) + 1; assert(symbols <= 26);
  const count = new Array(26).fill(0); ids.forEach(v => count[v]++);
  const frequencyOrder = [...Array(26).keys()].sort((a, b) => count[b] - count[a] || a - b);
  const common = [...'ETAOINSHRDLCUMWFGYPBVKJXQZ'].map(c => c.charCodeAt(0) - 65);
  const starts = Array.from({length: 26}, () => new Set());
  ids.forEach((v, index) => {for (let i = Math.max(0, index - 3); i <= Math.min(ids.length - 4, index); i++) starts[v].add(i);});
  const affected = Array.from({length: 26}, (_, a) => Array.from({length: 26}, (_, b) => [...new Set([...starts[a], ...starts[b]])]));
  const restartBests = [], improvements = []; let best = null, evaluations = 0, deltaChecks = 0;
  for (let restart = 0; restart < restarts; restart++) {
    let key = shuffle([...Array(26).keys()], random);
    if (restart % 2 === 0) {key = new Array(26); frequencyOrder.forEach((id, i) => {key[id] = common[i];}); for (let n = 0; n < restart * 2; n++) {const a = Math.floor(random() * 26), b = Math.floor(random() * 26); [key[a], key[b]] = [key[b], key[a]];}}
    let current = score(ids, key), local = null;
    const remember = () => {
      if (!local || current > local.total) local = {total: current, score: current / (ids.length - 3), key: key.slice(), text: ids.map(v => String.fromCharCode(65 + key[v])).join(''), restart};
      if (!best || current > best.total) {best = local; improvements.push(best);}
    };
    remember();
    const quad = start => q[((key[ids[start]] * 26 + key[ids[start + 1]]) * 26 + key[ids[start + 2]]) * 26 + key[ids[start + 3]]];
    for (let iteration = 0; iteration < iterations; iteration++) {
      const a = Math.floor(random() * 26), b = Math.floor(random() * 26); if (a === b) continue;
      const positions = affected[a][b]; let before = 0; for (const start of positions) before += quad(start);
      [key[a], key[b]] = [key[b], key[a]]; let after = 0; for (const start of positions) after += quad(start);
      const delta = after - before, temperature = 12 * Math.pow(0.02 / 12, iteration / (iterations - 1)); evaluations++;
      if (delta >= 0 || random() < Math.exp(delta / temperature)) {current += delta; remember();}
      else [key[a], key[b]] = [key[b], key[a]];
      if (iteration % 10000 === 0) {assert(Math.abs(current - score(ids, key)) < 1e-8); deltaChecks++;}
    }
    assert(Math.abs(local.total - score(ids, local.key)) < 1e-8); restartBests.push(local);
  }
  return {best, restartBests, improvements, evaluations, deltaChecks};
}
function controls(options) {
  const passages = [
    'THEUNANIMOUSDECLARATIONOFTHETHIRTEENUNITEDSTATESOFAMERICAWHENINTHECOURSEOFHUMANEVENTSITBECOMESNECESSARYFORONEPEOPLETODISSOLVETHEPOLITICALBANDSWHICHHAVECONNECTEDTHEMWITHANOTHERANDTOASSUMEAMONGTHEPOWERSOFTHEEARTHTHESEPARATEANDEQUALSTATIONTOWHICHTHELAWSOFNATUREANDOFNATURESGODENTITLETHEMADECENTRESPECTTOTHEOPINIONSOFMANKINDREQUIRESTHATTHEYSHOULDDECLARETHECAUSESWHICHIMPELTHEMTOTHESEPARATIONWEHOLDTHESETRUTHSTOBESELFEVIDENTTHATALLMENARECREATEDEQUALTHATTHEYAREENDOWEDBYTHEIRCREATORWITHCERTAINUNALIENABLERIGHTS',
    input.phase32_text.replace(/[^a-z]/gi, '').toUpperCase(),
    'ALICEWASBEGINNINGTOGETVERYTIREDOFSITTINGBYHERSISTERONTHEBANKANDOFHAVINGNOTHINGTODOONCEORTWICESHEHADPEEPEDINTOTHEBOOKHERSISTERWASREADINGBUTITHADNOPICTURESORCONVERSATIONSINITANDWHATISTHEUSEOFABOOKTHOUGHTALICEWITHOUTPICTURESORCONVERSATIONSSOSHEWASCONSIDERINGINHEROWNMINDASWELLASSHECOULDFORTHEHOTDAYMADEHERFEELVERYSLEEPYANDSTUPIDWHETHERTHEPLEASUREOFMAKINGADAISYCHAINWOULDBEWORTHTHETROUBLEOFGETTINGUPANDPICKINGTHEDAISIESWHENSUDDENLYAWHITERABBITWITHPINKEYESRANCLOSEBYHER'
  ];
  const records = passages.map((source, index) => {
    const text = source.replace(/J/g, 'I').slice(0, 451); assert.equal(text.length, 451);
    const alphabet = shuffle([...'ABCDEFGHIKLMNOPQRSTUVWXYZ'], rng(811 + index)), ids = [...text].map(c => alphabet.indexOf(c));
    assert(ids.every(i => i >= 0)); const result = search(ids, {seed: 4001 + index, ...options});
    const accuracy = [...text].filter((c, i) => c === result.best.text[i]).length / text.length;
    console.log(JSON.stringify({control: index, accuracy, score: result.best.score, expectedScore: score(ids, alphabet.map(c => c.charCodeAt(0) - 65)) / 448}));
    return {index, text, alphabet, ids, accuracy, ...result};
  });
  fs.mkdirSync(out, {recursive: true}); fs.writeFileSync(path.join(out, 'controls.json'), JSON.stringify({options, records}, null, 2) + '\n');
  return records;
}
function main() {
  const options = {restarts: 8, iterations: 30000};
  if (process.argv[2] === 'controls') {controls(options); return;}
  if (process.argv[2] === 'routes') {console.log(JSON.stringify({routes: routes().length})); return;}
  assert.equal(process.argv[2], 'run');
  const calibration = JSON.parse(fs.readFileSync(path.join(out, 'controls.json'))); assert(calibration.records.every(r => r.accuracy >= 0.99)); assert.deepEqual(calibration.options, options);
  const permutations = routes(), datasets = [];
  for (const sourceReversed of [false, true]) {
    const source = sourceReversed ? [...input.faed].reverse().join('') : input.faed, tokens = parse(source), symbols = [...new Set(tokens)].sort();
    assert.equal(tokens.length, 451); assert.equal(symbols.length, 25); const ids = tokens.map(t => symbols.indexOf(t));
    datasets.push({name: 'real', sourceReversed, symbols, tokens, ids});
    for (let i = 1; i <= 2; i++) datasets.push({name: 'shuffle' + i, sourceReversed, symbols, ids: shuffle(ids, rng(701 + i + Number(sourceReversed) * 1009))});
  }
  const spec = {sourceSHA256: hash(fs.readFileSync(__filename)), inputSHA256: hash(inputBytes), scorerSHA256: hash(qb),
    controlsSHA256: hash(fs.readFileSync(path.join(out, 'controls.json'))), options, routes: permutations, datasets,
    scope: 'Fixed b/g parse, both source directions. 11x41/41x11 grid row/column/snake/spiral routes with flips, reversal and inverse; row-major fill. Arbitrary injective 25-symbol-to-26-letter substitution; finite heuristic search, no zero aliases or other alphabets.'};
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const file = path.join(out, 'cases.jsonl'); fs.writeFileSync(file, ''); const tops = [], candidates = new Map(); let cases = 0;
  for (const data of datasets) {
    let top = null;
    for (let route = 0; route < permutations.length; route++) {
      const ids = permutations[route].permutation.map(i => data.ids[i]), result = search(ids, {seed: 20260916 + route * 101 + Number(data.sourceReversed), ...options});
      const record = {dataset: data.name, sourceReversed: data.sourceReversed, route, ...result};
      fs.appendFileSync(file, JSON.stringify(record) + '\n'); cases++;
      if (!top || result.best.score > top.score) top = {route, ...result.best};
      if (data.name === 'real') for (const r of [...result.improvements, ...result.restartBests]) if (!candidates.has(r.text)) candidates.set(r.text, {text: r.text, score: r.score, sourceReversed: data.sourceReversed, route});
      if (cases % 8 === 0) console.log(JSON.stringify({cases, dataset: data.name, sourceReversed: data.sourceReversed, route, top: top.score, head: top.text.slice(0,80)}));
    }
    tops.push({dataset: data.name, sourceReversed: data.sourceReversed, best: top});
  }
  fs.writeFileSync(path.join(out, 'candidates.json'), JSON.stringify([...candidates.values()], null, 2) + '\n');
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify({cases, routes: permutations.length, candidates: candidates.size, tops, finalPasswordFound: false}, null, 2) + '\n');
  console.log(JSON.stringify({complete: true, cases, candidates: candidates.size, tops: tops.map(t => ({dataset: t.dataset, reversed: t.sourceReversed, score: t.best.score}))}));
}
module.exports = {parse, routes, search, score};
if (require.main === module) main();
