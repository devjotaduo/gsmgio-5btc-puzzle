'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { graph } = require('./matrix_sum_words.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/matrix_sum_words_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
const raw = fs.readFileSync(path.join(root, '_work/ambiguous_checkerboard_2026-09-15/general_english/quadgram.f32'));
assert.equal(sha(raw), 'd2a64e70154725a0c0d1901690df47c73086e0bfc112ad419aad2eb069f89a43'); assert.equal(raw.length, 26 ** 4 * 4);
const quads = Float64Array.from({ length: 26 ** 4 }, (_, i) => raw.readFloatLE(i * 4)); assert(quads.every(Number.isFinite));
const letter = m => m >= 65 && m <= 90 ? m - 65 : m >= 97 && m <= 122 ? m - 97 : -1;
const better = (a, b) => !b || a[0] > b[0] || a[0] === b[0] && a[1] > b[1];
function score(text) {
  const ls = [...Buffer.from(text)].map(letter).filter(i => i >= 0); let q = 0;
  for (let i = 0; i + 3 < ls.length; i++) q += quads[((ls[i] * 26 + ls[i + 1]) * 26 + ls[i + 2]) * 26 + ls[i + 3]];
  return [ls.length, q];
}
function solve(edges) {
  if (edges.some(e => !e.length)) return { strings: '0', best: null, states: 0 };
  let strings = 1n, states = 0, dp = new Map([[0, { len: 0, history: 0, score: [0, 0], text: '' }]]);
  for (const row of edges) {
    strings *= BigInt(row.length); const next = new Map();
    for (const r of dp.values()) for (const e of row) {
      const c = letter(e.m), len = c < 0 ? r.len : Math.min(3, r.len + 1), history = c < 0 ? r.history : (r.history * 26 + c) % (26 ** 3), value = c < 0 ? r.score : [r.score[0] + 1, r.score[1] + (r.len === 3 ? quads[r.history * 26 + c] : 0)], key = len * 26 ** 3 + history, old = next.get(key);
      if (!old || better(value, old.score)) next.set(key, { len, history, score: value, text: r.text + String.fromCharCode(e.m) });
    }
    dp = next; states += dp.size;
  }
  let best = null; for (const r of dp.values()) if (!best || better(r.score, best.score)) best = { text: r.text, score: r.score };
  assert.deepEqual(best.score, score(best.text)); return { strings: String(strings), best, states };
}
function controls() {
  let exactCases = 0, strings = 0;
  for (const n of [4, 6, 8]) for (const alphabet of [[65,84],[32,69],[97,116],[65,9]]) {
    const edges = Array.from({ length: n }, (_, i) => alphabet.map(m => ({ m, end: i + 1 }))); let optimum = null;
    for (let bits = 0; bits < 2 ** n; bits++) { const text = String.fromCharCode(...Array.from({ length: n }, (_, i) => alphabet[bits >> i & 1])), s = score(text); if (better(s, optimum)) optimum = s; strings++; }
    const r = solve(edges); assert.deepEqual(r.best.score, optimum); assert.equal(r.strings, String(2 ** n)); exactCases++;
  }
  const planted = [];
  for (const text of ['FOLLOWTHEWHITERABBIT', 'thematrixhasyou', 'lookattheblueandyellownumbers', 'THEANSWERISINTHEFIRSTPUZZLEPIECE', 'Read the numbers.']) {
    const width = 19, parts = [];
    for (const m of Buffer.from(text)) { const digits = Array(width - 1).fill(1); let remaining = m - digits.length; assert(remaining >= 0); for (let i = 0; i < digits.length; i++) { const extra = Math.min(8, remaining); digits[i] += extra; remaining -= extra; } assert.equal(remaining, 0); parts.push(digits.map(d => String.fromCharCode(96 + d)).join('') + 'g'); }
    const source = parts.join(''), p = { groups: parts.map((_, i) => Array.from({ length: width }, (_, j) => i * width + j)) }, edges = graph(source,p,'g','ascii');
    assert([...Buffer.from(text)].every((m,i) => edges[i].some(e => e.m === m))); const r = solve(edges); assert(!better(score(text), r.best.score));
    planted.push({ text, recovered: r.best.text, exact: text === r.best.text, matchingFraction: [...text].filter((c,i) => c===r.best.text[i]).length / text.length });
  }
  return { exactCases, enumeratedStrings: strings, planted };
}
function main() {
  assert(!fs.existsSync(path.join(folder, 'quadgrams.json')), 'Inspect previous quadgram result first');
  const spec = JSON.parse(fs.readFileSync(path.join(folder,'spec.json'))), rows = JSON.parse(fs.readFileSync(path.join(folder,'results.json'))), input = JSON.parse(fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json'))), results = [], checks = controls();
  for (const r of rows) if (r.threshold === 1000000 && r.grammar === 'strict') {
    const { id, field, partition, zeroLetter, format } = r, p = spec.layouts[field][partition], edges = graph(input[field],p,zeroLetter,format);
    results.push({ id, field, partition, zeroLetter, format, ...solve(edges) });
  }
  const result = { complete:true, hypothesis:'Same rectangular sum domains as spec.json; remove dictionary constraints. Exact dynamic-programming optimum: maximize number of ASCII letters, then their A-Z quadgram log-score, case-insensitive and ignoring nonletters between letters. This is a ranking, not proof of English or authentication. Counts are distinct sum/code strings, not zero masks; only one optimum per configuration is selected.', configurations:results.length, compatible:results.filter(r=>r.best).length, controls:checks, profileSHA256:sha(raw), sourceSHA256:sha(fs.readFileSync(__filename)), results };
  fs.writeFileSync(path.join(folder,'quadgrams.json'),JSON.stringify(result,null,2)+'\n'); console.log(JSON.stringify({...result,results:undefined}));
}
if (require.main === module) main();
module.exports = { solve, score, controls };
