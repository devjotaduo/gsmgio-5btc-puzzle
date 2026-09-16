'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), zlib = require('node:zlib'), assert = require('node:assert/strict');
const base = require('./unbounded_integer_words.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/unbounded_integer_words_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function wordcase(v) {
  const distance = new Uint8Array(v.distance.length * 3), terminal = new Uint8Array(v.terminal.length * 3);
  for (let n = 0; n < v.size; n++) for (let mode = 0; mode < 3; mode++) { distance[n * 3 + mode] = v.distance[n]; terminal[n * 3 + mode] = v.terminal[n]; }
  function step(state, c) {
    const node = Math.floor(state / 3), mode = state % 3, isLower = c >= 97 && c <= 122, isUpper = c >= 65 && c <= 90;
    const next = v.step(node, c); if (next < 0) return -1;
    if (!isLower && !isUpper) return 0;
    if (node === 0) return next * 3 + Number(isUpper);
    if (mode === 0) return isLower ? next * 3 : -1;
    if (mode === 1) return next * 3 + (isUpper ? 2 : 0);
    return isUpper ? next * 3 + 2 : -1;
  }
  function accept(b) { let state = 0; for (const c of b) { state = step(state, c); if (state < 0) return false; } return Boolean(terminal[state]); }
  return { ...v, step, accept, distance, terminal };
}
function controls(v) {
  let grammarChecks = 0, exactCases = 0, assignments = 0, planted = 0;
  for (const text of ['The matrix has you!', 'Follow the white rabbit.', 'The answer is: 42.', 'ThE', 'tHe', 'THE', 'The', 'the', 'I 2 a', '12345']) {
    const b = Buffer.from(text), expected = [...text].every(c => /[a-z]/i.test(c) || base.separators.includes(c.charCodeAt(0))) && (text.match(/[a-z]+/gi) || []).every(w => v.words.has(w.toLowerCase()) && (/^[a-z]+$/.test(w) || /^[A-Z][a-z]*$/.test(w) || /^[A-Z]+$/.test(w)));
    assert.equal(v.accept(b), expected); grammarChecks++;
  }
  for (const source of ['abcdefghi', 'debcdf', 'ggggg', 'ihbca']) {
    const expected = [];
    for (let mask = 0; mask < 2 ** source.length; mask++) {
      const n = BigInt([...source].map((c, i) => mask >> i & 1 ? c.charCodeAt(0) - 96 : 0).join(''));
      let h = n.toString(16); if (h.length % 2) h = '0' + h;
      if (v.accept(Buffer.from(h, 'hex'))) expected.push(h); assignments++;
    }
    const actual = base.search(source, v); assert(actual.complete); assert.deepEqual(actual.hits.map(h => h.hex).sort(), expected.sort()); exactCases++;
  }
  for (const text of ['the', 'THE', 'I 2', 'Hi!', 'The 42']) {
    const hex = Buffer.from(text).toString('hex'), decimal = BigInt('0x' + hex).toString(), source = [...decimal].map((c, i) => String.fromCharCode(c === '0' ? 97 + i % 9 : 96 + +c)).join('');
    const result = base.search(source, v); assert(result.complete && result.hits.some(h => h.hex === hex)); planted++;
  }
  return { grammarChecks, exactCases, enumeratedAssignments: assignments, planted };
}
function main() {
  assert(!fs.existsSync(path.join(folder, 'wordcase_summary.json')), 'Inspect prior wordcase experiment before rerunning');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw), cases = [], dictionaries = [], candidates = new Map(), limits = { maxNodes: 1000000, maxMs: 10000 };
  for (const threshold of [1000000, 0]) {
    const v = wordcase(base.vocabulary(threshold)), dictionary = threshold ? 'common' : 'full';
    dictionaries.push({ name: dictionary, threshold, words: v.words.size, corpusSHA256: v.corpusSHA256, controls: controls(v) });
    for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) {
      const source = reverse ? [...input[field]].reverse().join('') : input[field], result = base.search(source, v, limits), id = `${field}_${reverse ? 'reverse' : 'forward'}_${dictionary}_wordcase`, file = id + '.json.gz';
      fs.writeFileSync(path.join(folder, file), zlib.gzipSync(JSON.stringify({ field, reverse, dictionary, threshold, casing: 'wordcase', ...result })));
      for (const hit of result.hits) if (!candidates.has(hit.hex)) candidates.set(hit.hex, { id: candidates.size, ...hit, provenance: id });
      const record = { field, reverse, dictionary, threshold, file, ...result, terminal: result.terminal.length, hits: result.hits.length, maxBytes: Math.max(0, ...result.hits.map(h => h.hex.length / 2)), artifactSHA256: sha(fs.readFileSync(path.join(folder, file))) }; cases.push(record); console.log(JSON.stringify(record));
    }
  }
  fs.writeFileSync(path.join(folder, 'wordcase_spec.json'), JSON.stringify({ hypothesis: 'Same exact integer and lexical model as spec.json, but each alphabetic run must be all lowercase, Initialcapital, or ALLUPPERCASE. Case may differ between words.', dictionaries, limits, inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)), baseSourceSHA256: sha(fs.readFileSync(path.join(__dirname, 'unbounded_integer_words.cjs'))) }, null, 2) + '\n');
  fs.writeFileSync(path.join(folder, 'wordcase_candidates.json'), JSON.stringify([...candidates.values()], null, 2) + '\n');
  fs.writeFileSync(path.join(folder, 'wordcase_summary.json'), JSON.stringify({ cases, complete: cases.every(c => c.complete), candidates: candidates.size }, null, 2) + '\n');
}
if (require.main === module) main();
module.exports = { wordcase, controls };
