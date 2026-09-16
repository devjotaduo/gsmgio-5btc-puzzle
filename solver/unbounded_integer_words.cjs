'use strict';
// A conditional language model, not a decryption or authentication oracle.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), zlib = require('node:zlib');
const assert = require('node:assert/strict');
const { bytes } = require('./unbounded_zero_integer.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/unbounded_integer_words_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const separators = [9, 10, 13, 32, 33, 34, 39, 40, 41, 44, 45, 46, 47, 58, 59, 63, ...Array.from({ length: 10 }, (_, i) => 48 + i)].sort((a, b) => a - b);
function vocabulary(threshold = 0) {
  const raw = fs.readFileSync(path.join(root, '_work/checkerboard_exact_mask_2026-09-16/count_1w.txt'));
  assert.equal(sha(raw), '51df159fd3de12b20e403c108f526e96dbd723d9cabdd5f17955cdc16059e690');
  const words = new Map();
  for (const line of raw.toString().trim().split(/\r?\n/)) {
    const [word, count] = line.split(/\s+/);
    if (+count >= threshold && /^[a-z]+$/.test(word) && word.length <= 32 && (word.length > 1 || word === 'a' || word === 'i')) words.set(word, +count);
  }
  const capacity = 805575, first = new Uint32Array(capacity), next = new Uint32Array(capacity), letter = new Uint8Array(capacity), terminal = new Uint8Array(capacity), distance = new Uint8Array(capacity);
  let size = 1, previous = '', chain = [0]; terminal[0] = 1;
  for (const word of [...words.keys()].sort()) {
    let common = 0; while (common < word.length && common < previous.length && word[common] === previous[common]) common++;
    chain.length = common + 1;
    for (let i = common; i < word.length; i++) {
      const at = size++; assert(at < capacity); const parent = chain.at(-1);
      letter[at] = word.charCodeAt(i) - 32; next[at] = first[parent]; first[parent] = at; chain.push(at);
    }
    terminal[chain.at(-1)] = 1; previous = word;
  }
  for (let node = size - 1; node >= 0; node--) {
    distance[node] = terminal[node] ? 0 : 255;
    for (let at = first[node]; at; at = next[at]) distance[node] = Math.min(distance[node], distance[at] + 1);
  }
  const sep = new Set(separators), alphabet = [...separators, ...Array.from({ length: 26 }, (_, i) => 65 + i), ...Array.from({ length: 26 }, (_, i) => 97 + i)].sort((a, b) => a - b);
  function step(node, c) {
    if (c >= 97 && c <= 122) c -= 32;
    if (c >= 65 && c <= 90) { for (let at = first[node]; at; at = next[at]) if (letter[at] === c) return at; return -1; }
    return terminal[node] && sep.has(c) ? 0 : -1;
  }
  function accept(b) { let state = 0; for (const c of b) { state = step(state, c); if (state < 0) return false; } return Boolean(terminal[state]); }
  return { threshold, words, size, corpusSHA256: sha(raw), step, accept, distance, alphabet, terminal };
}
function successor(n, v) {
  const b = [...bytes(n)], states = [0], length = b.length; let failed = length;
  for (let i = 0; i < length; i++) {
    const state = v.step(states[i], b[i]);
    if (state < 0 || v.distance[state] > length - i - 1) { failed = i; break; }
    states.push(state);
  }
  if (failed === length) return n;
  for (let i = failed; i >= 0; i--) {
    for (const c of v.alphabet) {
      if (c <= b[i]) continue;
      let state = v.step(states[i], c);
      if (state < 0 || v.distance[state] > length - i - 1) continue;
      b[i] = c;
      for (let j = i + 1; j < length; j++) {
        let chosen = false;
        for (const d of v.alphabet) {
          const next = v.step(state, d);
          if (next >= 0 && v.distance[next] <= length - j - 1) { b[j] = d; state = next; chosen = true; break; }
        }
        assert(chosen);
      }
      assert(v.terminal[state]); return BigInt('0x' + Buffer.from(b).toString('hex'));
    }
  }
  return BigInt('0x' + Buffer.alloc(length + 1, separators[0]).toString('hex'));
}
function search(source, v, { maxNodes = 200000, maxMs = 10000 } = {}) {
  assert(/^[a-i]+$/.test(source));
  const digits = [...source].map(c => c.charCodeAt(0) - 96), weights = digits.map((d, i) => BigInt(d) * 10n ** BigInt(digits.length - i - 1));
  const tails = Array(digits.length + 1).fill(0n); for (let i = digits.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
  const terminal = [], hits = []; let nodes = 0, excluded = 0n, pending = 0n; const start = Date.now();
  function visit(low, mask) {
    const count = 1n << BigInt(digits.length - mask.length);
    if (nodes >= maxNodes || Date.now() - start >= maxMs) { terminal.push({ mask, status: 'pending' }); pending += count; return; }
    nodes++;
    if (successor(low, v) > low + tails[mask.length]) { terminal.push({ mask, status: 'excluded' }); excluded += count; return; }
    if (mask.length === digits.length) {
      const value = bytes(low); assert(v.accept(value));
      terminal.push({ mask, status: 'hit' }); hits.push({ mask, hex: value.toString('hex'), leadingZeroDigits: mask.indexOf('1') }); return;
    }
    visit(low, mask + '0'); visit(low + weights[mask.length], mask + '1');
  }
  visit(0n, ''); const total = 1n << BigInt(digits.length); assert.equal(excluded + pending + BigInt(hits.length), total);
  return { complete: pending === 0n, nodes, total: String(total), excluded: String(excluded), pending: String(pending), terminal, hits, elapsedMs: Date.now() - start };
}
function controls(v) {
  let grammarChecks = 0, successorComparisons = 0, assignments = 0, exactCases = 0, planted = 0;
  for (const text of ['The matrix has you!', 'Follow the white rabbit.', 'The answer is: 42.', 'aBc', 'I 2 a', '12345', '\t\n', 'th']) {
    const b = Buffer.from(text), expected = [...text].every(c => /[a-z]/i.test(c) || separators.includes(c.charCodeAt(0))) && (text.match(/[a-z]+/gi) || []).every(w => v.words.has(w.toLowerCase()));
    assert.equal(v.accept(b), expected); if (expected) assert.equal(successor(BigInt('0x' + b.toString('hex')), v), BigInt('0x' + b.toString('hex'))); grammarChecks++;
  }
  const finite = [];
  for (let n = 0; n < 65536; n++) if (v.accept(bytes(BigInt(n)))) finite.push(BigInt(n));
  finite.push(0x090909n);
  for (let n = 0n; n < 65536n; n += 97n) { assert.equal(successor(n, v), finite.find(x => x >= n)); successorComparisons++; }
  for (const source of ['abcdefghi', 'debcdf', 'ggggg', 'ihbca']) {
    const expected = [];
    for (let mask = 0; mask < 2 ** source.length; mask++) {
      const n = BigInt([...source].map((c, i) => mask >> i & 1 ? c.charCodeAt(0) - 96 : 0).join('')), b = bytes(n);
      if (v.accept(b)) expected.push(b.toString('hex')); assignments++;
    }
    const actual = search(source, v); assert(actual.complete); assert.deepEqual(actual.hits.map(h => h.hex).sort(), expected.sort()); exactCases++;
  }
  for (const text of ['the', 'ThE', 'I 2', 'Hi!', 'The 42']) {
    assert(v.accept(Buffer.from(text)));
    const hex = Buffer.from(text).toString('hex'), decimal = BigInt('0x' + hex).toString(), source = [...decimal].map((c, i) => String.fromCharCode(c === '0' ? 97 + i % 9 : 96 + +c)).join('');
    const actual = search(source, v); assert(actual.complete); assert(actual.hits.some(h => h.hex === hex)); planted++;
  }
  return { grammarChecks, successorComparisons, enumeratedAssignments: assignments, exactCases, planted };
}
function main() {
  fs.mkdirSync(folder, { recursive: true }); assert(!fs.existsSync(path.join(folder, 'summary.json')), 'Inspect previous experiment before rerunning');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw), cases = [], candidates = new Map(), dictionaries = [];
  const limits = { maxNodes: 200000, maxMs: 10000 };
  for (const threshold of [1000000, 0]) {
    const v = vocabulary(threshold), checks = controls(v), dictionary = threshold ? 'common' : 'full';
    dictionaries.push({ name: dictionary, threshold, words: v.words.size, nodes: v.size, corpusSHA256: v.corpusSHA256, controls: checks });
    for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) {
      const source = reverse ? [...input[field]].reverse().join('') : input[field], result = search(source, v, limits), id = `${field}_${reverse ? 'reverse' : 'forward'}_${dictionary}`, file = id + '.json.gz';
      fs.writeFileSync(path.join(folder, file), zlib.gzipSync(JSON.stringify({ field, reverse, dictionary, threshold, ...result })));
      for (const hit of result.hits) if (!candidates.has(hit.hex)) candidates.set(hit.hex, { id: candidates.size, ...hit, provenance: id });
      const record = { field, reverse, dictionary, threshold, file, ...result, terminal: result.terminal.length, hits: result.hits.length, maxBytes: Math.max(0, ...result.hits.map(h => h.hex.length / 2)), artifactSHA256: sha(fs.readFileSync(path.join(folder, file))) }; cases.push(record); console.log(JSON.stringify(record));
    }
  }
  const spec = { hypothesis: 'Every occurrence independently becomes zero or a1..i9. Whole decimal integer -> minimal big-endian bytes. Every maximal ASCII alphabetic run must be a corpus word (length<=32, single letters a/i only), with arbitrary mixed case. Digits and listed punctuation separate words. Pure nonletter strings are also admitted. No unknown substitution, deletion, additional cipher or transposition.', separators, dictionaries, limits, inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)), limitsOfConclusion: 'Dictionary compatibility is not coherent language or authentication. Missing names, typos, joined words, other languages, punctuation outside the list and non-ASCII data are outside this model. Pending intervals remain unresolved.' };
  fs.writeFileSync(path.join(folder, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  fs.writeFileSync(path.join(folder, 'candidates.json'), JSON.stringify([...candidates.values()], null, 2) + '\n');
  fs.writeFileSync(path.join(folder, 'summary.json'), JSON.stringify({ cases, complete: cases.every(c => c.complete), candidates: candidates.size }, null, 2) + '\n');
}
if (require.main === module) main();
module.exports = { vocabulary, successor, search, controls, separators };
