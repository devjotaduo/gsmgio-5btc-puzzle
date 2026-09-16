'use strict';
// Literal rectangular sum-list hypothesis. Lexical compatibility is not authentication.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { vocabulary: makeVocabulary } = require('./unbounded_integer_words.cjs');
const strict = require('./unbounded_zero_words.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/matrix_sum_words_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const isLetter = m => m >= 65 && m <= 90 || m >= 97 && m <= 122, upper = m => m >= 97 && m <= 122 ? m - 32 : m;
function better(a, b) { if (!b) return true; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] > b[i]; return false; }
function partitions(length) {
  const found = new Map();
  for (let width = 2; width < length; width++) if (length % width === 0) {
    const height = length / width;
    for (const snake of [false, true]) {
      const grid = Array.from({ length: height }, (_, r) => Array.from({ length: width }, (_, c) => r * width + (snake && r % 2 ? width - 1 - c : c)));
      for (const axis of ['rows', 'columns']) for (const reverse of [false, true]) {
        let groups = axis === 'rows' ? grid : Array.from({ length: width }, (_, c) => grid.map(r => r[c]));
        groups = groups.map(g => [...g].sort((a, b) => a - b)); if (reverse) groups.reverse();
        const id = JSON.stringify(groups); if (!found.has(id)) found.set(id, { id: found.size, width, height, snake, axis, reverse, groups });
      }
    }
  }
  return [...found.values()];
}
const primes = []; for (let p = 2; primes.length < 26; p++) if (!primes.some(q => q * q <= p && p % q === 0)) primes.push(p);
function code(sum, format) {
  if (format === 'ascii') return sum >= 32 && sum <= 126 || [9, 10, 13].includes(sum) ? sum : null;
  if (sum === 0) return 32;
  if (format === 'a1z26') return sum >= 1 && sum <= 26 ? 64 + sum : null;
  assert.equal(format, 'prime-codepoint'); const i = primes.indexOf(sum); return i >= 0 ? 65 + i : null;
}
function graph(source, partition, zeroLetter, format) {
  const weight = zeroLetter.charCodeAt(0) - 96;
  return partition.groups.map((group, at) => {
    const total = group.reduce((s, i) => s + source.charCodeAt(i) - 96, 0), count = group.filter(i => source[i] === zeroLetter).length;
    return Array.from({ length: count + 1 }, (_, removed) => ({ end: at + 1, sum: total - removed * weight, removed, m: code(total - removed * weight, format) })).filter(e => e.m !== null);
  });
}
function vocabulary(threshold) {
  const v = makeVocabulary(threshold), logp = new Float64Array(v.size); logp.fill(NaN);
  const total = [...v.words.values()].reduce((a, b) => a + b, 0);
  function child(node, c) { assert(c >= 65 && c <= 90); return v.step(node, c); }
  for (const [word, count] of v.words) { let node = 0; for (const c of Buffer.from(word.toUpperCase())) node = child(node, c); assert(node > 0); logp[node] = Math.log10(count / total); }
  return { child, logp, wordCount: v.words.size, corpusSHA256: v.corpusSHA256, threshold, total };
}
function joinedCharacters(edges, v) {
  const n = edges.length, dp = Array.from({ length: n + 1 }, () => new Map()); dp[0].set(0, { count: 1n, score: [0, 0, 0], text: '', segmented: '' }); let states = 0;
  function add(at, key, count, score, text, segmented) { const old = dp[at].get(key); if (!old) dp[at].set(key, { count, score, text, segmented }); else { old.count += count; if (better(score, old.score)) Object.assign(old, { score, text, segmented }); } }
  for (let at = 0; at <= n; at++) {
    // Epsilon word boundary: terminal non-root -> root; no root self-loop.
    for (const [key, r] of [...dp[at]]) {
      const node = Math.floor(key / 2); if (node && !Number.isNaN(v.logp[node])) add(at, 1, r.count, [r.score[0], r.score[1], r.score[2] + v.logp[node]], r.text, r.segmented + ' ');
    }
    states += dp[at].size; if (at === n) break;
    for (const [key, r] of dp[at]) {
      const node = Math.floor(key / 2), flag = key % 2;
      for (const e of edges[at]) {
        const c = String.fromCharCode(e.m);
        if (isLetter(e.m)) { const child = v.child(node, upper(e.m)); if (child >= 0) add(e.end, child * 2 + flag, r.count, [r.score[0] + 1, r.score[1], r.score[2]], r.text + c, r.segmented + c); }
        else if (!node) add(e.end, flag, r.count, [r.score[0], r.score[1] - 1, r.score[2]], r.text + c, r.segmented + c);
      }
    }
  }
  const r = dp[n].get(1); return { paths: String(r?.count || 0n), best: r ? { text: r.text, segmented: r.segmented.trim(), score: r.score } : null, states };
}
function joinedWords(edges, v) {
  const n = edges.length, dp = Array.from({ length: n + 1 }, () => [0n, 0n]), scores = Array.from({ length: n + 1 }, () => [null, null]); dp[0][0] = 1n; scores[0][0] = [0, 0, 0];
  function add(at, flag, count, score) { dp[at][flag] += count; if (better(score, scores[at][flag])) scores[at][flag] = score; }
  for (let at = 0; at < n; at++) {
    if (!dp[at][0] && !dp[at][1]) continue;
    for (let flag = 0; flag < 2; flag++) if (dp[at][flag]) for (const e of edges[at]) if (!isLetter(e.m)) { const s = scores[at][flag]; add(e.end, flag, dp[at][flag], [s[0], s[1] - 1, s[2]]); }
    function walk(end, node, length) {
      if (node && !Number.isNaN(v.logp[node])) for (let flag = 0; flag < 2; flag++) if (dp[at][flag]) { const s = scores[at][flag]; add(end, 1, dp[at][flag], [s[0] + length, s[1], s[2] + v.logp[node]]); }
      for (const e of edges[end] || []) if (isLetter(e.m)) { const child = v.child(node, upper(e.m)); if (child >= 0) walk(e.end, child, length + 1); }
    }
    walk(at, 0, 0);
  }
  return { paths: String(dp[n][1]), score: scores[n][1] };
}
function checkAgreement(a, b) { assert.equal(a.paths, b.paths); assert.equal(Boolean(a.best), Boolean(b.score)); if (a.best) assert(a.best.score.every((s, i) => Math.abs(s - b.score[i]) < 1e-8)); }
function controls(v) {
  let literals = 0, planted = 0, brute = 0;
  for (const text of ['The matrix has you!', 'matrixsumlist', 'followthewhiterabbit', 'The answer is: 42.', 'THERAPIST', '123']) {
    const edges = [...Buffer.from(text)].map((m, i) => [{ m, end: i + 1 }]); checkAgreement(strict.characters(edges, v), strict.words(edges, v)); checkAgreement(joinedCharacters(edges, v), joinedWords(edges, v)); literals++;
    if (text !== '123') assert(BigInt(joinedCharacters(edges, v).paths) > 0n);
  }
  for (const text of ['The matrix has you!', 'matrixsumlist']) {
    // One fixed-width group per desired ASCII byte; one g must be zeroed.
    const width = 15, groups = [], chunks = [];
    for (const c of Buffer.from(text)) { let remainder = c; const ds = Array(width - 1).fill(1); remainder -= ds.length; assert(remainder >= 0 && remainder <= ds.length * 8); for (let i = 0; i < ds.length; i++) { const extra = Math.min(8, remainder); ds[i] += extra; remainder -= extra; } chunks.push(ds.map(d => String.fromCharCode(96 + d)).join('') + 'g'); }
    const source = chunks.join(''); for (let i = 0; i < chunks.length; i++) groups.push(Array.from({ length: width }, (_, j) => i * width + j));
    const edges = graph(source, { groups }, 'g', 'ascii'); assert([...Buffer.from(text)].every((m, i) => edges[i].some(e => e.m === m))); assert(BigInt(joinedCharacters(edges, v).paths) > 0n); planted++;
  }
  for (const alphabet of [[65,66,32],[65,73,84],[65,78,68]]) {
    const edges = Array.from({ length: 4 }, (_, i) => alphabet.map(m => ({ m, end: i + 1 }))); let strictCount = 0n, joinedCount = 0n;
    for (let i = 0; i < alphabet.length ** 4; i++) {
      let x = i; const singleton = edges.map((_, j) => { const m = alphabet[x % alphabet.length]; x = Math.floor(x / alphabet.length); return [{ m, end: j + 1 }]; });
      strictCount += BigInt(strict.characters(singleton, v).paths); joinedCount += BigInt(joinedWords(singleton, v).paths); brute++;
    }
    assert.equal(strict.characters(edges, v).paths, String(strictCount)); assert.equal(joinedCharacters(edges, v).paths, String(joinedCount));
  }
  return { literals, planted, enumeratedStrings: brute };
}
function main() {
  fs.mkdirSync(folder, { recursive: true }); assert(!fs.existsSync(path.join(folder, 'summary.json')), 'Inspect previous results before rerunning');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw), layouts = Object.fromEntries(['dbbi', 'faed'].map(field => [field, partitions(input[field].length)])), dictionaries = [], records = [], selected = new Map();
  for (const threshold of [1000000, 0]) {
    const v = vocabulary(threshold); dictionaries.push({ threshold, words: v.wordCount, total: v.total, corpusSHA256: v.corpusSHA256, controls: controls(v) });
    for (const field of ['dbbi','faed']) for (const p of layouts[field]) for (const zeroLetter of 'abcdefghi') for (const format of ['ascii','a1z26','prime-codepoint']) {
      const edges = graph(input[field], p, zeroLetter, format), empty = edges.findIndex(e => !e.length);
      for (const grammar of ['strict', 'joined']) {
        const id = records.length, record = { id, field, partition: p.id, zeroLetter, format, threshold, grammar };
        if (empty >= 0) { records.push({ ...record, excludedAtGroup: empty, paths: '0', best: null }); continue; }
        const a = grammar === 'strict' ? strict.characters(edges, v) : joinedCharacters(edges, v), b = grammar === 'strict' ? strict.words(edges, v) : joinedWords(edges, v); checkAgreement(a, b);
        records.push({ ...record, ...a, independentlyCountedPaths: b.paths });
        if (a.best) { const hex = Buffer.from(a.best.text).toString('hex'); if (!selected.has(hex)) selected.set(hex, { id: selected.size, hex, provenance: id, ...a.best }); }
      }
    }
    console.log(JSON.stringify({ threshold, configurations: records.length, compatible: records.filter(r => r.paths !== '0').length, selected: selected.size }));
  }
  const spec = { hypothesis: 'a1..i9 numeric values. Write the complete field in every proper rectangular factorization in row-major or alternating-row order, sum rows or columns, optionally reverse the sum list. In each model, every occurrence of exactly one chosen letter may independently become zero. Decode each sum as ASCII, A1Z26 with zero space, or A=2,...,Z=101 with zero space. No extra key, modulus, offset, omitted cell, arbitrary permutation or mixed digit mapping.', language: 'Two vocabularies; strict maximal alphabetic runs or concatenated dictionary words. At least one word. Joined counts count segmentations, not necessarily distinct decoded texts or zero masks. Best witness maximizes letters, then minimizes nonletters, then unigram log-probability. One best witness per compatible configuration is selected for authentication; other compatible strings are not all tested.', dictionaries, primes, layouts, inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)), dependencies: Object.fromEntries(['unbounded_integer_words.cjs','unbounded_zero_words.cjs'].map(f => [f, sha(fs.readFileSync(path.join(__dirname,f)))])) };
  fs.writeFileSync(path.join(folder, 'spec.json'), JSON.stringify(spec, null, 2) + '\n'); fs.writeFileSync(path.join(folder, 'results.json'), JSON.stringify(records, null, 2) + '\n'); fs.writeFileSync(path.join(folder, 'selected.json'), JSON.stringify([...selected.values()], null, 2) + '\n');
  const summary = { complete: true, configurations: records.length, compatible: records.filter(r => r.paths !== '0').length, alphabetExcluded: records.filter(r => r.excludedAtGroup !== undefined).length, selected: selected.size, layoutCounts: Object.fromEntries(Object.entries(layouts).map(([f,l]) => [f,l.length])), byModel: [] };
  for (const field of ['dbbi','faed']) for (const threshold of [1000000,0]) for (const grammar of ['strict','joined']) for (const format of ['ascii','a1z26','prime-codepoint']) { const rows = records.filter(r => r.field === field && r.threshold === threshold && r.grammar === grammar && r.format === format); summary.byModel.push({field, threshold, grammar, format, configurations: rows.length, compatible: rows.filter(r => r.paths !== '0').length}); }
  fs.writeFileSync(path.join(folder, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'); console.log(JSON.stringify(summary));
}
if (require.main === module) main();
module.exports = { partitions, graph, vocabulary, joinedCharacters, joinedWords, controls, code, primes };
