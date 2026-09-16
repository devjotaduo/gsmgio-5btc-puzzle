'use strict';
// Dictionary filter on all paths, respecting spaces actually decoded as zero.
// This is a declared language filter, never an authentication oracle.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/prime_codepoints_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function vocabulary() {
  const raw = fs.readFileSync(path.join(root, '_work/checkerboard_exact_mask_2026-09-16/count_1w.txt'));
  assert.equal(sha(raw), '51df159fd3de12b20e403c108f526e96dbd723d9cabdd5f17955cdc16059e690');
  const words = new Map(); let total = 0;
  for (const line of raw.toString().trim().split(/\r?\n/)) { const [word, count] = line.split('\t'), n = +count; total += n; if (/^[a-z]+$/.test(word) && word.length <= 32 && (word.length > 1 || word === 'a' || word === 'i')) words.set(word.toUpperCase(), (words.get(word.toUpperCase()) || 0) + n); }
  const size = 805575, first = new Uint32Array(size), next = new Uint32Array(size), letter = new Uint8Array(size), logp = new Float64Array(size); logp.fill(NaN);
  let nodes = 1, previous = '', chain = [0];
  for (const [word, count] of [...words].sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)) {
    let common = 0; while (common < word.length && common < previous.length && word[common] === previous[common]) common++;
    chain.length = common + 1;
    for (let i = common; i < word.length; i++) { const at = nodes++; assert(at < size); const parent = chain.at(-1); letter[at] = word.charCodeAt(i); next[at] = first[parent]; first[parent] = at; chain.push(at); }
    logp[chain.at(-1)] = Math.log10(count / total); previous = word;
  }
  assert.equal(nodes, size); assert.equal(words.size, 333296);
  function child(node, c) { for (let at = first[node]; at; at = next[at]) if (letter[at] === c) return at; return -1; }
  return { words, child, logp, rawSHA256: sha(raw), size, total };
}
function edges(source, mapping, aliases, codes) {
  return Array.from({ length: source.length + 1 }, (_, at) => codes.filter(w => at + w.word.length <= source.length && [...w.word].every((d, k) => d === '0' ? aliases.includes(source[at + k]) : +d === mapping[source.charCodeAt(at + k) - 97])).map(w => ({ end: at + w.word.length, m: w.m })));
}
function byCharacters(graph, v) {
  const length = graph.length - 1, dp = Array.from({ length: length + 1 }, () => new Map()); dp[0].set(0, { count: 1n, score: 0, text: '' }); let states = 0;
  function add(at, key, count, score, text) { const old = dp[at].get(key); if (!old) dp[at].set(key, { count, score, text }); else { old.count += count; if (score > old.score) { old.score = score; old.text = text; } } }
  for (let at = 0; at < length; at++) {
    states += dp[at].size;
    for (const [key, r] of dp[at]) {
      const node = Math.floor(key / 2), hasWord = key % 2;
      for (const e of graph[at]) {
        if (e.m === 32) { if (node === 0) add(e.end, hasWord, r.count, r.score, r.text + ' '); else if (!Number.isNaN(v.logp[node])) add(e.end, 1, r.count, r.score + v.logp[node], r.text + ' '); }
        else { const child = v.child(node, e.m); if (child >= 0) add(e.end, child * 2 + hasWord, r.count, r.score, r.text + String.fromCharCode(e.m)); }
      }
    }
  }
  let count = 0n, best = null;
  for (const [key, r] of dp[length]) {
    const node = Math.floor(key / 2); if (node === 0 && !(key % 2) || node !== 0 && Number.isNaN(v.logp[node])) continue;
    const score = r.score + (node ? v.logp[node] : 0); count += r.count; if (!best || score > best.score) best = { text: r.text, score };
  }
  return { count: String(count), best, states };
}
function byWords(graph, v) {
  const length = graph.length - 1, matches = Array.from({ length }, () => []);
  for (let start = 0; start < length; start++) {
    function walk(at, node, word) {
      if (!Number.isNaN(v.logp[node])) matches[start].push({ end: at, word, score: v.logp[node] });
      for (const e of graph[at]) if (e.m !== 32) { const child = v.child(node, e.m); if (child >= 0) walk(e.end, child, word + String.fromCharCode(e.m)); }
    }
    walk(start, 0, '');
  }
  const count = Array.from({ length: length + 1 }, () => [0n, 0n]), score = Array.from({ length: length + 1 }, () => [-Infinity, -Infinity]); count[length][1] = 1n; score[length][1] = 0;
  for (let at = length - 1; at >= 0; at--) for (let flag = 0; flag < 2; flag++) {
    if (graph[at].some(e => e.m === 32)) { count[at][flag] += count[at + 1][flag]; score[at][flag] = score[at + 1][flag]; }
    for (const word of matches[at]) {
      if (word.end === length) { count[at][flag]++; score[at][flag] = Math.max(score[at][flag], word.score); }
      else if (graph[word.end].some(e => e.m === 32)) { count[at][flag] += count[word.end + 1][1]; score[at][flag] = Math.max(score[at][flag], word.score + score[word.end + 1][1]); }
    }
  }
  return { count: String(count[0][0]), score: score[0][0] };
}
function main() {
  assert(!fs.existsSync(path.join(out, 'word_filter.jsonl')), 'Inspect previous language filter first');
  const spec = JSON.parse(fs.readFileSync(path.join(out, 'space_dfa_spec.json'))), sourceRaw = fs.readFileSync(path.join(out, 'space_dfa_results.jsonl')), rows = sourceRaw.toString().trim().split(/\r?\n/).map(JSON.parse), input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), v = vocabulary();
  let controls = 0;
  for (const text of ['THE MATRIX HAS YOU', 'HELLO WORLD', 'THE PRIME NUMBER']) {
    const mapping = [1, 2, 3, 4, 5, 6, 7, 8, 9], aliases = 'bg', map = new Map(spec.words.map(w => [w.m, w.word])); let z = 0;
    const source = [...Buffer.from(text)].map(c => map.get(c).replace(/\d/g, d => d === '0' ? aliases[z++ % 2] : String.fromCharCode(96 + +d))).join(''), graph = edges(source, mapping, aliases, spec.words), a = byCharacters(graph, v), b = byWords(graph, v); assert(BigInt(a.count) > 0n); assert.equal(a.count, b.count); assert(Math.abs(a.best.score - b.score) < 1e-10); controls++;
  }
  const fd = fs.openSync(path.join(out, 'word_filter.jsonl'), 'wx'); let found = 0, states = 0; const start = Date.now();
  for (const [index, row] of rows.entries()) {
    const source = row.reverse ? [...input[row.field]].reverse().join('') : input[row.field], graph = edges(source, row.mapping, row.zeroLetters, spec.words), a = byCharacters(graph, v), b = byWords(graph, v);
    assert.equal(a.count, b.count); if (a.best) { assert(Math.abs(a.best.score - b.score) < 1e-10); found++; }
    states += a.states; fs.writeSync(fd, JSON.stringify({ index, permutation: row.permutation, pairIndex: row.pairIndex, fieldIndex: row.fieldIndex, ...a, independentlyCountedPaths: b.count }) + '\n');
  }
  fs.closeSync(fd); const result = { complete: true, configurations: rows.length, configurationsWithDictionaryPhrases: found, states, controls, wordCount: v.words.size, trieNodes: v.size, corpusSHA256: v.rawSHA256, configurationsSHA256: sha(sourceRaw), resultsSHA256: sha(fs.readFileSync(path.join(out, 'word_filter.jsonl'))), sourceSHA256: sha(fs.readFileSync(__filename)), elapsedMs: Date.now() - start, scope: 'Each maximal run of decoded letters must be a dictionary word (length<=32, only A/I one-letter words). Spaces must actually come from ciphertext zero code, permitting leading/trailing/multiple spaces. Exact path counts and maximum unigram log-score under this vocabulary, cross-checked by a separate word-boundary suffix DP. Does not establish English meaning and does not cover unknown names, other languages, or messages with words concatenated across a decoded space boundary.' };
  fs.writeFileSync(path.join(out, 'word_filter_summary.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
if (require.main === module) main();
module.exports = { vocabulary, edges, byCharacters, byWords };
