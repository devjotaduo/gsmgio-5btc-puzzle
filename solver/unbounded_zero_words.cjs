'use strict';
// Exact dictionary filter: maximal letter runs are words; decoded punctuation/digits separate them.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { vocabulary } = require('./prime_space_words.cjs');
const { graph } = require('./unbounded_zero_keyformats.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/unbounded_zero_codepoints_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
const isLetter = m => m >= 65 && m <= 90 || m >= 97 && m <= 122, upper = m => m >= 97 ? m - 32 : m;
function better(a, b) { if (!b) return true; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] > b[i]; return false; }
function characters(edges, v) {
  const n = edges.length, dp = Array.from({ length: n + 1 }, () => new Map()); dp[0].set(0, { count: 1n, score: [0, 0, 0], text: '' }); let states = 0;
  function add(at, key, count, score, text) { const old = dp[at].get(key); if (!old) dp[at].set(key, { count, score, text }); else { old.count += count; if (better(score, old.score)) { old.score = score; old.text = text; } } }
  for (let at = 0; at < n; at++) {
    states += dp[at].size;
    for (const [key, r] of dp[at]) {
      const node = Math.floor(key / 2), seenWord = key % 2;
      for (const e of edges[at]) {
        const text = r.text + String.fromCharCode(e.m);
        if (isLetter(e.m)) { const child = v.child(node, upper(e.m)); if (child >= 0) add(e.end, child * 2 + seenWord, r.count, [r.score[0] + 1, r.score[1], r.score[2]], text); }
        else if (!node || !Number.isNaN(v.logp[node])) add(e.end, node ? 1 : seenWord, r.count, [r.score[0], r.score[1] - 1, r.score[2] + (node ? v.logp[node] : 0)], text);
      }
    }
  }
  let count = 0n, best = null;
  for (const [key, r] of dp[n]) {
    const node = Math.floor(key / 2); if (!node && !(key % 2) || node && Number.isNaN(v.logp[node])) continue;
    const score = [r.score[0], r.score[1], r.score[2] + (node ? v.logp[node] : 0)]; count += r.count; if (!best || better(score, best.score)) best = { text: r.text, score };
  }
  return { paths: String(count), best, states };
}
function words(edges, v) {
  const n = edges.length, match = Array.from({ length: n }, () => []);
  for (let start = 0; start < n; start++) {
    function walk(at, node, length) {
      if (!Number.isNaN(v.logp[node])) match[start].push({ end: at, length, logp: v.logp[node] });
      for (const e of edges[at] || []) if (isLetter(e.m)) { const child = v.child(node, upper(e.m)); if (child >= 0) walk(e.end, child, length + 1); }
    }
    walk(start, 0, 0);
  }
  const dp = Array.from({ length: n + 1 }, () => [0n, 0n]), score = Array.from({ length: n + 1 }, () => [null, null]); dp[n][1] = 1n; score[n][1] = [0, 0, 0];
  function add(at, flag, count, candidate) { dp[at][flag] += count; if (better(candidate, score[at][flag])) score[at][flag] = candidate; }
  for (let at = n - 1; at >= 0; at--) for (let flag = 0; flag < 2; flag++) {
    for (const e of edges[at]) if (!isLetter(e.m) && dp[e.end][flag]) { const s = score[e.end][flag]; add(at, flag, dp[e.end][flag], [s[0], s[1] - 1, s[2]]); }
    for (const w of match[at]) {
      if (w.end === n) add(at, flag, 1n, [w.length, 0, w.logp]);
      else for (const e of edges[w.end]) if (!isLetter(e.m) && dp[e.end][1]) { const s = score[e.end][1]; add(at, flag, dp[e.end][1], [w.length + s[0], s[1] - 1, w.logp + s[2]]); }
    }
  }
  return { paths: String(dp[0][0]), score: score[0][0] };
}
function main() {
  const read = f => JSON.parse(fs.readFileSync(path.join(out, f))); assert(read('verification.json').complete); assert(!fs.existsSync(path.join(out, 'word_filter.jsonl')), 'Inspect prior language campaign before rerunning');
  const rows = read('printable_candidates.json'), input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), source = [...input.dbbi].map(c => c.charCodeAt(0) - 97), v = vocabulary(); let controls = 0;
  for (const text of ['THE MATRIX HAS YOU!', 'Follow the white rabbit.', 'The answer is: 42.']) {
    const mapping = [6, 2, 1, 7, 3, 8, 9, 5, 4], inverse = new Map(mapping.map((d, i) => [String(d), i])); let zero = 0;
    const src = [...Buffer.from(text)].flatMap(m => [...String(m)].map(d => d === '0' ? zero++ % 9 : inverse.get(d))), edges = graph(src, mapping), a = characters(edges, v), b = words(edges, v);
    assert(BigInt(a.paths) > 0n); assert.equal(a.paths, b.paths); assert(a.best.score.every((x, i) => Math.abs(x - b.score[i]) < 1e-9)); controls++;
  }
  const fd = fs.openSync(path.join(out, 'word_filter.jsonl'), 'wx'); let positive = 0, states = 0, paths = 0n; const start = Date.now(), bests = [];
  for (const [record, r] of rows.entries()) {
    const edges = graph(source, r.mapping), a = characters(edges, v), b = words(edges, v); assert.equal(a.paths, b.paths); if (a.best) { assert(a.best.score.every((x, i) => Math.abs(x - b.score[i]) < 1e-9)); positive++; bests.push({ record, mapping: r.mapping, ...a.best }); }
    states += a.states; paths += BigInt(a.paths); fs.writeSync(fd, JSON.stringify({ record, rank: r.rank, ...a }) + '\n');
    if ((record + 1) % 720 === 0) console.log(JSON.stringify({ records: record + 1, positive, states, elapsedMs: Date.now() - start }));
  }
  fs.closeSync(fd); bests.sort((a, b) => better(a.score, b.score) ? -1 : better(b.score, a.score) ? 1 : 0);
  const summary = { complete: true, configurations: rows.length, compatibleConfigurations: positive, summedPaths: String(paths), states, controls, corpusSHA256: v.rawSHA256, sourceSHA256: sha(fs.readFileSync(__filename)), resultsSHA256: sha(fs.readFileSync(path.join(out, 'word_filter.jsonl'))), top: bests.slice(0, 12), elapsedMs: Date.now() - start, scope: 'All paths in3600 printable configurations. Every maximal A-Z/a-z run must belong to declared Norvig vocabulary, length<=32, single-letter words only A/I. Any decoded digit/space/punctuation separates words; at least one word required. Exact count and lexicographic optimum: most word letters, fewest nonletters, highest unigram log-probability. Independently cross-checked with whole-word boundary suffix DP. No claim of natural-language completeness or cryptographic validity.' };
  fs.writeFileSync(path.join(out, 'word_filter_summary.json'), JSON.stringify(summary, null, 2) + '\n'); console.log(JSON.stringify(summary));
}
if (require.main === module) main();
module.exports = { characters, words };
