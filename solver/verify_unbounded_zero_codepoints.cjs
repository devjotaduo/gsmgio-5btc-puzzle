'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { definitions: primeTables } = require('./verify_prime_codepoints.cjs');
const { machine: reverseMachine } = require('./verify_rsa_pending_dfa.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/unbounded_zero_codepoints_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
function checkPath(source, words, mapping, hex) {
  const codes = new Map(words.map(w => [w.m, w.word])); let at = 0;
  for (const m of Buffer.from(hex, 'hex')) { const word = codes.get(m); assert(word); for (const d of word) { assert(at < source.length); assert(d === '0' || +d === mapping[source[at]]); at++; } }
  assert.equal(at, source.length);
}
function forwardCount(source, words, mapping) {
  const dp = Array(source.length + 1).fill(0n); dp[0] = 1n;
  for (let at = 0; at < source.length; at++) if (dp[at]) for (const { word } of words) {
    const end = at + word.length; if (end > source.length) continue;
    if ([...word].every((d, i) => d === '0' || +d === mapping[source[at + i]])) dp[end] += dp[at];
  }
  return dp[source.length];
}
function main() {
  const read = f => JSON.parse(fs.readFileSync(path.join(out, f))), spec = read('spec.json'), summary = read('summary.json'), results = read('results.json'), printable = read('printable_candidates.json'); assert(summary.complete);
  const flags = fs.readFileSync(path.join(out, 'flags.bin')), raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw);
  assert.equal(sha(flags), summary.flagsSHA256); assert.equal(sha(raw), spec.inputSHA256);
  for (const [f, h] of Object.entries(spec.sources)) assert.equal(sha(fs.readFileSync(path.join(__dirname, f))), h);
  const tables = primeTables();
  for (const mode of ['lettersSpace', 'printable', 'ascii']) {
    const entries = [];
    for (let m = 9; m <= 126; m++) if ((m >= 32 || mode === 'ascii' && [9, 10, 13].includes(m)) && (mode !== 'lettersSpace' || m === 32 || m >= 65 && m <= 90 || m >= 97 && m <= 122)) entries.push({ m, c: m });
    tables.push(entries);
  }
  for (let i = 0; i < tables.length; i++) assert.deepEqual(tables[i], spec.definitions[i].entries);
  const cache = new Map(), models = spec.models.map(r => {
    const key = r.definition + '/' + r.format;
    if (!cache.has(key)) { const width = String(Math.max(...tables[r.definition].map(w => w.c))).length, words = tables[r.definition].map(w => ({ ...w, word: r.format === 'minimal' ? String(w.c) : String(w.c).padStart(width, '0') })); cache.set(key, { words, dfa: reverseMachine(words) }); }
    const source = [...input[r.field]].map(c => c.charCodeAt(0) - 97); if (r.reverse) source.reverse(); return { ...r, ...cache.get(key), source, backwards: [...source].reverse(), count: 0 };
  });
  const factorial = [1]; for (let i = 1; i <= 9; i++) factorial.push(factorial[i - 1] * i);
  const permutation = [1, 2, 3, 4, 5, 6, 7, 8, 9], visited = new Uint8Array(362880); let decisions = 0, count = 0;
  function rank() { let n = 0; for (let i = 0; i < 9; i++) for (let j = i + 1; j < 9; j++) if (permutation[j] < permutation[i]) n += factorial[8 - i]; return n; }
  function test() {
    const pi = rank(); assert(!visited[pi]); visited[pi] = 1; count++;
    for (const m of models) {
      let state = 1; for (const c of m.backwards) { state = m.dfa.transitions[state * 18 + permutation[c] + 8]; if (!state) break; }
      const yes = m.dfa.accepting[state]; assert.equal(flags[m.index * 362880 + pi], yes); decisions++; m.count += yes;
    }
  }
  function heap(n) { if (n === 1) { test(); return; } heap(n - 1); for (let i = 0; i < n - 1; i++) { const j = n % 2 ? 0 : i; [permutation[j], permutation[n - 1]] = [permutation[n - 1], permutation[j]]; heap(n - 1); } }
  heap(9); assert.equal(count, 362880); assert(visited.every(Boolean)); assert.equal(decisions, summary.decisions);
  let witnessChecks = 0;
  for (const r of results) {
    const model = models[r.index]; assert.equal(model.count, r.compatibleMappings); assert.equal(r.knownMapCompatible, Boolean(flags[r.index * 362880]));
    if (r.first) { checkPath(model.source, model.words, r.first.mapping, r.first.witnessHex); assert.equal(String(forwardCount(model.source, model.words, r.first.mapping)), r.first.paths); witnessChecks++; }
  }
  const positiveRanks = new Set(); let paths = 0n;
  for (const r of printable) {
    assert.deepEqual([...r.mapping].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let actualRank = 0; for (let i = 0; i < 9; i++) for (let j = i + 1; j < 9; j++) if (r.mapping[j] < r.mapping[i]) actualRank += factorial[8 - i]; assert.equal(actualRank, r.rank);
    const model = models[r.index]; assert.equal(model.name, 'decimalASCII/printable'); assert.equal(flags[r.index * 362880 + r.rank], 1); const key = r.index + '/' + r.rank; assert(!positiveRanks.has(key)); positiveRanks.add(key);
    const n = forwardCount(model.source, model.words, r.mapping); assert.equal(String(n), r.paths); paths += n; checkPath(model.source, model.words, r.mapping, r.witnessHex); witnessChecks++;
  }
  assert.equal(positiveRanks.size, models.filter(r => r.name === 'decimalASCII/printable').reduce((n, r) => n + r.count, 0)); assert.equal(String(paths), summary.printablePaths);
  const oldRaw = fs.readFileSync(path.join(root, '_work/substituted_codepoints_2026-09-16/accepted.json')); assert.equal(sha(oldRaw), summary.oldAcceptedSHA256);
  let oldPathsRetained = 0; for (const r of JSON.parse(oldRaw)) if (r.texts.length) { const model = models.find(m => m.name === 'decimalASCII/printable' && m.format === 'minimal' && m.field === r.field && m.reverse === r.reverse); assert(model); for (const hex of r.texts) { checkPath(model.source, model.words, r.mapping, hex); oldPathsRetained++; } }
  const result = { complete: true, decisions, models: models.length, witnessChecks, printablePathCountsChecked: printable.length, printablePaths: String(paths), previousPrintablePathsRetained: oldPathsRetained, flagsSHA256: sha(flags), verifierSHA256: sha(fs.readFileSync(__filename)), helpers: Object.fromEntries(['verify_prime_codepoints.cjs', 'verify_rsa_pending_dfa.cjs'].map(f => [f, sha(fs.readFileSync(path.join(__dirname, f)))])), method: 'Independent sieve/ASCII codebooks, reverse-codeword automaton with prefix sets, Heap permutations indexed by Lehmer rank. Every flag compared; independent forward DP counts and recodes saved witnesses and old printable paths.' };
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
if (require.main === module) main();
module.exports = { checkPath, forwardCount };
