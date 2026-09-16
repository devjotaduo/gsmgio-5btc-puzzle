'use strict';
// Reverse-codeword, set-valued NFA; independent BigInt RSA and Heap enumeration.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_pending_dfa_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function book(r) {
  const words = [];
  for (let m = 9; m < Math.min(r.n, 127); m++) if ([9, 10, 13].includes(m) || m >= 32) {
    let a = BigInt(m), e = BigInt(r.e), c = 1n, n = BigInt(r.n); while (e) { if (e & 1n) c = c * a % n; a = a * a % n; e >>= 1n; }
    words.push({ m, c: Number(c), word: r.format === 'padded' ? String(c).padStart(String(r.n - 1).length, '0') : String(c) });
  }
  return words;
}
function machine(words) {
  const complete = new Set(words.map(w => [...w.word].reverse().join(''))), prefixSet = new Set(['']);
  for (const w of complete) for (let i = 1; i < w.length; i++) prefixSet.add(w.slice(0, i));
  const prefix = [...prefixSet].sort(), ids = new Map(prefix.map((s, i) => [s, i])); assert.equal(prefix[0], '');
  const base = prefix.map(p => Array.from({ length: 10 }, (_, d) => { const t = p + d, next = []; if (complete.has(t)) next.push(0); if (ids.has(t)) next.push(ids.get(t)); return next; }));
  const states = [[], [0]], seen = new Map([['', 0], ['0', 1]]), transitions = [];
  for (let at = 0; at < states.length; at++) for (let op = 0; op < 18; op++) {
    const next = new Set(); for (const p of states[at]) { for (const j of base[p][op % 9 + 1]) next.add(j); if (op >= 9) for (const j of base[p][0]) next.add(j); }
    const sorted = [...next].sort((a, b) => a - b), key = sorted.join(','); if (!seen.has(key)) { seen.set(key, states.length); states.push(sorted); } transitions.push(seen.get(key));
    assert(states.length < 100000, 'Unfinished construction, not exclusion');
  }
  return { prefixCount: prefix.length, states: states.length, transitions: Uint32Array.from(transitions), accepting: Uint8Array.from(states, s => Number(s.includes(0))) };
}
function parse(source, words, mapping, pair) {
  const dp = Array(source.length + 1).fill(0n), choice = Array(source.length).fill(null); dp[source.length] = 1n;
  for (let at = source.length - 1; at >= 0; at--) for (const w of words) {
    const end = at + w.word.length; if (end > source.length || !dp[end]) continue;
    if ([...w.word].every((d, i) => d === '0' ? pair.includes(source[at + i]) : +d === mapping[source[at + i]])) { dp[at] += dp[end]; if (!choice[at]) choice[at] = w; }
  }
  if (!dp[0]) return null;
  let at = 0; const blocks = [];
  while (at < source.length) { const w = choice[at]; assert(w); blocks.push({ start: at, end: at + w.word.length, m: w.m, c: w.c }); at += w.word.length; }
  return { paths: String(dp[0]), witnessHex: Buffer.from(blocks.map(b => b.m)).toString('hex'), blocks };
}
function main() {
  const spec = JSON.parse(fs.readFileSync(path.join(out, 'spec.json'))), summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json'))), resultRaw = fs.readFileSync(path.join(out, 'results.jsonl')), results = resultRaw.toString().trim().split('\n').map(JSON.parse);
  assert(summary.complete); assert.equal(sha(resultRaw), summary.resultsSHA256); assert.equal(sha(fs.readFileSync(path.join(__dirname, 'rsa_pending_dfa.cjs'))), spec.sourceSHA256);
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw); assert.equal(sha(raw), spec.inputSHA256);
  assert(!fs.existsSync(path.join(out, 'verification_groups.jsonl')), 'Inspect previous verification first');
  const fd = fs.openSync(path.join(out, 'verification_groups.jsonl'), 'wx'), positiveFD = fs.openSync(path.join(out, 'positive_configurations.jsonl'), 'wx'), start = Date.now();
  let total = 0, decisions = 0, witnesses = 0; const factorial = [1]; for (let i = 1; i <= 9; i++) factorial.push(factorial[i - 1] * i);
  function rank(p) { let n = 0; for (let i = 0; i < 9; i++) for (let j = i + 1; j < 9; j++) if (p[j] < p[i]) n += factorial[8 - i]; return n; }
  for (const [group, g] of spec.groups.entries()) {
    const expected = results[group], words = book(g.representative); assert.deepEqual(words, g.words);
    for (const r of g.rows) assert.equal([...new Set(book(r).map(w => w.word))].sort().join(','), g.signature);
    const m = machine(words), sources = g.fields.map(f => [...(f.reverse ? input[f.field] : [...input[f.field]].reverse().join(''))].map(c => c.charCodeAt(0) - 97));
    const flags = Buffer.alloc(362880 * 36 * sources.length), counts = Array(sources.length).fill(0), visited = new Uint8Array(362880), permutation = [1, 2, 3, 4, 5, 6, 7, 8, 9], options = new Uint8Array(9); let permutations = 0;
    function test() {
      const pi = rank(permutation); assert(!visited[pi]); visited[pi] = 1;
      for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) {
        const pairIndex = a * (17 - a) / 2 + b - a - 1;
        for (let i = 0; i < 9; i++) options[i] = permutation[i] - 1 + (i === a || i === b ? 9 : 0);
        for (let f = 0; f < sources.length; f++) {
          let state = 1; for (const symbol of sources[f]) { state = m.transitions[state * 18 + options[symbol]]; if (!state) break; }
          const okay = m.accepting[state]; flags[(pi * 36 + pairIndex) * sources.length + f] = okay;
          if (okay) {
            counts[f]++; const source = [...sources[f]].reverse(), witness = parse(source, words, permutation, [a, b]); assert(witness); witnesses++;
            fs.writeSync(positiveFD, JSON.stringify({ group, field: g.fields[f].field, reverse: g.fields[f].reverse, permutation: pi, pairIndex, mapping: [...permutation], zeroPair: [a, b], ...witness }) + '\n');
          }
        }
      }
      permutations++;
    }
    function heap(n) { if (n === 1) { test(); return; } heap(n - 1); for (let i = 0; i < n - 1; i++) { const j = n % 2 ? 0 : i; [permutation[j], permutation[n - 1]] = [permutation[n - 1], permutation[j]]; heap(n - 1); } }
    heap(9); assert.equal(permutations, 362880); assert(visited.every(Boolean)); assert.equal(sha(flags), expected.flagsSHA256);
    for (const r of expected.rows) {
      const f = g.fields.findIndex(x => x.field === r.field && x.reverse === r.reverse); assert.equal(counts[f], r.compatibleConfigurations); assert.equal(r.status, counts[f] ? 'compatible' : 'excluded');
      if (r.witness) {
        const original = [...sources[f]].reverse(), own = book(r), reconstructed = parse(original, own, r.first.mapping, r.first.zeroPair); assert(reconstructed); assert.equal(reconstructed.paths, r.witness.paths);
        let at = 0; const bytes = [];
        for (const b of r.witness.blocks) { const w = own.find(x => x.m === b.m && x.c === b.c); assert(w); assert.equal(b.start, at); assert.equal(b.end, at + w.word.length); assert([...w.word].every((d, i) => d === '0' ? r.first.zeroPair.includes(original[at + i]) : +d === r.first.mapping[original[at + i]])); at = b.end; bytes.push(b.m); }
        assert.equal(at, original.length); assert.equal(Buffer.from(bytes).toString('hex'), r.witness.witnessHex);
      }
      decisions++;
    }
    total += flags.length; const report = { group, reversedPrefixStates: m.prefixCount, reversedDFAStates: m.states, configurations: flags.length, positiveConfigurations: counts, flagsSHA256: sha(flags) };
    fs.writeSync(fd, JSON.stringify(report) + '\n'); console.log(JSON.stringify({ ...report, elapsedMs: Date.now() - start }));
  }
  fs.closeSync(fd); fs.closeSync(positiveFD); assert.equal(total, summary.configurations); assert.equal(decisions, 60);
  const report = { complete: true, decisions, comparisons: total, checkedPositiveConfigurations: witnesses, resultsSHA256: summary.resultsSHA256, positiveConfigurationsSHA256: sha(fs.readFileSync(path.join(out, 'positive_configurations.jsonl'))), verificationGroupsSHA256: sha(fs.readFileSync(path.join(out, 'verification_groups.jsonl'))), verifierSHA256: sha(fs.readFileSync(__filename)), elapsedMs: Date.now() - start, method: 'Independent BigInt codebooks, reversed source/codewords, prefix sets instead of bitmasks, Heap permutations indexed by Lehmer rank. Every configuration flag reproduced and compared by SHA256. All producer witnesses reencoded, and all positive configurations counted by independent suffix DP with a saved witness.' };
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report));
}
if (require.main === module) main();
module.exports = { book, machine, parse };
