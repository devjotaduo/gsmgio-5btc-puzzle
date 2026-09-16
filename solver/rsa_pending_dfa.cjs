'use strict';
// Complete the sixty capped RSA grammar cases with reachable-subset automata.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { pow } = require('./rsa_color_blocks.cjs');
const { parse } = require('./prime_space_dfa.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_pending_dfa_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const ascii = [9, 10, 13, ...Array.from({ length: 95 }, (_, i) => i + 32)];
function book(r) { return ascii.filter(m => m < r.n).map(m => { const c = pow(m, r.e, r.n); return { m, c, word: r.format === 'padded' ? String(c).padStart(String(r.n - 1).length, '0') : String(c) }; }); }
function machine(words) {
  const prefixes = ['']; for (const { word } of words) for (let i = 1; i < word.length; i++) if (!prefixes.includes(word.slice(0, i))) prefixes.push(word.slice(0, i));
  const complete = new Set(words.map(w => w.word));
  const base = prefixes.map(p => Array.from({ length: 10 }, (_, d) => { const v = p + d, j = prefixes.indexOf(v); return (complete.has(v) ? 1n : 0n) | (j > 0 ? 1n << BigInt(j) : 0n); }));
  const states = [0n, 1n], ids = new Map(states.map((s, i) => [s, i])), edges = [];
  for (let at = 0; at < states.length; at++) {
    const next = Array(10).fill(0n);
    for (let j = 0; j < prefixes.length; j++) if (states[at] & (1n << BigInt(j))) for (let d = 0; d < 10; d++) next[d] |= base[j][d];
    for (let op = 0; op < 18; op++) { const mask = next[op % 9 + 1] | (op >= 9 ? next[0] : 0n); if (!ids.has(mask)) { ids.set(mask, states.length); states.push(mask); } edges.push(ids.get(mask)); }
    assert(states.length <= 100000, 'Automaton construction safety bound reached: not an exclusion');
  }
  return { prefixes, transition: Uint32Array.from(edges), accepting: Uint8Array.from(states, s => Number(Boolean(s & 1n))), states: states.length };
}
function accepts(source, mapping, pair, m) {
  const codes = mapping.map((d, i) => d - 1 + (pair.includes(i) ? 9 : 0)); let state = 1;
  for (const symbol of source) { state = m.transition[state * 18 + codes[symbol]]; if (!state) return false; }
  return Boolean(m.accepting[state]);
}
function controls(words, m) {
  let checked = 0;
  for (let seed = 0; seed < 180; seed++) {
    const mapping = Array.from({ length: 9 }, (_, i) => (i + seed % 9) % 9 + 1), pair = [seed % 9, (seed % 9 + 1 + Math.floor(seed / 9) % 8) % 9], source = Array.from({ length: 3 + seed % 12 }, (_, i) => (seed * 7 + i * i + 3 * i) % 9);
    assert.equal(accepts(source, mapping, pair, m), Boolean(parse(source, mapping, pair, words))); checked++;
  }
  const mapping = [6, 2, 7, 1, 8, 4, 9, 5, 3], inverse = new Map(mapping.map((d, i) => [String(d), i])), pair = [1, 4]; let z = 0;
  const source = words.flatMap(w => [...w.word].map(d => d === '0' ? pair[z++ % 2] : inverse.get(d)));
  assert(accepts(source, mapping, pair, m)); assert(parse(source, mapping, pair, words)); return checked + 1;
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'results.jsonl')), 'Inspect completed results before rerunning');
  const oldRaw = fs.readFileSync(path.join(root, '_work/rsa_substituted_digits_2026-09-16/final_status.json')), old = JSON.parse(oldRaw), pending = old.pending;
  assert.equal(pending.length, 60);
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), groups = [], groupMap = new Map();
  for (const row of pending) {
    const words = book(row), signature = [...new Set(words.map(w => w.word))].sort().join(',');
    if (!groupMap.has(signature)) { groupMap.set(signature, groups.length); groups.push({ representative: row, words, signature, rows: [], fields: [] }); }
    const g = groups[groupMap.get(signature)]; g.rows.push(row); if (!g.fields.some(f => f.field === row.field && f.reverse === row.reverse)) g.fields.push({ field: row.field, reverse: row.reverse });
  }
  const pairs = []; for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) pairs.push([a, b]);
  const spec = { scope: 'Exactly the60 previous capped unknown-bijection RSA one-character ASCII models. Enumerates every positive-digit bijection and every pair of zero-capable letters. This covers zero/one/two actually used zero aliases, with all per-occurrence choices and codeword boundaries. No search cap in enumeration. Equivalent decimal word sets share decisions, but witnesses are rebuilt with each original character codebook.', groups, pairs, inputSHA256: sha(inputRaw), previousStatusSHA256: sha(oldRaw), sourceSHA256: sha(fs.readFileSync(__filename)), helperSHA256: sha(fs.readFileSync(path.join(__dirname, 'rsa_color_blocks.cjs'))), parseHelperSHA256: sha(fs.readFileSync(path.join(__dirname, 'prime_space_dfa.cjs'))) };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const fd = fs.openSync(path.join(out, 'results.jsonl'), 'wx'), start = Date.now(); let totalConfigurations = 0;
  for (const [group, g] of groups.entries()) {
    const m = machine(g.words), checked = controls(g.words, m), fields = g.fields.map(f => ({ ...f, source: [...(f.reverse ? [...input[f.field]].reverse().join('') : input[f.field])].map(c => c.charCodeAt(0) - 97), compatible: 0, first: null }));
    const flags = Buffer.alloc(362880 * 36 * fields.length), mapping = new Uint8Array(9), used = new Uint8Array(10), codes = new Uint8Array(9); let offset = 0, permutations = 0;
    function visit(at) {
      if (at < 9) { for (let d = 1; d <= 9; d++) if (!used[d]) { used[d] = 1; mapping[at] = d; visit(at + 1); used[d] = 0; } return; }
      for (const pair of pairs) {
        for (let i = 0; i < 9; i++) codes[i] = mapping[i] - 1 + (pair[0] === i || pair[1] === i ? 9 : 0);
        for (const f of fields) {
          let state = 1; for (let i = 0; i < f.source.length && state; i++) state = m.transition[state * 18 + codes[f.source[i]]];
          const okay = m.accepting[state]; flags[offset++] = okay;
          if (okay) { f.compatible++; if (!f.first) f.first = { mapping: [...mapping], zeroPair: pair }; }
        }
      }
      permutations++;
    }
    visit(0); assert.equal(permutations, 362880); assert.equal(offset, flags.length); totalConfigurations += offset;
    const rows = g.rows.map(row => { const f = fields.find(x => x.field === row.field && x.reverse === row.reverse), witness = f.first ? parse(f.source, f.first.mapping, f.first.zeroPair, book(row)) : null; if (f.first) assert(witness); return { ...row, status: f.compatible ? 'compatible' : 'excluded', configurations: 362880 * 36, compatibleConfigurations: f.compatible, first: f.first, witness }; });
    const result = { group, prefixStates: m.prefixes.length, states: m.states, controls: checked, configurations: offset, flagsSHA256: sha(flags), transitionSHA256: sha(Buffer.from(m.transition.buffer)), rows };
    fs.writeSync(fd, JSON.stringify(result) + '\n'); console.log(JSON.stringify({ group, states: m.states, configurations: totalConfigurations, rows: rows.map(r => [r.index, r.status, r.compatibleConfigurations]), elapsedMs: Date.now() - start }));
  }
  fs.closeSync(fd); const results = fs.readFileSync(path.join(out, 'results.jsonl')), rows = results.toString().trim().split('\n').flatMap(s => JSON.parse(s).rows);
  const summary = { complete: true, groups: groups.length, decisions: rows.length, configurations: totalConfigurations, excluded: rows.filter(r => r.status === 'excluded').length, compatible: rows.filter(r => r.status === 'compatible').length, elapsedMs: Date.now() - start, resultsSHA256: sha(results) };
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'); console.log(JSON.stringify(summary));
}
if (require.main === module) main();
module.exports = { book, machine, accepts };
