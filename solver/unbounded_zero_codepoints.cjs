'use strict';
// Dominating relaxation: every symbol occurrence may be zero or its positive digit.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { definitions: primeDefinitions, book } = require('./prime_codepoints.cjs');
const { machine } = require('./rsa_pending_dfa.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/unbounded_zero_codepoints_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
function definitions() {
  const defs = primeDefinitions();
  for (const mode of ['lettersSpace', 'printable', 'ascii']) {
    let chars = mode === 'ascii' ? [9, 10, 13, ...Array.from({ length: 95 }, (_, i) => i + 32)] : Array.from({ length: 95 }, (_, i) => i + 32);
    if (mode === 'lettersSpace') chars = chars.filter(c => c === 32 || c >= 65 && c <= 90 || c >= 97 && c <= 122);
    defs.push({ name: 'decimalASCII/' + mode, entries: chars.map(m => ({ m, c: m })) });
  }
  return defs;
}
function parse(source, words, mapping, enumerate = false) {
  const dp = Array(source.length + 1).fill(0n), edges = Array.from({ length: source.length }, () => []); dp[source.length] = 1n;
  for (let at = source.length - 1; at >= 0; at--) for (const w of words) {
    const end = at + w.word.length; if (end > source.length || !dp[end]) continue;
    if ([...w.word].every((d, i) => d === '0' || +d === mapping[source[at + i]])) { edges[at].push({ ...w, end }); dp[at] += dp[end]; }
  }
  if (!dp[0]) return { paths: '0', witnessHex: null, texts: [] };
  let at = 0; const witness = []; while (at < source.length) { const e = edges[at][0]; assert(e); witness.push(e.m); at = e.end; }
  const texts = [];
  if (enumerate) {
    assert(dp[0] <= 100000n, 'Output bound reached: no exhaustive claim'); const bytes = [];
    function visit(pos) { if (pos === source.length) { texts.push(Buffer.from(bytes).toString('hex')); return; } for (const e of edges[pos]) { bytes.push(e.m); visit(e.end); bytes.pop(); } }
    visit(0); assert.equal(BigInt(texts.length), dp[0]);
  }
  return { paths: String(dp[0]), witnessHex: Buffer.from(witness).toString('hex'), texts };
}
function controls(words, m) {
  let checked = 0;
  for (const mapping of [[1, 2, 3, 4, 5, 6, 7, 8, 9], [9, 8, 7, 6, 5, 4, 3, 2, 1]]) {
    const inverse = new Map(mapping.map((v, i) => [String(v), i])); let zero = 0;
    const source = words.flatMap(w => [...w.word].map(d => d === '0' ? zero++ % 9 : inverse.get(d)));
    let state = 1; for (const c of source) state = m.transition[state * 18 + mapping[c] + 8]; assert(m.accepting[state]); assert(BigInt(parse(source, words, mapping).paths) > 0n); checked++;
  }
  for (let seed = 0; seed < 64; seed++) {
    const mapping = Array.from({ length: 9 }, (_, i) => (i + seed) % 9 + 1), source = Array.from({ length: 1 + seed % 11 }, (_, i) => (seed + 3 * i + i * i) % 9); let state = 1;
    for (const c of source) state = m.transition[state * 18 + mapping[c] + 8]; assert.equal(Boolean(m.accepting[state]), BigInt(parse(source, words, mapping).paths) > 0n); checked++;
  }
  return checked;
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'summary.json')), 'Inspect existing campaign first');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), defs = definitions(), models = []; let checked = 0;
  for (const [definition, def] of defs.entries()) for (const format of ['minimal', 'padded']) {
    const words = book(def, format), dfa = machine(words); checked += controls(words, dfa);
    for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) {
      const source = [...input[field]].map(c => c.charCodeAt(0) - 97); if (reverse) source.reverse();
      models.push({ index: models.length, definition, name: def.name, format, field, reverse, source, words, dfa, compatibleMappings: 0, first: null, knownMapCompatible: false });
    }
  }
  const spec = { scope: 'Thirteen explicit one-character codebooks, whole DBBI/FAED in both directions, minimal or three-digit padded decimal. Every one of9! a..i positive-digit bijections; independently EACH symbol occurrence may be zero or its assigned positive digit. This dominates every subset of zero-capable letters. No symbol deletion, transposition, arbitrary prime offset or extra encoding. Alphabet26/zero admits all-space degeneracy. Compatibility is not a recovered password.', definitions: defs, models: models.map(({ source, words, dfa, compatibleMappings, first, knownMapCompatible, ...r }) => r), controls: checked, inputSHA256: sha(inputRaw), sources: Object.fromEntries(['unbounded_zero_codepoints.cjs', 'prime_codepoints.cjs', 'rsa_pending_dfa.cjs'].map(f => [f, sha(fs.readFileSync(path.join(__dirname, f)))])) };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const flags = Buffer.alloc(models.length * 362880), mapping = new Uint8Array(9), used = new Uint8Array(10), printable = [], start = Date.now(); let rank = 0;
  function visit(at) {
    if (at < 9) { for (let d = 1; d <= 9; d++) if (!used[d]) { used[d] = 1; mapping[at] = d; visit(at + 1); used[d] = 0; } return; }
    for (const r of models) {
      let state = 1; for (const c of r.source) { state = r.dfa.transition[state * 18 + mapping[c] + 8]; if (!state) break; }
      const yes = r.dfa.accepting[state]; flags[r.index * 362880 + rank] = yes;
      if (yes) {
        r.compatibleMappings++; if (!rank) r.knownMapCompatible = true;
        if (!r.first) r.first = { rank, mapping: [...mapping], ...parse(r.source, r.words, [...mapping]) };
        if (r.name === 'decimalASCII/printable') { const result = parse(r.source, r.words, [...mapping]); printable.push({ index: r.index, rank, mapping: [...mapping], ...result }); }
      }
    }
    rank++;
  }
  visit(0); assert.equal(rank, 362880);
  fs.writeFileSync(path.join(out, 'flags.bin'), flags); fs.writeFileSync(path.join(out, 'printable_candidates.json'), JSON.stringify(printable, null, 2) + '\n');
  const results = models.map(({ source, words, dfa, ...r }) => ({ ...r, status: r.compatibleMappings ? 'compatible' : 'excluded', flagsSHA256: sha(flags.subarray(r.index * 362880, (r.index + 1) * 362880)) }));
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(results, null, 2) + '\n');
  const oldRaw = fs.readFileSync(path.join(root, '_work/substituted_codepoints_2026-09-16/accepted.json')), old = JSON.parse(oldRaw), oldTexts = new Set(old.flatMap(r => r.texts)), witnesses = new Set(printable.map(r => r.witnessHex));
  const summary = { complete: true, models: models.length, decisions: flags.length, excludedModels: results.filter(r => r.status === 'excluded').length, compatibleModels: results.filter(r => r.status === 'compatible').length, printableMappings: printable.length, printablePaths: printable.reduce((n, r) => n + BigInt(r.paths), 0n).toString(), distinctSavedPrintableWitnesses: witnesses.size, priorDistinctPrintableTexts: oldTexts.size, newSavedPrintableWitnesses: [...witnesses].filter(t => !oldTexts.has(t)).length, printableEnumerationComplete: false, oldAcceptedSHA256: sha(oldRaw), flagsSHA256: sha(flags), resultsSHA256: sha(fs.readFileSync(path.join(out, 'results.json'))), printableSHA256: sha(fs.readFileSync(path.join(out, 'printable_candidates.json'))), elapsedMs: Date.now() - start };
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'); console.log(JSON.stringify(summary));
}
if (require.main === module) main();
module.exports = { definitions, parse };
