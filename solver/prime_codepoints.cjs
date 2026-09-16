'use strict';
// Explicit prime-index substitution hypotheses, not a claimed puzzle cipher.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { prepare, search } = require('./rsa_substituted_digits.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/prime_codepoints_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const alpha = m => m === 32 || m >= 65 && m <= 90 || m >= 97 && m <= 122;
function primes(count) { const ps = []; for (let n = 2; ps.length < count; n++) if (!ps.some(p => p * p <= n && n % p === 0)) ps.push(n); return ps; }
function definitions() {
  const p = primes(127), defs = [];
  for (const space of ['absent', 'zero', 'one', 'prime27']) {
    const entries = Array.from({ length: 26 }, (_, i) => ({ m: i + 65, c: p[i] }));
    if (space !== 'absent') entries.push({ m: 32, c: space === 'zero' ? 0 : space === 'one' ? 1 : p[26] });
    defs.push({ name: 'alphabet26/' + space, formula: 'A=p1,...,Z=p26', repertoire: 'uppercase' + (space === 'absent' ? '' : '+space'), space, entries });
  }
  for (const scheme of ['asciiIndex', 'asciiIndexPlus1', 'printableIndex']) for (const repertoire of ['lettersSpace', 'ascii']) {
    let chars = scheme === 'printableIndex' ? Array.from({ length: 95 }, (_, i) => i + 32) : [9, 10, 13, ...Array.from({ length: 95 }, (_, i) => i + 32)];
    if (repertoire === 'lettersSpace') chars = chars.filter(alpha);
    const index = m => scheme === 'asciiIndex' ? m : scheme === 'asciiIndexPlus1' ? m + 1 : m - 31;
    defs.push({ name: scheme + '/' + repertoire, formula: scheme === 'asciiIndex' ? 'c=p_(ASCII)' : scheme === 'asciiIndexPlus1' ? 'c=p_(ASCII+1)' : 'c=p_(ASCII-31)', repertoire, entries: chars.map(m => ({ m, c: p[index(m) - 1] })) });
  }
  return defs;
}
function book(definition, format) {
  const width = String(Math.max(...definition.entries.map(x => x.c))).length;
  return definition.entries.map(({ m, c }) => { const word = format === 'padded' ? String(c).padStart(width, '0') : String(c); return { m, c, word, digits: [...word].map(Number) }; });
}
function filteredEdges(source, words, mapping) {
  const get = prepare(source, words);
  return at => get(at).filter(edge => (mapping === 'unknownAny2' || edge.assignments.every(([letter, digit]) => digit === letter + 1)) && (mapping !== 'knownG' || !(edge.zero & ~(1 << 6))));
}
function checkWitness(source, words, mapping, witness) {
  const pairs = new Map(words.map(w => [w.m + '/' + w.c, w.word])), positives = witness.mapping.filter(Boolean);
  assert.equal(new Set(positives).size, positives.length); assert(positives.every(n => n >= 1 && n <= 9));
  assert(new Set(witness.zeroLetters).size <= 2); if (mapping === 'knownG') assert([...witness.zeroLetters].every(c => c === 'g'));
  let at = 0; const bytes = [];
  for (const b of witness.blocks) {
    const word = pairs.get(b.m + '/' + b.c); assert.notEqual(word, undefined); assert.equal(at + word.length, b.end);
    for (let i = 0; i < word.length; i++) { const symbol = source[at + i], index = symbol.charCodeAt(0) - 97; assert(word[i] === '0' ? witness.zeroLetters.includes(symbol) : witness.mapping[index] === +word[i]); if (word[i] !== '0' && mapping !== 'unknownAny2') assert.equal(+word[i], index + 1); }
    at = b.end; bytes.push(b.m);
  }
  assert.equal(at, source.length); assert.equal(Buffer.from(bytes).toString('hex'), witness.hex);
}
function controls(defs) {
  let planted = 0;
  for (const def of defs) for (const format of ['minimal', 'padded']) for (const mapping of ['knownG', 'knownAny2', 'unknownAny2']) {
    const words = book(def, format), encode = new Map(words.map(w => [w.m, w.word])), text = def.space === 'absent' ? 'THEMATRIXHASYOU' : 'THE MATRIX HAS YOU';
    const alphabet = mapping === 'unknownAny2' ? 'ibgacfdhe' : 'abcdefghi', zero = mapping === 'knownG' ? 'g' : 'be'; let z = 0;
    const source = [...Buffer.from(text)].map(m => encode.get(m).replace(/\d/g, d => d === '0' ? zero[z++ % zero.length] : alphabet[+d - 1])).join('');
    const result = search(source, filteredEdges(source, words, mapping), false, 2000000); assert.equal(result.status, 'compatible'); checkWitness(source, words, mapping, result.witness); planted++;
  }
  return { planted };
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'cases.jsonl')), 'Inspect existing results before restarting');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), defs = definitions(), checked = controls(defs);
  const spec = { scope: 'Explicit one-character prime-index tables listed below. Whole DBBI/FAED in both source directions. Minimal decimal codewords or zero-padded to maximum table code width. Known a..i=1..9 with g zero-capable, known map with up to two arbitrary zero-capable letters, or any bijection with up to two. All zero occurrences independent; all codeword boundaries searched. Canonical uppercase alphabet tables plus stated space conventions; other tables use ASCII or printable-ASCII ranks. No transposition, added key, arbitrary prime offset or symbol deletion. Limits yield unknown, not exclusion.', definitions: defs, mappings: ['knownG', 'knownAny2', 'unknownAny2'], formats: ['minimal', 'padded'], controls: checked, nodeCap: 500000, inputSHA256: sha(inputRaw), sources: Object.fromEntries(['prime_codepoints.cjs', 'rsa_substituted_digits.cjs'].map(f => [f, sha(fs.readFileSync(path.join(__dirname, f)))])) };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n'); const fd = fs.openSync(path.join(out, 'cases.jsonl'), 'wx'); let index = 0, nodes = 0; const tally = {}, start = Date.now();
  for (const [definition, def] of defs.entries()) {
    const group = {};
    for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const format of spec.formats) for (const mapping of spec.mappings) {
      const source = reverse ? [...input[field]].reverse().join('') : input[field], words = book(def, format), width = Math.max(...words.map(w => w.word.length));
      const result = format === 'padded' && source.length % width ? { status: 'excluded', reason: 'length', nodes: 0, witness: null } : search(source, filteredEdges(source, words, mapping), false, spec.nodeCap);
      if (result.witness) checkWitness(source, words, mapping, result.witness);
      fs.writeSync(fd, JSON.stringify({ index, definition, name: def.name, field, reverse, format, mapping, ...result }) + '\n'); index++; nodes += result.nodes;
      tally[result.status] = (tally[result.status] || 0) + 1; group[result.status] = (group[result.status] || 0) + 1;
    }
    console.log(JSON.stringify({ name: def.name, group, nodes, elapsedMs: Date.now() - start }));
  }
  fs.closeSync(fd); const result = { complete: true, allModelsResolved: !tally['unknown-cap'], definitions: defs.length, decisions: index, nodes, tally, elapsedMs: Date.now() - start, casesSHA256: sha(fs.readFileSync(path.join(out, 'cases.jsonl'))) };
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
if (require.main === module) main();
module.exports = { definitions, book, filteredEdges, checkWitness };
