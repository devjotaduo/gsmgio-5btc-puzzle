'use strict';
// Independent prime sieve, fixed-map suffix DP and unknown-map suffix parser.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { search } = require('./verify_rsa_substituted_digits.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/prime_codepoints_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const read = f => JSON.parse(fs.readFileSync(path.join(out, f)));
const lines = f => fs.readFileSync(path.join(out, f), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
function definitions() {
  const sieve = new Uint8Array(1000), primes = [];
  for (let n = 2; n < sieve.length; n++) if (!sieve[n]) { primes.push(n); for (let k = n * n; k < sieve.length; k += n) sieve[k] = 1; }
  const defs = [];
  for (const space of [null, 0, 1, primes[26]]) { const entries = Array.from({ length: 26 }, (_, i) => ({ m: 65 + i, c: primes[i] })); if (space !== null) entries.push({ m: 32, c: space }); defs.push(entries); }
  for (let scheme = 0; scheme < 3; scheme++) for (let alphabet = 0; alphabet < 2; alphabet++) {
    const entries = [];
    for (let m = 9; m <= 126; m++) {
      if (m < 32 && (scheme === 2 || ![9, 10, 13].includes(m))) continue;
      if (!alphabet && !(m === 32 || m >= 65 && m <= 90 || m >= 97 && m <= 122)) continue;
      entries.push({ m, c: primes[scheme === 0 ? m - 1 : scheme === 1 ? m : m - 32] });
    }
    defs.push(entries);
  }
  return defs;
}
function fixed(source, words, onlyG) {
  const seen = new Set(); let nodes = 0;
  function visit(end, zeros) {
    if (!end) return true;
    const key = end + '/' + zeros; if (seen.has(key)) return false; seen.add(key); nodes++;
    for (const { word } of words) {
      const start = end - word.length; if (start < 0) continue;
      let z = zeros, good = true;
      for (let j = 0; j < word.length; j++) {
        const letter = source.charCodeAt(start + j) - 97, digit = +word[j];
        if (digit === 0) { if (onlyG && letter !== 6) { good = false; break; } z |= 1 << letter; if (z.toString(2).replace(/0/g, '').length > 2) { good = false; break; } }
        else if (digit !== letter + 1) { good = false; break; }
      }
      if (good && visit(start, z)) return true;
    }
    return false;
  }
  return { status: visit(source.length, 0) ? 'compatible' : 'excluded', nodes };
}
function main() {
  const spec = read('spec.json'), summary = read('summary.json'), cases = lines('cases.jsonl'), followups = new Map(lines('followup.jsonl').map(x => [x.index, x]));
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), defs = definitions();
  assert.equal(sha(inputRaw), spec.inputSHA256); assert.equal(sha(fs.readFileSync(path.join(out, 'cases.jsonl'))), summary.casesSHA256);
  for (const [i, entries] of defs.entries()) assert.deepEqual(entries, spec.definitions[i].entries);
  const spaceSummary = read('space_dfa_summary.json'), spaceCheck = read('space_dfa_verification.json'), records = lines('space_dfa_results.jsonl');
  assert(spaceSummary.complete && spaceCheck.complete); assert.equal(sha(fs.readFileSync(path.join(out, 'space_dfa_results.jsonl'))), spaceSummary.resultsSHA256);
  const results = [], methods = {}; let nodes = 0;
  for (const row of cases) {
    const source = row.reverse ? [...input[row.field]].reverse().join('') : input[row.field];
    const width = String(Math.max(...defs[row.definition].map(x => x.c))).length;
    const words = defs[row.definition].map(x => ({ ...x, word: row.format === 'padded' ? String(x.c).padStart(width, '0') : String(x.c) }));
    let result;
    if (row.format === 'padded') {
      assert.equal(width, 3);
      if (source.length % width) result = { status: 'excluded', method: 'length' };
      else {
        const symbols = new Set([...source].filter((_, i) => i % width === width - 1));
        const lastDigits = new Set(words.map(x => x.word.at(-1))), positive = [...lastDigits].filter(x => x !== '0').length, capacity = positive + (lastDigits.has('0') ? 2 : 0);
        assert(symbols.size > capacity); result = { status: 'excluded', method: 'lastDigitCapacity', symbols: symbols.size, capacity };
      }
    } else if (row.mapping !== 'unknownAny2') result = { ...fixed(source, words, row.mapping === 'knownG'), method: 'fixedMapSuffixDP' };
    else if (row.definition === 1) result = { status: records.some(x => x.field === row.field && x.reverse === row.reverse) ? 'compatible' : 'excluded', method: 'independentlyVerifiedExhaustiveDFA' };
    else {
      result = { ...search(source, words, 5000000), method: 'independentSuffixParser' };
      if (result.status === 'unknown-cap') result = { ...search([...source].reverse().join(''), words.map(x => ({ ...x, word: [...x.word].reverse().join('') })), 5000000), method: 'independentReversedSuffixParser' };
      assert.notEqual(result.status, 'unknown-cap'); assert.equal(result.witness, null);
    }
    const expected = followups.get(row.index) || row; assert.equal(result.status, expected.status, String(row.index));
    methods[result.method] = (methods[result.method] || 0) + 1; nodes += result.nodes || 0; results.push({ index: row.index, ...result });
  }
  assert.equal(results.length, 240);
  const report = { complete: true, decisions: results.length, excluded: results.filter(r => r.status === 'excluded').length, compatible: results.filter(r => r.status === 'compatible').length, methods, nodes, verifierSHA256: sha(fs.readFileSync(__filename)), helperSHA256: sha(fs.readFileSync(path.join(__dirname, 'verify_rsa_substituted_digits.cjs'))), casesSHA256: summary.casesSHA256, results };
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify({ ...report, results: undefined }));
}
if (require.main === module) main();
module.exports = { definitions, fixed };
