'use strict';
// Exact finite-domain parsing with an unknown positive-digit bijection.
// A cap yields UNKNOWN, never a negative certificate.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { pow } = require('./rsa_color_blocks.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_substituted_digits_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const alpha = n => n === 32 || n >= 65 && n <= 90 || n >= 97 && n <= 122;
const allowed = [32, ...Buffer.from('etaoinshrdlucmfwypvbgkjqxzETAOINSHRDLUCMFWYPVBGKJQXZ'), ...Array.from({ length: 95 }, (_, i) => i + 32).filter(n => !alpha(n)), 9, 10, 13];
assert.equal(new Set(allowed).size, 98);
const bits = new Uint8Array(512); for (let i = 1; i < bits.length; i++) bits[i] = bits[i >> 1] + (i & 1);
function gcd(a, b) { while (b) [a, b] = [b, a % b]; return a; }
function codebook(n, e, format) {
  const width = String(n - 1).length;
  return allowed.filter(m => m < n).map(m => { const c = pow(m, e, n), word = format === 'padded' ? String(c).padStart(width, '0') : String(c); return { m, c, digits: [...word].map(Number), word }; });
}
function prepare(source, book) {
  const input = [...source].map(c => c.charCodeAt(0) - 97), cache = new Map();
  return at => {
    if (cache.has(at)) return cache.get(at);
    const edges = [];
    for (const b of book) {
      if (at + b.digits.length > input.length) continue;
      const map = new Uint8Array(9), owners = new Uint8Array(10); let zero = 0, okay = true;
      for (const [k, d] of b.digits.entries()) {
        const letter = input[at + k];
        if (d === 0) { zero |= 1 << letter; if (bits[zero] > 2) { okay = false; break; } }
        else {
          if (map[letter] && map[letter] !== d || owners[d] && owners[d] !== letter + 1) { okay = false; break; }
          map[letter] = d; owners[d] = letter + 1;
        }
      }
      if (okay) edges.push({ end: at + b.digits.length, zero, assignments: [...map].flatMap((d, i) => d ? [[i, d]] : []), m: b.m, c: b.c });
    }
    cache.set(at, edges); return edges;
  };
}
function search(source, edgesAt, lettersOnly, cap = 50000) {
  const map = new Uint8Array(9), owners = new Uint8Array(10), dead = new Set(), stack = [];
  let nodes = 0, aborted = false, solution = null;
  function visit(at, zero, packed) {
    if (at === source.length) { solution = { mapping: [...map], zeroLetters: [...source].filter((c, i, a) => a.indexOf(c) === i && (zero >> (c.charCodeAt(0) - 97) & 1)).sort().join(''), blocks: stack.map(b => ({ end: b.end, m: b.m, c: b.c })), hex: Buffer.from(stack.map(b => b.m)).toString('hex') }; return true; }
    const key = at + '/' + zero + '/' + packed;
    if (dead.has(key)) return false;
    if (nodes >= cap) { aborted = true; return false; }
    nodes++;
    for (const edge of edgesAt(at)) {
      if (lettersOnly && !alpha(edge.m)) continue;
      const nextZero = zero | edge.zero; if (bits[nextZero] > 2) continue;
      let okay = true; const added = []; let nextPacked = packed;
      for (const [letter, digit] of edge.assignments) {
        if (map[letter] && map[letter] !== digit || owners[digit] && owners[digit] !== letter + 1) { okay = false; break; }
        if (!map[letter]) { map[letter] = digit; owners[digit] = letter + 1; added.push([letter, digit]); nextPacked += digit * 16 ** letter; }
      }
      if (okay) { stack.push(edge); if (visit(edge.end, nextZero, nextPacked)) return true; stack.pop(); }
      for (const [letter, digit] of added) { map[letter] = 0; owners[digit] = 0; }
      if (aborted) return false;
    }
    dead.add(key); return false;
  }
  const found = visit(0, 0, 0);
  return { status: found ? 'compatible' : aborted ? 'unknown-cap' : 'excluded', nodes, dead: dead.size, witness: solution };
}
function controls() {
  let planted = 0, brute = 0;
  const digitByLetter = [6, 2, 7, 1, 8, 4, 9, 5, 3], letterByDigit = Object.fromEntries(digitByLetter.map((d, i) => [d, String.fromCharCode(97 + i)]));
  for (const n of [543, 6697, 1690721]) for (const format of ['minimal', 'padded']) for (const zeros of ['g', 'be']) {
    const e = 65537, width = String(n - 1).length, text = 'THE MATRIX HAS YOU'; let z = 0;
    const source = [...Buffer.from(text)].map(m => { const c = pow(m, e, n); return (format === 'padded' ? String(c).padStart(width, '0') : String(c)).replace(/\d/g, d => d === '0' ? zeros[z++ % zeros.length] : letterByDigit[d]); }).join('');
    const r = search(source, prepare(source, codebook(n, e, format)), true, 200000); assert.equal(r.status, 'compatible'); planted++;
  }
  // Small sources: enumerate every bijection of the used letters and every zero mask.
  for (const source of ['abb', 'abc', 'aaba', 'bbcc']) for (const format of ['minimal', 'padded']) for (const lettersOnly of [false, true]) {
    const n = 543, e = 17, book = codebook(n, e, format).filter(b => !lettersOnly || alpha(b.m)), lookup = new Set(book.map(b => b.word)), width = String(n - 1).length;
    const used = [...new Set(source)], digits = []; let compatible = false;
    function mappings(i) {
      if (compatible) return;
      if (i < used.length) { for (let d = 1; d <= 9; d++) if (!digits.includes(d)) { digits.push(d); mappings(i + 1); digits.pop(); } return; }
      for (let mask = 0; mask < 2 ** source.length; mask++) {
        const zs = new Set([...source].filter((_, k) => mask >> k & 1)); if (zs.size > 2) continue;
        const word = [...source].map((c, k) => mask >> k & 1 ? '0' : String(digits[used.indexOf(c)])).join(''), good = new Uint8Array(source.length + 1); good[0] = 1;
        for (let at = 0; at < source.length; at++) if (good[at]) for (let len = 1; len <= width && at + len <= source.length; len++) if (lookup.has(word.slice(at, at + len))) good[at + len] = 1;
        if (good[source.length]) { compatible = true; return; }
      }
    }
    mappings(0); const r = search(source, prepare(source, codebook(n, e, format)), lettersOnly); assert.notEqual(r.status, 'unknown-cap'); assert.equal(r.status === 'compatible', compatible); brute++;
  }
  return { planted, exhaustiveSmall: brute };
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'cases.jsonl')), 'Do not overwrite a previous run');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw);
  const oldRaw = fs.readFileSync(path.join(root, '_work/rsa_color_multibyte_2026-09-16/spec.json')), moduli = JSON.parse(oldRaw).moduli;
  const checked = controls(), models = [];
  for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const format of ['minimal', 'padded']) models.push({ field, reverse, format });
  const spec = { inputSHA256: sha(inputRaw), previousSpecSHA256: sha(oldRaw), moduli, models, allowed, modes: ['lettersSpace', 'ascii'], nodesPerSearch: 50000, controls: checked, sourceSHA256: sha(fs.readFileSync(__filename)), scope: 'One ASCII character per modular-power block, all listed invertible exponent classes. Unknown bijection a..i to 1..9, plus zero assigned at any occurrence of at most two letters. Full fields, both source directions, minimal or full-width decimal ciphertext. Exact existence search within declared domain; a reached node cap is UNKNOWN. No multi-character plaintext blocks, arbitrary moduli, transposition or digit deletion.' };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const fd = fs.openSync(path.join(out, 'cases.jsonl'), 'wx'), tally = {}, start = Date.now(); let keys = 0, decisions = 0, nodes = 0;
  for (const mod of moduli) {
    const group = { n: mod.n, keys: 0, decisions: 0, nodes: 0, compatible: 0, excluded: 0, unknown: 0 };
    for (let e = 1; e < mod.lambda; e++) if (gcd(e, mod.lambda) === 1) {
      const books = Object.fromEntries(['minimal', 'padded'].map(format => [format, codebook(mod.n, e, format)]));
      for (const [modelIndex, model] of models.entries()) {
        const source = model.reverse ? [...input[model.field]].reverse().join('') : input[model.field], edgesAt = prepare(source, books[model.format]);
        let alphaResult = null;
        for (const mode of spec.modes) {
          let result;
          if (model.format === 'padded' && source.length % String(mod.n - 1).length) result = { status: 'excluded', nodes: 0, dead: 0, witness: null, reason: 'length' };
          else if (mode === 'ascii' && alphaResult.status === 'compatible') result = { ...alphaResult, nodes: 0, dead: 0, reason: 'lettersSpaceSubset' };
          else result = search(source, edgesAt, mode === 'lettersSpace', spec.nodesPerSearch);
          if (mode === 'lettersSpace') alphaResult = result;
          const row = { keyIndex: keys, modelIndex, n: mod.n, lambda: mod.lambda, e, ...model, mode, ...result };
          fs.writeSync(fd, JSON.stringify(row) + '\n'); decisions++; nodes += result.nodes; group.decisions++; group.nodes += result.nodes; group[result.status === 'unknown-cap' ? 'unknown' : result.status]++;
          const id = [model.field, model.format, mode, result.status].join('/'); tally[id] = (tally[id] || 0) + 1;
        }
      }
      keys++; group.keys++;
    }
    console.log(JSON.stringify({ ...group, elapsedMs: Date.now() - start }));
  }
  fs.closeSync(fd);
  const summary = { complete: true, keys, decisions, nodes, tally, elapsedMs: Date.now() - start, casesSHA256: sha(fs.readFileSync(path.join(out, 'cases.jsonl'))) };
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'); console.log(JSON.stringify(summary));
}
if (require.main === module) main();
module.exports = { prepare, search, codebook };
