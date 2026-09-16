'use strict';
// Independent suffix-word parser: string assignments, BigInt codebooks.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_substituted_digits_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const allowed = [9, 10, 13, ...Array.from({ length: 95 }, (_, i) => i + 32)];
const alpha = c => c === 32 || c >= 65 && c <= 90 || c >= 97 && c <= 122;
function power(a, e, n) { let b = BigInt(a), k = BigInt(e), m = BigInt(n), r = 1n; while (k) { if (k & 1n) r = r * b % m; b = b * b % m; k >>= 1n; } return Number(r); }
function gcd(a, b) { while (b) [a, b] = [b, a % b]; return a; }
function book(n, e, format, mode) {
  return allowed.filter(m => m < n && (mode !== 'lettersSpace' || alpha(m))).map(m => { const c = power(m, e, n); return { m, c, word: format === 'padded' ? String(c).padStart(String(n - 1).length, '0') : String(c) }; });
}
function search(source, words, cap = 500000) {
  const local = new Map(), failed = new Set(), route = []; let nodes = 0, hit = null, capped = false;
  function choices(end) {
    if (local.has(end)) return local.get(end);
    const edges = [];
    for (const item of words) {
      const start = end - item.word.length; if (start < 0) continue;
      const pairs = new Map(), owners = new Map(), zero = new Set(); let valid = true;
      for (let k = 0; k < item.word.length; k++) {
        const symbol = source[start + k], digit = item.word[k];
        if (digit === '0') { zero.add(symbol); if (zero.size > 2) { valid = false; break; } }
        else {
          if (pairs.has(symbol) && pairs.get(symbol) !== digit || owners.has(digit) && owners.get(digit) !== symbol) { valid = false; break; }
          pairs.set(symbol, digit); owners.set(digit, symbol);
        }
      }
      if (valid) edges.push({ start, end, pairs: [...pairs], zero: [...zero], ...item });
    }
    local.set(end, edges); return edges;
  }
  function visit(end, assignment, zeros) {
    if (!end) { const blocks = [...route].reverse(); hit = { mapping: [...assignment].map(Number), zeroLetters: zeros, blocks: blocks.map(b => ({ end: b.end, m: b.m, c: b.c })), hex: Buffer.from(blocks.map(b => b.m)).toString('hex') }; return true; }
    const id = end + '/' + assignment + '/' + zeros; if (failed.has(id)) return false;
    if (nodes >= cap) { capped = true; return false; } nodes++;
    for (const edge of choices(end)) {
      const zeroSet = new Set([...zeros, ...edge.zero]); if (zeroSet.size > 2) continue;
      const mapping = [...assignment]; let valid = true;
      for (const [symbol, digit] of edge.pairs) {
        const i = symbol.charCodeAt(0) - 97;
        if (mapping[i] !== '0' && mapping[i] !== digit || mapping.includes(digit) && mapping[i] !== digit) { valid = false; break; }
        mapping[i] = digit;
      }
      if (valid) { route.push(edge); if (visit(edge.start, mapping.join(''), [...zeroSet].sort().join(''))) return true; route.pop(); }
      if (capped) return false;
    }
    failed.add(id); return false;
  }
  visit(source.length, '000000000', '');
  return { status: hit ? 'compatible' : capped ? 'unknown-cap' : 'excluded', nodes, witness: hit };
}
function checkWitness(r, source, witness) {
  assert.equal(witness.mapping.length, 9);
  const positive = witness.mapping.filter(Boolean); assert(positive.every(n => n >= 1 && n <= 9)); assert.equal(new Set(positive).size, positive.length);
  assert(new Set(witness.zeroLetters).size <= 2); let at = 0; const bytes = [];
  for (const block of witness.blocks) {
    assert(allowed.includes(block.m) && block.m < r.n); if (r.mode === 'lettersSpace') assert(alpha(block.m));
    assert.equal(power(block.m, r.e, r.n), block.c);
    const word = r.format === 'padded' ? String(block.c).padStart(String(r.n - 1).length, '0') : String(block.c);
    assert.equal(block.end, at + word.length);
    for (let k = 0; k < word.length; k++) assert(word[k] === '0' ? witness.zeroLetters.includes(source[at + k]) : witness.mapping[source.charCodeAt(at + k) - 97] === +word[k]);
    at = block.end; bytes.push(block.m);
  }
  assert.equal(at, source.length); assert.equal(Buffer.from(bytes).toString('hex'), witness.hex);
}
function main() {
  const spec = JSON.parse(fs.readFileSync(path.join(out, 'spec.json'))), summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json')));
  const raw = fs.readFileSync(path.join(out, 'cases.jsonl')), cases = raw.toString().trim().split(/\r?\n/).map(JSON.parse);
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw);
  assert.equal(sha(raw), summary.casesSHA256); assert.equal(sha(inputRaw), spec.inputSHA256); assert.equal(sha(fs.readFileSync(path.join(__dirname, 'rsa_substituted_digits.cjs'))), spec.sourceSHA256);
  assert(!fs.existsSync(path.join(out, 'verification_cases.jsonl')), 'Inspect previous verification before restarting');
  const fd = fs.openSync(path.join(out, 'verification_cases.jsonl'), 'wx'), cache = new Map(), books = new Map(), tally = {}, start = Date.now();
  let keys = 0, position = 0, checkedWitnesses = 0, independentlySearched = 0, nodes = 0;
  for (const mod of spec.moduli) for (let e = 1; e < mod.lambda; e++) if (gcd(e, mod.lambda) === 1) {
    for (const [modelIndex, model] of spec.models.entries()) for (const mode of spec.modes) {
      const row = cases[position]; assert(row); assert.equal(row.keyIndex, keys); assert.equal(row.modelIndex, modelIndex); assert.equal(row.n, mod.n); assert.equal(row.e, e); assert.equal(row.mode, mode);
      for (const [k, v] of Object.entries(model)) assert.equal(row[k], v);
      const source = model.reverse ? [...input[model.field]].reverse().join('') : input[model.field]; let result;
      if (row.status === 'compatible') {
        checkWitness(row, source, row.witness); checkedWitnesses++; result = { status: 'compatible', method: 'reencryptedProducerWitness', nodes: 0 };
      } else if (model.format === 'padded' && source.length % String(mod.n - 1).length) {
        assert.equal(row.status, 'excluded'); result = { status: 'excluded', method: 'length', nodes: 0 };
      } else {
        const bookId = [mod.n, e, model.format, mode].join('/'); if (!books.has(bookId)) books.set(bookId, book(mod.n, e, model.format, mode));
        const words = books.get(bookId), signature = words.map(x => x.m + ':' + x.word).join(','), id = [model.field, model.reverse, signature].join('/');
        if (!cache.has(id)) { const r = search(source, words, 500000); cache.set(id, r); nodes += r.nodes; independentlySearched++; }
        result = { ...cache.get(id), method: 'independentSuffixSearch' };
        if (result.status === 'compatible') { assert.notEqual(row.status, 'excluded', 'Contradicts producer negative'); checkWitness(row, source, result.witness); checkedWitnesses++; }
      }
      const category = row.status + '/' + result.status; tally[category] = (tally[category] || 0) + 1;
      fs.writeSync(fd, JSON.stringify({ index: position, producerStatus: row.status, ...result }) + '\n'); position++;
    }
    keys++;
    if (keys % 1000 === 0) console.log(JSON.stringify({ keys, decisions: position, independentlySearched, nodes, elapsedMs: Date.now() - start, tally }));
    // Retain identical-codebook outcomes; avoid retaining every large book twice.
    books.clear();
  }
  fs.closeSync(fd); assert.equal(position, cases.length); assert.equal(keys, summary.keys);
  const result = { complete: true, keys, decisions: position, independentlySearched, nodes, checkedWitnesses, tally, elapsedMs: Date.now() - start, casesSHA256: sha(raw), verificationCasesSHA256: sha(fs.readFileSync(path.join(out, 'verification_cases.jsonl'))), verifierSHA256: sha(fs.readFileSync(__filename)), scope: 'Re-encrypt every producer witness. Independently parse all other cases from suffixes with BigInt codebooks. Search caps remain unknown; no capped independent result certifies a negative. Identical codebooks for the same field/direction share outcomes.' };
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
if (require.main === module) main();
module.exports = { search, book, checkWitness };
