'use strict';
// Whole decimal integer, each occurrence independently 0 or a1..i9.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), zlib = require('node:zlib');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/unbounded_zero_integer_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const punctuation = [9, 10, 13, 32, 33, 34, 39, 40, 41, 44, 45, 46, 47, 58, 59, 63];
function alphabets() {
  return [
    ['lowercase-punctuation', [...punctuation, ...Array.from({ length: 26 }, (_, i) => 97 + i)]],
    ['uppercase-punctuation', [...punctuation, ...Array.from({ length: 26 }, (_, i) => 65 + i)]],
    ['numeric-list', [9, 10, 13, 32, 40, 41, 44, 45, 46, 58, 59, 91, 93, ...Array.from({ length: 10 }, (_, i) => 48 + i)]],
    ['hex-lowercase', [...Buffer.from('0123456789abcdef')]],
    ['hex-uppercase', [...Buffer.from('0123456789ABCDEF')]],
  ].map(([name, values]) => ({ name, allowed: [...new Set(values)].sort((a, b) => a - b) }));
}
function bytes(n) { let h = n.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex'); }
function successor(n, allowed) {
  const b = [...bytes(n)];
  for (let at = 0; at < b.length; at++) {
    if (allowed.includes(b[at])) continue;
    for (let j = at; j >= 0; j--) {
      const next = allowed.find(x => x > b[j]);
      if (next === undefined) continue;
      b[j] = next; b.fill(allowed[0], j + 1); return BigInt('0x' + Buffer.from(b).toString('hex'));
    }
    return BigInt('0x' + Buffer.alloc(b.length + 1, allowed[0]).toString('hex'));
  }
  return n;
}
function search(source, allowed, { maxNodes = 200000, maxMs = 10000 } = {}) {
  assert(/^[a-i]+$/.test(source)); assert(allowed.length && allowed[0] > 0 && allowed.at(-1) < 256);
  const digits = [...source].map(c => c.charCodeAt(0) - 96), weights = digits.map((d, i) => BigInt(d) * 10n ** BigInt(digits.length - i - 1));
  const tails = Array(digits.length + 1).fill(0n); for (let i = digits.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
  const terminal = [], hits = []; let nodes = 0, excluded = 0n, pending = 0n; const start = Date.now();
  function visit(low, mask) {
    const count = 1n << BigInt(digits.length - mask.length);
    if (nodes >= maxNodes || Date.now() - start >= maxMs) { terminal.push({ mask, status: 'pending' }); pending += count; return; }
    nodes++;
    const high = low + tails[mask.length], next = successor(low, allowed);
    if (next > high) { terminal.push({ mask, status: 'excluded' }); excluded += count; return; }
    if (mask.length === digits.length) {
      const value = bytes(low); assert([...value].every(x => allowed.includes(x)));
      terminal.push({ mask, status: 'hit' }); hits.push({ mask, hex: value.toString('hex'), leadingZeroDigits: mask.indexOf('1'), zeroLetters: [...new Set([...source].filter((_, i) => mask[i] === '0'))].sort().join('') }); return;
    }
    visit(low, mask + '0'); visit(low + weights[mask.length], mask + '1');
  }
  visit(0n, ''); const total = 1n << BigInt(digits.length); assert.equal(excluded + pending + BigInt(hits.length), total);
  return { complete: pending === 0n, nodes, total: String(total), excluded: String(excluded), pending: String(pending), terminal, hits, elapsedMs: Date.now() - start };
}
function controls() {
  let exact = 0, assignments = 0, successors = 0, planted = 0;
  for (const { allowed } of alphabets()) {
    const finite = [...allowed.map(x => BigInt(x)), ...allowed.flatMap(x => allowed.map(y => BigInt(x * 256 + y)))].sort((a, b) => a < b ? -1 : 1);
    for (let n = 0n; n <= 32767n; n += 139n) {
      const expected = finite.find(v => v >= n); if (expected !== undefined) { assert.equal(successor(n, allowed), expected); successors++; }
    }
    for (const source of ['abcdefghi', 'debcdf', 'ggggg', 'ihbca']) {
      const expected = [];
      for (let mask = 0; mask < 2 ** source.length; mask++) {
        const n = BigInt([...source].map((c, i) => mask >> i & 1 ? c.charCodeAt(0) - 96 : 0).join(''));
        const b = bytes(n); if ([...b].every(x => allowed.includes(x))) expected.push(b.toString('hex')); assignments++;
      }
      const actual = search(source, allowed); assert(actual.complete); assert.deepEqual(actual.hits.map(h => h.hex).sort(), expected.sort()); exact++;
    }
  }
  for (const text of ['matrixsumlist', 'THE PRIME', '[2,3,5,7]', 'abcdef09', 'ABCDEF09']) {
    const alphabet = alphabets().find(a => [...Buffer.from(text)].every(c => a.allowed.includes(c)));
    const decimal = BigInt('0x' + Buffer.from(text).toString('hex')).toString();
    const source = [...decimal].map((c, i) => c === '0' ? String.fromCharCode(97 + i % 9) : String.fromCharCode(96 + Number(c))).join('');
    const actual = search(source, alphabet.allowed, { maxNodes: 200000, maxMs: 3000 }); assert(actual.complete && actual.hits.some(h => h.hex === Buffer.from(text).toString('hex'))); planted++;
  }
  return { exactCases: exact, enumeratedAssignments: assignments, successorComparisons: successors, plantedRecovered: planted };
}
function main() {
  fs.mkdirSync(folder, { recursive: true }); assert(!fs.existsSync(path.join(folder, 'summary.json')), 'Inspect existing results before rerunning');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw), checks = controls();
  const spec = { hypothesis: 'For each occurrence of ANY of the nine letters, independently retain a1..i9 or write zero. Interpret the COMPLETE decimal field as an integer and require every minimal big-endian byte to belong to the declared alphabet. Leading zero decimal positions are allowed, making this a relaxation of every subset of zero-capable letters. No letter deletion, new digit bijection, offset, transposition or additional cipher.', alphabets: alphabets(), limits: { maxNodes: 200000, maxMs: 10000 }, exclusionsNotClaimed: 'Mixed upper/lowercase prose, digits in prose alphabets, other punctuation or Unicode, arbitrary binary data and alphabets absent from this specification. Lexical meaning is not required by the alphabet filters.', inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)), controls: checks };
  fs.writeFileSync(path.join(folder, 'spec.json'), JSON.stringify(spec, null, 2) + '\n'); const cases = [], candidates = new Map();
  for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const a of spec.alphabets) {
    const source = reverse ? [...input[field]].reverse().join('') : input[field], result = search(source, a.allowed, spec.limits);
    const id = `${field}_${reverse ? 'reverse' : 'forward'}_${a.name}`, file = id + '.json.gz';
    fs.writeFileSync(path.join(folder, file), zlib.gzipSync(JSON.stringify({ field, reverse, alphabet: a.name, ...result })));
    for (const hit of result.hits) if (!candidates.has(hit.hex)) candidates.set(hit.hex, { id: candidates.size, ...hit, provenance: id });
    const record = { field, reverse, alphabet: a.name, file, ...result, terminal: result.terminal.length, hits: result.hits.length, artifactSHA256: sha(fs.readFileSync(path.join(folder, file))) }; cases.push(record); console.log(JSON.stringify(record));
  }
  fs.writeFileSync(path.join(folder, 'candidates.json'), JSON.stringify([...candidates.values()], null, 2) + '\n');
  fs.writeFileSync(path.join(folder, 'summary.json'), JSON.stringify({ cases, complete: cases.every(c => c.complete), candidates: candidates.size }, null, 2) + '\n');
}
if (require.main === module) main();
module.exports = { alphabets, bytes, successor, search, controls };
