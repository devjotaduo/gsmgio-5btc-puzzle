'use strict';
// Two zero-free representations, derived from the nine-symbol alphabet itself.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const hash = b => crypto.createHash('sha256').update(b).digest();
const bytes = n => { let h = n.toString(16); return Buffer.from(h.length % 2 ? '0' + h : h, 'hex'); };

function eachPermutation(callback) {
  const a = [1,2,3,4,5,6,7,8,9], c = Array(9).fill(0); let rank = 0;
  callback(a, rank++);
  for (let i = 0; i < 9;) {
    if (c[i] < i) { const j = i % 2 ? c[i] : 0; [a[j],a[i]] = [a[i],a[j]]; callback(a, rank++); c[i]++; i = 0; }
    else { c[i] = 0; i++; }
  }
  assert.equal(rank, 362880);
}

function bijectiveEncode(n, mapping) {
  const inverse = new Map(mapping.map((v, i) => [v, i])); let result = '';
  while (n > 0n) { const d = Number((n - 1n) % 9n) + 1; result = String.fromCharCode(97 + inverse.get(d)) + result; n = (n - BigInt(d)) / 9n; }
  return result;
}
function bijectiveDecode(s, mapping) {
  let n = 0n; for (const c of s) n = n * 9n + BigInt(mapping[c.charCodeAt(0) - 97]); return n;
}

function machine(codes) {
  const words = new Set(codes.map(c => c.word));
  const prefixes = ['', ...new Set([...words].flatMap(w => Array.from({length: w.length - 1}, (_, i) => w.slice(0, i + 1))))];
  assert(prefixes.length < 31);
  const single = prefixes.map(p => Array.from({length: 10}, (_, d) => {
    const s = p + d, k = prefixes.indexOf(s); return (words.has(s) ? 1 : 0) | (k > 0 ? 1 << k : 0);
  }));
  const cache = Array.from({length: 10}, () => new Map([[0, 0]]));
  function step(mask, digit) {
    let result = cache[digit].get(mask); if (result !== undefined) return result;
    result = 0; for (let bits = mask; bits; bits &= bits - 1) result |= single[31 - Math.clz32(bits & -bits)][digit];
    cache[digit].set(mask, result); return result;
  }
  function accepts(source, mapping) {
    let mask = 1; for (const symbol of source) { mask = step(mask, mapping[symbol]); if (!mask) return false; } return Boolean(mask & 1);
  }
  return {prefixes, codes, accepts};
}

function graph(source, mapping, codes) {
  const digits = source.map(s => mapping[s]).join('');
  return Array.from({length: source.length + 1}, (_, start) => codes.filter(c => digits.startsWith(c.word, start)).map(c => ({end: start + c.word.length, m: c.m})));
}
function parseCount(edges) {
  const counts = Array(edges.length).fill(0n); counts[counts.length - 1] = 1n;
  for (let i = edges.length - 2; i >= 0; i--) for (const e of edges[i]) counts[i] += counts[e.end];
  return counts;
}
function enumerate(edges, limit = 1000) {
  const counts = parseCount(edges), texts = [];
  function visit(at, text) {
    if (texts.length >= limit) return;
    if (at === edges.length - 1) { texts.push(text); return; }
    for (const e of edges[at]) if (counts[e.end]) visit(e.end, text + String.fromCharCode(e.m));
  }
  visit(0, ''); return {paths: String(counts[0]), complete: BigInt(texts.length) === counts[0], texts};
}

function main() {
  const out = path.resolve(process.argv[2] || path.join(root, '_work/zero_free_numerals_2026-09-17/run1'));
  assert(!fs.existsSync(out), 'Use a fresh output directory.'); fs.mkdirSync(out, {recursive: true});
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), data = JSON.parse(inputRaw);
  const encodingRaw = fs.readFileSync(path.join(root, '_work/ebcdic_decimal_2026-09-16/encoding.json'));
  const ebcdic = JSON.parse(encodingRaw.toString('utf8').replace(/^\uFEFF/, '')).decoded;
  const fields = [];
  for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) {
    const text = reverse ? [...data[field]].reverse().join('') : data[field];
    const source = [...text].map(c => c.charCodeAt(0) - 97), weights = Array(9).fill(0n); let power = 1n;
    for (let i = source.length - 1; i >= 0; i--) { weights[source[i]] += power; power *= 9n; }
    fields.push({field, reverse, text, source, weights});
  }
  const models = [];
  for (const encoding of ['ASCII', 'CP1141']) for (const repertoire of ['lower-space', 'upper-space', 'printable-controls']) {
    const allowed = Array.from({length: 128}, (_, m) => m).filter(m => repertoire === 'lower-space' ? m === 32 || m >= 97 && m <= 122 : repertoire === 'upper-space' ? m === 32 || m >= 65 && m <= 90 : m >= 32 && m <= 126 || [9,10,13].includes(m));
    const codes = allowed.map(m => ({m, value: encoding === 'ASCII' ? m : ebcdic.indexOf(String.fromCharCode(m))}));
    assert(codes.every(c => c.value > 0)); codes.forEach(c => { c.word = String(c.value).replaceAll('0', ''); });
    assert(codes.every(c => /^[1-9]+$/.test(c.word)));
    models.push({encoding, repertoire, machine: machine(codes)});
  }
  let bijectiveControls = 0, strippedControls = 0;
  const mappings = [[1,2,3,4,5,6,7,8,9], [6,2,7,1,8,4,9,5,3], [9,8,7,6,5,4,3,2,1]];
  for (const mapping of mappings) for (const text of ['matrixsumlist', 'Missing zero 10', 'A'.repeat(35)]) {
    const n = BigInt('0x' + Buffer.from(text).toString('hex')), encoded = bijectiveEncode(n, mapping);
    assert.equal(bijectiveDecode(encoded, mapping), n); bijectiveControls++;
  }
  for (const model of models) for (const mapping of mappings) {
    const text = model.repertoire === 'lower-space' ? 'the missing zero' : model.repertoire === 'upper-space' ? 'THE MISSING ZERO' : 'Decoded 10!';
    const encode = new Map(model.machine.codes.map(c => [c.m, c.word]));
    const source = [...text].flatMap(c => [...encode.get(c.charCodeAt(0))].map(d => mapping.indexOf(+d)));
    assert(model.machine.accepts(source, mapping));
    const edges = graph(source, mapping, model.machine.codes); assert(parseCount(edges)[0] > 0n);
    let at = 0; for (const c of text) { const e = edges[at].find(e => e.m === c.charCodeAt(0)); assert(e); at = e.end; } assert.equal(at, source.length);
    strippedControls++;
  }
  save('spec.json', {hypotheses: ['Bijective base 9 uses digits 1..9, with no zero digit; whole-field value n = 9*n + digit. All 9! symbol assignments.', 'Each ASCII or CP1141 code is written in decimal, all decimal zero digits are removed, remaining digits concatenated and substituted by a..i. All 9! assignments and all code boundaries.'],
    fields: fields.map(({field, reverse, text}) => ({field, reverse, length: text.length})),
    outputRequirements: ['Bijective: all whole-number minimal bytes <128, or a complete 36-byte key/checksum frame SHA256d(key32)[:4]. Both byte orders for the checksum.', 'Zero-omitted: lower+space, upper+space, or ASCII32..126 and TAB/LF/CR. Feasibility is exact; large ambiguous plaintext sets require subsequent analysis.'],
    exclusions: 'No prime-host parse, no Bifid square, no selected substrings, no insertion of arbitrary nonzero digits, no extra cipher, no arbitrary trimming. Does not exhaust arbitrary binary passwords.',
    models: models.map(m => ({encoding: m.encoding, repertoire: m.repertoire, codes: m.machine.codes, prefixes: m.machine.prefixes})),
    inputSHA256: sha(inputRaw), encodingTableSHA256: sha(encodingRaw), sourceSHA256: sha(fs.readFileSync(__filename)), permutationOrder: 'Heap; rank0 maps a..i to1..9'});
  save('controls.json', {bijectiveRoundtrips: bijectiveControls, strippedTextRecoveries: strippedControls});

  const radixHits = [], groups = fields.map(f => ({field: f.field, reverse: f.reverse, cases: 0, sevenBit: 0, checksum: 0}));
  const flags = Buffer.alloc(362880 * 4 * 6), radixFlags = Buffer.alloc(362880 * 4); let decisions = 0;
  const acceptedFile = path.join(out, 'accepted.jsonl'), fd = fs.openSync(acceptedFile, 'wx');
  const counts = models.map(m => fields.map(f => ({encoding: m.encoding, repertoire: m.repertoire, field: f.field, reverse: f.reverse, compatible: 0})));
  const start = Date.now();
  eachPermutation((mapping, rank) => {
    const big = mapping.map(BigInt);
    for (let f = 0; f < fields.length; f++) {
      const field = fields[f]; let n = 0n; for (let s = 0; s < 9; s++) n += big[s] * field.weights[s];
      const b = bytes(n), sevenBit = b.every(x => x < 128); let checksum = false;
      if (b.length === 36) for (const candidate of [b, Buffer.from(b).reverse()]) {
        if (hash(hash(candidate.subarray(0,32))).subarray(0,4).equals(candidate.subarray(32))) { checksum = true; radixHits.push({field: field.field, reverse: field.reverse, rank, mapping: [...mapping], kind: 'checksum', hex: candidate.toString('hex')}); }
      }
      if (sevenBit) radixHits.push({field: field.field, reverse: field.reverse, rank, mapping: [...mapping], kind: 'seven-bit', hex: b.toString('hex')});
      groups[f].cases++; groups[f].sevenBit += Number(sevenBit); groups[f].checksum += Number(checksum);
      radixFlags[rank * 4 + f] = Number(sevenBit) | Number(checksum) * 2;
    }
    for (let m = 0; m < models.length; m++) for (let f = 0; f < fields.length; f++) {
      const okay = models[m].machine.accepts(fields[f].source, mapping); flags[decisions++] = Number(okay);
      if (okay) { counts[m][f].compatible++; fs.writeSync(fd, JSON.stringify({rank, model: m, field: f, mapping: mapping.join('')}) + '\n'); }
    }
    if ((rank + 1) % 50000 === 0) console.log(JSON.stringify({permutations: rank + 1, radix: groups.map(g => [g.sevenBit, g.checksum]), omittedZero: counts.map(x => x.map(c => c.compatible)), elapsedMs: Date.now() - start}));
  });
  fs.closeSync(fd); fs.writeFileSync(path.join(out, 'flags.bin'), flags, {flag: 'wx'}); fs.writeFileSync(path.join(out, 'radix_flags.bin'), radixFlags, {flag: 'wx'});
  save('radix_candidates.json', radixHits);
  const result = {completeFeasibility: true, permutations: 362880, bijectiveCases: groups.reduce((n, g) => n + g.cases, 0), bijective: groups,
    omittedZeroCases: decisions, omittedZero: counts.flat(), omittedZeroCompatible: counts.flat().reduce((n, g) => n + g.compatible, 0),
    flagsSHA256: sha(flags), radixFlagsSHA256: sha(radixFlags), acceptedSHA256: sha(fs.readFileSync(acceptedFile)),
    authenticatedSolution: false, status: 'Feasibility is not plaintext authentication. Any positive grammar models still need decoding and cryptographic checks.', elapsedMs: Date.now() - start};
  save('summary.json', result); console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
module.exports = {eachPermutation, bijectiveEncode, bijectiveDecode, machine, graph, parseCount, enumerate};
