'use strict';
// Nine symbols = two trits; five trits represent an ASCII byte (0..127).
// FAED's 570 symbols produce 1140 trits = exactly 228 complete bytes.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {eachPermutation} = require('./zero_free_numerals.cjs');
const root = path.resolve(__dirname, '..'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
function decode(source, mapping, layout, requireSevenBit = true) {
  const length = source.length * 2; assert.equal(length % 5, 0); const out = Buffer.alloc(length / 5);
  function trit(at) {
    const symbol = layout === 'adjacent' ? source[Math.floor(at / 2)] : source[at % source.length];
    const v = mapping[symbol] - 1;
    return (layout === 'adjacent' ? at % 2 === 0 : at < source.length) ? Math.floor(v / 3) : v % 3;
  }
  for (let i = 0; i < out.length; i++) {
    let n = 0; for (let j = 0; j < 5; j++) n = n * 3 + trit(i * 5 + j);
    if (requireSevenBit && n >= 128) return null; out[i] = n;
  }
  return out;
}
function encode(body, mapping, layout) {
  assert.equal(body.length % 2, 0); const trits = [];
  for (const b of body) { assert(b < 243); trits.push(...b.toString(3).padStart(5, '0').split('').map(Number)); }
  const count = trits.length / 2, source = [];
  for (let i = 0; i < count; i++) {
    const a = layout === 'adjacent' ? trits[2 * i] : trits[i], b = layout === 'adjacent' ? trits[2 * i + 1] : trits[i + count];
    source.push(mapping.indexOf(3 * a + b + 1));
  }
  return source;
}
function main() {
  const out = path.resolve(process.argv[2] || path.join(root, '_work/zero_free_numerals_2026-09-17/ternary'));
  assert(!fs.existsSync(out)); fs.mkdirSync(out, {recursive: true});
  const save = (f, v) => fs.writeFileSync(path.join(out, f), JSON.stringify(v, null, 2) + '\n', {flag: 'wx'});
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), data = JSON.parse(raw);
  const source = [...data.faed].map(c => c.charCodeAt(0) - 97);
  const cases = []; for (const reverse of [false, true]) for (const layout of ['adjacent', 'coordinate-halves']) cases.push({reverse, layout, source: reverse ? [...source].reverse() : source});
  let controls = 0;
  for (const mapping of [[1,2,3,4,5,6,7,8,9], [6,2,7,1,8,4,9,5,3]]) for (const layout of ['adjacent', 'coordinate-halves']) {
    const body = Buffer.from('This is a control.'); assert.deepEqual(decode(encode(body, mapping, layout), mapping, layout), body); controls++;
  }
  const flags = Buffer.alloc(362880 * 4), hits = [], count = cases.map(() => 0); let attempted = 0;
  eachPermutation((mapping, rank) => {
    for (let c = 0; c < cases.length; c++) {
      const model = cases[c], b = decode(model.source, mapping, model.layout); flags[rank * 4 + c] = Number(Boolean(b)); attempted++;
      if (b) { assert.deepEqual(encode(b, mapping, model.layout), model.source); count[c]++; hits.push({rank, reverse: model.reverse, layout: model.layout, mapping: [...mapping], hex: b.toString('hex')}); }
    }
  });
  fs.writeFileSync(path.join(out, 'flags.bin'), flags, {flag: 'wx'}); save('candidates.json', hits);
  save('spec.json', {hypothesis: 'Unknown bijection a..i to coordinate pairs00..22. Concatenate each pair or the complete row-coordinate stream followed by the column-coordinate stream. Read consecutive five-trit groups as complete bytes0..242; require every byte<128.',
    fields: ['FAED entire570 symbols, original and reversed'], cases: cases.map(({source, ...r}) => r), permutationOrder: 'Heap; rank0 maps a..i to1..9 then subtracts1',
    limits: 'No guessed keyword or decoded BTCSEED prefix; no skipped symbols, leftover trits or further cipher. DBBI is outside this exact layout because its 182 trits are not divisible by5. No binary-password or UTF8 exclusion claimed.',
    inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename))});
  save('controls.json', {plantedRoundtrips: controls});
  const result = {complete: true, cases: attempted, permutations: 362880, compatible: count, candidates: hits.length, flagsSHA256: sha(flags), authenticatedSolution: false};
  save('summary.json', result); console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
module.exports = {encode, decode};
