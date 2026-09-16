'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {nextAscii} = require('./zero_decimal_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/joined_fields_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function prove(symbols, alias, tailLength) {
  const factor = 10n ** BigInt(tailLength), weights = [], low = BigInt([...symbols].map(c => alias.includes(c) ? 0 : c.charCodeAt(0) - 96).join('')) * factor;
  [...symbols].forEach((c, i) => {if (alias.includes(c)) weights.push(BigInt(c.charCodeAt(0) - 96) * 10n ** BigInt(symbols.length - 1 - i) * factor);});
  const tails = Array(weights.length + 1).fill(factor - 1n);
  for (let i = weights.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
  const certificates = [], frontiers = []; let nodes = 0;
  function visit(i, n, mask) {
    nodes++;
    if (nextAscii(n, true) > n + tails[i]) {certificates.push(mask); return;}
    if (i === weights.length) {frontiers.push({mask, lo: n.toString(), hi: (n + factor - 1n).toString()}); return;}
    visit(i + 1, n, mask + '0'); visit(i + 1, n + weights[i], mask + '1');
  }
  visit(0, low, '');
  assert.equal(certificates.reduce((n, mask) => n + (1n << BigInt(weights.length - mask.length)), 0n) + BigInt(frontiers.length), 1n << BigInt(weights.length));
  return {ambiguous: weights.length, nodes, certificates, frontiers};
}
function main() {
  fs.mkdirSync(out, {recursive: true});
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw);
  const options = [...'abcdefghi']; for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) options.push(String.fromCharCode(97 + a, 97 + b));
  let planted = 0;
  for (const text of ['matrixsumlist', 'lastwordsbeforearchichoice', 'thispassword', 'the matrix has you']) for (const alias of ['a', 'g', 'be']) for (const split of [2, 3]) {
    const n = BigInt('0x' + Buffer.from(text).toString('hex')), decimal = n.toString(), cut = Math.floor(decimal.length / split);
    const symbols = [...decimal.slice(0, cut)].map(d => d === '0' ? alias[0] : String.fromCharCode(96 + Number(d))).join('');
    const result = prove(symbols, alias, decimal.length - cut);
    assert(result.frontiers.some(f => BigInt(f.lo) <= n && BigInt(f.hi) >= n)); planted++;
  }
  const records = [];
  for (const first of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const alias of options) {
    const source = reverse ? [...input[first]].reverse().join('') : input[first], second = first === 'dbbi' ? 'faed' : 'dbbi';
    records.push({first, reverse, alias, tailLength: input[second].length, ...prove(source, alias, input[second].length)});
  }
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');
  save('ascii_prefix_spec.json', {createdAt: new Date().toISOString(), inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)),
    helperSHA256: sha(fs.readFileSync(path.join(root, 'solver/zero_decimal_constraints.cjs'))), aliases: options,
    hypothesis: 'For either field A first, in either direction, allow up to two independently zeroable letters in A. Relax the entire second field to any integer B in [0,10^length(B)-1]. Require every minimal byte of A*10^length(B)+B to be below 128.',
    consequence: 'A prefix exclusion rules out all second-field values, hence both second-field orientations and all its one/two-letter zero masks. Reversing bytes does not change whether every byte is below 128.',
    controls: {planted}});
  save('ascii_prefix_cases.json', records);
  const summary = {prefixTrees: records.length, nodes: records.reduce((n, r) => n + r.nodes, 0),
    certificates: records.reduce((n, r) => n + r.certificates.length, 0), frontiers: records.reduce((n, r) => n + r.frontiers.length, 0),
    allTreesComplete: true, coveredOriginalJoinedModels: records.length * 2 * 45 * 2,
    casesSHA256: sha(fs.readFileSync(path.join(out, 'ascii_prefix_cases.json'))), controls: {planted}, finalPasswordFound: false};
  save('ascii_prefix_summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
