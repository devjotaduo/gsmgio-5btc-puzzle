'use strict';
// A distinct, fixed zero symbol plus optional deletion of a different symbol.
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {solve} = require('./optional_null_decimal.cjs');
const root = path.resolve(__dirname, '..'), dir = path.join(root, '_work/optional_null_decimal_2026-09-16/fixed_zero');
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
const bytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(bytes);
fs.mkdirSync(dir, {recursive: true});
const controls = [];
for (const text of ['enter', 'hello', 'matrix']) {
  const decimal = BigInt('0x' + Buffer.from(text).toString('hex')).toString();
  const missingDigit = [...'123456789'].find(c => !decimal.includes(c) && c !== '2'); assert(missingDigit && decimal.includes('0'));
  const zeroAlias = String.fromCharCode(96 + Number(missingDigit)), alias = 'b';
  const source = [...decimal].map((c, i) => (c === '0' ? zeroAlias : String.fromCharCode(96 + Number(c))) + (i % 4 === 0 ? alias : '')).join('');
  const digits = [...source].map(c => c === zeroAlias ? 0 : c.charCodeAt(0) - 96).join(''), answer = solve(digits, [...source].map(c => c === alias));
  assert(answer.complete && answer.hits.includes(decimal)); controls.push({text, decimal, source, digits, alias, zeroAlias, recovered: true});
}
fs.writeFileSync(path.join(dir, 'controls.json'), JSON.stringify(controls, null, 2) + '\n');
fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify({sourceSHA256: hash(fs.readFileSync(path.join(__dirname, 'optional_null_decimal.cjs'))),
  runnerSHA256: hash(fs.readFileSync(__filename)), inputSHA256: hash(bytes), successorSHA256: hash(fs.readFileSync(path.join(__dirname, 'zero_decimal_constraints.cjs'))),
  hypothesis: 'Any one letter is always decimal zero; a distinct letter may independently be kept at its A1..I9 value or deleted per occurrence. Remaining letters use A1..I9. Complete fields, both directions, minimal integer bytes must be below 128.',
  allowZero: false, fixedZero: true, maxNodesPerCase: 1000000}, null, 2) + '\n');
const summary = [], candidates = new Map();
for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const alias of 'abcdefghi') for (const zeroAlias of 'abcdefghi') {
  if (alias === zeroAlias) continue;
  const text = reverse ? [...input[field]].reverse().join('') : input[field], digits = [...text].map(c => c === zeroAlias ? 0 : c.charCodeAt(0) - 96).join('');
  const result = solve(digits, [...text].map(c => c === alias)), id = [field, reverse ? 'reverse' : 'forward', alias, zeroAlias].join('_'), file = id + '.json.gz';
  fs.writeFileSync(path.join(dir, file), zlib.gzipSync(JSON.stringify({...result, field, reverse, alias, zeroAlias, digits})));
  for (const decimal of result.hits) {let hex = BigInt(decimal).toString(16); if (hex.length % 2) hex = '0' + hex; if (!candidates.has(hex)) candidates.set(hex, {hex, decimal, source: id});}
  summary.push({id, field, reverse, alias, zeroAlias, complete: result.complete, optionalCount: result.optionalCount, masks: result.masks,
    ...result.stats, distinctCandidates: result.hits.length, file, artifactSHA256: hash(fs.readFileSync(path.join(dir, file)))});
  if (summary.length % 36 === 0) console.log(JSON.stringify({cases: summary.length, incomplete: summary.filter(c => !c.complete).length, candidates: candidates.size}));
}
fs.writeFileSync(path.join(dir, 'candidates.json'), JSON.stringify([...candidates.values()], null, 2) + '\n');
fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify({cases: summary, completeCases: summary.filter(c => c.complete).length, distinctCandidates: candidates.size, finalPasswordFound: false}, null, 2) + '\n');
