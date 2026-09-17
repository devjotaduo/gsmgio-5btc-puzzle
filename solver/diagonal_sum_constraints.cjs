'use strict';
// Necessary conditions for direct decimal diagonal sums, with unknown digit labels.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {canonical, repeated, boundsFor} = require('./color_sum_symbolic.cjs');
const root = path.resolve(__dirname, '..');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function profiles(input) {
  const colors = new Map(input.colored.map(([, color, r, c]) => [r + ',' + c, color]));
  const result = [];
  for (const axis of ['difference', 'sum', 'wrapped-difference', 'wrapped-sum']) {
    for (const zeroWeight of [0, 1]) for (const oneWeight of [0, 1]) {
      const sums = Array.from({length: axis.startsWith('wrapped') ? 14 : 27}, () => [0, 0, 0]);
      for (let r = 0; r < 14; r++) for (let c = 0; c < 14; c++) {
        const index = axis === 'difference' ? r - c + 13 : axis === 'sum' ? r + c :
          axis === 'wrapped-difference' ? (r - c + 14) % 14 : (r + c) % 14;
        const color = colors.get(r + ',' + c), row = sums[index];
        if (color === 'B') row[0]++;
        else if (color === 'Y') row[1]++;
        else row[2] += input.matrix[r][c] ? oneWeight : zeroWeight;
      }
      assert.equal(sums.reduce((n, row) => n + row[0], 0), 15);
      assert.equal(sums.reduce((n, row) => n + row[1], 0), 9);
      result.push({id: result.length, axis, zeroWeight, oneWeight, sums});
    }
  }
  return result;
}

function bindConstant(value, part, bindings, aliasCount) {
  const digits = String(value), next = [...bindings];
  if (part.length !== digits.length) return null;
  for (let i = 0; i < digits.length; i++) {
    const d = +digits[i], ch = part[i];
    if (d === 0) {if (ch !== '0') return null; continue;}
    if (next[d] !== '' && next[d] !== ch) return null;
    if (ch !== '0' && next.some((bound, j) => j !== d && bound === ch)) return null;
    next[d] = ch;
  }
  if (next.slice(1).filter(ch => ch === '0').length > aliasCount) return null;
  return next;
}

function segment(text, sums, maxLengths, nodeLimit = 500000, aliasCount = 2) {
  const keys = sums.map(row => row.join(','));
  const unique = [...new Set(keys)], ids = keys.map(key => unique.indexOf(key));
  const first = unique.map(key => keys.indexOf(key)), last = unique.map(key => keys.lastIndexOf(key));
  const lower = sums.map(([a, b, c]) => String(2 * a + 2 * b + c).length);
  const upper = sums.map(([a, b, c], i) => a + b === 0 ? String(c).length : maxLengths[i]);
  const minSuffix = new Array(sums.length + 1).fill(0), maxSuffix = [...minSuffix];
  for (let i = sums.length - 1; i >= 0; i--) {
    minSuffix[i] = minSuffix[i + 1] + lower[i];
    maxSuffix[i] = maxSuffix[i + 1] + upper[i];
  }
  let nodes = 0, capped = false, witness = null;
  const bound = new Array(unique.length).fill(null), dead = new Set(), pieces = [];
  function visit(index, position, digits) {
    if (++nodes > nodeLimit) {capped = true; return false;}
    const remaining = text.length - position;
    if (remaining < minSuffix[index] || remaining > maxSuffix[index]) return false;
    if (index === sums.length) {witness = [...pieces]; return true;}
    // Only bindings whose first occurrence has passed and which occur again matter.
    const state = index + ':' + position + ':' + bound.map((value, j) =>
      first[j] < index && last[j] >= index ? value : '').join('/') + ':' + digits.join('/');
    if (dead.has(state)) return false;
    const id = ids[index], previous = bound[id];
    const lo = Math.max(lower[index], remaining - maxSuffix[index + 1]);
    const hi = Math.min(upper[index], remaining - minSuffix[index + 1]);
    for (let length = lo; length <= hi; length++) {
      const part = text.slice(position, position + length);
      if (previous !== null && previous !== part) continue;
      const nextDigits = sums[index][0] + sums[index][1] === 0 ?
        bindConstant(sums[index][2], part, digits, aliasCount) : digits;
      if (nextDigits === null) continue;
      bound[id] = part;
      pieces.push(length);
      const found = visit(index + 1, position + length, nextDigits);
      pieces.pop();
      bound[id] = previous;
      if (found || capped) return found;
    }
    dead.add(state);
    return false;
  }
  const compatible = visit(0, 0, new Array(10).fill(''));
  return {complete: !capped, compatible, witness, nodes, deadStates: dead.size};
}

function encode(sums, p, q, alphabet, aliases) {
  let zeros = 0;
  return sums.map(([a, b, c]) => String(BigInt(a) * p + BigInt(b) * q + BigInt(c)))
    .join('').split('').map(d => d === '0' ? aliases[zeros++ % aliases.length] : alphabet[+d - 1]).join('');
}

function controls(ps) {
  let planted = 0, exhaustive = 0;
  for (const profile of ps) for (const [p, q] of [[2n, 3n], [47n, 113n], [1000003n, 1000033n]]) {
    const text = canonical(encode(profile.sums, p, q, 'ihgfedcba', 'be'), 'be');
    const bounds = boundsFor(text, profile.sums, repeated(text));
    assert(BigInt(bounds.limits[0]) >= p && BigInt(bounds.limits[1]) >= q);
    const result = segment(text, profile.sums, bounds.maxLengths, 2000000);
    assert(result.complete && result.compatible, JSON.stringify({profile: profile.id, p: String(p), result}));
    planted++;
  }
  const rows = [[1, 0, 0], [0, 0, 1], [1, 0, 0]];
  for (let size = 3; size <= 8; size++) for (let mask = 0; mask < 2 ** size; mask++) {
    const text = mask.toString(2).padStart(size, '0');
    let wanted = false;
    for (let length = 1; length <= 4; length++) {
      if (2 * length + 1 === size && text.slice(0, length) === text.slice(length + 1)) wanted = true;
    }
    const actual = segment(text, rows, [4, 1, 4]);
    assert(actual.complete && actual.compatible === wanted); exhaustive++;
  }
  assert.equal(segment('aaaaaaa', rows, [4, 1, 4], 1).complete, false);
  return {planted, exhaustive, capControl: true};
}

function main() {
  const destination = path.resolve(process.argv[2] || path.join(root, '_work/diagonal_sum_constraints_2026-09-17'));
  assert(!fs.existsSync(destination), 'Use a fresh output directory');
  const bytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const input = JSON.parse(bytes), ps = profiles(input), aliases = [''];
  for (const a of 'abcdefghi') {
    aliases.push(a);
    for (const b of 'abcdefghi') if (a < b) aliases.push(a + b);
  }
  const control = controls(ps);
  fs.mkdirSync(destination, {recursive: true});
  const write = (name, value) => fs.writeFileSync(path.join(destination, name), JSON.stringify(value, null, 2) + '\n');
  write('spec.json', {
    inputSHA256: hash(bytes), sourceSHA256: hash(fs.readFileSync(__filename)),
    helperSHA256: hash(fs.readFileSync(path.join(__dirname, 'color_sum_symbolic.cjs'))),
    hypothesis: 'Minimal decimal values of full diagonal sums concatenated in order. Blue p>=2, yellow q>=2; black/white each 0 or 1. Fixed unknown bijection a..i to 1..9; up to two letters may also represent zero, independently per occurrence.',
    scope: 'DBBI and FAED in both directions; ascending and descending diagonal lists. Ordinary r-c+13 / r+c and wrapped (r-c+14)%14 / (r+c)%14. No cyclic origin search or arbitrary permutation.',
    relaxation: 'Collapse chosen zero aliases, use equal coefficient triples requiring equal substrings. Constant sums have exact decimal lengths and a shared injective digit labelling (up to alias count labels can collapse to zero). Nonconstant sums have repeat-derived finite upper bounds and minimum lengths for p=q=2. Numeric consistency of nonconstant sums is NOT required; compatibility is only a necessary condition.',
    nodeLimit: 500000, aliases, profiles: ps
  });
  write('controls.json', control);
  const fd = fs.openSync(path.join(destination, 'cases.jsonl'), 'wx');
  let models = 0, lengthRejected = 0, segmentationRejected = 0, capped = 0, nodes = 0;
  const survivors = [];
  for (const field of ['dbbi', 'faed']) for (const profile of ps) {
    for (const textReverse of [false, true]) for (const sumsReverse of [false, true]) for (const zeroAliases of aliases) {
      const text = canonical(textReverse ? [...input[field]].reverse().join('') : input[field], zeroAliases);
      const sums = sumsReverse ? [...profile.sums].reverse() : profile.sums;
      const repeat = repeated(text), bounds = boundsFor(text, sums, repeat);
      const model = {id: models++, field, profile: profile.id, textReverse, sumsReverse, aliases: zeroAliases};
      const result = bounds.maxLength < text.length ? {reason: 'length', complete: true, compatible: false, nodes: 0} :
        {reason: 'segmentation', ...segment(text, sums, bounds.maxLengths, 500000, zeroAliases.length)};
      if (result.reason === 'length') lengthRejected++;
      else if (result.complete && !result.compatible) segmentationRejected++;
      if (!result.complete) capped++;
      if (result.compatible || !result.complete) survivors.push({...model, ...result});
      nodes += result.nodes;
      fs.writeSync(fd, JSON.stringify({...model, repeat, ...bounds, ...result}) + '\n');
    }
    console.log(JSON.stringify({field, profile: profile.id, models, survivors: survivors.length, capped, nodes}));
  }
  fs.closeSync(fd);
  const summary = {complete: capped === 0, models, lengthRejected, segmentationRejected, capped, nodes,
    compatibleModels: survivors.filter(s => s.compatible).length, survivors, controls: control,
    casesSHA256: hash(fs.readFileSync(path.join(destination, 'cases.jsonl'))), finalPasswordFound: false};
  write('summary.json', summary);
  console.log(JSON.stringify({...summary, survivors: survivors.length}, null, 2));
}

if (require.main === module) main();
module.exports = {profiles, segment, encode, bindConstant};
