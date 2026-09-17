'use strict';
// Invert ordered decimal sums with a shared, unknown a..i -> 1..9 bijection.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {profiles} = require('./diagonal_sum_constraints.cjs');
const root = path.resolve(__dirname, '..');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const countBits = n => n.toString(2).replace(/0/g, '').length;
const fresh = () => ({digits: new Array(10).fill(-1), letters: new Array(9).fill(-1), zeros: 0});
const clone = state => ({digits: [...state.digits], letters: [...state.letters], zeros: state.zeros});

function bind(state, digit, letter, maxZeroAliases = 2) {
  if (digit === 0) {
    state.zeros |= 1 << letter;
    return countBits(state.zeros) <= maxZeroAliases;
  }
  if ((state.digits[digit] >= 0 && state.digits[digit] !== letter) ||
      (state.letters[letter] >= 0 && state.letters[letter] !== digit)) return false;
  state.digits[digit] = letter;
  state.letters[letter] = digit;
  return true;
}

function constantState(value, part, previous, maxZeroAliases = 2) {
  const digits = String(value), state = clone(previous);
  if (part.length !== digits.length) return null;
  for (let i = 0; i < digits.length; i++) {
    if (!bind(state, +digits[i], part.charCodeAt(i) - 97, maxZeroAliases)) return null;
  }
  return state;
}

function lengthDifferences(sums) {
  const shifted = sums.map(([a, b, c]) => [a, b, 2 * a + 2 * b + c]);
  // p=p'+2,q=q'+2. Coefficient-wise Si<=10^d*Sj implies len(Si)<=len(Sj)+d.
  return shifted.map(left => shifted.map(right => {
    for (let d = 0; d <= 3; d++) if (left.every((n, k) => n <= 10 ** d * right[k])) return d;
    return Infinity;
  }));
}

function solveDigits(sums, parts, initial, budget, maxZeroAliases = 2) {
  const reversed = parts.map(part => [...part].reverse().map(c => c.charCodeAt(0) - 97));
  const width = Math.max(...parts.map(part => part.length)), dead = new Set(), matches = [];
  let nodes = 0, transitions = 0, capped = false;
  function visit(k, carry, state, p, q, smallP, smallQ, power) {
    nodes++;
    if (++budget.nodes > budget.limit) {capped = true; return false;}
    if (k === width) {
      if (smallP === 2 && smallQ === 2 && carry.every(n => n === 0)) {
        matches.push({p: String(p), q: String(q), digits: state.digits.slice(1),
          zeroAliases: [...'abcdefghi'].filter((_, j) => (state.zeros >> j) & 1).join('')});
        return true;
      }
      return false;
    }
    const key = [k, carry.join(','), state.digits.join(','), state.zeros, smallP, smallQ].join(':');
    if (dead.has(key)) return false;
    let found = false;
    for (let pd = 0; pd < 10; pd++) for (let qd = 0; qd < 10; qd++) {
      const next = clone(state), totals = [], nextCarry = [];
      let okay = true;
      for (let i = 0; i < sums.length; i++) {
        const total = sums[i][0] * pd + sums[i][1] * qd + carry[i], digit = total % 10;
        totals.push(total); nextCarry.push(Math.floor(total / 10));
        if (k >= reversed[i].length) {if (digit !== 0) {okay = false; break;}}
        else if ((digit === 0 && k === reversed[i].length - 1 && reversed[i].length > 1) ||
          !bind(next, digit, reversed[i][k], maxZeroAliases)) {okay = false; break;}
      }
      if (!okay) continue;
      transitions++;
      const nextP = smallP === 2 || pd >= 2 || (k > 0 && pd > 0) ? 2 : Math.max(smallP, pd);
      const nextQ = smallQ === 2 || qd >= 2 || (k > 0 && qd > 0) ? 2 : Math.max(smallQ, qd);
      if (visit(k + 1, nextCarry, next, p + BigInt(pd) * power, q + BigInt(qd) * power,
        nextP, nextQ, power * 10n)) found = true;
      if (capped) return found;
    }
    if (!found) dead.add(key);
    return found;
  }
  visit(0, sums.map(row => row[2]), initial, 0n, 0n, 0, 0, 1n);
  return {nodes, transitions, complete: !capped, matches};
}

function inverse(text, sums, nodeLimit = 3000000, maxZeroAliases = 2) {
  const difference = lengthDifferences(sums);
  const lower = sums.map(([a, b, c]) => String(2 * a + 2 * b + c).length);
  const upper = sums.map(([a, b, c]) => a + b === 0 ? String(c).length : text.length);
  const lengths = [], parts = [], budget = {nodes: 0, limit: nodeLimit};
  let lengthNodes = 0, partitions = 0, digitNodes = 0, digitTransitions = 0, complete = true;
  const hits = [];
  function intervals(index) {
    const lo = lower.slice(index), hi = upper.slice(index);
    for (let i = index; i < sums.length; i++) for (let j = 0; j < index; j++) {
      lo[i - index] = Math.max(lo[i - index], lengths[j] - difference[j][i]);
      hi[i - index] = Math.min(hi[i - index], lengths[j] + difference[i][j]);
    }
    return {lo, hi};
  }
  function visit(index, position, bindings) {
    lengthNodes++;
    if (++budget.nodes > budget.limit) {complete = false; return;}
    if (index === sums.length) {
      if (position !== text.length) return;
      partitions++;
      const result = solveDigits(sums, parts, bindings, budget, maxZeroAliases);
      digitNodes += result.nodes; digitTransitions += result.transitions;
      complete = complete && result.complete;
      result.matches.forEach(match => hits.push({lengths: [...lengths], ...match}));
      return;
    }
    const remaining = text.length - position, {lo, hi} = intervals(index);
    if (lo.some((n, i) => n > hi[i]) || lo.reduce((a, b) => a + b, 0) > remaining ||
      hi.reduce((a, b) => a + b, 0) < remaining) return;
    const start = Math.max(lo[0], remaining - hi.slice(1).reduce((a, b) => a + b, 0));
    const end = Math.min(hi[0], remaining - lo.slice(1).reduce((a, b) => a + b, 0));
    for (let length = start; length <= end; length++) {
      const part = text.slice(position, position + length), [a, b, c] = sums[index];
      const next = a + b === 0 ? constantState(c, part, bindings, maxZeroAliases) : bindings;
      if (next === null) continue;
      lengths.push(length); parts.push(part);
      visit(index + 1, position + length, next);
      lengths.pop(); parts.pop();
      if (!complete) return;
    }
  }
  visit(0, 0, fresh());
  return {complete, lengthNodes, partitions, digitNodes, digitTransitions, hits};
}

function encoded(sums, p, q, alphabet = 'ihgfedcba', zeros = 'be') {
  assert(/^[a-i]+$/.test(zeros), 'At least one valid zero alias is required');
  assert(alphabet.length === 9 && new Set(alphabet).size === 9 && /^[a-i]+$/.test(alphabet),
    'Alphabet must be a permutation of a..i');
  let zeroAt = 0;
  return sums.map(([a, b, c]) => String(BigInt(a) * p + BigInt(b) * q + BigInt(c)))
    .join('').split('').map(d => d === '0' ? zeros[zeroAt++ % zeros.length] : alphabet[+d - 1]).join('');
}

function controls(ps) {
  let planted = 0;
  assert.throws(() => encoded([[0, 0, 10]], 2n, 3n, 'ihgfedcba', ''));
  for (const profile of ps) for (const [p, q] of [[2n, 3n], [47n, 113n], [1000003n, 1000033n]]) {
    const text = encoded(profile.sums, p, q), result = inverse(text, profile.sums);
    assert(result.hits.some(hit => hit.p === String(p) && hit.q === String(q)), JSON.stringify({id: profile.id, p: String(p), q: String(q), result}));
    assert(result.complete);
    planted++;
  }
  assert.equal(inverse('aaaaaaaaa', [[1, 0, 0], [0, 1, 0]], 1).complete, false);
  return {planted, capControl: true, emptyAliasControl: true};
}

function main() {
  const destination = path.resolve(process.argv[2] || path.join(root, '_work/diagonal_sum_inverse_2026-09-17'));
  assert(!fs.existsSync(destination), 'Use a fresh output directory');
  const inputBytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const input = JSON.parse(inputBytes), ps = profiles(input);
  const control = controls(ps);
  fs.mkdirSync(destination, {recursive: true});
  const save = (name, value) => fs.writeFileSync(path.join(destination, name), JSON.stringify(value, null, 2) + '\n');
  save('spec.json', {inputSHA256: sha(inputBytes), sourceSHA256: sha(fs.readFileSync(__filename)),
    profiles: ps, hypothesis: 'Ordered minimal decimal diagonal sums. Blue p>=2, yellow q>=2, independent binary background weights. Unknown shared bijection a..i to 1..9 and zero at occurrences of at most two chosen letters.',
    scope: 'Both DBBI/FAED directions and both diagonal list directions; 16 profiles. All integer p,q subject to source length, no prime ceiling. Unknown digit map is solved jointly, not chosen for readability.',
    method: 'Coefficient-wise ratios bound possible decimal lengths. Full constant sums constrain a shared bijection. Simultaneous decimal carries constrain each digit of p/q and every output symbol. Complete=false explicitly records a node cap.', nodeLimit: 3000000});
  save('controls.json', control);
  const cases = [];
  for (const field of ['dbbi', 'faed']) for (const profile of ps) for (const sourceReverse of [false, true]) for (const sumsReverse of [false, true]) {
    const text = sourceReverse ? [...input[field]].reverse().join('') : input[field];
    const sums = sumsReverse ? [...profile.sums].reverse() : profile.sums;
    const result = inverse(text, sums);
    const row = {id: cases.length, field, profile: profile.id, sourceReverse, sumsReverse, ...result};
    cases.push(row); fs.appendFileSync(path.join(destination, 'cases.jsonl'), JSON.stringify(row) + '\n');
    console.log(JSON.stringify({...row, hits: row.hits.length}));
  }
  const summary = {complete: cases.every(c => c.complete), models: cases.length, capped: cases.filter(c => !c.complete).length,
    partitions: cases.reduce((a, c) => a + c.partitions, 0), digitNodes: cases.reduce((a, c) => a + c.digitNodes, 0),
    hits: cases.flatMap(c => c.hits.map(hit => ({model: c.id, ...hit}))), controls: control,
    casesSHA256: sha(fs.readFileSync(path.join(destination, 'cases.jsonl'))), finalPasswordFound: false};
  save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
module.exports = {bind, constantState, lengthDifferences, solveDigits, inverse, encoded, fresh};
