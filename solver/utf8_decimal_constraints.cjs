/* Whole decimal fields with one or two independently zeroable symbols, then strict
 * UTF-8 in either integer byte order. No replacement decoding or stripping.
 * node solver/utf8_decimal_constraints.cjs
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'utf8_decimal_2026-09-16');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const strict = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});

function bytesOf(n) {
  assert(n >= 0n);
  let h = n.toString(16);
  return Buffer.from(h.length % 2 ? '0' + h : h, 'hex');
}
function fatalValid(bytes) {
  try { strict.decode(bytes); return true; } catch { return false; }
}
function machine(reversed = false) {
  const rows = Array.from({length: 8}, () => Array(256).fill(-1));
  const fill = (state, a, b, next) => {for (let x = a; x <= b; x++) rows[state][x] = next;};
  fill(0, 0, 127, 0); fill(0, 0xc2, 0xdf, 1);
  fill(0, 0xe1, 0xec, 2); fill(0, 0xee, 0xef, 2);
  fill(0, 0xf1, 0xf3, 3);
  rows[0][0xe0] = 4; rows[0][0xed] = 5;
  rows[0][0xf0] = 6; rows[0][0xf4] = 7;
  fill(1, 0x80, 0xbf, 0); fill(2, 0x80, 0xbf, 1); fill(3, 0x80, 0xbf, 2);
  fill(4, 0xa0, 0xbf, 1); fill(5, 0x80, 0x9f, 1);
  fill(6, 0x90, 0xbf, 2); fill(7, 0x80, 0x8f, 2);
  if (!reversed) return {transitions: rows, start: 0, accepting: rows.map((_, i) => i === 0)};
  // Reverse the finite automaton, then determinize its state subsets. This
  // recognizes complete reversed UTF-8 strings, not reversed characters.
  const masks = [1], ids = new Map([[1, 0]]), transitions = [];
  for (let index = 0; index < masks.length; index++) {
    const row = [];
    for (let b = 0; b < 256; b++) {
      let mask = 0;
      for (let state = 0; state < 8; state++) {
        const next = rows[state][b];
        if (next >= 0 && (masks[index] & (1 << next))) mask |= 1 << state;
      }
      if (!mask) { row.push(-1); continue; }
      if (!ids.has(mask)) { ids.set(mask, masks.length); masks.push(mask); }
      row.push(ids.get(mask));
    }
    transitions.push(row);
  }
  return {transitions, start: 0, accepting: masks.map(mask => !!(mask & 1)), masks};
}
const machines = {big: machine(), little: machine(true)};
const feasible = Object.fromEntries(Object.entries(machines).map(([name, dfa]) => [name, [dfa.accepting]]));
function ensureLength(order, length) {
  const dfa = machines[order], rows = feasible[order];
  while (rows.length <= length) rows.push(dfa.transitions.map(row => row.some(next => next >= 0 && rows.at(-1)[next])));
}
function accepted(bytes, order) {
  const dfa = machines[order]; let state = dfa.start;
  for (const b of bytes) { state = dfa.transitions[state][b]; if (state < 0) return false; }
  return dfa.accepting[state];
}
function nextUtf8(n, order = 'big') {
  assert(Object.hasOwn(machines, order));
  const lower = [...bytesOf(n)], dfa = machines[order];
  ensureLength(order, lower.length + 1);
  function suffix(state, remaining) {
    const answer = [];
    while (remaining) {
      const b = dfa.transitions[state].findIndex(next => next >= 0 && feasible[order][remaining - 1][next]);
      assert(b >= 0); answer.push(b); state = dfa.transitions[state][b]; remaining--;
    }
    assert(dfa.accepting[state]); return answer;
  }
  function solve(pos, state) {
    if (pos === lower.length) return dfa.accepting[state] ? [] : null;
    for (let b = lower[pos]; b < 256; b++) {
      const next = dfa.transitions[state][b], remaining = lower.length - pos - 1;
      if (next < 0 || !feasible[order][remaining][next]) continue;
      const rest = b === lower[pos] ? solve(pos + 1, next) : suffix(next, remaining);
      if (rest !== null) return [b, ...rest];
    }
    return null;
  }
  let answer = solve(0, dfa.start);
  if (answer === null) {
    // Minimal canonical value of the next byte width. ASCII 01 followed by
    // zero bytes guarantees such a value exists in both byte orders.
    const width = lower.length + 1;
    for (let b = 1; b < 256; b++) {
      const next = dfa.transitions[dfa.start][b];
      if (next >= 0 && feasible[order][width - 1][next]) {answer = [b, ...suffix(next, width - 1)]; break;}
    }
  }
  assert(answer !== null);
  const result = BigInt('0x' + Buffer.from(answer).toString('hex'));
  assert(result >= n && accepted(bytesOf(result), order)); return result;
}

function search(symbols, alias, order, {maxNodes = 2000000, maxMs = 20000} = {}) {
  assert.match(symbols, /^[a-i]+$/); assert.match(alias, /^[a-i]{1,2}$/);
  assert.equal(new Set(alias).size, alias.length);
  assert(Object.hasOwn(machines, order));
  const low = BigInt([...symbols].map(c => alias.includes(c) ? 0 : c.charCodeAt(0) - 96).join(''));
  const weights = [...symbols].flatMap((c, i) => alias.includes(c) ? [BigInt(c.charCodeAt(0) - 96) * 10n ** BigInt(symbols.length - i - 1)] : []);
  const tails = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
  const certificates = [], hits = [], pending = [];
  let nodes = 0, excluded = 0n;
  const start = Date.now();
  function visit(i, lo, mask) {
    if (nodes >= maxNodes || Date.now() - start >= maxMs) { pending.push(mask); return; }
    nodes++;
    const hi = lo + tails[i], next = nextUtf8(lo, order);
    if (next > hi) {
      excluded += 1n << BigInt(weights.length - i);
      certificates.push({mask, lo: lo.toString(), hi: hi.toString(), next: next.toString()}); return;
    }
    if (i === weights.length) {
      const bytes = bytesOf(lo); if (order === 'little') bytes.reverse();
      assert(fatalValid(bytes));
      hits.push({mask, decimal: lo.toString(), hex: bytes.toString('hex'), text: strict.decode(bytes)}); return;
    }
    visit(i + 1, lo, mask + '0'); visit(i + 1, lo + weights[i], mask + '1');
  }
  visit(0, low, '');
  const unvisited = pending.reduce((n, p) => n + (1n << BigInt(weights.length - p.length)), 0n);
  assert.equal(excluded + BigInt(hits.length) + unvisited, 1n << BigInt(weights.length));
  return {alias, order, ambiguous: weights.length, nodes, complete: pending.length === 0,
    elapsedMs: Date.now() - start, excluded: excluded.toString(), pendingAssignments: unvisited.toString(), certificates, hits, pending};
}
function encode(bytes, alias, order) {
  const copy = Buffer.from(bytes); if (order === 'little') copy.reverse();
  const decimal = BigInt('0x' + copy.toString('hex')).toString();
  return [...decimal].map(c => c === '0' ? alias : String.fromCharCode(96 + Number(c))).join('');
}
function controls() {
  let finiteBytes = 0, planted = 0, exhaustiveMasks = 0;
  const aliases = [...'abcdefghi', ...[...'abcdefghi'].flatMap((c, i) => [...'abcdefghi'].slice(i + 1).map(d => c + d))];
  for (const order of ['big', 'little']) {
    for (let n = 0; n < 65536; n++) {
      const bytes = bytesOf(BigInt(n)), asText = Buffer.from(bytes); if (order === 'little') asText.reverse();
      assert.equal(accepted(bytes, order), fatalValid(asText)); finiteBytes++;
    }
    for (const alias of aliases) {
      for (const text of ['Olá, “yin-yang” — π.', 'matrixsumlist', '源碼 🔑 𝄞']) {
        const source = encode(Buffer.from(text), alias[0], order), r = search(source, alias, order);
        assert(r.complete && r.hits.some(h => h.hex === Buffer.from(text).toString('hex'))); planted++;
      }
      for (const source of [alias.repeat(3), `abc${alias}${alias}ghi`, 'ggigbg']) {
        const count = [...source].filter(c => alias.includes(c)).length, expected = [];
        for (let mask = 0; mask < 2 ** count; mask++) {
          let i = 0;
          const n = BigInt([...source].map(c => alias.includes(c) ? ((mask >> i++) & 1 ? digitOf(c) : 0) : digitOf(c)).join(''));
          const bytes = bytesOf(n); if (order === 'little') bytes.reverse();
          if (fatalValid(bytes)) expected.push(n.toString());
        }
        const r = search(source, alias, order); assert(r.complete);
        assert.deepEqual(r.hits.map(h => h.decimal).sort(), expected.sort()); exhaustiveMasks++;
      }
    }
  }
  const invalid = ['c080', 'c1bf', 'eda080', 'edbfbf', 'f0808080', 'f4908080', 'f5808080', 'e282', '80'];
  for (const hex of invalid) for (const order of ['big', 'little']) {
    const bytes = Buffer.from(hex, 'hex'); if (order === 'little') bytes.reverse();
    assert(!accepted(bytes, order));
  }
  assert(!search('gggggg', 'g', 'big', {maxNodes: 1}).complete);
  return {finiteByteStrings: finiteBytes, planted, exhaustiveMasks, invalidBoundaryChecks: invalid.length * 2, limitAccounting: true};
}
function digitOf(c) { return c.charCodeAt(0) - 96; }
function main() {
  const paired = process.argv[2] === 'pairs';
  assert(process.argv[2] === undefined || paired);
  const checked = controls(); console.log(JSON.stringify({controls: checked}));
  const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
  const input = JSON.parse(inputBytes), results = [];
  const directory = paired ? path.join(out, 'two_symbols') : out;
  fs.mkdirSync(directory, {recursive: true});
  const aliases = paired ? [...'abcdefghi'].flatMap((c, i) => [...'abcdefghi'].slice(i + 1).map(d => c + d)) : [...'abcdefghi'];
  const spec = {hypothesis: 'Every occurrence of a selected symbol independently means zero or its a1z26 digit. Entire field is a decimal integer, converted to minimal big- or little-endian bytes, which must be strict RFC3629 UTF-8. Original and fully reversed symbol strings.',
    aliasSets: aliases, limits: `Selected sets contain ${paired ? 'two different symbols' : 'one symbol'}. No transposition, extra cipher, stripping, replacement decoding or alternate charset. UTF-8 validity alone is not a message or password validation.`,
    sourceURL: 'https://www.rfc-editor.org/rfc/rfc3629.html#section-4', inputSHA256: sha(inputBytes), sourceSHA256: sha(fs.readFileSync(__filename)), controls: checked,
    machines, fields: {dbbi: input.dbbi, faed: input.faed}};
  fs.writeFileSync(path.join(directory, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  fs.writeFileSync(path.join(directory, 'cases.jsonl'), '');
  for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const alias of aliases) for (const order of ['big', 'little']) {
    const source = reverse ? [...input[field]].reverse().join('') : input[field];
    const r = {field, reverse, ...search(source, alias, order)}; results.push(r);
    fs.appendFileSync(path.join(directory, 'cases.jsonl'), JSON.stringify(r) + '\n');
    console.log(JSON.stringify({field, reverse, alias, order, nodes: r.nodes, complete: r.complete, hits: r.hits.length}));
  }
  fs.writeFileSync(path.join(directory, 'results.json'), JSON.stringify(results, null, 2) + '\n');
  const candidates = results.flatMap(r => r.hits.map(h => ({field: r.field, reverse: r.reverse, alias: r.alias, order: r.order, ...h})));
  const summary = {cases: results.length, complete: results.filter(r => r.complete).length,
    nodes: results.reduce((s, r) => s + r.nodes, 0), certificates: results.reduce((s, r) => s + r.certificates.length, 0), candidates,
    incomplete: results.filter(r => !r.complete).map(({field, reverse, alias, order, nodes, pendingAssignments}) => ({field, reverse, alias, order, nodes, pendingAssignments})),
    resultsSHA256: sha(fs.readFileSync(path.join(directory, 'results.json')))};
  fs.writeFileSync(path.join(directory, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'); console.log(JSON.stringify({...summary, candidates: candidates.length}));
}
if (require.main === module) main();
module.exports = {nextUtf8, search, machine, machines, accepted, bytesOf};
