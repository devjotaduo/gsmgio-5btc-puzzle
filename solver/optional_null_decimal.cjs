'use strict';
// Optional deletion of each occurrence of one symbol before whole-decimal decoding.
// Group by number of deletions, then bound every suffix by its exact extrema.
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {nextAscii} = require('./zero_decimal_constraints.cjs');
const root = path.resolve(__dirname, '..'), zeroMode = process.argv.includes('--with-zero'), dir = path.join(root, '_work/optional_null_decimal_2026-09-16', ...(zeroMode ? ['with_zero'] : []));
const hash = b => crypto.createHash('sha256').update(b).digest('hex');

function prepare(digits, removable, allowZero = false) {
  assert.match(digits, /^[0-9]+$/); assert.equal(digits.length, removable.length);
  const chunks = [''], positions = [], optional = [];
  for (let i = 0; i < digits.length; i++) {
    if (removable[i]) {positions.push(i); optional.push(Number(digits[i])); chunks.push('');}
    else chunks[chunks.length - 1] += digits[i];
  }
  const m = positions.length, powers = [1n]; for (let i = 1; i <= digits.length; i++) powers.push(powers.at(-1) * 10n);
  const numbers = chunks.map(c => BigInt(c || '0')), remaining = new Array(m + 1).fill(0);
  for (let i = m - 1; i >= 0; i--) remaining[i] = remaining[i + 1] + 1 + chunks[i + 1].length;
  const lows = Array.from({length: m + 1}, () => []), highs = Array.from({length: m + 1}, () => []); lows[m][0] = highs[m][0] = 0n;
  for (let i = m - 1; i >= 0; i--) for (let deleted = 0; deleted <= m - i; deleted++) {
    const optionsLow = [], optionsHigh = [], chunk = numbers[i + 1], width = chunks[i + 1].length;
    if (deleted <= m - i - 1) {
      const head = BigInt(optional[i]) * powers[width] + chunk, shift = powers[remaining[i + 1] - deleted];
      optionsLow.push((allowZero ? chunk : head) * shift + lows[i + 1][deleted]); optionsHigh.push(head * shift + highs[i + 1][deleted]);
    }
    if (deleted > 0) {
      const shift = powers[remaining[i + 1] - (deleted - 1)];
      optionsLow.push(chunk * shift + lows[i + 1][deleted - 1]); optionsHigh.push(chunk * shift + highs[i + 1][deleted - 1]);
    }
    lows[i][deleted] = optionsLow.reduce((a, b) => a < b ? a : b); highs[i][deleted] = optionsHigh.reduce((a, b) => a > b ? a : b);
  }
  return {digits, chunks, positions, optional, powers, numbers, remaining, lows, highs, m};
}

function solve(digits, removable, maxNodes = 1000000, allowZero = false) {
  const p = prepare(digits, removable, allowZero), nodes = [], roots = [], seen = new Map(), hits = new Set(); let complete = true;
  function visit(index, deleted, prefix) {
    const identity = index + '/' + deleted + '/' + prefix;
    if (seen.has(identity)) return seen.get(identity);
    if (nodes.length >= maxNodes) {complete = false; return null;}
    const id = nodes.length, node = {index, deleted, prefix: String(prefix)}; nodes.push(node); seen.set(identity, id);
    const shift = p.powers[p.remaining[index] - deleted], low = prefix * shift + p.lows[index][deleted], high = prefix * shift + p.highs[index][deleted];
    if (nextAscii(low, true) > high) node.kind = 'excluded';
    else if (index === p.m) {node.kind = 'hit'; hits.add(String(prefix));}
    else {
      node.kind = 'branch'; node.children = [];
      const width = p.chunks[index + 1].length, literal = p.numbers[index + 1];
      if (deleted <= p.m - index - 1) node.children.push({action: 'keep', id: visit(index + 1, deleted, (prefix * 10n + BigInt(p.optional[index])) * p.powers[width] + literal)});
      if (allowZero && deleted <= p.m - index - 1) node.children.push({action: 'zero', id: visit(index + 1, deleted, prefix * 10n * p.powers[width] + literal)});
      if (deleted > 0) node.children.push({action: 'delete', id: visit(index + 1, deleted - 1, prefix * p.powers[width] + literal)});
    }
    return id;
  }
  for (let deleted = 0; deleted <= p.m; deleted++) roots.push({deleted, id: visit(0, deleted, p.numbers[0])});
  return {optionalCount: p.m, masks: String(BigInt(allowZero ? 3 : 2) ** BigInt(p.m)), allowZero, chunks: p.chunks, positions: p.positions, roots, nodes,
    hits: [...hits], complete, stats: {nodes: nodes.length, excluded: nodes.filter(n => n.kind === 'excluded').length, hits: nodes.filter(n => n.kind === 'hit').length}};
}

function byteHex(n) {let hex = BigInt(n).toString(16); return hex.length % 2 ? '0' + hex : hex;}
function controls(allowZero) {
  let exactCases = 0, masks = 0;
  for (const digits of ['199921', '9119999', '123999456', '9099909', '99999', '198273649']) for (const alias of ['1', '9']) {
    const optional = [...digits].map(d => d === alias), positions = optional.flatMap((v, i) => v ? [i] : []), expected = new Set();
    for (let mask = 0; mask < (allowZero ? 3 : 2) ** positions.length; mask++) {
      const choices = new Map(); let code = mask;
      for (const position of positions) {choices.set(position, code % (allowZero ? 3 : 2)); code = Math.floor(code / (allowZero ? 3 : 2));}
      const kept = [...digits].map((digit, i) => !choices.has(i) || choices.get(i) === 0 ? digit : choices.get(i) === 1 ? '' : '0').join('');
      const number = BigInt(kept || '0'); if ([...Buffer.from(byteHex(number), 'hex')].every(b => b < 128)) expected.add(String(number)); masks++;
    }
    const result = solve(digits, optional, 1000000, allowZero); assert(result.complete); assert.deepEqual(result.hits.sort(), [...expected].sort()); exactCases++;
  }
  const planted = [];
  for (const text of ['lastwords', 'matrixsumlist', 'thispassword']) {
    const decimal = BigInt('0x' + Buffer.from(text).toString('hex')).toString();
    const digits = [...decimal].map((c, i) => c + (i % 3 === 0 ? '9' : '')).join(''), result = solve(digits, [...digits].map(c => c === '9'), 1000000, allowZero);
    assert(result.complete && result.hits.includes(decimal)); planted.push({text, digits, optionalDigit: '9', decimal, recovered: true});
  }
  return {exactCases, masks, planted};
}

function main() {
  const inputBytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputBytes);
  fs.mkdirSync(dir, {recursive: true}); const checks = controls(zeroMode); fs.writeFileSync(path.join(dir, 'controls.json'), JSON.stringify(checks, null, 2) + '\n');
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify({sourceSHA256: hash(fs.readFileSync(__filename)), inputSHA256: hash(inputBytes), successorSHA256: hash(fs.readFileSync(path.join(__dirname, 'zero_decimal_constraints.cjs'))),
    hypothesis: 'A1..I9. Each occurrence of any ONE selected letter may independently be retained or deleted, and optionally zeroed as declared by allowZero. Complete original DBBI/FAED in both directions, interpreted as one decimal integer. All minimal bytes must be 0..127; no stripping.', allowZero: zeroMode, maxNodesPerCase: 1000000}, null, 2) + '\n');
  const summary = [], candidates = new Map();
  for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const alias of 'abcdefghi') {
    const text = reverse ? [...input[field]].reverse().join('') : input[field], digits = [...text].map(c => c.charCodeAt(0) - 96).join(''), id = [field, reverse ? 'reverse' : 'forward', alias].join('_');
    const result = solve(digits, [...text].map(c => c === alias), 1000000, zeroMode), payload = {...result, field, reverse, alias, digits};
    const file = id + '.json.gz'; fs.writeFileSync(path.join(dir, file), zlib.gzipSync(JSON.stringify(payload)));
    for (const decimal of result.hits) {
      const hex = byteHex(decimal); if (!candidates.has(hex)) candidates.set(hex, {hex, decimal, source: id});
    }
    const record = {id, field, reverse, alias, complete: result.complete, optionalCount: result.optionalCount, masks: result.masks,
      ...result.stats, distinctCandidates: result.hits.length, file, artifactSHA256: hash(fs.readFileSync(path.join(dir, file)))};
    summary.push(record); console.log(JSON.stringify(record));
  }
  fs.writeFileSync(path.join(dir, 'candidates.json'), JSON.stringify([...candidates.values()], null, 2) + '\n');
  fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify({cases: summary, completeCases: summary.filter(c => c.complete).length, distinctCandidates: candidates.size, finalPasswordFound: false}, null, 2) + '\n');
}
module.exports = {prepare, solve};
if (require.main === module) main();
