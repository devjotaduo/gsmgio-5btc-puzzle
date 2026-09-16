'use strict';
// Matrix bits/colours as exponents of successive primes; exact integer bounds.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/prime_product_matrix_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function primesTo(count) { const p = []; for (let n = 2; p.length < count; n++) if (!p.some(d => d * d <= n && n % d === 0)) p.push(n); return p; }
function prime(n) { if (n < 2) return false; for (let d = 2; d * d <= n; d++) if (n % d === 0) return false; return true; }
function routes() {
  const row = Array.from({ length: 196 }, (_, i) => [Math.floor(i / 14), i % 14]);
  const snake = row.map(([r, c]) => [r, r % 2 ? 13 - c : c]);
  const spiral = []; let top = 0, bottom = 13, left = 0, right = 13;
  while (top <= bottom) { for (let c = left; c <= right; c++) spiral.push([top, c]); top++; for (let r = top; r <= bottom; r++) spiral.push([r, right]); right--; for (let c = right; c >= left; c--) spiral.push([bottom, c]); bottom--; for (let r = bottom; r >= top; r--) spiral.push([r, left]); left++; }
  const result = new Map();
  for (const [name, base] of [['rows', row], ['snake', snake], ['spiral', spiral]]) for (const reflection of [false, true]) for (let rotation = 0; rotation < 4; rotation++) for (const reverse of [false, true]) {
    let route = base.map(([r, c]) => { if (reflection) c = 13 - c; for (let i = 0; i < rotation; i++) [r, c] = [c, 13 - r]; return [r, c]; }); if (reverse) route.reverse();
    const key = route.map(([r, c]) => r * 14 + c).join(','); if (!result.has(key)) result.set(key, { name, reflection, rotation, reverse, cells: route });
  }
  return [...result.values()];
}
function match(source, decimal) {
  if (source.length !== decimal.length) return null;
  const map = new Map(), owner = new Map(), zero = new Set();
  for (let i = 0; i < source.length; i++) {
    const s = source[i], d = decimal[i];
    if (d === '0') { zero.add(s); if (zero.size > 2) return null; }
    else { if (map.has(s) && map.get(s) !== d || owner.has(d) && owner.get(d) !== s) return null; map.set(s, d); owner.set(d, s); }
  }
  return { mapping: [...'abcdefghi'].map(c => +(map.get(c) || 0)), zeroLetters: [...zero].sort().join('') };
}
function products(input, route, black, white) {
  const p = primesTo(196), colors = new Map(input.colored.map(([, v, r, c]) => [r + ',' + c, v]));
  let A = 1n, B = 1n, Y = 1n;
  route.forEach(([r, c], i) => { const q = BigInt(p[i]), color = colors.get(r + ',' + c); if (color === 'B') B *= q; else if (color === 'Y') Y *= q; else if (input.matrix[r][c] ? white : black) A *= q; });
  assert(B > 1n && Y > 1n); return { A, B, Y };
}
function enumerate(A, B, Y, length) {
  const lo = 10n ** BigInt(length - 1), hi = 10n ** BigInt(length), rows = [], values = [];
  let poweredB = B * B, b = 2;
  for (; A * poweredB * Y * Y < hi; b++, poweredB *= B) if (prime(b)) {
    let n = A * poweredB * Y * Y, y = 2;
    for (; n < hi; y++, n *= Y) if (prime(y) && n >= lo) values.push({ b, y, decimal: String(n) });
    rows.push({ b, maxYellowInteger: y - 1 });
  }
  return { maxBlueInteger: b - 1, rows, values };
}
function controls() {
  let count = 0;
  for (const A of [1n, 7n]) for (const B of [2n, 3n, 11n]) for (const Y of [3n, 5n]) for (const length of [2, 3, 4]) {
    const actual = enumerate(A, B, Y, length), expected = [];
    for (let b = 2; b < 20; b++) if (prime(b)) for (let y = 2; y < 20; y++) if (prime(y)) { const n = A * B ** BigInt(b) * Y ** BigInt(y); if (String(n).length === length) expected.push({ b, y, decimal: String(n) }); }
    assert.deepEqual(actual.values, expected); count++;
  }
  const map = 'ibgacfdhe', digits = '123456789001234567899876543210', source = [...digits].map((d, i) => d === '0' ? i % 2 ? 'b' : 'g' : map[+d - 1]).join(''); assert(match(source, digits)); assert.equal(match('aba', '123'), null); assert.equal(match('abc', '111'), null); assert.equal(match('abc', '000'), null);
  return { exhaustiveSmallProducts: count, substitutionChecks: 4 };
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'cases.jsonl')), 'Existing search must be inspected first');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), rs = routes();
  for (const r of rs) assert.equal(new Set(r.cells.map(([x, y]) => x * 14 + y)).size, 196);
  const spec = { scope: 'Assign prime p_(i+1) to the cell at route position i. Use exponents black/white in {0,1}, and uniform prime exponents >=2 for blue/yellow. Concatenate nothing: compare the one resulting integer in minimum decimal to the full field. Any positive-digit bijection a..i to1..9 with up to two zero-capable letters, both source directions. Routes are all distinct dihedral transforms/reversals of row-major, row-snake, clockwise inward spiral. Exact length bounds, no arbitrary prime cutoff.', inputSHA256: sha(inputRaw), routes: rs, primes: primesTo(196), controls: controls(), sourceSHA256: sha(fs.readFileSync(__filename)) };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n'); const fd = fs.openSync(path.join(out, 'cases.jsonl'), 'wx'), hits = []; let cases = 0, candidates = 0, comparisons = 0; const start = Date.now();
  for (const [routeIndex, route] of rs.entries()) for (const black of [0, 1]) for (const white of [0, 1]) {
    const { A, B, Y } = products(input, route.cells, black, white);
    for (const field of ['dbbi', 'faed']) {
      const result = enumerate(A, B, Y, input[field].length); candidates += result.values.length;
      for (const value of result.values) for (const reverse of [false, true]) { const source = reverse ? [...input[field]].reverse().join('') : input[field], witness = match(source, value.decimal); comparisons++; if (witness) hits.push({ routeIndex, black, white, field, reverse, ...value, ...witness }); }
      fs.writeSync(fd, JSON.stringify({ routeIndex, black, white, field, length: input[field].length, A: String(A), B: String(B), Y: String(Y), ...result }) + '\n'); cases++;
    }
  }
  fs.closeSync(fd); fs.writeFileSync(path.join(out, 'hits.json'), JSON.stringify(hits, null, 2) + '\n');
  const result = { complete: true, routes: rs.length, cases, lengthCompatiblePrimePairs: candidates, patternComparisons: comparisons, hits: hits.length, elapsedMs: Date.now() - start, casesSHA256: sha(fs.readFileSync(path.join(out, 'cases.jsonl'))) };
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
if (require.main === module) main();
module.exports = { routes, products, enumerate, match };
