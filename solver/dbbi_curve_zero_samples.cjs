'use strict';
// Cross-backend checks of the scalar MITM transcript: OpenSSL + affine JS.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const folder = path.join(root, '_work/dbbi_curve_zero_2026-09-16');
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const mod = (x, m) => (x % m + m) % m;
const hex = x => x.toString(16).padStart(64, '0');
function power(a, b) {
  let r = 1n;
  for (a = mod(a, P); b; b >>= 1n, a = a * a % P) if (b & 1n) r = r * a % P;
  return r;
}
function inverse(x) {
  let a = mod(x, P), b = P, u = 1n, v = 0n;
  assert(a !== 0n);
  while (b) { const q = a / b; [a, b] = [b, a - q * b]; [u, v] = [v, u - q * v]; }
  assert.equal(a, 1n);
  return mod(u, P);
}
function decode(s) {
  if (s === '00'.repeat(33)) return null;
  let x, y;
  if (s.length === 130 && s.startsWith('04')) { x = BigInt('0x' + s.slice(2, 66)); y = BigInt('0x' + s.slice(66)); }
  else {
    assert(s.length === 66 && /^(02|03)/.test(s));
    x = BigInt('0x' + s.slice(2)); y = power(x * x * x + 7n, (P + 1n) / 4n);
    if ((y & 1n) !== BigInt(parseInt(s.slice(0, 2), 16) & 1)) y = P - y;
  }
  assert(x >= 0n && x < P && y >= 0n && y < P);
  assert.equal(mod(y * y - x * x * x - 7n, P), 0n);
  return [x, y];
}
const encode = a => a === null ? '00'.repeat(33) : (a[1] & 1n ? '03' : '02') + hex(a[0]);
const negate = a => a === null ? null : [a[0], mod(-a[1], P)];
function add(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a[0] === b[0] && mod(a[1] + b[1], P) === 0n) return null;
  const s = a[0] === b[0] ? mod(3n * a[0] * a[0] * inverse(2n * a[1]), P) : mod((b[1] - a[1]) * inverse(b[0] - a[0]), P);
  const x = mod(s * s - a[0] - b[0], P);
  return [x, mod(s * (a[0] - x) - a[1], P)];
}
function generator(k) {
  k = mod(k, N);
  if (!k) return null;
  const e = crypto.createECDH('secp256k1');
  e.setPrivateKey(Buffer.from(hex(k), 'hex'));
  return decode(e.getPublicKey('hex', 'uncompressed'));
}
function main() {
  const output = path.join(folder, 'sample_verification.json');
  assert(!fs.existsSync(output), 'Existing verification must be inspected before rerun');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const input = JSON.parse(raw), specRaw = fs.readFileSync(path.join(folder, 'spec.json')), spec = JSON.parse(specRaw);
  const producerRaw = fs.readFileSync(path.join(folder, 'producer_summary.json')), producer = JSON.parse(producerRaw);
  assert.equal(sha(raw), spec.inputSHA256);
  assert.equal(sha(specRaw), producer.specSHA256);
  assert.equal(sha(fs.readFileSync(path.join(__dirname, 'dbbi_curve_zero_spec.cjs'))), spec.sourceSHA256);
  assert.equal(spec.moduli.n, hex(N)); assert.equal(spec.moduli.p, hex(P));
  assert.equal(spec.targetPublicKey, input.target_pubkey);
  const target = decode(input.target_pubkey), targetBytes = Buffer.from(input.target_pubkey, 'hex');
  assert.equal(crypto.createHash('ripemd160').update(crypto.createHash('sha256').update(targetBytes).digest()).digest('hex'), input.target_h160);
  assert.equal(spec.targetHash160, input.target_h160);
  assert(producer.complete); assert.equal(producer.models, 144); assert.equal(spec.cases.length, 144);
  const scalars = [0n, 1n, 2n, 7n, 101n, N - 1n, P - N, 10n ** 60n];
  let controls = 0;
  for (const a of scalars) for (const b of scalars) {
    assert.equal(encode(add(generator(a), generator(b))), encode(generator(a + b)));
    assert.equal(encode(add(generator(a), negate(generator(b)))), encode(generator(a - b)));
    controls += 2;
  }
  assert.equal(encode(decode(encode(target))), encode(target));
  const byId = new Map(producer.cases.map(c => [c.id, c]));
  assert.equal(byId.size, 144);
  const records = []; let id = 0, checked = 0;
  for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) for (const reverse of [false, true]) for (const modulus of ['n', 'p']) {
    const c = spec.cases[id], aliases = String.fromCharCode(97 + a, 97 + b), source = reverse ? Array.from(input.dbbi).reverse().join('') : input.dbbi;
    const m = modulus === 'n' ? N : P, positions = [], weights = []; let base = 0n;
    for (let j = 0; j < source.length; j++) {
      const w = BigInt(source.charCodeAt(j) - 96) * 10n ** BigInt(source.length - 1 - j);
      if (aliases.includes(source[j])) { positions.push(j); weights.push(w); } else base += w;
    }
    const split = Math.ceil(weights.length / 2);
    assert.deepEqual({id:c.id, aliases:c.aliases, reverse:c.reverse, modulus:c.modulus, source:c.source}, {id, aliases, reverse, modulus, source});
    assert.deepEqual(c.positions, positions); assert.deepEqual(c.weights, weights.map(String)); assert.equal(c.base, String(base));
    assert.deepEqual(c.residues, weights.map(w => String(w % m))); assert.equal(c.baseResidue, String(base % m));
    assert.equal(c.ambiguous, weights.length); assert.equal(c.split, split); assert.equal(c.assignments, String(1n << BigInt(weights.length)));
    assert.equal(c.leftAssignments, 2 ** split); assert.equal(c.rightAssignments, 2 ** (weights.length - split)); assert.equal(c.queryBranches, modulus === 'n' ? 2 : 4);
    const caseRaw = fs.readFileSync(path.join(folder, 'cases', `case_${String(id).padStart(3, '0')}.json`)), result = JSON.parse(caseRaw);
    const row = byId.get(id); assert.equal(sha(caseRaw), row.sha256 ?? row.SHA256);
    assert(result.complete); assert.equal(result.id, id); assert.equal(result.samples.length, result.directPointChecks);
    for (const s of result.samples) {
      assert(Number.isSafeInteger(s.mask) && s.mask >= 0);
      const ws = s.half === 'left' ? weights.slice(0, split) : weights.slice(split);
      assert(s.mask < 2 ** ws.length);
      let value = s.half === 'left' ? 0n : base;
      ws.forEach((w, j) => { if (s.mask & 2 ** j) value += w; });
      const residue = value % m; assert.equal(String(residue), s.residue);
      let expected;
      if (s.half === 'left') expected = generator(residue);
      else {
        assert.equal(s.half, 'query'); assert(s.sign === 1 || s.sign === -1);
        assert(s.carry === 0 || (modulus === 'p' && s.carry === 1));
        const variants = modulus === 'n' ? [[1,0],[-1,0]] : [[1,0],[1,1],[-1,0],[-1,1]];
        assert.deepEqual(variants[s.tag - 1], [s.sign, s.carry]);
        expected = add(s.sign === 1 ? target : negate(target), generator(-residue + BigInt(s.carry) * m));
      }
      assert.equal(s.point, encode(expected), `case ${id}, ${s.half}, mask ${s.mask}`);
      checked++;
    }
    records.push({id, samples:result.samples.length, caseSHA256:sha(caseRaw)}); id++;
  }
  const report = {complete:true, models:id, checkedSamples:checked, arithmeticControls:controls, backend:`Node ${process.version}; OpenSSL ${process.versions.openssl} fixed-generator multiplication; independent JavaScript affine addition`, scope:'All model specifications and every saved sample, not every full search record. Full stream verification is separate.', specSHA256:sha(specRaw), producerSHA256:sha(producerRaw), sourceSHA256:sha(fs.readFileSync(__filename)), cases:records};
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({complete:true, models:id, checkedSamples:checked, arithmeticControls:controls}));
}
if (require.main === module) main();
module.exports = {add, negate, generator, encode, decode};
