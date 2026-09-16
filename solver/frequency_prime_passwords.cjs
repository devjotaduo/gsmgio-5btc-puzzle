'use strict';
// Bounded frequency counterpart of the wavelength hypothesis. Exact rational
// conversion in vacuum; conventional colour bands, not an RGB inversion.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/frequency_primes_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function prime(n) {for (let d = 2; d * d <= n; d++) if (n % d === 0) return false; return n >= 2;}
function main() {
  fs.mkdirSync(out, {recursive: true});
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw);
  const speed = 299792458n;
  function frequencyBand(loNm, hiNm) {
    const denominatorLo = BigInt(hiNm) * 1000n, denominatorHi = BigInt(loNm) * 1000n;
    const lo = Number((speed + denominatorLo - 1n) / denominatorLo), hi = Number(speed / denominatorHi);
    assert(BigInt(lo) * denominatorLo >= speed && BigInt(lo - 1) * denominatorLo < speed);
    assert(BigInt(hi) * denominatorHi <= speed && BigInt(hi + 1) * denominatorHi > speed);
    return {wavelengthNm: [loNm, hiNm], integerTHz: [lo, hi], primes: Array.from({length: hi - lo + 1}, (_, i) => lo + i).filter(prime)};
  }
  const bands = {blue: frequencyBand(450, 495), yellow: frequencyBand(570, 590)};
  const blue = bands.blue.primes, yellow = bands.yellow.primes;
  assert.deepEqual(blue, [607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661]);
  assert.deepEqual(yellow, [509, 521, 523]);
  const normalized = input.phase32_text.replace(/[^a-z]/gi, '').toLowerCase();
  const start = normalized.indexOf('reinsertingtheprimebasics'), end = normalized.indexOf('select', start); assert(start >= 0 && end > start);
  const lastwords = [normalized.slice(start, end), 'sheisgoingtodieandthereisnothingyoucandotostopit'];
  const lists = [], preimages = new Map();
  function add(label, bytes) {const hex = bytes.toString('hex'); if (!preimages.has(hex)) preimages.set(hex, {label, hex});}
  for (const b of blue) for (const y of yellow) for (const background of ['bits', 'zero']) {
    const matrix = input.matrix.map(row => row.map(v => background === 'bits' ? v : 0));
    for (const [, c, r, k] of input.colored) matrix[r][k] = c === 'B' ? b : y;
    for (const axis of ['rows', 'columns']) for (const reverse of [false, true]) {
      const values = Array.from({length: 14}, (_, i) => Array.from({length: 14}, (_, j) => axis === 'rows' ? matrix[i][j] : matrix[j][i]).reduce((a, b) => a + b, 0));
      if (reverse) values.reverse();
      const id = lists.length; lists.push({blue: b, yellow: y, background, axis, reverse, values});
      const forms = [['digits', Buffer.from(values.join(''))], ['comma', Buffer.from(values.join(','))], ['space', Buffer.from(values.join(' '))],
        ['newline', Buffer.from(values.join('\n'))], ['json', Buffer.from(JSON.stringify(values))]];
      for (const endian of ['BE', 'LE']) {
        const packed = Buffer.alloc(values.length * 2); values.forEach((v, i) => packed['writeUInt16' + endian](v, i * 2));
        forms.push(['uint16' + endian, packed]);
      }
      for (const [form, bytes] of forms) {
        add({list: id, form, words: null, side: null}, bytes);
        for (let words = 0; words < lastwords.length; words++) for (const side of ['before', 'after']) {
          const wordBytes = Buffer.from(lastwords[words]);
          add({list: id, form, words, side}, side === 'before' ? Buffer.concat([wordBytes, bytes]) : Buffer.concat([bytes, wordBytes]));
        }
      }
    }
  }
  // Known original ciphertext validates the password-to-key path.
  const control = Buffer.from(input.phase32_control_b64, 'base64');
  const controlPlain = open(Buffer.from(input.phase32_control_password), {salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex')}, 'sha256');
  assert.equal(sha(controlPlain), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const materials = [...preimages.values()], passwords = new Map(), padding = [], scalars = [], pubHits = [], seenScalars = new Set();
  const ec = crypto.createECDH('secp256k1'), curveOrder = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  ec.setPrivateKey(Buffer.from('1'.padStart(64, '0'), 'hex')); assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  let decisions = 0;
  for (let material = 0; material < materials.length; material++) {
    const bytes = Buffer.from(materials[material].hex, 'hex'), hash = sha(bytes), n = BigInt('0x' + hash);
    if (n > 0n && n < curveOrder && !seenScalars.has(hash)) {
      seenScalars.add(hash); ec.setPrivateKey(Buffer.from(hash, 'hex')); const point = ec.getPublicKey('hex', 'uncompressed');
      scalars.push({material, hex: hash, pubkey: point});
      if (point.slice(2, 66) === input.target_pubkey.slice(2, 66)) pubHits.push({material, hex: hash, relation: point === input.target_pubkey ? 'target' : 'negation'});
    }
    for (const [form, pw] of [['direct', bytes], ['sha256-hex', Buffer.from(hash)]]) {
      const hex = pw.toString('hex'); if (passwords.has(hex)) continue;
      const password = passwords.size; passwords.set(hex, {material, form, hex});
      for (const [blob, cipher] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
        decisions++; const plain = open(pw, cipher, digest); if (plain === null) continue;
        padding.push({password, blob, digest, hex: plain.toString('hex'), printable: [...plain].filter(v => v >= 32 && v <= 126 || [9, 10, 13].includes(v)).length / plain.length});
      }
    }
  }
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');
  save('spec.json', {createdAt: new Date().toISOString(), inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)),
    helperSHA256: sha(fs.readFileSync(path.join(root, 'solver/decimal_keystream_constraints.cjs'))),
    hypothesis: 'Assign to blue and yellow prime integer frequencies in terahertz, obtained from conventional visible-colour wavelength bands, then use original row/column sums as password material, directly or SHA256 hexadecimal. Optionally concatenate one of two last-words interpretations.',
    source: {url: 'https://lasp.colorado.edu/wp-content/uploads/2011/06/Wood_monday_SPECTRA.pdf', page: 2, speedDefinition: 'https://www.bipm.org/en/si-base-units/metre', speedMetresPerSecond: speed.toString(), relation: 'f[THz] = 299792458 / (1000 * lambda[nm])'}, bands,
    clue: {file: '_work/matrix_hint_2026-09-11/hint_context.json', creatorMessage: 6250, followingMessage: 6252, qualification: 'Infrared occurs in an informal exchange, followed by No hints. It does not identify wavelengths or this operation.'},
    blue, yellow, lastwords, lists, constructions: lists.length * 7 * 5,
    scope: 'The bands are a finite conventional choice, not an RGB-to-spectrum inversion. Only integer THz in the declared bands. No other units, colour boundaries, longer concatenations, different sums or untested cryptographic constructions.',
    controls: {phase32PlaintextSHA256: sha(controlPlain), secp256k1Generator: true}});
  save('materials.json', materials); save('oracles.json', {passwords: [...passwords.values()], padding, scalars, pubHits, aesDecisions: decisions});
  const summary = {primePairs: blue.length * yellow.length, matrices: blue.length * yellow.length * 2, lists: lists.length,
    constructions: lists.length * 7 * 5, materials: materials.length, passwords: passwords.size, aesDecisions: decisions,
    paddings: padding.length, maxPrintable: Math.max(0, ...padding.map(p => p.printable)), scalarChecks: scalars.length, pubHits,
    materialsSHA256: sha(fs.readFileSync(path.join(out, 'materials.json'))), oraclesSHA256: sha(fs.readFileSync(path.join(out, 'oracles.json'))), finalPasswordFound: false};
  save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
